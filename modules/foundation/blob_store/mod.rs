//! Content-addressed blob store (PIC module).
//!
//! Persists small opaque blobs in a dedicated flash region so data can
//! survive a graph reconfigure (module state migration, cached
//! certificates, identity material). Keys are fixed 16-byte byte arrays
//! chosen by the caller; values are up to 1024 bytes.
//!
//! ## Layout
//!
//! Two 4 KB sectors (ping-pong) at `abi::blob_store::OFFSET`. The sector
//! with a valid magic + checksum and the higher epoch is "live"; writes
//! target the other sector, which becomes live when its higher epoch is
//! flushed. If one sector has a stale header from a previous write that
//! was interrupted, the other sector remains valid.
//!
//! Sector format (4096 bytes):
//!
//!   offset 0..4    magic  "FXBS"
//!   offset 4       version (1)
//!   offset 5..8    reserved
//!   offset 8..16   epoch (u64 LE, higher wins)
//!   offset 16..18  entry_bytes (u16 LE; total bytes of packed entries)
//!   offset 18..20  reserved
//!   offset 20..24  checksum (CRC32 over entry bytes)
//!   offset 24..4096  packed entries
//!
//! Packed entry: `[key:16][val_len:u16 LE][val:val_len]`. No tombstones:
//! a deletion is implemented by writing the next sector without the key.
//!
//! ## Kernel registration
//!
//! Registers `blob_store_dispatch` via `BLOB_STORE_ENABLE` on first
//! step. The kernel routes `BLOB_PUT` / `BLOB_GET` / `BLOB_DELETE`
//! `dev_call` opcodes into the dispatch function, which reads and
//! rewrites sectors via the raw flash bridge syscalls.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// ============================================================================
// Constants
// ============================================================================

const XIP_BASE: u32 = 0x1000_0000;
const SECTOR_A_OFFSET: u32 = abi::blob_store::OFFSET;
const SECTOR_B_OFFSET: u32 = SECTOR_A_OFFSET + abi::blob_store::SECTOR_SIZE;
const SECTOR_SIZE: usize = abi::blob_store::SECTOR_SIZE as usize;

const MAGIC: u32 = abi::blob_store::MAGIC;
const VERSION: u8 = abi::blob_store::VERSION;
const KEY_SIZE: usize = abi::blob_store::KEY_SIZE;
const MAX_VALUE: usize = abi::blob_store::MAX_VALUE_SIZE;

const HEADER_SIZE: usize = 24;
const MAX_ENTRY_BYTES: usize = SECTOR_SIZE - HEADER_SIZE;
const ENTRY_HEADER_SIZE: usize = KEY_SIZE + 2; // key + val_len

const PAGE_SIZE: usize = 256;

// Syscall opcodes (mirror abi::dev_system).
const SYS_BLOB_STORE_ENABLE: u32 = 0x0C80;
const SYS_BLOB_PUT: u32 = 0x0C81;
const SYS_BLOB_GET: u32 = 0x0C82;
const SYS_BLOB_DELETE: u32 = 0x0C83;
const SYS_FLASH_RAW_ERASE: u32 = 0x0C38;
const SYS_FLASH_RAW_PROGRAM: u32 = 0x0C39;

// StepOutcome codes.
const CONTINUE: i32 = 0;
const READY: i32 = 3;

// Sentinel errno values (mirror src/kernel/errno.rs). `E_INVAL` comes
// from the SDK runtime.
const E_NOENT: i32 = -2;
const E_NOSPC: i32 = -28;

// ============================================================================
// State
// ============================================================================

/// Live-sector mirror + bookkeeping. A single in-RAM copy of the live
/// sector is kept so reads are served without touching XIP and writes
/// can be composed in place before being flushed to the inactive sector.
#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    registered: u8,
    signaled_ready: u8,
    live_sector: u8, // 0 = A, 1 = B
    _pad: u8,
    epoch: u64,
    entry_bytes: u32, // bytes of packed entries currently in `buf`
    buf: [u8; SECTOR_SIZE],
}

// ============================================================================
// Syscall wrappers
// ============================================================================

unsafe fn sys_erase(sys: &SyscallTable, offset: u32) -> i32 {
    let mut arg = offset.to_le_bytes();
    (sys.dev_call)(-1, SYS_FLASH_RAW_ERASE, arg.as_mut_ptr(), 4)
}

/// Program one 256-byte page. `data` must point to at least `PAGE_SIZE` bytes.
unsafe fn sys_program(sys: &SyscallTable, offset: u32, data: *const u8) -> i32 {
    // arg = [offset:u32 LE, page:256 bytes]
    let mut buf = [0u8; 4 + PAGE_SIZE];
    let ob = offset.to_le_bytes();
    let p = buf.as_mut_ptr();
    core::ptr::write_volatile(p.add(0), ob[0]);
    core::ptr::write_volatile(p.add(1), ob[1]);
    core::ptr::write_volatile(p.add(2), ob[2]);
    core::ptr::write_volatile(p.add(3), ob[3]);
    let mut i = 0usize;
    while i < PAGE_SIZE {
        core::ptr::write_volatile(p.add(4 + i), *data.add(i));
        i += 1;
    }
    (sys.dev_call)(-1, SYS_FLASH_RAW_PROGRAM, buf.as_mut_ptr(), 4 + PAGE_SIZE)
}

// ============================================================================
// Header + checksum
// ============================================================================

fn crc32(data: *const u8, len: usize) -> u32 {
    // Bitwise CRC-32/IEEE. PIC-safe (no lookup table in rodata).
    let mut crc: u32 = 0xFFFF_FFFF;
    let mut i = 0usize;
    while i < len {
        let b = unsafe { core::ptr::read(data.add(i)) };
        crc ^= b as u32;
        let mut k = 0;
        while k < 8 {
            let mask = (0u32).wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            k += 1;
        }
        i += 1;
    }
    !crc
}

/// Decode a sector header from `base` (XIP pointer). Returns
/// `Some((epoch, entry_bytes))` if the header is well-formed and the
/// entry checksum matches; `None` otherwise.
unsafe fn decode_header(base: *const u8) -> Option<(u64, u32)> {
    let magic = core::ptr::read_unaligned(base as *const u32);
    if magic != MAGIC { return None; }
    let version = core::ptr::read(base.add(4));
    if version != VERSION { return None; }
    let epoch = core::ptr::read_unaligned(base.add(8) as *const u64);
    let entry_bytes = core::ptr::read_unaligned(base.add(16) as *const u16) as u32;
    let checksum = core::ptr::read_unaligned(base.add(20) as *const u32);
    if entry_bytes as usize > MAX_ENTRY_BYTES { return None; }
    let computed = crc32(base.add(HEADER_SIZE), entry_bytes as usize);
    if computed != checksum { return None; }
    Some((epoch, entry_bytes))
}

/// Read both sectors, pick the live one, and populate `s.buf` with a
/// copy of its entry bytes. Leaves `s.epoch` / `s.entry_bytes` /
/// `s.live_sector` consistent with the chosen sector. If neither sector
/// is valid, leaves the buffer empty with epoch=0 and live_sector=1
/// (so the first write goes to sector A).
unsafe fn load_live(s: &mut State) {
    let a = (XIP_BASE + SECTOR_A_OFFSET) as *const u8;
    let b = (XIP_BASE + SECTOR_B_OFFSET) as *const u8;
    let ha = decode_header(a);
    let hb = decode_header(b);

    let (chosen, epoch, entry_bytes) = match (ha, hb) {
        (Some((ea, la)), Some((eb, lb))) => {
            if ea >= eb { (a, ea, la) } else { (b, eb, lb) }
        }
        (Some((ea, la)), None) => (a, ea, la),
        (None, Some((eb, lb))) => (b, eb, lb),
        (None, None) => {
            s.epoch = 0;
            s.entry_bytes = 0;
            s.live_sector = 1; // first write goes to A
            return;
        }
    };
    s.epoch = epoch;
    s.entry_bytes = entry_bytes;
    s.live_sector = if chosen == a { 0 } else { 1 };

    let mut i = 0usize;
    while i < entry_bytes as usize {
        let byte = core::ptr::read(chosen.add(HEADER_SIZE + i));
        core::ptr::write_volatile(s.buf.as_mut_ptr().add(i), byte);
        i += 1;
    }
}

// ============================================================================
// In-memory entry navigation
// ============================================================================

/// Find the entry whose key matches `key`. Returns
/// `Some((offset, val_len))` where `offset` is the index of the
/// `val_len` field (so value bytes live at offset+2).
unsafe fn find(s: &State, key: *const u8) -> Option<(u32, u16)> {
    let end = s.entry_bytes as usize;
    let buf = s.buf.as_ptr();
    let mut pos = 0usize;
    while pos + ENTRY_HEADER_SIZE <= end {
        let k_matches = mem_eq(buf.add(pos), key, KEY_SIZE);
        let vlen = core::ptr::read_unaligned(buf.add(pos + KEY_SIZE) as *const u16);
        let entry_size = ENTRY_HEADER_SIZE + vlen as usize;
        if k_matches {
            return Some(((pos + KEY_SIZE) as u32, vlen));
        }
        pos += entry_size;
    }
    None
}

unsafe fn mem_eq(a: *const u8, b: *const u8, n: usize) -> bool {
    let mut i = 0usize;
    while i < n {
        if core::ptr::read(a.add(i)) != core::ptr::read(b.add(i)) {
            return false;
        }
        i += 1;
    }
    true
}

unsafe fn mem_copy(dst: *mut u8, src: *const u8, n: usize) {
    let mut i = 0usize;
    while i < n {
        core::ptr::write_volatile(dst.add(i), core::ptr::read(src.add(i)));
        i += 1;
    }
}

// ============================================================================
// Mutation + flush
// ============================================================================

/// Remove the entry starting at `pos` (index of its key byte 0).
unsafe fn remove_at(s: &mut State, key_pos: usize) {
    let vlen = core::ptr::read_unaligned(
        s.buf.as_ptr().add(key_pos + KEY_SIZE) as *const u16,
    ) as usize;
    let entry_size = ENTRY_HEADER_SIZE + vlen;
    let tail = s.entry_bytes as usize - (key_pos + entry_size);
    if tail > 0 {
        let p = s.buf.as_mut_ptr();
        let mut i = 0usize;
        while i < tail {
            let byte = core::ptr::read(p.add(key_pos + entry_size + i));
            core::ptr::write_volatile(p.add(key_pos + i), byte);
            i += 1;
        }
    }
    s.entry_bytes -= entry_size as u32;
}

/// Append `[key][val_len][val]` to the in-RAM buffer. Returns `Ok(())`
/// or `Err(-ENOSPC)` if the entry does not fit.
unsafe fn append_entry(
    s: &mut State,
    key: *const u8,
    value: *const u8,
    value_len: usize,
) -> Result<(), i32> {
    let new_entry_size = ENTRY_HEADER_SIZE + value_len;
    if (s.entry_bytes as usize) + new_entry_size > MAX_ENTRY_BYTES {
        return Err(E_NOSPC);
    }
    let dst_base = s.entry_bytes as usize;
    let p = s.buf.as_mut_ptr();
    mem_copy(p.add(dst_base), key, KEY_SIZE);
    let vb = (value_len as u16).to_le_bytes();
    core::ptr::write_volatile(p.add(dst_base + KEY_SIZE), vb[0]);
    core::ptr::write_volatile(p.add(dst_base + KEY_SIZE + 1), vb[1]);
    if value_len > 0 {
        mem_copy(p.add(dst_base + ENTRY_HEADER_SIZE), value, value_len);
    }
    s.entry_bytes += new_entry_size as u32;
    Ok(())
}

/// Write `s.buf` to the inactive sector and flip `live_sector`.
/// Increments the epoch before writing. On failure, leaves the inactive
/// sector in an indeterminate state; the other sector remains valid.
unsafe fn flush(s: &mut State, sys: &SyscallTable) -> i32 {
    let target_offset = if s.live_sector == 0 { SECTOR_B_OFFSET } else { SECTOR_A_OFFSET };
    let new_epoch = s.epoch.wrapping_add(1);
    let entry_bytes = s.entry_bytes;
    let checksum = if entry_bytes > 0 {
        crc32(s.buf.as_ptr(), entry_bytes as usize)
    } else {
        crc32(core::ptr::null(), 0)
    };

    // Erase the target sector.
    let rc = sys_erase(sys, target_offset);
    if rc < 0 { return rc; }

    // Build and program page 0 (header + first portion of entries).
    let mut page = [0u8; PAGE_SIZE];
    let p = page.as_mut_ptr();
    let mb = MAGIC.to_le_bytes();
    core::ptr::write_volatile(p.add(0), mb[0]);
    core::ptr::write_volatile(p.add(1), mb[1]);
    core::ptr::write_volatile(p.add(2), mb[2]);
    core::ptr::write_volatile(p.add(3), mb[3]);
    core::ptr::write_volatile(p.add(4), VERSION);
    let eb = new_epoch.to_le_bytes();
    let mut i = 0usize;
    while i < 8 {
        core::ptr::write_volatile(p.add(8 + i), eb[i]);
        i += 1;
    }
    let lb = (entry_bytes as u16).to_le_bytes();
    core::ptr::write_volatile(p.add(16), lb[0]);
    core::ptr::write_volatile(p.add(17), lb[1]);
    // Bytes 18..20 reserved — left zero from the page init.
    let cb = checksum.to_le_bytes();
    core::ptr::write_volatile(p.add(20), cb[0]);
    core::ptr::write_volatile(p.add(21), cb[1]);
    core::ptr::write_volatile(p.add(22), cb[2]);
    core::ptr::write_volatile(p.add(23), cb[3]);

    let payload_in_first = core::cmp::min(entry_bytes as usize, PAGE_SIZE - HEADER_SIZE);
    mem_copy(p.add(HEADER_SIZE), s.buf.as_ptr(), payload_in_first);

    let rc = sys_program(sys, target_offset, page.as_ptr());
    if rc < 0 { return rc; }

    // Program subsequent pages.
    let mut remaining = (entry_bytes as usize).saturating_sub(payload_in_first);
    let mut src_off = payload_in_first;
    let mut page_off = PAGE_SIZE as u32;
    while remaining > 0 {
        let mut next = [0u8; PAGE_SIZE];
        let np = next.as_mut_ptr();
        let chunk = core::cmp::min(remaining, PAGE_SIZE);
        mem_copy(np, s.buf.as_ptr().add(src_off), chunk);
        let rc = sys_program(sys, target_offset + page_off, next.as_ptr());
        if rc < 0 { return rc; }
        remaining -= chunk;
        src_off += chunk;
        page_off += PAGE_SIZE as u32;
    }

    s.epoch = new_epoch;
    s.live_sector ^= 1;
    0
}

// ============================================================================
// Dispatch — routed from kernel BLOB_PUT / BLOB_GET / BLOB_DELETE
// ============================================================================

#[no_mangle]
#[link_section = ".text.blob_store_dispatch"]
pub unsafe extern "C" fn blob_store_dispatch(
    state: *mut u8,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if state.is_null() || arg.is_null() { return E_INVAL; }
    let s = &mut *(state as *mut State);
    if s.syscalls.is_null() { return E_INVAL; }
    let sys = &*s.syscalls;

    match opcode {
        SYS_BLOB_PUT => {
            if arg_len < KEY_SIZE + 2 { return E_INVAL; }
            let key = arg as *const u8;
            let vlen = core::ptr::read_unaligned(arg.add(KEY_SIZE) as *const u16) as usize;
            if vlen > MAX_VALUE { return E_INVAL; }
            if arg_len < KEY_SIZE + 2 + vlen { return E_INVAL; }
            let val = arg.add(KEY_SIZE + 2);

            if let Some((vpos, _)) = find(s, key) {
                remove_at(s, (vpos as usize) - KEY_SIZE);
            }
            if let Err(rc) = append_entry(s, key, val, vlen) {
                return rc;
            }
            flush(s, sys)
        }
        SYS_BLOB_GET => {
            if arg_len < KEY_SIZE + 2 { return E_INVAL; }
            let key = arg as *const u8;
            let entry = find(s, key);
            let (vpos, vlen) = match entry {
                Some(v) => v,
                None => return E_NOENT,
            };
            let max_out = arg_len - (KEY_SIZE + 2);
            if (vlen as usize) > max_out { return E_INVAL; }
            let lb = vlen.to_le_bytes();
            core::ptr::write_volatile(arg.add(KEY_SIZE), lb[0]);
            core::ptr::write_volatile(arg.add(KEY_SIZE + 1), lb[1]);
            mem_copy(
                arg.add(KEY_SIZE + 2),
                s.buf.as_ptr().add(vpos as usize + 2),
                vlen as usize,
            );
            vlen as i32
        }
        SYS_BLOB_DELETE => {
            if arg_len < KEY_SIZE { return E_INVAL; }
            let key = arg as *const u8;
            match find(s, key) {
                Some((vpos, _)) => {
                    remove_at(s, (vpos as usize) - KEY_SIZE);
                    flush(s, sys)
                }
                None => E_NOENT,
            }
        }
        _ => E_INVAL,
    }
}

// ============================================================================
// Module entry points
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<State>() { return -2; }
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.registered = 0;
        s.signaled_ready = 0;
        s.live_sector = 1; // so the first write goes to A when both sectors are empty
        s.epoch = 0;
        s.entry_bytes = 0;
        load_live(s);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() { return -1; }
        let sys = &*s.syscalls;

        if s.registered == 0 {
            let hash = fnv1a(b"blob_store_dispatch");
            let hb = hash.to_le_bytes();
            let mut a = [hb[0], hb[1], hb[2], hb[3]];
            let rc = (sys.dev_call)(-1, SYS_BLOB_STORE_ENABLE, a.as_mut_ptr(), 4);
            if rc < 0 { return rc; }
            s.registered = 1;
        }
        if s.signaled_ready == 0 {
            s.signaled_ready = 1;
            return READY;
        }
        CONTINUE
    }
}

#[no_mangle]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> i32 { 1 }

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
