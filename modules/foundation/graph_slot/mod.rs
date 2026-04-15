//! A/B graph slot store (PIC module).
//!
//! Owns the on-flash format of the two 512 KB OTA slots
//! (`abi::graph_slot::SLOT_{A,B}_OFFSET`). Each slot holds a full
//! graph bundle (module table + static config) preceded by a 256-byte
//! header. The slot with a valid magic and the higher epoch is live;
//! writes target the other slot and become live when
//! `GRAPH_SLOT_ACTIVATE` increments the epoch and validates the
//! SHA-256 recorded in the header.
//!
//! ## Kernel registration
//!
//! Registers `graph_slot_dispatch` via `GRAPH_SLOT_ENABLE` on first
//! step. The kernel forwards `GRAPH_SLOT_ACTIVE` / `ERASE` / `WRITE` /
//! `ACTIVATE` / `CONFIG_ADDR` dev_call opcodes here.
//!
//! ## Opcodes
//!
//! - ACTIVE → returns 0 (slot A), 1 (slot B), or -1 if neither valid.
//! - ERASE → erases the inactive slot's 128 sectors in one pass.
//! - WRITE(offset, page[256]) → programs one page of the inactive slot.
//! - ACTIVATE → recomputes SHA-256 over the just-written bundle,
//!   compares against the header's stored hash, and if it matches
//!   declares the slot live by virtue of its higher epoch.
//!   (The caller is expected to have written a header whose epoch
//!   exceeds the live slot's.) Returns 0 or `-EIO` on hash mismatch.
//! - CONFIG_ADDR → XIP address of the live slot's config blob.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/sha256.rs");

// ============================================================================
// Constants
// ============================================================================

const XIP_BASE: u32 = 0x1000_0000;
const SLOT_A_OFFSET: u32 = abi::graph_slot::SLOT_A_OFFSET;
const SLOT_B_OFFSET: u32 = abi::graph_slot::SLOT_B_OFFSET;
const SLOT_SIZE: u32 = abi::graph_slot::SLOT_SIZE;
const SLOT_MAGIC: u32 = abi::graph_slot::MAGIC;
const SLOT_VERSION: u8 = abi::graph_slot::VERSION;

const SECTOR_SIZE: u32 = 4096;
const PAGE_SIZE: usize = 256;

// Syscall opcodes.
const SYS_GRAPH_SLOT_ENABLE: u32 = 0x0C90;
const SYS_GRAPH_SLOT_ACTIVE: u32 = 0x0C91;
const SYS_GRAPH_SLOT_ERASE: u32 = 0x0C92;
const SYS_GRAPH_SLOT_WRITE: u32 = 0x0C93;
const SYS_GRAPH_SLOT_ACTIVATE: u32 = 0x0C94;
const SYS_GRAPH_SLOT_CONFIG_ADDR: u32 = 0x0C95;
const SYS_FLASH_RAW_ERASE: u32 = 0x0C38;
const SYS_FLASH_RAW_PROGRAM: u32 = 0x0C39;

const CONTINUE: i32 = 0;
const READY: i32 = 3;

// `E_AGAIN` and `E_INVAL` come from the SDK runtime.
const E_IO: i32 = -5;

/// Sentinel for opcodes that return an index or address: `-1` means
/// "no live slot" and is not a generic errno.
const NO_LIVE_SLOT: i32 = -1;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    registered: u8,
    signaled_ready: u8,
    /// Cached live-slot index: 0 = A, 1 = B, 0xFF = neither valid.
    live_slot: u8,
    _pad: u8,
    /// Cached live-slot epoch (for inactive-slot epoch bump on activate).
    live_epoch: u64,
}

// ============================================================================
// Header decoding (read-only; the combine tool writes these)
// ============================================================================

struct HeaderFields {
    epoch: u64,
    modules_offset: u32,
    modules_size: u32,
    config_offset: u32,
    config_size: u32,
    sha256: [u8; 32],
}

unsafe fn read_u32_le(p: *const u8) -> u32 {
    (core::ptr::read(p) as u32)
        | ((core::ptr::read(p.add(1)) as u32) << 8)
        | ((core::ptr::read(p.add(2)) as u32) << 16)
        | ((core::ptr::read(p.add(3)) as u32) << 24)
}

unsafe fn read_u64_le(p: *const u8) -> u64 {
    (read_u32_le(p) as u64) | ((read_u32_le(p.add(4)) as u64) << 32)
}

unsafe fn decode_header(base_xip: *const u8) -> Option<HeaderFields> {
    if read_u32_le(base_xip) != SLOT_MAGIC { return None; }
    if core::ptr::read(base_xip.add(4)) != SLOT_VERSION { return None; }
    let epoch = read_u64_le(base_xip.add(8));
    let modules_offset = read_u32_le(base_xip.add(16));
    let modules_size = read_u32_le(base_xip.add(20));
    let config_offset = read_u32_le(base_xip.add(24));
    let config_size = read_u32_le(base_xip.add(28));

    // Bounds: regions must fit inside the slot.
    if (modules_offset as u64) + (modules_size as u64) > SLOT_SIZE as u64 { return None; }
    if (config_offset as u64) + (config_size as u64) > SLOT_SIZE as u64 { return None; }

    let mut sha = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        sha[i] = core::ptr::read(base_xip.add(32 + i));
        i += 1;
    }

    Some(HeaderFields {
        epoch, modules_offset, modules_size, config_offset, config_size,
        sha256: sha,
    })
}

unsafe fn refresh_live(s: &mut State) {
    let a = (XIP_BASE + SLOT_A_OFFSET) as *const u8;
    let b = (XIP_BASE + SLOT_B_OFFSET) as *const u8;
    let ha = decode_header(a);
    let hb = decode_header(b);
    match (ha, hb) {
        (Some(ha), Some(hb)) => {
            if ha.epoch >= hb.epoch {
                s.live_slot = 0; s.live_epoch = ha.epoch;
            } else {
                s.live_slot = 1; s.live_epoch = hb.epoch;
            }
        }
        (Some(ha), None) => { s.live_slot = 0; s.live_epoch = ha.epoch; }
        (None, Some(hb)) => { s.live_slot = 1; s.live_epoch = hb.epoch; }
        (None, None) => { s.live_slot = 0xFF; s.live_epoch = 0; }
    }
}

fn slot_offset(idx: u8) -> u32 {
    if idx == 0 { SLOT_A_OFFSET } else { SLOT_B_OFFSET }
}

fn inactive_slot(live: u8) -> u8 {
    // Treat "neither live" as: slot B is the inactive write target, so a
    // first-time provisioning writes to B and promotes it. (Slot A would
    // collide with the boot image's typical flashing tooling assumption.)
    if live == 1 { 0 } else { 1 }
}

// ============================================================================
// Syscall wrappers (raw flash bridge)
// ============================================================================

unsafe fn sys_erase_sector(sys: &SyscallTable, offset: u32) -> i32 {
    let mut arg = offset.to_le_bytes();
    (sys.dev_call)(-1, SYS_FLASH_RAW_ERASE, arg.as_mut_ptr(), 4)
}

unsafe fn sys_program_page(sys: &SyscallTable, offset: u32, page: *const u8) -> i32 {
    let mut buf = [0u8; 4 + PAGE_SIZE];
    let p = buf.as_mut_ptr();
    let ob = offset.to_le_bytes();
    core::ptr::write_volatile(p.add(0), ob[0]);
    core::ptr::write_volatile(p.add(1), ob[1]);
    core::ptr::write_volatile(p.add(2), ob[2]);
    core::ptr::write_volatile(p.add(3), ob[3]);
    let mut i = 0usize;
    while i < PAGE_SIZE {
        core::ptr::write_volatile(p.add(4 + i), *page.add(i));
        i += 1;
    }
    (sys.dev_call)(-1, SYS_FLASH_RAW_PROGRAM, buf.as_mut_ptr(), 4 + PAGE_SIZE)
}

// ============================================================================
// Dispatch
// ============================================================================

#[no_mangle]
#[link_section = ".text.graph_slot_dispatch"]
pub unsafe extern "C" fn graph_slot_dispatch(
    state: *mut u8,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if state.is_null() { return E_INVAL; }
    let s = &mut *(state as *mut State);
    if s.syscalls.is_null() { return E_INVAL; }
    let sys = &*s.syscalls;

    match opcode {
        SYS_GRAPH_SLOT_ACTIVE => {
            refresh_live(s);
            if s.live_slot > 1 { NO_LIVE_SLOT } else { s.live_slot as i32 }
        }

        SYS_GRAPH_SLOT_ERASE => {
            refresh_live(s);
            let target = slot_offset(inactive_slot(s.live_slot));
            let mut off = target;
            let end = target + SLOT_SIZE;
            while off < end {
                let rc = sys_erase_sector(sys, off);
                if rc < 0 { return rc; }
                off += SECTOR_SIZE;
            }
            0
        }

        SYS_GRAPH_SLOT_WRITE => {
            if arg.is_null() || arg_len < 4 + PAGE_SIZE { return E_INVAL; }
            refresh_live(s);
            let in_slot_off = read_u32_le(arg);
            if in_slot_off + PAGE_SIZE as u32 > SLOT_SIZE { return E_INVAL; }
            let target = slot_offset(inactive_slot(s.live_slot)) + in_slot_off;
            sys_program_page(sys, target, arg.add(4))
        }

        SYS_GRAPH_SLOT_ACTIVATE => {
            refresh_live(s);
            let candidate = inactive_slot(s.live_slot);
            let base_xip = (XIP_BASE + slot_offset(candidate)) as *const u8;
            let hdr = match decode_header(base_xip) {
                Some(h) => h,
                None => return E_IO,
            };
            // If a live slot already exists, the candidate must carry a
            // strictly higher epoch. `live_slot > 1` means "no live slot
            // yet"; any valid candidate can then activate.
            let have_live = s.live_slot <= 1;
            if have_live && hdr.epoch <= s.live_epoch {
                return E_AGAIN;
            }

            // Verify SHA-256 over (modules_bytes || config_bytes).
            // Stream the XIP regions through a 1 KB scratch buffer so we
            // never hold the whole slot payload on the stack.
            let mut hasher = Sha256::new();
            hash_xip_range(&mut hasher, base_xip, hdr.modules_offset, hdr.modules_size);
            hash_xip_range(&mut hasher, base_xip, hdr.config_offset, hdr.config_size);
            let out = hasher.finalize();
            if !ct_eq32(&out, &hdr.sha256) {
                return E_IO;
            }

            s.live_slot = candidate;
            s.live_epoch = hdr.epoch;
            0
        }

        SYS_GRAPH_SLOT_CONFIG_ADDR => {
            refresh_live(s);
            if s.live_slot > 1 { return NO_LIVE_SLOT; }
            let base = XIP_BASE + slot_offset(s.live_slot);
            match decode_header(base as *const u8) {
                Some(h) => (base + h.config_offset) as i32,
                None => NO_LIVE_SLOT,
            }
        }

        _ => E_INVAL,
    }
}

fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    let mut i = 0;
    while i < 32 {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

/// Stream `size` bytes starting at `base + off` through the hasher via
/// a small on-stack scratch. The slot payload can be up to 512 KB; we
/// never materialise all of it at once.
unsafe fn hash_xip_range(hasher: &mut Sha256, base: *const u8, off: u32, size: u32) {
    const CHUNK: usize = 1024;
    let mut buf = [0u8; CHUNK];
    let mut remaining = size as usize;
    let mut cursor = off as usize;
    while remaining > 0 {
        let n = core::cmp::min(remaining, CHUNK);
        let mut i = 0;
        while i < n {
            core::ptr::write_volatile(buf.as_mut_ptr().add(i), core::ptr::read(base.add(cursor + i)));
            i += 1;
        }
        hasher.update(&buf[..n]);
        cursor += n;
        remaining -= n;
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
        s.live_slot = 0xFF;
        s.live_epoch = 0;
        refresh_live(s);
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
            let hash = fnv1a(b"graph_slot_dispatch");
            let hb = hash.to_le_bytes();
            let mut a = [hb[0], hb[1], hb[2], hb[3]];
            let rc = (sys.dev_call)(-1, SYS_GRAPH_SLOT_ENABLE, a.as_mut_ptr(), 4);
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
