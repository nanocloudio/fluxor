//! Lattice KV — key-value store backed by a paged arena (E10-S8).
//!
//! Demonstrates transparent demand paging: the module uses plain pointer
//! arithmetic into its arena memory. On BCM2712 with an MMU, pages are
//! loaded on demand from backing store. On RP2350 (no MMU), the arena
//! is resident memory and all data must fit in RAM.
//!
//! # Data structure
//!
//! - Page 0: hash table header (256 buckets, 4 bytes each = 1024 bytes)
//!   Each bucket stores the byte offset of the first entry in that chain.
//!   0 = empty bucket.
//! - Pages 1+: KV entries (fixed 256 bytes each = 16 entries per page)
//!   Entry format: [key_len:u8, val_len:u8, flags:u8, _pad:u8,
//!                  next_offset:u32 LE, key:120, value:128]
//!
//! # Protocol (input channel)
//!
//! Commands are 8-byte headers followed by key/value data:
//!   GET:    [0x01, key_len, 0, 0, 0, 0, 0, 0, key_bytes...]
//!   SET:    [0x02, key_len, val_len, 0, 0, 0, 0, 0, key_bytes..., val_bytes...]
//!   DELETE: [0x03, key_len, 0, 0, 0, 0, 0, 0, key_bytes...]
//!
//! Responses on output channel:
//!   OK+data: [0x80, val_len, 0, 0, val_bytes...]
//!   NOT_FOUND: [0x81, 0, 0, 0]
//!   ERROR: [0x82, err_code, 0, 0]

#![no_std]

use core::ffi::c_void;

#[path = "../../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../pic_runtime.rs");

// ============================================================================
// Constants
// ============================================================================

const CMD_GET: u8 = 0x01;
const CMD_SET: u8 = 0x02;
const CMD_DELETE: u8 = 0x03;

const RESP_OK: u8 = 0x80;
const RESP_NOT_FOUND: u8 = 0x81;
const RESP_ERROR: u8 = 0x82;

const HASH_TABLE_BUCKETS: usize = 256;
const HASH_TABLE_SIZE: usize = HASH_TABLE_BUCKETS * 4; // 1024 bytes

const ENTRY_SIZE: usize = 256;
const ENTRY_KEY_MAX: usize = 120;
const ENTRY_VAL_MAX: usize = 128;
const ENTRY_HEADER: usize = 8; // key_len + val_len + flags + pad + next_offset

const CMD_HEADER_SIZE: usize = 8;

/// Offset in arena where entries start (after hash table + padding).
const ENTRIES_BASE: usize = 4096; // Align to page boundary

// Entry flags
const FLAG_USED: u8 = 0x01;
const FLAG_DELETED: u8 = 0x02;

// ============================================================================
// Module state
// ============================================================================

#[repr(C)]
struct State {
    sys: *const SyscallTable,
    in_ch: i32,
    out_ch: i32,
    /// Pointer to arena memory (paged or resident).
    arena_ptr: *mut u8,
    /// Arena size in bytes.
    arena_size: u32,
    /// Number of entries currently allocated.
    entry_count: u32,
    /// Maximum entries that fit in the arena.
    max_entries: u32,
    /// Whether arena is valid and initialized.
    initialized: bool,
    _pad: [u8; 3],
}

// ============================================================================
// Hash function (FNV-1a 32-bit)
// ============================================================================

fn hash_key(key: *const u8, key_len: usize) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    let mut i = 0;
    while i < key_len {
        let b = unsafe { *key.add(i) };
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
        i += 1;
    }
    h
}

// ============================================================================
// Arena access helpers
// ============================================================================

/// Read a u32 from arena at byte offset.
#[inline]
unsafe fn arena_read_u32(base: *const u8, offset: usize) -> u32 {
    let p = base.add(offset);
    u32::from_le_bytes([
        core::ptr::read_volatile(p),
        core::ptr::read_volatile(p.add(1)),
        core::ptr::read_volatile(p.add(2)),
        core::ptr::read_volatile(p.add(3)),
    ])
}

/// Write a u32 to arena at byte offset.
#[inline]
unsafe fn arena_write_u32(base: *mut u8, offset: usize, val: u32) {
    let p = base.add(offset);
    let bytes = val.to_le_bytes();
    core::ptr::write_volatile(p, bytes[0]);
    core::ptr::write_volatile(p.add(1), bytes[1]);
    core::ptr::write_volatile(p.add(2), bytes[2]);
    core::ptr::write_volatile(p.add(3), bytes[3]);
}

/// Get bucket offset in hash table.
#[inline]
fn bucket_offset(bucket: usize) -> usize {
    bucket * 4
}

/// Get entry byte offset from entry index.
#[inline]
fn entry_offset(entry_idx: u32) -> usize {
    ENTRIES_BASE + (entry_idx as usize) * ENTRY_SIZE
}

// ============================================================================
// KV operations
// ============================================================================

/// Look up a key. Returns entry index or u32::MAX if not found.
unsafe fn kv_lookup(state: &State, key: *const u8, key_len: usize) -> u32 {
    let arena = state.arena_ptr;
    let bucket = (hash_key(key, key_len) as usize) & (HASH_TABLE_BUCKETS - 1);
    let mut entry_idx_plus1 = arena_read_u32(arena, bucket_offset(bucket));

    let mut iterations = 0u32;
    while entry_idx_plus1 != 0 && iterations < 1000 {
        let idx = entry_idx_plus1 - 1;
        let off = entry_offset(idx);
        if off + ENTRY_SIZE > state.arena_size as usize {
            break;
        }

        let e_key_len = core::ptr::read_volatile(arena.add(off)) as usize;
        let e_flags = core::ptr::read_volatile(arena.add(off + 2));

        if (e_flags & FLAG_USED) != 0
            && (e_flags & FLAG_DELETED) == 0
            && e_key_len == key_len
        {
            // Compare keys byte by byte (no indexing — pointer arithmetic)
            let mut match_ok = true;
            let mut k = 0;
            while k < key_len {
                let a = core::ptr::read_volatile(arena.add(off + ENTRY_HEADER + k));
                let b = core::ptr::read_volatile(key.add(k));
                if a != b {
                    match_ok = false;
                    break;
                }
                k += 1;
            }
            if match_ok {
                return idx;
            }
        }

        // Follow chain
        entry_idx_plus1 = arena_read_u32(arena, off + 4);
        iterations += 1;
    }

    u32::MAX
}

/// Allocate a new entry. Returns entry index or u32::MAX.
unsafe fn kv_alloc_entry(state: &mut State) -> u32 {
    if state.entry_count >= state.max_entries {
        return u32::MAX;
    }
    let idx = state.entry_count;
    state.entry_count += 1;
    idx
}

/// SET operation.
unsafe fn kv_set(state: &mut State, key: *const u8, key_len: usize, val: *const u8, val_len: usize) -> bool {
    if key_len > ENTRY_KEY_MAX || val_len > ENTRY_VAL_MAX {
        return false;
    }

    let arena = state.arena_ptr;

    // Check if key already exists
    let existing = kv_lookup(state, key, key_len);
    if existing != u32::MAX {
        // Update value in place
        let off = entry_offset(existing);
        core::ptr::write_volatile(arena.add(off + 1), val_len as u8);
        let mut v = 0;
        while v < val_len {
            core::ptr::write_volatile(
                arena.add(off + ENTRY_HEADER + ENTRY_KEY_MAX + v),
                core::ptr::read_volatile(val.add(v)),
            );
            v += 1;
        }
        return true;
    }

    // Allocate new entry
    let idx = kv_alloc_entry(state);
    if idx == u32::MAX {
        return false;
    }

    let off = entry_offset(idx);
    if off + ENTRY_SIZE > state.arena_size as usize {
        return false;
    }

    // Write entry header
    core::ptr::write_volatile(arena.add(off), key_len as u8);
    core::ptr::write_volatile(arena.add(off + 1), val_len as u8);
    core::ptr::write_volatile(arena.add(off + 2), FLAG_USED);
    core::ptr::write_volatile(arena.add(off + 3), 0); // pad

    // Link into hash chain: new entry becomes head
    let bucket = (hash_key(key, key_len) as usize) & (HASH_TABLE_BUCKETS - 1);
    let old_head = arena_read_u32(arena, bucket_offset(bucket));
    arena_write_u32(arena, off + 4, old_head); // next = old head
    arena_write_u32(arena, bucket_offset(bucket), idx + 1); // bucket = this entry (1-based)

    // Write key
    let mut k = 0;
    while k < key_len {
        core::ptr::write_volatile(
            arena.add(off + ENTRY_HEADER + k),
            core::ptr::read_volatile(key.add(k)),
        );
        k += 1;
    }

    // Write value
    let mut v = 0;
    while v < val_len {
        core::ptr::write_volatile(
            arena.add(off + ENTRY_HEADER + ENTRY_KEY_MAX + v),
            core::ptr::read_volatile(val.add(v)),
        );
        v += 1;
    }

    true
}

/// GET operation. Writes response to output channel.
unsafe fn kv_get(state: &State, key: *const u8, key_len: usize) -> bool {
    let idx = kv_lookup(state, key, key_len);
    if idx == u32::MAX {
        // Not found
        let resp = [RESP_NOT_FOUND, 0, 0, 0];
        ((*state.sys).channel_write)(state.out_ch, resp.as_ptr(), 4);
        return false;
    }

    let arena = state.arena_ptr;
    let off = entry_offset(idx);
    let val_len = core::ptr::read_volatile(arena.add(off + 1)) as usize;

    // Write response: [0x80, val_len, 0, 0, value_bytes...]
    let mut resp = [0u8; 4 + ENTRY_VAL_MAX];
    let rp = resp.as_mut_ptr();
    core::ptr::write_volatile(rp, RESP_OK);
    core::ptr::write_volatile(rp.add(1), val_len as u8);

    let mut v = 0;
    while v < val_len {
        core::ptr::write_volatile(
            rp.add(4 + v),
            core::ptr::read_volatile(arena.add(off + ENTRY_HEADER + ENTRY_KEY_MAX + v)),
        );
        v += 1;
    }

    ((*state.sys).channel_write)(state.out_ch, resp.as_ptr(), 4 + val_len);
    true
}

/// DELETE operation.
unsafe fn kv_delete(state: &State, key: *const u8, key_len: usize) -> bool {
    let idx = kv_lookup(state, key, key_len);
    if idx == u32::MAX {
        return false;
    }

    // Mark as deleted
    let arena = state.arena_ptr;
    let off = entry_offset(idx);
    let flags = core::ptr::read_volatile(arena.add(off + 2));
    core::ptr::write_volatile(arena.add(off + 2), flags | FLAG_DELETED);

    true
}

// ============================================================================
// Module ABI exports
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const core::ffi::c_void) {}

#[no_mangle]
pub unsafe extern "C" fn module_new(
    in_ch: i32,
    out_ch: i32,
    _ctrl_ch: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if state_size < core::mem::size_of::<State>() {
        return -1;
    }

    let sys = syscalls as *const SyscallTable;
    let s = state as *mut State;

    (*s).sys = sys;
    (*s).in_ch = in_ch;
    (*s).out_ch = out_ch;
    (*s).arena_ptr = core::ptr::null_mut();
    (*s).arena_size = 0;
    (*s).entry_count = 0;
    (*s).max_entries = 0;
    (*s).initialized = false;

    // Try paged arena first (BCM2712 with MMU)
    let (pa_ptr, pa_size, pa_status) = dev_paged_arena_get(&*sys);
    if pa_status == 1 && !pa_ptr.is_null() && pa_size > 0 {
        (*s).arena_ptr = pa_ptr;
        (*s).arena_size = pa_size as u32;

        // Prefault the hash table page
        dev_paged_arena_prefault(&*sys, 0, 1);
    } else {
        // Fall back to resident arena (RP2350 or no paged arena configured)
        let (a_ptr, a_size) = dev_arena_get(&*sys);
        if !a_ptr.is_null() && a_size > 0 {
            (*s).arena_ptr = a_ptr;
            (*s).arena_size = a_size;
        }
    }

    if (*s).arena_ptr.is_null() || (*s).arena_size < (ENTRIES_BASE + ENTRY_SIZE) as u32 {
        // No usable arena — module is non-functional but won't crash
        return 0;
    }

    // Calculate max entries
    let usable = (*s).arena_size as usize - ENTRIES_BASE;
    (*s).max_entries = (usable / ENTRY_SIZE) as u32;
    (*s).initialized = true;

    // Zero the hash table (first HASH_TABLE_SIZE bytes)
    let mut i = 0;
    while i < HASH_TABLE_SIZE {
        core::ptr::write_volatile((*s).arena_ptr.add(i), 0);
        i += 1;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn module_step(state: *mut u8) -> i32 {
    let s = state as *mut State;
    if !(*s).initialized {
        return 0; // Continue (no-op)
    }

    let sys = &*(*s).sys;

    // Read command from input channel
    let mut cmd_buf = [0u8; CMD_HEADER_SIZE + ENTRY_KEY_MAX + ENTRY_VAL_MAX];
    let n = (sys.channel_read)((*s).in_ch, cmd_buf.as_mut_ptr(), cmd_buf.len());
    if n <= 0 {
        return 0; // No command, continue
    }

    if (n as usize) < CMD_HEADER_SIZE {
        return 0; // Malformed
    }

    let bp = cmd_buf.as_ptr();
    let cmd = *bp;
    let key_len = *bp.add(1) as usize;

    if key_len == 0 || key_len > ENTRY_KEY_MAX {
        let resp = [RESP_ERROR, 22, 0, 0]; // EINVAL
        (sys.channel_write)((*s).out_ch, resp.as_ptr(), 4);
        return 0;
    }

    let key_ptr = bp.add(CMD_HEADER_SIZE);

    match cmd {
        CMD_GET => {
            kv_get(&*s, key_ptr, key_len);
        }
        CMD_SET => {
            let val_len = *bp.add(2) as usize;
            if val_len > ENTRY_VAL_MAX {
                let resp = [RESP_ERROR, 22, 0, 0];
                (sys.channel_write)((*s).out_ch, resp.as_ptr(), 4);
                return 0;
            }
            let val_ptr = cmd_buf.as_ptr().add(CMD_HEADER_SIZE + key_len);
            let ok = kv_set(&mut *s, key_ptr, key_len, val_ptr, val_len);
            if ok {
                let resp = [RESP_OK, 0, 0, 0];
                (sys.channel_write)((*s).out_ch, resp.as_ptr(), 4);
            } else {
                let resp = [RESP_ERROR, 12, 0, 0]; // ENOMEM
                (sys.channel_write)((*s).out_ch, resp.as_ptr(), 4);
            }
        }
        CMD_DELETE => {
            let ok = kv_delete(&*s, key_ptr, key_len);
            if ok {
                let resp = [RESP_OK, 0, 0, 0];
                (sys.channel_write)((*s).out_ch, resp.as_ptr(), 4);
            } else {
                let resp = [RESP_NOT_FOUND, 0, 0, 0];
                (sys.channel_write)((*s).out_ch, resp.as_ptr(), 4);
            }
        }
        _ => {
            let resp = [RESP_ERROR, 38, 0, 0]; // ENOSYS
            (sys.channel_write)((*s).out_ch, resp.as_ptr(), 4);
        }
    }

    0 // Continue
}

#[no_mangle]
pub unsafe extern "C" fn module_arena_size() -> u32 {
    // Request 64KB resident arena as fallback (RP2350 without paged arena)
    // On BCM2712, the paged arena is used instead.
    65536
}
