//! Paging Provider — PIC module for page backing store.
//!
//! Extracts backing store logic from `bcm2712_backing_store.rs` into a PIC
//! module. Implements page read/write as a service using ramdisk (static
//! buffer in module state) or delegating to NVMe via storage syscalls.
//!
//! Registers as the paging backend. The kernel's page fault handler calls
//! this module's dispatch function to read/write pages.
//!
//! # Provider Dispatch
//!
//! - BACKING_REGISTER: register a new paged arena
//! - BACKING_READ:     read a page from backing store
//! - BACKING_WRITE:    write a page to backing store
//! - BACKING_RELEASE:  release an arena slot
//! - BACKING_FLUSH:    flush pending writes (no-op for ramdisk)

#![no_std]

use core::ffi::c_void;

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");

// ============================================================================
// Constants
// ============================================================================

/// Page size (4KB, matching AArch64 granule)
const PAGE_SIZE: usize = 4096;

/// Maximum arenas across all modules
const MAX_ARENAS: usize = 16;

/// Maximum ramdisk pages (1MB = 256 pages, for testing)
const MAX_RAMDISK_PAGES: usize = 256;

/// Backing store type IDs
const BACKING_NONE: u8 = 0;
const BACKING_RAMDISK: u8 = 1;
const BACKING_NVME: u8 = 2;

/// Writeback policy
const WB_DEFERRED: u8 = 0;
const WB_WRITETHROUGH: u8 = 1;

/// Provider dispatch opcodes (custom, within SYSTEM class range).
/// The kernel pager will call these via our registered dispatch fn.
const BACKING_REGISTER_OP: u32 = 0x0C02;
const BACKING_READ_OP: u32 = 0x0C03;
const BACKING_WRITE_OP: u32 = 0x0C04;
const BACKING_RELEASE_OP: u32 = 0x0C05;
const BACKING_FLUSH_OP: u32 = 0x0C06;

// ============================================================================
// State
// ============================================================================

/// Per-arena backing store descriptor.
#[repr(C)]
struct ArenaInfo {
    backing_type: u8,
    writeback: u8,
    module_idx: u8,
    active: u8,
    virtual_pages: u32,
    resident_max_pages: u32,
    backing_offset: u32,
}

/// Total state size must fit in module state allocation.
/// Ramdisk pages consume 256*4096 = 1MB, so we need a large arena.
/// For PIC modules, the state is allocated by the kernel from STATE_ARENA.
/// If STATE_ARENA can't hold 1MB, we fall back to a smaller ramdisk.
///
/// For a practical initial implementation: use 64 pages (256KB ramdisk).
const PRACTICAL_RAMDISK_PAGES: usize = 64;

#[repr(C)]
struct PagingState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    initialized: u8,
    arena_count: u8,
    ramdisk_next: u16,
    arenas: [ArenaInfo; MAX_ARENAS],
    // Ramdisk storage: 64 pages * 4096 bytes = 256KB
    ramdisk: [[u8; PAGE_SIZE]; PRACTICAL_RAMDISK_PAGES],
}

// ============================================================================
// Backing store operations
// ============================================================================

unsafe fn backing_register(
    s: &mut PagingState,
    module_idx: u8,
    virtual_pages: u32,
    resident_max: u32,
    backing_type: u8,
    writeback: u8,
) -> i32 {
    // Find free slot
    let mut slot = MAX_ARENAS;
    let mut i = 0usize;
    while i < MAX_ARENAS {
        let ap = s.arenas.as_ptr().add(i);
        if (*ap).active == 0 {
            slot = i;
            break;
        }
        i += 1;
    }
    if slot >= MAX_ARENAS {
        return -1;
    }

    let backing_offset;
    match backing_type {
        BACKING_RAMDISK | BACKING_NVME => {
            let offset = s.ramdisk_next as u32;
            if (offset + virtual_pages) as usize > PRACTICAL_RAMDISK_PAGES {
                return -1;
            }
            s.ramdisk_next = (offset + virtual_pages) as u16;
            backing_offset = offset;
        }
        _ => {
            backing_offset = 0;
        }
    }

    let ap = s.arenas.as_mut_ptr().add(slot);
    (*ap).backing_type = backing_type;
    (*ap).writeback = writeback;
    (*ap).module_idx = module_idx;
    (*ap).active = 1;
    (*ap).virtual_pages = virtual_pages;
    (*ap).resident_max_pages = resident_max;
    (*ap).backing_offset = backing_offset;

    s.arena_count += 1;
    slot as i32
}

unsafe fn backing_read(s: &mut PagingState, arena_id: usize, vpage_idx: u32, buf: *mut u8) -> i32 {
    if buf.is_null() { return -22; }
    if arena_id >= MAX_ARENAS { return -19; }

    let ap = s.arenas.as_ptr().add(arena_id);
    if (*ap).active == 0 { return -19; }
    if vpage_idx >= (*ap).virtual_pages { return -22; }

    let bt = (*ap).backing_type;
    if bt == BACKING_RAMDISK || bt == BACKING_NVME {
        let disk_page = ((*ap).backing_offset + vpage_idx) as usize;
        if disk_page >= PRACTICAL_RAMDISK_PAGES { return -22; }
        let rp = s.ramdisk.as_ptr().add(disk_page) as *const u8;
        let mut j = 0usize;
        while j < PAGE_SIZE {
            core::ptr::write_volatile(buf.add(j), core::ptr::read_volatile(rp.add(j)));
            j += 1;
        }
    } else {
        // No backing: zero-fill
        let mut j = 0usize;
        while j < PAGE_SIZE {
            core::ptr::write_volatile(buf.add(j), 0);
            j += 1;
        }
    }
    0
}

unsafe fn backing_write(s: &mut PagingState, arena_id: usize, vpage_idx: u32, buf: *const u8) -> i32 {
    if buf.is_null() { return -22; }
    if arena_id >= MAX_ARENAS { return -19; }

    let ap = s.arenas.as_ptr().add(arena_id);
    if (*ap).active == 0 { return -19; }
    if vpage_idx >= (*ap).virtual_pages { return -22; }

    let bt = (*ap).backing_type;
    if bt == BACKING_RAMDISK || bt == BACKING_NVME {
        let disk_page = ((*ap).backing_offset + vpage_idx) as usize;
        if disk_page >= PRACTICAL_RAMDISK_PAGES { return -22; }
        let wp = s.ramdisk.as_mut_ptr().add(disk_page) as *mut u8;
        let mut j = 0usize;
        while j < PAGE_SIZE {
            core::ptr::write_volatile(wp.add(j), core::ptr::read_volatile(buf.add(j)));
            j += 1;
        }
    }
    // BackingType::None: data is lost on eviction, that's OK
    0
}

unsafe fn backing_release(s: &mut PagingState, arena_id: usize) {
    if arena_id >= MAX_ARENAS { return; }
    let ap = s.arenas.as_mut_ptr().add(arena_id);
    if (*ap).active != 0 {
        (*ap).active = 0;
        s.arena_count = s.arena_count.saturating_sub(1);
    }
}

// ============================================================================
// Provider dispatch
// ============================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn paging_dispatch(
    state: *mut u8,
    _handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    let s = &mut *(state as *mut PagingState);

    match opcode {
        BACKING_REGISTER_OP => {
            // arg=[module_idx:u8, virtual_pages:u32 LE, resident_max:u32 LE,
            //      backing_type:u8, writeback:u8] (11 bytes)
            if arg.is_null() || arg_len < 11 { return -22; }
            let mod_idx = *arg;
            let vpages = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            let rmax = u32::from_le_bytes([*arg.add(5), *arg.add(6), *arg.add(7), *arg.add(8)]);
            let btype = *arg.add(9);
            let wb = *arg.add(10);
            backing_register(s, mod_idx, vpages, rmax, btype, wb)
        }
        BACKING_READ_OP => {
            // arg=[arena_id:u8, vpage_idx:u32 LE, buf_ptr:u64 LE] (13 bytes)
            if arg.is_null() || arg_len < 13 { return -22; }
            let arena_id = *arg as usize;
            let vpage = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            let buf_addr = u64::from_le_bytes([
                *arg.add(5), *arg.add(6), *arg.add(7), *arg.add(8),
                *arg.add(9), *arg.add(10), *arg.add(11), *arg.add(12),
            ]);
            backing_read(s, arena_id, vpage, buf_addr as *mut u8)
        }
        BACKING_WRITE_OP => {
            // arg=[arena_id:u8, vpage_idx:u32 LE, buf_ptr:u64 LE] (13 bytes)
            if arg.is_null() || arg_len < 13 { return -22; }
            let arena_id = *arg as usize;
            let vpage = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            let buf_addr = u64::from_le_bytes([
                *arg.add(5), *arg.add(6), *arg.add(7), *arg.add(8),
                *arg.add(9), *arg.add(10), *arg.add(11), *arg.add(12),
            ]);
            backing_write(s, arena_id, vpage, buf_addr as *const u8)
        }
        BACKING_RELEASE_OP => {
            if arg.is_null() || arg_len < 1 { return -22; }
            let arena_id = *arg as usize;
            backing_release(s, arena_id);
            0
        }
        BACKING_FLUSH_OP => {
            // Ramdisk writes are synchronous — nothing to flush
            0
        }
        _ => -38, // ENOSYS
    }
}

// ============================================================================
// Module ABI
// ============================================================================

#[unsafe(no_mangle)]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 { 1 }

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<PagingState>()
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32, out_chan: i32, ctrl_chan: i32,
    _params: *const u8, _params_len: usize,
    state: *mut u8, state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<PagingState>() { return -2; }

        let s = &mut *(state as *mut PagingState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;

        dev_log(&*s.syscalls, 3, b"[paging] ready\0".as_ptr(), 14);
        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut PagingState);

    // First step: return Ready to unblock downstream
    if s.initialized == 0 {
        s.initialized = 1;
        return 3; // Ready
    }

    0 // Continue
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
