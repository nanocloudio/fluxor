//! OTA ingest sink (PIC module).
//!
//! Receives a raw slot image as a byte stream on its input channel and
//! writes it into the inactive A/B graph slot via the `graph_slot`
//! syscalls. Transports (HTTP, MQTT, USB-CDC, serial) are separate
//! modules that feed this sink's input; the slot format and flash
//! mechanics live entirely in `graph_slot`, so all transports share one
//! backing implementation.
//!
//! ## Protocol
//!
//! The input stream is the raw slot image produced by `fluxor slot-image`
//! (exactly `abi::graph_slot::SLOT_SIZE` bytes — 512 KB for the current
//! layout). The module:
//!   1. Erases the inactive slot on the first received byte.
//!   2. Accumulates 256-byte pages and programs each via
//!      `GRAPH_SLOT_WRITE`.
//!   3. Emits a status event on the output channel at each phase change
//!      (erase-complete, slot-written, activation result).
//!   4. Calls `GRAPH_SLOT_ACTIVATE` once the full slot has been received.
//!
//! The input is expected to be one contiguous `SLOT_SIZE`-byte stream.
//! An interrupted stream leaves the inactive slot partially written; the
//! next `GRAPH_SLOT_ACTIVATE` call will reject it on SHA-256 mismatch,
//! and the live slot is untouched throughout. If bytes arrive past the
//! slot end — for example, two streams concatenated — the next page
//! write is rejected by `graph_slot` bounds-checking, which in turn
//! resets the sink so a fresh stream can start.
//!
//! Status event format (4 bytes): `[kind:u8, reserved:u8, rc:i16 LE]`.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// ============================================================================
// Constants
// ============================================================================

const SLOT_SIZE: u32 = abi::graph_slot::SLOT_SIZE;
const PAGE_SIZE: usize = 256;

const SYS_GRAPH_SLOT_ERASE: u32    = 0x0C92;
const SYS_GRAPH_SLOT_WRITE: u32    = 0x0C93;
const SYS_GRAPH_SLOT_ACTIVATE: u32 = 0x0C94;

const CONTINUE: i32 = 0;
const READY: i32 = 3;

// Status event kinds (1-byte). The status record is
// `[kind, 0, rc:i16 LE]` — the rc carries the syscall return code for
// diagnostic visibility.
const STATUS_ERASED: u8   = 0x01;
const STATUS_WRITTEN: u8  = 0x02;
const STATUS_ACTIVATED: u8 = 0x03;
const STATUS_FAILED: u8   = 0xFF;
const STATUS_RECORD_SIZE: usize = 4;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    in_chan: i32,
    status_chan: i32,
    signaled_ready: u8,
    /// Whether the inactive slot has been erased for this ingest.
    erased: u8,
    /// Bytes held in `page`, 0..PAGE_SIZE.
    page_fill: u16,
    /// Total bytes received since the last erase.
    byte_count: u32,
    /// Current page-aligned write offset inside the slot.
    write_offset: u32,
    /// Page assembly buffer.
    page: [u8; PAGE_SIZE],
}

// ============================================================================
// Helpers
// ============================================================================

unsafe fn emit_status(s: &State, sys: &SyscallTable, kind: u8, rc: i32) {
    if s.status_chan < 0 { return; }
    let mut rec = [0u8; STATUS_RECORD_SIZE];
    let p = rec.as_mut_ptr();
    core::ptr::write_volatile(p.add(0), kind);
    core::ptr::write_volatile(p.add(1), 0u8);
    let rb = (rc.clamp(i16::MIN as i32, i16::MAX as i32) as i16).to_le_bytes();
    core::ptr::write_volatile(p.add(2), rb[0]);
    core::ptr::write_volatile(p.add(3), rb[1]);
    let _ = (sys.channel_write)(s.status_chan, rec.as_ptr(), STATUS_RECORD_SIZE);
}

unsafe fn sys_slot_erase(sys: &SyscallTable) -> i32 {
    (sys.dev_call)(-1, SYS_GRAPH_SLOT_ERASE, core::ptr::null_mut(), 0)
}

unsafe fn sys_slot_write(sys: &SyscallTable, offset: u32, page: *const u8) -> i32 {
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
    (sys.dev_call)(-1, SYS_GRAPH_SLOT_WRITE, buf.as_mut_ptr(), 4 + PAGE_SIZE)
}

unsafe fn sys_slot_activate(sys: &SyscallTable) -> i32 {
    (sys.dev_call)(-1, SYS_GRAPH_SLOT_ACTIVATE, core::ptr::null_mut(), 0)
}

/// Reset per-ingest counters. The inactive slot remains in its current
/// state until the next `sys_slot_erase`.
fn reset_ingest(s: &mut State) {
    s.erased = 0;
    s.page_fill = 0;
    s.byte_count = 0;
    s.write_offset = 0;
}

// ============================================================================
// Ingest step
// ============================================================================

/// Consume up to `PAGE_SIZE` bytes from the input channel and advance
/// the ingest state machine. Returns 0 on continue, negative on fatal
/// ingest failure (which resets the ingest so a new stream can retry).
unsafe fn pump(s: &mut State, sys: &SyscallTable) -> i32 {
    if s.in_chan < 0 { return CONTINUE; }

    // Read into the tail of the page buffer.
    let room = PAGE_SIZE - s.page_fill as usize;
    if room == 0 {
        // The previous step filled a page but hasn't flushed; flush now.
        return flush_page(s, sys);
    }

    let mut tmp = [0u8; PAGE_SIZE];
    let rc = (sys.channel_read)(s.in_chan, tmp.as_mut_ptr(), room);
    if rc <= 0 {
        return CONTINUE;
    }
    let n = rc as usize;

    // On the first byte of a new ingest, erase the inactive slot.
    if s.erased == 0 {
        let er = sys_slot_erase(sys);
        if er < 0 {
            emit_status(s, sys, STATUS_FAILED, er);
            reset_ingest(s);
            return er;
        }
        s.erased = 1;
        emit_status(s, sys, STATUS_ERASED, 0);
    }

    // Append into the page buffer.
    let mut i = 0usize;
    while i < n {
        core::ptr::write_volatile(
            s.page.as_mut_ptr().add(s.page_fill as usize + i),
            core::ptr::read(tmp.as_ptr().add(i)),
        );
        i += 1;
    }
    s.page_fill += n as u16;
    s.byte_count += n as u32;

    // If we just filled a page, flush it.
    if s.page_fill as usize == PAGE_SIZE {
        return flush_page(s, sys);
    }
    CONTINUE
}

unsafe fn flush_page(s: &mut State, sys: &SyscallTable) -> i32 {
    let rc = sys_slot_write(sys, s.write_offset, s.page.as_ptr());
    if rc < 0 {
        emit_status(s, sys, STATUS_FAILED, rc);
        reset_ingest(s);
        return rc;
    }
    s.write_offset += PAGE_SIZE as u32;
    s.page_fill = 0;

    if s.byte_count == SLOT_SIZE {
        let ar = sys_slot_activate(sys);
        emit_status(
            s,
            sys,
            if ar == 0 { STATUS_ACTIVATED } else { STATUS_FAILED },
            ar,
        );
        reset_ingest(s);
    } else if s.write_offset & 0x3FFF == 0 {
        // Once every 16 KB, surface progress so monitors can track streaming.
        emit_status(s, sys, STATUS_WRITTEN, (s.byte_count >> 10) as i32);
    }
    CONTINUE
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
    in_chan: i32,
    out_chan: i32,
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
        s.in_chan = in_chan;
        s.status_chan = out_chan;
        s.signaled_ready = 0;
        reset_ingest(s);
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

        if s.signaled_ready == 0 {
            s.signaled_ready = 1;
            return READY;
        }

        pump(s, sys)
    }
}

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
