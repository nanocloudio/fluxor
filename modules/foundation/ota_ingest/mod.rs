//! OTA ingest — stream a graph bundle into the inactive slot.
//!
//! Reads a raw byte stream from `in_chan[0]` (normally wired from an
//! HTTP or net-tap source), accumulates it into 256-byte pages, and
//! forwards each page to the graph_slot service via channels.
//!
//! ## Wiring
//!
//! ```yaml
//! wiring:
//!   - from: http_client.body     # or whatever feeds the bundle bytes
//!     to:   ota_ingest.in
//!   - from: ota_ingest.status    # optional status records
//!     to:   log.in
//!   - from: ota_ingest.gs_req    # (out port 1) OTA → graph_slot requests
//!     to:   graph_slot.in
//!   - from: graph_slot.out       # graph_slot responses
//!     to:   ota_ingest.gs_resp   # (in port 1)
//! ```
//!
//! ## Protocol
//!
//! Uses the FMP channel protocol defined in
//! `abi::contracts::storage::graph_slot::channel`. OTA issues ERASE,
//! WRITE(offset, page), ACTIVATE in sequence, waiting for each
//! response on the graph_slot reply channel before advancing.
//!
//! ## State records
//!
//! Emitted on `out_chan[0]` (status_chan) as 4-byte records
//! `[kind:u8][_pad:u8][rc:i16 LE]`:
//!
//! - `kind=0x01` ERASED    rc=0
//! - `kind=0x02` WRITTEN   rc=bytes_written_so_far >> 10 (KB)
//! - `kind=0x03` ACTIVATED rc=0
//! - `kind=0xFF` FAILED    rc=negative errno

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;
use abi::platform::rp::flash_layout::GRAPH_SLOT_SIZE as SLOT_SIZE;
use abi::contracts::storage::graph_slot::channel::{
    REQ_ERASE, REQ_WRITE, REQ_ACTIVATE, RESP_RESULT,
    FRAME_HDR, RESP_PAYLOAD, RESP_FRAME_LEN,
};

include!("../../sdk/runtime.rs");

// ============================================================================
// Constants
// ============================================================================

const PAGE_SIZE: usize = 256;

const CONTINUE: i32 = 0;
const READY: i32 = 3;

// Extra port indices (primary in/out are index 0).
const PORT_IN_GS_RESP: u32 = 1;   // graph_slot response channel
const PORT_OUT_GS_REQ: u32 = 1;   // graph_slot request channel

// Status record kinds.
const STATUS_ERASED: u8   = 0x01;
const STATUS_WRITTEN: u8  = 0x02;
const STATUS_ACTIVATED: u8 = 0x03;
const STATUS_FAILED: u8   = 0xFF;
const STATUS_RECORD_SIZE: usize = 4;

// Ingest state machine.
const ST_IDLE: u8          = 0;  // waiting for first input byte
const ST_AWAIT_ERASE: u8   = 1;  // erase request sent, awaiting response
const ST_STREAMING: u8     = 2;  // accepting input, writing pages
const ST_AWAIT_WRITE: u8   = 3;  // write request sent, awaiting response
const ST_AWAIT_ACTIVATE: u8 = 4; // activate request sent, awaiting response
const ST_FAILED: u8        = 0xFF;

/// Full WRITE request frame: 6 header + 260 payload = 266.
const REQ_WRITE_FRAME_LEN: usize = FRAME_HDR + 4 + PAGE_SIZE;
/// Bare request frame (no payload): ERASE / ACTIVATE = 6 bytes.
const REQ_BARE_FRAME_LEN: usize = FRAME_HDR;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    in_chan: i32,
    status_chan: i32,
    gs_req_chan: i32,
    gs_resp_chan: i32,
    signaled_ready: u8,
    state: u8,
    /// Bytes buffered in `page`, 0..PAGE_SIZE.
    page_fill: u16,
    /// Total bytes received since the last erase.
    byte_count: u32,
    /// Current page-aligned write offset inside the slot.
    write_offset: u32,
    /// Page assembly buffer.
    page: [u8; PAGE_SIZE],
    /// Partial response frame accumulator.
    resp_buf: [u8; RESP_FRAME_LEN],
    resp_fill: u16,
}

// ============================================================================
// Helpers
// ============================================================================

fn write_u32_le(dst: &mut [u8], offset: usize, value: u32) {
    let b = value.to_le_bytes();
    dst[offset]     = b[0];
    dst[offset + 1] = b[1];
    dst[offset + 2] = b[2];
    dst[offset + 3] = b[3];
}

fn write_u16_le(dst: &mut [u8], offset: usize, value: u16) {
    let b = value.to_le_bytes();
    dst[offset]     = b[0];
    dst[offset + 1] = b[1];
}

unsafe fn read_u32_le(p: *const u8) -> u32 {
    (core::ptr::read(p) as u32)
        | ((core::ptr::read(p.add(1)) as u32) << 8)
        | ((core::ptr::read(p.add(2)) as u32) << 16)
        | ((core::ptr::read(p.add(3)) as u32) << 24)
}

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

unsafe fn send_bare_request(s: &State, sys: &SyscallTable, req_type: u32) -> bool {
    if s.gs_req_chan < 0 { return false; }
    let mut frame = [0u8; REQ_BARE_FRAME_LEN];
    write_u32_le(&mut frame, 0, req_type);
    write_u16_le(&mut frame, 4, 0);
    let n = (sys.channel_write)(s.gs_req_chan, frame.as_ptr(), REQ_BARE_FRAME_LEN);
    n as usize == REQ_BARE_FRAME_LEN
}

unsafe fn send_write_request(s: &State, sys: &SyscallTable, offset: u32) -> bool {
    if s.gs_req_chan < 0 { return false; }
    let mut frame = [0u8; REQ_WRITE_FRAME_LEN];
    write_u32_le(&mut frame, 0, REQ_WRITE);
    write_u16_le(&mut frame, 4, (4 + PAGE_SIZE) as u16);
    write_u32_le(&mut frame, FRAME_HDR, offset);
    let page_dst = FRAME_HDR + 4;
    let mut i = 0usize;
    while i < PAGE_SIZE {
        frame[page_dst + i] = core::ptr::read(s.page.as_ptr().add(i));
        i += 1;
    }
    let n = (sys.channel_write)(s.gs_req_chan, frame.as_ptr(), REQ_WRITE_FRAME_LEN);
    n as usize == REQ_WRITE_FRAME_LEN
}

/// Attempt to read one graph_slot response frame. Returns
/// `Some((echoed_req_type, value))` when a full frame is available,
/// `None` otherwise.
unsafe fn poll_response(s: &mut State, sys: &SyscallTable) -> Option<(u32, i32)> {
    if s.gs_resp_chan < 0 { return None; }
    let room = RESP_FRAME_LEN - s.resp_fill as usize;
    if room > 0 {
        let tail = s.resp_buf.as_mut_ptr().add(s.resp_fill as usize);
        let n = (sys.channel_read)(s.gs_resp_chan, tail, room);
        if n > 0 {
            s.resp_fill += n as u16;
        }
    }
    if (s.resp_fill as usize) < RESP_FRAME_LEN { return None; }
    // Validate the frame.
    let ty = read_u32_le(s.resp_buf.as_ptr());
    let len = u16::from_le_bytes([s.resp_buf[4], s.resp_buf[5]]) as usize;
    if ty != RESP_RESULT || len != RESP_PAYLOAD {
        // Malformed — drop and resync.
        s.resp_fill = 0;
        return None;
    }
    let echoed = read_u32_le(s.resp_buf.as_ptr().add(FRAME_HDR));
    let value = read_u32_le(s.resp_buf.as_ptr().add(FRAME_HDR + 4)) as i32;
    s.resp_fill = 0;
    Some((echoed, value))
}

fn reset_ingest(s: &mut State) {
    s.state = ST_IDLE;
    s.page_fill = 0;
    s.byte_count = 0;
    s.write_offset = 0;
    s.resp_fill = 0;
}

fn fail(s: &mut State, sys: &SyscallTable, rc: i32) {
    unsafe { emit_status(s, sys, STATUS_FAILED, rc); }
    reset_ingest(s);
    s.state = ST_FAILED;
}

// ============================================================================
// State machine
// ============================================================================

unsafe fn pump(s: &mut State, sys: &SyscallTable) -> i32 {
    // ST_FAILED is sticky until the caller resets by sending fresh data
    // — we re-arm to IDLE on the next byte so a new attempt can start.
    if s.state == ST_FAILED {
        // Drain any lingering response frames so they don't confuse
        // subsequent runs.
        let _ = poll_response(s, sys);
        // Peek input; any byte clears the failed flag and restarts.
        let mut peek = [0u8; 1];
        if s.in_chan >= 0 && (sys.channel_read)(s.in_chan, peek.as_mut_ptr(), 1) > 0 {
            // Restart: treat the peeked byte as the first byte of a new
            // stream. We need to re-enqueue it into the page buffer.
            reset_ingest(s);
            core::ptr::write_volatile(s.page.as_mut_ptr(), peek[0]);
            s.page_fill = 1;
            s.byte_count = 1;
            // Fall through to IDLE → request erase.
        } else {
            return CONTINUE;
        }
    }

    match s.state {
        ST_IDLE => {
            if s.in_chan < 0 { return CONTINUE; }
            // On the first byte, send ERASE and transition.
            if s.page_fill == 0 {
                let mut peek = [0u8; 1];
                let n = (sys.channel_read)(s.in_chan, peek.as_mut_ptr(), 1);
                if n <= 0 { return CONTINUE; }
                core::ptr::write_volatile(s.page.as_mut_ptr(), peek[0]);
                s.page_fill = 1;
                s.byte_count = 1;
            }
            if !send_bare_request(s, sys, REQ_ERASE) {
                fail(s, sys, E_AGAIN);
                return CONTINUE;
            }
            s.state = ST_AWAIT_ERASE;
            CONTINUE
        }
        ST_AWAIT_ERASE => {
            if let Some((echoed, rc)) = poll_response(s, sys) {
                if echoed != REQ_ERASE { return CONTINUE; }
                if rc < 0 { fail(s, sys, rc); return CONTINUE; }
                emit_status(s, sys, STATUS_ERASED, 0);
                s.state = ST_STREAMING;
            }
            CONTINUE
        }
        ST_STREAMING => {
            // Keep filling the page buffer from input.
            let room = PAGE_SIZE - s.page_fill as usize;
            if room > 0 && s.in_chan >= 0 {
                let mut tmp = [0u8; PAGE_SIZE];
                let n = (sys.channel_read)(s.in_chan, tmp.as_mut_ptr(), room);
                if n > 0 {
                    let n = n as usize;
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
                }
            }
            if s.page_fill as usize == PAGE_SIZE {
                if !send_write_request(s, sys, s.write_offset) {
                    fail(s, sys, E_AGAIN);
                    return CONTINUE;
                }
                s.state = ST_AWAIT_WRITE;
            }
            CONTINUE
        }
        ST_AWAIT_WRITE => {
            if let Some((echoed, rc)) = poll_response(s, sys) {
                if echoed != REQ_WRITE { return CONTINUE; }
                if rc < 0 { fail(s, sys, rc); return CONTINUE; }
                s.write_offset += PAGE_SIZE as u32;
                s.page_fill = 0;
                if s.write_offset & 0x3FFF == 0 {
                    emit_status(s, sys, STATUS_WRITTEN, (s.byte_count >> 10) as i32);
                }
                if s.byte_count == SLOT_SIZE {
                    if !send_bare_request(s, sys, REQ_ACTIVATE) {
                        fail(s, sys, E_AGAIN);
                        return CONTINUE;
                    }
                    s.state = ST_AWAIT_ACTIVATE;
                } else {
                    s.state = ST_STREAMING;
                }
            }
            CONTINUE
        }
        ST_AWAIT_ACTIVATE => {
            if let Some((echoed, rc)) = poll_response(s, sys) {
                if echoed != REQ_ACTIVATE { return CONTINUE; }
                emit_status(
                    s, sys,
                    if rc == 0 { STATUS_ACTIVATED } else { STATUS_FAILED },
                    rc,
                );
                reset_ingest(s);
            }
            CONTINUE
        }
        _ => CONTINUE,
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
        s.state = ST_IDLE;
        s.page_fill = 0;
        s.byte_count = 0;
        s.write_offset = 0;
        s.resp_fill = 0;
        // Extra ports resolved in module_step when we know the syscall table is live.
        s.gs_req_chan = -1;
        s.gs_resp_chan = -1;
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
            // Resolve extra ports once.
            s.gs_req_chan = channel_port_out(sys, PORT_OUT_GS_REQ);
            s.gs_resp_chan = channel_port_in(sys, PORT_IN_GS_RESP);
            s.signaled_ready = 1;
            return READY;
        }

        pump(s, sys)
    }
}

/// Resolve an extra output port by index via the `channel::PORT` opcode.
/// Returns -1 if unwired.
unsafe fn channel_port_out(sys: &SyscallTable, index: u32) -> i32 {
    // PORT opcode: handle=-1, arg=[port_type:u8, index:u8]
    let mut arg = [1u8, index as u8]; // 1 = out
    (sys.provider_call)(
        -1,
        abi::kernel_abi::channel::PORT,
        arg.as_mut_ptr(),
        arg.len(),
    )
}

unsafe fn channel_port_in(sys: &SyscallTable, index: u32) -> i32 {
    let mut arg = [0u8, index as u8]; // 0 = in
    (sys.provider_call)(
        -1,
        abi::kernel_abi::channel::PORT,
        arg.as_mut_ptr(),
        arg.len(),
    )
}

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
