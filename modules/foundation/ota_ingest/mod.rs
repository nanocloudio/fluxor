//! OTA ingest — stream a graph bundle into the inactive slot.
//!
//! Reads a raw byte stream from `in_chan[0]` (normally wired from an
//! HTTP or net-tap source), accumulates it into 256-byte pages, and
//! forwards each page to the graph_slot service via channels.
//!
//! An image is as long as its header says, not as long as a slot: the
//! header page names where the modules and the config end, the image is
//! activated once that much is written, and one longer than this board's
//! slot (`FLASH_LAYOUT`) is refused before anything is erased. Nothing is
//! erased until a whole header page has arrived, and bytes that do not
//! start with the image magic ("FXSL") -- the padding after an image, the
//! rest of one that was refused -- are dropped until one does.
//!
//! ## Wiring
//!
//! ```yaml
//! wiring:
//!   - from: stream_intake.bytes  # or whatever feeds the bundle bytes
//!     to:   ota_ingest.stream
//!   - from: ota_ingest.status    # optional status records
//!     to:   log.in
//!   - from: ota_ingest.gs_req    # (out port 1) OTA → graph_slot requests
//!     to:   graph_slot.requests
//!   - from: graph_slot.results   # graph_slot responses
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

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::contracts::storage::graph_slot::channel::{
    FRAME_HDR, REQ_ACTIVATE, REQ_ERASE, REQ_WRITE, RESP_FRAME_LEN, RESP_PAYLOAD, RESP_RESULT,
};
use abi::platform::rp::flash_layout::{GraphFlash, GRAPH_FLASH_LEN, GRAPH_SLOT_MAGIC};
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// ============================================================================
// Constants
// ============================================================================

const PAGE_SIZE: usize = 256;
/// A graph image's first four bytes, "FXSL".
const MAGIC: [u8; 4] = GRAPH_SLOT_MAGIC.to_le_bytes();

const CONTINUE: i32 = 0;
const READY: i32 = 3;

// Extra port indices (primary in/out are index 0).
const PORT_IN_GS_RESP: u32 = 1; // graph_slot response channel
const PORT_OUT_GS_REQ: u32 = 1; // graph_slot request channel

// Status record kinds.
const STATUS_ERASED: u8 = 0x01;
const STATUS_WRITTEN: u8 = 0x02;
const STATUS_ACTIVATED: u8 = 0x03;
const STATUS_FAILED: u8 = 0xFF;
const STATUS_RECORD_SIZE: usize = 4;

// Ingest state machine.
const ST_IDLE: u8 = 0; // waiting for first input byte
const ST_AWAIT_ERASE: u8 = 1; // erase request sent, awaiting response
const ST_STREAMING: u8 = 2; // accepting input, writing pages
const ST_AWAIT_WRITE: u8 = 3; // write request sent, awaiting response
const ST_AWAIT_ACTIVATE: u8 = 4; // activate request sent, awaiting response
const ST_FAILED: u8 = 0xFF;

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
    /// This board's slot size, from the kernel (`FLASH_LAYOUT`); 0 when it
    /// has no slots, and every image is refused.
    slot_size: u32,
    /// Where the image being written ends, page-aligned, as its header says:
    /// it is activated once that much is written, so it is sent unpadded.
    /// 0 until the header page has arrived.
    image_end: u32,
    /// Page assembly buffer.
    page: [u8; PAGE_SIZE],
    /// Partial response frame accumulator.
    resp_buf: [u8; RESP_FRAME_LEN],
    resp_fill: u16,
}

// ============================================================================
// Helpers
// ============================================================================

/// Where an image ends, from its header page: the further of its two
/// regions, rounded up to a whole page. `None` for a header that names no
/// region past itself, or one longer than this board's slot.
fn declared_end(header: &[u8; PAGE_SIZE], slot_size: u32) -> Option<u32> {
    let word = |at: usize| {
        u32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]]) as u64
    };
    let modules_end = word(16) + word(20);
    let config_end = word(24) + word(28);
    let end = modules_end.max(config_end).div_ceil(PAGE_SIZE as u64) * PAGE_SIZE as u64;
    if end <= PAGE_SIZE as u64 || end > slot_size as u64 {
        return None;
    }
    Some(end as u32)
}

fn write_u32_le(dst: &mut [u8], offset: usize, value: u32) {
    let b = value.to_le_bytes();
    dst[offset] = b[0];
    dst[offset + 1] = b[1];
    dst[offset + 2] = b[2];
    dst[offset + 3] = b[3];
}

fn write_u16_le(dst: &mut [u8], offset: usize, value: u16) {
    let b = value.to_le_bytes();
    dst[offset] = b[0];
    dst[offset + 1] = b[1];
}

unsafe fn read_u32_le(p: *const u8) -> u32 {
    (core::ptr::read(p) as u32)
        | ((core::ptr::read(p.add(1)) as u32) << 8)
        | ((core::ptr::read(p.add(2)) as u32) << 16)
        | ((core::ptr::read(p.add(3)) as u32) << 24)
}

unsafe fn emit_status(s: &State, sys: &SyscallTable, kind: u8, rc: i32) {
    log_status(sys, kind, rc);
    if s.status_chan < 0 {
        return;
    }
    let mut rec = [0u8; STATUS_RECORD_SIZE];
    let p = rec.as_mut_ptr();
    core::ptr::write_volatile(p.add(0), kind);
    core::ptr::write_volatile(p.add(1), 0u8);
    let rb = (rc.clamp(i16::MIN as i32, i16::MAX as i32) as i16).to_le_bytes();
    core::ptr::write_volatile(p.add(2), rb[0]);
    core::ptr::write_volatile(p.add(3), rb[1]);
    let _ = (sys.channel_write)(s.status_chan, rec.as_ptr(), STATUS_RECORD_SIZE);
}

/// Say a status record in the log as well, so a board with nothing wired to
/// `status` still shows how far an image got.
unsafe fn log_status(sys: &SyscallTable, kind: u8, rc: i32) {
    let text: &[u8] = match kind {
        STATUS_ERASED => b"[ota] erased",
        STATUS_WRITTEN => b"[ota] written kib=",
        STATUS_ACTIVATED => b"[ota] activated",
        _ => b"[ota] failed rc=-",
    };
    let mut line = [0u8; 40];
    let mut len = 0usize;
    let mut i = 0usize;
    while i < text.len() && len < line.len() {
        line[len] = text[i];
        len += 1;
        i += 1;
    }
    if kind == STATUS_WRITTEN || kind == STATUS_FAILED {
        let mut v = rc.unsigned_abs();
        let mut digits = [0u8; 10];
        let mut n = 0usize;
        loop {
            digits[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
            if v == 0 || n == digits.len() {
                break;
            }
        }
        while n > 0 && len < line.len() {
            n -= 1;
            line[len] = digits[n];
            len += 1;
        }
    }
    dev_log(sys, 3, line.as_ptr(), len);
}

unsafe fn send_bare_request(s: &State, sys: &SyscallTable, req_type: u32) -> bool {
    if s.gs_req_chan < 0 {
        return false;
    }
    let mut frame = [0u8; REQ_BARE_FRAME_LEN];
    write_u32_le(&mut frame, 0, req_type);
    write_u16_le(&mut frame, 4, 0);
    let n = (sys.channel_write)(s.gs_req_chan, frame.as_ptr(), REQ_BARE_FRAME_LEN);
    n as usize == REQ_BARE_FRAME_LEN
}

unsafe fn send_write_request(s: &State, sys: &SyscallTable, offset: u32) -> bool {
    if s.gs_req_chan < 0 {
        return false;
    }
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
    if s.gs_resp_chan < 0 {
        return None;
    }
    let room = RESP_FRAME_LEN - s.resp_fill as usize;
    if room > 0 {
        let tail = s.resp_buf.as_mut_ptr().add(s.resp_fill as usize);
        let n = (sys.channel_read)(s.gs_resp_chan, tail, room);
        if n > 0 {
            s.resp_fill += n as u16;
        }
    }
    if (s.resp_fill as usize) < RESP_FRAME_LEN {
        return None;
    }
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
    s.image_end = 0;
    s.resp_fill = 0;
}

fn fail(s: &mut State, sys: &SyscallTable, rc: i32) {
    unsafe {
        emit_status(s, sys, STATUS_FAILED, rc);
    }
    reset_ingest(s);
    s.state = ST_FAILED;
}

// ============================================================================
// State machine
// ============================================================================

unsafe fn pump(s: &mut State, sys: &SyscallTable) -> i32 {
    // A failure is reported once and the ingest goes back to waiting for an
    // image: what follows on the stream (the rest of the one refused) is
    // not one, and the idle state drops it until a header's magic arrives.
    if s.state == ST_FAILED {
        // Drain any lingering response frames so they don't confuse
        // subsequent runs.
        let _ = poll_response(s, sys);
        reset_ingest(s);
    }

    match s.state {
        ST_IDLE => {
            if s.in_chan < 0 {
                return CONTINUE;
            }
            // Gather the header page before erasing anything. An image
            // starts with its magic, so bytes that do not -- the padding
            // after one, the rest of one refused -- are dropped as they
            // come, and an image that follows them is found wherever it
            // starts.
            let room = PAGE_SIZE - s.page_fill as usize;
            let mut tmp = [0u8; PAGE_SIZE];
            let n = (sys.channel_read)(s.in_chan, tmp.as_mut_ptr(), room);
            let mut i = 0usize;
            while n > 0 && i < n as usize {
                let b = core::ptr::read(tmp.as_ptr().add(i));
                i += 1;
                let at = s.page_fill as usize;
                if at < 4 && b != MAGIC[at] {
                    // Out of step with the magic: start again at this byte
                    // if it could begin one ("FXSL" repeats no prefix).
                    s.page_fill = u16::from(b == MAGIC[0]);
                    if b == MAGIC[0] {
                        core::ptr::write_volatile(s.page.as_mut_ptr(), b);
                    }
                    continue;
                }
                core::ptr::write_volatile(s.page.as_mut_ptr().add(at), b);
                s.page_fill += 1;
            }
            if (s.page_fill as usize) < PAGE_SIZE {
                return CONTINUE;
            }
            s.byte_count = PAGE_SIZE as u32;
            // Where the image ends; graph_slot judges the rest of the header
            // at ACTIVATE.
            match declared_end(&s.page, s.slot_size) {
                Some(end) => s.image_end = end,
                None => {
                    fail(s, sys, if s.slot_size == 0 { E_NOSYS } else { E_INVAL });
                    return CONTINUE;
                }
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
                if echoed != REQ_ERASE {
                    return CONTINUE;
                }
                if rc < 0 {
                    fail(s, sys, rc);
                    return CONTINUE;
                }
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
                if echoed != REQ_WRITE {
                    return CONTINUE;
                }
                if rc < 0 {
                    fail(s, sys, rc);
                    return CONTINUE;
                }
                s.write_offset += PAGE_SIZE as u32;
                s.page_fill = 0;
                if s.write_offset & 0x3FFF == 0 {
                    emit_status(s, sys, STATUS_WRITTEN, (s.byte_count >> 10) as i32);
                }
                if s.image_end != 0 && s.write_offset >= s.image_end {
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
                if echoed != REQ_ACTIVATE {
                    return CONTINUE;
                }
                emit_status(
                    s,
                    sys,
                    if rc == 0 {
                        STATUS_ACTIVATED
                    } else {
                        STATUS_FAILED
                    },
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

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_state_size")]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

// Same figure as data, so `pack` records it in the manifest and a graph's
// state-arena demand is summable host-side.
declare_module_state_bytes!(State);

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
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
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<State>() {
            return -2;
        }
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.status_chan = out_chan;
        s.signaled_ready = 0;
        s.state = ST_IDLE;
        s.page_fill = 0;
        s.byte_count = 0;
        s.write_offset = 0;
        s.image_end = 0;
        s.resp_fill = 0;
        // This board's slot size, as the kernel partitioned its flash.
        let mut layout = [0u8; GRAPH_FLASH_LEN];
        let rc = ((*s.syscalls).provider_call)(
            -1,
            abi::kernel_abi::FLASH_LAYOUT,
            layout.as_mut_ptr(),
            layout.len(),
        );
        s.slot_size = GraphFlash::decode(&layout)
            .filter(|_| rc >= 0)
            .map_or(0, |g| g.slot_size);
        // Extra ports resolved in module_step when we know the syscall table is live.
        s.gs_req_chan = -1;
        s.gs_resp_chan = -1;
        0
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return -1;
        }
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

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");
