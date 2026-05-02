//! Link — bidirectional audio/control transport over UART.
//!
//! Combines TX (audio send, sync receive) and RX (audio receive, sync send)
//! into a single module. Mode selects direction:
//!   - mode 0 (TX): reads audio from in[0], sends over UART. Receives sync beacons.
//!   - mode 1 (RX): receives audio from UART, writes to out[0]. Sends sync beacons.
//!   - mode 2 (bidir): both directions simultaneously.
//!
//! Uses two UART handles for full duplex (one TX, one RX).
//! Exports `module_deferred_ready` — gates downstream until jitter buffer filled
//! (only relevant in RX/bidir modes).
//!
//! **Params (TLV v2):**
//!   tag 1: uart_bus (u8, default 0)
//!   tag 2: baud (u32, default 3000000)
//!   tag 3: block_size (u16, default 512 — samples per audio block)
//!   tag 4: jitter_depth (u8, default 3 — blocks of jitter buffer, 2-6)
//!   tag 5: pipeline_latency (u16, default 1024 — TX samples ahead of master)
//!   tag 6: mode (u8, default 0 — 0=TX, 1=RX, 2=bidir)
//!
//! **Ports:**
//!   - in[0]:  audio input  (TX/bidir)
//!   - out[0]: audio output (RX/bidir)
//!   - out[1]: forwarded FMP control messages (RX/bidir)
//!   - ctrl[0]: control input (forwarded to peer)

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

mod params_def;

// ============================================================================
// Protocol constants
// ============================================================================

const LINK_MSG_AUDIO: u8 = 0;
const LINK_MSG_SYNC: u8 = 1;
const LINK_MSG_CONTROL: u8 = 2;

const LINK_HDR_SIZE: usize = 10;
const LINK_CRC_SIZE: usize = 2;
const SYNC_PAYLOAD_SIZE: usize = 24;

// UART opcodes
const DEV_UART_OPEN: u32 = 0x0D00;
const DEV_UART_CONFIGURE: u32 = 0x0D05;

// Modes
const MODE_TX: u8 = 0;
const MODE_RX: u8 = 1;
const MODE_BIDIR: u8 = 2;

// ============================================================================
// PIC-safe helpers
// ============================================================================

type DevCallFn = unsafe extern "C" fn(i32, u32, *mut u8, usize) -> i32;

/// PIC-safe modulo for small divisors 2-6 (avoids division instruction).
#[inline(always)]
fn mod_small(val: usize, d: usize) -> usize {
    let q = match d {
        2 => val >> 1,
        3 => ((val as u64 * 0xAAAAAAAB) >> 33) as usize,
        4 => val >> 2,
        5 => ((val as u64 * 0xCCCCCCCD) >> 34) as usize,
        6 => ((val as u64 * 0xAAAAAAAB) >> 34) as usize,
        _ => 0,
    };
    val - q * d
}

// ============================================================================
// CRC-16/CCITT-FALSE
// ============================================================================

#[inline(always)]
unsafe fn crc16_update(crc: u16, byte: u8) -> u16 {
    let mut c = crc ^ ((byte as u16) << 8);
    let mut i = 0u8;
    while i < 8 {
        if (c & 0x8000) != 0 {
            c = (c << 1) ^ 0x1021;
        } else {
            c = c << 1;
        }
        i += 1;
    }
    c
}

#[inline(always)]
unsafe fn crc16_block(data: *const u8, len: usize) -> u16 {
    let mut crc: u16 = 0xFFFF;
    let mut i = 0usize;
    while i < len {
        crc = crc16_update(crc, *data.add(i));
        i += 1;
    }
    crc
}

// ============================================================================
// COBS
// ============================================================================

#[inline(never)]
unsafe fn cobs_encode(src: *const u8, src_len: usize, dst: *mut u8) -> usize {
    let mut read_idx = 0usize;
    let mut write_idx = 1usize;
    let mut code_idx = 0usize;
    let mut code: u8 = 1;

    while read_idx < src_len {
        let byte = *src.add(read_idx);
        if byte == 0 {
            *dst.add(code_idx) = code;
            code_idx = write_idx;
            write_idx += 1;
            code = 1;
        } else {
            *dst.add(write_idx) = byte;
            write_idx += 1;
            code += 1;
            if code == 0xFF {
                *dst.add(code_idx) = code;
                code_idx = write_idx;
                write_idx += 1;
                code = 1;
            }
        }
        read_idx += 1;
    }
    *dst.add(code_idx) = code;
    write_idx
}

#[inline(never)]
unsafe fn cobs_decode(src: *const u8, src_len: usize, dst: *mut u8) -> usize {
    let mut read_idx = 0usize;
    let mut write_idx = 0usize;

    while read_idx < src_len {
        let code = *src.add(read_idx);
        read_idx += 1;
        if code == 0 { return 0; }

        let mut i = 1u8;
        while i < code {
            if read_idx >= src_len { return 0; }
            *dst.add(write_idx) = *src.add(read_idx);
            write_idx += 1;
            read_idx += 1;
            i += 1;
        }
        if code < 0xFF && read_idx < src_len {
            *dst.add(write_idx) = 0;
            write_idx += 1;
        }
    }
    write_idx
}

#[inline(always)]
const fn cobs_max_encoded(src_len: usize) -> usize {
    src_len + (src_len >> 8) + 2
}

// ============================================================================
// Frame Encode / Decode
// ============================================================================

#[repr(C)]
struct LinkFrameHeader {
    msg_type: u8,
    flags: u8,
    seq: u16,
    frame_id: u32,
    payload_len: u16,
}

#[inline(never)]
unsafe fn link_frame_encode(
    msg_type: u8, flags: u8, seq: u16, frame_id: u32,
    payload: *const u8, payload_len: u16,
    wire_buf: *mut u8, wire_buf_cap: usize,
) -> usize {
    let raw_len = LINK_HDR_SIZE + payload_len as usize + LINK_CRC_SIZE;
    let cobs_needed = cobs_max_encoded(raw_len) + 2;
    if wire_buf_cap < cobs_needed { return 0; }

    let raw_offset = wire_buf_cap - raw_len;
    let raw = wire_buf.add(raw_offset);

    *raw.add(0) = msg_type;
    *raw.add(1) = flags;
    let sb = seq.to_le_bytes();
    *raw.add(2) = sb[0]; *raw.add(3) = sb[1];
    let fb = frame_id.to_le_bytes();
    *raw.add(4) = fb[0]; *raw.add(5) = fb[1];
    *raw.add(6) = fb[2]; *raw.add(7) = fb[3];
    let lb = payload_len.to_le_bytes();
    *raw.add(8) = lb[0]; *raw.add(9) = lb[1];

    if payload_len > 0 && !payload.is_null() {
        let mut i = 0usize;
        while i < payload_len as usize {
            *raw.add(LINK_HDR_SIZE + i) = *payload.add(i);
            i += 1;
        }
    }

    let crc = crc16_block(raw, LINK_HDR_SIZE + payload_len as usize);
    let cb = crc.to_le_bytes();
    *raw.add(LINK_HDR_SIZE + payload_len as usize) = cb[0];
    *raw.add(LINK_HDR_SIZE + payload_len as usize + 1) = cb[1];

    *wire_buf = 0x00;
    let cobs_len = cobs_encode(raw, raw_len, wire_buf.add(1));
    *wire_buf.add(1 + cobs_len) = 0x00;
    2 + cobs_len
}

#[inline(never)]
unsafe fn link_frame_decode(
    cobs_data: *const u8, cobs_len: usize,
    decoded_buf: *mut u8, decoded_cap: usize,
    header_out: *mut LinkFrameHeader,
) -> usize {
    let decoded_len = cobs_decode(cobs_data, cobs_len, decoded_buf);
    if decoded_len < LINK_HDR_SIZE + LINK_CRC_SIZE { return 0; }
    if decoded_len > decoded_cap { return 0; }

    let data_len = decoded_len - LINK_CRC_SIZE;
    let computed = crc16_block(decoded_buf, data_len);
    let received = u16::from_le_bytes([
        *decoded_buf.add(data_len), *decoded_buf.add(data_len + 1),
    ]);
    if computed != received { return 0; }

    let payload_len = u16::from_le_bytes([*decoded_buf.add(8), *decoded_buf.add(9)]);
    if LINK_HDR_SIZE + payload_len as usize + LINK_CRC_SIZE != decoded_len { return 0; }

    (*header_out).msg_type = *decoded_buf.add(0);
    (*header_out).flags = *decoded_buf.add(1);
    (*header_out).seq = u16::from_le_bytes([*decoded_buf.add(2), *decoded_buf.add(3)]);
    (*header_out).frame_id = u32::from_le_bytes([
        *decoded_buf.add(4), *decoded_buf.add(5),
        *decoded_buf.add(6), *decoded_buf.add(7),
    ]);
    (*header_out).payload_len = payload_len;
    LINK_HDR_SIZE
}

// ============================================================================
// Sync Beacon Helpers
// ============================================================================

#[inline(always)]
unsafe fn sync_beacon_encode(
    buf: *mut u8, consumed: u64, queued: u32, rate_q16: u32, micros: u64,
) {
    let cb = consumed.to_le_bytes();
    let mut i = 0usize;
    while i < 8 { *buf.add(i) = cb[i]; i += 1; }
    let qb = queued.to_le_bytes();
    i = 0;
    while i < 4 { *buf.add(8 + i) = qb[i]; i += 1; }
    let rb = rate_q16.to_le_bytes();
    i = 0;
    while i < 4 { *buf.add(12 + i) = rb[i]; i += 1; }
    let mb = micros.to_le_bytes();
    i = 0;
    while i < 8 { *buf.add(16 + i) = mb[i]; i += 1; }
}

#[inline(always)]
unsafe fn sync_beacon_decode(buf: *const u8) -> (u64, u32, u32, u64) {
    let consumed = u64::from_le_bytes([
        *buf, *buf.add(1), *buf.add(2), *buf.add(3),
        *buf.add(4), *buf.add(5), *buf.add(6), *buf.add(7),
    ]);
    let queued = u32::from_le_bytes([
        *buf.add(8), *buf.add(9), *buf.add(10), *buf.add(11),
    ]);
    let rate_q16 = u32::from_le_bytes([
        *buf.add(12), *buf.add(13), *buf.add(14), *buf.add(15),
    ]);
    let micros = u64::from_le_bytes([
        *buf.add(16), *buf.add(17), *buf.add(18), *buf.add(19),
        *buf.add(20), *buf.add(21), *buf.add(22), *buf.add(23),
    ]);
    (consumed, queued, rate_q16, micros)
}

// ============================================================================
// Jitter Buffer
// ============================================================================

const MAX_JITTER_BLOCKS: usize = 6;
const MAX_BLOCK_SAMPLES: usize = 512;
const MAX_BLOCK_BYTES: usize = MAX_BLOCK_SAMPLES * 2;

#[repr(C)]
struct JitterSlot {
    frame_id: u32,
    len: u16,
    valid: bool,
    _pad: u8,
}

// ============================================================================
// State
// ============================================================================

/// Maximum wire frame: COBS(header + 1024 audio + CRC) + 2 delimiters
const MAX_WIRE_BUF: usize = 1200;
/// UART RX accumulator (shared between modes)
const RX_ACCUM_SIZE: usize = 1200;
/// Small beacon wire buffer
const BEACON_WIRE_SIZE: usize = 64;
/// Beacon interval
const BEACON_INTERVAL_MS: u64 = 10;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Init = 0,
    WaitUart = 1,
    Filling = 2,   // RX: filling jitter buffer
    Running = 3,
    Error = 4,
}

#[repr(C)]
struct LinkState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    ctrl_out_chan: i32,

    // UART handles
    uart_tx_handle: i32,
    uart_rx_handle: i32,

    // Config
    uart_bus: u8,
    mode: u8,
    phase: Phase,
    jitter_depth: u8,
    block_size: u16,
    pipeline_latency: u16,
    baud: u32,

    // TX state
    tx_seq: u16,
    wire_pending_offset: u16,
    wire_pending_len: u16,

    // RX sync tracking (TX mode: receives beacons from RX peer)
    master_consumed: u64,
    master_micros: u64,
    master_rate_q16: u32,
    local_micros_at_sync: u64,
    sync_valid: bool,

    // RX jitter state
    playout_frame_id: u32,
    blocks_received: u16,
    rx_seq_last: u16,
    frames_dropped: u32,

    // Beacon state (RX mode: sends beacons to TX peer)
    last_beacon_ms: u64,
    beacon_pending: bool,

    // RX accumulator state (shared — both modes receive UART data)
    rx_accum_len: u16,
    rx_in_frame: bool,

    _pad: [u8; 2],

    // Buffers (at end for alignment)
    jitter_slots: [JitterSlot; MAX_JITTER_BLOCKS],
    wire_buf: [u8; MAX_WIRE_BUF],
    rx_accum: [u8; RX_ACCUM_SIZE],
    beacon_wire: [u8; BEACON_WIRE_SIZE],
    jitter_data: [u8; MAX_JITTER_BLOCKS * MAX_BLOCK_BYTES],
}

// ============================================================================
// PIC Module Interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<LinkState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<LinkState>() { return -2; }

        let s = &mut *(state as *mut LinkState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;
        s.ctrl_out_chan = -1;
        s.uart_tx_handle = -1;
        s.uart_rx_handle = -1;
        s.phase = Phase::Init;

        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Discover out[1] for control forwarding (RX/bidir modes)
        if s.mode == MODE_RX || s.mode == MODE_BIDIR {
            let dev_call = (*s.syscalls).provider_call;
            let mut port_arg = [1u8, 1u8]; // port_type=out, index=1
            s.ctrl_out_chan = (dev_call)(-1, 0x050C, port_arg.as_mut_ptr(), 2);
        }

        let sys = &*s.syscalls;
        dev_log(sys, 3, b"[link] ready".as_ptr(), 12);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut LinkState);
        if s.syscalls.is_null() { return -1; }

        match s.phase {
            Phase::Init => step_init(s),
            Phase::WaitUart => step_wait_uart(s),
            Phase::Filling => step_filling(s),
            Phase::Running => step_running(s),
            Phase::Error => -1,
        }
    }
}

// ============================================================================
// Phase: Init — Open UART handles
// ============================================================================

unsafe fn step_init(s: &mut LinkState) -> i32 {
    let dev_call = (*s.syscalls).provider_call;
    let dev_open = (*s.syscalls).provider_open;

    // UART open returns a handle; use provider_open so the kernel
    // binds it to the HAL_UART contract and subsequent calls on the
    // handle route through the tracked contract rather than the
    // class-byte fallback.
    const HAL_UART_CONTRACT: u32 = 0x000D;
    let bus_arg = [s.uart_bus];
    let tx_h = (dev_open)(HAL_UART_CONTRACT, DEV_UART_OPEN, bus_arg.as_ptr(), 1);
    if tx_h < 0 {
        dev_log(&*s.syscalls, 1, b"[link] uart tx fail".as_ptr(), 19);
        s.phase = Phase::Error;
        return -1;
    }
    s.uart_tx_handle = tx_h;

    let rx_h = (dev_open)(HAL_UART_CONTRACT, DEV_UART_OPEN, bus_arg.as_ptr(), 1);
    if rx_h < 0 {
        dev_log(&*s.syscalls, 1, b"[link] uart rx fail".as_ptr(), 19);
        s.phase = Phase::Error;
        return -1;
    }
    s.uart_rx_handle = rx_h;

    let mut baud_arg = s.baud.to_le_bytes();
    (dev_call)(tx_h, DEV_UART_CONFIGURE, baud_arg.as_mut_ptr(), 4);

    s.phase = if s.mode == MODE_TX {
        Phase::Running
    } else {
        Phase::Filling
    };

    dev_log(&*s.syscalls, 3, b"[link] uart ok".as_ptr(), 14);
    0
}

unsafe fn step_wait_uart(s: &mut LinkState) -> i32 {
    s.phase = if s.mode == MODE_TX { Phase::Running } else { Phase::Filling };
    0
}

// ============================================================================
// Phase: Filling — RX jitter buffer fill (RX/bidir only)
// ============================================================================

unsafe fn step_filling(s: &mut LinkState) -> i32 {
    let dev_call = (*s.syscalls).provider_call;

    poll_uart_rx(s, dev_call);
    maybe_send_beacon(s, dev_call);

    if s.blocks_received >= s.jitter_depth as u16 {
        let depth = s.jitter_depth as usize;
        let mut min_frame = u32::MAX;
        let mut i = 0usize;
        while i < depth {
            let sp = &*s.jitter_slots.as_ptr().add(i);
            if sp.valid && sp.frame_id < min_frame {
                min_frame = sp.frame_id;
            }
            i += 1;
        }
        if min_frame != u32::MAX {
            s.playout_frame_id = min_frame;
        }
        s.phase = Phase::Running;
        dev_log(&*s.syscalls, 3, b"[link] running".as_ptr(), 14);
        return 3; // StepOutcome::Ready
    }
    0
}

// ============================================================================
// Phase: Running — main loop
// ============================================================================

unsafe fn step_running(s: &mut LinkState) -> i32 {
    let dev_call = (*s.syscalls).provider_call;
    let channel_read = (*s.syscalls).channel_read;
    let channel_write = (*s.syscalls).channel_write;
    let channel_poll = (*s.syscalls).channel_poll;

    let mode = s.mode;

    // --- TX side: send audio + control ---
    if mode == MODE_TX || mode == MODE_BIDIR {
        // Drain pending UART TX
        if s.wire_pending_len > 0 {
            let uart_tx = s.uart_tx_handle;
            let result = (dev_call)(
                uart_tx, 0x0D02,
                s.wire_buf.as_mut_ptr().add(s.wire_pending_offset as usize),
                s.wire_pending_len as usize,
            );
            if result > 0 {
                s.wire_pending_offset = 0;
                s.wire_pending_len = 0;
            } else if result == 0 {
                let poll = (dev_call)(uart_tx, 0x0D04, core::ptr::null_mut(), 0);
                if poll > 0 {
                    s.wire_pending_offset = 0;
                    s.wire_pending_len = 0;
                } else {
                    // UART busy — still poll RX
                    poll_uart_rx(s, dev_call);
                    return 0;
                }
            }
        }

        // Send audio
        let in_chan = s.in_chan;
        if in_chan >= 0 && s.wire_pending_len == 0 {
            let block_bytes = (s.block_size as usize) * 2;
            let in_poll = (channel_poll)(in_chan, POLL_IN);
            if in_poll > 0 && ((in_poll as u32) & POLL_IN) != 0 {
                // Try mailbox
                let mut mailbox_len: u32 = 0;
                let mailbox_ptr = (dev_call)(
                    in_chan, 0x0A02,
                    &mut mailbox_len as *mut u32 as *mut u8, 4,
                ) as *const u8;
                if !mailbox_ptr.is_null() && mailbox_len >= block_bytes as u32 {
                    let frame_id = compute_frame_id(s, dev_call);
                    let wire_len = link_frame_encode(
                        LINK_MSG_AUDIO, 0, s.tx_seq, frame_id,
                        mailbox_ptr, block_bytes as u16,
                        s.wire_buf.as_mut_ptr(), MAX_WIRE_BUF,
                    );
                    (dev_call)(in_chan, 0x0A03, core::ptr::null_mut(), 0);
                    s.tx_seq = s.tx_seq.wrapping_add(1);
                    if wire_len > 0 {
                        send_wire(s, dev_call, wire_len);
                    }
                } else {
                    if !mailbox_ptr.is_null() {
                        (dev_call)(in_chan, 0x0A03, core::ptr::null_mut(), 0);
                    }
                    // FIFO path
                    let audio_offset = MAX_WIRE_BUF - block_bytes;
                    let audio_buf = s.wire_buf.as_mut_ptr().add(audio_offset);
                    let read = (channel_read)(in_chan, audio_buf, block_bytes);
                    if read >= block_bytes as i32 {
                        let frame_id = compute_frame_id(s, dev_call);
                        let wire_len = link_frame_encode(
                            LINK_MSG_AUDIO, 0, s.tx_seq, frame_id,
                            audio_buf, read as u16,
                            s.wire_buf.as_mut_ptr(), audio_offset,
                        );
                        s.tx_seq = s.tx_seq.wrapping_add(1);
                        if wire_len > 0 {
                            send_wire(s, dev_call, wire_len);
                        }
                    }
                }
            }
        }

        // Forward control messages
        let ctrl_chan = s.ctrl_chan;
        if ctrl_chan >= 0 && s.wire_pending_len == 0 {
            let ctrl_poll = (channel_poll)(ctrl_chan, POLL_IN);
            if ctrl_poll > 0 && ((ctrl_poll as u32) & POLL_IN) != 0 {
                let ctrl_offset = MAX_WIRE_BUF - 256;
                let ctrl_buf = s.wire_buf.as_mut_ptr().add(ctrl_offset);

                let mut hdr = [0u8; 6];
                let n = (channel_read)(ctrl_chan, hdr.as_mut_ptr(), 6);
                if n >= 6 {
                    let fmp_type = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
                    let fmp_payload_len = u16::from_le_bytes([hdr[4], hdr[5]]);

                    let tb = fmp_type.to_le_bytes();
                    *ctrl_buf = tb[0]; *ctrl_buf.add(1) = tb[1];
                    *ctrl_buf.add(2) = tb[2]; *ctrl_buf.add(3) = tb[3];

                    if fmp_payload_len > 0 {
                        let to_read = (fmp_payload_len as usize).min(250);
                        (channel_read)(ctrl_chan, ctrl_buf.add(4), to_read);
                    }

                    let total = 4 + fmp_payload_len as usize;
                    let wire_len = link_frame_encode(
                        LINK_MSG_CONTROL, 0, s.tx_seq, 0,
                        ctrl_buf, total as u16,
                        s.wire_buf.as_mut_ptr(), ctrl_offset,
                    );
                    s.tx_seq = s.tx_seq.wrapping_add(1);
                    if wire_len > 0 {
                        send_wire(s, dev_call, wire_len);
                    }
                }
            }
        }
    }

    // --- RX side: playout jitter buffer ---
    if mode == MODE_RX || mode == MODE_BIDIR {
        let out_chan = s.out_chan;
        let block_bytes = (s.block_size as usize) * 2;
        let depth = s.jitter_depth as usize;

        let out_poll = (channel_poll)(out_chan, POLL_OUT);
        if out_poll > 0 && ((out_poll as u32) & POLL_OUT) != 0 {
            let slot_idx = mod_small(s.playout_frame_id as usize, depth);
            let sp = &*s.jitter_slots.as_ptr().add(slot_idx);

            if sp.valid && sp.frame_id == s.playout_frame_id {
                // Mailbox write
                let mut cap: u32 = 0;
                let mbuf = (dev_call)(out_chan, 0x0A00, &mut cap as *mut u32 as *mut u8, 4) as *mut u8;
                if !mbuf.is_null() && cap >= block_bytes as u32 {
                    let src = s.jitter_data.as_ptr().add(slot_idx * MAX_BLOCK_BYTES);
                    let mut j = 0usize;
                    while j < block_bytes {
                        core::ptr::write_volatile(mbuf.add(j), *src.add(j));
                        j += 1;
                    }
                    let mut len_arg = (block_bytes as u32).to_le_bytes();
                    (dev_call)(out_chan, 0x0A01, len_arg.as_mut_ptr(), 4);
                } else {
                    if !mbuf.is_null() {
                        let mut zero_arg = 0u32.to_le_bytes();
                        (dev_call)(out_chan, 0x0A01, zero_arg.as_mut_ptr(), 4);
                    }
                    let src = s.jitter_data.as_ptr().add(slot_idx * MAX_BLOCK_BYTES);
                    (channel_write)(out_chan, src, block_bytes);
                }
                let sp_mut = &mut *s.jitter_slots.as_mut_ptr().add(slot_idx);
                sp_mut.valid = false;
            } else {
                // Missing block — output silence
                let mut cap: u32 = 0;
                let mbuf = (dev_call)(out_chan, 0x0A00, &mut cap as *mut u32 as *mut u8, 4) as *mut u8;
                if !mbuf.is_null() && cap >= block_bytes as u32 {
                    let mut j = 0usize;
                    while j < block_bytes {
                        core::ptr::write_volatile(mbuf.add(j), 0);
                        j += 1;
                    }
                    let mut len_arg = (block_bytes as u32).to_le_bytes();
                    (dev_call)(out_chan, 0x0A01, len_arg.as_mut_ptr(), 4);
                } else {
                    if !mbuf.is_null() {
                        let mut zero_arg = 0u32.to_le_bytes();
                        (dev_call)(out_chan, 0x0A01, zero_arg.as_mut_ptr(), 4);
                    }
                    let zeros = [0u8; 64];
                    let mut remaining = block_bytes;
                    while remaining > 0 {
                        let chunk = if remaining > 64 { 64 } else { remaining };
                        (channel_write)(out_chan, zeros.as_ptr(), chunk);
                        remaining -= chunk;
                    }
                }
                s.frames_dropped = s.frames_dropped.wrapping_add(1);
            }
            s.playout_frame_id = s.playout_frame_id.wrapping_add(s.block_size as u32);
        }

        // Send beacons
        maybe_send_beacon(s, dev_call);
    }

    // --- Always poll UART RX ---
    poll_uart_rx(s, dev_call);

    0
}

// ============================================================================
// Shared Helpers
// ============================================================================

#[inline(always)]
unsafe fn send_wire(s: &mut LinkState, dev_call: DevCallFn, wire_len: usize) {
    let result = (dev_call)(s.uart_tx_handle, 0x0D02, s.wire_buf.as_mut_ptr(), wire_len);
    if result == 0 {
        s.wire_pending_offset = 0;
        s.wire_pending_len = wire_len as u16;
    }
}

#[inline(always)]
unsafe fn compute_frame_id(s: &LinkState, dev_call: DevCallFn) -> u32 {
    if s.sync_valid {
        let mut buf = [0u8; 8];
        (dev_call)(-1, 0x0602, buf.as_mut_ptr(), 8); // TIMER_MICROS
        let now_us = u64::from_le_bytes(buf);
        let elapsed_us = now_us.wrapping_sub(s.local_micros_at_sync);
        let rate = s.master_rate_q16 >> 16;
        let frames_elapsed = if rate > 0 {
            let product = (elapsed_us as u64).wrapping_mul(rate as u64);
            (((product >> 16).wrapping_mul(4295)) >> 16) as u32
        } else { 0 };
        let current = s.master_consumed.wrapping_add(frames_elapsed as u64);
        current.wrapping_add(s.pipeline_latency as u64) as u32
    } else {
        (s.tx_seq as u32).wrapping_mul(s.block_size as u32)
    }
}

// ============================================================================
// UART RX — shared frame accumulator
// ============================================================================

unsafe fn poll_uart_rx(s: &mut LinkState, dev_call: DevCallFn) {
    let space = RX_ACCUM_SIZE - s.rx_accum_len as usize;
    if space == 0 {
        s.rx_accum_len = 0;
        s.rx_in_frame = false;
        return;
    }

    let result = (dev_call)(
        s.uart_rx_handle, 0x0D03,
        s.rx_accum.as_mut_ptr().add(s.rx_accum_len as usize),
        space,
    );

    let bytes = if result == 0 {
        let poll = (dev_call)(s.uart_rx_handle, 0x0D04, core::ptr::null_mut(), 0);
        if poll <= 0 { return; }
        poll as usize
    } else if result > 0 {
        result as usize
    } else { return; };

    let start = s.rx_accum_len as usize;
    let end = start + bytes;

    let mut i = start;
    while i < end {
        let byte = *s.rx_accum.as_ptr().add(i);

        if byte == 0x00 {
            if s.rx_in_frame && i > 0 {
                decode_frame(s, i);
            }
            let remaining = end - i - 1;
            if remaining > 0 {
                let mut j = 0usize;
                while j < remaining {
                    *s.rx_accum.as_mut_ptr().add(j) = *s.rx_accum.as_ptr().add(i + 1 + j);
                    j += 1;
                }
            }
            s.rx_accum_len = remaining as u16;
            s.rx_in_frame = true;
            return;
        }
        i += 1;
    }

    s.rx_accum_len = end as u16;
    if !s.rx_in_frame {
        s.rx_accum_len = 0;
    }
}

unsafe fn decode_frame(s: &mut LinkState, frame_end: usize) {
    let cobs_data = s.rx_accum.as_ptr();
    let cobs_len = frame_end;

    let mut header = LinkFrameHeader {
        msg_type: 0, flags: 0, seq: 0, frame_id: 0, payload_len: 0,
    };

    // Decode into scratch at end of jitter_data
    let max_decoded = LINK_HDR_SIZE + MAX_BLOCK_BYTES + LINK_CRC_SIZE;
    let scratch_offset = MAX_JITTER_BLOCKS * MAX_BLOCK_BYTES - max_decoded;
    let decode_buf = s.jitter_data.as_mut_ptr().add(scratch_offset);

    let payload_off = link_frame_decode(
        cobs_data, cobs_len,
        decode_buf, max_decoded,
        &mut header,
    );

    if payload_off == 0 { return; }

    match header.msg_type {
        LINK_MSG_AUDIO => {
            // Only accept audio in RX/bidir mode
            if s.mode == MODE_RX || s.mode == MODE_BIDIR {
                handle_audio(s, &header, decode_buf.add(payload_off));
            }
        }
        LINK_MSG_SYNC => {
            // Sync beacons: TX mode receives these from RX peer
            handle_sync(s, &header, decode_buf.add(payload_off));
        }
        LINK_MSG_CONTROL => {
            if s.mode == MODE_RX || s.mode == MODE_BIDIR {
                handle_control(s, &header, decode_buf.add(payload_off));
            }
        }
        _ => {}
    }
}

unsafe fn handle_audio(s: &mut LinkState, hdr: &LinkFrameHeader, payload: *const u8) {
    let depth = s.jitter_depth as usize;
    let block_bytes = (s.block_size as usize) * 2;

    if (hdr.payload_len as usize) < block_bytes { return; }

    let slot_idx = mod_small(hdr.frame_id as usize, depth);
    let slot = &mut *s.jitter_slots.as_mut_ptr().add(slot_idx);
    slot.frame_id = hdr.frame_id;
    slot.len = block_bytes as u16;
    slot.valid = true;

    let dst = s.jitter_data.as_mut_ptr().add(slot_idx * MAX_BLOCK_BYTES);
    let mut i = 0usize;
    while i < block_bytes {
        *dst.add(i) = *payload.add(i);
        i += 1;
    }

    s.blocks_received = s.blocks_received.wrapping_add(1);
    s.rx_seq_last = hdr.seq;
}

unsafe fn handle_sync(s: &mut LinkState, hdr: &LinkFrameHeader, payload: *const u8) {
    if (hdr.payload_len as usize) < SYNC_PAYLOAD_SIZE { return; }

    let dev_call = (*s.syscalls).provider_call;
    let (consumed, _queued, rate_q16, micros) = sync_beacon_decode(payload);
    s.master_consumed = consumed;
    s.master_micros = micros;
    s.master_rate_q16 = rate_q16;

    let mut tbuf = [0u8; 8];
    (dev_call)(-1, 0x0602, tbuf.as_mut_ptr(), 8);
    s.local_micros_at_sync = u64::from_le_bytes(tbuf);
    s.sync_valid = true;
}

unsafe fn handle_control(s: &mut LinkState, hdr: &LinkFrameHeader, payload: *const u8) {
    if s.ctrl_out_chan < 0 { return; }
    if (hdr.payload_len as usize) < 4 { return; }

    let channel_write = (*s.syscalls).channel_write;

    let fmp_type = u32::from_le_bytes([
        *payload, *payload.add(1), *payload.add(2), *payload.add(3),
    ]);
    let fmp_payload_len = hdr.payload_len.wrapping_sub(4);

    let mut fmp_hdr = [0u8; 6];
    let tb = fmp_type.to_le_bytes();
    fmp_hdr[0] = tb[0]; fmp_hdr[1] = tb[1]; fmp_hdr[2] = tb[2]; fmp_hdr[3] = tb[3];
    let lb = fmp_payload_len.to_le_bytes();
    fmp_hdr[4] = lb[0]; fmp_hdr[5] = lb[1];
    (channel_write)(s.ctrl_out_chan, fmp_hdr.as_ptr(), 6);

    if fmp_payload_len > 0 {
        (channel_write)(s.ctrl_out_chan, payload.add(4), fmp_payload_len as usize);
    }
}

// ============================================================================
// Sync Beacon TX (RX/bidir mode — sends beacons to TX peer)
// ============================================================================

unsafe fn maybe_send_beacon(s: &mut LinkState, dev_call: DevCallFn) {
    if s.mode == MODE_TX { return; }

    let mut milli_buf = [0u8; 8];
    (dev_call)(-1, abi::kernel_abi::timer::MILLIS, milli_buf.as_mut_ptr(), 8);
    let now_ms = u64::from_le_bytes(milli_buf);

    if now_ms.wrapping_sub(s.last_beacon_ms) < BEACON_INTERVAL_MS { return; }

    if s.beacon_pending {
        let poll = (dev_call)(s.uart_tx_handle, 0x0D04, core::ptr::null_mut(), 0);
        if poll == 0 { return; }
        s.beacon_pending = false;
    }

    let dev_query = (*s.syscalls).provider_query;
    let mut st_buf = [0u8; 24];
    let r = (dev_query)(-1, 0x0C30, st_buf.as_mut_ptr(), 24);
    if r < 0 { return; }

    let consumed = u64::from_le_bytes([
        st_buf[0], st_buf[1], st_buf[2], st_buf[3],
        st_buf[4], st_buf[5], st_buf[6], st_buf[7],
    ]);
    let queued = u32::from_le_bytes([st_buf[8], st_buf[9], st_buf[10], st_buf[11]]);
    let rate_q16 = u32::from_le_bytes([st_buf[12], st_buf[13], st_buf[14], st_buf[15]]);

    if rate_q16 == 0 { return; }

    let mut us_buf = [0u8; 8];
    (dev_call)(-1, 0x0602, us_buf.as_mut_ptr(), 8);
    let now_us = u64::from_le_bytes(us_buf);

    let mut payload = [0u8; SYNC_PAYLOAD_SIZE];
    sync_beacon_encode(payload.as_mut_ptr(), consumed, queued, rate_q16, now_us);

    let wire_len = link_frame_encode(
        LINK_MSG_SYNC, 0, 0,
        consumed as u32,
        payload.as_ptr(), SYNC_PAYLOAD_SIZE as u16,
        s.beacon_wire.as_mut_ptr(), BEACON_WIRE_SIZE,
    );

    if wire_len > 0 {
        let result = (dev_call)(s.uart_tx_handle, 0x0D02, s.beacon_wire.as_mut_ptr(), wire_len);
        if result == 0 {
            s.beacon_pending = true;
        }
        s.last_beacon_ms = now_ms;
    }
}

// ============================================================================
// Channel Hints
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        ChannelHint { port_type: 0, port_index: 0, buffer_size: 2048 }, // audio_in
        ChannelHint { port_type: 1, port_index: 0, buffer_size: 2048 }, // audio_out
        ChannelHint { port_type: 1, port_index: 1, buffer_size: 256 },  // ctrl_fwd
        ChannelHint { port_type: 2, port_index: 0, buffer_size: 256 },  // control
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

#[no_mangle]
#[link_section = ".text.module_mailbox_safe"]
pub extern "C" fn module_mailbox_safe() -> i32 { 1 }

#[no_mangle]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> i32 { 1 }

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
