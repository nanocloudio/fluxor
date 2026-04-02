//! RTP PIC Module (TX + RX)
//!
//! Combined RTP transmitter and receiver using a single UDP socket.
//!
//! - **TX path** (when in_chan is wired): Reads G.711 u-law from input,
//!   packetizes into RTP (RFC 3550), and sends via UDP.
//! - **RX path** (when out_chan is wired): Receives RTP from UDP, validates
//!   headers, extracts payload, and writes to output channel.
//!
//! **Control channel support:** If ctrl_chan is wired, the module starts idle
//! and waits for SET_ENDPOINT + START commands. Without ctrl_chan, it requires
//! peer_ip and auto-starts.
//!
//! **Params (TLV v2):**
//!   tag 1: peer_ip    (u32, required without ctrl — peer IPv4 network byte order)
//!   tag 2: peer_port  (u16, default 5004)
//!   tag 3: local_port (u16, default 5004)
//!   tag 4: ssrc       (u32, default 0x46585254 — TX only)
//!   tag 5: ptime      (u8, default 20 — TX packet interval in ms)

#![no_std]

use core::ffi::c_void;

#[path = "../../../src/abi.rs"]
mod abi;
use abi::{SyscallTable, ChannelAddr};

include!("../../pic_runtime.rs");
include!("../../param_macro.rs");

// ============================================================================
// Constants
// ============================================================================

// dev_call socket opcodes
const DEV_SOCKET_OPEN: u32 = 0x0800;
const DEV_SOCKET_CONNECT: u32 = 0x0801;
const DEV_SOCKET_SEND: u32 = 0x0802;
const DEV_SOCKET_RECV: u32 = 0x0803;
const DEV_SOCKET_POLL: u32 = 0x0804;
const DEV_SOCKET_CLOSE: u32 = 0x0805;
const DEV_SOCKET_BIND: u32 = 0x0806;

/// RTP header size (V2, no CSRC, no extensions)
const RTP_HEADER_SIZE: usize = 12;

/// Maximum payload per RTP packet (support up to 40ms @ 8kHz)
const MAX_PAYLOAD: usize = 320;

/// Total packet buffer (header + max payload)
const PKT_BUF_SIZE: usize = RTP_HEADER_SIZE + MAX_PAYLOAD;

/// Max RTP packet we can receive
const RX_BUF_SIZE: usize = PKT_BUF_SIZE;

// ============================================================================
// Control Channel Protocol (8-byte messages, little-endian)
// ============================================================================

const CTRL_SET_ENDPOINT: u8 = 0x01;
const CTRL_START: u8 = 0x02;
const CTRL_STOP: u8 = 0x03;
const CTRL_MSG_SIZE: usize = 8;

// ============================================================================
// State Machine
// ============================================================================

/// RTP transport lifecycle phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum RtpPhase {
    Init = 0,
    BindWait = 1,
    ConnectWait = 2,
    Running = 3,
    Error = 4,
    Idle = 5,
}

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct RtpState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    socket_handle: i32,
    phase: RtpPhase,
    ptime: u8,
    payload_type: u8,
    ctrl_mode: u8,
    peer_ip: u32,
    peer_port: u16,
    local_port: u16,
    ssrc: u32,
    // TX state
    seq_num: u16,
    ptime_bytes: u16,
    timestamp: u32,
    acc_len: u16,
    _pad_tx: u16,
    // RX state
    last_seq: u16,
    seq_valid: u8,
    _pad_rx: u8,
    packets_received: u32,
    packets_lost: u32,
    pending_out: u16,
    pending_offset: u16,
    // Buffers
    ctrl_buf: [u8; CTRL_MSG_SIZE],
    acc_buf: [u8; MAX_PAYLOAD],
    pkt_buf: [u8; PKT_BUF_SIZE],
    rx_buf: [u8; RX_BUF_SIZE],
    out_buf: [u8; MAX_PAYLOAD],
}

impl RtpState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.in_chan = -1;
        self.out_chan = -1;
        self.ctrl_chan = -1;
        self.socket_handle = -1;
        self.phase = RtpPhase::Init;
        self.ptime = 20;
        self.payload_type = 0; // PCMU
        self.ctrl_mode = 0;
        self.peer_ip = 0;
        self.peer_port = 5004;
        self.local_port = 5004;
        self.ssrc = 0x46585254; // "FXRT"
        self.seq_num = 0;
        self.ptime_bytes = 160; // 20ms * 8 samples/ms
        self._pad_tx = 0;
        self.timestamp = 0;
        self.acc_len = 0;
        self.last_seq = 0;
        self.seq_valid = 0;
        self._pad_rx = 0;
        self.packets_received = 0;
        self.packets_lost = 0;
        self.pending_out = 0;
        self.pending_offset = 0;
    }
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::RtpState;
    use super::{p_u8, p_u16, p_u32};
    use super::SCHEMA_MAX;

    define_params! {
        RtpState;

        1, peer_ip, u32, 0
            => |s, d, len| { s.peer_ip = p_u32(d, len, 0, 0); };

        2, peer_port, u16, 5004
            => |s, d, len| { s.peer_port = p_u16(d, len, 0, 5004); };

        3, local_port, u16, 5004
            => |s, d, len| { s.local_port = p_u16(d, len, 0, 5004); };

        4, ssrc, u32, 0x46585254
            => |s, d, len| { s.ssrc = p_u32(d, len, 0, 0x46585254); };

        5, ptime, u8, 20
            => |s, d, len| {
                let v = p_u8(d, len, 0, 20);
                s.ptime = if v == 0 { 20 } else { v };
                s.ptime_bytes = (s.ptime as u16) * 8;
            };
    }
}

// ============================================================================
// PIC Module Interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<RtpState>() as u32
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
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<RtpState>() {
            return -5;
        }

        let s = &mut *(state as *mut RtpState);
        s.init(syscalls as *const SyscallTable);
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        let sys = &*s.syscalls;

        if ctrl_chan >= 0 {
            // Ctrl mode: start idle, wait for commands
            s.ctrl_mode = 1;
            s.phase = RtpPhase::Idle;
            dev_log(sys, 3, b"[rtp] ctrl mode".as_ptr(), 15);
        } else {
            // Legacy mode: require peer_ip, auto-start
            if s.peer_ip == 0 {
                dev_log(sys, 1, b"[rtp] no peer_ip".as_ptr(), 16);
                return -10;
            }
        }

        dev_log(sys, 3, b"[rtp] ready".as_ptr(), 11);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut RtpState);
        if s.syscalls.is_null() {
            return -1;
        }

        match s.phase {
            RtpPhase::Idle => step_idle(s),
            RtpPhase::Init => step_init(s),
            RtpPhase::BindWait => step_bind_wait(s),
            RtpPhase::ConnectWait => step_connect_wait(s),
            RtpPhase::Running => step_running(s),
            RtpPhase::Error => -1,
            _ => -1,
        }
    }
}

// ============================================================================
// State: Idle — wait for control commands (ctrl_mode only)
// ============================================================================

unsafe fn step_idle(s: &mut RtpState) -> i32 {
    let sys = &*s.syscalls;

    let poll = (sys.channel_poll)(s.ctrl_chan, POLL_IN);
    if poll <= 0 || ((poll as u8) & POLL_IN) == 0 {
        return 0;
    }

    let read = (sys.channel_read)(s.ctrl_chan, s.ctrl_buf.as_mut_ptr(), CTRL_MSG_SIZE);
    if read < CTRL_MSG_SIZE as i32 {
        return 0;
    }

    let cmd = s.ctrl_buf[0];
    match cmd {
        CTRL_SET_ENDPOINT => {
            let port = u16::from_le_bytes([s.ctrl_buf[2], s.ctrl_buf[3]]);
            let addr = u32::from_le_bytes([s.ctrl_buf[4], s.ctrl_buf[5], s.ctrl_buf[6], s.ctrl_buf[7]]);
            s.peer_ip = addr;
            s.peer_port = port;
        }
        CTRL_START => {
            if s.peer_ip == 0 {
                dev_log(sys, 2, b"[rtp] no endpoint".as_ptr(), 17);
                return 0;
            }
            dev_log(sys, 3, b"[rtp] starting".as_ptr(), 14);
            s.phase = RtpPhase::Init;
            return 2; // Burst — open socket immediately
        }
        _ => {}
    }
    0
}

// ============================================================================
// State: Init — open and bind socket
// ============================================================================

unsafe fn step_init(s: &mut RtpState) -> i32 {
    let sys = &*s.syscalls;
    let dev_call = sys.dev_call;

    let mut sock_arg = [SOCK_TYPE_DGRAM];
    let handle = (dev_call)(-1, DEV_SOCKET_OPEN, sock_arg.as_mut_ptr(), 1);
    if handle < 0 {
        dev_log(sys, 1, b"[rtp] socket fail".as_ptr(), 17);
        s.phase = RtpPhase::Error;
        return -1;
    }
    s.socket_handle = handle;

    let mut port_arg = s.local_port.to_le_bytes();
    let rc = (dev_call)(handle, DEV_SOCKET_BIND, port_arg.as_mut_ptr(), 2);
    if rc < 0 && rc != E_INPROGRESS {
        dev_log(sys, 1, b"[rtp] bind fail".as_ptr(), 15);
        (dev_call)(handle, DEV_SOCKET_CLOSE, core::ptr::null_mut(), 0);
        s.phase = RtpPhase::Error;
        return -1;
    }

    s.phase = RtpPhase::BindWait;
    2 // Burst — try connect immediately
}

// ============================================================================
// State: BindWait — try connect once bind completes
// ============================================================================

unsafe fn step_bind_wait(s: &mut RtpState) -> i32 {
    let sys = &*s.syscalls;
    let dev_call = sys.dev_call;

    let addr = ChannelAddr::new(s.peer_ip, s.peer_port);
    let rc = (dev_call)(
        s.socket_handle,
        DEV_SOCKET_CONNECT,
        &addr as *const _ as *mut u8,
        core::mem::size_of::<ChannelAddr>(),
    );

    if rc == E_BUSY {
        return 0;
    }
    if rc < 0 && rc != E_INPROGRESS {
        dev_log(sys, 1, b"[rtp] conn fail".as_ptr(), 15);
        s.phase = RtpPhase::Error;
        return -1;
    }

    s.phase = RtpPhase::ConnectWait;
    2 // Burst — poll connection immediately
}

// ============================================================================
// State: ConnectWait — poll for connection ready
// ============================================================================

unsafe fn step_connect_wait(s: &mut RtpState) -> i32 {
    let sys = &*s.syscalls;
    let dev_call = sys.dev_call;

    let mut poll_arg = [POLL_CONN | POLL_ERR];
    let poll = (dev_call)(s.socket_handle, DEV_SOCKET_POLL, poll_arg.as_mut_ptr(), 1);

    if poll > 0 && ((poll as u8) & POLL_ERR) != 0 {
        dev_log(sys, 1, b"[rtp] poll err".as_ptr(), 14);
        s.phase = RtpPhase::Error;
        return -1;
    }
    if poll > 0 && ((poll as u8) & POLL_CONN) != 0 {
        dev_log(sys, 3, b"[rtp] connected".as_ptr(), 15);
        s.phase = RtpPhase::Running;
        return 2; // Burst — start data flow immediately
    }
    0
}

// ============================================================================
// State: Running — TX and RX paths
// ============================================================================

unsafe fn step_running(s: &mut RtpState) -> i32 {
    let sys = &*s.syscalls;

    // Check for STOP command on ctrl channel
    if s.ctrl_mode != 0 {
        let ctrl_poll = (sys.channel_poll)(s.ctrl_chan, POLL_IN);
        if ctrl_poll > 0 && ((ctrl_poll as u8) & POLL_IN) != 0 {
            let read = (sys.channel_read)(s.ctrl_chan, s.ctrl_buf.as_mut_ptr(), CTRL_MSG_SIZE);
            if read >= CTRL_MSG_SIZE as i32 {
                let cmd = s.ctrl_buf[0];
                if cmd == CTRL_STOP {
                    close_socket(s);
                    dev_log(sys, 3, b"[rtp] stopped".as_ptr(), 13);
                    s.phase = RtpPhase::Idle;
                    return 0;
                } else if cmd == CTRL_SET_ENDPOINT {
                    let port = u16::from_le_bytes([s.ctrl_buf[2], s.ctrl_buf[3]]);
                    let addr = u32::from_le_bytes([s.ctrl_buf[4], s.ctrl_buf[5], s.ctrl_buf[6], s.ctrl_buf[7]]);
                    s.peer_ip = addr;
                    s.peer_port = port;
                }
            }
        }
    }

    // TX path
    if s.in_chan >= 0 {
        step_tx(s);
    }

    // RX path
    if s.out_chan >= 0 {
        step_rx(s);
    }

    0
}

// ============================================================================
// TX: accumulate G.711, build RTP packets, send
// ============================================================================

unsafe fn step_tx(s: &mut RtpState) {
    let sys = &*s.syscalls;
    let in_chan = s.in_chan;

    let in_poll = (sys.channel_poll)(in_chan, POLL_IN);
    if in_poll <= 0 || ((in_poll as u8) & POLL_IN) == 0 {
        return;
    }

    let space = MAX_PAYLOAD - s.acc_len as usize;
    if space == 0 {
        send_rtp_packet(s);
        return;
    }

    let read = (sys.channel_read)(
        in_chan,
        s.acc_buf.as_mut_ptr().add(s.acc_len as usize),
        space,
    );
    if read <= 0 {
        return;
    }
    s.acc_len += read as u16;

    while s.acc_len >= s.ptime_bytes {
        send_rtp_packet(s);
    }
}

// ============================================================================
// RX: receive RTP, validate, extract payload, write to channel
// ============================================================================

unsafe fn step_rx(s: &mut RtpState) {
    let sys = &*s.syscalls;
    let dev_call = sys.dev_call;
    let out_chan = s.out_chan;

    // Drain any pending output from previous step
    if !drain_pending(sys, out_chan, s.out_buf.as_ptr(), &mut s.pending_out, &mut s.pending_offset) {
        return;
    }

    // Check output channel ready
    let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
    if out_poll <= 0 || ((out_poll as u8) & POLL_OUT) == 0 {
        return;
    }

    // Try to receive a packet
    let read = (dev_call)(
        s.socket_handle,
        DEV_SOCKET_RECV,
        s.rx_buf.as_mut_ptr(),
        RX_BUF_SIZE,
    );

    if read <= 0 {
        return;
    }

    let pkt_len = read as usize;
    if pkt_len < RTP_HEADER_SIZE {
        return;
    }

    // Validate RTP header
    let pkt = s.rx_buf.as_ptr();
    let version = (*pkt >> 6) & 0x03;
    if version != 2 {
        return;
    }

    // Parse header: skip CSRC entries
    let cc = *pkt & 0x0F;
    let header_len = RTP_HEADER_SIZE + (cc as usize * 4);
    if pkt_len <= header_len {
        return;
    }

    let seq = ((*pkt.add(2) as u16) << 8) | (*pkt.add(3) as u16);

    // Track sequence numbers for loss detection
    if s.seq_valid != 0 {
        let expected = s.last_seq.wrapping_add(1);
        if seq != expected {
            let gap = seq.wrapping_sub(s.last_seq).wrapping_sub(1);
            if gap > 0 && gap < 1000 {
                s.packets_lost = s.packets_lost.wrapping_add(gap as u32);
            }
        }
    }
    s.last_seq = seq;
    s.seq_valid = 1;
    s.packets_received = s.packets_received.wrapping_add(1);

    // Extract payload
    let payload_len = pkt_len - header_len;
    let copy_len = if payload_len > MAX_PAYLOAD { MAX_PAYLOAD } else { payload_len };

    __aeabi_memcpy(s.out_buf.as_mut_ptr(), pkt.add(header_len), copy_len);

    // Write to output channel
    let written = (sys.channel_write)(out_chan, s.out_buf.as_ptr(), copy_len);
    if written < 0 && written != E_AGAIN {
        return;
    }

    track_pending(written, copy_len, &mut s.pending_out, &mut s.pending_offset);
}

// ============================================================================
// Close socket and reset streaming state
// ============================================================================

unsafe fn close_socket(s: &mut RtpState) {
    if s.socket_handle >= 0 {
        let dev_call = (&*s.syscalls).dev_call;
        (dev_call)(s.socket_handle, DEV_SOCKET_CLOSE, core::ptr::null_mut(), 0);
        s.socket_handle = -1;
    }
    // Reset TX state
    s.seq_num = 0;
    s.timestamp = 0;
    s.acc_len = 0;
    // Reset RX state
    s.last_seq = 0;
    s.seq_valid = 0;
    s.packets_received = 0;
    s.packets_lost = 0;
    s.pending_out = 0;
    s.pending_offset = 0;
}

// ============================================================================
// RTP Packet Construction and Send
// ============================================================================

unsafe fn send_rtp_packet(s: &mut RtpState) {
    let sys = &*s.syscalls;
    let dev_call = sys.dev_call;

    let payload_len = if s.acc_len < s.ptime_bytes {
        s.acc_len as usize
    } else {
        s.ptime_bytes as usize
    };

    if payload_len == 0 {
        return;
    }

    // Build RTP header (RFC 3550)
    let pkt = s.pkt_buf.as_mut_ptr();

    // Byte 0: V=2, P=0, X=0, CC=0 → 0x80
    *pkt = 0x80;
    // Byte 1: M=0, PT
    *pkt.add(1) = s.payload_type;
    // Bytes 2-3: sequence number (big-endian)
    *pkt.add(2) = (s.seq_num >> 8) as u8;
    *pkt.add(3) = (s.seq_num & 0xFF) as u8;
    // Bytes 4-7: timestamp (big-endian)
    *pkt.add(4) = (s.timestamp >> 24) as u8;
    *pkt.add(5) = ((s.timestamp >> 16) & 0xFF) as u8;
    *pkt.add(6) = ((s.timestamp >> 8) & 0xFF) as u8;
    *pkt.add(7) = (s.timestamp & 0xFF) as u8;
    // Bytes 8-11: SSRC (big-endian)
    *pkt.add(8) = (s.ssrc >> 24) as u8;
    *pkt.add(9) = ((s.ssrc >> 16) & 0xFF) as u8;
    *pkt.add(10) = ((s.ssrc >> 8) & 0xFF) as u8;
    *pkt.add(11) = (s.ssrc & 0xFF) as u8;

    // Copy payload after header
    __aeabi_memcpy(pkt.add(RTP_HEADER_SIZE), s.acc_buf.as_ptr(), payload_len);

    // Send packet
    let total = RTP_HEADER_SIZE + payload_len;
    let sent = (dev_call)(s.socket_handle, DEV_SOCKET_SEND, pkt, total);
    if sent < 0 && sent != E_AGAIN {
        dev_log(sys, 2, b"[rtp] send err".as_ptr(), 14);
    }

    // Advance sequence and timestamp
    s.seq_num = s.seq_num.wrapping_add(1);
    s.timestamp = s.timestamp.wrapping_add(payload_len as u32);

    // Shift remaining data in accumulator
    let remaining = s.acc_len as usize - payload_len;
    if remaining > 0 {
        __aeabi_memmove(
            s.acc_buf.as_mut_ptr(),
            s.acc_buf.as_ptr().add(payload_len),
            remaining,
        );
    }
    s.acc_len = remaining as u16;
}

// ============================================================================
// Panic Handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
