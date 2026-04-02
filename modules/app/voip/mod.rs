//! VoIP Module — G.711 codec + jitter buffer + SIP user agent
//!
//! Four independent subsystems:
//! - Jitter: RTP receive socket → playout buffer (internal)
//! - Decode: jitter output → G.711 u-law to PCM stereo → out[0]
//! - Encode: in[0] → PCM stereo to G.711 u-law → out[1]
//! - SIP:    signaling UA controlling jitter (internal) + rtp (via out[2])
//!
//! **Ports:**
//!   in[0]:  PCM stereo (from mic_source) — optional
//!   out[0]: PCM stereo (to i2s)
//!   out[1]: G.711 u-law bytes (to rtp) — optional
//!   out[2]: ctrl channel to rtp — optional (SIP)
//!   ctrl:   call trigger (from gesture) — optional (SIP)
//!
//! **Params (TLV v2):**
//!   tag 1: local_ip (u32) — SIP
//!   tag 2: local_sip_port (u16, default 5060) — SIP
//!   tag 3: peer_ip (u32) — SIP
//!   tag 4: peer_sip_port (u16, default 5060) — SIP
//!   tag 5: rtp_port (u16, default 5004) — SIP SDP + jitter local port
//!   tag 6: auto_answer (u8, default 1) — SIP
//!   tag 7: jitter_ms (u16, default 60) — jitter buffer depth
//!   tag 8: ptime (u8, default 20) — packet interval (ms)

#![no_std]

use core::ffi::c_void;

#[path = "../../../src/abi.rs"]
mod abi;
use abi::{SyscallTable, ChannelAddr};

include!("../../pic_runtime.rs");
include!("../../param_macro.rs");

include!("g711.rs");
include!("sip.rs");
include!("jitter.rs");

// ============================================================================
// Shared Constants
// ============================================================================

const DEV_SOCKET_OPEN: u32 = 0x0800;
const DEV_SOCKET_CONNECT: u32 = 0x0801;
const DEV_SOCKET_SEND: u32 = 0x0802;
const DEV_SOCKET_RECV: u32 = 0x0803;
const DEV_SOCKET_POLL: u32 = 0x0804;
const DEV_SOCKET_CLOSE: u32 = 0x0805;
const DEV_SOCKET_BIND: u32 = 0x0806;

// Control channel protocol (8-byte messages to rtp)
const CTRL_SET_ENDPOINT: u8 = 0x01;
const CTRL_START: u8 = 0x02;
const CTRL_STOP: u8 = 0x03;
const CTRL_MSG_SIZE: usize = 8;

// Buffer sizes
const DEC_OUT_BUF_SIZE: usize = 256;
const ENC_IN_BUF_SIZE: usize = 256;
const ENC_OUT_BUF_SIZE: usize = 64;
const SIP_TX_BUF_SIZE: usize = 512;
const SIP_RX_BUF_SIZE: usize = 512;
const CALL_ID_SIZE: usize = 16;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct VoipState {
    syscalls: *const SyscallTable,

    // Channel handles
    encode_in: i32,       // in[0]: PCM stereo from mic
    decode_out: i32,      // out[0]: PCM stereo to i2s
    encode_out: i32,      // out[1]: G.711 to rtp
    ctrl_chan: i32,        // ctrl: gesture/flash
    out_ctrl_rtp: i32,    // out[2]: ctrl to rtp

    // Sockets
    sip_socket: i32,      // SIP signaling
    jitter_socket: i32,   // RTP receive

    // SIP config
    local_ip: u32,
    peer_ip: u32,
    local_sip_port: u16,
    peer_sip_port: u16,
    rtp_port: u16,

    // SIP state
    sip_active: u8,
    sip_state: SipPhase,
    auto_answer: u8,
    sip_retransmit_count: u8,
    _pad1: u16,

    // Peer RTP endpoint (from SDP)
    peer_rtp_ip: u32,
    peer_rtp_port: u16,
    _pad2: u16,

    // SIP dialog
    cseq: u32,
    call_id_counter: u16,
    from_tag: u16,
    to_tag: u16,
    branch_counter: u16,

    // SIP timing
    sip_last_retransmit_ms: u64,

    // SIP TX/RX
    sip_tx_len: u16,
    sip_rx_have: u16,
    call_id: [u8; CALL_ID_SIZE],
    call_id_len: u8,
    _pad3: [u8; 3],

    // Jitter config + state
    jitter_phase: JitterPhase,
    ptime: u8,
    jitter_ms: u16,
    target_fill: u16,
    jitter_remote_ip: u32,
    jitter_remote_port: u16,
    _pad4: u16,

    // Jitter playout
    play_seq: u16,
    jitter_started: u8,
    _pad5: u8,
    fill_count: u16,
    _pad6: u16,
    last_output_ms: u64,

    // Jitter statistics
    packets_received: u32,
    packets_lost: u32,

    // Jitter → decode handoff
    jitter_out_len: u16,
    jitter_out_offset: u16,

    // Codec pending state
    dec_pending_out: u16,
    dec_pending_offset: u16,
    enc_pending_out: u16,
    enc_pending_offset: u16,

    // Buffers
    dec_out_buf: [u8; DEC_OUT_BUF_SIZE],
    enc_in_buf: [u8; ENC_IN_BUF_SIZE],
    enc_out_buf: [u8; ENC_OUT_BUF_SIZE],
    sip_tx_buf: [u8; SIP_TX_BUF_SIZE],
    sip_rx_buf: [u8; SIP_RX_BUF_SIZE],
    ctrl_out: [u8; CTRL_MSG_SIZE],
    jitter_rx_buf: [u8; JITTER_RX_BUF_SIZE],
    jitter_out_buf: [u8; SLOT_SIZE],

    // Jitter buffer slots (largest, last)
    slots: [JitterSlot; MAX_SLOTS],
}

impl VoipState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.encode_in = -1;
        self.decode_out = -1;
        self.encode_out = -1;
        self.ctrl_chan = -1;
        self.out_ctrl_rtp = -1;
        self.sip_socket = -1;
        self.jitter_socket = -1;
        self.local_ip = 0;
        self.peer_ip = 0;
        self.local_sip_port = SIP_PORT_DEFAULT;
        self.peer_sip_port = SIP_PORT_DEFAULT;
        self.rtp_port = RTP_PORT_DEFAULT;
        self.sip_active = 0;
        self.sip_state = SipPhase::Init;
        self.auto_answer = 1;
        self.sip_retransmit_count = 0;
        self._pad1 = 0;
        self.peer_rtp_ip = 0;
        self.peer_rtp_port = 0;
        self._pad2 = 0;
        self.cseq = 1;
        self.call_id_counter = 0;
        self.from_tag = 0;
        self.to_tag = 0;
        self.branch_counter = 0;
        self.sip_last_retransmit_ms = 0;
        self.sip_tx_len = 0;
        self.sip_rx_have = 0;
        self.call_id_len = 0;
        self._pad3 = [0; 3];
        self.jitter_phase = JitterPhase::Idle;
        self.ptime = 20;
        self.jitter_ms = 60;
        self.target_fill = 3;
        self.jitter_remote_ip = 0;
        self.jitter_remote_port = 0;
        self._pad4 = 0;
        self.play_seq = 0;
        self.jitter_started = 0;
        self._pad5 = 0;
        self.fill_count = 0;
        self._pad6 = 0;
        self.last_output_ms = 0;
        self.packets_received = 0;
        self.packets_lost = 0;
        self.jitter_out_len = 0;
        self.jitter_out_offset = 0;
        self.dec_pending_out = 0;
        self.dec_pending_offset = 0;
        self.enc_pending_out = 0;
        self.enc_pending_offset = 0;
        let mut i = 0;
        while i < MAX_SLOTS {
            self.slots[i] = JitterSlot::empty();
            i += 1;
        }
    }
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::VoipState;
    use super::{p_u8, p_u16, p_u32};
    use super::SCHEMA_MAX;

    define_params! {
        VoipState;

        1, local_ip, u32, 0
            => |s, d, len| { s.local_ip = p_u32(d, len, 0, 0); };

        2, local_sip_port, u16, 5060
            => |s, d, len| { s.local_sip_port = p_u16(d, len, 0, 5060); };

        3, peer_ip, u32, 0
            => |s, d, len| { s.peer_ip = p_u32(d, len, 0, 0); };

        4, peer_sip_port, u16, 5060
            => |s, d, len| { s.peer_sip_port = p_u16(d, len, 0, 5060); };

        5, rtp_port, u16, 5004
            => |s, d, len| { s.rtp_port = p_u16(d, len, 0, 5004); };

        6, auto_answer, u8, 1
            => |s, d, len| { s.auto_answer = p_u8(d, len, 0, 1); };

        7, jitter_ms, u16, 60
            => |s, d, len| {
                let v = p_u16(d, len, 0, 60);
                s.jitter_ms = if v == 0 { 60 } else { v };
            };

        8, ptime, u8, 20
            => |s, d, len| {
                let v = p_u8(d, len, 0, 20);
                s.ptime = if v == 0 { 20 } else { v };
            };
    }
}

// ============================================================================
// PIC Module Interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<VoipState>() as u32
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
        if state.is_null() || state_size < core::mem::size_of::<VoipState>() {
            return -5;
        }

        let s = &mut *(state as *mut VoipState);
        s.init(syscalls as *const SyscallTable);
        let sys = &*s.syscalls;

        // Primary ports
        s.encode_in = in_chan;    // in[0]: PCM from mic
        s.decode_out = out_chan;  // out[0]: PCM to i2s
        s.ctrl_chan = ctrl_chan;

        // Discover additional output ports
        let ch = dev_channel_port(sys, 1, 1); // out[1]: G.711 to rtp
        if ch >= 0 { s.encode_out = ch; }

        let ch = dev_channel_port(sys, 1, 2); // out[2]: ctrl to rtp
        if ch >= 0 { s.out_ctrl_rtp = ch; }

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Compute jitter target fill
        if s.ptime > 0 {
            s.target_fill = s.jitter_ms / (s.ptime as u16);
            if s.target_fill == 0 { s.target_fill = 1; }
            if s.target_fill > MAX_SLOTS as u16 { s.target_fill = MAX_SLOTS as u16; }
        }

        // SIP activates when both IPs are configured
        if s.local_ip != 0 && s.peer_ip != 0 {
            s.sip_active = 1;
            let now = dev_millis(sys) as u16;
            s.from_tag = now ^ 0x5349;
            s.branch_counter = now;
            dev_log(sys, 3, b"[voip] sip enabled".as_ptr(), 18);
        }

        dev_log(sys, 3, b"[voip] init".as_ptr(), 11);
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
        let s = &mut *(state as *mut VoipState);
        if s.syscalls.is_null() {
            return -1;
        }

        // 1. SIP state machine
        if s.sip_active != 0 {
            step_sip(s);
        }

        // 2. Jitter buffer (receive + playout)
        step_jitter(s);

        // 3. Decode: jitter output → PCM → out[0]
        if s.decode_out >= 0 {
            step_decode(s);
        }

        // 4. Encode: in[0] → G.711 → out[1]
        if s.encode_in >= 0 && s.encode_out >= 0 {
            step_encode(s);
        }

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        ChannelHint { port_type: 1, port_index: 0, buffer_size: (SLOT_SIZE * 4) as u16 },
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
