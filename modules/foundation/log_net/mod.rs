//! log_net — netconsole-style log forwarding.
//!
//! Drains the kernel log ring (via LOG_RING_DRAIN (diag) 0x0C64) and
//! forwards chunks as UDP datagrams through the IP module. Use this when
//! the UART is unavailable (HAT blocking GPIO14/15, remote bring-up, etc.).
//!
//! # Wiring
//!
//!   ip.net_out  →  log_net.net_in       (inbound frames from ip — discarded)
//!   log_net.net_out →  ip.net_in        (CMD_BIND + CMD_SEND)
//!
//! # Parameters
//!
//! | Tag | Name      | Type | Default      | Description                     |
//! |-----|-----------|------|--------------|---------------------------------|
//! | 1   | dst_ip    | u32  | 0 (disabled) | Destination IP (LE). Setting `0` or an L2 broadcast (`0xFFFFFFFF`) leaves the module dormant — broadcast would flood the subnet at tick rate. The stack injection in `stacks/debug.toml` pins `dst_ip` via `|required` against `~/.config/fluxor/host.toml` so a missing collector fails at build time, not at runtime. |
//! | 2   | dst_port  | u16  | 6666         | UDP destination port            |
//! | 3   | bind_port | u16  | 6667         | Local UDP source port           |
//!
//! # Host-side capture
//!
//!   nc -ul 6666
//!   socat -u UDP-RECV:6666 -

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

// ============================================================================
// Constants
// ============================================================================

const NET_MSG_BOUND: u8 = 0x04;
const NET_MSG_ERROR: u8 = 0x06;
const NET_CMD_BIND: u8 = 0x10;
const NET_CMD_SEND: u8 = 0x11;

/// Frame buffer: FRAME_HDR + conn_id + dst_ip + dst_port + log chunk.
const NET_BUF_SIZE: usize = 600;

/// Per-datagram log payload budget. Leaves ~72 B of slack vs NET_BUF_SIZE.
const CHUNK_SIZE: usize = 512;

/// LOG_RING_DRAIN (diag) opcode. Kept local to avoid bumping the SDK
/// include surface for a single constant.
const LOG_RING_DRAIN: u32 = 0x0C64;

// ============================================================================
// State
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Init = 0,
    Binding = 1,
    WaitBound = 2,
    Serving = 3,
    /// Bind failed or conn closed. Sleeps `BACKOFF_TICKS` then reruns Binding.
    Backoff = 4,
    /// `dst_ip` is unset (0) or an L2 broadcast. Terminal dormant
    /// state with a one-shot warning so the operator sees why UDP
    /// logging never started.
    Disabled = 5,
}

/// Backoff window between retries (in scheduler ticks). At tick_us=100 this
/// is 100 ms — slow enough to avoid flooding a broken ip module, fast
/// enough to resume within a second of recovery.
const BACKOFF_TICKS: u16 = 1000;

/// Cap on consecutive bind retries before we give up and stop consuming the
/// ring. Not an error state — the module keeps returning Continue(0) so the
/// scheduler doesn't mark it faulted.
const MAX_BIND_ATTEMPTS: u16 = 50;

#[repr(C)]
struct LogNetState {
    syscalls: *const SyscallTable,
    net_in_chan: i32,
    net_out_chan: i32,

    dst_ip: u32,
    dst_port: u16,
    bind_port: u16,

    phase: Phase,
    conn_id: u8,

    /// Backoff countdown (ticks remaining before next bind retry).
    backoff_ticks: u16,
    /// Number of consecutive bind attempts that have failed.
    bind_attempts: u16,

    /// Length of drained-but-unsent bytes in `chunk`. Preserves data across
    /// channel-full retries — if emit_datagram fails, we keep the bytes and
    /// try again next tick instead of losing them.
    pending_len: u16,

    /// Stats (informational; readable via memory dump if needed).
    datagrams_sent: u32,
    bytes_forwarded: u32,

    /// Frame buffer for CMD_BIND / CMD_SEND assembly and net_in drain.
    net_buf: [u8; NET_BUF_SIZE],
    /// Scratch for log ring drain chunks.
    chunk: [u8; CHUNK_SIZE],
}

impl LogNetState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.net_in_chan = -1;
        self.net_out_chan = -1;
        // `dst_ip = 0` = not configured. The module stays dormant
        // until a valid unicast dst_ip is supplied via params.
        self.dst_ip = 0;
        self.dst_port = 6666;
        self.bind_port = 6667;
        self.phase = Phase::Init;
        self.conn_id = 0;
        self.backoff_ticks = 0;
        self.bind_attempts = 0;
        self.pending_len = 0;
        self.datagrams_sent = 0;
        self.bytes_forwarded = 0;
    }
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::LogNetState;
    use super::p_u16;
    use super::p_u32;
    use super::SCHEMA_MAX;

    define_params! {
        LogNetState;

        1, dst_ip, u32, 0
            => |s, d, len| { s.dst_ip = p_u32(d, len, 0, 0); };

        2, dst_port, u16, 6666
            => |s, d, len| { s.dst_port = p_u16(d, len, 0, 6666); };

        3, bind_port, u16, 6667
            => |s, d, len| { s.bind_port = p_u16(d, len, 0, 6667); };
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Build and emit a CMD_SEND frame carrying `payload` to the configured
/// broadcast/unicast destination. Returns true iff the channel accepted it.
///
/// Caller must have transitioned to Phase::Serving (conn_id set from MSG_BOUND).
/// conn_id=0 is a legitimate slot assignment, so we do not gate on it.
unsafe fn emit_datagram(s: &mut LogNetState, payload: *const u8, payload_len: usize) -> bool {
    if s.net_out_chan < 0 { return false; }
    // NET_CMD_SEND payload: [conn_id:1][dst_ip:4 LE][dst_port:2 LE][data...]
    let body_len = 1 + 4 + 2 + payload_len;
    if body_len + 3 > NET_BUF_SIZE { return false; }

    let buf = s.net_buf.as_mut_ptr();
    let out_chan = s.net_out_chan;
    let conn_id = s.conn_id;
    let dst_ip = s.dst_ip;
    let dst_port = s.dst_port;
    let sys_ptr = s.syscalls;

    *buf = NET_CMD_SEND;
    let pl = (body_len as u16).to_le_bytes();
    *buf.add(1) = pl[0];
    *buf.add(2) = pl[1];
    *buf.add(3) = conn_id;
    let ip = dst_ip.to_le_bytes();
    *buf.add(4) = ip[0];
    *buf.add(5) = ip[1];
    *buf.add(6) = ip[2];
    *buf.add(7) = ip[3];
    let port = dst_port.to_le_bytes();
    *buf.add(8) = port[0];
    *buf.add(9) = port[1];

    let mut i = 0;
    while i < payload_len {
        *buf.add(10 + i) = *payload.add(i);
        i += 1;
    }

    let total = 3 + body_len;
    let wrote = ((*sys_ptr).channel_write)(out_chan, buf, total);
    if wrote > 0 {
        s.datagrams_sent = s.datagrams_sent.wrapping_add(1);
        s.bytes_forwarded = s.bytes_forwarded.wrapping_add(payload_len as u32);
        true
    } else {
        false
    }
}

/// Drain any inbound frame on net_in and discard. The IP module publishes
/// MSG_DATA for our bound socket — we don't act on remote control input.
unsafe fn discard_net_in(s: &mut LogNetState) {
    if s.net_in_chan < 0 { return; }
    let sys_ptr = s.syscalls;
    let chan = s.net_in_chan;
    let poll = ((*sys_ptr).channel_poll)(chan, 0x01 /* POLL_IN */);
    if poll > 0 && (poll & 0x01) != 0 {
        let buf = s.net_buf.as_mut_ptr();
        let _ = net_read_frame(&*sys_ptr, chan, buf, NET_BUF_SIZE);
    }
}

// ============================================================================
// Module interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<LogNetState>() as u32
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
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() { return -2; }
        if state.is_null() { return -5; }
        if state_size < core::mem::size_of::<LogNetState>() { return -6; }

        let s = &mut *(state as *mut LogNetState);
        s.init(syscalls as *const SyscallTable);
        s.net_in_chan = in_chan;
        s.net_out_chan = out_chan;

        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut LogNetState);
        if s.syscalls.is_null() { return -1; }

        match s.phase {
            Phase::Init => {
                // Refuse to run without a configured unicast dst_ip.
                // Both unset (0) and L2 broadcast (0xFFFFFFFF) drop
                // into `Disabled` — broadcast would flood the subnet
                // at tick rate.
                if s.dst_ip == 0 || s.dst_ip == 0xFFFF_FFFF {
                    let sys = &*s.syscalls;
                    let msg = if s.dst_ip == 0 {
                        b"[log_net] dst_ip unset; UDP log forwarding disabled\0".as_ref()
                    } else {
                        b"[log_net] dst_ip = broadcast rejected; UDP log forwarding disabled\0".as_ref()
                    };
                    dev_log(sys, 2, msg.as_ptr(), msg.len() - 1);
                    s.phase = Phase::Disabled;
                    return 0;
                }
                s.phase = Phase::Binding;
            }

            // Terminal. Returning 0 keeps the scheduler happy and
            // the module faultless until the next reboot.
            Phase::Disabled => return 0,

            Phase::Binding => {
                if s.net_out_chan < 0 { return 0; }
                if s.bind_attempts >= MAX_BIND_ATTEMPTS {
                    // Give up quietly — don't trip the fault monitor.
                    return 0;
                }
                let sys_ptr = s.syscalls;
                let out_chan = s.net_out_chan;
                let buf = s.net_buf.as_mut_ptr();
                let mut payload = [0u8; 2];
                let port = s.bind_port.to_le_bytes();
                payload[0] = port[0];
                payload[1] = port[1];
                let wrote = net_write_frame(
                    &*sys_ptr, out_chan, NET_CMD_BIND,
                    payload.as_ptr(), 2, buf, NET_BUF_SIZE,
                );
                // Channel full — retry next tick (phase unchanged).
                if wrote == 0 { return 0; }
                s.bind_attempts += 1;
                s.phase = Phase::WaitBound;
                return 2;
            }

            Phase::WaitBound => {
                if s.net_in_chan < 0 { return 0; }
                let sys_ptr = s.syscalls;
                let in_chan = s.net_in_chan;
                let poll = ((*sys_ptr).channel_poll)(in_chan, 0x01);
                if poll <= 0 || (poll & 0x01) == 0 { return 0; }
                let buf = s.net_buf.as_mut_ptr();
                let (msg_type, payload_len) = net_read_frame(&*sys_ptr, in_chan, buf, NET_BUF_SIZE);
                // MSG_BOUND payload: [conn_id:1][local_port:2 LE]. Match
                // on local_port so we only claim the conn_id belonging to
                // our own CMD_BIND — `ip.net_out` may be tee'd to other
                // consumers with their own binds in flight.
                if msg_type == NET_MSG_BOUND && payload_len >= 3 {
                    let bound_port = (*buf.add(4) as u16)
                        | ((*buf.add(5) as u16) << 8);
                    if bound_port == s.bind_port {
                        s.conn_id = *buf.add(3);
                        s.phase = Phase::Serving;
                        s.bind_attempts = 0;
                        s.pending_len = 0;
                        return 2;
                    }
                } else if msg_type == NET_MSG_ERROR {
                    // Transient — back off, then retry from Binding.
                    // Never returns -1: a debug overlay must not kill its own
                    // module and trigger the fault monitor.
                    s.phase = Phase::Backoff;
                    s.backoff_ticks = BACKOFF_TICKS;
                    return 0;
                }
                // Other message type — ignore, stay in WaitBound.
            }

            Phase::Backoff => {
                if s.backoff_ticks > 0 {
                    s.backoff_ticks -= 1;
                    return 0;
                }
                s.phase = Phase::Binding;
            }

            Phase::Serving => {
                // Always drain any inbound data to keep net_in from backing up.
                discard_net_in(s);

                // If a previous chunk couldn't be sent (channel full), retry
                // it now before draining new bytes from the ring — otherwise
                // the ring tail advances and we leak log data on the floor.
                if s.pending_len > 0 {
                    let len = s.pending_len as usize;
                    if emit_datagram(s, s.chunk.as_ptr(), len) {
                        s.pending_len = 0;
                    } else {
                        // Still can't write. Wait for the downstream channel
                        // to drain. New ring bytes accumulate in-place and
                        // are handled by the ring's own drop-new policy.
                        return 0;
                    }
                }

                // Drain up to CHUNK_SIZE bytes from the ring.
                let sys_ptr = s.syscalls;
                let chunk_ptr = s.chunk.as_mut_ptr();
                let ret = ((*sys_ptr).provider_call)(-1, LOG_RING_DRAIN, chunk_ptr, CHUNK_SIZE);
                if ret <= 0 {
                    return 0;
                }
                let len = (ret as u32) & 0xFFFF;
                let dropped = ((ret as u32) >> 16) & 0xFFFF;

                // If drops happened, emit a marker datagram so viewers know
                // there is a gap. Hex (4-bit shift) encoding avoids runtime
                // division, which RP2350 PIC modules cannot link. Marker is
                // fire-and-forget — if the channel is full, the marker is
                // dropped and the main chunk still goes into pending_len.
                if dropped > 0 {
                    let mut mark = [0u8; 40];
                    let prefix = b"[log_net: dropped 0x";
                    let mut pos = 0usize;
                    while pos < prefix.len() {
                        mark[pos] = prefix[pos];
                        pos += 1;
                    }
                    let hex = b"0123456789abcdef";
                    let mut shift: i32 = 12;
                    while shift >= 0 {
                        let nib = ((dropped >> shift as u32) & 0xF) as usize;
                        mark[pos] = hex[nib];
                        pos += 1;
                        shift -= 4;
                    }
                    let suffix = b" bytes]\n";
                    let mut k = 0usize;
                    while k < suffix.len() && pos < mark.len() {
                        mark[pos] = suffix[k];
                        pos += 1;
                        k += 1;
                    }
                    emit_datagram(s, mark.as_ptr(), pos);
                }

                if len > 0 {
                    if !emit_datagram(s, chunk_ptr, len as usize) {
                        // Hold the chunk across ticks until the channel
                        // accepts it. No data is lost.
                        s.pending_len = len as u16;
                    }
                    return 2;
                }
            }
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
