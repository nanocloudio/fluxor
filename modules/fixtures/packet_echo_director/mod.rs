//! packet_echo_director — fixture director for the ip decision seam.
//!
//! Reads `MSG_PKT_DECIDE` records on `decide_in`, answers each on
//! `dispose_out` with `CMD_PKT_DISPOSE` chosen by destination port, and
//! drains `fwd_in` so a TUNNEL or DSR disposition has somewhere to go.
//! Every count it keeps is logged on a period so a rig can read the
//! seam's behaviour off the console.
//!
//! Dispositions, by destination port:
//!
//!   `drop_port`    → DROP
//!   `reject_port`  → REJECT with `reject_kind`
//!   `tunnel_port`  → TUNNEL(attach_id = 7, flow_epoch = 1)
//!   `dsr_port`     → DSR(endpoint_id = 9, rewrite_id = 2)
//!   `hold_port`    → no answer, ever (the deadline releases it)
//!   `clone_port`   → CLONE, then LOCAL for the original; the clone is
//!                    disposed DROP when its id comes back
//!   anything else  → LOCAL
//!
//! A port value of 0 disables that row.

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
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

use abi::contracts::net::packet as pkt;

const FWD_IN_PORT: u8 = 1;
const LOG_PERIOD: u32 = 5000;
/// Largest frame the forward port can carry, plus its record prefix.
const FWD_BUF: usize = 3 + 4 + 1 + 6 + 1536;

#[repr(C)]
pub struct DirectorState {
    syscalls: *const SyscallTable,
    decide_in: i32,
    dispose_out: i32,
    fwd_in: i32,

    drop_port: u16,
    reject_port: u16,
    tunnel_port: u16,
    dsr_port: u16,
    hold_port: u16,
    clone_port: u16,
    reject_kind: u8,
    _pad: u8,

    step_count: u32,
    pub decided: u32,
    pub local: u32,
    pub dropped: u32,
    pub rejected: u32,
    pub tunnelled: u32,
    pub dsr: u32,
    pub held: u32,
    pub cloned: u32,
    pub forwarded_in: u32,
    pub expired: u32,
    pub clones_seen: u32,

    fwd_buf: [u8; FWD_BUF],
}

mod params_def {
    use super::*;
    define_params! {
        DirectorState;
        1, drop_port, u16, 0 => |s, d, len| { s.drop_port = p_u16(d, len, 0, 0); };
        2, reject_port, u16, 0 => |s, d, len| { s.reject_port = p_u16(d, len, 0, 0); };
        3, reject_kind, u8, 1, enum { silent=0, tcp_rst=1, icmp_unreachable=2 }
            => |s, d, len| { s.reject_kind = p_u8(d, len, 0, 1); };
        4, tunnel_port, u16, 0 => |s, d, len| { s.tunnel_port = p_u16(d, len, 0, 0); };
        5, dsr_port, u16, 0 => |s, d, len| { s.dsr_port = p_u16(d, len, 0, 0); };
        6, hold_port, u16, 0 => |s, d, len| { s.hold_port = p_u16(d, len, 0, 0); };
        7, clone_port, u16, 0 => |s, d, len| { s.clone_port = p_u16(d, len, 0, 0); };
    }
}

/// Write one disposition. `args` is the six-byte argument block.
unsafe fn dispose(s: &mut DirectorState, pkt_id: u32, disp: u8, args: &[u8; 6]) {
    let sys = &*s.syscalls;
    let mut payload = [0u8; 11];
    payload[0..4].copy_from_slice(&pkt_id.to_le_bytes());
    payload[4] = disp;
    payload[5..11].copy_from_slice(args);
    let mut scratch = [0u8; 3 + 11];
    net_write_frame(
        sys,
        s.dispose_out,
        pkt::CMD_PKT_DISPOSE,
        payload.as_ptr(),
        payload.len(),
        scratch.as_mut_ptr(),
        scratch.len(),
    );
}

unsafe fn clone(s: &mut DirectorState, pkt_id: u32) {
    let sys = &*s.syscalls;
    let payload = pkt_id.to_le_bytes();
    let mut scratch = [0u8; 3 + 4];
    net_write_frame(
        sys,
        s.dispose_out,
        pkt::CMD_PKT_CLONE,
        payload.as_ptr(),
        payload.len(),
        scratch.as_mut_ptr(),
        scratch.len(),
    );
}

/// Answer one decision record.
unsafe fn decide(s: &mut DirectorState, rec: &[u8]) {
    if rec.len() < pkt::DECIDE_LEN {
        return;
    }
    let pkt_id = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
    let dst_port = u16::from_le_bytes([rec[16], rec[17]]);
    s.decided = s.decided.wrapping_add(1);
    let mut args = [0u8; 6];
    let port_is = |p: u16| p != 0 && dst_port == p;
    if port_is(s.hold_port) {
        s.held = s.held.wrapping_add(1);
    } else if port_is(s.drop_port) {
        s.dropped = s.dropped.wrapping_add(1);
        args[0] = 1; // reason: fixture table
        dispose(s, pkt_id, pkt::disposition::DROP, &args);
    } else if port_is(s.reject_port) {
        s.rejected = s.rejected.wrapping_add(1);
        args[0] = 1;
        args[1] = s.reject_kind;
        dispose(s, pkt_id, pkt::disposition::REJECT, &args);
    } else if port_is(s.tunnel_port) {
        s.tunnelled = s.tunnelled.wrapping_add(1);
        args[0..2].copy_from_slice(&7u16.to_le_bytes());
        args[2..6].copy_from_slice(&1u32.to_le_bytes());
        dispose(s, pkt_id, pkt::disposition::TUNNEL, &args);
    } else if port_is(s.dsr_port) {
        s.dsr = s.dsr.wrapping_add(1);
        args[0..2].copy_from_slice(&9u16.to_le_bytes());
        args[2..4].copy_from_slice(&2u16.to_le_bytes());
        dispose(s, pkt_id, pkt::disposition::DSR, &args);
    } else if port_is(s.clone_port) {
        s.cloned = s.cloned.wrapping_add(1);
        clone(s, pkt_id);
        dispose(s, pkt_id, pkt::disposition::LOCAL, &args);
    } else {
        s.local = s.local.wrapping_add(1);
        dispose(s, pkt_id, pkt::disposition::LOCAL, &args);
    }
}

unsafe fn service_decide(s: &mut DirectorState) {
    let sys = &*s.syscalls;
    let mut budget = 64;
    while budget > 0 {
        budget -= 1;
        let poll = (sys.channel_poll)(s.decide_in, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            break;
        }
        // `net_read_frame` leaves the 3-byte header in `buf[..3]` and the
        // payload after it.
        let mut buf = [0u8; 3 + 64];
        let (msg, plen) = net_read_frame(sys, s.decide_in, buf.as_mut_ptr(), buf.len());
        let rec = &buf[3..3 + plen.min(64)];
        match msg {
            pkt::MSG_PKT_DECIDE => decide(s, rec),
            pkt::MSG_PKT_CLONED if plen >= 8 => {
                s.clones_seen = s.clones_seen.wrapping_add(1);
                let clone_id = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
                if clone_id != pkt::PKT_ID_NONE {
                    let args = [2u8, 0, 0, 0, 0, 0];
                    dispose(s, clone_id, pkt::disposition::DROP, &args);
                }
            }
            pkt::MSG_PKT_EXPIRED => s.expired = s.expired.wrapping_add(1),
            0 => break,
            _ => {}
        }
    }
}

unsafe fn service_fwd(s: &mut DirectorState) {
    if s.fwd_in < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let mut budget = 32;
    while budget > 0 {
        budget -= 1;
        let poll = (sys.channel_poll)(s.fwd_in, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            break;
        }
        let buf = s.fwd_buf.as_mut_ptr();
        let (msg, _plen) = net_read_frame(sys, s.fwd_in, buf, FWD_BUF);
        match msg {
            pkt::MSG_PKT_FORWARD => s.forwarded_in = s.forwarded_in.wrapping_add(1),
            0 => break,
            _ => {}
        }
    }
}

unsafe fn log_counts(s: &mut DirectorState) {
    let sys = &*s.syscalls;
    let mut buf = [0u8; 160];
    let bp = buf.as_mut_ptr();
    let mut pos = 0usize;
    let emit = |bytes: &[u8], pos: &mut usize| {
        let mut k = 0;
        while k < bytes.len() && *pos < 160 {
            *bp.add(*pos) = bytes[k];
            *pos += 1;
            k += 1;
        }
    };
    emit(b"[director] decided=", &mut pos);
    pos += fmt_u32_dec(s.decided, bp.add(pos));
    emit(b" local=", &mut pos);
    pos += fmt_u32_dec(s.local, bp.add(pos));
    emit(b" drop=", &mut pos);
    pos += fmt_u32_dec(s.dropped, bp.add(pos));
    emit(b" reject=", &mut pos);
    pos += fmt_u32_dec(s.rejected, bp.add(pos));
    emit(b" tunnel=", &mut pos);
    pos += fmt_u32_dec(s.tunnelled, bp.add(pos));
    emit(b" dsr=", &mut pos);
    pos += fmt_u32_dec(s.dsr, bp.add(pos));
    emit(b" held=", &mut pos);
    pos += fmt_u32_dec(s.held, bp.add(pos));
    emit(b" expired=", &mut pos);
    pos += fmt_u32_dec(s.expired, bp.add(pos));
    emit(b" fwd_in=", &mut pos);
    pos += fmt_u32_dec(s.forwarded_in, bp.add(pos));
    dev_log(sys, 3, bp, pos);
}

// ============================================================================
// Module interface
// ============================================================================

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<DirectorState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() {
        return -2;
    }
    if state.is_null() {
        return -5;
    }
    if state_size < core::mem::size_of::<DirectorState>() {
        return -6;
    }
    let s = &mut *(state as *mut DirectorState);
    core::ptr::write_bytes(state, 0, core::mem::size_of::<DirectorState>());
    s.syscalls = syscalls as *const SyscallTable;
    s.decide_in = in_chan;
    s.dispose_out = out_chan;
    s.fwd_in = dev_channel_port(&*s.syscalls, 0, FWD_IN_PORT);
    s.reject_kind = pkt::reject::TCP_RST;
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    let msg = b"[director] loaded";
    dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut DirectorState);
    s.step_count = s.step_count.wrapping_add(1);
    service_decide(s);
    service_fwd(s);
    if s.step_count.is_multiple_of(LOG_PERIOD) {
        log_counts(s);
    }
    0
}

include!("../../sdk/runtime/wasm_entry.rs");
