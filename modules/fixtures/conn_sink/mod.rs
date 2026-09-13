//! conn_sink — fixture consumer for the ip connection-table ladders.
//!
//! Binds `port`, accepts every connection offered, holds each open and
//! echoes its bytes back. One bit of state per connection, so the table
//! whose ceiling a ladder climbs is the transport's. Logs
//! `[sink] conns=N peak=P accepted=A bytes=B refused=R bound=0|1` every
//! `LOG_PERIOD` steps; the listen state rides the heartbeat because the
//! one-off `[sink] bound` line is logged before a network debug stack has
//! an address to carry it.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

const NET_MSG_ACCEPTED: u8 = 0x01;
const NET_MSG_DATA: u8 = 0x02;
const NET_MSG_CLOSED: u8 = 0x03;
const NET_MSG_BOUND: u8 = 0x04;
const NET_CMD_BIND: u8 = 0x10;
const NET_CMD_SEND: u8 = 0x11;
const NET_CMD_CLOSE: u8 = 0x12;

const LOG_PERIOD: u32 = 5000;
/// One bit per possible `conn_id`.
const OPEN_WORDS: usize = 65536 / 32;
/// One inbound frame: header + conn id + the largest data fragment.
const BUF: usize = 3 + 2 + 1460;
/// Frames read per step.
const FRAMES_PER_STEP: usize = 64;

#[repr(C)]
pub struct SinkState {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,
    port: u16,
    echo: u8,
    bound: u8,
    step_count: u32,
    pub open: u32,
    pub peak: u32,
    pub accepted: u32,
    pub bytes: u32,
    pub send_refused: u32,
    open_bits: [u32; OPEN_WORDS],
    buf: [u8; BUF],
}

mod params_def {
    use super::*;
    define_params! {
        SinkState;
        1, port, u16, 9000 => |s, d, len| { s.port = p_u16(d, len, 0, 9000); };
        2, echo, u8, 1 => |s, d, len| { s.echo = p_u8(d, len, 0, 1); };
    }
}

fn is_open(s: &SinkState, id: u16) -> bool {
    s.open_bits[id as usize / 32] & (1 << (id % 32)) != 0
}

fn set_open(s: &mut SinkState, id: u16, open: bool) {
    let w = id as usize / 32;
    let m = 1u32 << (id % 32);
    if open {
        s.open_bits[w] |= m;
    } else {
        s.open_bits[w] &= !m;
    }
}

unsafe fn send_bind(s: &mut SinkState) {
    let sys = &*s.syscalls;
    let payload = s.port.to_le_bytes();
    let mut scratch = [0u8; 8];
    net_write_frame(
        sys,
        s.net_out,
        NET_CMD_BIND,
        payload.as_ptr(),
        2,
        scratch.as_mut_ptr(),
        8,
    );
}

unsafe fn log_counters(s: &mut SinkState) {
    let sys = &*s.syscalls;
    let mut line = [0u8; 96];
    let mut p = 0usize;
    let mut put = |b: &[u8]| {
        let n = b.len().min(96 - p);
        line[p..p + n].copy_from_slice(&b[..n]);
        p += n;
    };
    put(b"[sink] conns=");
    let mut tmp = [0u8; 12];
    put(fmt_u32(s.open, &mut tmp));
    put(b" peak=");
    put(fmt_u32(s.peak, &mut tmp));
    put(b" accepted=");
    put(fmt_u32(s.accepted, &mut tmp));
    put(b" bytes=");
    put(fmt_u32(s.bytes, &mut tmp));
    put(b" refused=");
    put(fmt_u32(s.send_refused, &mut tmp));
    put(b" bound=");
    put(fmt_u32(u32::from(s.bound), &mut tmp));
    dev_log(sys, 3, line.as_ptr(), p);
}

fn fmt_u32(mut v: u32, out: &mut [u8; 12]) -> &[u8] {
    let mut i = 12;
    if v == 0 {
        i -= 1;
        out[i] = b'0';
    }
    while v > 0 {
        i -= 1;
        out[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    &out[i..]
}

unsafe fn service(s: &mut SinkState) {
    let sys = &*s.syscalls;
    let mut n = 0;
    while n < FRAMES_PER_STEP {
        let (msg, plen) = net_read_frame(sys, s.net_in, s.buf.as_mut_ptr(), BUF);
        if msg == 0 {
            break;
        }
        let plen = plen as usize;
        let p = s.buf.as_ptr().add(3);
        match msg {
            NET_MSG_BOUND => {
                s.bound = 1;
                let m = b"[sink] bound";
                dev_log(sys, 3, m.as_ptr(), m.len());
            }
            NET_MSG_ACCEPTED if plen >= 2 => {
                let id = (*p as u16) | ((*p.add(1) as u16) << 8);
                // An accept on another listener's port belongs to another
                // reader of the same fanned `ip.net_out`.
                let port = if plen >= 4 {
                    (*p.add(2) as u16) | ((*p.add(3) as u16) << 8)
                } else {
                    s.port
                };
                if port == s.port && !is_open(s, id) {
                    set_open(s, id, true);
                    s.open += 1;
                    s.accepted = s.accepted.wrapping_add(1);
                    if s.open > s.peak {
                        s.peak = s.open;
                    }
                }
            }
            NET_MSG_DATA if plen > 2 => {
                let id = (*p as u16) | ((*p.add(1) as u16) << 8);
                let data_len = plen - 2;
                s.bytes = s.bytes.wrapping_add(data_len as u32);
                if s.echo != 0 && is_open(s, id) {
                    // Echo in place: the payload already has the shape of a
                    // CMD_SEND body, only the type byte differs.
                    *s.buf.as_mut_ptr() = NET_CMD_SEND;
                    let total = 3 + plen;
                    if (sys.channel_write)(s.net_out, s.buf.as_ptr(), total) != total as i32 {
                        s.send_refused = s.send_refused.wrapping_add(1);
                    }
                }
            }
            NET_MSG_CLOSED if plen >= 2 => {
                let id = (*p as u16) | ((*p.add(1) as u16) << 8);
                if is_open(s, id) {
                    set_open(s, id, false);
                    s.open = s.open.saturating_sub(1);
                    // The id is ours until we close it.
                    let payload = id.to_le_bytes();
                    let mut scratch = [0u8; 8];
                    net_write_frame(
                        sys,
                        s.net_out,
                        NET_CMD_CLOSE,
                        payload.as_ptr(),
                        2,
                        scratch.as_mut_ptr(),
                        8,
                    );
                }
            }
            _ => {}
        }
        n += 1;
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<SinkState>() as u32
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
    if syscalls.is_null() || state.is_null() {
        return -22;
    }
    if state_size < core::mem::size_of::<SinkState>() {
        return -6;
    }
    let s = &mut *(state as *mut SinkState);
    s.syscalls = syscalls as *const SyscallTable;
    s.net_in = in_chan;
    s.net_out = out_chan;
    s.port = 9000;
    s.echo = 1;
    s.bound = 0;
    s.step_count = 0;
    s.open = 0;
    s.peak = 0;
    s.accepted = 0;
    s.bytes = 0;
    s.send_refused = 0;
    let mut i = 0;
    while i < OPEN_WORDS {
        s.open_bits[i] = 0;
        i += 1;
    }
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut SinkState);
    s.step_count = s.step_count.wrapping_add(1);
    if s.bound == 0 && s.step_count % 256 == 1 {
        send_bind(s);
    }
    service(s);
    if s.step_count % LOG_PERIOD == 0 {
        log_counters(s);
    }
    0
}
