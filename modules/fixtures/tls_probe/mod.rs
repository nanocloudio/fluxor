//! tls_probe — a TLS client's proof of life: connect through `tls`, send
//! `ping`, expect `pong`, close, repeat `count` times.
//!
//! The probe sits on the clear side of a client-mode `tls` instance, so
//! its `CMD_CONNECT` completes only once the handshake has, and the
//! steps it counts between the two are the handshake's cost at the graph's
//! tick. Each success is one `[probe] tls ok` line; the run ends with
//! `[probe] done`. A failed attempt is logged and retried after a backoff,
//! so a board whose network is still coming up is not a failure.

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

const NET_MSG_DATA: u8 = 0x02;
const NET_MSG_CLOSED: u8 = 0x03;
const NET_MSG_CONNECTED: u8 = 0x05;
const NET_MSG_ERROR: u8 = 0x06;
const NET_CMD_SEND: u8 = 0x11;
const NET_CMD_CLOSE: u8 = 0x12;
const NET_CMD_CONNECT: u8 = 0x13;

const NO_CONN: u16 = 0xFFFF;
/// Largest inbound frame: header, conn id, one data fragment.
const BUF: usize = 3 + 2 + 1460;
const FRAMES_PER_STEP: usize = 16;
/// Between attempts, and before the first: the network is still coming up.
const RETRY_MS: u32 = 2000;
/// An attempt that has not completed by then is counted as failed.
const ATTEMPT_MS: u32 = 30000;

const PH_IDLE: u8 = 0;
const PH_DIALING: u8 = 1;
const PH_WAIT_PONG: u8 = 2;
const PH_DONE: u8 = 3;

const REASON_ERROR: u8 = 1;
const REASON_CLOSED: u8 = 2;
const REASON_TIMEOUT: u8 = 3;
const REASON_BAD_REPLY: u8 = 4;

#[repr(C)]
pub struct ProbeState {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,
    phase: u8,
    my_tag: u8,
    conn: u16,
    port: u16,
    count: u16,
    peer_ip: u32,
    /// When the current phase may act next (idle: dial; dialing / waiting:
    /// give up).
    at_ms: u32,
    started_ms: u32,
    steps: u32,
    ok: u16,
    fail: u16,
    worst_ms: u32,
    buf: [u8; BUF],
}

mod params_def {
    use super::*;
    define_params! {
        ProbeState;
        1, peer_ip, u32, 0 => |s, d, len| { s.peer_ip = p_u32(d, len, 0, 0); };
        2, port, u16, 8443 => |s, d, len| { s.port = p_u16(d, len, 0, 8443); };
        3, count, u16, 1 => |s, d, len| { s.count = p_u16(d, len, 0, 1); };
    }
}

unsafe fn log(s: &ProbeState, level: u8, m: &[u8]) {
    dev_log(&*s.syscalls, level, m.as_ptr(), m.len());
}

fn put(line: &mut [u8], at: usize, text: &[u8]) -> usize {
    let n = text.len().min(line.len() - at);
    line[at..at + n].copy_from_slice(&text[..n]);
    at + n
}

/// Decimal digits of `v`; the Cortex-M33 PIC build links no 64-bit divide.
fn put_dec(line: &mut [u8], at: usize, v: u32) -> usize {
    let mut w = v;
    let mut digits = [0u8; 10];
    let mut n = 0;
    if w == 0 {
        digits[0] = b'0';
        n = 1;
    }
    while w > 0 {
        digits[n] = b'0' + (w % 10) as u8;
        w /= 10;
        n += 1;
    }
    let mut at = at;
    while n > 0 && at < line.len() {
        n -= 1;
        line[at] = digits[n];
        at += 1;
    }
    at
}

unsafe fn send_connect(s: &mut ProbeState) {
    let sys = &*s.syscalls;
    let mut p = [0u8; 8];
    p[0] = SOCK_TYPE_STREAM;
    p[1..5].copy_from_slice(&s.peer_ip.to_le_bytes());
    p[5..7].copy_from_slice(&s.port.to_le_bytes());
    p[7] = s.my_tag;
    let mut scratch = [0u8; 12];
    net_write_frame(
        sys,
        s.net_out,
        NET_CMD_CONNECT,
        p.as_ptr(),
        8,
        scratch.as_mut_ptr(),
        12,
    );
}

unsafe fn send_ping(s: &mut ProbeState) {
    let sys = &*s.syscalls;
    let mut p = [0u8; 6];
    p[..2].copy_from_slice(&s.conn.to_le_bytes());
    p[2..6].copy_from_slice(b"ping");
    let mut scratch = [0u8; 12];
    net_write_frame(
        sys,
        s.net_out,
        NET_CMD_SEND,
        p.as_ptr(),
        6,
        scratch.as_mut_ptr(),
        12,
    );
}

unsafe fn send_close(s: &mut ProbeState, conn: u16) {
    let sys = &*s.syscalls;
    let p = conn.to_le_bytes();
    let mut scratch = [0u8; 8];
    net_write_frame(
        sys,
        s.net_out,
        NET_CMD_CLOSE,
        p.as_ptr(),
        2,
        scratch.as_mut_ptr(),
        8,
    );
}

unsafe fn report_ok(s: &mut ProbeState, now: u32) {
    let ms = now.wrapping_sub(s.started_ms);
    s.ok += 1;
    if ms > s.worst_ms {
        s.worst_ms = ms;
    }
    let mut line = [0u8; 64];
    let mut at = put(&mut line, 0, b"[probe] tls ok n=");
    at = put_dec(&mut line, at, s.ok as u32);
    at = put(&mut line, at, b" steps=");
    at = put_dec(&mut line, at, s.steps);
    at = put(&mut line, at, b" ms=");
    at = put_dec(&mut line, at, ms);
    dev_log(&*s.syscalls, 3, line.as_ptr(), at);
}

unsafe fn report_fail(s: &mut ProbeState, reason: u8) {
    s.fail += 1;
    let mut line = [0u8; 64];
    let mut at = put(&mut line, 0, b"[probe] tls FAIL n=");
    at = put_dec(&mut line, at, (s.ok as u32) + 1);
    at = put(&mut line, at, b" reason=");
    at = match reason {
        REASON_ERROR => put(&mut line, at, b"error"),
        REASON_CLOSED => put(&mut line, at, b"closed"),
        REASON_TIMEOUT => put(&mut line, at, b"timeout"),
        _ => put(&mut line, at, b"bad_reply"),
    };
    dev_log(&*s.syscalls, 2, line.as_ptr(), at);
}

unsafe fn report_done(s: &mut ProbeState) {
    let mut line = [0u8; 64];
    let mut at = put(&mut line, 0, b"[probe] done ok=");
    at = put_dec(&mut line, at, s.ok as u32);
    at = put(&mut line, at, b" fail=");
    at = put_dec(&mut line, at, s.fail as u32);
    at = put(&mut line, at, b" worst_ms=");
    at = put_dec(&mut line, at, s.worst_ms);
    dev_log(&*s.syscalls, 3, line.as_ptr(), at);
}

/// The attempt is over, one way or the other: close what is open and
/// either schedule the next — at once after a success, after the backoff
/// following a failure — or finish.
unsafe fn end_attempt(s: &mut ProbeState, now: u32, ok: bool) {
    if s.conn != NO_CONN {
        send_close(s, s.conn);
        s.conn = NO_CONN;
    }
    if s.ok >= s.count {
        s.phase = PH_DONE;
        report_done(s);
    } else {
        s.phase = PH_IDLE;
        s.at_ms = if ok { now } else { now.wrapping_add(RETRY_MS) };
    }
}

unsafe fn service_net(s: &mut ProbeState, now: u32) {
    let sys = &*s.syscalls;
    let mut n = 0;
    while n < FRAMES_PER_STEP && s.phase != PH_DONE {
        let (msg, plen) = net_read_frame(sys, s.net_in, s.buf.as_mut_ptr(), BUF);
        if msg == 0 {
            break;
        }
        let p = s.buf.as_ptr().add(3);
        let id = if plen >= 2 {
            (*p as u16) | ((*p.add(1) as u16) << 8)
        } else {
            NO_CONN
        };
        match msg {
            NET_MSG_CONNECTED if plen >= 3 && s.phase == PH_DIALING && *p.add(2) == s.my_tag => {
                s.conn = id;
                s.phase = PH_WAIT_PONG;
                send_ping(s);
            }
            NET_MSG_DATA if plen > 2 && id == s.conn && s.phase == PH_WAIT_PONG => {
                let data = core::slice::from_raw_parts(p.add(2), plen - 2);
                let ok = data == b"pong";
                if ok {
                    report_ok(s, now);
                } else {
                    report_fail(s, REASON_BAD_REPLY);
                }
                end_attempt(s, now, ok);
            }
            NET_MSG_ERROR if s.phase == PH_DIALING => {
                report_fail(s, REASON_ERROR);
                end_attempt(s, now, false);
            }
            NET_MSG_CLOSED | NET_MSG_ERROR if id == s.conn && s.phase == PH_WAIT_PONG => {
                s.conn = NO_CONN;
                report_fail(s, REASON_CLOSED);
                end_attempt(s, now, false);
            }
            _ => {}
        }
        n += 1;
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ProbeState>() as u32
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
    if state_size < core::mem::size_of::<ProbeState>() {
        return -6;
    }
    let s = &mut *(state as *mut ProbeState);
    s.syscalls = syscalls as *const SyscallTable;
    let sys = &*s.syscalls;
    s.net_in = in_chan;
    s.net_out = out_chan;
    s.phase = PH_IDLE;
    s.my_tag = dev_requester_tag(sys);
    s.conn = NO_CONN;
    s.port = 8443;
    s.count = 1;
    s.peer_ip = 0;
    s.at_ms = (dev_millis(sys) as u32).wrapping_add(RETRY_MS);
    s.started_ms = 0;
    s.steps = 0;
    s.ok = 0;
    s.fail = 0;
    s.worst_ms = 0;
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    if s.peer_ip == 0 {
        log(s, 1, b"[probe] refusing to construct: peer_ip is required");
        return -22;
    }
    if s.count == 0 {
        s.count = 1;
    }
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut ProbeState);
    if s.phase == PH_DONE {
        return 0;
    }
    let now = dev_millis(&*s.syscalls) as u32;
    if s.phase == PH_DIALING {
        s.steps = s.steps.wrapping_add(1);
    }
    service_net(s, now);
    let due = now.wrapping_sub(s.at_ms) < 0x8000_0000;
    match s.phase {
        PH_IDLE if due => {
            s.started_ms = now;
            s.steps = 0;
            s.at_ms = now.wrapping_add(ATTEMPT_MS);
            s.phase = PH_DIALING;
            send_connect(s);
        }
        PH_DIALING | PH_WAIT_PONG if due => {
            report_fail(s, REASON_TIMEOUT);
            end_attempt(s, now, false);
        }
        _ => {}
    }
    0
}
