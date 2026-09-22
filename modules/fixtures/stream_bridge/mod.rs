//! stream_bridge — one TCP connection as a raw byte stream, the transport
//! `remote_channel` multiplexes over.
//!
//! `mode = listen`: bind `port`, adopt the first accepted connection.
//! `mode = connect`: dial `authority` (`host[:port]`, port 9100 when
//! omitted — a name the network provider resolves, or a literal), redial
//! `RECONNECT_MS` after a close or a refused dial, and `5 ×
//! RECONNECT_MS` after one nothing answered. In both modes the
//! connection's bytes flow to `bytes_out` and `bytes_in` flows to the
//! connection in `CMD_SEND`
//! frames of at most `CHUNK` bytes; a refused write leaves the bytes on
//! `bytes_in` for the next step.

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

#[path = "../../sdk/contracts/net/net_proto.rs"]
mod net_proto;
use net_proto::{
    write_connect_to, Target, AF_INET, AF_INET6, CMD_BIND as NET_CMD_BIND,
    CMD_CLOSE as NET_CMD_CLOSE, CMD_CONNECT_TO as NET_CMD_CONNECT_TO, CMD_SEND as NET_CMD_SEND,
    CONNECT_TO_MAX, MSG_ACCEPTED as NET_MSG_ACCEPTED, MSG_BOUND as NET_MSG_BOUND,
    MSG_CLOSED as NET_MSG_CLOSED, MSG_CONNECTED as NET_MSG_CONNECTED, MSG_DATA as NET_MSG_DATA,
    MSG_ERROR as NET_MSG_ERROR,
};

/// `authority` as written: `host[:port]`.
const MAX_AUTHORITY_LEN: usize = 128;
/// The listener port, and the peer's port when `authority` names none.
const DEFAULT_PORT: u16 = 9100;

const MODE_LISTEN: u8 = 0;
const MODE_CONNECT: u8 = 1;

const BYTES_IN_PORT: u8 = 1;
const BYTES_OUT_PORT: u8 = 1;

const NO_CONN: u16 = 0xFFFF;
/// Bytes per `CMD_SEND`.
const CHUNK: usize = 1024;
/// Largest inbound frame: header, conn id, one data fragment.
const BUF: usize = 3 + 2 + 1460;
const RECONNECT_MS: u32 = 1000;
const FRAMES_PER_STEP: usize = 16;

const PH_IDLE: u8 = 0;
const PH_WAIT_BOUND: u8 = 1;
const PH_LISTENING: u8 = 2;
const PH_DIALING: u8 = 3;
const PH_LIVE: u8 = 4;

#[repr(C)]
pub struct BridgeState {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,
    bytes_in: i32,
    bytes_out: i32,
    mode: u8,
    phase: u8,
    conn: u16,
    /// `listen`: the port bound.
    port: u16,
    /// `connect`: the peer's port — the authority's, or `DEFAULT_PORT`.
    peer_port: u16,
    retry_at_ms: u32,
    my_tag: u8,
    authority_len: u8,
    /// The dial target parsed from `authority` once at construction:
    /// `AF_INET` / `AF_INET6` with the address in `peer_addr`, or
    /// `AF_NAME` with the name being `authority[..peer_host_len]`.
    peer_af: u8,
    peer_host_len: u8,
    peer_addr: [u8; 16],
    authority: [u8; MAX_AUTHORITY_LEN],
    pub bytes_up: u32,
    pub bytes_down: u32,
    pub connections: u32,
    buf: [u8; BUF],
    out: [u8; 3 + 2 + CHUNK],
}

mod params_def {
    use super::*;
    define_params! {
        BridgeState;
        1, mode, u8, 0, enum { listen=0, connect=1 } => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };
        2, port, u16, 9100 => |s, d, len| { s.port = p_u16(d, len, 0, 9100); };
        // Tag 3 is retired; the next allocation is 5.
        4, authority, str, 0 => |s, d, len| {
            // An authority that does not fit is dropped rather than
            // clipped: a prefix of a name is a different host, and the
            // admission below refuses an instance without one.
            let n = if len > MAX_AUTHORITY_LEN { 0 } else { len };
            s.authority_len = n as u8;
            let mut i = 0;
            while i < n {
                s.authority[i] = unsafe { *d.add(i) };
                i += 1;
            }
        };
    }
}

/// Parse `authority` into the dial target the bridge keeps. `false`
/// when it is absent or is not `host[:port]`.
fn adopt_authority(s: &mut BridgeState) -> bool {
    let n = s.authority_len as usize;
    if n == 0 {
        return false;
    }
    let mut copy = [0u8; MAX_AUTHORITY_LEN];
    copy[..n].copy_from_slice(&s.authority[..n]);
    let Some((target, port)) = Target::parse(&copy[..n]) else {
        return false;
    };
    s.peer_port = port.unwrap_or(DEFAULT_PORT);
    s.peer_af = target.af();
    match target {
        Target::V4(a) => s.peer_addr[..4].copy_from_slice(&a),
        Target::V6(a) => s.peer_addr.copy_from_slice(&a),
        Target::Name(name) => s.peer_host_len = name.len() as u8,
    }
    true
}

/// The target `adopt_authority` kept, borrowed for one dial.
fn dial_target(s: &BridgeState) -> Target<'_> {
    match s.peer_af {
        AF_INET => Target::V4([
            s.peer_addr[0],
            s.peer_addr[1],
            s.peer_addr[2],
            s.peer_addr[3],
        ]),
        AF_INET6 => Target::V6(s.peer_addr),
        _ => Target::Name(&s.authority[..s.peer_host_len as usize]),
    }
}

unsafe fn log(s: &BridgeState, m: &[u8]) {
    dev_log(&*s.syscalls, 3, m.as_ptr(), m.len());
}

unsafe fn send_bind(s: &mut BridgeState) {
    let sys = &*s.syscalls;
    let p = s.port.to_le_bytes();
    let mut scratch = [0u8; 8];
    net_write_frame(
        sys,
        s.net_out,
        NET_CMD_BIND,
        p.as_ptr(),
        2,
        scratch.as_mut_ptr(),
        8,
    );
}

unsafe fn send_connect(s: &mut BridgeState) {
    let sys = &*s.syscalls;
    let mut p = [0u8; CONNECT_TO_MAX];
    let n = write_connect_to(
        &mut p,
        SOCK_TYPE_STREAM,
        s.peer_port,
        &dial_target(s),
        Some(s.my_tag),
    );
    let mut scratch = [0u8; 3 + CONNECT_TO_MAX];
    net_write_frame(
        sys,
        s.net_out,
        NET_CMD_CONNECT_TO,
        p.as_ptr(),
        n,
        scratch.as_mut_ptr(),
        scratch.len(),
    );
}

unsafe fn send_close(s: &mut BridgeState, conn: u16) {
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

unsafe fn service_net(s: &mut BridgeState) {
    let sys = &*s.syscalls;
    let mut n = 0;
    while n < FRAMES_PER_STEP {
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
            NET_MSG_BOUND if s.phase == PH_WAIT_BOUND => {
                s.phase = PH_LISTENING;
                log(s, b"[bridge] listening");
            }
            NET_MSG_ACCEPTED if plen >= 2 => {
                // `net_in` may be one reader of a fanned `ip.net_out`: an
                // accept names its listener port, and one on another port
                // belongs to another consumer and is left alone. Only a
                // second accept on this bridge's own port, while it is
                // busy, is refused.
                let port = if plen >= 4 {
                    (*p.add(2) as u16) | ((*p.add(3) as u16) << 8)
                } else {
                    s.port
                };
                if s.mode != MODE_LISTEN || port != s.port {
                    // Not ours.
                } else if s.phase == PH_LISTENING && s.conn == NO_CONN {
                    s.conn = id;
                    s.phase = PH_LIVE;
                    s.connections = s.connections.wrapping_add(1);
                    log(s, b"[bridge] connected");
                } else {
                    send_close(s, id);
                }
            }
            NET_MSG_CONNECTED if plen >= 3 => {
                if s.phase == PH_DIALING && *p.add(2) == s.my_tag {
                    s.conn = id;
                    s.phase = PH_LIVE;
                    s.connections = s.connections.wrapping_add(1);
                    log(s, b"[bridge] connected");
                }
            }
            NET_MSG_DATA if plen > 2 && id == s.conn && s.phase == PH_LIVE => {
                let data = p.add(2);
                let len = plen - 2;
                if (sys.channel_write)(s.bytes_out, data, len) == len as i32 {
                    s.bytes_down = s.bytes_down.wrapping_add(len as u32);
                }
            }
            NET_MSG_CLOSED | NET_MSG_ERROR => {
                let connect_failed = msg == NET_MSG_ERROR && s.phase == PH_DIALING;
                if (id == s.conn && s.phase == PH_LIVE) || connect_failed {
                    if s.phase == PH_LIVE {
                        send_close(s, s.conn);
                        log(s, b"[bridge] closed");
                    }
                    s.conn = NO_CONN;
                    s.phase = if s.mode == MODE_LISTEN {
                        PH_LISTENING
                    } else {
                        PH_IDLE
                    };
                    s.retry_at_ms = (dev_millis(sys) as u32).wrapping_add(RECONNECT_MS);
                }
            }
            _ => {}
        }
        n += 1;
    }
}

unsafe fn service_bytes(s: &mut BridgeState) {
    if s.phase != PH_LIVE {
        return;
    }
    let sys = &*s.syscalls;
    let mut n = 0;
    while n < FRAMES_PER_STEP {
        let poll = (sys.channel_poll)(s.bytes_in, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            break;
        }
        // The net side must be able to take a whole chunk, or the bytes
        // stay where they are.
        let out_poll = (sys.channel_poll)(s.net_out, POLL_OUT);
        if out_poll <= 0 || (out_poll as u32 & POLL_OUT) == 0 {
            break;
        }
        let body = s.out.as_mut_ptr().add(5);
        let got = (sys.channel_read)(s.bytes_in, body, CHUNK);
        if got <= 0 {
            break;
        }
        let len = got as usize;
        let plen = 2 + len;
        *s.out.as_mut_ptr() = NET_CMD_SEND;
        *s.out.as_mut_ptr().add(1) = plen as u8;
        *s.out.as_mut_ptr().add(2) = (plen >> 8) as u8;
        let cb = s.conn.to_le_bytes();
        *s.out.as_mut_ptr().add(3) = cb[0];
        *s.out.as_mut_ptr().add(4) = cb[1];
        let total = 3 + plen;
        if (sys.channel_write)(s.net_out, s.out.as_ptr(), total) == total as i32 {
            s.bytes_up = s.bytes_up.wrapping_add(len as u32);
        }
        n += 1;
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<BridgeState>() as u32
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
    if state_size < core::mem::size_of::<BridgeState>() {
        return -6;
    }
    let s = &mut *(state as *mut BridgeState);
    s.syscalls = syscalls as *const SyscallTable;
    let sys = &*s.syscalls;
    s.net_in = in_chan;
    s.net_out = out_chan;
    s.bytes_in = dev_channel_port(sys, 0, BYTES_IN_PORT);
    s.bytes_out = dev_channel_port(sys, 1, BYTES_OUT_PORT);
    s.mode = MODE_LISTEN;
    s.phase = PH_IDLE;
    s.conn = NO_CONN;
    s.port = DEFAULT_PORT;
    s.peer_port = DEFAULT_PORT;
    s.authority = [0u8; MAX_AUTHORITY_LEN];
    s.authority_len = 0;
    s.peer_af = 0;
    s.peer_host_len = 0;
    s.peer_addr = [0u8; 16];
    s.retry_at_ms = 0;
    s.my_tag = dev_requester_tag(sys);
    s.bytes_up = 0;
    s.bytes_down = 0;
    s.connections = 0;
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    if s.mode == MODE_CONNECT && !adopt_authority(s) {
        let m = b"[bridge] refusing to construct: connect mode needs authority (host[:port])";
        dev_log(sys, 1, m.as_ptr(), m.len());
        return -22;
    }
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut BridgeState);
    let now = dev_millis(&*s.syscalls) as u32;
    service_net(s);
    if s.phase == PH_IDLE && now.wrapping_sub(s.retry_at_ms) < 0x8000_0000 {
        if s.mode == MODE_LISTEN {
            send_bind(s);
            s.phase = PH_WAIT_BOUND;
        } else {
            send_connect(s);
            s.phase = PH_DIALING;
            s.retry_at_ms = now.wrapping_add(5 * RECONNECT_MS);
        }
    } else if s.phase == PH_DIALING && now.wrapping_sub(s.retry_at_ms) < 0x8000_0000 {
        // A dial nobody answered: try again.
        s.phase = PH_IDLE;
    }
    service_bytes(s);
    0
}
