//! stream_intake — one TCP connection's bytes, as a byte stream.
//!
//! Binds `port`, accepts a connection, and writes what arrives on it to the
//! `bytes` output, in order and whole: a frame the consumer has no room for
//! is held, and nothing more is read from the network until it has gone, so
//! the transport's window closes rather than a byte being dropped. One
//! connection at a time; a second is closed on arrival.
//!
//! The fixture an on-board OTA run is fed by: the bench streams a graph image
//! to it and `ota_ingest` reads the image from `bytes`. Logs
//! `[intake] bound port=<p>` once listening, `[intake] open` and
//! `[intake] closed bytes=<n>` per connection, and the same `bytes=` as a
//! heartbeat every `LOG_PERIOD` steps while one is open.

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

const NET_MSG_ACCEPTED: u8 = 0x01;
const NET_MSG_DATA: u8 = 0x02;
const NET_MSG_CLOSED: u8 = 0x03;
const NET_MSG_BOUND: u8 = 0x04;
const NET_CMD_BIND: u8 = 0x10;
const NET_CMD_CLOSE: u8 = 0x12;

const LOG_PERIOD: u32 = 5000;
/// One inbound frame: header + conn id + the largest data fragment.
const BUF: usize = 3 + 2 + 1460;
/// Frames read per step.
const FRAMES_PER_STEP: usize = 8;
/// No connection is open.
const NO_CONN: u32 = u32::MAX;
/// The output port `bytes` (index 1; `net_out` is 0).
const PORT_OUT_BYTES: u8 = 1;

#[repr(C)]
pub struct IntakeState {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,
    bytes_out: i32,
    port: u16,
    bound: u8,
    resolved: u8,
    step_count: u32,
    /// The open connection's id, or `NO_CONN`.
    conn: u32,
    /// Bytes handed on for the open connection.
    taken: u32,
    /// A data payload not yet written whole: `buf[held_at..held_end]`.
    held_at: u16,
    held_end: u16,
    /// The open connection closed while bytes were still held: it is closed
    /// once they have gone.
    close_pending: u8,
    buf: [u8; BUF],
}

mod params_def {
    use super::*;
    define_params! {
        IntakeState;
        1, port, u16, 7100 => |s, d, len| { s.port = p_u16(d, len, 0, 7100); };
    }
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

unsafe fn say(sys: &SyscallTable, text: &[u8], value: Option<u32>) {
    let mut line = [0u8; 48];
    let mut p = 0usize;
    let mut put = |b: &[u8]| {
        let n = b.len().min(48 - p);
        line[p..p + n].copy_from_slice(&b[..n]);
        p += n;
    };
    put(text);
    if let Some(v) = value {
        let mut tmp = [0u8; 12];
        put(fmt_u32(v, &mut tmp));
    }
    dev_log(sys, 3, line.as_ptr(), p);
}

unsafe fn send_bind(s: &mut IntakeState) {
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

unsafe fn send_close(s: &mut IntakeState, id: u16) {
    let sys = &*s.syscalls;
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

/// Write what is held to `bytes`; answers whether nothing is left held.
unsafe fn drain(s: &mut IntakeState) -> bool {
    let sys = &*s.syscalls;
    while s.held_at < s.held_end {
        let at = s.held_at as usize;
        let len = (s.held_end - s.held_at) as usize;
        let n = (sys.channel_write)(s.bytes_out, s.buf.as_ptr().add(at), len);
        if n <= 0 {
            return false;
        }
        s.held_at += n as u16;
        s.taken = s.taken.wrapping_add(n as u32);
    }
    true
}

unsafe fn finish(s: &mut IntakeState) {
    let sys = &*s.syscalls;
    if s.conn != NO_CONN {
        send_close(s, s.conn as u16);
        say(sys, b"[intake] closed bytes=", Some(s.taken));
    }
    s.conn = NO_CONN;
    s.close_pending = 0;
}

unsafe fn service(s: &mut IntakeState) {
    let sys = &*s.syscalls;
    if !drain(s) {
        return;
    }
    if s.close_pending != 0 {
        finish(s);
    }
    let mut n = 0;
    while n < FRAMES_PER_STEP {
        let (msg, plen) = net_read_frame(sys, s.net_in, s.buf.as_mut_ptr(), BUF);
        if msg == 0 {
            break;
        }
        n += 1;
        let plen = plen as usize;
        let p = s.buf.as_ptr().add(3);
        let id = if plen >= 2 {
            u32::from(*p) | (u32::from(*p.add(1)) << 8)
        } else {
            NO_CONN
        };
        match msg {
            NET_MSG_BOUND => {
                if s.bound == 0 {
                    s.bound = 1;
                    say(sys, b"[intake] bound port=", Some(u32::from(s.port)));
                }
            }
            NET_MSG_ACCEPTED if plen >= 2 => {
                // An accept on another listener's port belongs to another
                // reader of the same fanned `ip.net_out`.
                let port = if plen >= 4 {
                    u16::from(*p.add(2)) | (u16::from(*p.add(3)) << 8)
                } else {
                    s.port
                };
                if port != s.port {
                    continue;
                }
                if s.conn == NO_CONN {
                    s.conn = id;
                    s.taken = 0;
                    say(sys, b"[intake] open", None);
                } else if id != s.conn {
                    send_close(s, id as u16);
                }
            }
            NET_MSG_DATA if plen > 2 && id == s.conn => {
                s.held_at = (3 + 2) as u16;
                s.held_end = (3 + plen) as u16;
                if !drain(s) {
                    // Held: nothing more is read until it has gone.
                    return;
                }
            }
            NET_MSG_CLOSED if id == s.conn && s.conn != NO_CONN => {
                if s.held_at < s.held_end {
                    s.close_pending = 1;
                    return;
                }
                finish(s);
            }
            _ => {}
        }
    }
}

declare_module_state_bytes!(IntakeState);

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<IntakeState>() as u32
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
    if state_size < core::mem::size_of::<IntakeState>() {
        return -6;
    }
    let s = &mut *(state as *mut IntakeState);
    s.syscalls = syscalls as *const SyscallTable;
    s.net_in = in_chan;
    s.net_out = out_chan;
    s.bytes_out = -1;
    s.port = 7100;
    s.bound = 0;
    s.resolved = 0;
    s.step_count = 0;
    s.conn = NO_CONN;
    s.taken = 0;
    s.held_at = 0;
    s.held_end = 0;
    s.close_pending = 0;
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut IntakeState);
    let sys = &*s.syscalls;
    if s.resolved == 0 {
        let mut arg = [1u8, PORT_OUT_BYTES];
        s.bytes_out = (sys.provider_call)(
            -1,
            abi::kernel_abi::channel::PORT,
            arg.as_mut_ptr(),
            arg.len(),
        );
        s.resolved = 1;
    }
    s.step_count = s.step_count.wrapping_add(1);
    if s.bound == 0 && s.step_count % 256 == 1 {
        send_bind(s);
    }
    if s.bytes_out >= 0 {
        service(s);
    }
    if s.conn != NO_CONN && s.step_count % LOG_PERIOD == 0 {
        say(sys, b"[intake] bytes=", Some(s.taken));
    }
    0
}

include!("../../sdk/runtime/wasm_entry.rs");
