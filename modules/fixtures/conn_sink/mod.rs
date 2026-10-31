//! conn_sink — fixture consumer for the ip connection-table ladders.
//!
//! Binds `port`, accepts every connection offered, holds each open and
//! echoes its bytes back. One bit of state per connection, so the table
//! whose ceiling a ladder climbs is the transport's. Logs
//! `[sink] conns=N peak=P accepted=A bytes=B refused=R bound=0|1` every
//! `LOG_PERIOD` steps; the listen state rides the heartbeat because the
//! one-off `[sink] bound` line is logged before a network debug stack has
//! an address to carry it.
//!
//! An echo the channel refuses is held and written first next step, and
//! nothing more is read until it is: back pressure reaches the transport
//! instead of the bytes being lost. With `ack` set, each echo is followed
//! by `tls`'s `CMD_DELIVERED` (`[conn_id][consumer_cursor][in_bytes]`),
//! which tells a `tls` running `delivery_ack` how many of the stream's clear
//! bytes are consumed — the worker acknowledgement a crash-continuous pair
//! mirrors. The sink's cursor is the bytes it has consumed (0 unless
//! `cursor` is set); a stream resumed here by a takeover (`MSG_RESUMED`)
//! continues from the byte it names. With `cursor` both are logged
//! (`[sink] acked cursor=N in=I`, `[sink] resumed cursor=C in=I out=O`).
//! With `echo_after`, exactly that many bytes are consumed at a time (an
//! acknowledgement may stand inside a record), the rest held for the next.

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
/// The connection's output horizon (`net_proto::MSG_HORIZON`).
const NET_MSG_HORIZON: u8 = 0x0B;
/// A stream resumed here by a takeover (`net_proto::MSG_RESUMED`).
const NET_MSG_RESUMED: u8 = abi::contracts::net::net_proto::MSG_RESUMED;
const NET_MSG_CLOSED: u8 = 0x03;
/// `MSG_CLOSED` kind: the peer finished sending (net_proto `CLOSED_PEER_FIN`).
const CLOSED_PEER_FIN: u8 = 1;
const NET_MSG_BOUND: u8 = 0x04;
const NET_CMD_BIND: u8 = 0x10;
const NET_CMD_SEND: u8 = 0x11;
const NET_CMD_CLOSE: u8 = 0x12;
const NET_CMD_CONNECT_TO: u8 = 0x14;
const NET_MSG_CONNECTED: u8 = 0x05;
/// What `echo_after` holds before echoing.
const HOLD_MAX: usize = 4096;
/// `tls`'s clear-side acknowledgement (`delivery_ack`).
const NET_CMD_DELIVERED: u8 = abi::contracts::net::net_proto::CMD_DELIVERED;
use abi::contracts::net::net_proto;
use net_proto::{DELIVERED_LEN, RESUMED_LEN};

const LOG_PERIOD: u32 = 5000;
/// One bit per possible `conn_id`.
const OPEN_WORDS: usize = 65536 / 32;
/// One inbound frame: header + conn id + the largest data fragment.
const BUF: usize = 3 + 2 + 1460;
/// Frames read per step.
const FRAMES_PER_STEP: usize = 64;
/// The longest `CMD_SEND` this writes: an `echo_after` hold, whole.
const SEND_MAX: usize = 5 + HOLD_MAX;
const _: () = assert!(SEND_MAX >= BUF);

#[repr(C)]
pub struct SinkState {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,
    port: u16,
    echo: u8,
    ack: u8,
    bound: u8,
    /// An echo the channel refused, written before anything else is read.
    held_len: u16,
    /// A `CMD_DELIVERED` owed for this connection.
    ack_owed: u8,
    ack_conn: u16,
    /// `cursor`: acknowledgements carry the consumer cursor — the bytes
    /// consumed so far (`consumed`), as of the owed one (`ack_cursor`).
    cursor: u8,
    consumed: u64,
    ack_cursor: u64,
    step_count: u32,
    pub open: u32,
    pub peak: u32,
    pub accepted: u32,
    pub bytes: u32,
    pub send_refused: u32,
    /// `linger_ms` / `farewell`: a connection whose peer half-closed is kept
    /// open this long, then sent `farewell` bytes, then closed — one at a
    /// time.
    linger_ms: u16,
    farewell: u16,
    lingering: u8,
    linger_id: u16,
    linger_until: u64,
    farewell_sent: u16,
    pub farewells: u32,
    /// `close_after`: our own close once this many bytes were echoed.
    close_after: u16,
    echoed: u32,
    /// `echo_after`: received bytes held (unconsumed) until this many.
    echo_after: u16,
    hold_len: u16,
    hold_conn: u16,
    hold: [u8; HOLD_MAX],
    /// `dial`: connect out to `dial_ip:dial_port` instead of listening.
    dial_ip: u32,
    dial_port: u16,
    dialled: u8,
    open_bits: [u32; OPEN_WORDS],
    buf: [u8; BUF],
    held: [u8; SEND_MAX],
}

mod params_def {
    use super::*;
    define_params! {
        SinkState;
        1, port, u16, 9000 => |s, d, len| { s.port = p_u16(d, len, 0, 9000); };
        2, echo, u8, 1 => |s, d, len| { s.echo = p_u8(d, len, 0, 1); };
        3, ack, u8, 0 => |s, d, len| { s.ack = p_u8(d, len, 0, 0); };
        // A peer that half-closes (MSG_CLOSED) is kept open `linger_ms`, then
        // sent `farewell` bytes — byte i is `(i * 31 + 7) mod 256` — and
        // closed: a service still writing after its client is done. 0: the
        // close is answered at once.
        4, linger_ms, u16, 0 => |s, d, len| { s.linger_ms = p_u16(d, len, 0, 0); };
        5, farewell, u16, 0 => |s, d, len| { s.farewell = p_u16(d, len, 0, 0); };
        // Our own close: once this many bytes were echoed on a connection
        // the service sends `farewell` and closes its side while the client
        // keeps its open. 0: never.
        6, close_after, u16, 0 => |s, d, len| { s.close_after = p_u16(d, len, 0, 0); };
        // Bytes received are held, unconsumed (no `CMD_DELIVERED`), until
        // this many have come; then they are echoed and acknowledged. One
        // hold serves every connection, so this is for one connection at a
        // time. 0: each is echoed as it comes.
        7, echo_after, u16, 0 => |s, d, len| { s.echo_after = p_u16(d, len, 0, 0).min(HOLD_MAX as u16); };
        // Dial out (`a.b.c.d:port`) instead of listening: the sink is the
        // client of the session and echoes what the server sends.
        8, dial, str, 0 => |s, d, len| { parse_dial(s, core::slice::from_raw_parts(d, len)); };
        // With `ack`: every CMD_DELIVERED carries the consumer cursor (the
        // bytes consumed so far), and a resumed stream continues from the
        // cursor its MSG_RESUMED names.
        9, cursor, u8, 0 => |s, d, len| { s.cursor = p_u8(d, len, 0, 0); };
    }
}

fn parse_dial(s: &mut SinkState, t: &[u8]) {
    let t = t.split(|&b| b == 0).next().unwrap_or(&[]);
    let Some(colon) = t.iter().rposition(|&b| b == b':') else {
        return;
    };
    let mut ip = 0u32;
    let mut parts = 0;
    for part in t[..colon].split(|&b| b == b'.') {
        let mut v = 0u32;
        for &b in part {
            if !b.is_ascii_digit() {
                return;
            }
            v = v * 10 + u32::from(b - b'0');
        }
        if part.is_empty() || v > 255 {
            return;
        }
        ip = (ip << 8) | v;
        parts += 1;
    }
    let mut port = 0u32;
    for &b in &t[colon + 1..] {
        if !b.is_ascii_digit() {
            return;
        }
        port = port * 10 + u32::from(b - b'0');
    }
    if parts == 4 && port > 0 && port < 65536 {
        s.dial_ip = ip;
        s.dial_port = port as u16;
    }
}

/// `CMD_CONNECT_TO` `[sock_type 1][af 4][port u16 LE][addr 4 BE]`.
unsafe fn send_dial(s: &mut SinkState) {
    let sys = &*s.syscalls;
    let pb = s.dial_port.to_le_bytes();
    let ab = s.dial_ip.to_be_bytes();
    let p = [1u8, 4, pb[0], pb[1], ab[0], ab[1], ab[2], ab[3]];
    let mut scratch = [0u8; 16];
    if net_write_frame(
        sys,
        s.net_out,
        NET_CMD_CONNECT_TO,
        p.as_ptr(),
        p.len(),
        scratch.as_mut_ptr(),
        16,
    ) != 0
    {
        s.dialled = 1;
    }
}

/// Write `bytes` for `id` as one CMD_SEND, holding it whole if refused.
unsafe fn send_data(s: &mut SinkState, id: u16, bytes: &[u8]) {
    let sys = &*s.syscalls;
    let total = 5 + bytes.len();
    let mut f = [0u8; SEND_MAX];
    f[0] = NET_CMD_SEND;
    f[1..3].copy_from_slice(&((2 + bytes.len()) as u16).to_le_bytes());
    f[3..5].copy_from_slice(&id.to_le_bytes());
    f[5..total].copy_from_slice(bytes);
    if (sys.channel_write)(s.net_out, f.as_ptr(), total) != total as i32 {
        s.send_refused = s.send_refused.wrapping_add(1);
        s.held[..total].copy_from_slice(&f[..total]);
        s.held_len = total as u16;
    }
}

/// After an echo: our own close once `close_after` bytes have gone.
unsafe fn after_echo(s: &mut SinkState, id: u16, n: usize) {
    s.echoed = s.echoed.wrapping_add(n as u32);
    if s.close_after != 0 && s.lingering == 0 && s.echoed >= u32::from(s.close_after) {
        s.close_after = 0;
        s.lingering = 1;
        s.linger_id = id;
        s.linger_until = 0;
        s.farewell_sent = 0;
        let m = b"[sink] closing our side";
        dev_log(&*s.syscalls, 3, m.as_ptr(), m.len());
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

/// `[sink] <head><a>` and, given one, ` out=<b>`.
unsafe fn log_value(sys: &SyscallTable, head: &[u8], a: u64, more: &[(&[u8], u64)]) {
    let mut line = [0u8; 96];
    let mut at = head.len().min(40);
    line[..at].copy_from_slice(&head[..at]);
    let mut tmp = [0u8; 12];
    let d = fmt_u32(a.min(u64::from(u32::MAX)) as u32, &mut tmp);
    line[at..at + d.len()].copy_from_slice(d);
    at += d.len();
    for &(label, v) in more {
        let l = label.len().min(8);
        line[at..at + l].copy_from_slice(&label[..l]);
        at += l;
        let d = fmt_u32(v.min(u64::from(u32::MAX)) as u32, &mut tmp);
        line[at..at + d.len()].copy_from_slice(d);
        at += d.len();
    }
    dev_log(sys, 3, line.as_ptr(), at);
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

/// Write what a refused write left owed: the held echo, then its
/// acknowledgement. False while either is still owed.
unsafe fn flush_owed(s: &mut SinkState) -> bool {
    let sys = &*s.syscalls;
    if s.held_len > 0 {
        let n = usize::from(s.held_len);
        if (sys.channel_write)(s.net_out, s.held.as_ptr(), n) != n as i32 {
            return false;
        }
        s.held_len = 0;
    }
    if s.ack_owed != 0 {
        let id = s.ack_conn.to_le_bytes();
        let mut f = [0u8; 3 + DELIVERED_LEN];
        f[..5].copy_from_slice(&[NET_CMD_DELIVERED, DELIVERED_LEN as u8, 0, id[0], id[1]]);
        let cursor = if s.cursor != 0 { s.ack_cursor } else { 0 };
        f[5..13].copy_from_slice(&cursor.to_le_bytes());
        f[13..21].copy_from_slice(&s.ack_cursor.to_le_bytes());
        if (sys.channel_write)(s.net_out, f.as_ptr(), f.len()) != f.len() as i32 {
            return false;
        }
        s.ack_owed = 0;
        if s.cursor != 0 {
            log_value(
                sys,
                b"[sink] acked cursor=",
                cursor,
                &[(b" in=", s.ack_cursor)],
            );
        }
    }
    true
}

/// A lingering connection's farewell, then its close, once its time is up.
unsafe fn linger(s: &mut SinkState) {
    if s.lingering == 0 {
        return;
    }
    let sys = &*s.syscalls;
    if dev_millis(sys) < s.linger_until || !flush_owed(s) {
        return;
    }
    let id = s.linger_id;
    while s.farewell_sent < s.farewell {
        let n = usize::from(s.farewell - s.farewell_sent).min(1024);
        let mut f = [0u8; 3 + 2 + 1024];
        f[0] = NET_CMD_SEND;
        f[1..3].copy_from_slice(&((2 + n) as u16).to_le_bytes());
        f[3..5].copy_from_slice(&id.to_le_bytes());
        let mut k = 0;
        while k < n {
            let i = u32::from(s.farewell_sent) + k as u32;
            f[5 + k] = (i.wrapping_mul(31).wrapping_add(7)) as u8;
            k += 1;
        }
        if (sys.channel_write)(s.net_out, f.as_ptr(), 5 + n) != (5 + n) as i32 {
            return;
        }
        s.farewell_sent += n as u16;
    }
    let payload = id.to_le_bytes();
    let mut scratch = [0u8; 8];
    if net_write_frame(
        sys,
        s.net_out,
        NET_CMD_CLOSE,
        payload.as_ptr(),
        2,
        scratch.as_mut_ptr(),
        8,
    ) == 0
    {
        return;
    }
    s.lingering = 0;
    s.farewells = s.farewells.wrapping_add(1);
    if is_open(s, id) {
        set_open(s, id, false);
        s.open = s.open.saturating_sub(1);
    }
    let m = b"[sink] farewell sent; closed";
    dev_log(sys, 3, m.as_ptr(), m.len());
}

unsafe fn service(s: &mut SinkState) {
    let sys = &*s.syscalls;
    let mut n = 0;
    while n < FRAMES_PER_STEP {
        if !flush_owed(s) {
            break;
        }
        let (msg, plen) = net_read_frame(sys, s.net_in, s.buf.as_mut_ptr(), BUF);
        if msg == 0 {
            break;
        }
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
            // Our dial's session, or one we dialled elsewhere that moved
            // here (`tls` activates a client session with CONNECTED).
            NET_MSG_CONNECTED if plen >= 2 => {
                let id = (*p as u16) | ((*p.add(1) as u16) << 8);
                if !is_open(s, id) {
                    set_open(s, id, true);
                    s.open += 1;
                    s.accepted = s.accepted.wrapping_add(1);
                    s.peak = s.peak.max(s.open);
                    let m = b"[sink] connected";
                    dev_log(sys, 3, m.as_ptr(), m.len());
                }
            }
            // `tls`'s output horizon (`write_horizon`): logged, so a rig can
            // hold what a takeover kept against what the client received.
            NET_MSG_HORIZON if plen == 10 => {
                let mut b = [0u8; 8];
                core::ptr::copy_nonoverlapping(p.add(2), b.as_mut_ptr(), 8);
                let through = u64::from_le_bytes(b);
                let mut line = [0u8; 48];
                let head = b"[sink] horizon bytes=";
                line[..head.len()].copy_from_slice(head);
                let mut tmp = [0u8; 12];
                let digits = fmt_u32(through.min(u64::from(u32::MAX)) as u32, &mut tmp);
                line[head.len()..head.len() + digits.len()].copy_from_slice(digits);
                dev_log(sys, 3, line.as_ptr(), head.len() + digits.len());
            }
            // A stream resumed here: its predecessor's cursor, the byte it
            // had consumed through and its output horizon. The count of
            // bytes consumed continues from that byte.
            NET_MSG_RESUMED if plen == RESUMED_LEN => {
                let mut r = [0u8; RESUMED_LEN];
                core::ptr::copy_nonoverlapping(p, r.as_mut_ptr(), RESUMED_LEN);
                if let Some((_, cursor, in_bytes, out)) = net_proto::resumed_parts(&r) {
                    s.consumed = in_bytes;
                    log_value(
                        sys,
                        b"[sink] resumed cursor=",
                        cursor,
                        &[(b" in=", in_bytes), (b" out=", out)],
                    );
                }
            }
            NET_MSG_DATA if plen > 2 && s.echo_after != 0 => {
                let id = (*p as u16) | ((*p.add(1) as u16) << 8);
                let data_len = plen - 2;
                s.bytes = s.bytes.wrapping_add(data_len as u32);
                if is_open(s, id) {
                    // Held unconsumed until `echo_after` bytes have come.
                    let at = usize::from(s.hold_len);
                    let k = data_len.min(HOLD_MAX - at);
                    core::ptr::copy_nonoverlapping(p.add(2), s.hold.as_mut_ptr().add(at), k);
                    s.hold_len += k as u16;
                    s.hold_conn = id;
                    if s.hold_len >= s.echo_after {
                        // Exactly `echo_after` consumed; the rest waits for
                        // the next.
                        let n = usize::from(s.echo_after);
                        let held = s.hold;
                        let rest = usize::from(s.hold_len) - n;
                        s.hold.copy_within(n..n + rest, 0);
                        s.hold_len = rest as u16;
                        send_data(s, id, &held[..n]);
                        if s.ack != 0 {
                            s.ack_owed = 1;
                            s.ack_conn = id;
                            s.consumed = s.consumed.wrapping_add(n as u64);
                            s.ack_cursor = s.consumed;
                        }
                        let m = b"[sink] held bytes echoed";
                        dev_log(sys, 3, m.as_ptr(), m.len());
                        after_echo(s, id, n);
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
                        s.held[..total].copy_from_slice(&s.buf[..total]);
                        s.held_len = total as u16;
                    }
                    if s.ack != 0 {
                        s.ack_owed = 1;
                        s.ack_conn = id;
                        s.consumed = s.consumed.wrapping_add(data_len as u64);
                        s.ack_cursor = s.consumed;
                    }
                    after_echo(s, id, data_len);
                }
            }
            NET_MSG_CLOSED if plen >= 2 => {
                let id = (*p as u16) | ((*p.add(1) as u16) << 8);
                // `[conn_id][kind]`: only the peer's FIN half-closes; a
                // connection that is gone is closed at once.
                let peer_fin = plen >= 3 && *p.add(2) == CLOSED_PEER_FIN;
                if is_open(s, id) && peer_fin && s.linger_ms != 0 && s.lingering == 0 {
                    // Half-closed: ours stays open for a while yet.
                    s.lingering = 1;
                    s.linger_id = id;
                    s.linger_until = dev_millis(sys) + u64::from(s.linger_ms);
                    s.farewell_sent = 0;
                    let m = b"[sink] peer half-closed; lingering";
                    dev_log(sys, 3, m.as_ptr(), m.len());
                } else if is_open(s, id) {
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

declare_module_state_bytes!(SinkState);

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<SinkState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
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
    core::ptr::write_bytes(state, 0, core::mem::size_of::<SinkState>());
    let s = &mut *(state as *mut SinkState);
    s.syscalls = syscalls as *const SyscallTable;
    s.net_in = in_chan;
    s.net_out = out_chan;
    s.port = 9000;
    s.echo = 1;
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut SinkState);
    s.step_count = s.step_count.wrapping_add(1);
    if s.dial_port != 0 {
        if s.dialled == 0 && s.step_count % 256 == 1 {
            send_dial(s);
        }
    } else if s.bound == 0 && s.step_count % 256 == 1 {
        send_bind(s);
    }
    service(s);
    linger(s);
    if s.step_count.is_multiple_of(LOG_PERIOD) {
        log_counters(s);
    }
    0
}
