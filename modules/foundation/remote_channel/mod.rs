//! Remote-channel multiplexer: local channels carried record for record
//! across one authenticated transport session.
//!
//! See `manifest.toml` for the ports and parameters and `wire.rs` for the
//! protocol. In outline:
//!
//! - A channel table (`channels`) names each channel's content type, how
//!   its records are delimited locally, and its maximum record. Both ends
//!   exchange tables when a session opens and refuse the session on any
//!   difference.
//! - A record up to its channel's maximum is cut into fragments on the
//!   wire and reassembled whole on the far side before any byte of it is
//!   delivered. A record over the maximum is refused — never truncated —
//!   and counted.
//! - Every channel has its own credit: the receiver grants room in that
//!   channel's reassembly ring and the sender never exceeds it, so a large
//!   or stalled record holds up its own channel and no other, and nothing is
//!   dropped under backpressure.
//! - The transport authenticates. `transport: net` speaks `net_proto` to
//!   the clear side of `tls` (or to a network provider directly, with
//!   `require_peer: 0`); `transport: mux` speaks the mux contract to `quic`,
//!   one stream per channel, so one channel's loss recovery never blocks
//!   another's. With `require_peer` set, a session whose transport did not
//!   bind a peer identity is closed before a byte of it is used.
//! - Authentication is decided once, when a session attaches, from a
//!   record that names that session — on `net`, by its connection id and
//!   the generation the transport numbered it with. The module does not
//!   read a peer's validity window or re-authenticate a live session; a
//!   transport that must end a session when a credential expires closes
//!   it, and the module treats that like any other close. It holds no
//!   credentials of its own.
//! - A delimited record (`tlv16`, `len32`) must carry, in its own header,
//!   the length the wire gave it; a peer whose record does not is refused,
//!   so the local consumer's framing and this module's never differ.
//! - A session that does not finish its setup (identity bound, tables
//!   exchanged) within `SETUP_TIMEOUT_MS` is closed, so a silent peer cannot
//!   hold the one session this instance serves, and a connection or
//!   session that arrives while one is served is closed.
//!
//! Local channels are read and written with `channel_read` and
//! `channel_write` only. On a `mailbox` edge one buffer is one record; an
//! empty buffer is not a record and is skipped.
//!
//! One session at a time. A record whose sending had begun when its session
//! ended is lost and counted; a record not yet begun waits for the next
//! session, and every record delivered was delivered whole. The optional
//! `session` output says when a session opens and ends
//! (`contracts/mesh/remote_session.rs`), so a consumer can stop sending
//! toward a member that cannot hear it rather than wait out a deadline.

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
use abi::contracts::mesh::remote_session;
use abi::contracts::net::{mux, net_proto, peer_identity};
use abi::{errno, SyscallTable};

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

pub mod wire;
use wire::{Entry, Event, Parser, Table, BEGIN_PREFIX, FRAME_HDR, MAX_CHANNELS};

// ── Ceilings ────────────────────────────────────────────────────────────────

/// Largest record any channel may declare. One record is reassembled whole
/// before delivery, so this is the largest single allocation a peer can
/// make this module hold.
#[cfg(target_arch = "aarch64")]
pub const MAX_RECORD: u32 = 256 * 1024;
#[cfg(target_arch = "wasm32")]
pub const MAX_RECORD: u32 = 128 * 1024;
#[cfg(not(any(target_arch = "aarch64", target_arch = "wasm32")))]
pub const MAX_RECORD: u32 = 16 * 1024;

/// Reassembly bytes across every channel: the sum over channels of
/// `max_record + RECORD_CHARGE` must fit, or the instance refuses to
/// construct.
#[cfg(target_arch = "aarch64")]
pub const REASSEMBLY_BYTES: usize = 1024 * 1024;
#[cfg(target_arch = "wasm32")]
pub const REASSEMBLY_BYTES: usize = 256 * 1024;
#[cfg(not(any(target_arch = "aarch64", target_arch = "wasm32")))]
pub const REASSEMBLY_BYTES: usize = 32 * 1024;

/// Record bytes in one frame on the `net` carrier. Bounds how long one
/// channel's fragment holds the shared stream before the next channel's
/// turn.
pub const FRAGMENT_MAX: usize = 4096;

/// Record bytes in one frame on the `mux` carrier: a whole frame fits one
/// `CMD_MUX_STREAM_SEND`.
pub const MUX_FRAGMENT_MAX: usize = 1192;
const _: () = assert!(MUX_FRAGMENT_MAX == mux::MUX_QUIC_STREAM_SEND_MAX - FRAME_HDR - BEGIN_PREFIX);

/// Credit each record costs beyond its bytes: the length the receiver
/// files it under in its ring. Charging it is what bounds the ring at
/// `max_record + RECORD_CHARGE` however small the records are.
pub const RECORD_CHARGE: u32 = 4;

const TRANSPORT_NET: u8 = 0;
const TRANSPORT_MUX: u8 = 1;
const ROLE_LISTEN: u8 = 0;
const ROLE_DIAL: u8 = 1;

const PORT_PEER_IDENTITY: u8 = 1;
const PORT_CH_IN: u8 = 2;
const PORT_CH_OUT: u8 = 1;
/// Output after the eight `chN_rx`.
const PORT_SESSION: u8 = 9;

const MAX_AUTHORITY_LEN: usize = 128;
const TABLE_TEXT_MAX: usize = 512;
const DEFAULT_PORT: u16 = 9100;
const NO_CONN: u16 = 0xFFFF;

/// Transport events taken per step.
const EVENTS_PER_STEP: usize = 32;
/// Frames written per step.
const FRAMES_PER_STEP: usize = 32;
/// How long a transport session may take to become a channel session —
/// peer identity bound, tables exchanged — before it is closed. A peer that
/// connects and says nothing must not hold the one session this instance
/// serves. Once the peer is bound, time spent waiting for the local
/// consumers to drain a previous session's records does not count.
const SETUP_TIMEOUT_MS: u32 = 10_000;
/// Closes owed for connections (`net`) or sessions (`mux`) this instance
/// will not use and the transport has not yet taken. Transport input pauses
/// while the queue is full, so none is dropped.
const CLOSES_OWED: usize = 4;

const RX_SCRATCH: usize = 3 + mux::MUX_QUIC_STREAM_RX_FRAME_MAX + 64;
const TX_PREFIX: usize = 3 + mux::STREAM_DATA_PREFIX;
const TX_BUF: usize = TX_PREFIX + FRAME_HDR + BEGIN_PREFIX + FRAGMENT_MAX;

// Session phases.
const PH_IDLE: u8 = 0;
const PH_WAIT_BOUND: u8 = 1;
const PH_LISTENING: u8 = 2;
const PH_DIALING: u8 = 3;
/// Transport session up; waiting for its peer identity, for streams, and
/// for every reassembly ring to drain before the table goes out.
const PH_ATTACHING: u8 = 4;
/// Table sent; waiting for the peer's.
const PH_HELLO: u8 = 5;
const PH_OPEN: u8 = 6;

// Send states per channel.
const TX_IDLE: u8 = 0;
const TX_BODY: u8 = 1;
const TX_DISCARD: u8 = 2;

#[repr(C)]
struct Chan {
    entry: Entry,
    input: i32,
    output: i32,
    // Reassembly ring: [len:4 LE][record] per record, `ring_off` into the pool.
    ring_off: u32,
    ring_cap: u32,
    ring_head: u32,
    ring_used: u32,
    /// The record being received: its length, bytes so far, and where its
    /// length prefix sits.
    rx_len: u32,
    rx_have: u32,
    rx_active: bool,
    /// Bytes of the front record already written to the local output.
    deliver_off: u32,
    /// Credit to return to the peer.
    credit_owed: u32,
    /// Credit the peer has granted for our sends.
    tx_credit: u32,
    tx_state: u8,
    tx_hdr: [u8; 4],
    tx_hdr_have: u8,
    tx_len: u64,
    tx_sent: u64,
    /// `mailbox`: where a record is held whole while it is sent, and where
    /// a reassembled one is laid out flat for its single delivering write.
    tx_stage: u32,
    rx_stage: u32,
    /// `mux`: the stream carrying this channel, and whether the peer's
    /// table has arrived on it.
    stream: u32,
    has_stream: bool,
    hello_rx: bool,
    hello_owed: bool,
    pub records_sent: u32,
    pub records_delivered: u32,
    pub refused_oversize: u32,
    pub lost: u32,
}

/// A `mux` stream not yet known to carry a channel, with its parser.
#[repr(C)]
struct Slot {
    stream: u32,
    used: bool,
    channel: u8,
    ack_owed: u32,
    parser: Parser,
}

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    transport_in: i32,
    transport_out: i32,
    identity_in: i32,
    transport: u8,
    role: u8,
    require_peer: u8,
    phase: u8,
    port: u16,
    peer_port: u16,
    redial_ms: u32,
    retry_at_ms: u32,
    /// When an attaching session is given up on; see `SETUP_TIMEOUT_MS`.
    setup_deadline_ms: u32,
    my_tag: u8,
    peer_af: u8,
    peer_host_len: u8,
    authority_len: u8,
    peer_addr: [u8; 16],
    authority: [u8; MAX_AUTHORITY_LEN],
    table_text: [u8; TABLE_TEXT_MAX],
    table_text_len: u16,
    table_text_overflow: bool,
    table: Table,
    // Transport session.
    conn: u16,
    generation: u16,
    session: u32,
    local_init: bool,
    peer_bound: bool,
    hello_owed: bool,
    refuse_owed: u8,
    opening: u8,
    open_pending: bool,
    /// The latest peer-identity record seen: whose and whether it bound.
    id_conn: u16,
    id_generation: u16,
    id_bound: bool,
    id_seen: bool,
    net_parser: Parser,
    chans: [Chan; MAX_CHANNELS],
    slots: [Slot; MAX_CHANNELS],
    rr: u8,
    tx: [u8; TX_BUF],
    tx_len: u16,
    /// Owed closes, oldest first; see `CLOSES_OWED`.
    closes: [u32; CLOSES_OWED],
    n_closes: u8,
    rx: [u8; RX_SCRATCH],
    pub sessions: u32,
    /// `session` output; see `report_session`.
    session_out: i32,
    /// The state the `session` output last carried: open, and its ordinal.
    reported_open: bool,
    reported_session: u32,
    pool: [u8; REASSEMBLY_BYTES],
}

mod params_def {
    use super::*;
    define_params! {
        State;
        1, transport, u8, 0, enum { net=0, mux=1 } => |s, d, len| { s.transport = p_u8(d, len, 0, 0); };
        2, role, u8, 0, enum { listen=0, dial=1 } => |s, d, len| { s.role = p_u8(d, len, 0, 0); };
        3, port, u16, 9100 => |s, d, len| { s.port = p_u16(d, len, 0, 9100); };
        4, authority, str, 0 => |s, d, len| {
            // A value that does not fit is dropped, not clipped: a prefix of
            // a name is another host.
            let n = if len > MAX_AUTHORITY_LEN { 0 } else { len };
            s.authority_len = n as u8;
            let mut i = 0;
            while i < n {
                s.authority[i] = unsafe { *d.add(i) };
                i += 1;
            }
        };
        5, channels, str, 0 => |s, d, len| {
            if len > TABLE_TEXT_MAX {
                s.table_text_overflow = true;
            } else {
                s.table_text_len = len as u16;
                let mut i = 0;
                while i < len {
                    s.table_text[i] = unsafe { *d.add(i) };
                    i += 1;
                }
            }
        };
        6, require_peer, u8, 1 => |s, d, len| { s.require_peer = p_u8(d, len, 0, 1); };
        7, redial_ms, u32, 1000 => |s, d, len| { s.redial_ms = p_u32(d, len, 0, 1000); };
    }
}

// Indexed by `wire::TableError`.
name_table!(
    TABLE_ERRORS = [
        b"[remote_channel] refusing to construct: `channels` is empty",
        b"[remote_channel] refusing to construct: `channels` names more than MAX_CHANNELS",
        b"[remote_channel] refusing to construct: a `channels` entry is not content_type:framing:max_record",
        b"[remote_channel] refusing to construct: a `channels` content type is empty, too long, or not alphanumeric",
        b"[remote_channel] refusing to construct: a `channels` framing is not tlv16, len32, mailbox or bytes",
        b"[remote_channel] refusing to construct: a `channels` max_record is outside what its framing and MAX_RECORD admit",
    ]
);

unsafe fn log(s: &State, level: u8, m: &[u8]) {
    dev_log(&*s.syscalls, level, m.as_ptr(), m.len());
}

fn n_channels(s: &State) -> usize {
    s.table.channels as usize
}

// ── Construction ────────────────────────────────────────────────────────────

fn adopt_authority(s: &mut State) -> bool {
    let n = s.authority_len as usize;
    if n == 0 {
        return false;
    }
    let mut copy = [0u8; MAX_AUTHORITY_LEN];
    copy[..n].copy_from_slice(&s.authority[..n]);
    let Some((target, port)) = net_proto::Target::parse(&copy[..n]) else {
        return false;
    };
    s.peer_port = port.unwrap_or(DEFAULT_PORT);
    s.peer_af = target.af();
    match target {
        net_proto::Target::V4(a) => s.peer_addr[..4].copy_from_slice(&a),
        net_proto::Target::V6(a) => s.peer_addr.copy_from_slice(&a),
        net_proto::Target::Name(name) => s.peer_host_len = name.len() as u8,
    }
    true
}

fn dial_target(s: &State) -> net_proto::Target<'_> {
    match s.peer_af {
        net_proto::AF_INET => net_proto::Target::V4([
            s.peer_addr[0],
            s.peer_addr[1],
            s.peer_addr[2],
            s.peer_addr[3],
        ]),
        net_proto::AF_INET6 => net_proto::Target::V6(s.peer_addr),
        _ => net_proto::Target::Name(&s.authority[..s.peer_host_len as usize]),
    }
}

/// Lay each channel's region out in the pool: its reassembly ring, and on
/// a `mailbox` channel a send stage and a delivery stage of one record
/// each. `false` when the table needs more than `REASSEMBLY_BYTES`.
fn carve_pool(s: &mut State) -> bool {
    let mut at: u64 = 0;
    for i in 0..n_channels(s) {
        let e = s.table.entries[i];
        let max = e.max_record as u64;
        let ring = max + RECORD_CHARGE as u64;
        s.chans[i].ring_off = at as u32;
        s.chans[i].ring_cap = ring as u32;
        at += ring;
        if e.framing == wire::framing::MAILBOX {
            s.chans[i].tx_stage = at as u32;
            s.chans[i].rx_stage = (at + max) as u32;
            at += 2 * max;
        }
        if at > REASSEMBLY_BYTES as u64 {
            return false;
        }
    }
    true
}

/// The deadline `wait_ms` after `now`. Deadlines are compared by wrapping
/// difference, so a wait is held below half the clock's range: a longer one
/// would read as already past.
fn later(now: u32, wait_ms: u32) -> u32 {
    now.wrapping_add(wait_ms.min(i32::MAX as u32))
}

// ── Transport writes ────────────────────────────────────────────────────────

/// Write the frame staged in `tx`. True when it went out (or none was
/// owed); a refused write stays staged and goes first on the next call.
unsafe fn flush_tx(s: &mut State) -> bool {
    if s.tx_len == 0 {
        return true;
    }
    let sys = &*s.syscalls;
    let n = s.tx_len as usize;
    if (sys.channel_write)(s.transport_out, s.tx.as_ptr(), n) == n as i32 {
        s.tx_len = 0;
        true
    } else {
        false
    }
}

/// Stage a carrier command whose payload is already at `tx[TX_PREFIX..]`
/// (`body_len` bytes), addressed to `chan` (`mux`: its stream), and try to
/// write it. The command is committed once staged: a refused write leaves it
/// in `tx` for `flush_tx`, so callers never stage it again.
unsafe fn send_staged(s: &mut State, chan: Option<usize>, body_len: usize) {
    let (start, cmd, plen) = if s.transport == TRANSPORT_NET {
        let start = TX_PREFIX - 5;
        s.tx[start + 3..start + 5].copy_from_slice(&s.conn.to_le_bytes());
        (start, net_proto::CMD_SEND, 2 + body_len)
    } else {
        let stream = match chan {
            Some(c) => s.chans[c].stream,
            None => return,
        };
        let start = TX_PREFIX - 3 - mux::STREAM_DATA_PREFIX;
        mux::put_session_id(&mut s.tx[start + 3..], s.session);
        mux::put_stream_id(&mut s.tx[start + 3..], stream);
        (
            start,
            mux::CMD_MUX_STREAM_SEND,
            mux::STREAM_DATA_PREFIX + body_len,
        )
    };
    s.tx[start] = cmd;
    s.tx[start + 1..start + 3].copy_from_slice(&(plen as u16).to_le_bytes());
    if start > 0 {
        s.tx.copy_within(start..start + 3 + plen, 0);
    }
    s.tx_len = (3 + plen) as u16;
    flush_tx(s);
}

/// Commit a whole carrier-level command (`net_proto` / mux) with `payload`.
/// True when it was staged — written, or held for the next flush; false
/// when an earlier frame is still unwritten and nothing was staged.
unsafe fn command(s: &mut State, cmd: u8, payload: &[u8]) -> bool {
    if !flush_tx(s) {
        return false;
    }
    let n = 3 + payload.len();
    s.tx[0] = cmd;
    s.tx[1..3].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    s.tx[3..n].copy_from_slice(payload);
    s.tx_len = n as u16;
    flush_tx(s);
    true
}

/// Commit a protocol frame `[kind][channel][len][body]` for `chan`, with the
/// same result as [`command`].
unsafe fn frame(s: &mut State, chan: Option<usize>, kind: u8, channel: u8, body: &[u8]) -> bool {
    if !flush_tx(s) {
        return false;
    }
    let at = TX_PREFIX;
    wire::header(kind, channel, body.len(), &mut s.tx[at..]);
    s.tx[at + FRAME_HDR..at + FRAME_HDR + body.len()].copy_from_slice(body);
    send_staged(s, chan, FRAME_HDR + body.len());
    true
}

/// Owe the transport a close of `id` — a connection (`net`) or session
/// (`mux`) this instance will not use — and try it.
unsafe fn close_unused(s: &mut State, id: u32) {
    let n = s.n_closes as usize;
    if n < CLOSES_OWED {
        s.closes[n] = id;
        s.n_closes += 1;
    }
    flush_closes(s);
}

/// The transport has ended `id` itself, or issued it afresh: a close still
/// owed for it would end whatever now holds the id.
fn forget_close(s: &mut State, id: u32) {
    let mut k = 0;
    while k < s.n_closes as usize {
        if s.closes[k] == id {
            s.closes.copy_within(k + 1..s.n_closes as usize, k);
            s.n_closes -= 1;
        } else {
            k += 1;
        }
    }
}

/// Write the owed closes, oldest first. They go beside `tx`, not through
/// it: each names a connection or session other than the one `tx` serves,
/// so their order against it does not matter, and a frame staged in `tx`
/// never holds one back.
unsafe fn flush_closes(s: &mut State) {
    let sys = &*s.syscalls;
    while s.n_closes > 0 {
        let id = s.closes[0];
        let mut f = [0u8; 3 + 5];
        let n = if s.transport == TRANSPORT_NET {
            f[0] = net_proto::CMD_CLOSE;
            f[3..5].copy_from_slice(&(id as u16).to_le_bytes());
            5
        } else {
            f[0] = mux::CMD_MUX_SESSION_CLOSE;
            mux::put_session_id(&mut f[3..], id);
            8
        };
        f[1..3].copy_from_slice(&((n - 3) as u16).to_le_bytes());
        if (sys.channel_write)(s.transport_out, f.as_ptr(), n) != n as i32 {
            return;
        }
        s.closes.copy_within(1..s.n_closes as usize, 0);
        s.n_closes -= 1;
    }
}

// ── Session lifecycle ───────────────────────────────────────────────────────

unsafe fn start_attach(s: &mut State) {
    s.phase = PH_ATTACHING;
    s.setup_deadline_ms = later(dev_millis(&*s.syscalls) as u32, SETUP_TIMEOUT_MS);
    s.peer_bound = s.require_peer == 0;
    s.hello_owed = false;
    s.refuse_owed = 0;
    s.opening = 0;
    s.open_pending = false;
    s.net_parser.reset();
    for i in 0..MAX_CHANNELS {
        let c = &mut s.chans[i];
        c.has_stream = false;
        c.hello_rx = false;
        c.hello_owed = false;
        c.credit_owed = 0;
        c.tx_credit = 0;
        let sl = &mut s.slots[i];
        sl.used = false;
        sl.ack_owed = 0;
        sl.parser.reset();
    }
}

/// End the session: tell the transport, drop the record each channel was
/// receiving, abandon the record each was sending, and go back to waiting.
unsafe fn end_session(s: &mut State, why: &[u8]) {
    log(s, 2, why);
    if s.phase >= PH_ATTACHING {
        // A frame still staged belongs to the session that is ending; the
        // close that replaces it is held for the next flush if the
        // transport refuses it now.
        s.tx_len = 0;
        if s.transport == TRANSPORT_NET {
            let c = s.conn.to_le_bytes();
            command(s, net_proto::CMD_CLOSE, &c);
        } else {
            let mut p = [0u8; 5];
            mux::put_session_id(&mut p, s.session);
            command(s, mux::CMD_MUX_SESSION_CLOSE, &p);
        }
        // This session's identity record is spent with it.
        if s.id_seen && s.id_conn == s.conn && s.id_generation == s.generation {
            s.id_seen = false;
        }
    }
    let sys = &*s.syscalls;
    for i in 0..n_channels(s) {
        let c = &mut s.chans[i];
        if c.rx_active {
            // The partial record's bytes leave the ring.
            c.ring_used -= RECORD_CHARGE + c.rx_have;
            c.rx_active = false;
            c.lost = c.lost.wrapping_add(1);
        }
        if c.tx_state == TX_BODY && c.tx_sent > 0 {
            c.lost = c.lost.wrapping_add(1);
            // A mailbox record is already off its input; a delimited one
            // still has bytes there to skip.
            c.tx_state = if c.entry.framing == wire::framing::MAILBOX {
                TX_IDLE
            } else {
                TX_DISCARD
            };
            c.tx_hdr_have = 0;
        }
    }
    s.conn = NO_CONN;
    // A listener goes on listening; a dialler redials, and on `mux` the
    // transport announces the next session.
    s.phase = if s.transport == TRANSPORT_NET && s.role == ROLE_LISTEN {
        PH_LISTENING
    } else {
        PH_IDLE
    };
    s.retry_at_ms = later(dev_millis(sys) as u32, s.redial_ms);
}

/// Refuse the session: say why, then end it.
unsafe fn refuse(s: &mut State, reason: u8, why: &[u8]) {
    let body = [reason];
    if s.transport == TRANSPORT_NET {
        frame(s, None, wire::KIND_REFUSE, wire::CONTROL, &body);
    } else {
        for i in 0..n_channels(s) {
            if s.chans[i].has_stream {
                frame(s, Some(i), wire::KIND_REFUSE, i as u8, &body);
                break;
            }
        }
    }
    end_session(s, why);
}

/// Attaching → hello once the identity is bound, every stream is open and
/// every ring has drained.
unsafe fn try_hello(s: &mut State) {
    if s.phase != PH_ATTACHING || !s.peer_bound {
        return;
    }
    for i in 0..n_channels(s) {
        if s.chans[i].ring_used != 0 {
            return;
        }
    }
    if s.transport == TRANSPORT_MUX {
        if s.local_init {
            if (s.opening as usize) < n_channels(s) {
                return;
            }
        } else {
            // The acceptor answers each stream's table as it arrives.
            s.phase = PH_HELLO;
            return;
        }
        for i in 0..n_channels(s) {
            s.chans[i].hello_owed = true;
        }
    } else {
        s.hello_owed = true;
    }
    s.phase = PH_HELLO;
}

unsafe fn maybe_open(s: &mut State) {
    if s.phase != PH_HELLO {
        return;
    }
    let all = if s.transport == TRANSPORT_NET {
        !s.hello_owed && s.chans[0].hello_rx
    } else {
        (0..n_channels(s)).all(|i| s.chans[i].hello_rx && !s.chans[i].hello_owed)
    };
    if !all {
        return;
    }
    for i in 0..n_channels(s) {
        let c = &mut s.chans[i];
        c.tx_credit = c.entry.max_record + RECORD_CHARGE;
    }
    s.phase = PH_OPEN;
    s.sessions = s.sessions.wrapping_add(1);
    log(s, 3, b"[remote_channel] session open");
}

/// A peer's table arrived for `chan` (`net`: the whole session).
unsafe fn on_hello(s: &mut State, body: &[u8]) -> bool {
    if !wire::hello_matches(&s.table, body) {
        refuse(
            s,
            wire::refuse::TABLE_MISMATCH,
            b"[remote_channel] refused: the peer's channel table differs",
        );
        return false;
    }
    true
}

// ── Receiving ───────────────────────────────────────────────────────────────

/// A ring position from an offset below twice the capacity — every
/// offset taken is a head below `cap` plus at most `cap`.
fn wrap(at: u32, cap: u32) -> u32 {
    if at >= cap {
        at - cap
    } else {
        at
    }
}

fn ring_put(pool: &mut [u8], off: u32, cap: u32, at: u32, bytes: &[u8]) {
    let mut pos = wrap(at, cap);
    for &b in bytes {
        pool[(off + pos) as usize] = b;
        pos += 1;
        if pos == cap {
            pos = 0;
        }
    }
}

fn ring_get(pool: &[u8], off: u32, cap: u32, at: u32, out: &mut [u8]) {
    let mut pos = wrap(at, cap);
    for b in out.iter_mut() {
        *b = pool[(off + pos) as usize];
        pos += 1;
        if pos == cap {
            pos = 0;
        }
    }
}

/// Copy `len` ring bytes from `at` to the flat region at `dst` of the same
/// pool (a `mailbox` channel's delivery stage, which no ring overlaps).
fn ring_flatten(pool: &mut [u8], off: u32, cap: u32, at: u32, dst: u32, len: u32) {
    let mut pos = wrap(at, cap);
    for k in 0..len {
        pool[(dst + k) as usize] = pool[(off + pos) as usize];
        pos += 1;
        if pos == cap {
            pos = 0;
        }
    }
}

/// One parsed protocol event from a carrier. `stream_channel` is the
/// channel a `mux` stream is known to carry. False ends processing of this
/// carrier input (the session ended).
unsafe fn on_event(s: &mut State, ev: Event<'_>, stream_channel: Option<usize>) -> bool {
    let nch = n_channels(s);
    let channel_of = |ch: u8| -> Option<usize> {
        let c = ch as usize;
        if c >= nch {
            return None;
        }
        match stream_channel {
            Some(sc) if sc != c => None,
            _ => Some(c),
        }
    };
    match ev {
        Event::None => true,
        Event::Error => {
            refuse(
                s,
                wire::refuse::PROTOCOL,
                b"[remote_channel] refused: malformed frame",
            );
            false
        }
        Event::Refuse(_) => {
            end_session(s, b"[remote_channel] the peer refused the session");
            false
        }
        Event::Hello(ch, body) => {
            if s.transport == TRANSPORT_NET {
                if ch != wire::CONTROL || s.chans[0].hello_rx || s.phase < PH_ATTACHING {
                    refuse(
                        s,
                        wire::refuse::PROTOCOL,
                        b"[remote_channel] refused: unexpected table",
                    );
                    return false;
                }
                let mut copy = [0u8; wire::HELLO_MAX];
                copy[..body.len()].copy_from_slice(body);
                if !on_hello(s, &copy[..body.len()]) {
                    return false;
                }
                s.chans[0].hello_rx = true;
            } else {
                let Some(c) = channel_of(ch) else {
                    refuse(
                        s,
                        wire::refuse::PROTOCOL,
                        b"[remote_channel] refused: table on a stray stream",
                    );
                    return false;
                };
                if s.chans[c].hello_rx {
                    refuse(
                        s,
                        wire::refuse::PROTOCOL,
                        b"[remote_channel] refused: second table on a stream",
                    );
                    return false;
                }
                let mut copy = [0u8; wire::HELLO_MAX];
                copy[..body.len()].copy_from_slice(body);
                if !on_hello(s, &copy[..body.len()]) {
                    return false;
                }
                s.chans[c].hello_rx = true;
                if !s.local_init {
                    s.chans[c].hello_owed = true;
                }
            }
            maybe_open(s);
            true
        }
        Event::Credit(ch, n) => {
            let Some(c) = channel_of(ch) else {
                refuse(
                    s,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: credit for no channel",
                );
                return false;
            };
            if s.phase != PH_OPEN {
                refuse(
                    s,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: credit before the tables",
                );
                return false;
            }
            let cap = s.chans[c].entry.max_record as u64 + RECORD_CHARGE as u64;
            let next = s.chans[c].tx_credit as u64 + n as u64;
            if next > cap {
                refuse(
                    s,
                    wire::refuse::CREDIT,
                    b"[remote_channel] refused: credit beyond the peer's ring",
                );
                return false;
            }
            s.chans[c].tx_credit = next as u32;
            true
        }
        Event::Begin(ch, len) => {
            let Some(c) = channel_of(ch) else {
                refuse(
                    s,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: record for no channel",
                );
                return false;
            };
            let chan = &mut s.chans[c];
            if s.phase != PH_OPEN || chan.rx_active {
                refuse(
                    s,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: record out of sequence",
                );
                return false;
            }
            if (len as usize) < chan.entry.header_len() {
                refuse(
                    s,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: a record shorter than its own header",
                );
                return false;
            }
            if len == 0 || len > chan.entry.max_record {
                refuse(
                    s,
                    wire::refuse::OVERSIZE,
                    b"[remote_channel] refused: record over the channel maximum",
                );
                return false;
            }
            if chan.ring_used + RECORD_CHARGE > chan.ring_cap {
                refuse(
                    s,
                    wire::refuse::CREDIT,
                    b"[remote_channel] refused: record beyond granted credit",
                );
                return false;
            }
            let (at, off, cap) = (
                chan.ring_head + chan.ring_used,
                chan.ring_off,
                chan.ring_cap,
            );
            ring_put(&mut s.pool, off, cap, at, &len.to_le_bytes());
            let chan = &mut s.chans[c];
            chan.ring_used += RECORD_CHARGE;
            chan.rx_len = len;
            chan.rx_have = 0;
            chan.rx_active = true;
            true
        }
        Event::Data(ch, bytes) => {
            let Some(c) = channel_of(ch) else {
                refuse(
                    s,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: bytes for no channel",
                );
                return false;
            };
            let chan = &s.chans[c];
            if !chan.rx_active || chan.rx_have as u64 + bytes.len() as u64 > chan.rx_len as u64 {
                refuse(
                    s,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: bytes outside a record",
                );
                return false;
            }
            if chan.ring_used as u64 + bytes.len() as u64 > chan.ring_cap as u64 {
                refuse(
                    s,
                    wire::refuse::CREDIT,
                    b"[remote_channel] refused: bytes beyond granted credit",
                );
                return false;
            }
            let (at, off, cap) = (
                chan.ring_head + chan.ring_used,
                chan.ring_off,
                chan.ring_cap,
            );
            ring_put(&mut s.pool, off, cap, at, bytes);
            let chan = &mut s.chans[c];
            let had = chan.rx_have;
            let have = had + bytes.len() as u32;
            // A delimited record must say, in its own header, the length
            // the wire gave it: otherwise the local consumer's idea of where
            // records end differs from this module's, and every record after
            // it is misframed. Checked before the bytes are committed, so a
            // refused record is dropped with the session rather than kept as
            // a complete one.
            let hl = chan.entry.header_len();
            if hl > 0 && (had as usize) < hl && (have as usize) >= hl {
                let (entry, rx_len) = (chan.entry, chan.rx_len);
                let start = chan.ring_head + chan.ring_used - had;
                let mut hdr = [0u8; 4];
                ring_get(&s.pool, off, cap, start, &mut hdr[..hl]);
                if entry.record_len(&hdr[..hl]) != rx_len as u64 {
                    refuse(
                        s,
                        wire::refuse::PROTOCOL,
                        b"[remote_channel] refused: a record whose header disagrees with its length",
                    );
                    return false;
                }
            }
            let chan = &mut s.chans[c];
            chan.ring_used += bytes.len() as u32;
            chan.rx_have = have;
            if have == chan.rx_len {
                chan.rx_active = false;
            }
            true
        }
    }
}

/// Feed carrier bytes through a carrier's parser (`slot` for a `mux`
/// stream, `None` for the `net` stream), dispatching each event.
unsafe fn feed(s: &mut State, slot: Option<usize>, mut input: &[u8]) {
    while !input.is_empty() {
        // The parser is not touched by event handling — a session ending
        // inside it resets parsers only when the next one attaches — so its
        // events may borrow it while the rest of the state changes.
        let parser: *mut Parser = match slot {
            None => &mut s.net_parser,
            Some(i) => &mut s.slots[i].parser,
        };
        let (used, ev) = (*parser).next(input);
        input = &input[used..];
        if matches!(ev, Event::None) {
            // Part of a frame: nothing to act on until the rest arrives,
            // wherever the carrier happened to split the stream.
            if used == 0 {
                break;
            }
            continue;
        }
        let stream_channel = match slot {
            None => None,
            Some(i) => {
                if let Event::Hello(ch, _) = ev {
                    // A stream names its channel with its first table.
                    let c = ch as usize;
                    if s.slots[i].channel == 0xFF && c < n_channels(s) && !s.chans[c].has_stream {
                        s.slots[i].channel = ch;
                        s.chans[c].has_stream = true;
                        s.chans[c].stream = s.slots[i].stream;
                    }
                }
                let ch = s.slots[i].channel;
                if ch == 0xFF {
                    refuse(
                        s,
                        wire::refuse::PROTOCOL,
                        b"[remote_channel] refused: a stream that names no channel",
                    );
                    return;
                }
                Some(ch as usize)
            }
        };
        if !on_event(s, ev, stream_channel) {
            return;
        }
        if used == 0 {
            break;
        }
    }
}

/// Deliver complete records to their local outputs, returning their credit.
unsafe fn deliver(s: &mut State) {
    let sys = &*s.syscalls;
    for i in 0..n_channels(s) {
        loop {
            let c = &s.chans[i];
            let complete_bytes = if c.rx_active {
                c.ring_used - RECORD_CHARGE - c.rx_have
            } else {
                c.ring_used
            };
            if complete_bytes == 0 || c.output < 0 {
                break;
            }
            let mut lb = [0u8; 4];
            let (off, cap, head, output) = (c.ring_off, c.ring_cap, c.ring_head, c.output);
            ring_get(&s.pool, off, cap, head, &mut lb);
            let len = u32::from_le_bytes(lb);
            let base = head + RECORD_CHARGE;
            let framing = c.entry.framing;
            let deliver_off = c.deliver_off;
            let mut refused = false;
            let done = if framing == wire::framing::MAILBOX {
                // One write is one record: lay it out flat and hand it over
                // whole.
                let stage = s.chans[i].rx_stage;
                ring_flatten(&mut s.pool, off, cap, base, stage, len);
                let r =
                    (sys.channel_write)(output, s.pool.as_ptr().add(stage as usize), len as usize);
                if r == len as i32 {
                    true
                } else if r == errno::EAGAIN {
                    false
                } else {
                    log(s, 1, b"[remote_channel] the mailbox cannot take a record this size; record refused");
                    s.chans[i].refused_oversize = s.chans[i].refused_oversize.wrapping_add(1);
                    refused = true;
                    true
                }
            } else {
                // Chunked: the consumer delimits by the record's own header.
                let mut done_bytes = deliver_off;
                let mut chunk = [0u8; 1024];
                let mut stalled = false;
                while done_bytes < len {
                    let want = ((len - done_bytes) as usize).min(chunk.len());
                    ring_get(&s.pool, off, cap, base + done_bytes, &mut chunk[..want]);
                    let mut n = want;
                    let mut wrote = false;
                    while n > 0 {
                        if (sys.channel_write)(output, chunk.as_ptr(), n) == n as i32 {
                            wrote = true;
                            break;
                        }
                        n /= 4;
                    }
                    if !wrote {
                        stalled = true;
                        break;
                    }
                    done_bytes += n as u32;
                }
                s.chans[i].deliver_off = done_bytes;
                !stalled
            };
            if !done {
                break;
            }
            let c = &mut s.chans[i];
            c.deliver_off = 0;
            c.ring_head = wrap(c.ring_head + RECORD_CHARGE + len, c.ring_cap);
            c.ring_used -= RECORD_CHARGE + len;
            if s.phase == PH_OPEN {
                c.credit_owed += RECORD_CHARGE + len;
            }
            if !refused {
                c.records_delivered = c.records_delivered.wrapping_add(1);
            }
        }
    }
}

// ── Transport input ─────────────────────────────────────────────────────────

unsafe fn read_identity(s: &mut State) {
    if s.identity_in < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let mut buf = [0u8; peer_identity::MAX_TOTAL];
    loop {
        let (t, n) = net_read_frame(sys, s.identity_in, buf.as_mut_ptr(), buf.len());
        if t == 0 {
            break;
        }
        if t != peer_identity::MSG_PEER_IDENTITY || n < peer_identity::PAYLOAD_FIXED {
            continue;
        }
        let p = &buf[3..3 + n];
        s.id_conn = peer_identity::conn_id(p);
        s.id_generation = peer_identity::generation(p);
        s.id_bound = peer_identity::binds_identity(p);
        s.id_seen = true;
    }
}

/// Settle a net session's identity from the latest record. A record binds
/// only the session its connection id and generation both name: a
/// connection id outlives its sessions, and a record that arrives after its
/// session closed must not authenticate the next one on that id. A
/// transport that numbers no sessions gives nothing to tie a record to, so
/// its sessions cannot be authenticated.
unsafe fn check_net_identity(s: &mut State) {
    if s.phase != PH_ATTACHING || s.peer_bound {
        return;
    }
    if s.generation == 0 {
        end_session(
            s,
            b"[remote_channel] refused: the transport numbers no sessions, so no peer identity can be tied to this one",
        );
        return;
    }
    if !s.id_seen || s.id_conn != s.conn || s.id_generation != s.generation {
        return;
    }
    if s.id_bound {
        s.peer_bound = true;
    } else {
        end_session(
            s,
            b"[remote_channel] refused: the transport did not authenticate the peer",
        );
    }
}

/// Give up on a session that is not becoming a channel session. Once the
/// peer is bound, waiting on the local consumers to drain old records is
/// local, not the peer's doing, and restarts the clock; an unbound peer is
/// given no such grace.
unsafe fn check_setup_deadline(s: &mut State, now: u32) {
    if s.phase != PH_ATTACHING && s.phase != PH_HELLO {
        return;
    }
    if s.phase == PH_ATTACHING
        && s.peer_bound
        && (0..n_channels(s)).any(|i| s.chans[i].ring_used != 0)
    {
        s.setup_deadline_ms = later(now, SETUP_TIMEOUT_MS);
        return;
    }
    if now.wrapping_sub(s.setup_deadline_ms) < 0x8000_0000 {
        end_session(
            s,
            b"[remote_channel] the session did not complete its setup in time",
        );
    }
}

unsafe fn net_input(s: &mut State) {
    let sys = &*s.syscalls;
    for _ in 0..EVENTS_PER_STEP {
        // An event owes at most one close: read one only with room for it.
        flush_closes(s);
        if s.n_closes as usize == CLOSES_OWED {
            break;
        }
        let (msg, plen, full) =
            net_read_frame_aligned(sys, s.transport_in, s.rx.as_mut_ptr(), RX_SCRATCH);
        if msg == 0 {
            break;
        }
        if plen != full {
            end_session(
                s,
                b"[remote_channel] transport frame larger than the contract allows",
            );
            continue;
        }
        let p = &s.rx[3..3 + plen];
        let id = if plen >= 2 {
            net_proto::conn_id(p)
        } else {
            NO_CONN
        };
        match msg {
            net_proto::MSG_BOUND if s.phase == PH_WAIT_BOUND => {
                s.phase = PH_LISTENING;
            }
            net_proto::MSG_ACCEPTED if plen >= 2 => {
                let port = if plen >= 4 {
                    u16::from_le_bytes([p[2], p[3]])
                } else {
                    s.port
                };
                if s.role != ROLE_LISTEN || port != s.port {
                    // Another consumer's listener.
                } else if s.phase == PH_LISTENING {
                    s.conn = id;
                    s.generation = net_proto::session_generation(p, net_proto::ACCEPTED_FIXED);
                    forget_close(s, id as u32);
                    start_attach(s);
                } else {
                    // One session at a time.
                    close_unused(s, id as u32);
                }
            }
            net_proto::MSG_CONNECTED if plen >= 3 && p[2] == s.my_tag => {
                if s.phase == PH_DIALING {
                    s.conn = id;
                    s.generation = net_proto::session_generation(p, net_proto::CONNECTED_FIXED);
                    forget_close(s, id as u32);
                    start_attach(s);
                } else if !(id == s.conn && s.phase >= PH_ATTACHING) {
                    // An answer to a dial this instance has given up on, or
                    // a second answer: nothing will use the connection.
                    close_unused(s, id as u32);
                }
            }
            net_proto::MSG_DATA if plen > 2 && id == s.conn && s.phase >= PH_ATTACHING => {
                let mut data = [0u8; RX_SCRATCH];
                data[..plen - 2].copy_from_slice(&p[2..]);
                feed(s, None, &data[..plen - 2]);
            }
            net_proto::MSG_CLOSED if plen >= 2 => {
                forget_close(s, id as u32);
                if id == s.conn && s.phase >= PH_ATTACHING {
                    end_session(s, b"[remote_channel] session closed");
                }
            }
            net_proto::MSG_ERROR => {
                if s.phase == PH_DIALING && plen >= 4 && p[3] == s.my_tag {
                    s.phase = PH_IDLE;
                    s.retry_at_ms = later(dev_millis(sys) as u32, s.redial_ms);
                } else if id == s.conn && s.phase >= PH_ATTACHING {
                    end_session(s, b"[remote_channel] session failed");
                }
            }
            _ => {}
        }
    }
}

unsafe fn mux_input(s: &mut State) {
    let sys = &*s.syscalls;
    for _ in 0..EVENTS_PER_STEP {
        // An event owes at most one close: read one only with room for it.
        flush_closes(s);
        if s.n_closes as usize == CLOSES_OWED {
            break;
        }
        let (msg, plen, full) =
            net_read_frame_aligned(sys, s.transport_in, s.rx.as_mut_ptr(), RX_SCRATCH);
        if msg == 0 {
            break;
        }
        if plen != full {
            end_session(
                s,
                b"[remote_channel] mux event larger than the contract allows",
            );
            continue;
        }
        let mut p = [0u8; RX_SCRATCH];
        p[..plen].copy_from_slice(&s.rx[3..3 + plen]);
        let p = &p[..plen];
        if plen < mux::SESSION_ID_BYTES {
            continue;
        }
        let session = mux::session_id(p);
        match msg {
            mux::MSG_MUX_SESSION_OPENED if plen >= 4 + mux::SESSION_OPENED_BODY_MIN => {
                if s.phase >= PH_ATTACHING || p[4] != mux::STATUS_OK {
                    if p[4] == mux::STATUS_OK {
                        // One session at a time.
                        close_unused(s, session);
                    }
                    continue;
                }
                forget_close(s, session);
                s.session = session;
                s.local_init = p[5] & mux::SESSION_FLAG_LOCAL_INIT != 0;
                start_attach(s);
                for i in 0..MAX_CHANNELS {
                    s.slots[i].channel = 0xFF;
                }
            }
            mux::MSG_MUX_SESSION_CLOSED | mux::MSG_MUX_SESSION_ERROR if session != s.session => {
                forget_close(s, session);
            }
            _ if s.phase < PH_ATTACHING || session != s.session => {}
            mux::MSG_MUX_PEER_IDENTITY => {
                if s.peer_bound {
                    continue;
                }
                if peer_identity::binds_identity(p) {
                    s.peer_bound = true;
                } else {
                    end_session(
                        s,
                        b"[remote_channel] refused: the transport did not authenticate the peer",
                    );
                }
            }
            mux::MSG_MUX_STREAM_OPENED
                if plen >= mux::STREAM_DATA_PREFIX + mux::STREAM_OPENED_BODY =>
            {
                let stream = mux::stream_id(p);
                if !s.open_pending || !s.local_init {
                    continue;
                }
                s.open_pending = false;
                if p[8] != mux::STATUS_OK {
                    end_session(s, b"[remote_channel] the transport has fewer streams than the table has channels");
                    continue;
                }
                let k = s.opening as usize;
                s.slots[k].used = true;
                s.slots[k].stream = stream;
                s.slots[k].channel = k as u8;
                s.chans[k].stream = stream;
                s.chans[k].has_stream = true;
                s.opening += 1;
            }
            mux::MSG_MUX_STREAM_ACCEPTED if plen >= mux::STREAM_DATA_PREFIX => {
                let stream = mux::stream_id(p);
                if s.local_init {
                    refuse(
                        s,
                        wire::refuse::PROTOCOL,
                        b"[remote_channel] refused: the accepting side opened a stream",
                    );
                    continue;
                }
                match (0..n_channels(s)).find(|&i| !s.slots[i].used) {
                    Some(i) => {
                        s.slots[i].used = true;
                        s.slots[i].stream = stream;
                        s.slots[i].channel = 0xFF;
                        s.slots[i].parser.reset();
                    }
                    None => {
                        refuse(
                            s,
                            wire::refuse::PROTOCOL,
                            b"[remote_channel] refused: more streams than channels",
                        );
                    }
                }
            }
            mux::MSG_MUX_STREAM_RX if plen > mux::STREAM_DATA_PREFIX => {
                let stream = mux::stream_id(p);
                let Some(i) =
                    (0..MAX_CHANNELS).find(|&i| s.slots[i].used && s.slots[i].stream == stream)
                else {
                    continue;
                };
                let data = &p[mux::STREAM_DATA_PREFIX..];
                // Every byte taken is acknowledged at once: what bounds the
                // peer is the credit this protocol grants, never the
                // transport's window.
                s.slots[i].ack_owed += data.len() as u32;
                let mut copy = [0u8; RX_SCRATCH];
                copy[..data.len()].copy_from_slice(data);
                feed(s, Some(i), &copy[..data.len()]);
            }
            mux::MSG_MUX_STREAM_CLOSED | mux::MSG_MUX_STREAM_RESET | mux::MSG_MUX_STREAM_ERROR => {
                end_session(s, b"[remote_channel] a channel stream ended");
            }
            mux::MSG_MUX_SESSION_CLOSED | mux::MSG_MUX_SESSION_ERROR => {
                // The transport's session is gone: nothing to close, and
                // nothing staged for it can be sent.
                s.tx_len = 0;
                s.phase = PH_IDLE;
                end_session(s, b"[remote_channel] session closed");
            }
            _ => {}
        }
    }
}

// ── Sending ─────────────────────────────────────────────────────────────────

/// Control owed before any record byte: transport acks, tables, credit.
unsafe fn send_control(s: &mut State) -> bool {
    let nch = n_channels(s);
    if s.transport == TRANSPORT_MUX {
        for i in 0..MAX_CHANNELS {
            if s.slots[i].used && s.slots[i].ack_owed > 0 {
                let mut p = [0u8; mux::STREAM_DATA_PREFIX + 4];
                mux::put_session_id(&mut p, s.session);
                mux::put_stream_id(&mut p, s.slots[i].stream);
                p[8..12].copy_from_slice(&s.slots[i].ack_owed.to_le_bytes());
                if !command(s, mux::CMD_MUX_STREAM_ACK, &p) {
                    return false;
                }
                s.slots[i].ack_owed = 0;
            }
        }
        if s.phase == PH_ATTACHING
            && s.local_init
            && s.peer_bound
            && !s.open_pending
            && (s.opening as usize) < nch
        {
            let mut p = [0u8; 5];
            mux::put_session_id(&mut p, s.session);
            p[4] = mux::STREAM_FLAG_BIDI;
            if !command(s, mux::CMD_MUX_STREAM_OPEN, &p) {
                return false;
            }
            s.open_pending = true;
        }
    }
    let mut hello = [0u8; wire::HELLO_MAX];
    let hn = wire::encode_hello(&s.table, &mut hello);
    if s.hello_owed {
        if !frame(s, None, wire::KIND_HELLO, wire::CONTROL, &hello[..hn]) {
            return false;
        }
        s.hello_owed = false;
        maybe_open(s);
    }
    for i in 0..nch {
        if s.chans[i].hello_owed && s.chans[i].has_stream && s.phase >= PH_HELLO {
            if !frame(s, Some(i), wire::KIND_HELLO, i as u8, &hello[..hn]) {
                return false;
            }
            s.chans[i].hello_owed = false;
            maybe_open(s);
        }
    }
    if s.phase == PH_OPEN {
        for i in 0..nch {
            let owed = s.chans[i].credit_owed;
            if owed > 0 {
                if !frame(s, Some(i), wire::KIND_CREDIT, i as u8, &owed.to_le_bytes()) {
                    return false;
                }
                s.chans[i].credit_owed = 0;
            }
        }
    }
    true
}

/// Advance channel `i`'s send: start a record, or put out its next
/// fragment. True when a frame was written.
unsafe fn send_channel(s: &mut State, i: usize) -> bool {
    let sys = &*s.syscalls;
    let c = &mut s.chans[i];
    if c.input < 0 {
        return false;
    }
    let frag_max = if s.transport == TRANSPORT_NET {
        FRAGMENT_MAX
    } else {
        MUX_FRAGMENT_MAX
    };
    // Finish discarding an abandoned or refused record.
    if c.tx_state == TX_DISCARD {
        let mut sink = [0u8; 512];
        while c.tx_sent < c.tx_len {
            let want = ((c.tx_len - c.tx_sent) as usize).min(sink.len());
            let n = (sys.channel_read)(c.input, sink.as_mut_ptr(), want);
            if n <= 0 {
                return false;
            }
            c.tx_sent += n as u64;
        }
        c.tx_state = TX_IDLE;
        c.tx_hdr_have = 0;
    }
    if c.tx_state == TX_IDLE {
        if c.entry.framing == wire::framing::BYTES {
            // A stream has no records: whatever is there, up to one
            // frame and the credit left, goes as one piece.
            if c.tx_credit <= RECORD_CHARGE {
                return false;
            }
            let room = ((c.tx_credit - RECORD_CHARGE) as usize)
                .min(c.entry.max_record as usize)
                .min(frag_max);
            let body_at = TX_PREFIX + FRAME_HDR + BEGIN_PREFIX;
            let input = c.input;
            let n = (sys.channel_read)(input, s.tx.as_mut_ptr().add(body_at), room);
            if n <= 0 {
                return false;
            }
            let n = n as usize;
            s.tx[TX_PREFIX + FRAME_HDR..TX_PREFIX + FRAME_HDR + 4]
                .copy_from_slice(&(n as u32).to_le_bytes());
            wire::header(
                wire::KIND_BEGIN,
                i as u8,
                BEGIN_PREFIX + n,
                &mut s.tx[TX_PREFIX..],
            );
            let c = &mut s.chans[i];
            c.tx_credit -= RECORD_CHARGE + n as u32;
            c.records_sent = c.records_sent.wrapping_add(1);
            send_staged(s, Some(i), FRAME_HDR + BEGIN_PREFIX + n);
            return true;
        }
        if c.entry.framing == wire::framing::MAILBOX {
            // A mailbox read takes one whole record or, when it is larger
            // than the buffer offered, nothing at all.
            let (stage, max, input) = (c.tx_stage as usize, c.entry.max_record as usize, c.input);
            let n = (sys.channel_read)(input, s.pool.as_mut_ptr().add(stage), max);
            if n == errno::EINVAL {
                // Over the maximum: refuse it by flushing it off the edge.
                dev_channel_ioctl(sys, input, IOCTL_FLUSH, core::ptr::null_mut(), 0);
                s.chans[i].refused_oversize = s.chans[i].refused_oversize.wrapping_add(1);
                log(
                    s,
                    1,
                    b"[remote_channel] record over the channel maximum refused",
                );
                return false;
            }
            if n <= 0 {
                return false;
            }
            let c = &mut s.chans[i];
            c.tx_len = n as u64;
            c.tx_sent = 0;
            c.tx_state = TX_BODY;
        } else {
            let hl = c.entry.header_len();
            while (c.tx_hdr_have as usize) < hl {
                let n = (sys.channel_read)(
                    c.input,
                    c.tx_hdr.as_mut_ptr().add(c.tx_hdr_have as usize),
                    hl - c.tx_hdr_have as usize,
                );
                if n <= 0 {
                    return false;
                }
                c.tx_hdr_have += n as u8;
            }
            let len = c.entry.record_len(&c.tx_hdr[..hl]);
            if len > c.entry.max_record as u64 {
                c.tx_state = TX_DISCARD;
                c.tx_len = len;
                c.tx_sent = hl as u64;
                c.refused_oversize = c.refused_oversize.wrapping_add(1);
                log(
                    s,
                    1,
                    b"[remote_channel] record over the channel maximum refused",
                );
                return false;
            }
            c.tx_len = len;
            c.tx_sent = 0;
            c.tx_state = TX_BODY;
        }
    }
    let c = &mut s.chans[i];
    // TX_BODY.
    let begin = c.tx_sent == 0;
    let charge = if begin { RECORD_CHARGE } else { 0 };
    if c.tx_credit <= charge {
        return false;
    }
    let room = (c.tx_credit - charge) as u64;
    let want = (c.tx_len - c.tx_sent).min(room).min(frag_max as u64) as usize;
    let body_at = TX_PREFIX + FRAME_HDR + if begin { BEGIN_PREFIX } else { 0 };
    let mut got = 0usize;
    if c.entry.framing == wire::framing::MAILBOX {
        let src = c.tx_stage as usize + c.tx_sent as usize;
        s.tx[body_at..body_at + want].copy_from_slice(&s.pool[src..src + want]);
        got = want;
    } else {
        let hl = c.entry.header_len() as u64;
        while got < want && c.tx_sent + (got as u64) < hl {
            s.tx[body_at + got] = c.tx_hdr[(c.tx_sent as usize) + got];
            got += 1;
        }
        if got < want {
            let n = (sys.channel_read)(c.input, s.tx.as_mut_ptr().add(body_at + got), want - got);
            if n > 0 {
                got += n as usize;
            }
        }
    }
    if got == 0 && !begin {
        return false;
    }
    let (kind, prefix) = if begin {
        (wire::KIND_BEGIN, BEGIN_PREFIX)
    } else {
        (wire::KIND_MORE, 0)
    };
    if begin {
        let rl = (c.tx_len as u32).to_le_bytes();
        s.tx[TX_PREFIX + FRAME_HDR..TX_PREFIX + FRAME_HDR + 4].copy_from_slice(&rl);
    }
    wire::header(kind, i as u8, prefix + got, &mut s.tx[TX_PREFIX..]);
    let c = &mut s.chans[i];
    c.tx_credit -= charge + got as u32;
    c.tx_sent += got as u64;
    let finished = c.tx_sent == c.tx_len;
    if finished {
        c.tx_state = TX_IDLE;
        c.tx_hdr_have = 0;
        c.records_sent = c.records_sent.wrapping_add(1);
    }
    // The bytes are off the local input now; a refused write stays staged
    // and goes first next step.
    send_staged(s, Some(i), FRAME_HDR + prefix + got);
    true
}

unsafe fn send_records(s: &mut State) {
    if s.phase != PH_OPEN {
        return;
    }
    let nch = n_channels(s);
    let mut frames = 0;
    let mut idle_rounds = 0;
    while frames < FRAMES_PER_STEP && idle_rounds < nch {
        if s.tx_len != 0 && !flush_tx(s) {
            return;
        }
        let i = if (s.rr as usize) < nch {
            s.rr as usize
        } else {
            0
        };
        s.rr = if i + 1 < nch { (i + 1) as u8 } else { 0 };
        if send_channel(s, i) {
            frames += 1;
            idle_rounds = 0;
        } else {
            idle_rounds += 1;
        }
    }
}

// ── Entry points ────────────────────────────────────────────────────────────

declare_module_state_bytes!(State);

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// The module consumes whole buffers on `mailbox` channels.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_mailbox_safe"]
pub extern "C" fn module_mailbox_safe() -> i32 {
    1
}

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
    if state_size < core::mem::size_of::<State>() {
        return -6;
    }
    // Zero the whole state: every field below starts from zero unless set.
    core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
    let s = &mut *(state as *mut State);
    s.syscalls = syscalls as *const SyscallTable;
    let sys = &*s.syscalls;
    s.transport_in = in_chan;
    s.transport_out = out_chan;
    s.identity_in = dev_channel_port(sys, 0, PORT_PEER_IDENTITY);
    s.session_out = dev_channel_port(sys, 1, PORT_SESSION);
    s.port = DEFAULT_PORT;
    s.peer_port = DEFAULT_PORT;
    s.require_peer = 1;
    s.redial_ms = 1000;
    s.conn = NO_CONN;
    s.my_tag = dev_requester_tag(sys);
    s.net_parser = Parser::new();
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    if s.table_text_overflow {
        log(s, 1, b"[remote_channel] refusing to construct: `channels` is longer than its parameter allows");
        return -22;
    }
    let text = s.table_text;
    s.table = match wire::parse_table(&text[..s.table_text_len as usize], MAX_RECORD) {
        Ok(t) => t,
        Err(e) => {
            log(s, 1, TABLE_ERRORS.get(e as usize));
            return -22;
        }
    };
    if !carve_pool(s) {
        log(s, 1, b"[remote_channel] refusing to construct: the channels' records exceed REASSEMBLY_BYTES");
        return -22;
    }
    for i in 0..n_channels(s) {
        s.chans[i].entry = s.table.entries[i];
        s.chans[i].input = dev_channel_port(sys, 0, PORT_CH_IN + i as u8);
        s.chans[i].output = dev_channel_port(sys, 1, PORT_CH_OUT + i as u8);
        s.slots[i].parser = Parser::new();
        s.slots[i].channel = 0xFF;
    }
    if s.transport == TRANSPORT_NET && s.role == ROLE_DIAL && !adopt_authority(s) {
        log(
            s,
            1,
            b"[remote_channel] refusing to construct: dial needs authority (host[:port])",
        );
        return -22;
    }
    s.phase = PH_IDLE;
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut State);
    let sys = &*s.syscalls;
    let now = dev_millis(sys) as u32;
    if !flush_tx(s) {
        // The transport takes nothing this step; inbound still drains so
        // our own acks and credit keep flowing on the next.
    }
    read_identity(s);
    if s.transport == TRANSPORT_NET {
        net_input(s);
        check_net_identity(s);
        let due = now.wrapping_sub(s.retry_at_ms) < 0x8000_0000;
        if s.phase == PH_IDLE && due && s.tx_len == 0 {
            if s.role == ROLE_LISTEN {
                let p = s.port.to_le_bytes();
                if command(s, net_proto::CMD_BIND, &p) {
                    s.phase = PH_WAIT_BOUND;
                }
            } else {
                let mut p = [0u8; net_proto::CONNECT_TO_MAX];
                let n = net_proto::write_connect_to(
                    &mut p,
                    SOCK_TYPE_STREAM,
                    s.peer_port,
                    &dial_target(s),
                    Some(s.my_tag),
                );
                if command(s, net_proto::CMD_CONNECT_TO, &p[..n]) {
                    s.phase = PH_DIALING;
                    s.retry_at_ms = later(now, s.redial_ms.saturating_mul(5));
                }
            }
        } else if s.phase == PH_DIALING && due {
            s.phase = PH_IDLE;
        }
    } else {
        mux_input(s);
    }
    deliver(s);
    try_hello(s);
    check_setup_deadline(s, now);
    if flush_tx(s) && send_control(s) {
        send_records(s);
    }
    report_session(s);
    0
}

/// Tell the `session` output whether a session is open, when that differs
/// from what it last carried. A frame the output cannot take now is
/// written on a later step, as whatever the state is by then: a consumer
/// needs the session it may send on, not a history of them.
unsafe fn report_session(s: &mut State) {
    if s.session_out < 0 {
        return;
    }
    let open = s.phase == PH_OPEN;
    let session = s.sessions;
    if open == s.reported_open && (!open || session == s.reported_session) {
        return;
    }
    // A session that opened and ended between two reports still ended:
    // the frame for a closed state names the last session that opened.
    let frame = remote_session::encode(open, session);
    let sys = &*s.syscalls;
    if (sys.channel_write)(s.session_out, frame.as_ptr(), frame.len()) == frame.len() as i32 {
        s.reported_open = open;
        s.reported_session = session;
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub extern "C" fn module_arena_size() -> u32 {
    0
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/runtime/wasm_entry.rs");
