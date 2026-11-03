//! Remote-channel multiplexer: local channels carried record for record
//! across authenticated transport sessions.
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
//! - Every channel has its own credit, per session: the receiver grants
//!   room in that channel's reassembly ring and the sender never exceeds
//!   it, so a large or stalled record holds up its own channel and no
//!   other, and nothing is dropped under backpressure.
//! - The transport authenticates. `transport: net` speaks `net_proto` to
//!   the clear side of `tls` (or to a network provider directly, with
//!   `require_peer: 0`); `transport: mux` speaks the mux contract to `quic`,
//!   one stream per channel, so one channel's loss recovery never blocks
//!   another's. With `require_peer` set, a session whose transport did not
//!   bind a peer identity is closed before a byte of it is used.
//! - Authentication is decided once, when a session attaches, from a
//!   record that names that session — on `net`, by its connection id and
//!   the generation the transport numbered it with. The transport reports
//!   a handshake when it completes, before the session it opened arrives
//!   here, so a record is kept per connection until its session is
//!   decided (`Identities`). The module does not
//!   read a peer's validity window or re-authenticate a live session; a
//!   transport that must end a session when a credential expires closes
//!   it, and the module treats that like any other close. It holds no
//!   credentials of its own.
//! - A delimited record (a length framing: `tlv16`, `len32`,
//!   `len16@<off>+<add>`, `len32@<off>+<add>`) must carry, in its own
//!   header, the length the wire gave it; a peer whose record does not is
//!   refused, so the local consumer's framing and this module's never
//!   differ.
//! - A session that does not finish its setup (identity bound, tables
//!   exchanged) within `SETUP_TIMEOUT_MS` is closed, so a silent peer cannot
//!   hold a session this instance serves.
//!
//! Local channels are read and written with `channel_read` and
//! `channel_write` only. On a `mailbox` edge one buffer is one record; an
//! empty buffer is not a record and is skipped. On a FIFO edge records are
//! delimited by their length framing, however the producer's writes split
//! or join them.
//!
//! ## Sessions
//!
//! A dialler holds one session. A listener on `net` serves up to
//! `sessions` at once, one per peer: a session belongs to the peer its
//! transport authenticated, named by the key fingerprint the transport
//! reported for it (`peer_identity::fingerprint`, the bytes an HTTP server
//! stamps as a request's `peer`). A new session from a peer that already
//! has one replaces it — the old one is closed, and the new one takes its
//! place, its resume state included — so a half-dead connection never holds
//! a peer out. Each peer's session has its own reassembly rings, credit,
//! and (with `resume`) retained windows.
//!
//! With `peer_tag: 0` the sessions are interchangeable to the local side:
//! records arriving on any of them are merged onto the channel's output,
//! record by record, and every record written to a channel's input goes to
//! every open session (with `resume`, to every peer whose streams are held,
//! and a record is taken only once each of them has room). With
//! `peer_tag: 1` every local record carries, ahead of its own bytes, the
//! 32-byte fingerprint of the peer it came from or goes to: an inbound
//! record is stamped with its session's, and an outbound record goes to the
//! session its prefix names — all zero for every session, a peer with no
//! session dropped and counted (`unrouted`).
//!
//! A record whose sending had begun when its session ended is lost and
//! counted; with one session, a record not yet begun waits for the next
//! one, and every record delivered was delivered whole. With `resume`
//! nothing is lost with a session: every record is numbered and kept until
//! the peer acknowledges it, and the next session resumes exactly where the
//! last left off — each record delivered once, in order, across any number
//! of reconnects — while a record the peer already has is refused as a
//! replay (`wire.rs`, Resume). The optional `session` output says when a
//! session opens and ends (`contracts/mesh/remote_session.rs`), so a
//! consumer can stop sending toward a member that cannot hear it rather
//! than wait out a deadline.
//!
//! ## Exchange endpoint
//!
//! With `exchange` set, the instance also carries one exchange
//! (`contracts/exchange.rs`) across its sessions, so a requester reaches a
//! provider on another node with the records it would use on a local edge.
//! The `near` side stands in for the provider (`request_in`,
//! `response_out`); the `far` side stands in for the requester
//! (`request_out`, `response_in`) and is wired to the real provider. The
//! endpoint is two channels appended to the table — requests near to far,
//! answers far to near.
//!
//! What a plain channel does not have is the exchange's account of a lost
//! session, and the endpoint supplies it:
//!
//! - The far side hands the provider every exchange under an id of its own,
//!   mapped from the session's id and back on every answer, so any number
//!   of requesters on any number of sessions share one provider, and a
//!   record of an exchange the far side has ended can never reach a newer
//!   one. It writes each request HEAD's `peer` as the session's verified
//!   fingerprint, whatever the requester put there. When a session ends it
//!   ABORTs each of that session's exchanges still open and drops what the
//!   provider writes for them; the next session's answer channel opens with
//!   a LINK record stating the provider's link.
//! - The near side holds its requester's first requests until that LINK
//!   record arrives. After a session it carried ends, it delivers the
//!   answers that arrived whole, writes LINK DOWN, and discards what the
//!   requester writes until the DOWN is taken and the requester's input is
//!   drained; it writes LINK UP when the next session's LINK record says
//!   the provider is up. The requester issues its open exchanges again.
//! - The provider's own LINK records cross like any answer, to every
//!   session; the near side writes the requester the state the session and
//!   the provider make together, and only when it changes.

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
use abi::config::tls::MAX_SESSIONS as TLS_SESSIONS;
use abi::contracts::exchange as xc;
use abi::contracts::mesh::remote_session;
use abi::contracts::net::{mux, net_proto, peer_identity};
use abi::{errno, SyscallTable};

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

pub mod wire;
use wire::{
    Entry, Event, Parser, Table, BEGIN_PREFIX, FRAME_HDR, HDR_MAX, INCARNATION_LEN, MAX_CHANNELS,
    RBEGIN_PREFIX,
};

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

/// Reassembly bytes across every channel and session: the sum over
/// channels of their stages and, per session, of `max_record +
/// RECORD_CHARGE` (and a retained window under `resume`) must fit, or the
/// instance refuses to construct.
#[cfg(target_arch = "aarch64")]
pub const REASSEMBLY_BYTES: usize = 1024 * 1024;
#[cfg(target_arch = "wasm32")]
pub const REASSEMBLY_BYTES: usize = 256 * 1024;
#[cfg(not(any(target_arch = "aarch64", target_arch = "wasm32")))]
pub const REASSEMBLY_BYTES: usize = 32 * 1024;

/// Sessions one listener serves at once (`sessions`), one per peer. Each is
/// a send and receive state per channel, a reassembly ring per channel in
/// `REASSEMBLY_BYTES`, and a transport session.
pub const SESSIONS_MAX: usize = if abi::config::TARGET_CLASS == abi::config::target_class::HOST {
    8
} else {
    4
};
/// Transport sessions held at once: one per peer, and one more being set
/// up, so a peer whose session must be replaced is not shut out by its own
/// stale one.
const LINKS_MAX: usize = SESSIONS_MAX + 1;
const _: () = assert!(SESSIONS_MAX <= 8, "a peer set is a u8 bit mask");

/// The fingerprint prefix a `peer_tag` channel's local records carry: one
/// SHA-256, as the peer-identity contract carries it.
pub const PEER_TAG_LEN: usize = peer_identity::MAX_FINGERPRINT;

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
/// The exchange endpoint's ports, after the channels and `session`: the
/// near side's provider-shaped pair, the far side's requester-shaped pair.
const PORT_REQUEST_IN: u8 = 10;
const PORT_RESPONSE_IN: u8 = 11;
const PORT_RESPONSE_OUT: u8 = 10;
const PORT_REQUEST_OUT: u8 = 11;

/// Exchanges the far side holds open between the request HEAD it hands the
/// provider and the provider's terminal record — the ones it must ABORT
/// when their session ends. A HEAD past it is answered `503`, marked
/// RAISED, and never reaches the provider.
pub const OPEN_EXCHANGES_MAX: usize =
    if abi::config::TARGET_CLASS == abi::config::target_class::HOST {
        256
    } else {
        32
    };
/// The longest record the module writes of its own on an exchange edge: a
/// refusal HEAD with no content type, headers or body.
const OWN_RECORD_LEN: usize = xc::HDR + xc::RESP_HEAD_FIXED;

const MAX_AUTHORITY_LEN: usize = 128;
const TABLE_TEXT_MAX: usize = 512;
const DEFAULT_PORT: u16 = 9100;
const NO_CONN: u16 = 0xFFFF;
const NO_PEER: u8 = 0xFF;
const NO_LINK: u8 = 0xFF;

/// Transport events taken per step.
const EVENTS_PER_STEP: usize = 32;
/// Frames written per step.
const FRAMES_PER_STEP: usize = 32;
/// How long a transport session may take to become a channel session —
/// peer identity bound, tables exchanged — before it is closed. A peer that
/// connects and says nothing must not hold a session this instance serves.
/// Once the peer is bound, time spent waiting for the local consumers to
/// drain a previous session's records does not count.
const SETUP_TIMEOUT_MS: u32 = 10_000;
/// Closes owed for connections (`net`) or sessions (`mux`) this instance
/// will not use, or has ended, and the transport has not yet taken: one per
/// transport session it holds, and a few for arrivals it turns away.
/// Transport input pauses while the queue is full, so none is dropped.
const CLOSES_OWED: usize = LINKS_MAX + 4;
/// Peer-identity records held, one per connection: as many as the
/// transport can seat sessions. See `Identities`.
const IDENTITIES: usize = TLS_SESSIONS;

const RX_SCRATCH: usize = 3 + mux::MUX_QUIC_STREAM_RX_FRAME_MAX + 64;
const TX_PREFIX: usize = 3 + mux::STREAM_DATA_PREFIX;
const TX_BUF: usize = TX_PREFIX + FRAME_HDR + RBEGIN_PREFIX + FRAGMENT_MAX;
/// `resume`: a channel's retained window when `window` names none, in
/// records at the channel's maximum.
const WINDOW_RECORDS: u32 = 4;
/// `resume`: records one step takes from a channel's input into its window.
const INGEST_PER_STEP: usize = 32;

// The instance's own phase: what its listener or dialler is doing.
const PH_IDLE: u8 = 0;
const PH_WAIT_BOUND: u8 = 1;
const PH_LISTENING: u8 = 2;
const PH_DIALING: u8 = 3;
/// A dialler whose dial has become a transport session.
const PH_LINKED: u8 = 7;

// A transport session's phase.
const L_FREE: u8 = 0;
/// Transport session up; waiting for its peer identity, for streams, and
/// for every reassembly ring of its peer to drain before the table goes out.
const PH_ATTACHING: u8 = 4;
/// Table sent; waiting for the peer's.
const PH_HELLO: u8 = 5;
const PH_OPEN: u8 = 6;

// Which way an exchange channel carries records, from this side.
const DIR_BOTH: u8 = 0;
const DIR_SEND: u8 = 1;
const DIR_RECV: u8 = 2;

// The near side's account of the requester.
/// No session has opened its answer channel yet: requests wait in
/// `request_in`.
const NS_HOLD: u8 = 0;
/// Requests cross; answers are delivered.
const NS_FORWARD: u8 = 1;
/// The session requests were crossing on ended: answers that arrived whole
/// are delivered, then LINK DOWN, and the requester's records are discarded
/// until it has taken the DOWN.
const NS_PURGE: u8 = 2;
/// The requester knows; its records are discarded until the next session
/// says the provider is reachable.
const NS_WAIT: u8 = 3;

// What an exchange endpoint makes of a record before it is delivered.
const X_DELIVER: u8 = 0;
/// Taken off the ring without delivery.
const X_CONSUME: u8 = 1;
/// Left on the ring; the channel waits.
const X_STALL: u8 = 2;

// Send states per channel: the record being taken off its input.
const TX_IDLE: u8 = 0;
/// Held (staged, or streaming on its one session) and being sent.
const TX_BODY: u8 = 1;
/// Being skipped on the input: refused, routed nowhere, or abandoned.
const TX_DISCARD: u8 = 2;
/// Being read into its stage before it is sent.
const TX_FILL: u8 = 3;

/// One local channel: its ports, the record being taken off its input, and
/// the delivery of reassembled records to its output.
#[repr(C)]
struct Chan {
    entry: Entry,
    input: i32,
    output: i32,
    /// `DIR_SEND` / `DIR_RECV` for an exchange channel, which only ever
    /// carries records one way; `DIR_BOTH` otherwise.
    xdir: u8,
    /// Records are held whole in `tx_stage` while they are sent (a mailbox,
    /// or a channel several sessions take each record from); otherwise a
    /// record streams from the input to the one session.
    staged: bool,
    tx_state: u8,
    /// `peer_tag`: the record's fingerprint prefix, and bytes of it read.
    tag: [u8; PEER_TAG_LEN],
    tag_have: u8,
    /// A delimited record's header, and bytes of it read.
    tx_hdr: [u8; HDR_MAX],
    tx_hdr_have: u8,
    /// The record's length, and bytes of it taken off the input
    /// (`TX_FILL`, `TX_DISCARD`, and a streamed record's header).
    tx_len: u64,
    tx_read: u64,
    /// Sessions (peer slots) the record is still owed to.
    tx_mask: u8,
    /// Where a staged record starts in the pool, and where a reassembled
    /// mailbox record is laid out flat for its single delivering write (its
    /// fingerprint prefix first, under `peer_tag`).
    tx_stage: u32,
    rx_stage: u32,
    /// The peer whose record is part-way onto the output, or `NO_PEER`;
    /// bytes of it written (prefix included); the next peer to look at.
    deliver_peer: u8,
    deliver_off: u32,
    deliver_rr: u8,
    /// `resume`: a delimited record being taken off the input into the
    /// windows of `in_mask`: its length and bytes so far (its region is
    /// reserved when it completes).
    in_active: bool,
    in_len: u32,
    in_have: u32,
    in_mask: u8,
    pub records_sent: u32,
    pub records_delivered: u32,
    pub refused_oversize: u32,
    pub lost: u32,
    /// `resume`: records sent again after a session ended.
    pub resent: u32,
    /// `peer_tag`: records whose prefix named no peer this side holds.
    pub unrouted: u32,
}

/// One channel as one peer's session carries it.
#[repr(C)]
struct PeerChan {
    // Reassembly ring: [len:4 LE][record] per record, `ring_off` into the pool.
    ring_off: u32,
    ring_cap: u32,
    ring_head: u32,
    ring_used: u32,
    /// The record being received: its length and bytes so far.
    rx_len: u32,
    rx_have: u32,
    rx_active: bool,
    /// Credit to return to the peer.
    credit_owed: u32,
    /// Credit the peer has granted for our sends.
    tx_credit: u32,
    /// Bytes of the channel's current record sent to this peer.
    tx_sent: u32,
    /// `mux`: the stream carrying this channel, and whether the tables have
    /// crossed on it.
    stream: u32,
    has_stream: bool,
    hello_rx: bool,
    hello_owed: bool,
    // `resume`. The retained window — `[len:4 LE][record]` per record, the
    // oldest at `rt_head` — holds every record taken off the input for this
    // peer that it has not acknowledged; the oldest is number `rt_base`.
    rt_off: u32,
    rt_cap: u32,
    rt_head: u32,
    rt_used: u32,
    rt_count: u32,
    rt_base: u64,
    /// The record being sent: its offset from `rt_head`, number, and bytes
    /// already sent this session.
    cur_at: u32,
    cur_seq: u64,
    cur_sent: u32,
    /// The highest record sent whole this session, and ever (a lower one
    /// sent again is a resend).
    sent_through: u64,
    sent_high: u64,
    /// The next record expected from the peer's stream, and whether its
    /// acknowledgement is owed.
    rx_next: u64,
    ack_owed: bool,
}

/// One peer: what this instance holds for it across its sessions.
#[repr(C)]
struct Peer {
    /// Held for a peer: its streams are retained, or a session is live.
    used: bool,
    /// The transport session serving it, or `NO_LINK`.
    link: u8,
    /// Its verified key fingerprint (empty without `require_peer`).
    fp: [u8; PEER_TAG_LEN],
    fp_len: u8,
    /// When its last session ended, by `State::clock`.
    gone_at: u32,
    /// `resume`: the peer's incarnation whose streams this side holds, and
    /// what this side's `HELLO` tells it, fixed when the session attaches.
    peer_inc: [u8; INCARNATION_LEN],
    hello_held: [u8; INCARNATION_LEN],
    hello_next: [u64; MAX_CHANNELS],
    /// Far: this session's opening LINK record is away (or queued).
    far_announced: bool,
    /// Far: a record of the module's own owed to this peer ahead of the
    /// provider's — the opening LINK or a refusal — and its length.
    own_len: u8,
    own: [u8; OWN_RECORD_LEN],
    chans: [PeerChan; MAX_CHANNELS],
}

/// One transport session: a connection (`net`) or a QUIC session (`mux`).
#[repr(C)]
struct Link {
    phase: u8,
    /// The peer slot it serves, once its identity is bound.
    peer: u8,
    conn: u16,
    generation: u16,
    session: u32,
    local_init: bool,
    peer_bound: bool,
    fp: [u8; PEER_TAG_LEN],
    fp_len: u8,
    /// `net`: this side's table is owed, and the peer's has arrived.
    hello_owed: bool,
    hello_rx: bool,
    /// `mux`: streams opened, and an open awaiting its answer.
    opening: u8,
    open_pending: bool,
    /// When an attaching session is given up on; see `SETUP_TIMEOUT_MS`.
    setup_deadline_ms: u32,
    last_rx_ms: u32,
    last_tx_ms: u32,
    /// `net`: the peer's table, when it arrives before this session's peer
    /// is bound — applied once it is.
    early_len: u16,
    early: [u8; wire::HELLO_MAX],
    parser: Parser,
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

/// An exchange the far side handed its provider.
#[repr(C)]
#[derive(Clone, Copy)]
struct XOpen {
    /// The peer slot whose session issued it.
    peer: u8,
    /// Its session ended: an ABORT is owed to the provider.
    aborting: bool,
    /// The id the requester gave it, and the one the provider knows it by.
    theirs: xc::ExchangeId,
    local: xc::ExchangeId,
}

/// The peer-identity records the transport has reported, one per
/// connection.
///
/// `tls` reports every handshake it completes, on every connection it
/// seats, whichever port the connection was accepted on. The report
/// reaches this module directly, when the handshake completes; the
/// session it names reaches this module later, through whatever stands
/// between — `http`'s upgrade, say — or never, when the connection was
/// for something else. So a record waits here for its session, beside
/// the records of every other connection whose handshake completed
/// meanwhile, and a session arriving finds its own by connection id and
/// generation.
///
/// A connection id outlives its sessions, and of the sessions on one id
/// only the newest can still arrive, so a record replaces the one its
/// connection held. A record is spent once its session is decided —
/// bound, refused, or ended — and only then: the id's next record can be
/// here before the close of the session before it, which comes the long
/// way round, so spending goes by generation, and a close the transport
/// reports for a connection this module never served spends nothing.
///
/// The table holds one record for every session the transport can seat
/// at once. A record whose connection was never served stays until its
/// id is reused, so on a transport whose connection ids outnumber its
/// seats the table can fill, and the record that has waited longest is
/// displaced.
#[repr(C)]
#[derive(Clone, Copy)]
struct Identity {
    conn: u16,
    generation: u16,
    bound: bool,
    used: bool,
    /// The key fingerprint a binding record names (empty otherwise).
    fp_len: u8,
    fp: [u8; PEER_TAG_LEN],
    /// When the record arrived, by `Identities::clock`.
    arrived: u32,
}

#[repr(C)]
struct Identities {
    slots: [Identity; IDENTITIES],
    /// Counts records in; a record's age is its distance from this.
    clock: u32,
}

impl Identities {
    fn find(&self, conn: u16) -> Option<usize> {
        self.slots.iter().position(|e| e.used && e.conn == conn)
    }

    /// Keep `conn`'s record, in place of any it held.
    fn put(&mut self, conn: u16, generation: u16, bound: bool, fp: &[u8]) {
        self.clock = self.clock.wrapping_add(1);
        let i = self
            .find(conn)
            .or_else(|| self.slots.iter().position(|e| !e.used))
            .unwrap_or_else(|| self.oldest());
        let mut e = Identity {
            conn,
            generation,
            bound,
            used: true,
            fp_len: 0,
            fp: [0; PEER_TAG_LEN],
            arrived: self.clock,
        };
        if fp.len() <= PEER_TAG_LEN {
            e.fp[..fp.len()].copy_from_slice(fp);
            e.fp_len = fp.len() as u8;
        }
        self.slots[i] = e;
    }

    /// The slot whose record has waited longest.
    fn oldest(&self) -> usize {
        let mut oldest = 0;
        for (i, e) in self.slots.iter().enumerate() {
            if self.clock.wrapping_sub(e.arrived)
                > self.clock.wrapping_sub(self.slots[oldest].arrived)
            {
                oldest = i;
            }
        }
        oldest
    }

    /// The record naming (`conn`, `generation`); None when none does.
    fn get(&self, conn: u16, generation: u16) -> Option<Identity> {
        self.find(conn)
            .filter(|&i| self.slots[i].generation == generation)
            .map(|i| self.slots[i])
    }

    /// Spend the record naming (`conn`, `generation`). A record naming a
    /// later session on the same connection is that session's, and stays.
    fn spend(&mut self, conn: u16, generation: u16) {
        if let Some(i) = self.find(conn) {
            if self.slots[i].generation == generation {
                self.slots[i].used = false;
            }
        }
    }
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
    /// `sessions`: peers served at once (a listener's; 1 otherwise).
    n_peers: u8,
    /// Transport sessions held at once: `n_peers`, and one being set up on
    /// a listener.
    n_links: u8,
    /// `peer_tag`: local records carry the peer's fingerprint.
    peer_tag: u8,
    phase: u8,
    port: u16,
    peer_port: u16,
    redial_ms: u32,
    retry_at_ms: u32,
    my_tag: net_proto::RequesterTag,
    peer_af: u8,
    peer_host_len: u8,
    authority_len: u8,
    peer_addr: [u8; 16],
    authority: [u8; MAX_AUTHORITY_LEN],
    table_text: [u8; TABLE_TEXT_MAX],
    table_text_len: u16,
    table_text_overflow: bool,
    table: Table,
    ids: Identities,
    links: [Link; LINKS_MAX],
    peers: [Peer; SESSIONS_MAX],
    chans: [Chan; MAX_CHANNELS],
    /// `mux`: the one session's streams.
    slots: [Slot; MAX_CHANNELS],
    rr: u8,
    /// The peer a channel's sends start from, turned each step.
    prr: u8,
    /// Counts sessions ending, for which peer has been gone longest.
    clock: u32,
    tx: [u8; TX_BUF],
    tx_len: u16,
    /// The transport session the frame staged in `tx` belongs to.
    tx_link: u8,
    /// Owed closes, oldest first; see `CLOSES_OWED`.
    closes: [u32; CLOSES_OWED],
    n_closes: u8,
    rx: [u8; RX_SCRATCH],
    /// Sessions opened, ever.
    pub sessions: u32,
    /// Sessions closed because a newer session of the same peer arrived.
    pub sessions_replaced: u32,
    /// Sessions closed because every one this instance serves was in use.
    pub sessions_refused: u32,
    /// `resume`: peers whose retained streams were given up to make room
    /// for a new peer.
    pub peers_evicted: u32,
    // `resume`.
    resume: u8,
    /// `window`: retained bytes per channel (0: `WINDOW_RECORDS` records).
    window: u32,
    /// This instance's incarnation.
    pub incarnation: [u8; INCARNATION_LEN],
    /// `keepalive_ms`: an open resume session that has sent nothing this
    /// long sends an acknowledgement, and one that has heard nothing for
    /// three of these is given up — a link that died without a close
    /// (a cut that reset only one end, a black hole) ends its session and
    /// the next one resumes, rather than holding the session for ever.
    keepalive_ms: u32,
    /// Records refused as replays (a number the receiver already had).
    pub replays_refused: u32,
    /// Sessions whose peer named another incarnation than the one held: its
    /// first, or one after it restarted.
    pub peer_restarts: u32,
    /// `session` output; see `report_session`.
    session_out: i32,
    /// The state the `session` output last carried: open, and its ordinal.
    reported_open: bool,
    reported_session: u32,
    // Exchange endpoint (`table.side`). Its request channel is
    // `table.exchange_at`, its response channel the next.
    /// Near: `NS_*`.
    near_state: u8,
    /// Near: what the requester last heard (or is about to): up until a
    /// DOWN, so a requester never told anything is up.
    told_up: bool,
    /// The provider's link as the far side last reported it.
    prov_up: bool,
    /// Near: this session's opening LINK record has arrived.
    far_ready: bool,
    /// Near: the LINK state owed to the requester, 0 for none.
    link_owed: u8,
    /// Far: the exchanges handed to the provider, and the next id of its
    /// own the far side gives one.
    n_open: u16,
    open: [XOpen; OPEN_EXCHANGES_MAX],
    next_local: u64,
    /// Far: requests answered 503 (the open table was full), 413 (the HEAD
    /// no longer fit once its `peer` was written) or 400 (not a HEAD).
    pub x_refused: u32,
    /// Far: ABORTs written for exchanges a session left open.
    pub x_aborted: u32,
    /// Records an endpoint dropped: the requester's after a lost session,
    /// the provider's for exchanges no longer open.
    pub x_discarded: u32,
    pool: [u8; REASSEMBLY_BYTES],
}

impl State {
    /// `resume`: records channel `i` sent again after a session ended.
    pub fn chans_resent(&self, i: usize) -> u32 {
        self.chans[i].resent
    }

    /// `peer_tag`: records channel `i` dropped because their prefix named
    /// no peer.
    pub fn chans_unrouted(&self, i: usize) -> u32 {
        self.chans[i].unrouted
    }

    /// Records channel `i` lost with a session.
    pub fn chans_lost(&self, i: usize) -> u32 {
        self.chans[i].lost
    }

    /// Records channel `i` sent (each once, however many sessions it went
    /// to) and delivered.
    pub fn chans_records(&self, i: usize) -> (u32, u32) {
        (self.chans[i].records_sent, self.chans[i].records_delivered)
    }

    /// Sessions open now.
    pub fn open_sessions(&self) -> usize {
        self.links[..self.n_links as usize]
            .iter()
            .filter(|l| l.phase == PH_OPEN)
            .count()
    }
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
        8, exchange, u8, 0, enum { none=0, near=1, far=2 } => |s, d, len| { s.table.side = p_u8(d, len, 0, 0); };
        9, resume, u8, 0 => |s, d, len| { s.resume = p_u8(d, len, 0, 0); };
        10, window, u32, 0 => |s, d, len| { s.window = p_u32(d, len, 0, 0); };
        11, keepalive_ms, u32, 1000 => |s, d, len| { s.keepalive_ms = p_u32(d, len, 0, 1000); };
        12, sessions, u8, 1 => |s, d, len| { s.n_peers = p_u8(d, len, 0, 1); };
        13, peer_tag, u8, 0 => |s, d, len| { s.peer_tag = p_u8(d, len, 0, 0); };
    }
}

// Indexed by `wire::TableError`.
name_table!(
    TABLE_ERRORS = [
        b"[remote_channel] refusing to construct: `channels` is empty",
        b"[remote_channel] refusing to construct: `channels` names more than MAX_CHANNELS",
        b"[remote_channel] refusing to construct: a `channels` entry is not content_type:framing:max_record",
        b"[remote_channel] refusing to construct: a `channels` content type is empty, too long, or not alphanumeric",
        b"[remote_channel] refusing to construct: a `channels` framing is not tlv16, len32, len16@<off>+<add>, len32@<off>+<add> (header within 64 bytes), mailbox or bytes",
        b"[remote_channel] refusing to construct: a `channels` max_record is outside what its framing and MAX_RECORD admit",
    ]
);

unsafe fn log(s: &State, level: u8, m: &[u8]) {
    dev_log(&*s.syscalls, level, m.as_ptr(), m.len());
}

fn n_channels(s: &State) -> usize {
    s.table.channels as usize
}

/// The exchange endpoint's request channel.
fn x_req(s: &State) -> usize {
    s.table.exchange_at as usize
}

/// The exchange endpoint's response channel.
fn x_resp(s: &State) -> usize {
    s.table.exchange_at as usize + 1
}

/// Whether channel `i` belongs to the exchange endpoint.
fn is_x(s: &State, i: usize) -> bool {
    s.table.side != wire::side::NONE && (i == x_req(s) || i == x_resp(s))
}

/// Bytes of fingerprint prefix channel `i`'s local records carry.
fn tag_len(s: &State, i: usize) -> usize {
    if s.peer_tag != 0 && !is_x(s, i) {
        PEER_TAG_LEN
    } else {
        0
    }
}

/// `at` taken round `n` slots, for an `at` below `2 * n`. Not `%`: a
/// remainder by a count the compiler cannot prove non-zero links a panic
/// a position-independent module cannot carry.
fn ring_next(at: usize, n: usize) -> usize {
    if at >= n {
        at - n
    } else {
        at
    }
}

/// Whether peer `p` has a session open.
fn peer_open(s: &State, p: usize) -> bool {
    let l = s.peers[p].link;
    l != NO_LINK && s.links[l as usize].phase == PH_OPEN
}

/// The peers with a session open.
fn open_mask(s: &State) -> u8 {
    let mut m = 0u8;
    for p in 0..s.n_peers as usize {
        if peer_open(s, p) {
            m |= 1 << p;
        }
    }
    m
}

/// The peers whose streams are held (`resume`): every peer slot in use; one
/// session's instance always holds its one.
fn held_mask(s: &State) -> u8 {
    let mut m = 0u8;
    for p in 0..s.n_peers as usize {
        if s.peers[p].used {
            m |= 1 << p;
        }
    }
    m
}

/// The peers a record's fingerprint prefix sends it to, among `among`: all
/// zero is every one, a peer's fingerprint that peer, anything else none.
fn route(s: &State, tag: &[u8; PEER_TAG_LEN], among: u8) -> u8 {
    if *tag == [0; PEER_TAG_LEN] {
        return among;
    }
    for p in 0..s.n_peers as usize {
        let e = &s.peers[p];
        if e.used && e.fp_len > 0 && peer_fp(s, p) == *tag {
            return among & (1 << p);
        }
    }
    0
}

/// Peer `p`'s fingerprint as a prefix: zero past its length.
fn peer_fp(s: &State, p: usize) -> [u8; PEER_TAG_LEN] {
    let mut out = [0u8; PEER_TAG_LEN];
    let e = &s.peers[p];
    out[..e.fp_len as usize].copy_from_slice(&e.fp[..e.fp_len as usize]);
    out
}

/// Whether peer `p`'s reassembly rings are empty.
fn rings_empty(s: &State, p: usize) -> bool {
    (0..n_channels(s)).all(|i| s.peers[p].chans[i].ring_used == 0)
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

/// Lay each channel's regions out in the pool. Per channel: a send stage
/// where records are staged (a `mailbox`, or a channel several sessions
/// take each record from) and, on a `mailbox`, a delivery stage — each with
/// room for the fingerprint prefix under `peer_tag`. Per channel and peer:
/// a reassembly ring, and under `resume` a retained window. An exchange
/// channel carries records one way, so it has only the half it uses: a send
/// stage where this side sends, rings and a delivery stage where it
/// receives. `false` when the whole needs more than `REASSEMBLY_BYTES`.
fn carve_pool(s: &mut State) -> bool {
    let mut at: u64 = 0;
    let peers = s.n_peers as usize;
    for i in 0..n_channels(s) {
        let e = s.table.entries[i];
        let dir = s.chans[i].xdir;
        let max = e.max_record as u64;
        let tag = tag_len(s, i) as u64;
        let mailbox = e.framing == wire::framing::MAILBOX;
        s.chans[i].staged = mailbox || peers > 1;
        if s.chans[i].staged && dir != DIR_RECV {
            s.chans[i].tx_stage = (at + tag) as u32;
            at += tag + max;
        }
        if mailbox && dir != DIR_SEND {
            s.chans[i].rx_stage = at as u32;
            at += tag + max;
        }
        for p in 0..peers {
            let pc = &mut s.peers[p].chans[i];
            if dir != DIR_SEND {
                pc.ring_off = at as u32;
                pc.ring_cap = (max + RECORD_CHARGE as u64) as u32;
                at += max + RECORD_CHARGE as u64;
            }
            if s.table.resume {
                let floor = max + RECORD_CHARGE as u64;
                let win = if s.window == 0 {
                    floor * WINDOW_RECORDS as u64
                } else {
                    (s.window as u64).max(floor)
                };
                pc.rt_off = at as u32;
                pc.rt_cap = win as u32;
                at += win;
            }
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
/// (`body_len` bytes), addressed to transport session `l` and `chan`
/// (`mux`: its stream), and try to write it. The command is committed once
/// staged: a refused write leaves it in `tx` for `flush_tx`, so callers
/// never stage it again.
unsafe fn send_staged(s: &mut State, l: usize, chan: Option<usize>, body_len: usize) {
    let (start, cmd, plen) = if s.transport == TRANSPORT_NET {
        let start = TX_PREFIX - 5;
        let conn = s.links[l].conn;
        s.tx[start + 3..start + 5].copy_from_slice(&conn.to_le_bytes());
        (start, net_proto::CMD_SEND, 2 + body_len)
    } else {
        let p = s.links[l].peer as usize;
        let stream = match chan {
            Some(c) if p < SESSIONS_MAX => s.peers[p].chans[c].stream,
            _ => return,
        };
        let start = TX_PREFIX - 3 - mux::STREAM_DATA_PREFIX;
        let session = s.links[l].session;
        mux::put_session_id(&mut s.tx[start + 3..], session);
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
    s.tx_link = l as u8;
    s.links[l].last_tx_ms = dev_millis(&*s.syscalls) as u32;
    flush_tx(s);
}

/// Commit a whole carrier-level command (`net_proto` / mux) with `payload`,
/// on behalf of transport session `l` (`NO_LINK` for the instance's own).
/// True when it was staged — written, or held for the next flush; false
/// when an earlier frame is still unwritten and nothing was staged.
unsafe fn command(s: &mut State, l: u8, cmd: u8, payload: &[u8]) -> bool {
    if !flush_tx(s) {
        return false;
    }
    let n = 3 + payload.len();
    s.tx[0] = cmd;
    s.tx[1..3].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    s.tx[3..n].copy_from_slice(payload);
    s.tx_len = n as u16;
    s.tx_link = l;
    flush_tx(s);
    true
}

/// Commit a protocol frame `[kind][channel][len][body]` on transport
/// session `l` for `chan`, with the same result as [`command`].
unsafe fn frame(
    s: &mut State,
    l: usize,
    chan: Option<usize>,
    kind: u8,
    channel: u8,
    body: &[u8],
) -> bool {
    if !flush_tx(s) {
        return false;
    }
    let at = TX_PREFIX;
    wire::header(kind, channel, body.len(), &mut s.tx[at..]);
    s.tx[at + FRAME_HDR..at + FRAME_HDR + body.len()].copy_from_slice(body);
    send_staged(s, l, chan, FRAME_HDR + body.len());
    true
}

/// Owe the transport a close of `id` — a connection (`net`) or session
/// (`mux`) this instance will not use, or has ended — and try it.
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
/// it: a frame staged in `tx` never holds one back, and the frame of a
/// session being closed is dropped from `tx` before its close is owed.
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

/// A free transport-session slot, if any.
fn free_link(s: &State) -> Option<usize> {
    (0..s.n_links as usize).find(|&l| s.links[l].phase == L_FREE)
}

/// The transport session on connection `conn` (`net`).
fn link_of_conn(s: &State, conn: u16) -> Option<usize> {
    (0..s.n_links as usize).find(|&l| s.links[l].phase >= PH_ATTACHING && s.links[l].conn == conn)
}

/// Transport session `l` is up: set it attaching. Its peer is decided
/// once its identity binds — at once without `require_peer`; on `mux`
/// the one session serves the one peer slot from the start.
unsafe fn start_attach(s: &mut State, l: usize) {
    let now = dev_millis(&*s.syscalls) as u32;
    let lk = &mut s.links[l];
    lk.phase = PH_ATTACHING;
    lk.setup_deadline_ms = later(now, SETUP_TIMEOUT_MS);
    lk.peer_bound = s.require_peer == 0;
    lk.last_rx_ms = now;
    lk.last_tx_ms = now;
    lk.hello_owed = false;
    lk.hello_rx = false;
    lk.opening = 0;
    lk.open_pending = false;
    lk.peer = NO_PEER;
    lk.fp_len = 0;
    lk.early_len = 0;
    lk.parser.reset();
    if s.transport == TRANSPORT_MUX {
        for i in 0..MAX_CHANNELS {
            let sl = &mut s.slots[i];
            sl.used = false;
            sl.ack_owed = 0;
            sl.channel = 0xFF;
            sl.parser.reset();
        }
        attach_peer(s, l, 0);
    } else if s.links[l].peer_bound {
        bind_link(s, l);
    }
}

/// Transport session `l`'s peer is known (its fingerprint in `fp`, empty
/// without `require_peer`): give it the peer slot that peer holds — ending
/// that peer's older session — or a free one, or under `resume` the slot of
/// the peer gone longest. A session with nowhere to go is closed. False
/// when `l` was closed.
unsafe fn bind_link(s: &mut State, l: usize) -> bool {
    let fp_len = s.links[l].fp_len as usize;
    let mut fp = [0u8; PEER_TAG_LEN];
    fp[..fp_len].copy_from_slice(&s.links[l].fp[..fp_len]);
    let same = |s: &State, p: usize| {
        let e = &s.peers[p];
        e.used && fp_len > 0 && e.fp_len as usize == fp_len && e.fp[..fp_len] == fp[..fp_len]
    };
    if s.require_peer != 0 && fp_len == 0 && (s.n_peers > 1 || s.peer_tag != 0) {
        end_link(
            s,
            l,
            true,
            b"[remote_channel] refused: the peer's identity names no fingerprint to tell its session from another's",
        );
        return false;
    }
    let p = if s.n_peers == 1 {
        let old = s.peers[0].link;
        if old != NO_LINK {
            if !same(s, 0) {
                s.sessions_refused = s.sessions_refused.wrapping_add(1);
                end_link(
                    s,
                    l,
                    true,
                    b"[remote_channel] refused: a session is already being served",
                );
                return false;
            }
            s.sessions_replaced = s.sessions_replaced.wrapping_add(1);
            end_link(
                s,
                old as usize,
                true,
                b"[remote_channel] a newer session of the same peer replaces this one",
            );
        }
        0
    } else if let Some(p) = (0..s.n_peers as usize).find(|&p| same(s, p)) {
        let old = s.peers[p].link;
        if old != NO_LINK {
            s.sessions_replaced = s.sessions_replaced.wrapping_add(1);
            end_link(
                s,
                old as usize,
                true,
                b"[remote_channel] a newer session of the same peer replaces this one",
            );
        }
        p
    } else if let Some(p) = (0..s.n_peers as usize).find(|&p| !s.peers[p].used) {
        claim_peer(s, p);
        p
    } else {
        // Every slot holds a peer. Under `resume` the one gone longest whose
        // records have all been delivered gives its streams up.
        let mut pick: Option<usize> = None;
        if s.table.resume {
            for p in 0..s.n_peers as usize {
                let e = &s.peers[p];
                if e.link != NO_LINK || !rings_empty(s, p) {
                    continue;
                }
                let older = match pick {
                    None => true,
                    Some(q) => {
                        s.clock.wrapping_sub(e.gone_at) > s.clock.wrapping_sub(s.peers[q].gone_at)
                    }
                };
                if older {
                    pick = Some(p);
                }
            }
        }
        let Some(p) = pick else {
            s.sessions_refused = s.sessions_refused.wrapping_add(1);
            end_link(
                s,
                l,
                true,
                b"[remote_channel] refused: every session this instance serves is in use",
            );
            return false;
        };
        s.peers_evicted = s.peers_evicted.wrapping_add(1);
        log(
            s,
            2,
            b"[remote_channel] a peer gone longest gives its retained streams up to a new peer",
        );
        claim_peer(s, p);
        p
    };
    let e = &mut s.peers[p];
    e.fp[..fp_len].copy_from_slice(&fp[..fp_len]);
    e.fp_len = fp_len as u8;
    attach_peer(s, l, p);
    // A table the peer sent before its identity was settled is applied now,
    // after this side's own was fixed.
    let n = s.links[l].early_len as usize;
    if n > 0 {
        s.links[l].early_len = 0;
        let mut copy = [0u8; wire::HELLO_MAX];
        copy[..n].copy_from_slice(&s.links[l].early[..n]);
        if !on_hello(s, l, &copy[..n]) {
            return false;
        }
        s.links[l].hello_rx = true;
        maybe_open(s, l);
    }
    true
}

/// Take peer slot `p` for a peer it did not hold: nothing of the last
/// holder's streams survives (its rings drain on their own).
fn claim_peer(s: &mut State, p: usize) {
    let bit = !(1u8 << p);
    for i in 0..MAX_CHANNELS {
        let c = &mut s.chans[i];
        c.tx_mask &= bit;
        c.in_mask &= bit;
        let pc = &mut s.peers[p].chans[i];
        pc.tx_sent = 0;
        pc.rt_head = 0;
        pc.rt_used = 0;
        pc.rt_count = 0;
        pc.rt_base = 1;
        pc.cur_at = 0;
        pc.cur_seq = 1;
        pc.cur_sent = 0;
        pc.sent_through = 0;
        pc.sent_high = 0;
        pc.rx_next = 1;
        pc.ack_owed = false;
    }
    let e = &mut s.peers[p];
    e.used = true;
    e.peer_inc = [0; INCARNATION_LEN];
    e.far_announced = false;
    e.own_len = 0;
}

/// Transport session `l` serves peer slot `p` from now: fix what this
/// side's table will say, and start every channel's credit afresh.
fn attach_peer(s: &mut State, l: usize, p: usize) {
    s.links[l].peer = p as u8;
    let e = &mut s.peers[p];
    e.link = l as u8;
    e.used = true;
    // What this side's HELLO says, as things stand before the peer's.
    e.hello_held = e.peer_inc;
    for i in 0..MAX_CHANNELS {
        e.hello_next[i] = e.chans[i].rx_next.max(1);
        let pc = &mut e.chans[i];
        pc.has_stream = false;
        pc.hello_rx = false;
        pc.hello_owed = false;
        pc.credit_owed = 0;
        pc.tx_credit = 0;
    }
}

/// End transport session `l`: close it with the transport (`close`; not for
/// one the transport has already ended), and end what its peer's session
/// held — the record each channel was receiving, the record each was
/// sending.
unsafe fn end_link(s: &mut State, l: usize, close: bool, why: &[u8]) {
    log(s, 2, why);
    if s.links[l].phase >= PH_ATTACHING {
        // A frame still staged for this session ends with it.
        if s.tx_len != 0 && s.tx_link == l as u8 {
            s.tx_len = 0;
        }
        if close {
            let id = if s.transport == TRANSPORT_NET {
                s.links[l].conn as u32
            } else {
                s.links[l].session
            };
            close_unused(s, id);
        }
        // This session's identity record is spent with it.
        let (conn, generation) = (s.links[l].conn, s.links[l].generation);
        s.ids.spend(conn, generation);
    }
    let p = s.links[l].peer;
    let lk = &mut s.links[l];
    lk.phase = L_FREE;
    lk.peer = NO_PEER;
    lk.conn = NO_CONN;
    lk.fp_len = 0;
    lk.early_len = 0;
    lk.peer_bound = false;
    if p != NO_PEER {
        peer_ended(s, p as usize);
    }
    let sys = &*s.syscalls;
    // A dialler redials; a listener goes on listening, and on `mux` the
    // transport announces the next session.
    if s.transport == TRANSPORT_NET && s.role == ROLE_DIAL {
        s.phase = PH_IDLE;
    }
    s.retry_at_ms = later(dev_millis(sys) as u32, s.redial_ms);
}

/// Peer slot `p`'s session ended: drop the record each channel was
/// receiving from it, and settle the record each was sending it.
fn peer_ended(s: &mut State, p: usize) {
    let bit = 1u8 << p;
    let resume = s.table.resume;
    let several = s.n_peers > 1;
    for i in 0..n_channels(s) {
        let pc = &mut s.peers[p].chans[i];
        if pc.rx_active {
            // The partial record's bytes leave the ring. With `resume` the
            // sender still holds it and sends it again; without, it is lost.
            pc.ring_used -= RECORD_CHARGE + pc.rx_have;
            pc.rx_active = false;
            if !resume {
                s.chans[i].lost = s.chans[i].lost.wrapping_add(1);
            }
        }
        pc.credit_owed = 0;
        pc.tx_credit = 0;
        if resume {
            // Nothing sent is lost: the next session starts from the
            // oldest record the peer has not acknowledged.
            pc.cur_at = 0;
            pc.cur_seq = pc.rt_base;
            pc.cur_sent = 0;
            pc.sent_through = pc.rt_base - 1;
            pc.ack_owed = false;
            continue;
        }
        let sent = pc.tx_sent;
        pc.tx_sent = 0;
        if is_x(s, i) {
            // The endpoint settles its own channels (`x_peer_ended`).
            continue;
        }
        let c = &mut s.chans[i];
        if c.staged {
            if c.tx_mask & bit == 0 {
                continue;
            }
            // A record begun is lost to this peer. With one session a record
            // not yet begun waits for the next; with several it was taken for
            // the sessions open then, and this one is gone.
            if sent == 0 && !several {
                continue;
            }
            c.tx_mask &= !bit;
            c.lost = c.lost.wrapping_add(1);
            if c.tx_mask == 0 {
                c.tx_state = match c.tx_state {
                    TX_FILL => TX_DISCARD,
                    TX_BODY => TX_IDLE,
                    other => other,
                };
            }
        } else if c.tx_state == TX_BODY && sent > 0 {
            // Streamed: the rest of the record is still on its input.
            c.lost = c.lost.wrapping_add(1);
            c.tx_state = TX_DISCARD;
            c.tx_read = c.tx_read.max(sent as u64);
            c.tag_have = 0;
            c.tx_hdr_have = 0;
        }
    }
    x_peer_ended(s, p);
    s.clock = s.clock.wrapping_add(1);
    let e = &mut s.peers[p];
    e.link = NO_LINK;
    e.gone_at = s.clock;
    if !resume && several {
        e.used = false;
        e.fp_len = 0;
    }
}

/// The exchange endpoint's share of a session ending. Nothing an exchange
/// channel holds for that session crosses into the next: its requester
/// issues every exchange still open again.
fn x_peer_ended(s: &mut State, p: usize) {
    let bit = 1u8 << p;
    match s.table.side {
        wire::side::NEAR => {
            let q = x_req(s);
            if s.chans[q].tx_mask & bit != 0 {
                // Taken from the requester and not yet begun.
                s.chans[q].tx_mask = 0;
                s.chans[q].tx_state = TX_IDLE;
                s.x_discarded = s.x_discarded.wrapping_add(1);
            }
            s.far_ready = false;
            if s.near_state == NS_FORWARD {
                s.near_state = NS_PURGE;
            }
        }
        wire::side::FAR => {
            let q = x_req(s);
            let pc = &mut s.peers[p].chans[q];
            if pc.ring_used != 0 {
                // Requests that crossed whole and were not handed over.
                s.x_discarded = s.x_discarded.wrapping_add(1);
            }
            pc.ring_used = 0;
            pc.ring_head = 0;
            let r = x_resp(s);
            let c = &mut s.chans[r];
            if c.tx_mask & bit != 0 {
                // An answer taken from the provider for this session.
                c.tx_mask &= !bit;
                if c.tx_mask == 0 {
                    c.tx_state = TX_IDLE;
                }
                s.x_discarded = s.x_discarded.wrapping_add(1);
            }
            s.peers[p].chans[r].tx_sent = 0;
            let e = &mut s.peers[p];
            e.far_announced = false;
            e.own_len = 0;
            for k in 0..s.n_open as usize {
                if s.open[k].peer == p as u8 {
                    s.open[k].aborting = true;
                }
            }
        }
        _ => {}
    }
}

/// Refuse transport session `l`: say why, then end it.
unsafe fn refuse(s: &mut State, l: usize, reason: u8, why: &[u8]) {
    let body = [reason];
    if s.transport == TRANSPORT_NET {
        frame(s, l, None, wire::KIND_REFUSE, wire::CONTROL, &body);
    } else {
        let p = s.links[l].peer as usize;
        if p < SESSIONS_MAX {
            for i in 0..n_channels(s) {
                if s.peers[p].chans[i].has_stream {
                    frame(s, l, Some(i), wire::KIND_REFUSE, i as u8, &body);
                    break;
                }
            }
        }
    }
    end_link(s, l, true, why);
}

/// Attaching → hello once the identity is bound, every stream is open and
/// every ring of its peer has drained.
unsafe fn try_hello(s: &mut State, l: usize) {
    let lk = &s.links[l];
    if lk.phase != PH_ATTACHING || !lk.peer_bound || lk.peer == NO_PEER {
        return;
    }
    let p = lk.peer as usize;
    if !rings_empty(s, p) {
        return;
    }
    if s.transport == TRANSPORT_MUX {
        if lk.local_init {
            if (lk.opening as usize) < n_channels(s) {
                return;
            }
        } else {
            // The acceptor answers each stream's table as it arrives.
            s.links[l].phase = PH_HELLO;
            return;
        }
        for i in 0..n_channels(s) {
            s.peers[p].chans[i].hello_owed = true;
        }
    } else {
        s.links[l].hello_owed = true;
    }
    s.links[l].phase = PH_HELLO;
}

unsafe fn maybe_open(s: &mut State, l: usize) {
    let lk = &s.links[l];
    if lk.phase != PH_HELLO {
        return;
    }
    let p = lk.peer as usize;
    let all = if s.transport == TRANSPORT_NET {
        !lk.hello_owed && lk.hello_rx
    } else {
        (0..n_channels(s)).all(|i| {
            let pc = &s.peers[p].chans[i];
            pc.hello_rx && !pc.hello_owed
        })
    };
    if !all {
        return;
    }
    for i in 0..n_channels(s) {
        let max = s.chans[i].entry.max_record;
        s.peers[p].chans[i].tx_credit = max + RECORD_CHARGE;
    }
    s.links[l].phase = PH_OPEN;
    s.sessions = s.sessions.wrapping_add(1);
    log(s, 3, b"[remote_channel] session open");
}

/// A peer's table arrived on transport session `l` (`net`: the whole
/// session).
unsafe fn on_hello(s: &mut State, l: usize, body: &[u8]) -> bool {
    let Some(resume) = wire::hello_parse(&s.table, body) else {
        refuse(
            s,
            l,
            wire::refuse::TABLE_MISMATCH,
            b"[remote_channel] refused: the peer's channel table differs",
        );
        return false;
    };
    match resume {
        Some(r) => on_resume(s, l, &r),
        None => true,
    }
}

/// The peer's resume trailer: where each of its streams to us stands, and
/// where it holds ours.
unsafe fn on_resume(s: &mut State, l: usize, r: &wire::Resume) -> bool {
    let nch = n_channels(s);
    let p = s.links[l].peer as usize;
    // Its streams. A sender this side has not heard from under that
    // incarnation starts its numbering afresh.
    if r.incarnation != s.peers[p].peer_inc {
        if s.peers[p].peer_inc != [0; INCARNATION_LEN] {
            s.peer_restarts = s.peer_restarts.wrapping_add(1);
            log(
                s,
                2,
                b"[remote_channel] the peer is a new incarnation; its streams start afresh",
            );
        }
        s.peers[p].peer_inc = r.incarnation;
        for i in 0..nch {
            s.peers[p].chans[i].rx_next = 1;
        }
    }
    // Ours.
    if r.held == s.incarnation {
        let mut again = 0u32;
        for i in 0..nch {
            let pc = &s.peers[p].chans[i];
            let next = r.next[i];
            // The peer can neither expect a record we never took (it would
            // be acknowledging one that does not exist) nor one we already
            // released (only an acknowledgement releases, so it had it).
            if next < pc.rt_base || next > pc.rt_base + pc.rt_count as u64 {
                refuse(
                    s,
                    l,
                    wire::refuse::SEQUENCE,
                    b"[remote_channel] refused: the peer's resume point is outside the retained window",
                );
                return false;
            }
            release(s, p, i, next - 1);
            again += s.peers[p].chans[i].rt_count;
        }
        // What the peer never had whole goes again; say how much, so a
        // reconnect that recovered records is visible as one.
        let mut line = [0u8; 80];
        let head = b"[remote_channel] resumed: records going again=";
        line[..head.len()].copy_from_slice(head);
        let n = fmt_u32_raw(line.as_mut_ptr().add(head.len()), again);
        log(s, 3, &line[..head.len() + n]);
    } else {
        // It never saw our streams under this incarnation: everything we
        // retain for it is new to it, numbered from 1.
        for i in 0..nch {
            let pc = &mut s.peers[p].chans[i];
            pc.rt_base = 1;
            pc.sent_high = 0;
        }
    }
    for i in 0..nch {
        let pc = &mut s.peers[p].chans[i];
        pc.cur_at = 0;
        pc.cur_seq = pc.rt_base;
        pc.cur_sent = 0;
        pc.sent_through = pc.rt_base - 1;
    }
    true
}

/// Release peer `p`'s retained records on channel `i` through `seq`: the
/// peer has them.
fn release(s: &mut State, p: usize, i: usize, seq: u64) {
    let pc = &mut s.peers[p].chans[i];
    while pc.rt_count > 0 && pc.rt_base <= seq {
        let mut lb = [0u8; 4];
        ring_get(&s.pool, pc.rt_off, pc.rt_cap, pc.rt_head, &mut lb);
        let step = RECORD_CHARGE + u32::from_le_bytes(lb);
        pc.rt_head = wrap(pc.rt_head + step, pc.rt_cap);
        pc.rt_used -= step;
        pc.rt_count -= 1;
        pc.rt_base += 1;
        if pc.cur_seq < pc.rt_base {
            pc.cur_at = 0;
            pc.cur_seq = pc.rt_base;
            pc.cur_sent = 0;
        } else {
            pc.cur_at -= step;
        }
    }
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

/// The channel a frame's channel byte names on transport session `l`:
/// within the table, and on a `mux` stream the stream's own.
fn channel_of(s: &State, ch: u8, stream_channel: Option<usize>) -> Option<usize> {
    let c = ch as usize;
    if c >= n_channels(s) {
        return None;
    }
    match stream_channel {
        Some(sc) if sc != c => None,
        _ => Some(c),
    }
}

/// One parsed protocol event from transport session `l`'s carrier.
/// `stream_channel` is the channel a `mux` stream is known to carry. False
/// ends processing of this carrier input (the session ended).
unsafe fn on_event(s: &mut State, l: usize, ev: Event<'_>, stream_channel: Option<usize>) -> bool {
    let lp = s.links[l].peer;
    if lp == NO_PEER {
        // Before its peer is settled a session can only have sent its table:
        // the peer sends nothing else until it has this side's.
        return match ev {
            Event::None => true,
            Event::Refuse(_) => {
                end_link(s, l, true, b"[remote_channel] the peer refused the session");
                false
            }
            Event::Hello(ch, body)
                if s.transport == TRANSPORT_NET
                    && ch == wire::CONTROL
                    && s.links[l].early_len == 0
                    && !body.is_empty() =>
            {
                let lk = &mut s.links[l];
                lk.early[..body.len()].copy_from_slice(body);
                lk.early_len = body.len() as u16;
                true
            }
            _ => {
                refuse(
                    s,
                    l,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: a frame before the session's peer is known",
                );
                false
            }
        };
    }
    let p = lp as usize;
    let open = s.links[l].phase == PH_OPEN;
    match ev {
        Event::None => true,
        Event::Error => {
            refuse(
                s,
                l,
                wire::refuse::PROTOCOL,
                b"[remote_channel] refused: malformed frame",
            );
            false
        }
        Event::Refuse(_) => {
            end_link(s, l, true, b"[remote_channel] the peer refused the session");
            false
        }
        Event::Hello(ch, body) => {
            if s.transport == TRANSPORT_NET {
                if ch != wire::CONTROL || s.links[l].hello_rx || s.links[l].phase < PH_ATTACHING {
                    refuse(
                        s,
                        l,
                        wire::refuse::PROTOCOL,
                        b"[remote_channel] refused: unexpected table",
                    );
                    return false;
                }
                let mut copy = [0u8; wire::HELLO_MAX];
                copy[..body.len()].copy_from_slice(body);
                if !on_hello(s, l, &copy[..body.len()]) {
                    return false;
                }
                s.links[l].hello_rx = true;
            } else {
                let Some(c) = channel_of(s, ch, stream_channel) else {
                    refuse(
                        s,
                        l,
                        wire::refuse::PROTOCOL,
                        b"[remote_channel] refused: table on a stray stream",
                    );
                    return false;
                };
                if s.peers[p].chans[c].hello_rx {
                    refuse(
                        s,
                        l,
                        wire::refuse::PROTOCOL,
                        b"[remote_channel] refused: second table on a stream",
                    );
                    return false;
                }
                let mut copy = [0u8; wire::HELLO_MAX];
                copy[..body.len()].copy_from_slice(body);
                if !on_hello(s, l, &copy[..body.len()]) {
                    return false;
                }
                s.peers[p].chans[c].hello_rx = true;
                if !s.links[l].local_init {
                    s.peers[p].chans[c].hello_owed = true;
                }
            }
            maybe_open(s, l);
            true
        }
        Event::Credit(ch, n) => {
            let Some(c) = channel_of(s, ch, stream_channel) else {
                refuse(
                    s,
                    l,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: credit for no channel",
                );
                return false;
            };
            if !open {
                refuse(
                    s,
                    l,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: credit before the tables",
                );
                return false;
            }
            let cap = s.chans[c].entry.max_record as u64 + RECORD_CHARGE as u64;
            let next = s.peers[p].chans[c].tx_credit as u64 + n as u64;
            if next > cap {
                refuse(
                    s,
                    l,
                    wire::refuse::CREDIT,
                    b"[remote_channel] refused: credit beyond the peer's ring",
                );
                return false;
            }
            s.peers[p].chans[c].tx_credit = next as u32;
            true
        }
        Event::Ack(ch, seq) => {
            let Some(c) = channel_of(s, ch, stream_channel) else {
                refuse(
                    s,
                    l,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: acknowledgement for no channel",
                );
                return false;
            };
            if !s.table.resume || !open {
                refuse(
                    s,
                    l,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: acknowledgement outside a resume session",
                );
                return false;
            }
            let pc = &s.peers[p].chans[c];
            if seq > pc.sent_through || seq + 1 < pc.rt_base {
                refuse(
                    s,
                    l,
                    wire::refuse::SEQUENCE,
                    b"[remote_channel] refused: an acknowledgement of a record not sent, or behind one released",
                );
                return false;
            }
            release(s, p, c, seq);
            true
        }
        Event::RBegin(ch, len, seq) => {
            if !s.table.resume {
                refuse(
                    s,
                    l,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: a numbered record outside a resume session",
                );
                return false;
            }
            let Some(c) = channel_of(s, ch, stream_channel) else {
                refuse(
                    s,
                    l,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: record for no channel",
                );
                return false;
            };
            let next = s.peers[p].chans[c].rx_next;
            if seq != next {
                if seq < next {
                    s.replays_refused = s.replays_refused.wrapping_add(1);
                    refuse(
                        s,
                        l,
                        wire::refuse::SEQUENCE,
                        b"[remote_channel] refused: a replay of a record already received",
                    );
                } else {
                    refuse(
                        s,
                        l,
                        wire::refuse::SEQUENCE,
                        b"[remote_channel] refused: a record past the next one expected",
                    );
                }
                return false;
            }
            on_begin(s, l, ch, len, stream_channel)
        }
        Event::Begin(_, _) if s.table.resume && open => {
            refuse(
                s,
                l,
                wire::refuse::PROTOCOL,
                b"[remote_channel] refused: an unnumbered record in a resume session",
            );
            false
        }
        Event::Begin(ch, len) => on_begin(s, l, ch, len, stream_channel),
        Event::Data(ch, bytes) => {
            let Some(c) = channel_of(s, ch, stream_channel) else {
                refuse(
                    s,
                    l,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: bytes for no channel",
                );
                return false;
            };
            let pc = &s.peers[p].chans[c];
            if !pc.rx_active || pc.rx_have as u64 + bytes.len() as u64 > pc.rx_len as u64 {
                refuse(
                    s,
                    l,
                    wire::refuse::PROTOCOL,
                    b"[remote_channel] refused: bytes outside a record",
                );
                return false;
            }
            if pc.ring_used as u64 + bytes.len() as u64 > pc.ring_cap as u64 {
                refuse(
                    s,
                    l,
                    wire::refuse::CREDIT,
                    b"[remote_channel] refused: bytes beyond granted credit",
                );
                return false;
            }
            let (at, off, cap) = (pc.ring_head + pc.ring_used, pc.ring_off, pc.ring_cap);
            ring_put(&mut s.pool, off, cap, at, bytes);
            let pc = &s.peers[p].chans[c];
            let had = pc.rx_have;
            let have = had + bytes.len() as u32;
            // A delimited record must say, in its own header, the length
            // the wire gave it: otherwise the local consumer's idea of where
            // records end differs from this module's, and every record after
            // it is misframed. Checked before the bytes are committed, so a
            // refused record is dropped with the session rather than kept as
            // a complete one.
            let entry = s.chans[c].entry;
            let hl = entry.header_len();
            if hl > 0 && (had as usize) < hl && (have as usize) >= hl {
                let start = pc.ring_head + pc.ring_used - had;
                let mut hdr = [0u8; HDR_MAX];
                ring_get(&s.pool, off, cap, start, &mut hdr[..hl]);
                if entry.record_len(&hdr[..hl]) != pc.rx_len as u64 {
                    refuse(
                        s,
                        l,
                        wire::refuse::PROTOCOL,
                        b"[remote_channel] refused: a record whose header disagrees with its length",
                    );
                    return false;
                }
            }
            let resume = s.table.resume;
            let pc = &mut s.peers[p].chans[c];
            pc.ring_used += bytes.len() as u32;
            pc.rx_have = have;
            if have == pc.rx_len {
                pc.rx_active = false;
                if resume {
                    pc.rx_next += 1;
                    pc.ack_owed = true;
                }
            }
            true
        }
    }
}

/// A record of `len` bytes starts on channel byte `ch` of transport session
/// `l` (numbered or not: a resume session's number is checked before this).
unsafe fn on_begin(
    s: &mut State,
    l: usize,
    ch: u8,
    len: u32,
    stream_channel: Option<usize>,
) -> bool {
    let p = s.links[l].peer as usize;
    let Some(c) = channel_of(s, ch, stream_channel) else {
        refuse(
            s,
            l,
            wire::refuse::PROTOCOL,
            b"[remote_channel] refused: record for no channel",
        );
        return false;
    };
    if s.chans[c].xdir == DIR_SEND {
        refuse(
            s,
            l,
            wire::refuse::PROTOCOL,
            b"[remote_channel] refused: a record on a channel only this side sends on",
        );
        return false;
    }
    let entry = s.chans[c].entry;
    let pc = &s.peers[p].chans[c];
    if s.links[l].phase != PH_OPEN || pc.rx_active {
        refuse(
            s,
            l,
            wire::refuse::PROTOCOL,
            b"[remote_channel] refused: record out of sequence",
        );
        return false;
    }
    if (len as usize) < entry.header_len() {
        refuse(
            s,
            l,
            wire::refuse::PROTOCOL,
            b"[remote_channel] refused: a record shorter than its own header",
        );
        return false;
    }
    if len == 0 || len > entry.max_record {
        refuse(
            s,
            l,
            wire::refuse::OVERSIZE,
            b"[remote_channel] refused: record over the channel maximum",
        );
        return false;
    }
    if pc.ring_used + RECORD_CHARGE > pc.ring_cap {
        refuse(
            s,
            l,
            wire::refuse::CREDIT,
            b"[remote_channel] refused: record beyond granted credit",
        );
        return false;
    }
    let (at, off, cap) = (pc.ring_head + pc.ring_used, pc.ring_off, pc.ring_cap);
    ring_put(&mut s.pool, off, cap, at, &len.to_le_bytes());
    let pc = &mut s.peers[p].chans[c];
    pc.ring_used += RECORD_CHARGE;
    pc.rx_len = len;
    pc.rx_have = 0;
    pc.rx_active = true;
    true
}

/// Feed transport session `l`'s carrier bytes through its parser (`slot`
/// for a `mux` stream, `None` for the `net` stream), dispatching each event.
unsafe fn feed(s: &mut State, l: usize, slot: Option<usize>, mut input: &[u8]) {
    while !input.is_empty() {
        // The parser is not touched by event handling — a session ending
        // inside it resets parsers only when the next one attaches — so its
        // events may borrow it while the rest of the state changes.
        let parser: *mut Parser = match slot {
            None => &mut s.links[l].parser,
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
                    let p = s.links[l].peer as usize;
                    if s.slots[i].channel == 0xFF
                        && c < n_channels(s)
                        && !s.peers[p].chans[c].has_stream
                    {
                        s.slots[i].channel = ch;
                        s.peers[p].chans[c].has_stream = true;
                        s.peers[p].chans[c].stream = s.slots[i].stream;
                    }
                }
                let ch = s.slots[i].channel;
                if ch == 0xFF {
                    refuse(
                        s,
                        l,
                        wire::refuse::PROTOCOL,
                        b"[remote_channel] refused: a stream that names no channel",
                    );
                    return;
                }
                Some(ch as usize)
            }
        };
        if !on_event(s, l, ev, stream_channel) {
            return;
        }
        if used == 0 {
            break;
        }
    }
}

/// Bytes of complete records in peer `p`'s ring for channel `i`.
fn complete_bytes(s: &State, p: usize, i: usize) -> u32 {
    let pc = &s.peers[p].chans[i];
    if pc.rx_active {
        pc.ring_used - RECORD_CHARGE - pc.rx_have
    } else {
        pc.ring_used
    }
}

/// Deliver complete records to their local outputs, returning their credit.
/// Records from several sessions on one channel are merged record by
/// record, each session's in order.
unsafe fn deliver(s: &mut State) {
    let peers = s.n_peers as usize;
    for i in 0..n_channels(s) {
        if s.chans[i].output < 0 {
            continue;
        }
        loop {
            let c = &s.chans[i];
            let p = if c.deliver_peer != NO_PEER {
                c.deliver_peer as usize
            } else {
                let from = c.deliver_rr as usize;
                match (0..peers)
                    .map(|k| ring_next(from + k, peers))
                    .find(|&p| complete_bytes(s, p, i) > 0)
                {
                    Some(p) => p,
                    None => break,
                }
            };
            if !deliver_one(s, i, p) {
                break;
            }
            s.chans[i].deliver_rr = ring_next(p + 1, peers) as u8;
        }
    }
}

/// Deliver the front record of peer `p`'s ring on channel `i`. True when
/// it is off the ring (delivered, or refused); false when the output holds
/// it back.
unsafe fn deliver_one(s: &mut State, i: usize, p: usize) -> bool {
    let sys = &*s.syscalls;
    let pc = &s.peers[p].chans[i];
    let c = &s.chans[i];
    let mut lb = [0u8; 4];
    let (off, cap, head, output) = (pc.ring_off, pc.ring_cap, pc.ring_head, c.output);
    ring_get(&s.pool, off, cap, head, &mut lb);
    let len = u32::from_le_bytes(lb);
    let base = head + RECORD_CHARGE;
    let framing = c.entry.framing;
    let tag = tag_len(s, i) as u32;
    let fp = peer_fp(s, p);
    let mut refused = false;
    if framing == wire::framing::MAILBOX {
        // One write is one record: lay it out flat, prefix first, and hand
        // it over whole.
        let stage = s.chans[i].rx_stage;
        let (st, tl) = (stage as usize, tag as usize);
        s.pool[st..st + tl].copy_from_slice(&fp[..tl]);
        ring_flatten(&mut s.pool, off, cap, base, stage + tag, len);
        let (verdict, out_len) = if is_x(s, i) {
            x_inbound(s, p, stage as usize, len as usize)
        } else {
            (X_DELIVER, len as usize)
        };
        let total = tag as usize + out_len;
        let r = if verdict == X_DELIVER {
            (sys.channel_write)(output, s.pool.as_ptr().add(stage as usize), total)
        } else {
            0
        };
        if verdict == X_STALL {
            return false;
        } else if verdict == X_CONSUME {
            refused = true;
        } else if r == total as i32 {
            if is_x(s, i) {
                x_delivered(s, p, stage as usize, out_len);
            }
        } else if r == errno::EAGAIN || r == 0 {
            // Nothing placed: the consumer has not taken the last.
            return false;
        } else {
            log(
                s,
                1,
                b"[remote_channel] the mailbox cannot take a record this size; record refused",
            );
            s.chans[i].refused_oversize = s.chans[i].refused_oversize.wrapping_add(1);
            refused = true;
        }
    } else {
        // Chunked: the consumer delimits by the record's own header, after
        // the prefix.
        let total = tag + len;
        let mut done_bytes = s.chans[i].deliver_off;
        let mut chunk = [0u8; 1024];
        while done_bytes < total {
            let want = ((total - done_bytes) as usize).min(chunk.len());
            let mut k = 0usize;
            while k < want && done_bytes + (k as u32) < tag {
                chunk[k] = fp[(done_bytes as usize) + k];
                k += 1;
            }
            if k < want {
                let from = done_bytes + k as u32 - tag;
                ring_get(&s.pool, off, cap, base + from, &mut chunk[k..want]);
            }
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
                break;
            }
            done_bytes += n as u32;
        }
        let c = &mut s.chans[i];
        c.deliver_off = done_bytes;
        if done_bytes < total {
            // Part-way: this peer's record holds the output until it is whole.
            c.deliver_peer = if done_bytes > 0 { p as u8 } else { NO_PEER };
            return false;
        }
    }
    let c = &mut s.chans[i];
    c.deliver_off = 0;
    c.deliver_peer = NO_PEER;
    if !refused {
        c.records_delivered = c.records_delivered.wrapping_add(1);
    }
    let open = peer_open(s, p);
    let pc = &mut s.peers[p].chans[i];
    pc.ring_head = wrap(pc.ring_head + RECORD_CHARGE + len, pc.ring_cap);
    pc.ring_used -= RECORD_CHARGE + len;
    if open {
        pc.credit_owed += RECORD_CHARGE + len;
    }
    true
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
        s.ids.put(
            peer_identity::conn_id(p),
            peer_identity::generation(p),
            peer_identity::binds_identity(p),
            peer_identity::fingerprint(p).unwrap_or(&[]),
        );
    }
}

/// Settle a net session's identity from the record naming it. A record
/// binds only the session its connection id and generation both name: a
/// connection id outlives its sessions, and a record that arrives after its
/// session closed must not authenticate the next one on that id. A
/// transport that numbers no sessions gives nothing to tie a record to, so
/// its sessions cannot be authenticated. The record is spent whichever way
/// it decides the session: nothing else can use it.
unsafe fn check_net_identity(s: &mut State, l: usize) {
    let lk = &s.links[l];
    if lk.phase != PH_ATTACHING || lk.peer_bound {
        return;
    }
    if lk.generation == 0 {
        end_link(
            s,
            l,
            true,
            b"[remote_channel] refused: the transport numbers no sessions, so no peer identity can be tied to this one",
        );
        return;
    }
    let (conn, generation) = (lk.conn, lk.generation);
    let Some(rec) = s.ids.get(conn, generation) else {
        return;
    };
    s.ids.spend(conn, generation);
    if rec.bound {
        let lk = &mut s.links[l];
        lk.peer_bound = true;
        lk.fp = rec.fp;
        lk.fp_len = rec.fp_len;
        bind_link(s, l);
    } else {
        end_link(
            s,
            l,
            true,
            b"[remote_channel] refused: the transport did not authenticate the peer",
        );
    }
}

/// Give up on a session that is not becoming a channel session. Once the
/// peer is bound, waiting on the local consumers to drain old records is
/// local, not the peer's doing, and restarts the clock; an unbound peer is
/// given no such grace.
unsafe fn check_setup_deadline(s: &mut State, l: usize, now: u32) {
    let lk = &s.links[l];
    if lk.phase != PH_ATTACHING && lk.phase != PH_HELLO {
        return;
    }
    if lk.phase == PH_ATTACHING
        && lk.peer_bound
        && lk.peer != NO_PEER
        && !rings_empty(s, lk.peer as usize)
    {
        s.links[l].setup_deadline_ms = later(now, SETUP_TIMEOUT_MS);
        return;
    }
    if now.wrapping_sub(lk.setup_deadline_ms) < 0x8000_0000 {
        end_link(
            s,
            l,
            true,
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
            net_read_frame_sized(sys, s.transport_in, s.rx.as_mut_ptr(), RX_SCRATCH);
        if msg == 0 {
            break;
        }
        let p = &s.rx[3..3 + plen];
        let id = if plen >= 2 {
            net_proto::conn_id(p)
        } else {
            NO_CONN
        };
        if plen != full {
            if let Some(l) = link_of_conn(s, id) {
                end_link(
                    s,
                    l,
                    true,
                    b"[remote_channel] transport frame larger than the contract allows",
                );
            }
            continue;
        }
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
                } else if let (PH_LISTENING, Some(l)) = (s.phase, free_link(s)) {
                    let generation = net_proto::session_generation(p, net_proto::ACCEPTED_FIXED);
                    s.links[l].conn = id;
                    s.links[l].generation = generation;
                    forget_close(s, id as u32);
                    start_attach(s, l);
                } else {
                    // Every session this instance holds is taken.
                    close_unused(s, id as u32);
                }
            }
            net_proto::MSG_CONNECTED
                if plen >= net_proto::CONNECTED_FIXED
                    && net_proto::connected_parts(p).1 == s.my_tag =>
            {
                if s.phase == PH_DIALING {
                    let generation = net_proto::session_generation(p, net_proto::CONNECTED_FIXED);
                    s.links[0].conn = id;
                    s.links[0].generation = generation;
                    s.phase = PH_LINKED;
                    forget_close(s, id as u32);
                    start_attach(s, 0);
                } else if link_of_conn(s, id).is_none() {
                    // An answer to a dial this instance has given up on, or
                    // a second answer: nothing will use the connection.
                    close_unused(s, id as u32);
                }
            }
            net_proto::MSG_DATA if plen > 2 => {
                let Some(l) = link_of_conn(s, id) else {
                    continue;
                };
                s.links[l].last_rx_ms = dev_millis(sys) as u32;
                let mut data = [0u8; RX_SCRATCH];
                data[..plen - 2].copy_from_slice(&p[2..]);
                feed(s, l, None, &data[..plen - 2]);
            }
            net_proto::MSG_CLOSED if plen >= 2 => {
                forget_close(s, id as u32);
                if let Some(l) = link_of_conn(s, id) {
                    end_link(s, l, true, b"[remote_channel] session closed");
                }
            }
            net_proto::MSG_ERROR => {
                if s.phase == PH_DIALING
                    && plen >= net_proto::ERROR_FIXED + net_proto::REQUESTER_TAG_LEN
                    && net_proto::error_parts(p).2 == s.my_tag
                {
                    s.phase = PH_IDLE;
                    s.retry_at_ms = later(dev_millis(sys) as u32, s.redial_ms);
                } else if let Some(l) = link_of_conn(s, id) {
                    end_link(s, l, true, b"[remote_channel] session failed");
                }
            }
            _ => {}
        }
    }
}

/// `mux`: the one transport session, `links[0]`, serving peer slot 0.
unsafe fn mux_input(s: &mut State) {
    let sys = &*s.syscalls;
    for _ in 0..EVENTS_PER_STEP {
        // An event owes at most one close: read one only with room for it.
        flush_closes(s);
        if s.n_closes as usize == CLOSES_OWED {
            break;
        }
        let (msg, plen, full) =
            net_read_frame_sized(sys, s.transport_in, s.rx.as_mut_ptr(), RX_SCRATCH);
        if msg == 0 {
            break;
        }
        if plen != full {
            if s.links[0].phase >= PH_ATTACHING {
                end_link(
                    s,
                    0,
                    true,
                    b"[remote_channel] mux event larger than the contract allows",
                );
            }
            continue;
        }
        let mut p = [0u8; RX_SCRATCH];
        p[..plen].copy_from_slice(&s.rx[3..3 + plen]);
        let p = &p[..plen];
        if plen < mux::SESSION_ID_BYTES {
            continue;
        }
        let session = mux::session_id(p);
        let attached = s.links[0].phase >= PH_ATTACHING;
        match msg {
            mux::MSG_MUX_SESSION_OPENED if plen >= 4 + mux::SESSION_OPENED_BODY_MIN => {
                if attached || p[4] != mux::STATUS_OK {
                    if p[4] == mux::STATUS_OK {
                        // One session at a time.
                        close_unused(s, session);
                    }
                    continue;
                }
                forget_close(s, session);
                s.links[0].session = session;
                s.links[0].local_init = p[5] & mux::SESSION_FLAG_LOCAL_INIT != 0;
                start_attach(s, 0);
            }
            mux::MSG_MUX_SESSION_CLOSED | mux::MSG_MUX_SESSION_ERROR
                if !attached || session != s.links[0].session =>
            {
                forget_close(s, session);
            }
            _ if !attached || session != s.links[0].session => {}
            mux::MSG_MUX_PEER_IDENTITY => {
                if s.links[0].peer_bound {
                    continue;
                }
                if peer_identity::binds_identity(p) {
                    let fp = peer_identity::fingerprint(p).unwrap_or(&[]);
                    let n = fp.len().min(PEER_TAG_LEN);
                    let lk = &mut s.links[0];
                    lk.peer_bound = true;
                    lk.fp[..n].copy_from_slice(&fp[..n]);
                    lk.fp_len = n as u8;
                    let e = &mut s.peers[0];
                    e.fp[..n].copy_from_slice(&fp[..n]);
                    e.fp_len = n as u8;
                    if s.peer_tag != 0 && n == 0 {
                        end_link(
                            s,
                            0,
                            true,
                            b"[remote_channel] refused: the peer's identity names no fingerprint to tell its session from another's",
                        );
                    }
                } else {
                    end_link(
                        s,
                        0,
                        true,
                        b"[remote_channel] refused: the transport did not authenticate the peer",
                    );
                }
            }
            mux::MSG_MUX_STREAM_OPENED
                if plen >= mux::STREAM_DATA_PREFIX + mux::STREAM_OPENED_BODY =>
            {
                let stream = mux::stream_id(p);
                if !s.links[0].open_pending || !s.links[0].local_init {
                    continue;
                }
                s.links[0].open_pending = false;
                if p[8] != mux::STATUS_OK {
                    end_link(s, 0, true, b"[remote_channel] the transport has fewer streams than the table has channels");
                    continue;
                }
                let k = s.links[0].opening as usize;
                s.slots[k].used = true;
                s.slots[k].stream = stream;
                s.slots[k].channel = k as u8;
                s.peers[0].chans[k].stream = stream;
                s.peers[0].chans[k].has_stream = true;
                s.links[0].opening += 1;
            }
            mux::MSG_MUX_STREAM_ACCEPTED if plen >= mux::STREAM_DATA_PREFIX => {
                let stream = mux::stream_id(p);
                if s.links[0].local_init {
                    refuse(
                        s,
                        0,
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
                            0,
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
                // What arrives on a stream proves the link as a `net`
                // segment does: without this, a resumable mux session with
                // a keepalive is given up 3 × keepalive_ms after it opened,
                // however busy it is.
                s.links[0].last_rx_ms = dev_millis(sys) as u32;
                let data = &p[mux::STREAM_DATA_PREFIX..];
                // Every byte taken is acknowledged at once: what bounds the
                // peer is the credit this protocol grants, never the
                // transport's window.
                s.slots[i].ack_owed += data.len() as u32;
                let mut copy = [0u8; RX_SCRATCH];
                copy[..data.len()].copy_from_slice(data);
                feed(s, 0, Some(i), &copy[..data.len()]);
            }
            mux::MSG_MUX_STREAM_CLOSED | mux::MSG_MUX_STREAM_RESET | mux::MSG_MUX_STREAM_ERROR => {
                end_link(s, 0, true, b"[remote_channel] a channel stream ended");
            }
            mux::MSG_MUX_SESSION_CLOSED | mux::MSG_MUX_SESSION_ERROR => {
                // The transport's session is gone: nothing to close, and
                // nothing staged for it can be sent.
                end_link(s, 0, false, b"[remote_channel] session closed");
            }
            _ => {}
        }
    }
}

// ── Sending ─────────────────────────────────────────────────────────────────

/// Control owed before any record byte: transport acks, tables, credit.
unsafe fn send_control(s: &mut State) -> bool {
    let nch = n_channels(s);
    if s.transport == TRANSPORT_MUX && s.links[0].phase >= PH_ATTACHING {
        let session = s.links[0].session;
        for i in 0..MAX_CHANNELS {
            if s.slots[i].used && s.slots[i].ack_owed > 0 {
                let mut p = [0u8; mux::STREAM_DATA_PREFIX + 4];
                mux::put_session_id(&mut p, session);
                mux::put_stream_id(&mut p, s.slots[i].stream);
                p[8..12].copy_from_slice(&s.slots[i].ack_owed.to_le_bytes());
                if !command(s, 0, mux::CMD_MUX_STREAM_ACK, &p) {
                    return false;
                }
                s.slots[i].ack_owed = 0;
            }
        }
        let lk = &s.links[0];
        if lk.phase == PH_ATTACHING
            && lk.local_init
            && lk.peer_bound
            && !lk.open_pending
            && (lk.opening as usize) < nch
        {
            let mut p = [0u8; 5];
            mux::put_session_id(&mut p, session);
            p[4] = mux::STREAM_FLAG_BIDI;
            if !command(s, 0, mux::CMD_MUX_STREAM_OPEN, &p) {
                return false;
            }
            s.links[0].open_pending = true;
        }
    }
    for l in 0..s.n_links as usize {
        if s.links[l].phase < PH_HELLO || s.links[l].peer == NO_PEER {
            continue;
        }
        let p = s.links[l].peer as usize;
        let mut hello = [0u8; wire::HELLO_MAX];
        let hn = wire::encode_hello(&s.table, &mut hello);
        let hn = wire::encode_resume(
            &s.table,
            &s.incarnation,
            &s.peers[p].hello_held,
            &s.peers[p].hello_next,
            &mut hello,
            hn,
        );
        if s.links[l].hello_owed {
            if !frame(s, l, None, wire::KIND_HELLO, wire::CONTROL, &hello[..hn]) {
                return false;
            }
            s.links[l].hello_owed = false;
            maybe_open(s, l);
        }
        for i in 0..nch {
            let pc = &s.peers[p].chans[i];
            if pc.hello_owed && pc.has_stream {
                if !frame(s, l, Some(i), wire::KIND_HELLO, i as u8, &hello[..hn]) {
                    return false;
                }
                s.peers[p].chans[i].hello_owed = false;
                maybe_open(s, l);
            }
        }
        if s.links[l].phase != PH_OPEN {
            continue;
        }
        for i in 0..nch {
            let owed = s.peers[p].chans[i].credit_owed;
            if owed > 0 {
                if !frame(
                    s,
                    l,
                    Some(i),
                    wire::KIND_CREDIT,
                    i as u8,
                    &owed.to_le_bytes(),
                ) {
                    return false;
                }
                s.peers[p].chans[i].credit_owed = 0;
            }
            if s.peers[p].chans[i].ack_owed {
                let through = s.peers[p].chans[i].rx_next - 1;
                if !frame(
                    s,
                    l,
                    Some(i),
                    wire::KIND_ACK,
                    i as u8,
                    &through.to_le_bytes(),
                ) {
                    return false;
                }
                s.peers[p].chans[i].ack_owed = false;
            }
        }
    }
    true
}

/// The largest record-byte count one frame carries on this carrier.
fn frag_max(s: &State) -> usize {
    if s.transport == TRANSPORT_NET {
        FRAGMENT_MAX
    } else {
        MUX_FRAGMENT_MAX
    }
}

/// Skip the rest of channel `i`'s record on its input. True once it is
/// skipped.
unsafe fn discard_rest(s: &mut State, i: usize) -> bool {
    let sys = &*s.syscalls;
    let c = &mut s.chans[i];
    let mut sink = [0u8; 512];
    while c.tx_read < c.tx_len {
        let want = ((c.tx_len - c.tx_read) as usize).min(sink.len());
        let n = (sys.channel_read)(c.input, sink.as_mut_ptr(), want);
        if n <= 0 {
            return false;
        }
        c.tx_read += n as u64;
    }
    c.tx_state = TX_IDLE;
    c.tag_have = 0;
    c.tx_hdr_have = 0;
    true
}

/// Read channel `i`'s fingerprint prefix and length header off its input.
/// True once both are whole.
unsafe fn read_head(s: &mut State, i: usize) -> bool {
    let sys = &*s.syscalls;
    let tag = tag_len(s, i);
    let c = &mut s.chans[i];
    while (c.tag_have as usize) < tag {
        let n = (sys.channel_read)(
            c.input,
            c.tag.as_mut_ptr().add(c.tag_have as usize),
            tag - c.tag_have as usize,
        );
        if n <= 0 {
            return false;
        }
        c.tag_have += n as u8;
    }
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
    true
}

/// A delimited record's header is whole on channel `i`: its length, or
/// `None` when it is refused (over the maximum, or shorter than its own
/// header) and is being skipped.
unsafe fn head_len(s: &mut State, i: usize) -> Option<u64> {
    let c = &mut s.chans[i];
    let hl = c.entry.header_len();
    let len = c.entry.record_len(&c.tx_hdr[..hl]);
    if len > c.entry.max_record as u64 || len < hl as u64 {
        c.tx_state = TX_DISCARD;
        c.tx_len = len.max(hl as u64);
        c.tx_read = hl as u64;
        c.refused_oversize = c.refused_oversize.wrapping_add(1);
        log(
            s,
            1,
            b"[remote_channel] record over the channel maximum, or shorter than its own header, refused",
        );
        return None;
    }
    Some(len)
}

/// A record's prefix routed it nowhere it can go: skip it, counted.
unsafe fn unrouted(s: &mut State, i: usize, len: u64, read: u64) {
    let c = &mut s.chans[i];
    c.unrouted = c.unrouted.wrapping_add(1);
    c.tx_state = TX_DISCARD;
    c.tx_len = len;
    c.tx_read = read;
    log(
        s,
        2,
        b"[remote_channel] a record's peer prefix names no peer with a session; dropped",
    );
}

/// Non-`resume`, staged: take channel `i`'s next record off its input
/// for the sessions open now — every one, or the one its prefix names.
unsafe fn take(s: &mut State, i: usize, targets: u8) {
    let sys = &*s.syscalls;
    if s.chans[i].input < 0 {
        return;
    }
    if s.chans[i].tx_state == TX_DISCARD && !discard_rest(s, i) {
        return;
    }
    if s.chans[i].tx_state == TX_FILL {
        fill(s, i);
        return;
    }
    if s.chans[i].tx_state != TX_IDLE || targets == 0 {
        return;
    }
    let tag = tag_len(s, i);
    if s.chans[i].entry.framing == wire::framing::MAILBOX {
        // A mailbox read takes one whole buffer — prefix and record — or,
        // when it is larger than offered, nothing at all.
        let c = &s.chans[i];
        let (at, max, input) = (
            c.tx_stage as usize - tag,
            c.entry.max_record as usize + tag,
            c.input,
        );
        let n = (sys.channel_read)(input, s.pool.as_mut_ptr().add(at), max);
        if n == errno::EINVAL {
            // Over the maximum: refuse it by flushing it off the edge.
            dev_channel_ioctl(sys, input, IOCTL_FLUSH, core::ptr::null_mut(), 0);
            s.chans[i].refused_oversize = s.chans[i].refused_oversize.wrapping_add(1);
            log(
                s,
                1,
                b"[remote_channel] record over the channel maximum refused",
            );
            return;
        }
        if n <= 0 {
            return;
        }
        let n = n as usize;
        let mut mask = targets;
        if tag > 0 {
            let mut t = [0u8; PEER_TAG_LEN];
            if n > tag {
                t.copy_from_slice(&s.pool[at..at + PEER_TAG_LEN]);
                mask = route(s, &t, targets);
            } else {
                mask = 0;
            }
            if mask == 0 {
                unrouted(s, i, 0, 0);
                s.chans[i].tx_state = TX_IDLE;
                return;
            }
        }
        let stage = s.chans[i].tx_stage as usize;
        if is_x(s, i) && !x_outbound(s, stage, n - tag) {
            s.x_discarded = s.x_discarded.wrapping_add(1);
            return;
        }
        begin_staged(s, i, (n - tag) as u64, mask);
        return;
    }
    if !read_head(s, i) {
        return;
    }
    let Some(len) = head_len(s, i) else {
        return;
    };
    let hl = s.chans[i].entry.header_len();
    let mask = if tag > 0 {
        let t = s.chans[i].tag;
        route(s, &t, targets)
    } else {
        targets
    };
    if mask == 0 {
        unrouted(s, i, len, hl as u64);
        return;
    }
    let c = &mut s.chans[i];
    let stage = c.tx_stage as usize;
    let hdr = c.tx_hdr;
    s.pool[stage..stage + hl].copy_from_slice(&hdr[..hl]);
    let c = &mut s.chans[i];
    c.tx_len = len;
    c.tx_read = hl as u64;
    c.tx_mask = mask;
    c.tx_state = TX_FILL;
    fill(s, i);
}

/// Read the rest of channel `i`'s record into its stage; it goes once
/// whole.
unsafe fn fill(s: &mut State, i: usize) {
    let sys = &*s.syscalls;
    let c = &mut s.chans[i];
    while c.tx_read < c.tx_len {
        let at = c.tx_stage as usize + c.tx_read as usize;
        let n = (sys.channel_read)(
            c.input,
            s.pool.as_mut_ptr().add(at),
            (c.tx_len - c.tx_read) as usize,
        );
        if n <= 0 {
            return;
        }
        c.tx_read += n as u64;
    }
    let (len, mask) = (c.tx_len, c.tx_mask);
    c.tx_state = TX_IDLE;
    if mask != 0 {
        begin_staged(s, i, len, mask);
    } else {
        c.tag_have = 0;
        c.tx_hdr_have = 0;
    }
}

/// Channel `i`'s staged record of `len` bytes goes to the peers of `mask`.
fn begin_staged(s: &mut State, i: usize, len: u64, mask: u8) {
    let c = &mut s.chans[i];
    c.tx_len = len;
    c.tx_mask = mask;
    c.tx_state = TX_BODY;
    c.tag_have = 0;
    c.tx_hdr_have = 0;
    for p in 0..s.n_peers as usize {
        s.peers[p].chans[i].tx_sent = 0;
    }
}

/// Put out the next fragment of channel `i`'s staged record to peer `p`.
/// True when a frame was written.
unsafe fn send_staged_fragment(s: &mut State, p: usize, i: usize) -> bool {
    let l = s.peers[p].link as usize;
    let fmax = frag_max(s);
    let c = &s.chans[i];
    let pc = &s.peers[p].chans[i];
    let len = c.tx_len as u32;
    let sent = pc.tx_sent;
    let begin = sent == 0;
    let charge = if begin { RECORD_CHARGE } else { 0 };
    if pc.tx_credit <= charge {
        return false;
    }
    let room = pc.tx_credit - charge;
    let want = (len - sent).min(room).min(fmax as u32) as usize;
    let (kind, prefix) = if begin {
        (wire::KIND_BEGIN, BEGIN_PREFIX)
    } else {
        (wire::KIND_MORE, 0)
    };
    let body_at = TX_PREFIX + FRAME_HDR + prefix;
    let src = c.tx_stage as usize + sent as usize;
    s.tx[body_at..body_at + want].copy_from_slice(&s.pool[src..src + want]);
    if begin {
        s.tx[TX_PREFIX + FRAME_HDR..TX_PREFIX + FRAME_HDR + 4].copy_from_slice(&len.to_le_bytes());
    }
    wire::header(kind, i as u8, prefix + want, &mut s.tx[TX_PREFIX..]);
    let pc = &mut s.peers[p].chans[i];
    pc.tx_credit -= charge + want as u32;
    pc.tx_sent += want as u32;
    if pc.tx_sent == len {
        pc.tx_sent = 0;
        let c = &mut s.chans[i];
        c.tx_mask &= !(1u8 << p);
        if c.tx_mask == 0 {
            c.tx_state = TX_IDLE;
            c.records_sent = c.records_sent.wrapping_add(1);
        }
    }
    send_staged(s, l, Some(i), FRAME_HDR + prefix + want);
    true
}

/// Far: put out the record of the module's own owed to peer `p` on the
/// answer channel, whole in one frame. True when a frame was written.
unsafe fn send_own(s: &mut State, p: usize) -> bool {
    let l = s.peers[p].link as usize;
    let r = x_resp(s);
    let n = s.peers[p].own_len as u32;
    if s.peers[p].chans[r].tx_credit < RECORD_CHARGE + n {
        return false;
    }
    let body_at = TX_PREFIX + FRAME_HDR + BEGIN_PREFIX;
    let own = s.peers[p].own;
    s.tx[body_at..body_at + n as usize].copy_from_slice(&own[..n as usize]);
    s.tx[TX_PREFIX + FRAME_HDR..TX_PREFIX + FRAME_HDR + 4].copy_from_slice(&n.to_le_bytes());
    wire::header(
        wire::KIND_BEGIN,
        r as u8,
        BEGIN_PREFIX + n as usize,
        &mut s.tx[TX_PREFIX..],
    );
    s.peers[p].chans[r].tx_credit -= RECORD_CHARGE + n;
    s.peers[p].own_len = 0;
    send_staged(s, l, Some(r), FRAME_HDR + BEGIN_PREFIX + n as usize);
    true
}

/// One session, unstaged: advance channel `i`'s record straight from its
/// input to peer slot 0 — start a record, or put out its next fragment.
/// True when a frame was written.
unsafe fn send_streamed(s: &mut State, i: usize) -> bool {
    let sys = &*s.syscalls;
    let l = s.peers[0].link as usize;
    let fmax = frag_max(s);
    if s.chans[i].input < 0 {
        return false;
    }
    if s.chans[i].tx_state == TX_DISCARD && !discard_rest(s, i) {
        return false;
    }
    if s.chans[i].tx_state == TX_IDLE {
        if s.chans[i].entry.framing == wire::framing::BYTES {
            // A stream has no records: whatever is there, up to one
            // frame and the credit left, goes as one piece.
            let credit = s.peers[0].chans[i].tx_credit;
            if credit <= RECORD_CHARGE {
                return false;
            }
            let c = &s.chans[i];
            let room = ((credit - RECORD_CHARGE) as usize)
                .min(c.entry.max_record as usize)
                .min(fmax);
            let body_at = TX_PREFIX + FRAME_HDR + BEGIN_PREFIX;
            let n = (sys.channel_read)(c.input, s.tx.as_mut_ptr().add(body_at), room);
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
            s.peers[0].chans[i].tx_credit -= RECORD_CHARGE + n as u32;
            s.chans[i].records_sent = s.chans[i].records_sent.wrapping_add(1);
            send_staged(s, l, Some(i), FRAME_HDR + BEGIN_PREFIX + n);
            return true;
        }
        if !read_head(s, i) {
            return false;
        }
        let Some(len) = head_len(s, i) else {
            return false;
        };
        let hl = s.chans[i].entry.header_len() as u64;
        if tag_len(s, i) > 0 {
            let t = s.chans[i].tag;
            if route(s, &t, 1) == 0 {
                unrouted(s, i, len, hl);
                return false;
            }
        }
        let c = &mut s.chans[i];
        c.tx_len = len;
        c.tx_read = hl;
        c.tx_state = TX_BODY;
        s.peers[0].chans[i].tx_sent = 0;
    }
    let c = &s.chans[i];
    let pc = &s.peers[0].chans[i];
    let sent = pc.tx_sent as u64;
    let begin = sent == 0;
    let charge = if begin { RECORD_CHARGE } else { 0 };
    if pc.tx_credit <= charge {
        return false;
    }
    let room = (pc.tx_credit - charge) as u64;
    let want = (c.tx_len - sent).min(room).min(fmax as u64) as usize;
    let body_at = TX_PREFIX + FRAME_HDR + if begin { BEGIN_PREFIX } else { 0 };
    let hl = c.entry.header_len() as u64;
    let mut got = 0usize;
    while got < want && sent + (got as u64) < hl {
        s.tx[body_at + got] = c.tx_hdr[(sent as usize) + got];
        got += 1;
    }
    if got < want {
        let n = (sys.channel_read)(c.input, s.tx.as_mut_ptr().add(body_at + got), want - got);
        if n > 0 {
            got += n as usize;
            s.chans[i].tx_read += n as u64;
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
    let c = &mut s.chans[i];
    if begin {
        let rl = (c.tx_len as u32).to_le_bytes();
        s.tx[TX_PREFIX + FRAME_HDR..TX_PREFIX + FRAME_HDR + 4].copy_from_slice(&rl);
    }
    wire::header(kind, i as u8, prefix + got, &mut s.tx[TX_PREFIX..]);
    let pc = &mut s.peers[0].chans[i];
    pc.tx_credit -= charge + got as u32;
    pc.tx_sent += got as u32;
    if pc.tx_sent as u64 == c.tx_len {
        pc.tx_sent = 0;
        c.tx_state = TX_IDLE;
        c.tag_have = 0;
        c.tx_hdr_have = 0;
        c.records_sent = c.records_sent.wrapping_add(1);
    }
    // The bytes are off the local input now; a refused write stays staged
    // and goes first next step.
    send_staged(s, l, Some(i), FRAME_HDR + prefix + got);
    true
}

/// Advance channel `i`'s sends: take records off its input, and put out a
/// fragment to each session owed one. Frames written.
unsafe fn send_channel(s: &mut State, i: usize) -> usize {
    if s.table.resume {
        ingest(s, i);
        return send_retained_all(s, i);
    }
    let side = s.table.side;
    let far_resp = side == wire::side::FAR && is_x(s, i) && i == x_resp(s);
    if !s.chans[i].staged {
        // One session, records streamed.
        if peer_open(s, 0) && send_streamed(s, i) {
            return 1;
        }
        return 0;
    }
    if !far_resp {
        let targets = if is_x(s, i) {
            if x_may_send(s, i) {
                open_mask(s) & 1
            } else {
                0
            }
        } else {
            open_mask(s)
        };
        take(s, i, targets);
    }
    let peers = s.n_peers as usize;
    let mut frames = 0;
    for k in 0..peers {
        let p = ring_next(s.prr as usize + k, peers);
        if !peer_open(s, p) {
            continue;
        }
        if s.tx_len != 0 && !flush_tx(s) {
            break;
        }
        let bit = 1u8 << p;
        let pending = s.chans[i].tx_mask & bit != 0 && s.chans[i].tx_state == TX_BODY;
        if far_resp && s.peers[p].own_len > 0 && (!pending || s.peers[p].chans[i].tx_sent == 0) {
            // A record of the module's own goes ahead of the provider's.
            if send_own(s, p) {
                frames += 1;
            }
            continue;
        }
        if pending && send_staged_fragment(s, p, i) {
            frames += 1;
        }
    }
    frames
}

/// `resume`: free bytes in the retained window of every peer in `mask`, the
/// least of them.
fn window_room(s: &State, i: usize, mask: u8) -> u32 {
    let mut room = u32::MAX;
    for p in 0..s.n_peers as usize {
        if mask & (1 << p) != 0 {
            let pc = &s.peers[p].chans[i];
            room = room.min(pc.rt_cap - pc.rt_used);
        }
    }
    room
}

/// `resume`: the peers a record taken now is retained for: the one peer of
/// a single-session instance, or every peer whose streams are held.
fn resume_targets(s: &State) -> u8 {
    if s.n_peers == 1 {
        1
    } else {
        held_mask(s)
    }
}

/// `resume`: append `bytes` at `at` past the tail of the window of every
/// peer in `mask` on channel `i`.
fn window_put(s: &mut State, i: usize, mask: u8, at: u32, bytes_at: usize, n: usize) {
    for p in 0..s.n_peers as usize {
        if mask & (1 << p) == 0 {
            continue;
        }
        let pc = &s.peers[p].chans[i];
        let (off, cap, tail) = (pc.rt_off, pc.rt_cap, pc.rt_head + pc.rt_used);
        let mut pos = wrap(tail + at, cap);
        for k in 0..n {
            s.pool[(off + pos) as usize] = s.pool[bytes_at + k];
            pos += 1;
            if pos == cap {
                pos = 0;
            }
        }
    }
}

/// `resume`: a record of `len` bytes is whole in the windows of `mask`.
fn window_commit(s: &mut State, i: usize, mask: u8, len: u32) {
    for p in 0..s.n_peers as usize {
        if mask & (1 << p) != 0 {
            let pc = &mut s.peers[p].chans[i];
            pc.rt_used += RECORD_CHARGE + len;
            pc.rt_count += 1;
        }
    }
}

/// `resume`: take records off channel `i`'s input into the retained window
/// of every peer it goes to, while every one of them has room. A record is
/// numbered when it is whole in a window; it leaves one only when that peer
/// acknowledges it.
unsafe fn ingest(s: &mut State, i: usize) {
    let sys = &*s.syscalls;
    if s.chans[i].input < 0 {
        return;
    }
    let tag = tag_len(s, i);
    // Scratch for a record's bytes on their way into the windows: past the
    // first, the mailbox stage serves.
    let mut scratch = [0u8; 1024];
    for _ in 0..INGEST_PER_STEP {
        if s.chans[i].tx_state == TX_DISCARD && !discard_rest(s, i) {
            return;
        }
        let targets = resume_targets(s);
        if targets == 0 {
            return;
        }
        let c = &s.chans[i];
        let (max, input) = (c.entry.max_record, c.input);
        match c.entry.framing {
            wire::framing::BYTES => {
                // One session only (construction refuses more).
                let free = window_room(s, i, 1);
                if free <= RECORD_CHARGE {
                    return;
                }
                let room = ((free - RECORD_CHARGE) as usize)
                    .min(max as usize)
                    .min(scratch.len());
                let n = (sys.channel_read)(input, scratch.as_mut_ptr(), room);
                if n <= 0 {
                    return;
                }
                let n = n as u32;
                let pc = &s.peers[0].chans[i];
                let (off, cap, tail) = (pc.rt_off, pc.rt_cap, pc.rt_head + pc.rt_used);
                ring_put(&mut s.pool, off, cap, tail, &n.to_le_bytes());
                ring_put(
                    &mut s.pool,
                    off,
                    cap,
                    tail + RECORD_CHARGE,
                    &scratch[..n as usize],
                );
                window_commit(s, i, 1, n);
            }
            wire::framing::MAILBOX => {
                if window_room(s, i, targets) < RECORD_CHARGE + max {
                    return;
                }
                let at = c.tx_stage as usize - tag;
                let n = (sys.channel_read)(input, s.pool.as_mut_ptr().add(at), tag + max as usize);
                if n == errno::EINVAL {
                    dev_channel_ioctl(sys, input, IOCTL_FLUSH, core::ptr::null_mut(), 0);
                    s.chans[i].refused_oversize = s.chans[i].refused_oversize.wrapping_add(1);
                    log(
                        s,
                        1,
                        b"[remote_channel] record over the channel maximum refused",
                    );
                    return;
                }
                if n <= 0 {
                    return;
                }
                let n = n as usize;
                let mask = if tag > 0 {
                    let mut t = [0u8; PEER_TAG_LEN];
                    if n > tag {
                        t.copy_from_slice(&s.pool[at..at + PEER_TAG_LEN]);
                        route(s, &t, targets)
                    } else {
                        0
                    }
                } else {
                    targets
                };
                if mask == 0 {
                    unrouted(s, i, 0, 0);
                    s.chans[i].tx_state = TX_IDLE;
                    continue;
                }
                let len = (n - tag) as u32;
                let lb = len.to_le_bytes();
                scratch[..4].copy_from_slice(&lb);
                // The length first, then the record from its stage.
                for p in 0..s.n_peers as usize {
                    if mask & (1 << p) != 0 {
                        let pc = &s.peers[p].chans[i];
                        let (off, cap, tail) = (pc.rt_off, pc.rt_cap, pc.rt_head + pc.rt_used);
                        ring_put(&mut s.pool, off, cap, tail, &lb);
                    }
                }
                window_put(s, i, mask, RECORD_CHARGE, at + tag, len as usize);
                window_commit(s, i, mask, len);
            }
            _ => {
                if !s.chans[i].in_active {
                    if !read_head(s, i) {
                        return;
                    }
                    let Some(len) = head_len(s, i) else {
                        return;
                    };
                    let hl = s.chans[i].entry.header_len();
                    let mask = if tag > 0 {
                        let t = s.chans[i].tag;
                        route(s, &t, targets)
                    } else {
                        targets
                    };
                    if mask == 0 {
                        unrouted(s, i, len, hl as u64);
                        continue;
                    }
                    if (window_room(s, i, mask) as u64) < RECORD_CHARGE as u64 + len {
                        // Held, prefix, header and all, until every peer it
                        // goes to has released room.
                        return;
                    }
                    let len = len as u32;
                    let hdr = s.chans[i].tx_hdr;
                    for p in 0..s.n_peers as usize {
                        if mask & (1 << p) != 0 {
                            let pc = &s.peers[p].chans[i];
                            let (off, cap, tail) = (pc.rt_off, pc.rt_cap, pc.rt_head + pc.rt_used);
                            ring_put(&mut s.pool, off, cap, tail, &len.to_le_bytes());
                            ring_put(&mut s.pool, off, cap, tail + RECORD_CHARGE, &hdr[..hl]);
                        }
                    }
                    let c = &mut s.chans[i];
                    c.in_active = true;
                    c.in_len = len;
                    c.in_have = hl as u32;
                    c.in_mask = mask;
                }
                while s.chans[i].in_have < s.chans[i].in_len {
                    let c = &s.chans[i];
                    let (have, len, mask) = (c.in_have, c.in_len, c.in_mask);
                    let want = ((len - have) as usize).min(scratch.len());
                    let n = (sys.channel_read)(input, scratch.as_mut_ptr(), want);
                    if n <= 0 {
                        return;
                    }
                    let n = n as usize;
                    for p in 0..s.n_peers as usize {
                        if mask & (1 << p) != 0 {
                            let pc = &s.peers[p].chans[i];
                            let (off, cap, tail) = (pc.rt_off, pc.rt_cap, pc.rt_head + pc.rt_used);
                            ring_put(
                                &mut s.pool,
                                off,
                                cap,
                                tail + RECORD_CHARGE + have,
                                &scratch[..n],
                            );
                        }
                    }
                    s.chans[i].in_have += n as u32;
                }
                let c = &mut s.chans[i];
                let (len, mask) = (c.in_len, c.in_mask);
                c.in_active = false;
                c.tag_have = 0;
                c.tx_hdr_have = 0;
                window_commit(s, i, mask, len);
            }
        }
    }
}

/// `resume`: put out the next fragment of channel `i`'s records retained
/// for peer `p`, from the one its session has reached. True when a frame
/// was written.
unsafe fn send_retained(s: &mut State, p: usize, i: usize) -> bool {
    let l = s.peers[p].link as usize;
    let pc = &s.peers[p].chans[i];
    if pc.cur_seq >= pc.rt_base + pc.rt_count as u64 {
        return false;
    }
    let pos = pc.rt_head + pc.cur_at;
    let mut lb = [0u8; 4];
    ring_get(&s.pool, pc.rt_off, pc.rt_cap, pos, &mut lb);
    let len = u32::from_le_bytes(lb);
    let begin = pc.cur_sent == 0;
    let charge = if begin { RECORD_CHARGE } else { 0 };
    if pc.tx_credit <= charge {
        return false;
    }
    let room = pc.tx_credit - charge;
    let (prefix, kind) = if begin {
        (RBEGIN_PREFIX, wire::KIND_RBEGIN)
    } else {
        (0, wire::KIND_MORE)
    };
    // On `mux` the whole frame is one `CMD_MUX_STREAM_SEND`, so the record
    // bytes are what is left of it beside the header and this frame's prefix
    // (`RBEGIN`'s is longer than `BEGIN`'s).
    let fmax = if s.transport == TRANSPORT_NET {
        FRAGMENT_MAX
    } else {
        MUX_FRAGMENT_MAX + BEGIN_PREFIX - prefix
    };
    let want = (len - pc.cur_sent).min(room).min(fmax as u32) as usize;
    let body_at = TX_PREFIX + FRAME_HDR + prefix;
    let (off, cap) = (pc.rt_off, pc.rt_cap);
    let from = pos + RECORD_CHARGE + pc.cur_sent;
    let seq = pc.cur_seq;
    ring_get(&s.pool, off, cap, from, &mut s.tx[body_at..body_at + want]);
    if begin {
        let at = TX_PREFIX + FRAME_HDR;
        s.tx[at..at + 4].copy_from_slice(&len.to_le_bytes());
        s.tx[at + 4..at + 12].copy_from_slice(&seq.to_le_bytes());
    }
    wire::header(kind, i as u8, prefix + want, &mut s.tx[TX_PREFIX..]);
    let pc = &mut s.peers[p].chans[i];
    pc.tx_credit -= charge + want as u32;
    pc.cur_sent += want as u32;
    if pc.cur_sent == len {
        let c = &mut s.chans[i];
        if pc.cur_seq <= pc.sent_high {
            c.resent = c.resent.wrapping_add(1);
        } else {
            pc.sent_high = pc.cur_seq;
            c.records_sent = c.records_sent.wrapping_add(1);
        }
        pc.sent_through = pc.cur_seq;
        pc.cur_seq += 1;
        pc.cur_at += RECORD_CHARGE + len;
        pc.cur_sent = 0;
    }
    send_staged(s, l, Some(i), FRAME_HDR + prefix + want);
    true
}

/// `resume`: a fragment of channel `i` to each open session that has one
/// to send. Frames written.
unsafe fn send_retained_all(s: &mut State, i: usize) -> usize {
    let peers = s.n_peers as usize;
    let mut frames = 0;
    for k in 0..peers {
        let p = ring_next(s.prr as usize + k, peers);
        if !peer_open(s, p) {
            continue;
        }
        if s.tx_len != 0 && !flush_tx(s) {
            break;
        }
        if send_retained(s, p, i) {
            frames += 1;
        }
    }
    frames
}

unsafe fn send_records(s: &mut State) {
    if open_mask(s) == 0 {
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
        let n = send_channel(s, i);
        if n > 0 {
            frames += n;
            idle_rounds = 0;
        } else {
            idle_rounds += 1;
        }
    }
    s.prr = if (s.prr as usize) + 1 < s.n_peers as usize {
        s.prr + 1
    } else {
        0
    };
}

// ── Exchange endpoint ───────────────────────────────────────────────────────

/// Whether the near side's request channel may take a record to send now:
/// once the far side has opened the session's answer channel.
fn x_may_send(s: &State, i: usize) -> bool {
    s.table.side == wire::side::NEAR && i == x_req(s) && s.near_state == NS_FORWARD
}

/// The open exchange peer `p`'s requester calls `theirs`.
fn open_by_theirs(s: &State, p: usize, theirs: &xc::ExchangeId) -> Option<usize> {
    s.open[..s.n_open as usize]
        .iter()
        .position(|o| o.peer == p as u8 && !o.aborting && o.theirs == *theirs)
}

/// The open exchange the provider calls `local`.
fn open_by_local(s: &State, local: &xc::ExchangeId) -> Option<usize> {
    s.open[..s.n_open as usize]
        .iter()
        .position(|o| o.local == *local)
}

fn close_open(s: &mut State, k: usize) {
    // An element at a time: `copy_within`'s bounds panic would carry a
    // pointer table into a module that is loaded without relocation.
    let n = s.n_open as usize;
    for j in k..n - 1 {
        s.open[j] = s.open[j + 1];
    }
    s.n_open -= 1;
}

/// Far: the module's own answer to peer `p`'s exchange `id`, raised.
fn far_refuse(s: &mut State, p: usize, id: &xc::ExchangeId, status: u16) {
    let mut own = [0u8; OWN_RECORD_LEN];
    let n = xc::write_refusal(id, status, &mut own).unwrap_or(0);
    s.peers[p].own = own;
    s.peers[p].own_len = n as u8;
    s.x_refused = s.x_refused.wrapping_add(1);
}

/// A record whole on an exchange channel's ring from peer `p`, laid out at
/// `stage`, before delivery: on the near side an answer, on the far side a
/// request — rewritten there to the provider's id and, on a HEAD, to the
/// session's verified `peer`. The verdict, and the length to deliver.
unsafe fn x_inbound(s: &mut State, p: usize, stage: usize, len: usize) -> (u8, usize) {
    let rec = &s.pool[stage..stage + len];
    let kind = xc::record_kind(rec);
    let id = xc::record_id(rec);
    if s.table.side == wire::side::NEAR {
        // A LINK owed goes before any answer that arrived after it.
        if s.link_owed != 0 && !near_flush_link(s) {
            return (X_STALL, len);
        }
        if kind == Some(xc::kind::LINK) {
            if len == xc::HDR + 1 {
                s.prov_up = s.pool[stage + xc::HDR] == xc::link::UP;
                if !s.far_ready {
                    // The far side's opening record: this is the provider's
                    // link.
                    s.far_ready = true;
                } else if s.near_state == NS_FORWARD {
                    near_retell(s);
                }
            }
            return (X_CONSUME, len);
        }
        return (X_DELIVER, len);
    }
    // The ABORTs an ended session owes the provider go first, and nothing
    // of a session is handed over before its answer channel is open.
    if s.open[..s.n_open as usize].iter().any(|o| o.aborting)
        || !s.peers[p].far_announced
        || s.peers[p].own_len != 0
    {
        return (X_STALL, len);
    }
    let (Some(kind), Some(id)) = (kind, id) else {
        s.x_discarded = s.x_discarded.wrapping_add(1);
        return (X_CONSUME, len);
    };
    if let Some(k) = open_by_theirs(s, p, &id) {
        let local = s.open[k].local;
        s.pool[stage + 2..stage + xc::HDR].copy_from_slice(&local.0);
        return (X_DELIVER, len);
    }
    if kind != xc::kind::HEAD {
        // For an exchange the provider has ended or never saw.
        s.x_discarded = s.x_discarded.wrapping_add(1);
        return (X_CONSUME, len);
    }
    if s.n_open as usize == OPEN_EXCHANGES_MAX {
        far_refuse(s, p, &id, xc::status::BUSY);
        return (X_CONSUME, len);
    }
    // The HEAD's `peer` is the session's verified fingerprint, whatever the
    // requester wrote: the provider authorises on it.
    let (peer_at, peer_len) = match xc::parse_request(&s.pool[stage..stage + len]) {
        Some(xc::Record::Head(h)) => (
            xc::HDR + xc::REQ_HEAD_FIXED + h.target.len() + h.headers.len(),
            h.peer.len(),
        ),
        _ => {
            far_refuse(s, p, &id, xc::status::BAD_REQUEST);
            return (X_CONSUME, len);
        }
    };
    let fp_len = if s.require_peer != 0 {
        s.peers[p].fp_len as usize
    } else {
        0
    };
    let out_len = len - peer_len + fp_len;
    if out_len > xc::RECORD_MAX {
        far_refuse(s, p, &id, xc::status::TOO_LARGE);
        return (X_CONSUME, len);
    }
    // The body moves to follow the new `peer`: from its end when it moves
    // up, from its start when it moves down.
    let (from, to, n) = (
        stage + peer_at + peer_len,
        stage + peer_at + fp_len,
        len - peer_at - peer_len,
    );
    if to > from {
        for j in (0..n).rev() {
            s.pool[to + j] = s.pool[from + j];
        }
    } else {
        for j in 0..n {
            s.pool[to + j] = s.pool[from + j];
        }
    }
    let fp = s.peers[p].fp;
    s.pool[stage + peer_at..stage + peer_at + fp_len].copy_from_slice(&fp[..fp_len]);
    let pl = (fp_len as u16).to_le_bytes();
    s.pool[stage + xc::HDR + 5..stage + xc::HDR + 7].copy_from_slice(&pl);
    let local = xc::ExchangeId::from_u64(s.next_local);
    s.pool[stage + 2..stage + xc::HDR].copy_from_slice(&local.0);
    (X_DELIVER, out_len)
}

/// A request the far side handed the provider for peer `p`, as delivered
/// (under the provider's id).
fn x_delivered(s: &mut State, p: usize, stage: usize, len: usize) {
    if s.table.side != wire::side::FAR {
        return;
    }
    let rec = &s.pool[stage..stage + len];
    let (Some(kind), Some(local)) = (xc::record_kind(rec), xc::record_id(rec)) else {
        return;
    };
    match (kind, open_by_local(s, &local)) {
        (xc::kind::HEAD, None) => {
            // Its requester's id, read back from the ring's copy.
            let pc = &s.peers[p].chans[x_req(s)];
            let mut theirs = xc::ExchangeId::NONE;
            ring_get(
                &s.pool,
                pc.ring_off,
                pc.ring_cap,
                pc.ring_head + RECORD_CHARGE + 2,
                &mut theirs.0,
            );
            let n = s.n_open as usize;
            if n < OPEN_EXCHANGES_MAX {
                s.open[n] = XOpen {
                    peer: p as u8,
                    aborting: false,
                    theirs,
                    local,
                };
                s.n_open += 1;
            }
            s.next_local = s.next_local.wrapping_add(1);
        }
        (xc::kind::ABORT, Some(k)) => close_open(s, k),
        _ => {}
    }
}

/// A record the far side took from the provider (at `stage`): the peers it
/// goes to, rewritten to the requester's id; 0 when it goes nowhere. A LINK
/// goes to every session whose answer channel is open; any other record to
/// the session of the exchange it names, while that exchange is open.
fn far_outbound(s: &mut State, stage: usize, len: usize) -> u8 {
    let rec = &s.pool[stage..stage + len];
    let (Some(kind), Some(local)) = (xc::record_kind(rec), xc::record_id(rec)) else {
        return 0;
    };
    if kind == xc::kind::LINK {
        if len != xc::HDR + 1 {
            return 0;
        }
        far_link(s, s.pool[stage + xc::HDR]);
        let mut m = 0;
        for p in 0..s.n_peers as usize {
            if peer_open(s, p) && s.peers[p].far_announced {
                m |= 1 << p;
            }
        }
        return m;
    }
    let Some(k) = open_by_local(s, &local) else {
        return 0;
    };
    let o = s.open[k];
    if o.aborting {
        return 0;
    }
    s.pool[stage + 2..stage + xc::HDR].copy_from_slice(&o.theirs.0);
    if xc::ends_direction(&s.pool[stage..stage + len]) {
        close_open(s, k);
    }
    let p = o.peer as usize;
    if peer_open(s, p) && s.peers[p].far_announced {
        1 << p
    } else {
        0
    }
}

/// A record the near side took from the requester: whether it crosses.
fn x_outbound(s: &mut State, _stage: usize, _len: usize) -> bool {
    s.table.side == wire::side::NEAR
}

/// The provider reported its link. Down, every exchange it held is
/// unknowable and each requester issues it again after up: none is open.
fn far_link(s: &mut State, state: u8) {
    s.prov_up = state == xc::link::UP;
    if !s.prov_up {
        s.n_open = 0;
    }
}

/// Far: take the provider's next record while none is held — its LINK
/// kept, any other routed to the session of its exchange or dropped.
unsafe fn far_take(s: &mut State) {
    let sys = &*s.syscalls;
    let r = x_resp(s);
    for _ in 0..FRAMES_PER_STEP {
        let c = &s.chans[r];
        if c.tx_state != TX_IDLE {
            return;
        }
        let (input, stage, max) = (c.input, c.tx_stage as usize, c.entry.max_record as usize);
        let n = (sys.channel_read)(input, s.pool.as_mut_ptr().add(stage), max);
        if n == errno::EINVAL {
            dev_channel_ioctl(sys, input, IOCTL_FLUSH, core::ptr::null_mut(), 0);
            s.x_discarded = s.x_discarded.wrapping_add(1);
            continue;
        }
        if n <= 0 {
            return;
        }
        let n = n as usize;
        let link = xc::record_kind(&s.pool[stage..stage + n]) == Some(xc::kind::LINK);
        let mask = far_outbound(s, stage, n);
        if mask == 0 {
            if !link {
                s.x_discarded = s.x_discarded.wrapping_add(1);
            }
            continue;
        }
        begin_staged(s, r, n as u64, mask);
    }
}

/// The far side, each step: ABORT to the provider what ended sessions left
/// open, take its answers, and open each new session's answer channel with
/// the provider's link.
unsafe fn far_step(s: &mut State) {
    if s.table.side != wire::side::FAR {
        return;
    }
    let sys = &*s.syscalls;
    let out = s.chans[x_req(s)].output;
    let mut k = 0;
    while k < s.n_open as usize {
        if !s.open[k].aborting {
            k += 1;
            continue;
        }
        let mut rec = [0u8; xc::HDR + 1];
        let n = xc::write_abort(&s.open[k].local, xc::abort::PEER_GONE, &mut rec).unwrap_or(0);
        if (sys.channel_write)(out, rec.as_ptr(), n) != n as i32 {
            break;
        }
        s.x_aborted = s.x_aborted.wrapping_add(1);
        close_open(s, k);
    }
    far_take(s);
    for p in 0..s.n_peers as usize {
        let e = &s.peers[p];
        if peer_open(s, p) && !e.far_announced && e.own_len == 0 {
            let state = if s.prov_up {
                xc::link::UP
            } else {
                xc::link::DOWN
            };
            let mut own = [0u8; OWN_RECORD_LEN];
            let n = xc::write_link(state, &mut own).unwrap_or(0);
            let e = &mut s.peers[p];
            e.own = own;
            e.own_len = n as u8;
            e.far_announced = true;
        }
    }
}

/// Write the LINK state owed to the requester. True when none is owed.
unsafe fn near_flush_link(s: &mut State) -> bool {
    if s.link_owed == 0 {
        return true;
    }
    let sys = &*s.syscalls;
    let out = s.chans[x_resp(s)].output;
    let mut rec = [0u8; xc::HDR + 1];
    let n = xc::write_link(s.link_owed, &mut rec).unwrap_or(0);
    if (sys.channel_write)(out, rec.as_ptr(), n) == n as i32 {
        s.link_owed = 0;
    }
    s.link_owed == 0
}

/// Tell the requester the provider's link, when it differs from what the
/// requester last heard. Called with nothing owed.
unsafe fn near_retell(s: &mut State) {
    if s.prov_up != s.told_up {
        s.told_up = s.prov_up;
        s.link_owed = if s.prov_up {
            xc::link::UP
        } else {
            xc::link::DOWN
        };
        near_flush_link(s);
    }
}

/// Discard what the requester wrote: records of exchanges a lost session
/// made unknowable, which it issues again after LINK UP.
unsafe fn near_discard(s: &mut State) {
    let sys = &*s.syscalls;
    let q = x_req(s);
    let (input, stage, max) = (
        s.chans[q].input,
        s.chans[q].tx_stage as usize,
        s.chans[q].entry.max_record as usize,
    );
    for _ in 0..FRAMES_PER_STEP {
        let n = (sys.channel_read)(input, s.pool.as_mut_ptr().add(stage), max);
        if n == errno::EINVAL {
            dev_channel_ioctl(sys, input, IOCTL_FLUSH, core::ptr::null_mut(), 0);
        } else if n <= 0 {
            return;
        }
        s.x_discarded = s.x_discarded.wrapping_add(1);
    }
}

/// The near side, each step after delivery: tell the requester a lost
/// session, purge what it wrote before it knew, and resume once the far
/// side opens the next session's answer channel.
unsafe fn near_step(s: &mut State) {
    if s.table.side != wire::side::NEAR {
        return;
    }
    let sys = &*s.syscalls;
    if !near_flush_link(s) {
        return;
    }
    match s.near_state {
        NS_PURGE => {
            near_discard(s);
            if complete_bytes(s, 0, x_resp(s)) != 0 {
                // Answers that arrived whole go to the requester first.
                return;
            }
            if s.told_up {
                s.told_up = false;
                s.link_owed = xc::link::DOWN;
                near_flush_link(s);
                return;
            }
            // Once the requester has taken the DOWN, everything it wrote
            // before it knew is on `request_in`.
            let out = s.chans[x_resp(s)].output;
            if (sys.channel_poll)(out, POLL_OUT) & POLL_OUT as i32 != 0 {
                near_discard(s);
                s.near_state = NS_WAIT;
            }
        }
        NS_WAIT => near_discard(s),
        _ => {}
    }
    if (s.near_state == NS_HOLD || s.near_state == NS_WAIT) && peer_open(s, 0) && s.far_ready {
        s.near_state = NS_FORWARD;
        near_retell(s);
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

/// Bind the exchange endpoint's ports for this instance's side. The side's
/// own pair must be wired and the other side's must not: an edge to a port
/// the instance does not serve would carry nothing, silently.
unsafe fn wire_exchange(s: &mut State) -> bool {
    let sys = &*s.syscalls;
    let req_in = dev_channel_port(sys, 0, PORT_REQUEST_IN);
    let resp_in = dev_channel_port(sys, 0, PORT_RESPONSE_IN);
    let resp_out = dev_channel_port(sys, 1, PORT_RESPONSE_OUT);
    let req_out = dev_channel_port(sys, 1, PORT_REQUEST_OUT);
    let (own, other) = match s.table.side {
        wire::side::NEAR => ((req_in, resp_out), (resp_in, req_out)),
        wire::side::FAR => ((resp_in, req_out), (req_in, resp_out)),
        _ => {
            if req_in >= 0 || resp_in >= 0 || resp_out >= 0 || req_out >= 0 {
                log(s, 1, b"[remote_channel] refusing to construct: exchange ports are wired and `exchange` is none");
                return false;
            }
            return true;
        }
    };
    if own.0 < 0 || own.1 < 0 {
        log(s, 1, b"[remote_channel] refusing to construct: the exchange side's own port pair is not wired");
        return false;
    }
    if other.0 >= 0 || other.1 >= 0 {
        log(
            s,
            1,
            b"[remote_channel] refusing to construct: the other exchange side's ports are wired",
        );
        return false;
    }
    let (q, r) = (x_req(s), x_resp(s));
    if s.table.side == wire::side::NEAR {
        s.chans[q].input = req_in;
        s.chans[q].output = -1;
        s.chans[r].input = -1;
        s.chans[r].output = resp_out;
    } else {
        s.chans[q].input = -1;
        s.chans[q].output = req_out;
        s.chans[r].input = resp_in;
        s.chans[r].output = -1;
    }
    // A requester never told anything treats its provider as up.
    s.told_up = true;
    s.prov_up = true;
    true
}

/// Refuse to construct, saying why.
unsafe fn refuse_construct(s: &State, why: &[u8]) -> i32 {
    log(s, 1, why);
    -22
}

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
    s.keepalive_ms = 1000;
    s.n_peers = 1;
    s.next_local = 1;
    s.tx_link = NO_LINK;
    s.my_tag = dev_requester_tag(sys);
    for lk in s.links.iter_mut() {
        lk.conn = NO_CONN;
        lk.peer = NO_PEER;
        lk.parser = Parser::new();
    }
    for e in s.peers.iter_mut() {
        e.link = NO_LINK;
    }
    for c in s.chans.iter_mut() {
        c.deliver_peer = NO_PEER;
    }
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    if s.table_text_overflow {
        return refuse_construct(s, b"[remote_channel] refusing to construct: `channels` is longer than its parameter allows");
    }
    let side = s.table.side;
    if side > wire::side::FAR {
        return refuse_construct(
            s,
            b"[remote_channel] refusing to construct: `exchange` is not none, near or far",
        );
    }
    if s.n_peers == 0 || s.n_peers as usize > SESSIONS_MAX {
        return refuse_construct(
            s,
            b"[remote_channel] refusing to construct: `sessions` is outside 1..=SESSIONS_MAX",
        );
    }
    if s.n_peers > 1 && (s.transport != TRANSPORT_NET || s.role != ROLE_LISTEN) {
        return refuse_construct(
            s,
            b"[remote_channel] refusing to construct: more than one session is a `net` listener's",
        );
    }
    if s.n_peers > 1 && side == wire::side::NEAR {
        return refuse_construct(s, b"[remote_channel] refusing to construct: a near endpoint serves one requester's id space, so one session");
    }
    if s.peer_tag > 1 {
        return refuse_construct(
            s,
            b"[remote_channel] refusing to construct: `peer_tag` is 0 or 1",
        );
    }
    if s.peer_tag != 0 && s.require_peer == 0 {
        return refuse_construct(s, b"[remote_channel] refusing to construct: `peer_tag` names verified peers, so it needs `require_peer`");
    }
    let text = s.table_text;
    s.table = if s.table_text_len == 0 && side != wire::side::NONE {
        wire::Table::EMPTY
    } else {
        match wire::parse_table(&text[..s.table_text_len as usize], MAX_RECORD) {
            Ok(t) => t,
            Err(e) => {
                log(s, 1, TABLE_ERRORS.get(e as usize));
                return -22;
            }
        }
    };
    let bytes = (0..n_channels(s)).any(|i| s.table.entries[i].framing == wire::framing::BYTES);
    if bytes && (s.n_peers > 1 || s.peer_tag != 0) {
        return refuse_construct(s, b"[remote_channel] refusing to construct: a `bytes` channel has no records to merge, route or prefix, so it needs one session and no `peer_tag`");
    }
    if side != wire::side::NONE {
        if s.table.add_exchange(side, xc::RECORD_MAX as u32).is_err() {
            return refuse_construct(s, b"[remote_channel] refusing to construct: `channels` leaves no room for the exchange endpoint's two channels");
        }
        let (q, r) = (x_req(s), x_resp(s));
        let near = side == wire::side::NEAR;
        s.chans[q].xdir = if near { DIR_SEND } else { DIR_RECV };
        s.chans[r].xdir = if near { DIR_RECV } else { DIR_SEND };
    }
    if s.resume != 0 {
        // On `mux` each channel's HELLO carries the same trailer, fixed when
        // the session attached: applying it once per stream is applying it
        // once, before any record of the session is sent.
        if side != wire::side::NONE {
            return refuse_construct(s, b"[remote_channel] refusing to construct: `resume` is for channels without an exchange endpoint");
        }
        if s.n_peers > 1 && s.require_peer == 0 {
            return refuse_construct(s, b"[remote_channel] refusing to construct: `resume` across several sessions keeps each peer's streams by its verified identity, so it needs `require_peer`");
        }
        s.table.resume = true;
        // An incarnation no other instance, and no earlier life of this
        // one, can be holding streams under.
        if dev_csprng_fill(sys, s.incarnation.as_mut_ptr(), INCARNATION_LEN) < 0
            || s.incarnation == [0; INCARNATION_LEN]
        {
            return refuse_construct(
                s,
                b"[remote_channel] refusing to construct: no randomness for the incarnation",
            );
        }
        for e in s.peers.iter_mut() {
            for pc in e.chans.iter_mut() {
                pc.rt_base = 1;
                pc.cur_seq = 1;
                pc.rx_next = 1;
            }
        }
    }
    s.n_links = if s.transport == TRANSPORT_NET && s.role == ROLE_LISTEN {
        s.n_peers + 1
    } else {
        1
    };
    // One session's instance always holds its one peer's streams.
    if s.n_peers == 1 {
        s.peers[0].used = true;
    }
    if !carve_pool(s) {
        return refuse_construct(s, b"[remote_channel] refusing to construct: the channels' records, across every session, exceed REASSEMBLY_BYTES");
    }
    for i in 0..n_channels(s) {
        s.chans[i].entry = s.table.entries[i];
        if !is_x(s, i) {
            s.chans[i].input = dev_channel_port(sys, 0, PORT_CH_IN + i as u8);
            s.chans[i].output = dev_channel_port(sys, 1, PORT_CH_OUT + i as u8);
        }
        s.slots[i].parser = Parser::new();
        s.slots[i].channel = 0xFF;
    }
    if !wire_exchange(s) {
        return -22;
    }
    if s.transport == TRANSPORT_NET && s.role == ROLE_DIAL && !adopt_authority(s) {
        return refuse_construct(
            s,
            b"[remote_channel] refusing to construct: dial needs authority (host[:port])",
        );
    }
    s.phase = PH_IDLE;
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
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
        for l in 0..s.n_links as usize {
            check_net_identity(s, l);
        }
        let due = now.wrapping_sub(s.retry_at_ms) < 0x8000_0000;
        if s.phase == PH_IDLE && due && s.tx_len == 0 {
            if s.role == ROLE_LISTEN {
                let p = s.port.to_le_bytes();
                if command(s, NO_LINK, net_proto::CMD_BIND, &p) {
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
                if command(s, NO_LINK, net_proto::CMD_CONNECT_TO, &p[..n]) {
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
    far_step(s);
    deliver(s);
    near_step(s);
    for l in 0..s.n_links as usize {
        try_hello(s, l);
        check_setup_deadline(s, l, now);
        keepalive(s, l, now);
    }
    if flush_tx(s) && send_control(s) {
        send_records(s);
    }
    report_session(s);
    0
}

/// `resume`: keep an idle session's link proven, and give up on one that
/// has gone silent.
unsafe fn keepalive(s: &mut State, l: usize, now: u32) {
    if !s.table.resume || s.keepalive_ms == 0 || s.links[l].phase != PH_OPEN {
        return;
    }
    let k = s.keepalive_ms.min(i32::MAX as u32 / 4);
    let lk = &s.links[l];
    if now.wrapping_sub(lk.last_rx_ms) >= 3 * k && now.wrapping_sub(lk.last_rx_ms) < 0x8000_0000 {
        end_link(
            s,
            l,
            true,
            b"[remote_channel] the peer went silent; the session is given up",
        );
        return;
    }
    if now.wrapping_sub(lk.last_tx_ms) >= k && now.wrapping_sub(lk.last_tx_ms) < 0x8000_0000 {
        // An acknowledgement of what has arrived — true whenever it is sent,
        // so it is also the cheapest frame that proves the link.
        let p = lk.peer as usize;
        let through = s.peers[p].chans[0].rx_next - 1;
        frame(s, l, Some(0), wire::KIND_ACK, 0, &through.to_le_bytes());
    }
}

/// Tell the `session` output whether a session is open, when that differs
/// from what it last carried: open while any session is, under the ordinal
/// of the last one that opened. A frame the output cannot take now is
/// written on a later step, as whatever the state is by then: a consumer
/// needs the session it may send on, not a history of them.
unsafe fn report_session(s: &mut State) {
    if s.session_out < 0 {
        return;
    }
    let open = s.open_sessions() > 0;
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
