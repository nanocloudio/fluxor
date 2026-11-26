//! The node's host sockets: the stream (`net_proto`) and datagram
//! (`datagram`) surfaces served over the host's TCP and UDP, the half of
//! the provider a graph names as `linux_net`.
//!
//! Commands arrive as whole records on lanes, and events and data leave as
//! whole records, framed `tlv16` as the surfaces frame them. Every consumer
//! is a lane, added and removed with its owner ([`Sockets::attach`]): the
//! owner of the module writing its commands, the node or a workload. Lanes are drained in the order they attached, so the node graph's,
//! which attach first and in wiring order, come before any workload's, and
//! a bulk stream on a later lane cannot serialise ahead of
//! latency-critical traffic on an earlier one. A lane reaches only the
//! connections and endpoints it opened, and their events go to it alone.
//!
//! Every lane carries the owner its commands act for and what that owner
//! may claim ([`Sockets::gate`]); a lane's commands wait until it has one.
//! A new bind of an owner that is not the node's needs its admission open
//! and, to listen, the owner's grant for the endpoint
//! (`net_proto::grant`).
//!
//! The engine runs in steps ([`Sockets::step`]), each planned against what
//! every destination ring can take ([`View`]) and handed on after it
//! ([`Sockets::drain_out`]), so a write that is all-or-nothing on a ring is
//! all-or-nothing here. Sockets are non-blocking and level-triggered in one
//! epoll set, which is also what wakes the serve loop ([`Sockets::wake`]);
//! names are resolved on a thread of their own with the host's resolver
//! ladder (`getaddrinfo`), its answers cached.

use std::collections::VecDeque;
use std::os::fd::RawFd;
use std::time::Duration;

use fluxor_host_lane::control::gate;
use fluxor_host_lane::provider::Poll;
use fluxor_host_lane::ring::View;

// The stream and datagram surfaces this provider serves
// (`contracts/net/net_proto.rs`, `contracts/net/datagram.rs`); the contract
// modules are the only source of their values and layouts.
use fluxor_abi::contracts::net::datagram as dgc;
use fluxor_abi::contracts::net::net_proto as np;
use np::{
    CLOSED_GONE, CLOSED_ID_GRACE_MS, CLOSED_PEER_FIN, CMD_BIND, CMD_CLOSE, CMD_CONNECT_TO,
    CMD_SEND, MSG_ACCEPTED, MSG_BOUND, MSG_CLOSED, MSG_CONNECTED, MSG_DATA, MSG_ERROR,
};

/// An owner, as the runtime names it: slot and generation. The node's own
/// is slot 0, generation 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Owner {
    pub slot: u16,
    pub generation: u32,
}

impl Owner {
    /// The node's own owner.
    pub const NODE: Owner = Owner {
        slot: 0,
        generation: 0,
    };

    /// Whether this is the node's own owner.
    pub fn is_node(&self) -> bool {
        *self == Owner::NODE
    }
}

/// What an instance is built with.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Connection slots (listeners, accepted and dialled connections).
    pub max_conns: usize,
    /// Per-connection unsent-byte backlog cap.
    pub write_buf_max: usize,
    /// `listen()` backlog.
    pub listen_backlog: i32,
}

impl Default for Config {
    /// The surfaces' defaults.
    fn default() -> Config {
        Config {
            max_conns: MAX_CONNS_DEFAULT,
            write_buf_max: WRITE_BUF_DEFAULT,
            listen_backlog: LISTEN_BACKLOG_DEFAULT,
        }
    }
}

/// How long a deferred `CMD_CLOSE` waits for the connection's queued bytes to
/// reach the wire before closing anyway.
///
/// The wait exists so a close does not discard what the consumer already
/// handed over (RFC 793 §3.5). It is bounded because a peer that has stopped
/// reading would otherwise hold the slot and its descriptor for good: past
/// this the remainder is dropped, loudly, which is a reported loss rather than
/// a silent one.
const CLOSE_DRAIN_MAX_MS: u64 = 10_000;

const DG_CMD_BIND: u8 = dgc::CMD_DG_BIND;
const DG_CMD_SEND_TO: u8 = dgc::CMD_DG_SEND_TO;
const DG_CMD_CLOSE: u8 = dgc::CMD_DG_CLOSE;
const DG_MSG_BOUND: u8 = dgc::MSG_DG_BOUND;
const DG_MSG_RX_FROM: u8 = dgc::MSG_DG_RX_FROM;
const DG_MSG_CLOSED: u8 = dgc::MSG_DG_CLOSED;
const DG_MSG_ERROR: u8 = dgc::MSG_DG_ERROR;
const DG_AF_INET: u8 = dgc::AF_INET;
/// Datagram destination given as a DNS name (`[len][name]`), resolved by
/// this provider exactly as a stream dial is. A name not yet in the cache
/// starts a lookup and the datagram is DROPPED: a datagram sender
/// retransmits, and the next send after the answer lands goes out.
const DG_AF_NAME: u8 = dgc::AF_NAME;

/// The largest record an events lane carries, header included (the
/// `net_out` port's `max_record`): a `MSG_DATA` of 1460 bytes (`STREAM_CHUNK`) is 1465, and
/// a datagram is delivered only while its `MSG_DG_RX_FROM` frame fits this
/// bound — 1472 bytes of IPv4 payload, one Ethernet MTU. A larger host
/// datagram is dropped and counted (`dg_rx_dropped`), never cut.
pub const OUT_MAX_RECORD: usize = dgc::TRANSPORT_RECORD_MAX;
/// The largest command record acted on, header included (the `net_in`
/// port's `accepts_record`): the command scratch.
pub const IN_ACCEPTS_RECORD: usize = 3 + CMD_MAX;
/// Data bytes one `MSG_DATA` frame carries.
const STREAM_CHUNK: usize = 1460;
const _: () = assert!(3 + np::DATA_HEAD + STREAM_CHUNK <= OUT_MAX_RECORD);
/// Ring bytes one `MSG_DATA` frame takes beyond its data: the frame header,
/// the connection id, the ring's length word and its padding to 4.
const STREAM_FRAME_OVERHEAD: usize = 3 + np::DATA_HEAD + 4 + 3;

/// The stream bytes `room` writable bytes of a lane carry as `MSG_DATA`
/// frames of at most `STREAM_CHUNK` each, every frame a record of its own.
const fn stream_data_fits(room: usize) -> usize {
    let per = STREAM_FRAME_OVERHEAD + STREAM_CHUNK;
    (room / per) * STREAM_CHUNK + (room % per).saturating_sub(STREAM_FRAME_OVERHEAD)
}

const CONN_TYPE_UDP_BOUND: u8 = 2;

/// Connection slots (listeners + clients) when the graph does not set
/// `max_conns`. The table is a heap `Vec` sized once at start from the
/// graph's `max_conns`, capped at
/// `MAX_CONNS_CAP` because net_proto carries the slot index
/// as `u16 LE`. A slot holds no buffer until a send backs up, so a large
/// table of idle connections costs only the fixed per-slot fields.
pub const MAX_CONNS_DEFAULT: usize = 128;
/// Hard ceiling on `max_conns`: the wire id is a `u16`. A configured value
/// outside `MAX_CONNS_MIN..=MAX_CONNS_CAP` is refused at start, never
/// adjusted.
pub const MAX_CONNS_CAP: usize = 65535;
/// Floor on `max_conns`: one listener and one connection.
pub const MAX_CONNS_MIN: usize = 2;
/// Ready-event batch drained from the epoll set per step. Level
/// triggered, so a socket left out of one batch is served next step.
const READY_BATCH: usize = 1024;
/// The epoll token of the resolver's doorbell: no slot has it.
const RESOLVER_TOKEN: u64 = u64::MAX;
/// Records one lane holds before it takes no more off its ring.
const INBOX_RECORDS: usize = 32;
/// Bytes one lane holds before it takes no more off its ring.
const INBOX_BYTES: usize = 192 * 1024;
/// Lanes attached at once: one per lane key (a byte). The runtime adds no
/// more than the graph's `lanes`, the node graph's and its workloads'.
pub const MAX_LANES: usize = 256;
/// Datagram endpoints take slots below this: an endpoint id is a byte.
const DG_ENDPOINT_SLOTS: usize = 256;
/// Control frames held for one destination while it is full. At the
/// cap the sources that would add to it pause: the lane's commands are left
/// on its ring and its listeners' pending connections in the host's
/// accept queue, so a wedged consumer back-pressures its producer.
/// No queued frame is ever evicted. What can still arrive while paused is
/// bounded by the slots the lane already holds (each emits at most a
/// connect result, a peer report and a close), so the queue never passes
/// [`Sockets::pending_ctrl_ceiling`]; a frame refused there is
/// counted and logged.
pub const PENDING_CTRL_CAP: usize = 256;
/// Per-connection write backlog cap when the graph does not set
/// `write_buf_kib`. 128 KiB holds a full Spectrum video frame's worth of
/// WS fragments (~98 KB) so a slow peer can absorb one frame's
/// transmission pause without the producer overflowing the backlog
/// (which closes the connection). The buffer is allocated the first
/// time a send backs up and released with the slot, so the cap is a
/// per-connection worst case, not a resident cost.
pub const WRITE_BUF_DEFAULT: usize = 128 * 1024;
/// The largest command frame payload acted on (the command scratch). A
/// larger frame is answered `EMSGSIZE` in the shape its command's requester
/// waits on.
pub const CMD_MAX: usize = 49152;
/// Listen backlog when the graph does not set `listen_backlog`. The
/// kernel's SYN queue must absorb a whole connect burst; at 8 a
/// 32-client burst dropped SYNs 9..=32.
pub const LISTEN_BACKLOG_DEFAULT: i32 = 128;

// Intentionally NOT Copy: `write_buf` owns a heap allocation.
// References / field-access only.
struct Conn {
    fd: i32,
    conn_type: u8,
    state: u8,
    /// For TCP listeners (`conn_type == 1, state == 3`): the port the
    /// listener is bound to. Used by `cmd_bind` to recognise
    /// re-binds on the same port. Zero for non-listener slots.
    port: u16,
    /// `CMD_CLOSE` arrived while `write_buf` still held unsent bytes. The
    /// close waits for them: RFC 793 §3.5 has CLOSE transmit everything
    /// already queued, and `close(2)` over a live backlog drops it — the peer
    /// then reads a clean FIN on a response short by exactly that much, with
    /// no error anywhere to say so. The bare-metal `ip` module defers its FIN
    /// for the same reason.
    close_when_drained: bool,
    /// When the deferred close gives up and closes regardless.
    close_deadline: Option<std::time::Instant>,
    /// Bytes already drained from `write_buf`.
    write_offset: u32,
    /// Total valid bytes in `write_buf` (drained slice is `[offset..len]`).
    write_len: u32,
    /// Requester tag from `CMD_CONNECT_TO`, echoed in `MSG_CONNECTED` /
    /// connect-failure `MSG_ERROR` so a fanned net_out routes the event back.
    connect_tag: fluxor_abi::contracts::net::net_proto::RequesterTag,
    /// `state == 5` (resolving, no fd yet): the lookup this slot is waiting
    /// on. A result whose id does not match is stale — the slot was revoked
    /// and possibly retaken while the lookup ran — and is dropped.
    resolve_id: u32,
    /// `state == 5`: when the lookup was handed to the resolver thread, so a
    /// resolver that never answers cannot pin the slot.
    resolve_started: Option<std::time::Instant>,
    /// The COMMANDING owner — the owner whose lane issued the bind/connect
    /// that created this slot (attribution is carried by the lane, never
    /// inferred from who serves it). Immutable for the life of the slot.
    owner: Owner,
    /// The lane whose command created this slot (an accepted connection
    /// takes its listener's). Every event about the slot goes to that
    /// lane's events, and a lane may act only on the slots it created.
    /// Immutable for the life of the slot.
    lane: u16,
    /// Unsent bytes. Empty until a send backs up; then grown as the backlog
    /// does (to the instance's `write_buf_max`) and kept until the slot is
    /// released.
    write_buf: Vec<u8>,
    /// `state == 4` (closed, id held): when the id is released if the
    /// consumer has not sent CMD_CLOSE by then. net_proto's release rule —
    /// after MSG_CLOSED the id stays the consumer's for
    /// `CLOSED_ID_GRACE_MS`, so its CMD_CLOSE can never land on a newcomer
    /// that took the same index, and a consumer that never closes cannot
    /// pin the slot either.
    release_at: Option<std::time::Instant>,
    /// `state == 2`: the peer finished sending (`recv` returned 0). The
    /// socket stays open for the consumer to send on and is no longer read;
    /// `release_at` bounds how long it waits for the consumer's CMD_CLOSE.
    peer_fin: bool,
    /// `state == 1` (connecting): the addresses this name resolved to that
    /// have not been tried yet, in the host's order. A refused or
    /// unreachable connect moves to the next before it is reported, so a
    /// name whose first address is dead — `localhost` on a dual-stack box
    /// answering `::1` ahead of `127.0.0.1` — still reaches a service
    /// listening on the other one.
    alts: Vec<Resolved>,
    /// `state == 1`: when the attempt now in `fd` was started, so a family
    /// that is black-holed rather than refusing does not hold the dial for
    /// the whole connect timeout (RFC 8305 §5).
    attempt_started: Option<std::time::Instant>,
    /// `state == 1`: attempts started BEFORE the one in `fd` and still in
    /// flight. The first of any of them to connect wins and the rest are
    /// closed; a consumer never learns a race happened.
    racing: Vec<i32>,
    /// Datagram endpoints only: for each peer heard from, the local address
    /// its last datagram arrived at, `(peer addr, peer port, local addr)`
    /// with addresses as `s_addr`. A send to that peer leaves from that
    /// address, so an endpoint bound to every address answers from the one
    /// it was asked at — not from whichever source the route prefers, which
    /// the asker (and connection tracking, for a translated service) would
    /// not take for the answer. At most [`DG_REPLY_FROM_MAX`] peers, the
    /// longest unheard replaced first.
    dg_reply_from: Vec<(u32, u16, u32)>,
    /// Datagram endpoints only: arrivals not delivered to the consumer — its
    /// lane was full or held control frames, or the datagram was larger
    /// than one frame carries.
    dg_rx_dropped: u64,
}

/// Peers a datagram endpoint remembers the arrival address of.
const DG_REPLY_FROM_MAX: usize = 64;

impl Conn {
    fn empty() -> Self {
        Self {
            fd: -1,
            conn_type: 0,
            state: 0,
            port: 0,
            close_when_drained: false,
            close_deadline: None,
            write_offset: 0,
            write_len: 0,
            connect_tag: 0,
            resolve_id: 0,
            resolve_started: None,
            release_at: None,
            peer_fin: false,
            owner: Owner::NODE,
            lane: 0,
            write_buf: Vec::new(),
            alts: Vec::new(),
            attempt_started: None,
            racing: Vec::new(),
            dg_reply_from: Vec::new(),
            dg_rx_dropped: 0,
        }
    }
}

/// Largest control frame a lane queue holds: a stream's peer report
/// (`MSG_PEER`, `[type][len: u16][conn_id: u16][family][addr: 16][port: u16]`),
/// queued with the accept it follows. Every control frame fits it, which
/// `send_msg` checks at compile time; data (`MSG_DATA`,
/// `DG_MSG_RX_FROM`) is never queued.
const CTRL_FRAME_MAX: usize = 3 + fluxor_abi::contracts::net::net_proto::PEER_LEN;

/// Control frames waiting for room on one destination, in order.
type PendingCtrl = std::collections::VecDeque<([u8; CTRL_FRAME_MAX], usize)>;

/// What one lane's owner may claim, as the runtime last said
/// ([`Sockets::gate`]).
#[derive(Clone, Debug)]
struct LaneGate {
    /// `control::gate` flags.
    flags: u8,
    /// The owner's whole grant set.
    grants: Vec<u8>,
}

/// One lane's commands, taken off its ring and not yet acted on.
#[derive(Default)]
struct Inbox {
    recs: VecDeque<Vec<u8>>,
    bytes: usize,
}

impl Inbox {
    fn has_room(&self) -> bool {
        self.recs.len() < INBOX_RECORDS && self.bytes < INBOX_BYTES
    }

    fn push(&mut self, rec: &[u8]) {
        self.bytes += rec.len();
        self.recs.push_back(rec.to_vec());
    }

    fn pop(&mut self) -> Option<Vec<u8>> {
        let r = self.recs.pop_front()?;
        self.bytes -= r.len();
        Some(r)
    }
}

/// Records planned for one destination in this step, and what its ring
/// could take when the step began.
struct Outq {
    view: View,
    recs: VecDeque<Vec<u8>>,
}

impl Outq {
    fn new() -> Outq {
        Outq {
            view: View::NONE,
            recs: VecDeque::new(),
        }
    }

    /// Plan `rec` whole, or refuse it whole.
    fn put(&mut self, rec: &[u8]) -> bool {
        if !self.view.fits(rec.len()) {
            return false;
        }
        self.recs.push_back(rec.to_vec());
        true
    }

    /// Bytes of `MSG_DATA` frames that fit after what is planned.
    fn room(&self) -> usize {
        self.view.room(OUT_MAX_RECORD)
    }
}

/// A lane: its own commands and its own events, which every event for a
/// slot the lane created goes to and nothing else does.
struct Lane {
    key: u8,
    owner: Owner,
    gate: Option<LaneGate>,
    inbox: Inbox,
    out: Outq,
    /// Control frames its events had no room for. Per lane, so one consumer
    /// that falls behind holds up only its own terminal results.
    pending: PendingCtrl,
}

/// The engine: the connection table, every lane, the epoll set and the
/// resolver.
pub struct Sockets {
    /// Connection table, `max_conns` slots; the slot index is the
    /// net_proto conn id.
    conns: Vec<Conn>,
    /// The slots a listener or datagram endpoint was bound in, for the
    /// endpoint report ([`Sockets::bound_endpoints`]); a slot freed or
    /// reused since no longer reads as one and is dropped there.
    endpoint_slots: Vec<u16>,
    /// Per-connection write backlog cap (`write_buf_kib` param).
    write_buf_max: usize,
    /// `listen()` backlog for every listener this instance binds.
    listen_backlog: i32,
    /// epoll set holding every live fd, `data.u64` = slot index, and the
    /// resolver's doorbell. Level triggered: readiness is re-reported every
    /// step until consumed, so a socket skipped for back-pressure is not
    /// lost.
    epfd: i32,
    /// The resolver thread's doorbell (an eventfd in the epoll set).
    resolver_bell: i32,
    /// Scratch for one `epoll_wait` batch.
    ready: Vec<libc::epoll_event>,
    ready_len: usize,
    /// One command frame's payload, `CMD_MAX` (48 KiB) bytes: `net_in`'s
    /// `accepts_record` less the frame header, so every record a producer
    /// the composer admitted can write fits. A frame whose payload is
    /// larger is answered `EMSGSIZE`, never acted on in part.
    cmd_buf: Box<[u8; CMD_MAX]>,
    msg_buf: Box<[u8; 16384]>,
    recv_buf: Box<[u8; 16384]>,
    /// The part of `recv_buf` a full destination left un-forwarded, and the
    /// slot it came from. A frame write is all-or-nothing, so a short
    /// write leaves bytes read from the socket but not yet delivered;
    /// they are already out of the kernel's buffer, so the only place
    /// they can be re-offered from is here. While a tail is held no
    /// socket is read, because `recv_buf` is the one place to read into
    /// and overwriting it is how those bytes would be lost.
    hold_slot: i32,
    hold_off: usize,
    hold_len: usize,
    /// The lane the held tail is owed to, fixed when the hold is taken: the
    /// slot may be closed while its tail waits, and its bytes still belong
    /// to the lane that was reading it.
    hold_lane: usize,
    /// Next slot to consider when allocating a connection. Used to
    /// allocate round-robin instead of "first free", so a slot freed
    /// in step T isn't immediately reused in step T+1 — that race lets
    /// stale `CMD_SEND` bytes from the previous session land on the
    /// fresh connection's fd, scrambling its response stream.
    next_alloc: usize,
    /// Control frames refused at `pending_ctrl_ceiling`. The pause at
    /// `PENDING_CTRL_CAP` keeps a queue below the ceiling, so this staying
    /// zero is the design holding.
    ctrl_refused: u64,
    /// Datagrams received and not delivered, over every endpoint.
    dg_rx_dropped: u64,
    /// The lanes, by lane index. A detached entry is `None` and its index
    /// may be reused, which is safe because detaching closes every slot the
    /// lane created.
    lanes: Vec<Option<Lane>>,
    /// The attached lanes' indices in the order they attached: the order
    /// their commands are acted on and their events handed on.
    order: Vec<usize>,
    /// The resolver thread's queues, started on the first name this
    /// instance is asked to dial. Everything crossing the thread boundary
    /// is owned: a job carries its own copy of the name.
    resolver: Option<Resolver>,
    /// Ids handed to lookups, so a result can be matched to the slot that
    /// is still waiting for it and no other.
    resolve_seq: u32,
    /// Slots in `resolving`, so a step with none pays nothing for the
    /// guard sweep.
    resolving: usize,
    /// Names a cache-warming lookup (a named datagram destination) is in
    /// flight for. A datagram sender retransmits while it waits, and
    /// without this every retransmit would queue another identical job.
    warming: Vec<String>,
    /// Positive cache, consulted BEFORE a slot is taken: `getaddrinfo` has
    /// no TTL to report, so entries live `DNS_CACHE_TTL`. It is what keeps
    /// the common case out of the resolver thread — and out of tls's single
    /// in-flight connect window, which a lookup would otherwise stretch to
    /// a DNS round-trip.
    dns_cache: Vec<DnsCacheEntry>,
    /// Something moved in this step: a command acted on, a record planned,
    /// backlog bytes written.
    moved: bool,
    /// The last step ended holding something it could not hand on: the
    /// epoll set may stay readable for a socket left unread, so it is not
    /// what wakes the loop then.
    holding: bool,
}

/// One address a name resolved to, in network order as the socket wants it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Resolved {
    V4([u8; 4]),
    V6([u8; 16]),
}

struct DnsCacheEntry {
    name: String,
    /// Every candidate the host gave, in its order. Cached whole so a name
    /// answered from cache falls back exactly as a freshly resolved one does.
    addrs: Vec<Resolved>,
    expires: std::time::Instant,
}

/// How many addresses one name may be dialled at. A name that resolves to
/// more than this is not worth a longer ladder: the connect timeout bounds
/// each rung, and a host with four dead addresses is down, not slow. The cut
/// is taken after the families are interleaved ([`dial_candidates`]), so
/// both families are dialled whenever the host answered both.
pub const MAX_DIAL_CANDIDATES: usize = 4;

/// Cache entries per instance; one slot per distinct name the graph dials.
const DNS_CACHE_SLOTS: usize = 32;
/// How long a positive answer is reused. `getaddrinfo` returns no TTL, so
/// the contract's fallback applies.
const DNS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
/// A resolving slot older than this is failed `ENOENT`: glibc's own retry
/// ladder is shorter, so this only fires if the resolver thread is gone.
const RESOLVE_GUARD: std::time::Duration = std::time::Duration::from_secs(30);

struct ResolveJob {
    id: u32,
    /// The stream slot waiting on this lookup; `None` for a datagram
    /// destination, which only warms the cache.
    slot: Option<usize>,
    name: String,
    /// Datagram sockets here are `AF_INET`, so their lookups ask for v4.
    v4_only: bool,
}

struct ResolveDone {
    id: u32,
    slot: Option<usize>,
    name: String,
    result: Result<Vec<Resolved>, i32>,
}

struct Resolver {
    jobs: std::sync::mpsc::Sender<ResolveJob>,
    done: std::sync::mpsc::Receiver<ResolveDone>,
}

impl Resolver {
    /// Start the thread; each answer it sends rings `bell` (an eventfd in
    /// the engine's epoll set, or -1).
    fn start(bell: i32) -> Option<Self> {
        let (jobs, job_rx) = std::sync::mpsc::channel::<ResolveJob>();
        let (done_tx, done) = std::sync::mpsc::channel::<ResolveDone>();
        let spawned = std::thread::Builder::new()
            .name("fluxor-resolver".into())
            .spawn(move || {
                while let Ok(job) = job_rx.recv() {
                    let result = resolve_blocking(&job.name, job.v4_only);
                    let reply = ResolveDone {
                        id: job.id,
                        slot: job.slot,
                        name: job.name,
                        result,
                    };
                    if done_tx.send(reply).is_err() {
                        break;
                    }
                    if bell >= 0 {
                        let one: u64 = 1;
                        // SAFETY: an eventfd the engine keeps open for as
                        // long as this thread's queue lives, and an 8-byte
                        // value.
                        unsafe { libc::write(bell, (&raw const one).cast(), 8) };
                    }
                }
            });
        match spawned {
            Ok(_) => Some(Self { jobs, done }),
            Err(e) => {
                log::error!("[linux_net] cannot start the resolver thread: {e}");
                None
            }
        }
    }
}

/// `getaddrinfo(3)` with `AI_ADDRCONFIG`: the host's resolver, hosts file
/// and nsswitch order, which is the order the candidates are returned in.
/// Every address is returned; the caller picks the ones it dials with
/// [`dial_candidates`]. Runs on the resolver thread only.
fn resolve_blocking(name: &str, v4_only: bool) -> Result<Vec<Resolved>, i32> {
    let cname = match std::ffi::CString::new(name) {
        Ok(c) => c,
        Err(_) => return Err(libc::EINVAL),
    };
    // SAFETY: `hints` is zeroed then filled; `cname` outlives the call; the
    // result list is walked while owned and released with `freeaddrinfo`.
    unsafe {
        let mut hints: libc::addrinfo = core::mem::zeroed();
        hints.ai_family = if v4_only {
            libc::AF_INET
        } else {
            libc::AF_UNSPEC
        };
        hints.ai_socktype = libc::SOCK_STREAM;
        hints.ai_flags = libc::AI_ADDRCONFIG;
        let mut res: *mut libc::addrinfo = core::ptr::null_mut();
        let rc = libc::getaddrinfo(cname.as_ptr(), core::ptr::null(), &hints, &mut res);
        if rc != 0 {
            let why = std::ffi::CStr::from_ptr(libc::gai_strerror(rc)).to_string_lossy();
            log::warn!("[linux_net] resolve {name}: {why}");
            return Err(libc::ENOENT);
        }
        let mut found: Vec<Resolved> = Vec::new();
        let mut cur = res;
        while !cur.is_null() {
            let ai = &*cur;
            if ai.ai_family == libc::AF_INET && !ai.ai_addr.is_null() {
                let sa = &*(ai.ai_addr as *const libc::sockaddr_in);
                found.push(Resolved::V4(sa.sin_addr.s_addr.to_ne_bytes()));
            } else if ai.ai_family == libc::AF_INET6 && !ai.ai_addr.is_null() && !v4_only {
                let sa = &*(ai.ai_addr as *const libc::sockaddr_in6);
                found.push(Resolved::V6(sa.sin6_addr.s6_addr));
            }
            cur = ai.ai_next;
        }
        libc::freeaddrinfo(res);
        if found.is_empty() {
            Err(libc::ENOENT)
        } else {
            Ok(found)
        }
    }
}

impl Sockets {
    /// A cached, unexpired answer for `name`.
    fn dns_cache_get(&self, name: &[u8]) -> Option<Vec<Resolved>> {
        let now = std::time::Instant::now();
        self.dns_cache
            .iter()
            .find(|e| e.name.as_bytes() == name && e.expires > now)
            .map(|e| e.addrs.clone())
    }

    fn dns_cache_put(&mut self, name: String, addrs: Vec<Resolved>) {
        let now = std::time::Instant::now();
        let expires = now + DNS_CACHE_TTL;
        if let Some(e) = self.dns_cache.iter_mut().find(|e| e.name == name) {
            e.addrs = addrs;
            e.expires = expires;
            return;
        }
        if self.dns_cache.len() >= DNS_CACHE_SLOTS {
            // Evict an expired entry if any, else the soonest to expire.
            let victim = self
                .dns_cache
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.expires)
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.dns_cache.swap_remove(victim);
        }
        self.dns_cache.push(DnsCacheEntry {
            name,
            addrs,
            expires,
        });
    }

    /// Hand `name` to the resolver thread. `false` when the thread cannot
    /// be started or has gone away, which the caller reports as `ENOENT`.
    fn resolve_async(&mut self, name: &[u8], slot: Option<usize>, v4_only: bool) -> Option<u32> {
        if slot.is_none() && self.warming.iter().any(|n| n.as_bytes() == name) {
            return None; // already looking this one up
        }
        if self.resolver.is_none() {
            self.resolver = Resolver::start(self.resolver_bell);
        }
        let resolver = self.resolver.as_ref()?;
        self.resolve_seq = self.resolve_seq.wrapping_add(1).max(1);
        let id = self.resolve_seq;
        let job = ResolveJob {
            id,
            slot,
            name: String::from_utf8_lossy(name).into_owned(),
            v4_only,
        };
        if resolver.jobs.send(job).is_err() {
            log::error!("[linux_net] resolver thread is gone");
            self.resolver = None;
            // Nothing is in flight any more: the answers those names were
            // waiting for died with the thread.
            self.warming.clear();
            return None;
        }
        if slot.is_none() {
            self.warming
                .push(String::from_utf8_lossy(name).into_owned());
        }
        Some(id)
    }

    /// Control frames refused because a destination's queue stood at
    /// [`Self::pending_ctrl_ceiling`].
    pub fn ctrl_refused(&self) -> u64 {
        self.ctrl_refused
    }

    /// Datagrams received and not delivered, over every endpoint.
    pub fn dg_rx_dropped(&self) -> u64 {
        self.dg_rx_dropped
    }

    /// Datagrams endpoint `ep` received and did not deliver.
    pub fn dg_endpoint_rx_dropped(&self, ep: usize) -> u64 {
        self.conns.get(ep).map_or(0, |c| c.dg_rx_dropped)
    }

    /// Control frames waiting for `lane`'s events.
    pub fn pending_ctrl_len(&self, lane: usize) -> usize {
        self.lanes
            .get(lane)
            .and_then(|a| a.as_ref())
            .map_or(0, |a| a.pending.len())
    }

    /// Whether `lane`'s control queue is at [`PENDING_CTRL_CAP`]: its
    /// commands and accepts wait until the consumer reads.
    fn lane_paused(&self, lane: usize) -> bool {
        self.pending_ctrl_len(lane) >= PENDING_CTRL_CAP
    }

    /// The most frames one destination's queue can hold. A paused lane
    /// creates no slot, so past [`PENDING_CTRL_CAP`] the queue grows only
    /// by what the slots that exist still owe — at most three frames each
    /// (`MSG_CONNECTED`, `MSG_PEER`, `MSG_CLOSED`) — plus the two frames one
    /// command or accept emits before the pause is seen.
    pub fn pending_ctrl_ceiling(&self) -> usize {
        PENDING_CTRL_CAP + 2 + 3 * self.conns.len()
    }

    /// Register `fd` (held by slot `slot`) for `events` in the epoll set.
    /// Closing the fd removes it again, so slots are never explicitly
    /// deregistered.
    unsafe fn watch(&self, fd: i32, slot: usize, events: u32) {
        if self.epfd < 0 {
            return;
        }
        let mut ev = libc::epoll_event {
            events,
            u64: slot as u64,
        };
        if libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) < 0 {
            let err = *libc::__errno_location();
            log::warn!("[linux_net] epoll add failed for slot {slot} (errno {err})");
        }
    }

    /// Change the events watched for `fd`.
    unsafe fn rewatch(&self, fd: i32, slot: usize, events: u32) {
        if self.epfd < 0 {
            return;
        }
        let mut ev = libc::epoll_event {
            events,
            u64: slot as u64,
        };
        libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_MOD, fd, &mut ev);
    }

    /// Fill `ready` with the slots whose fds report readiness. Zero
    /// timeout: a step never waits.
    unsafe fn poll_ready(&mut self) {
        self.ready_len = 0;
        if self.epfd < 0 {
            return;
        }
        let n = libc::epoll_wait(
            self.epfd,
            self.ready.as_mut_ptr(),
            self.ready.len() as i32,
            0,
        );
        if n > 0 {
            self.ready_len = n as usize;
        }
        // The resolver's doorbell is read here, so it does not stay ready;
        // its answers are taken by `drain_resolved`.
        for k in 0..self.ready_len {
            if self.ready[k].u64 == RESOLVER_TOKEN {
                let mut v = 0u64;
                libc::read(self.resolver_bell, (&raw mut v).cast(), 8);
            }
        }
    }

    /// Slot index carried by ready event `k`, or `None` if it no longer
    /// names a slot.
    fn ready_slot(&self, k: usize) -> Option<usize> {
        let slot = self.ready[k].u64 as usize;
        if slot < self.conns.len() {
            Some(slot)
        } else {
            None
        }
    }

    /// Build an engine. The connection table is a `Vec` of small slot
    /// records; write backlogs are allocated per connection on first use,
    /// so the engine's size does not scale with `max_conns * write_buf_max`.
    /// A `max_conns` outside `MAX_CONNS_MIN..=MAX_CONNS_CAP` is refused with
    /// the reason, never adjusted.
    pub fn new(cfg: &Config) -> Result<Box<Self>, String> {
        let max_conns = cfg.max_conns;
        if !(MAX_CONNS_MIN..=MAX_CONNS_CAP).contains(&max_conns) {
            return Err(format!(
                "max_conns {max_conns} is outside [{MAX_CONNS_MIN}, \
                 {MAX_CONNS_CAP}] (the conn id is a u16 and the table needs a \
                 listener and a connection)"
            ));
        }
        let mut conns = Vec::with_capacity(max_conns);
        for _ in 0..max_conns {
            conns.push(Conn::empty());
        }
        // SAFETY: plain libc calls with no pointer arguments.
        let (epfd, bell) = unsafe {
            (
                libc::epoll_create1(libc::EPOLL_CLOEXEC),
                libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK),
            )
        };
        if epfd < 0 {
            log::error!("[linux_net] epoll_create1 failed; sockets will never report ready");
        } else if bell >= 0 {
            let mut ev = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: RESOLVER_TOKEN,
            };
            // SAFETY: two descriptors this engine owns and a live event.
            unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, bell, &mut ev) };
        }
        let mut ready = Vec::with_capacity(READY_BATCH);
        for _ in 0..READY_BATCH {
            ready.push(libc::epoll_event { events: 0, u64: 0 });
        }
        Ok(Box::new(Self {
            conns,
            endpoint_slots: Vec::new(),
            write_buf_max: cfg.write_buf_max.max(1),
            listen_backlog: cfg.listen_backlog.max(1),
            epfd,
            resolver_bell: bell,
            ready,
            ready_len: 0,
            cmd_buf: Box::new([0u8; CMD_MAX]),
            msg_buf: Box::new([0u8; 16384]),
            recv_buf: Box::new([0u8; 16384]),
            hold_slot: -1,
            hold_off: 0,
            hold_len: 0,
            hold_lane: 0,
            // Skip slot 0 in initial rotation — it's almost always the
            // TCP listener bound by the first CMD_BIND.
            next_alloc: 1,
            lanes: Vec::new(),
            order: Vec::new(),
            resolver: None,
            resolve_seq: 0,
            warming: Vec::new(),
            resolving: 0,
            dns_cache: Vec::new(),
            ctrl_refused: 0,
            dg_rx_dropped: 0,
            moved: false,
            holding: false,
        }))
    }

    /// Whether `lane` takes another command record now: it exists and holds
    /// fewer than its inbox's worth. One it does not take stays on its ring,
    /// back-pressuring its producer.
    pub fn takes(&self, lane: usize) -> bool {
        self.inbox(lane).is_some_and(Inbox::has_room)
    }

    /// The lane index of lane `key`.
    pub fn lane_of_key(&self, key: u8) -> Option<usize> {
        self.lanes
            .iter()
            .position(|a| a.as_ref().is_some_and(|a| a.key == key))
    }

    /// A command record (`[type][len:u16][payload]`) arrived on `lane`.
    pub fn offer(&mut self, lane: usize, rec: &[u8]) {
        if let Some(b) = self.inbox_mut(lane) {
            b.push(rec);
        }
    }

    /// What `lane`'s owner may claim (`control::gate` flags, its whole
    /// grant set). A lane's commands wait for its
    /// first gate; its owner is the one it was attached for, whatever a gate
    /// names.
    pub fn gate(&mut self, lane: usize, flags: u8, grants: &[u8]) {
        if let Some(Some(a)) = self.lanes.get_mut(lane) {
            a.gate = Some(LaneGate {
                flags,
                grants: grants.to_vec(),
            });
        }
    }

    /// Attach lane `key` for `owner`: its lane index. `EEXIST` for a key
    /// attached, `ENOSPC` when every lane is taken.
    pub fn attach(&mut self, key: u8, owner: Owner) -> Result<usize, i32> {
        if self.lane_of_key(key).is_some() {
            return Err(fluxor_abi::errno::EEXIST);
        }
        let j = match self.lanes.iter().position(Option::is_none) {
            Some(j) => j,
            None if self.lanes.len() < MAX_LANES => {
                self.lanes.push(None);
                self.lanes.len() - 1
            }
            None => {
                log::warn!(
                    "[linux_net] owner slot {} lane {key} refused: all {MAX_LANES} lanes taken",
                    owner.slot
                );
                return Err(fluxor_abi::errno::ENOSPC);
            }
        };
        self.lanes[j] = Some(Lane {
            key,
            owner,
            gate: None,
            inbox: Inbox::default(),
            out: Outq::new(),
            pending: PendingCtrl::new(),
        });
        self.order.push(j);
        log::info!(
            "[linux_net] owner slot {} lane {key} attached as lane {j}",
            owner.slot
        );
        Ok(j)
    }

    /// Detach lane `key`: drop what was queued for it and close every slot
    /// it created, without a word to it (its rings go with it). A no-op for
    /// a key not attached.
    pub fn detach(&mut self, key: u8) {
        let Some(lane) = self.lane_of_key(key) else {
            return;
        };
        let owner = self.lanes[lane].as_ref().map_or(Owner::NODE, |a| a.owner);
        self.lanes[lane] = None;
        self.order.retain(|&j| j != lane);
        // SAFETY: the engine's own descriptors.
        unsafe { close_lane_conns(self, lane) };
        log::info!("[linux_net] owner slot {} lane {lane} detached", owner.slot);
    }

    /// Lane `key`'s owner is draining: it binds nothing new.
    pub fn drain(&mut self, key: u8) {
        if let Some(lane) = self.lane_of_key(key) {
            if let Some(Some(a)) = self.lanes.get_mut(lane) {
                if let Some(g) = a.gate.as_mut() {
                    g.flags &= !gate::OPEN;
                }
            }
        }
    }

    /// Close every connection slot stamped with `owner`: the owner is
    /// freed, and its ports are free once this returns.
    pub fn close_owner_conns(&mut self, owner: Owner) {
        let mut resolving_freed = 0usize;
        for (i, conn) in self.conns.iter_mut().enumerate() {
            if conn.state != 0 && conn.owner == owner {
                if conn.state == 5 {
                    resolving_freed += 1;
                }
                // SAFETY: descriptors this engine opened and owns.
                unsafe {
                    if conn.fd >= 0 {
                        libc::close(conn.fd);
                        log::info!(
                            "[linux_net] closed slot {i} (owner slot {} revoked)",
                            owner.slot
                        );
                    }
                    for &fd in &conn.racing {
                        libc::close(fd);
                    }
                }
                *conn = Conn::empty();
            }
        }
        self.resolving = self.resolving.saturating_sub(resolving_freed);
    }

    /// The bound endpoints, into `out`: `(owner, protocol, port)` for every
    /// live listener and datagram endpoint, in the order they were bound;
    /// `protocol` is the IP protocol number (`net_proto::grant::PROTO_*`).
    /// Costs a look at each endpoint, not at every connection slot.
    pub fn bound_endpoints(&mut self, out: &mut Vec<(Owner, u8, u16)>) {
        out.clear();
        let conns = &self.conns;
        self.endpoint_slots.retain(|&i| {
            let Some(conn) = conns.get(usize::from(i)) else {
                return false;
            };
            if conn.state != 3 || conn.fd < 0 || conn.port == 0 {
                return false;
            }
            let proto = match conn.conn_type {
                1 => np::grant::PROTO_TCP,
                CONN_TYPE_UDP_BOUND => np::grant::PROTO_UDP,
                _ => return false,
            };
            out.push((conn.owner, proto, conn.port));
            true
        });
    }

    /// Slot `idx` now holds a bound listener or datagram endpoint.
    fn endpoint_bound(&mut self, idx: usize) {
        let i = idx as u16;
        if !self.endpoint_slots.contains(&i) {
            self.endpoint_slots.push(i);
        }
    }

    /// What wakes the serve loop for the engine: its epoll set (sockets and
    /// the resolver) unless the last step held something back, and its next
    /// deadline.
    pub fn wake(&self) -> (Option<RawFd>, Duration) {
        let timed = self.resolving > 0
            || self
                .conns
                .iter()
                .any(|c| c.state == 1 || c.state == 4 || c.peer_fin || c.close_when_drained);
        let within = if timed {
            Duration::from_millis(5)
        } else {
            Duration::from_secs(1)
        };
        let fd = (!self.holding && self.epfd >= 0).then_some(self.epfd);
        (fd, within)
    }

    /// Hand every record the last step planned to `put` with its lane's
    /// key, lane by lane in attach order and each lane's in the order
    /// planned. Each was planned against what its ring could take, so each
    /// is taken.
    pub fn drain_out(&mut self, put: &mut dyn FnMut(u8, &[u8])) {
        for &j in &self.order {
            if let Some(a) = self.lanes[j].as_mut() {
                while let Some(r) = a.out.recs.pop_front() {
                    put(a.key, &r);
                }
            }
        }
    }

    fn inbox(&self, lane: usize) -> Option<&Inbox> {
        self.lanes.get(lane)?.as_ref().map(|a| &a.inbox)
    }

    fn inbox_mut(&mut self, lane: usize) -> Option<&mut Inbox> {
        self.lanes.get_mut(lane)?.as_mut().map(|a| &mut a.inbox)
    }

    fn lane_gate(&self, lane: usize) -> Option<&LaneGate> {
        self.lanes.get(lane)?.as_ref()?.gate.as_ref()
    }

    /// The planned records of `lane`'s events. `None` for no lane.
    fn lane_out_q(&mut self, lane: usize) -> Option<&mut Outq> {
        self.lanes
            .get_mut(lane)
            .and_then(|a| a.as_mut())
            .map(|a| &mut a.out)
    }

    /// Plan one whole event record for `lane`; `false` when its ring has no
    /// room for it whole now.
    fn emit(&mut self, lane: usize, rec: &[u8]) -> bool {
        let put = self.lane_out_q(lane).is_some_and(|q| q.put(rec));
        self.moved |= put;
        put
    }

    /// [`Sockets::emit`] of `msg_buf[..len]`.
    fn emit_scratch(&mut self, lane: usize, len: usize) -> bool {
        let Sockets {
            msg_buf,
            lanes,
            moved,
            ..
        } = self;
        let q = match lanes.get_mut(lane).and_then(|a| a.as_mut()) {
            Some(a) => &mut a.out,
            None => return false,
        };
        let put = q.put(&msg_buf[..len]);
        *moved |= put;
        put
    }

    /// Bytes of `MSG_DATA` frames `lane`'s events can take now.
    fn room(&mut self, lane: usize) -> usize {
        self.lane_out_q(lane).map_or(0, |q| q.room())
    }

    /// The control-frame (MSG_CONNECTED / CLOSED / ERROR / BOUND) retry
    /// queue of `lane`'s events: a ring is all-or-nothing, and a tiny
    /// control frame it is momentarily too full for would otherwise be
    /// dropped, stranding a waiter, so it waits here and is flushed before
    /// each step. At `PENDING_CTRL_CAP` the lane's sources pause; nothing
    /// queued is evicted. Each lane queues on its own, so one consumer that
    /// falls behind holds up only its own terminal results. `None` for an
    /// index with no lane.
    fn lane_queue(&mut self, lane: usize) -> Option<&mut PendingCtrl> {
        self.lanes
            .get_mut(lane)
            .and_then(|a| a.as_mut())
            .map(|a| &mut a.pending)
    }

    /// Flush `lane`'s queued control frames; stops at the first one its
    /// destination can't take so ordering is preserved. Returns true if the
    /// queue is now empty.
    fn flush_lane(&mut self, lane: usize) -> bool {
        loop {
            let Some(q) = self.lane_queue(lane) else {
                return true;
            };
            let Some(&(frame, len)) = q.front() else {
                return true;
            };
            if !self.emit(lane, &frame[..len]) {
                return false;
            }
            if let Some(q) = self.lane_queue(lane) {
                q.pop_front();
            }
        }
    }

    /// Flush every destination's queued control frames, each on its own so
    /// a full one holds up only its own. Returns true if all are empty.
    fn flush_pending_ctrl(&mut self) -> bool {
        let mut all_empty = true;
        for k in 0..self.order.len() {
            all_empty &= self.flush_lane(self.order[k]);
        }
        all_empty
    }
}

impl Drop for Sockets {
    /// The engine's sockets, its epoll set and its resolver's doorbell
    /// close with it.
    fn drop(&mut self) {
        for conn in self.conns.iter_mut() {
            // SAFETY: descriptors this engine opened and owns.
            unsafe {
                if conn.fd >= 0 {
                    libc::close(conn.fd);
                }
                for &fd in &conn.racing {
                    libc::close(fd);
                }
            }
            *conn = Conn::empty();
        }
        // The resolver thread may still ring the bell: its queue goes
        // first, so it finds nobody waiting and ends.
        self.resolver = None;
        // SAFETY: as above.
        unsafe {
            if self.epfd >= 0 {
                libc::close(self.epfd);
            }
        }
    }
}

/// The owner a lane's commands run as: the one it was attached for. A lane
/// is served only while attached, so a lane index with none never acts.
fn lane_owner(st: &Sockets, lane: usize) -> Owner {
    st.lanes
        .get(lane)
        .and_then(|a| a.as_ref())
        .map_or(Owner::NODE, |a| a.owner)
}

/// Whether a command on `lane` may act on slot `idx`: a lane reaches only
/// the slots it created, and no other lane reaches those.
fn lane_may_touch(st: &Sockets, lane: usize, idx: usize) -> bool {
    let Some(c) = st.conns.get(idx) else {
        return true; // no such slot: the handler ignores it
    };
    c.state == 0 || c.lane as usize == lane
}

/// Close every slot `lane` created, without a word to the lane: it is being
/// detached, and its events go with it. Drops a recv tail held
/// for it, whose bytes have nowhere left to go.
unsafe fn close_lane_conns(st: &mut Sockets, lane: usize) {
    let mut resolving_freed = 0usize;
    for (i, conn) in st.conns.iter_mut().enumerate() {
        if conn.state == 0 || conn.lane as usize != lane {
            continue;
        }
        if conn.state == 5 {
            resolving_freed += 1;
        }
        if conn.fd >= 0 {
            libc::close(conn.fd);
        }
        for &fd in &conn.racing {
            libc::close(fd);
        }
        log::info!("[linux_net] closed slot {i} (lane {lane} detached)");
        *conn = Conn::empty();
    }
    st.resolving = st.resolving.saturating_sub(resolving_freed);
    if st.hold_slot >= 0 && st.hold_lane == lane {
        st.hold_slot = -1;
        st.hold_off = 0;
        st.hold_len = 0;
    }
}

unsafe fn set_nonblocking(fd: i32) {
    let flags = libc::fcntl(fd, libc::F_GETFL);
    if flags >= 0 {
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

fn alloc_conn(st: &mut Sockets) -> i32 {
    alloc_conn_below(st, st.conns.len())
}

/// A free slot below `limit`, round-robin as [`alloc_conn`]: a datagram
/// endpoint's id is a byte, so it takes a slot below [`DG_ENDPOINT_SLOTS`].
fn alloc_conn_below(st: &mut Sockets, limit: usize) -> i32 {
    // Round-robin from `next_alloc`. After allocating slot N, advance
    // `next_alloc` to N+1 so the same slot isn't picked again until the
    // table has cycled — by that time any stale CMD_SEND bytes for the
    // previous occupant have been drained and harmlessly dropped (they
    // hit `state == 0` and exit early).
    let n = st.conns.len();
    let limit = limit.min(n);
    if limit == 0 {
        return -1;
    }
    let start = st.next_alloc % limit;
    for off in 0..limit {
        let i = (start + off) % limit;
        if st.conns[i].state == 0 {
            st.next_alloc = (i + 1) % n;
            return i as i32;
        }
    }
    -1
}

/// Emit one control frame, `[type][payload]`, to `lane`'s events:
/// the lane a slot's events belong to, or the lane whose command a
/// slot-less result answers. Every control frame fits a queue slot, checked
/// at compile time, so none can be too large to build. Ordering is per
/// destination: a frame that cannot be written now, or that would overtake
/// one already queued, is queued behind it. Nothing queued is evicted; the
/// lane's sources pause at [`PENDING_CTRL_CAP`] instead, and a frame that
/// finds the queue at [`Sockets::pending_ctrl_ceiling`] is counted and
/// logged.
unsafe fn send_msg<const N: usize>(st: &mut Sockets, lane: usize, data: &[u8; N]) {
    const {
        assert!(
            N >= 1 && N + 2 <= CTRL_FRAME_MAX,
            "a control frame must fit a queue slot"
        );
    }
    if st.lane_queue(lane).is_none() {
        return;
    }
    let payload_len = (N - 1) as u16;
    let total = N + 2;
    let mut frame = [0u8; CTRL_FRAME_MAX];
    frame[0] = data[0];
    frame[1] = payload_len as u8;
    frame[2] = (payload_len >> 8) as u8;
    frame[3..total].copy_from_slice(&data[1..]);
    let queued_empty = st.flush_lane(lane);
    if queued_empty && st.emit(lane, &frame[..total]) {
        return;
    }
    let ceiling = st.pending_ctrl_ceiling();
    let queued = match st.lane_queue(lane) {
        Some(q) if q.len() < ceiling => {
            q.push_back((frame, total));
            true
        }
        _ => false,
    };
    if !queued {
        st.ctrl_refused += 1;
        log::error!(
            "[linux_net] lane {lane}: control frame 0x{:02x} refused, its queue is at its \
             ceiling of {ceiling} ({} refused)",
            data[0],
            st.ctrl_refused
        );
    }
}

/// `MSG_ERROR [conn_id: u16 LE][errno][requester_tag: u16 LE]`, framed for
/// `send_msg`: with a tag, the terminal result of a failed dial;
/// with tag 0, an established connection's or a bind's error.
fn error_frame(conn_id: u16, errno: u8, tag: np::RequesterTag) -> [u8; 1 + np::ERROR_LEN] {
    let mut m = [0u8; 1 + np::ERROR_LEN];
    m[0] = MSG_ERROR;
    m[1..].copy_from_slice(&np::error(conn_id, errno as i8, tag));
    m
}

/// A transport reports no session facts and grants no sideband: it serves
/// none (`net_proto::flag`). The host's TCP keeps its own copy of what is
/// sent, so no stream here is ever offered `stream_retx`.
const OPENING: np::Opening<'static> = np::Opening::PLAIN;

/// Whether a `CMD_BIND` / `CMD_CONNECT_TO` request's flags are ones the
/// contract defines (a defined bit this provider does not serve is simply
/// not granted).
fn flags_defined(flags: u8) -> bool {
    flags & !np::flag::REQUESTABLE == 0
}

/// Report stream `conn_id`'s peer (`MSG_PEER`), the socket's remote end,
/// queued after the `MSG_ACCEPTED` / `MSG_CONNECTED` it follows and ahead of
/// the stream's data.
unsafe fn send_peer(st: &mut Sockets, lane: usize, conn_id: usize, fd: i32) {
    let mut ss: libc::sockaddr_storage = core::mem::zeroed();
    let mut len = core::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if libc::getpeername(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut len) != 0 {
        return;
    }
    let mut addr = [0u8; 16];
    let (family, port) = match ss.ss_family as i32 {
        libc::AF_INET => {
            let a = &*(&ss as *const _ as *const libc::sockaddr_in);
            addr[..4].copy_from_slice(&a.sin_addr.s_addr.to_ne_bytes());
            (np::AF_INET, u16::from_be(a.sin_port))
        }
        libc::AF_INET6 => {
            let a = &*(&ss as *const _ as *const libc::sockaddr_in6);
            addr = a.sin6_addr.s6_addr;
            (np::AF_INET6, u16::from_be(a.sin6_port))
        }
        _ => return,
    };
    let mut frame = [0u8; 3 + np::PEER_LEN];
    if np::write_peer(&mut frame, conn_id as u16, family, &addr, port).is_none() {
        return;
    }
    // `send_msg` takes `[type][payload]` and frames it.
    let mut msg = [0u8; 1 + np::PEER_LEN];
    msg[0] = np::MSG_PEER;
    msg[1..].copy_from_slice(&frame[3..]);
    send_msg(st, lane, &msg);
}

/// `MSG_CONNECTED [conn_id][requester_tag][flags_granted][generation]
/// [alpn_len]`, framed for `send_msg`.
fn connected_frame(conn_id: [u8; 2], tag: np::RequesterTag) -> [u8; 1 + np::CONNECTED_FIXED] {
    let mut m = [0u8; 1 + np::CONNECTED_FIXED];
    m[0] = MSG_CONNECTED;
    let c = np::Connected {
        conn_id: u16::from_le_bytes(conn_id),
        requester_tag: tag,
        opening: OPENING,
    };
    let _ = np::put_connected(&mut m[1..], &c);
    m
}

/// `MSG_ACCEPTED [conn_id][local_port][flags_granted][generation]
/// [alpn_len]`, framed for `send_msg`.
fn accepted_frame(conn_id: u16, local_port: u16) -> [u8; 1 + np::ACCEPTED_FIXED] {
    let mut m = [0u8; 1 + np::ACCEPTED_FIXED];
    m[0] = MSG_ACCEPTED;
    let a = np::Accepted {
        conn_id,
        local_port,
        opening: OPENING,
    };
    let _ = np::put_accepted(&mut m[1..], &a);
    m
}

/// `MSG_BOUND [conn_id][local_port][flags_granted]`, framed for
/// `send_msg`.
fn bound_frame(conn_id: u16, local_port: u16) -> [u8; 1 + np::BOUND_LEN] {
    let mut m = [0u8; 1 + np::BOUND_LEN];
    m[0] = MSG_BOUND;
    m[1..].copy_from_slice(&np::bound(conn_id, local_port, OPENING.flags_granted));
    m
}

/// A stream bind failed or was refused: `MSG_ERROR` with no connection and
/// no tag, so its requester never waits on a `MSG_BOUND` that will not come.
unsafe fn send_bind_refused(st: &mut Sockets, lane: usize, port: u16, errno: u8) {
    log::warn!("[linux_net] lane {lane}: stream bind of port {port} refused (errno {errno})");
    send_msg(st, lane, &error_frame(0, errno, np::REQUESTER_TAG_NONE));
}

/// Emit the datagram contract's `DG_MSG_ERROR [ep_id][errno]` for a failed
/// `DG_CMD_BIND`: `ep_id` 0xFF = no endpoint was allocated.
unsafe fn send_dg_error(st: &mut Sockets, lane: usize, errno: u8) {
    send_dg_ep_error(st, lane, 0xFF, errno);
}

/// `DG_MSG_ERROR [ep_id][errno]` for endpoint `ep` (0xFF: none).
unsafe fn send_dg_ep_error(st: &mut Sockets, lane: usize, ep: u8, errno: u8) {
    let msg = [DG_MSG_ERROR, ep, errno];
    send_msg(st, lane, &msg);
}

/// The bind gate for a NEW bind on `lane`: admission must be open (a
/// draining or paused owner binds nothing new — same-owner re-binds of held
/// ports never reach this, they take the use-class fast path), and a
/// listening bind (a nonzero port) must be one of the owner's
/// `net.endpoint` grants: an owner granted nothing listens nowhere. Port 0
/// (an ephemeral source) claims nothing. The node owner's lanes are ungated.
/// Returns the refusal errno, or None to proceed.
fn new_bind_refusal(st: &Sockets, lane: usize, protocol: u8, port: u16) -> Option<u8> {
    let commander = lane_owner(st, lane);
    if commander.is_node() {
        return None;
    }
    let Some(g) = st.lane_gate(lane) else {
        return Some(1); // EPERM: nothing said yet
    };
    if g.flags & gate::OPEN == 0 {
        log::warn!(
            "[linux_net] bind port {port} refused: owner slot {} draining/revoked",
            commander.slot
        );
        return Some(1); // EPERM
    }
    if port == 0 {
        return None; // an ephemeral source port claims nothing
    }
    if np::grant::grants_endpoint(&g.grants, protocol, port) {
        None
    } else {
        log::warn!(
            "[linux_net] bind port {port} refused: no grant to owner slot {}",
            commander.slot
        );
        Some(13) // EACCES
    }
}

unsafe fn cmd_bind(st: &mut Sockets, port: u16, lane: usize) {
    let commander = lane_owner(st, lane);
    // Embedded IP modules close their listener after each accepted
    // connection; their TCP/IP servers re-issue CMD_BIND between
    // requests. On Linux the listening fd persists, so a re-bind on the
    // same port would fail with EADDRINUSE. Acknowledge the re-bind with
    // MSG_BOUND immediately when an existing listener is alive *for the
    // same port* — but ONLY for the same commanding owner: the fast path
    // was owner-blind and would silently hand one owner's listener to
    // another. Same-owner re-bind is use-class (allowed even while
    // Draining — the accept-loop case); a cross-owner claim on a live
    // listener is refused. So is a claim from another lane: the
    // listener's accepts go to the lane that bound it, never to another.
    for (li, c) in st.conns.iter().enumerate() {
        if c.state == 3 && c.conn_type == 1 && c.fd >= 0 && c.port == port {
            if c.owner == commander && lane_may_touch(st, lane, li) {
                send_msg(st, lane, &bound_frame(li as u16, port));
            } else {
                log::warn!(
                    "[linux_net] bind port {port} refused: held by owner slot {} \
                     (requester owner slot {})",
                    c.owner.slot,
                    commander.slot
                );
                send_bind_refused(st, lane, port, 98); // EADDRINUSE
            }
            return;
        }
    }

    if let Some(errno) = new_bind_refusal(
        st,
        lane,
        fluxor_abi::contracts::net::net_proto::grant::PROTO_TCP,
        port,
    ) {
        send_bind_refused(st, lane, port, errno);
        return;
    }

    let slot = alloc_conn(st);
    if slot < 0 {
        log::error!("[linux_net] no free slots for listener");
        send_bind_refused(st, lane, port, 105); // ENOBUFS
        return;
    }

    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
    if fd < 0 {
        log::error!("[linux_net] socket() failed");
        send_bind_refused(st, lane, port, 23); // ENFILE
        return;
    }

    let opt: i32 = 1;
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_REUSEADDR,
        &opt as *const i32 as *const libc::c_void,
        4,
    );

    let mut addr: libc::sockaddr_in = core::mem::zeroed();
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = 0;

    if libc::bind(
        fd,
        &addr as *const libc::sockaddr_in as *const libc::sockaddr,
        core::mem::size_of::<libc::sockaddr_in>() as u32,
    ) < 0
    {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        log::error!("[linux_net] bind() failed on port {port} (errno {errno})");
        libc::close(fd);
        send_bind_refused(st, lane, port, errno.clamp(0, 255) as u8);
        return;
    }

    // Backlog 128: the kernel's SYN queue must absorb the entire
    // burst of a high-concurrency connect (clients ramp up
    // simultaneously in benchmarks). At backlog=8 a 32-client burst
    // dropped SYNs 9..=32 — clients saw ConnectionReset on connect.
    if libc::listen(fd, st.listen_backlog) < 0 {
        log::error!("[linux_net] listen() failed");
        libc::close(fd);
        send_bind_refused(st, lane, port, 95); // EOPNOTSUPP
        return;
    }

    set_nonblocking(fd);
    let idx = slot as usize;
    st.conns[idx] = Conn {
        fd,
        conn_type: 1,
        state: 3,
        port,
        owner: commander,
        lane: lane as u16,
        ..Conn::empty()
    };
    st.watch(fd, idx, libc::EPOLLIN as u32);
    st.endpoint_bound(idx);
    // The scenario runner uses this stderr line as its readiness signal. Keep it
    // visible at the default warning log level; an info-only signal makes
    // `fluxor run` kill a healthy, already-listening host after five seconds.
    log::warn!("[linux_net] listening on port {port} (slot {idx})");

    // Consumers sharing net_out filter accepts by the bound port.
    send_msg(st, lane, &bound_frame(idx as u16, port));
}

// ----------------------------------------------------------------------
// Datagram surface — UDP bind / send_to / recvfrom on the same channel
// ----------------------------------------------------------------------

unsafe fn dg_cmd_bind(st: &mut Sockets, port: u16, lane: usize) {
    let commander = lane_owner(st, lane);
    if let Some(errno) = new_bind_refusal(
        st,
        lane,
        fluxor_abi::contracts::net::net_proto::grant::PROTO_UDP,
        port,
    ) {
        send_dg_error(st, lane, errno);
        return;
    }
    let slot = alloc_conn_below(st, DG_ENDPOINT_SLOTS);
    if slot < 0 {
        log::error!("[linux_net] no free endpoint slot for UDP bind");
        send_dg_error(st, lane, 105);
        return;
    }

    let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
    if fd < 0 {
        log::error!("[linux_net] UDP socket() failed");
        send_dg_error(st, lane, 23);
        return;
    }
    let opt: i32 = 1;
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_REUSEADDR,
        &opt as *const i32 as *const libc::c_void,
        4,
    );
    // Each datagram's arrival address, so its answer leaves from it.
    libc::setsockopt(
        fd,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        &opt as *const i32 as *const libc::c_void,
        4,
    );

    let mut addr: libc::sockaddr_in = core::mem::zeroed();
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = 0;

    if libc::bind(
        fd,
        &addr as *const libc::sockaddr_in as *const libc::sockaddr,
        core::mem::size_of::<libc::sockaddr_in>() as u32,
    ) < 0
    {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        log::error!("[linux_net] UDP bind() failed on port {port} (errno {errno})");
        libc::close(fd);
        send_dg_error(st, lane, errno.clamp(0, 255) as u8);
        return;
    }
    set_nonblocking(fd);
    let idx = slot as usize;
    // `port` is recorded: the endpoint report and the bind gate both need it.
    st.conns[idx] = Conn {
        fd,
        conn_type: CONN_TYPE_UDP_BOUND,
        state: 3,
        port,
        owner: commander,
        lane: lane as u16,
        ..Conn::empty()
    };
    st.watch(fd, idx, libc::EPOLLIN as u32);
    st.endpoint_bound(idx);
    log::info!("[linux_net] UDP bound port {port} (slot {idx})");

    // MSG_DG_BOUND payload (datagram contract):
    //   [ep_id: u8] [local_port: u16 LE].
    let mut msg = [0u8; 1 + 3];
    msg[0] = DG_MSG_BOUND;
    msg[1] = idx as u8;
    msg[2] = (port & 0xFF) as u8;
    msg[3] = (port >> 8) as u8;
    send_msg(st, lane, &msg);
}

/// Whether `lane` may send on endpoint `ep`: the slot holds a live bound
/// datagram endpoint, the lane bound it, and the owner the runtime attests
/// for the lane is the one that bound it. Answers `EPERM` on a live endpoint
/// reached from another lane, and nothing at all on a slot that holds no
/// endpoint. Asked BEFORE the destination is read, so an unowned endpoint
/// buys neither a datagram nor a name lookup.
unsafe fn dg_endpoint_admits(st: &mut Sockets, lane: usize, ep: i16) -> bool {
    if ep < 0 || (ep as usize) >= st.conns.len() {
        return false;
    }
    let c = &st.conns[ep as usize];
    if c.state != 3 || c.conn_type != CONN_TYPE_UDP_BOUND || c.fd < 0 {
        return false;
    }
    if c.owner != lane_owner(st, lane) || c.lane as usize != lane {
        send_dg_error(st, lane, 1); // EPERM
        return false;
    }
    true
}

unsafe fn dg_cmd_send_to(st: &mut Sockets, ep: i16, ip: [u8; 4], port: u16, data: &[u8]) {
    if ep < 0 || (ep as usize) >= st.conns.len() {
        return;
    }
    let idx = ep as usize;
    let (state, conn_type, fd) = {
        let c = &st.conns[idx];
        (c.state, c.conn_type, c.fd)
    };
    if state != 3 || conn_type != CONN_TYPE_UDP_BOUND || fd < 0 {
        return;
    }
    let mut addr: libc::sockaddr_in = core::mem::zeroed();
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = u32::from_le_bytes([ip[0], ip[1], ip[2], ip[3]]);
    let from = st.conns[idx]
        .dg_reply_from
        .iter()
        .find(|(a, p, _)| *a == addr.sin_addr.s_addr && *p == port)
        .map(|e| e.2);
    dg_send_from(fd, &addr, from, data);
}

/// Send `data` to `to` on `fd`, from local address `from` (`s_addr`) when
/// given — an answer leaves from the address its question arrived at — and
/// from the route's preferred source otherwise.
unsafe fn dg_send_from(fd: i32, to: &libc::sockaddr_in, from: Option<u32>, data: &[u8]) {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // Room for one `in_pktinfo` control message, aligned as cmsg requires.
    let mut cbuf = [0u64; 8];
    let mut msg: libc::msghdr = core::mem::zeroed();
    msg.msg_name = to as *const libc::sockaddr_in as *mut libc::c_void;
    msg.msg_namelen = core::mem::size_of::<libc::sockaddr_in>() as u32;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(src) = from {
        let space = libc::CMSG_SPACE(core::mem::size_of::<libc::in_pktinfo>() as u32) as usize;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space.min(core::mem::size_of_val(&cbuf)) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        if !c.is_null() {
            (*c).cmsg_level = libc::IPPROTO_IP;
            (*c).cmsg_type = libc::IP_PKTINFO;
            (*c).cmsg_len = libc::CMSG_LEN(core::mem::size_of::<libc::in_pktinfo>() as u32) as _;
            let info = libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: libc::in_addr { s_addr: src },
                ipi_addr: libc::in_addr { s_addr: 0 },
            };
            core::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut libc::in_pktinfo, info);
        }
    }
    libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL);
}

/// The local address a datagram arrived at, from its `IP_PKTINFO`: the
/// header's destination when it is a unicast one, else the address the host
/// would answer a broadcast or multicast from.
unsafe fn dg_arrival_addr(msg: &libc::msghdr) -> Option<u32> {
    let mut c = libc::CMSG_FIRSTHDR(msg);
    while !c.is_null() {
        if (*c).cmsg_level == libc::IPPROTO_IP && (*c).cmsg_type == libc::IP_PKTINFO {
            let info = core::ptr::read_unaligned(libc::CMSG_DATA(c) as *const libc::in_pktinfo);
            let dst = info.ipi_addr.s_addr;
            let first = dst.to_le_bytes()[0];
            let unicast = dst != 0 && dst != u32::MAX && !(224..=239).contains(&first);
            let a = if unicast {
                dst
            } else {
                info.ipi_spec_dst.s_addr
            };
            return (a != 0).then_some(a);
        }
        c = libc::CMSG_NXTHDR(msg, c);
    }
    None
}

/// Remember that `peer` reached `conn` at local address `local`.
fn dg_note_arrival(conn: &mut Conn, peer: (u32, u16), local: u32) {
    let v = &mut conn.dg_reply_from;
    if let Some(at) = v.iter().position(|(a, p, _)| (*a, *p) == peer) {
        v.remove(at);
    } else if v.len() >= DG_REPLY_FROM_MAX {
        v.remove(0);
    }
    v.push((peer.0, peer.1, local));
}

unsafe fn dg_cmd_close(st: &mut Sockets, lane: usize, ep: i16) {
    if ep < 0 || (ep as usize) >= st.conns.len() {
        return;
    }
    let idx = ep as usize;
    // Close is the destructive half of the same authority question as send.
    if st.conns[idx].conn_type == CONN_TYPE_UDP_BOUND
        && (st.conns[idx].owner != lane_owner(st, lane) || st.conns[idx].lane as usize != lane)
    {
        send_dg_error(st, lane, 1); // EPERM
        return;
    }
    if st.conns[idx].fd >= 0 && st.conns[idx].conn_type == CONN_TYPE_UDP_BOUND {
        libc::close(st.conns[idx].fd);
    }
    st.conns[idx] = Conn::empty();

    send_msg(st, lane, &[DG_MSG_CLOSED, idx as u8]);
}

unsafe fn dg_poll_recv(st: &mut Sockets) -> bool {
    // `DG_MSG_RX_FROM [ep_id][af = 4][src_addr: 4 BE][src_port: u16 LE][data]`,
    // built whole in `msg_buf`: the datagram is received straight after its
    // header, so the largest one delivered is what one frame there carries.
    const HDR: usize = 3 + 1 + 1 + 4 + 2;
    let mut had_work = false;
    let mut k = 0;
    while k < st.ready_len {
        let Some(i) = st.ready_slot(k) else {
            k += 1;
            continue;
        };
        if st.conns[i].conn_type == CONN_TYPE_UDP_BOUND
            && st.conns[i].state == 3
            && st.conns[i].fd >= 0
        {
            let mut from: libc::sockaddr_in = core::mem::zeroed();
            // A datagram is delivered only while its frame fits `net_out`'s
            // `max_record`; a larger one arrives truncated and is dropped.
            let mut iov = libc::iovec {
                iov_base: st.msg_buf.as_mut_ptr().add(HDR) as *mut libc::c_void,
                iov_len: st.msg_buf.len().min(OUT_MAX_RECORD) - HDR,
            };
            let mut cbuf = [0u64; 8];
            let mut mh: libc::msghdr = core::mem::zeroed();
            mh.msg_name = &mut from as *mut libc::sockaddr_in as *mut libc::c_void;
            mh.msg_namelen = core::mem::size_of::<libc::sockaddr_in>() as u32;
            mh.msg_iov = &mut iov;
            mh.msg_iovlen = 1;
            mh.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
            mh.msg_controllen = core::mem::size_of_val(&cbuf) as _;
            let n = libc::recvmsg(st.conns[i].fd, &mut mh, 0);
            if n > 0 {
                let n = n as usize;
                let port = u16::from_be(from.sin_port);
                if let Some(local) = dg_arrival_addr(&mh) {
                    dg_note_arrival(&mut st.conns[i], (from.sin_addr.s_addr, port), local);
                }
                let lane = st.conns[i].lane as usize;
                let total = HDR + n;
                let delivered = if mh.msg_flags & libc::MSG_TRUNC != 0 {
                    // Larger than a frame carries: a cut datagram is never
                    // delivered as if it were whole.
                    false
                } else {
                    let payload_len = (total - 3) as u16;
                    let ip_b = from.sin_addr.s_addr.to_le_bytes();
                    let pb = port.to_le_bytes();
                    st.msg_buf[..HDR].copy_from_slice(&[
                        DG_MSG_RX_FROM,
                        payload_len as u8,
                        (payload_len >> 8) as u8,
                        i as u8,
                        DG_AF_INET,
                        ip_b[0],
                        ip_b[1],
                        ip_b[2],
                        ip_b[3],
                        pb[0],
                        pb[1],
                    ]);
                    // A datagram never overtakes a queued control frame (the
                    // endpoint's own DG_MSG_BOUND among them).
                    st.flush_lane(lane) && st.emit_scratch(lane, total)
                };
                if !delivered {
                    // UDP may drop; it is never dropped uncounted.
                    st.conns[i].dg_rx_dropped += 1;
                    st.dg_rx_dropped += 1;
                    if st.dg_rx_dropped.is_power_of_two() {
                        log::warn!(
                            "[linux_net] datagram endpoint {i}: {} arrival(s) not delivered \
                             ({} over every endpoint; the latest {n} B{})",
                            st.conns[i].dg_rx_dropped,
                            st.dg_rx_dropped,
                            if mh.msg_flags & libc::MSG_TRUNC != 0 {
                                ", larger than a frame"
                            } else {
                                ", its consumer's lane full"
                            }
                        );
                    }
                }
                had_work = true;
            }
        }
        k += 1;
    }
    had_work
}

/// The dial. Literals dial at once; a name is served from the cache or
/// parked in a `resolving` slot (state 5, no fd) until the resolver thread
/// answers, at which point it takes the same path a literal does.
unsafe fn cmd_connect_to(
    st: &mut Sockets,
    sock_type: u8,
    port: u16,
    target: fluxor_abi::contracts::net::net_proto::Target<'_>,
    tag: fluxor_abi::contracts::net::net_proto::RequesterTag,
    lane: usize,
) {
    use fluxor_abi::contracts::net::net_proto::Target;
    // STREAM-only surface (the net_proto stream surface). Datagram traffic uses
    // the datagram surface (CMD_DG_BIND / CMD_DG_SEND_TO), so a non-stream
    // sock_type is rejected with EINVAL — matching the bare-metal IP module
    // and the public contract.
    const SOCK_TYPE_STREAM: u8 = 1;
    if sock_type != SOCK_TYPE_STREAM {
        let msg = error_frame(0, 22u8, tag); // EINVAL, no slot allocated (conn 0, u16 LE)
        send_msg(st, lane, &msg);
        return;
    }
    let addrs = match target {
        Target::V4(a) => Some(vec![Resolved::V4(a)]),
        Target::V6(a) => Some(vec![Resolved::V6(a)]),
        Target::Name(name) => st.dns_cache_get(name),
    };
    let slot = alloc_conn(st);
    if slot < 0 {
        log::error!("[linux_net] no free connection slots");
        // Tagged terminal result (ENOMEM) so the requester completes.
        let msg = error_frame(0, 12u8, tag);
        send_msg(st, lane, &msg);
        return;
    }
    let idx = slot as usize;
    let owner = lane_owner(st, lane);
    match addrs {
        Some(addrs) if !addrs.is_empty() => {
            let mut addrs = dial_candidates(addrs);
            let first = addrs.remove(0);
            let dial = Dial {
                sock_type,
                alts: addrs,
                port,
                tag,
                owner,
                lane: lane as u16,
                racing: Vec::new(),
            };
            start_dial(st, idx, first, dial);
        }
        _ => {
            let Target::Name(name) = target else {
                unreachable!("a literal always has an address");
            };
            match st.resolve_async(name, Some(idx), false) {
                Some(id) => {
                    st.resolving += 1;
                    st.conns[idx] = Conn {
                        fd: -1,
                        conn_type: sock_type,
                        state: 5,
                        port,
                        connect_tag: tag,
                        resolve_id: id,
                        resolve_started: Some(std::time::Instant::now()),
                        owner,
                        lane: lane as u16,
                        ..Conn::empty()
                    };
                }
                None => {
                    st.conns[idx] = Conn::empty();
                    let msg = error_frame(0, 2u8, tag); // ENOENT
                    send_msg(st, lane, &msg);
                }
            }
        }
    }
}

/// One posted result, or `None` when the queue is empty — or the thread is
/// gone, in which case the queue is dropped with it.
fn take_resolved(st: &mut Sockets) -> Option<ResolveDone> {
    match st.resolver.as_ref()?.done.try_recv() {
        Ok(d) => Some(d),
        Err(std::sync::mpsc::TryRecvError::Empty) => None,
        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
            st.resolver = None;
            st.warming.clear();
            None
        }
    }
}

/// Take the results the resolver thread has posted since the last step.
/// A stream result lands in the slot that is still waiting on it (matched
/// by id, so a revoked-and-retaken slot never receives someone else's
/// address); a datagram result only warms the cache.
unsafe fn drain_resolved(st: &mut Sockets) -> bool {
    let mut had_work = false;
    while let Some(done) = take_resolved(st) {
        had_work = true;
        if done.slot.is_none() {
            st.warming.retain(|n| *n != done.name);
        }
        // The candidates are chosen once, and the cache holds exactly them,
        // so a name answered from cache dials as a fresh one does.
        let result = done.result.map(dial_candidates);
        if let Ok(addrs) = &result {
            st.dns_cache_put(done.name.clone(), addrs.clone());
        }
        let Some(idx) = done.slot else {
            continue;
        };
        if idx >= st.conns.len() || st.conns[idx].state != 5 || st.conns[idx].resolve_id != done.id
        {
            continue; // stale: the slot was revoked while the lookup ran
        }
        st.resolving = st.resolving.saturating_sub(1);
        let (sock_type, port, tag, owner, lane) = {
            let c = &st.conns[idx];
            (c.conn_type, c.port, c.connect_tag, c.owner, c.lane)
        };
        match result {
            Ok(addrs) if !addrs.is_empty() => {
                let mut addrs = addrs;
                let first = addrs.remove(0);
                let dial = Dial {
                    sock_type,
                    alts: addrs,
                    port,
                    tag,
                    owner,
                    lane,
                    racing: Vec::new(),
                };
                start_dial(st, idx, first, dial);
            }
            Ok(_) => {
                st.conns[idx] = Conn::empty();
                let msg = error_frame(0, libc::ENOENT as u8, tag);
                send_msg(st, lane as usize, &msg);
            }
            Err(errno) => {
                st.conns[idx] = Conn::empty();
                let msg = error_frame(0, errno as u8, tag);
                send_msg(st, lane as usize, &msg);
            }
        }
    }
    // A slot the resolver never answered for: fail it rather than pin it.
    if st.resolving == 0 {
        return had_work;
    }
    let now = std::time::Instant::now();
    for i in 0..st.conns.len() {
        if st.conns[i].state != 5 {
            continue;
        }
        let Some(started) = st.conns[i].resolve_started else {
            continue;
        };
        if now.duration_since(started) > RESOLVE_GUARD {
            let tag = st.conns[i].connect_tag;
            let lane = st.conns[i].lane as usize;
            st.conns[i] = Conn::empty();
            st.resolving = st.resolving.saturating_sub(1);
            let msg = error_frame(0, 2u8, tag); // ENOENT
            send_msg(st, lane, &msg);
            had_work = true;
        }
    }
    had_work
}

/// Interleave the resolved addresses by family, first of each in turn
/// (RFC 8305 §4).
///
/// `getaddrinfo` groups by family, so a host that answers with four IPv6
/// addresses and one IPv4 would have the ladder spend all its patience on
/// IPv6 before ever reaching the address that works. Alternating means the
/// second rung is always the other family, which is where the answer is when
/// a family is the thing that is broken.
///
/// The host's ordering WITHIN a family is preserved: that part encodes
/// policy this provider has no better view of.
pub fn interleave_families(addrs: Vec<Resolved>) -> Vec<Resolved> {
    let mut first: Vec<Resolved> = Vec::with_capacity(addrs.len());
    let mut second: Vec<Resolved> = Vec::new();
    // Whichever family the host put first keeps the lead: its preference
    // ordering is the one signal available about which is likelier to work.
    let lead_is_v6 = matches!(addrs.first(), Some(Resolved::V6(_)));
    for a in addrs {
        let is_v6 = matches!(a, Resolved::V6(_));
        if is_v6 == lead_is_v6 {
            first.push(a);
        } else {
            second.push(a);
        }
    }
    let mut out = Vec::with_capacity(first.len() + second.len());
    let mut a = first.into_iter();
    let mut b = second.into_iter();
    loop {
        match (a.next(), b.next()) {
            (None, None) => break,
            (x, y) => {
                if let Some(v) = x {
                    out.push(v);
                }
                if let Some(v) = y {
                    out.push(v);
                }
            }
        }
    }
    out
}

/// The addresses a name is dialled at, in dial order: every address the host
/// answered, families interleaved, then cut to [`MAX_DIAL_CANDIDATES`]. The
/// cut comes after the interleave, so a host that answers several addresses
/// of one family ahead of the other is still dialled over both.
pub fn dial_candidates(addrs: Vec<Resolved>) -> Vec<Resolved> {
    let mut out = interleave_families(addrs);
    out.truncate(MAX_DIAL_CANDIDATES);
    out
}

/// One outbound connect as this provider carries it: what the consumer
/// asked for, who to answer, and the addresses the name resolved to that
/// have not been tried yet. Passed whole down the dial ladder so a rung
/// hands the next one everything it needs and nothing it does not.
struct Dial {
    sock_type: u8,
    /// Addresses left to try after the one being dialled now.
    alts: Vec<Resolved>,
    port: u16,
    /// The requester's tag, echoed on the single terminal result.
    tag: fluxor_abi::contracts::net::net_proto::RequesterTag,
    owner: Owner,
    /// The lane that asked, which every result of the dial answers.
    lane: u16,
    /// Attempts already in flight, carried down the ladder so a rung
    /// started on the attempt delay does not abandon the one before it.
    racing: Vec<i32>,
}

/// How long one attempt is given before the next address is tried
/// ALONGSIDE it rather than after it (RFC 8305 §5 calls this the Connection
/// Attempt Delay and recommends 250 ms).
///
/// The sequential ladder alone handles an address that refuses, which is
/// immediate. It does nothing for one that is black-holed — no RST, just
/// silence — where the dial would wait out the whole connect timeout before
/// trying the address that works. That is the case this exists for, and it
/// is the common shape of a broken IPv6 path.
const ATTEMPT_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// Open a socket and start a non-blocking connect to `addr`, answering the
/// fd or `None` when even that could not be done.
///
/// No slot is touched: this is the part the dial ladder and the attempt-delay
/// race both need, and the race needs it WITHOUT the slot bookkeeping because
/// it is adding a second attempt to a slot that already has one.
unsafe fn start_connect(addr: Resolved, port: u16) -> Option<i32> {
    let family = match addr {
        Resolved::V4(_) => libc::AF_INET,
        Resolved::V6(_) => libc::AF_INET6,
    };
    let fd = libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
    if fd < 0 {
        return None;
    }
    set_nonblocking(fd);
    tune_stream(fd);
    let mut sa4: libc::sockaddr_in = core::mem::zeroed();
    let mut sa6: libc::sockaddr_in6 = core::mem::zeroed();
    let (sa_ptr, sa_len): (*const libc::sockaddr, u32) = match addr {
        Resolved::V4(a) => {
            sa4.sin_family = libc::AF_INET as u16;
            sa4.sin_port = port.to_be();
            sa4.sin_addr.s_addr = u32::from_ne_bytes(a);
            (
                &sa4 as *const libc::sockaddr_in as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        }
        Resolved::V6(a) => {
            sa6.sin6_family = libc::AF_INET6 as u16;
            sa6.sin6_port = port.to_be();
            sa6.sin6_addr.s6_addr = a;
            (
                &sa6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_in6>() as u32,
            )
        }
    };
    let ret = libc::connect(fd, sa_ptr, sa_len);
    if ret < 0 && *libc::__errno_location() != libc::EINPROGRESS {
        libc::close(fd);
        return None;
    }
    Some(fd)
}

/// Open the socket for `addr` and start the non-blocking connect into slot
/// `idx`, which the caller has reserved.
///
/// A failure here is not yet the connect's answer: `dial_failed`
/// takes the next candidate and only reports `MSG_ERROR` once none is left,
/// so the requester sees one terminal result however many rungs were tried.
unsafe fn start_dial(st: &mut Sockets, idx: usize, addr: Resolved, dial: Dial) {
    let family = match addr {
        Resolved::V4(_) => libc::AF_INET,
        Resolved::V6(_) => libc::AF_INET6,
    };
    let fd = libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
    if fd < 0 {
        log::error!("[linux_net] socket() failed for connect");
        let errno = *libc::__errno_location();
        dial_failed(st, idx, dial, errno);
        return;
    }

    set_nonblocking(fd);
    tune_stream(fd);

    let mut sa4: libc::sockaddr_in = core::mem::zeroed();
    let mut sa6: libc::sockaddr_in6 = core::mem::zeroed();
    let (sa_ptr, sa_len): (*const libc::sockaddr, u32) = match addr {
        Resolved::V4(a) => {
            sa4.sin_family = libc::AF_INET as u16;
            sa4.sin_port = dial.port.to_be();
            sa4.sin_addr.s_addr = u32::from_ne_bytes(a);
            (
                &sa4 as *const libc::sockaddr_in as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        }
        Resolved::V6(a) => {
            sa6.sin6_family = libc::AF_INET6 as u16;
            sa6.sin6_port = dial.port.to_be();
            sa6.sin6_addr.s6_addr = a;
            (
                &sa6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_in6>() as u32,
            )
        }
    };
    let ret = libc::connect(fd, sa_ptr, sa_len);

    if ret < 0 {
        let errno = *libc::__errno_location();
        if errno != libc::EINPROGRESS {
            libc::close(fd);
            dial_failed(st, idx, dial, errno);
            return;
        }
        st.conns[idx] = Conn {
            fd,
            conn_type: dial.sock_type,
            state: 1,
            port: dial.port,
            connect_tag: dial.tag,
            alts: dial.alts,
            attempt_started: Some(std::time::Instant::now()),
            racing: dial.racing,
            // Stamp the commanding owner so this outbound data conn is torn
            // down with its owner on drain/revoke; otherwise it stays
            // OWNER_NODE and outlives revocation.
            owner: dial.owner,
            lane: dial.lane,
            ..Conn::empty()
        };
        st.watch(fd, idx, (libc::EPOLLOUT | libc::EPOLLIN) as u32);
    } else {
        st.conns[idx] = Conn {
            fd,
            conn_type: dial.sock_type,
            state: 2,
            port: dial.port,
            connect_tag: dial.tag,
            owner: dial.owner,
            lane: dial.lane,
            ..Conn::empty()
        };
        st.watch(fd, idx, libc::EPOLLIN as u32);
        let cb = (idx as u16).to_le_bytes();
        let msg = connected_frame(cb, dial.tag);
        send_msg(st, dial.lane as usize, &msg);
        send_peer(st, dial.lane as usize, idx, fd);
    }
}

/// One rung of the dial ladder failed. Take the next candidate if there is
/// one; otherwise release the slot and give the requester the single
/// terminal `MSG_ERROR` it is owed, carrying the errno of the last address
/// tried. A ladder is invisible to the consumer: it asked for a name, not
/// for an address, and what it gets back is whether the name was reached.
unsafe fn dial_failed(st: &mut Sockets, idx: usize, mut dial: Dial, errno: i32) {
    if !dial.alts.is_empty() {
        let next = dial.alts.remove(0);
        log::debug!(
            "[linux_net] connect failed errno={errno}; {} candidate(s) left",
            dial.alts.len()
        );
        start_dial(st, idx, next, dial);
        return;
    }
    log::error!("[linux_net] connect() failed errno={errno}");
    st.conns[idx] = Conn::empty();
    let msg = error_frame(idx as u16, errno as u8, dial.tag);
    send_msg(st, dial.lane as usize, &msg);
}

/// Send `data` on `conn_id`. The fd is non-blocking, so libc::send may
/// return short or EAGAIN when the kernel buffer is full — anything that
/// doesn't go out immediately gets stashed in the per-connection
/// `write_buf` and drained by `drain_writes` on subsequent
/// steps. The step stops acting on commands while a connection's backlog
/// is full, so the lanes' rings carry the back-pressure to the producers
/// instead of data being dropped.
unsafe fn cmd_send(st: &mut Sockets, conn_id: u16, data: &[u8]) {
    let idx = conn_id as usize;
    if idx >= st.conns.len() || st.conns[idx].state < 2 {
        return;
    }
    let conn = &mut st.conns[idx];
    if conn.fd < 0 {
        return;
    }

    let mut sent_now: usize = 0;
    if conn.write_len == conn.write_offset {
        // No backlog: try a direct send. If it goes out fully, no
        // buffering is needed — common case on fast networks / loopback.
        let n = libc::send(
            conn.fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            libc::MSG_NOSIGNAL,
        );
        if n > 0 {
            sent_now = n as usize;
        } else if n < 0 {
            // Hard send error → peer is gone (EPIPE, ECONNRESET, …).
            // Don't buffer bytes for a dead socket; drop the conn so
            // `drain_writes` doesn't sit on it forever and
            // gate every lane's commands.
            let err = *libc::__errno_location();
            if err != libc::EAGAIN && err != libc::EWOULDBLOCK && err != libc::EINTR {
                // Said out loud: a connection dropped on a send error is
                // indistinguishable, from the peer, from a crash or a
                // firewall.
                log::warn!("[linux_net] dropping conn {conn_id} on send error (errno {err})");
                let fd = conn.fd;
                let lane = conn.lane as usize;
                st.conns[idx] = Conn::empty();
                libc::close(fd);
                let cb = conn_id.to_le_bytes();
                let msg = [MSG_CLOSED, cb[0], cb[1], CLOSED_GONE];
                send_msg(st, lane, &msg);
                return;
            }
        }
    }

    let remaining = data.len().saturating_sub(sent_now);
    if remaining == 0 {
        return;
    }

    // Compact any drained prefix so the new tail starts at offset 0.
    let already = (conn.write_len - conn.write_offset) as usize;
    if conn.write_offset > 0 && already > 0 {
        conn.write_buf
            .copy_within(conn.write_offset as usize..conn.write_len as usize, 0);
    }
    conn.write_len = already as u32;
    conn.write_offset = 0;

    let write_buf_max = st.write_buf_max;
    let conn = &mut st.conns[idx];
    if already + remaining > write_buf_max {
        // Backlog overflow: upstream produced data faster than our
        // sized backlog can absorb. Drop the connection cleanly so
        // the peer fails fast rather than waiting on a stalled stream.
        log::warn!(
            "[linux_net] write backlog overflow on conn {conn_id} ({already} pending + {remaining} new > {write_buf_max})"
        );
        let fd = conn.fd;
        let lane = conn.lane as usize;
        st.conns[idx] = Conn::empty();
        libc::close(fd);
        let cb = conn_id.to_le_bytes();
        let msg = [MSG_CLOSED, cb[0], cb[1], CLOSED_GONE];
        send_msg(st, lane, &msg);
        return;
    }

    // Grown as needed (doubling, to `write_buf_max`) rather than sized to the
    // maximum on the first short send: a large maximum is for the peer that
    // falls far behind, not a cost every briefly-backlogged connection pays.
    let need = already + remaining;
    if conn.write_buf.len() < need {
        let mut cap = conn.write_buf.len().max(64 * 1024);
        while cap < need {
            cap = cap.saturating_mul(2);
        }
        conn.write_buf.resize(cap.min(write_buf_max), 0);
    }
    let dst = &mut conn.write_buf[already..already + remaining];
    dst.copy_from_slice(&data[sent_now..]);
    conn.write_len = (already + remaining) as u32;
}

/// Try to drain any per-connection write backlog. Returns true if any
/// connection's backlog is FULL after the pass — it could not take one more
/// command frame (`backlog_full`) — and the caller defers further commands
/// so the lanes apply back-pressure. Only then: a lane is shared by every
/// connection it opened, so gating on a backlog that is
/// merely large holds up every other connection's commands behind one peer
/// that is slow to read (a watch client busy elsewhere stalled the whole API
/// server's answers that way). A large backlog is buffered instead, up to
/// `write_buf_max`.
///
/// Connections whose `libc::send` returns a hard error (EPIPE,
/// ECONNRESET, EBADF, …) — i.e. the peer is gone — are torn down here
/// rather than left pending forever. Without this the gating signal
/// would stay true, blocking every subsequent command and making
/// the server unable to handle a second connection.
/// A backlog of `pending` bytes that could not take one more command frame
/// (`CMD_MAX`) without passing `write_buf_max`. While one exists no
/// command is read, so a frame that is read always fits and the overflow
/// close in `cmd_send` is reached only when `write_buf_max` itself
/// is smaller than a frame.
fn backlog_full(write_buf_max: usize, pending: usize) -> bool {
    pending > 0 && pending + CMD_MAX > write_buf_max
}

unsafe fn drain_writes(st: &mut Sockets) -> bool {
    let mut heavy_pending = false;
    for i in 0..st.conns.len() {
        let c = &mut st.conns[i];
        if c.fd < 0 || c.write_len == c.write_offset {
            continue;
        }
        let to_send = (c.write_len - c.write_offset) as usize;
        let p = c.write_buf.as_ptr().add(c.write_offset as usize);
        let n = libc::send(c.fd, p as *const libc::c_void, to_send, libc::MSG_NOSIGNAL);
        if n > 0 {
            c.write_offset = c.write_offset.saturating_add(n as u32);
            st.moved = true;
        } else if n < 0 {
            // EAGAIN / EWOULDBLOCK = "kernel buffer full, retry". Any
            // other errno is a dead socket — drop it now so the slot
            // can be reused and `heavy_pending` clears.
            let err = *libc::__errno_location();
            if err != libc::EAGAIN && err != libc::EWOULDBLOCK && err != libc::EINTR {
                log::warn!("[linux_net] dropping conn {i} on drain-write error (errno {err})");
                let fd = c.fd;
                let lane = c.lane as usize;
                let cb = (i as u16).to_le_bytes();
                st.conns[i] = Conn::empty();
                libc::close(fd);
                let msg = [MSG_CLOSED, cb[0], cb[1], CLOSED_GONE];
                send_msg(st, lane, &msg);
                continue;
            }
        }
        let still_pending = (c.write_len - c.write_offset) as usize;
        if backlog_full(st.write_buf_max, still_pending) {
            heavy_pending = true;
        }
        if c.close_when_drained
            && c.close_deadline
                .is_some_and(|t| std::time::Instant::now() >= t)
        {
            log::warn!(
                "[linux_net] conn {i}: closing with {still_pending} bytes undelivered \u{2014} the \
                 peer stopped reading for {CLOSE_DRAIN_MAX_MS}ms"
            );
            let fd = c.fd;
            let lane = c.lane as usize;
            let cb = (i as u16).to_le_bytes();
            st.conns[i] = Conn::empty();
            if fd >= 0 {
                libc::close(fd);
            }
            let msg = [MSG_CLOSED, cb[0], cb[1], CLOSED_GONE];
            send_msg(st, lane, &msg);
            continue;
        }
        if c.write_offset >= c.write_len {
            c.write_offset = 0;
            c.write_len = 0;
            if c.close_when_drained {
                // Everything queued is on the wire: the deferred close runs
                // now, and reports as any other close does.
                let fd = c.fd;
                let lane = c.lane as usize;
                let cb = (i as u16).to_le_bytes();
                st.conns[i] = Conn::empty();
                if fd >= 0 {
                    libc::close(fd);
                }
                let msg = [MSG_CLOSED, cb[0], cb[1], CLOSED_GONE];
                send_msg(st, lane, &msg);
                continue;
            }
        }
    }
    heavy_pending
}

/// The socket is gone (reset, failed, or hung up). Close the fd, report
/// MSG_CLOSED (`CLOSED_GONE`), and HOLD the slot (`state = 4`) rather than freeing it, so the
/// id is not handed to the next accept until the consumer has answered with
/// CMD_CLOSE or the contract's grace interval has passed. Freeing on the
/// spot would let a consumer's CMD_CLOSE close a newcomer that had already
/// taken the index.
unsafe fn hold_closed_slot(st: &mut Sockets, i: usize) {
    if st.conns[i].fd >= 0 {
        libc::close(st.conns[i].fd);
    }
    let owner = st.conns[i].owner;
    let lane = st.conns[i].lane;
    st.conns[i] = Conn::empty();
    st.conns[i].owner = owner;
    st.conns[i].lane = lane;
    st.conns[i].state = 4;
    st.conns[i].release_at = Some(
        std::time::Instant::now() + std::time::Duration::from_millis(u64::from(CLOSED_ID_GRACE_MS)),
    );
    let cb = (i as u16).to_le_bytes();
    let msg = [MSG_CLOSED, cb[0], cb[1], CLOSED_GONE];
    send_msg(st, lane as usize, &msg);
}

/// The peer finished sending (`recv` returned 0): report MSG_CLOSED
/// (`CLOSED_PEER_FIN`) and keep the socket for the consumer to send on. It
/// is no longer read — only a hangup or an error wakes it — and a consumer
/// that has not closed within the grace interval has it closed for it.
unsafe fn peer_finished(st: &mut Sockets, i: usize) {
    let c = &mut st.conns[i];
    c.peer_fin = true;
    c.release_at = Some(
        std::time::Instant::now() + std::time::Duration::from_millis(u64::from(CLOSED_ID_GRACE_MS)),
    );
    let (fd, lane) = (c.fd, c.lane as usize);
    st.rewatch(fd, i, 0);
    let cb = (i as u16).to_le_bytes();
    let msg = [MSG_CLOSED, cb[0], cb[1], CLOSED_PEER_FIN];
    send_msg(st, lane, &msg);
}

/// Release held ids whose grace interval has passed, and close the
/// half-closed connections whose consumer has not.
unsafe fn sweep_held_slots(st: &mut Sockets) {
    let now = std::time::Instant::now();
    for i in 0..st.conns.len() {
        let due = st.conns[i].release_at.is_some_and(|t| now >= t);
        if st.conns[i].state == 4 && due {
            st.conns[i] = Conn::empty();
        } else if st.conns[i].state == 2
            && st.conns[i].peer_fin
            && due
            && !st.conns[i].close_when_drained
        {
            hold_closed_slot(st, i);
        }
    }
}

unsafe fn cmd_close(st: &mut Sockets, conn_id: u16, abort: bool) {
    let idx = conn_id as usize;
    if idx >= st.conns.len() || st.conns[idx].state == 0 {
        return;
    }
    if st.conns[idx].state == 4 {
        // The consumer answered MSG_CLOSED within the grace interval: the id
        // is released now, and MSG_CLOSED is not repeated.
        st.conns[idx] = Conn::empty();
        return;
    }
    if abort && st.conns[idx].fd >= 0 {
        // An abortive close: whatever is queued is dropped and the host
        // resets the connection (`SO_LINGER` zero) instead of a FIN.
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        libc::setsockopt(
            st.conns[idx].fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const libc::linger as *const libc::c_void,
            core::mem::size_of::<libc::linger>() as u32,
        );
        st.conns[idx].write_offset = st.conns[idx].write_len;
    }
    if st.conns[idx].fd >= 0 && st.conns[idx].write_len > st.conns[idx].write_offset {
        // Queued bytes first. The drain sweep finishes the close once they
        // are on the wire; until then the slot stays live so nothing reuses
        // the id, and the consumer is answered `MSG_CLOSED` only when the
        // close has actually happened.
        st.conns[idx].close_when_drained = true;
        st.conns[idx].close_deadline =
            Some(std::time::Instant::now() + std::time::Duration::from_millis(CLOSE_DRAIN_MAX_MS));
        return;
    }
    if st.conns[idx].fd >= 0 {
        libc::close(st.conns[idx].fd);
    }
    if st.conns[idx].state == 5 {
        st.resolving = st.resolving.saturating_sub(1);
    }
    let lane = st.conns[idx].lane as usize;
    st.conns[idx] = Conn::empty();
    let cb = conn_id.to_le_bytes();
    let msg = [MSG_CLOSED, cb[0], cb[1], CLOSED_GONE];
    send_msg(st, lane, &msg);
}

unsafe fn poll_accept(st: &mut Sockets) -> bool {
    let mut had_work = false;

    // Per-listener accept budget: pending connections drained per
    // listener per step. The number binds in both directions. Accept one
    // per step and a 32-client connect burst needs 32 steps (32 ms at a
    // 1 ms step) before the last client is accepted,
    // which outlasts a client's initial HTTP/2 handshake timeout. Accept
    // without a bound and one burst owns the tick. 32 clears a full burst
    // in a single pass while keeping the worst-case per-tick cost bounded
    // (~32 × per-socket setsockopt overhead ≈ a few hundred µs).
    const PER_TICK_ACCEPT_BUDGET: u32 = 32;

    for k in 0..st.ready_len {
        let Some(li) = st.ready_slot(k) else {
            continue;
        };
        if st.conns[li].state != 3 || st.conns[li].conn_type != 1 || st.conns[li].fd < 0 {
            continue;
        }

        let listener_fd = st.conns[li].fd;
        let listener_port = st.conns[li].port;
        // The accepted client inherits the listener's owner so it is torn down
        // with the owner on drain/revoke.
        let listener_owner = st.conns[li].owner;
        // ... and the listener's lane, so its accepts and their data go to
        // the lane that bound it.
        let listener_lane = st.conns[li].lane;
        let mut accepted_on_this_listener: u32 = 0;
        while accepted_on_this_listener < PER_TICK_ACCEPT_BUDGET {
            // A lane whose control queue is full takes no new connection:
            // it would owe an accept the lane cannot yet be told about. The
            // kernel's accept queue holds it until the consumer reads.
            if st.lane_paused(listener_lane as usize) {
                had_work = true;
                break;
            }
            let mut addr: libc::sockaddr_in = core::mem::zeroed();
            let mut addr_len: libc::socklen_t = core::mem::size_of::<libc::sockaddr_in>() as u32;

            let client_fd = libc::accept4(
                listener_fd,
                &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut addr_len,
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            );
            if client_fd < 0 {
                break; // EAGAIN / EWOULDBLOCK — queue drained
            }
            accepted_on_this_listener += 1;
            accept_one_client(st, client_fd, listener_port, listener_owner, listener_lane);
            had_work = true;
        }
    }
    had_work
}

/// The options every TCP stream this provider carries is given, accepted or
/// dialled alike.
unsafe fn tune_stream(fd: i32) {
    // Enable application-friendly TCP keepalive so a silently-dead
    // peer (laptop suspended, NAT timeout without RST) is detected
    // within ~30 s instead of the kernel default ~2 h. Without
    // this, a paused-emulator/idle stream wouldn't trigger the
    // outbound-write cleanup path (no data → no EPIPE) and the
    // slot would stay live until OS keepalive fired.
    let one: i32 = 1;
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_KEEPALIVE,
        &one as *const i32 as *const libc::c_void,
        4,
    );

    // TCP_NODELAY disables Nagle's algorithm, which would otherwise
    // hold small sends until either the kernel ACKs the previous
    // outbound packet or a 200 ms timer fires. Fluxor already does
    // its own segmentation/coalescing per `CMD_SEND`, so Nagle only
    // adds latency. With NODELAY the throughput ceiling is set by
    // `SO_SNDBUF` instead.
    libc::setsockopt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_NODELAY,
        &one as *const i32 as *const libc::c_void,
        4,
    );
    let buf_bytes: i32 = 1 << 20; // 1 MiB
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_SNDBUF,
        &buf_bytes as *const i32 as *const libc::c_void,
        4,
    );
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        &buf_bytes as *const i32 as *const libc::c_void,
        4,
    );
    let idle_secs: i32 = 15;
    libc::setsockopt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPIDLE,
        &idle_secs as *const i32 as *const libc::c_void,
        4,
    );
    let intvl_secs: i32 = 5;
    libc::setsockopt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPINTVL,
        &intvl_secs as *const i32 as *const libc::c_void,
        4,
    );
    let probes: i32 = 3;
    libc::setsockopt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPCNT,
        &probes as *const i32 as *const libc::c_void,
        4,
    );
}

/// Per-accepted-connection setsockopt + slot allocation + MSG_ACCEPTED
/// delivery. Split out of `poll_accept` so the drain loop
/// stays readable.
///
/// `listener_port` is included in the MSG_ACCEPTED payload so
/// consumers that share `net_out` with other anchors (multi-anchor
/// graphs binding distinct ports) can filter on it and only claim
/// their own connections — the broadcast surface would otherwise
/// double-allocate the conn_id across every consumer.
unsafe fn accept_one_client(
    st: &mut Sockets,
    client_fd: i32,
    listener_port: u16,
    owner: Owner,
    lane: u16,
) {
    tune_stream(client_fd);

    let slot = alloc_conn(st);
    if slot < 0 {
        // A connection dropped without a word.
        //
        // This is what a client sees as "peer closed connection" mid-TLS
        // handshake with no alert and no server-side error — the socket is
        // accepted and immediately closed, so from the outside it is
        // indistinguishable from a crash, a firewall, or a protocol bug.
        // Debugging it from the client end is close to impossible, which is
        // how one instance of this went unexplained across an entire
        // programme of work.
        //
        // At `warn`, because a full connection table is not routine: it
        // means the deployment is at its ceiling and refusing work.
        log::warn!(
            "[linux_net] connection table full ({} slots) — \
             refusing an accepted connection on port {listener_port}; the peer \
             will see a close with no alert",
            st.conns.len()
        );
        libc::close(client_fd);
        return;
    }
    let idx = slot as usize;
    st.conns[idx] = Conn {
        fd: client_fd,
        conn_type: 1,
        state: 2,
        owner,
        lane,
        ..Conn::empty()
    };
    st.watch(client_fd, idx, libc::EPOLLIN as u32);

    send_msg(
        st,
        lane as usize,
        &accepted_frame(idx as u16, listener_port),
    );
    send_peer(st, lane as usize, idx, client_fd);
    log::info!("[linux_net] accepted conn_id={idx}");
}

/// Write `recv_buf[from..total]` to `lane`'s events as MSG_DATA
/// frames, returning where it got to.
///
/// A frame write is all-or-nothing, so this stops at the first one that does
/// not fit rather than splitting it. What it returns is the caller's business:
/// the bytes past it have left the kernel's buffer and exist nowhere else.
unsafe fn forward_chunks(
    st: &mut Sockets,
    lane: usize,
    slot: usize,
    from: usize,
    total: usize,
) -> usize {
    // Data never overtakes a queued control frame (an accept and its peer
    // report): it waits, as for a full destination.
    if !st.flush_lane(lane) {
        return from;
    }
    let mut off = from;
    while off < total {
        let chunk = (total - off).min(STREAM_CHUNK);
        let payload_len = 2 + chunk;
        let frame_len = 3 + payload_len;
        if frame_len > st.msg_buf.len() {
            break;
        }
        st.msg_buf[0] = MSG_DATA;
        st.msg_buf[1] = payload_len as u8;
        st.msg_buf[2] = (payload_len >> 8) as u8;
        let cb = (slot as u16).to_le_bytes();
        st.msg_buf[3] = cb[0];
        st.msg_buf[4] = cb[1];
        core::ptr::copy_nonoverlapping(
            st.recv_buf.as_ptr().add(off),
            st.msg_buf.as_mut_ptr().add(5),
            chunk,
        );
        if !st.emit_scratch(lane, frame_len) {
            break;
        }
        off += chunk;
    }
    off
}

unsafe fn poll_recv(st: &mut Sockets) -> bool {
    let mut had_work = false;

    // A tail held from a previous step goes first, and nothing is read until
    // it has gone: `recv_buf` is the only place a read lands, so reading over
    // a tail is how those bytes would be lost. This is the case the whole
    // hold exists for -- a consumer that fell behind, which is every consumer
    // eventually.
    if st.hold_slot >= 0 {
        let slot = st.hold_slot as usize;
        let off = forward_chunks(st, st.hold_lane, slot, st.hold_off, st.hold_len);
        if off < st.hold_len {
            st.hold_off = off;
            return true; // still blocked — keep getting scheduled
        }
        st.hold_slot = -1;
        st.hold_off = 0;
        st.hold_len = 0;
        had_work = true;
    }

    for k in 0..st.ready_len {
        let Some(i) = st.ready_slot(k) else {
            continue;
        };
        if st.conns[i].state != 2 && st.conns[i].state != 1 {
            continue;
        }
        if st.conns[i].fd < 0 {
            continue;
        }
        if st.conns[i].peer_fin {
            // Watched for nothing once the peer finished: what wakes it is a
            // hangup or an error, and the connection is gone.
            hold_closed_slot(st, i);
            had_work = true;
            continue;
        }

        if st.conns[i].state != 2 {
            if st.conns[i].state == 1 {
                // Every attempt in flight for this slot: the current one and
                // any started earlier on the attempt delay. The first to
                // connect wins and the others are closed, so what the
                // consumer sees is one connect that either worked or did not.
                let mut fds: Vec<i32> = Vec::with_capacity(1 + st.conns[i].racing.len());
                fds.push(st.conns[i].fd);
                fds.extend_from_slice(&st.conns[i].racing);
                let mut polls: Vec<libc::pollfd> = fds
                    .iter()
                    .map(|&fd| libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    })
                    .collect();
                let ready = libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, 0);
                let mut winner: Option<i32> = None;
                let mut last_err = 0i32;
                let mut dead: Vec<i32> = Vec::new();
                if ready > 0 {
                    for p in &polls {
                        if p.revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) == 0 {
                            continue;
                        }
                        let mut err: i32 = 0;
                        let mut errlen: libc::socklen_t = 4;
                        libc::getsockopt(
                            p.fd,
                            libc::SOL_SOCKET,
                            libc::SO_ERROR,
                            &mut err as *mut i32 as *mut libc::c_void,
                            &mut errlen,
                        );
                        if err == 0 && winner.is_none() {
                            winner = Some(p.fd);
                        } else if err != 0 {
                            last_err = err;
                            dead.push(p.fd);
                        }
                    }
                }
                let tag = st.conns[i].connect_tag;
                if let Some(fd) = winner {
                    // Close every attempt that did not win, the current one
                    // included when an earlier rung answered first.
                    for &other in &fds {
                        if other != fd {
                            libc::close(other);
                        }
                    }
                    let c = &mut st.conns[i];
                    c.fd = fd;
                    c.state = 2;
                    c.alts.clear();
                    c.racing.clear();
                    c.attempt_started = None;
                    st.rewatch(fd, i, libc::EPOLLIN as u32);
                    let cb = (i as u16).to_le_bytes();
                    let msg = connected_frame(cb, tag);
                    let lane = st.conns[i].lane as usize;
                    send_msg(st, lane, &msg);
                    send_peer(st, lane, i, fd);
                    had_work = true;
                } else if !dead.is_empty() {
                    // Drop the attempts that failed. The slot only falls to
                    // the ladder when nothing is left in flight.
                    for &fd in &dead {
                        libc::close(fd);
                    }
                    let alive: Vec<i32> =
                        fds.iter().copied().filter(|f| !dead.contains(f)).collect();
                    if alive.is_empty() {
                        let dial = {
                            let c = &mut st.conns[i];
                            Dial {
                                sock_type: c.conn_type,
                                alts: core::mem::take(&mut c.alts),
                                port: c.port,
                                tag,
                                owner: c.owner,
                                lane: c.lane,
                                racing: Vec::new(),
                            }
                        };
                        st.conns[i] = Conn::empty();
                        dial_failed(st, i, dial, last_err);
                    } else {
                        let c = &mut st.conns[i];
                        c.fd = alive[0];
                        c.racing = alive[1..].to_vec();
                    }
                    had_work = true;
                } else if st.conns[i]
                    .attempt_started
                    .is_some_and(|t| t.elapsed() >= ATTEMPT_DELAY)
                    && !st.conns[i].alts.is_empty()
                {
                    // Nothing has answered and the delay has passed: try the
                    // next address ALONGSIDE, rather than waiting out a path
                    // that may never answer at all.
                    let next = st.conns[i].alts.remove(0);
                    match start_connect(next, st.conns[i].port) {
                        Some(fd) => {
                            let c = &mut st.conns[i];
                            c.racing.push(c.fd);
                            c.fd = fd;
                            c.attempt_started = Some(std::time::Instant::now());
                            st.watch(fd, i, (libc::EPOLLOUT | libc::EPOLLIN) as u32);
                            had_work = true;
                        }
                        None => {
                            // Could not even open the socket; the attempt
                            // already running is still the live one.
                            st.conns[i].attempt_started = Some(std::time::Instant::now());
                        }
                    }
                }
            }
            continue;
        }

        // BACKPRESSURE: ring writes are all-or-nothing, so read from the
        // socket only as many bytes as the lane's events can take right now
        // — leaving the rest in the socket so TCP windows the peer down.
        // Reading more and dropping the overflow would silently corrupt the
        // stream. Bound the recv to the data the writable space carries as
        // frames (`stream_data_fits`). The space is the connection's own
        // lane's, so a full lane windows down only its own sockets.
        // Queued control frames go first, since they take the same room.
        let lane = st.conns[i].lane as usize;
        let room = if st.flush_lane(lane) {
            st.room(lane)
        } else {
            0
        };
        // Sized so the frames always land whole: a tail left over would be
        // held in `recv_buf`, and while it is held no connection is read.
        let cap = st.recv_buf.len().min(stream_data_fits(room));
        if cap == 0 {
            // Destination full — don't read; let TCP backpressure the peer.
            // But this is work pending, not work finished: the socket is
            // readable and stays readable, and the room appears on a ring
            // the runtime drains, which rings nobody. Reporting idle would
            // end the transfer wherever the consumer first fell behind —
            // the bytes already sent arrive, and the rest never do.
            had_work = true; // still blocked — step again on a short beat
            continue;
        }
        let n = libc::recv(
            st.conns[i].fd,
            st.recv_buf.as_mut_ptr() as *mut libc::c_void,
            cap,
            0,
        );
        if n > 0 {
            // CHUNK the read into ≤STREAM_CHUNK frames. The recv was
            // bounded by the room, so every chunk should fit; a short write
            // anyway leaves a tail to re-offer rather than bytes to drop.
            let total = n as usize;
            let off = forward_chunks(st, lane, i, 0, total);
            if off < total {
                st.hold_slot = i as i32;
                st.hold_lane = lane;
                st.hold_off = off;
                st.hold_len = total;
                // Every connection shares `recv_buf`, so no other one may be
                // read while a tail is held in it.
                return true;
            }
            had_work = true;
        } else if n == 0 {
            peer_finished(st, i);
            had_work = true;
        } else {
            // n < 0. EAGAIN / EWOULDBLOCK / EINTR is "no data right
            // now"; everything else (ECONNRESET, EPIPE, EBADF, …) is a
            // dead socket: hold the id and emit MSG_CLOSED
            // (`CLOSED_GONE`). Without this, an RST'd connection
            // (browser tab closed, force-close, route flap) leaks its
            // slot forever and the 24-slot table eventually fills up,
            // after which all new accepts queue and the server appears
            // to "fall over after one connection".
            let err = *libc::__errno_location();
            if err != libc::EAGAIN && err != libc::EWOULDBLOCK && err != libc::EINTR {
                hold_closed_slot(st, i);
                had_work = true;
            }
        }
    }
    had_work
}

/// Leading payload bytes kept from an oversized command: a connection id,
/// an endpoint id or a bind's port.
const OVERSIZED_HEAD: usize = 2;

/// Answer a command frame larger than `CMD_MAX` with `EMSGSIZE`,
/// in the shape its requester waits on: a dial's `MSG_ERROR` on its tag
/// (`CMD_CONNECT_TO`'s last two bytes), a stream bind's untagged
/// `MSG_ERROR`, a datagram bind's `DG_MSG_ERROR`, a
/// datagram send's or close's `DG_MSG_ERROR` on its endpoint, and a stream
/// command's `MSG_ERROR` on its connection. An oversized `CMD_SEND` has lost
/// bytes from the middle of the stream, so the connection is closed after
/// the error (`MSG_CLOSED`): the peer must not read a stream with a hole in
/// it as whole. A connection or endpoint the lane may not act on is not
/// touched and its id is not echoed. An opcode with no requester shape is
/// logged.
unsafe fn refuse_oversized(
    st: &mut Sockets,
    lane: usize,
    msg_type: u8,
    payload_len: usize,
    head: &[u8; OVERSIZED_HEAD],
    tail: [u8; 2],
) {
    const EMSGSIZE: u8 = libc::EMSGSIZE as u8;
    log::warn!(
        "[linux_net] lane {lane}: command 0x{msg_type:02x} of {payload_len} B is larger than \
         {CMD_MAX} B; refused EMSGSIZE"
    );
    match msg_type {
        CMD_CONNECT_TO => {
            let msg = error_frame(0, EMSGSIZE, u16::from_le_bytes(tail));
            send_msg(st, lane, &msg);
        }
        CMD_SEND | CMD_CLOSE => {
            let conn_id = u16::from_le_bytes([head[0], head[1]]);
            let idx = conn_id as usize;
            let live = st.conns.get(idx).is_some_and(|c| c.state != 0);
            if !live || !lane_may_touch(st, lane, idx) {
                return;
            }
            send_msg(
                st,
                lane,
                &error_frame(conn_id, EMSGSIZE, np::REQUESTER_TAG_NONE),
            );
            if msg_type == CMD_SEND && st.conns[idx].state == 2 {
                hold_closed_slot(st, idx);
            }
        }
        CMD_BIND => {
            send_bind_refused(st, lane, u16::from_le_bytes([head[0], head[1]]), EMSGSIZE);
        }
        DG_CMD_BIND => {
            send_dg_error(st, lane, EMSGSIZE);
        }
        DG_CMD_SEND_TO | DG_CMD_CLOSE => {
            let ep = head[0];
            let named = st
                .conns
                .get(ep as usize)
                .is_some_and(|c| c.state != 0 && c.conn_type == CONN_TYPE_UDP_BOUND)
                && lane_may_touch(st, lane, ep as usize);
            send_dg_ep_error(st, lane, if named { ep } else { 0xFF }, EMSGSIZE);
        }
        _ => {}
    }
}

impl Sockets {
    /// One step: refresh what every destination can take (`view`), act on
    /// what the lanes hold, flush queued control frames and backlogs, and
    /// serve every ready socket. What it plans is handed on by
    /// [`Sockets::drain_out`].
    pub fn step(&mut self, view: &mut dyn FnMut(u8) -> View) -> Poll {
        for a in self.lanes.iter_mut().flatten() {
            a.out.view = view(a.key);
        }
        self.moved = false;
        // SAFETY: the engine's own descriptors and buffers, on the one
        // thread that steps it.
        let had_work = unsafe { step_inner(self) };
        self.holding = had_work && !self.moved;
        if self.moved {
            Poll::Busy
        } else if had_work {
            Poll::Holding
        } else {
            Poll::Idle
        }
    }
}

/// The step's body; `true` while there is work left (a held tail, a paused
/// lane, a backlog, a destination with no room).
///
/// # Safety
/// The engine's own state, on the one thread that steps it.
unsafe fn step_inner(st: &mut Sockets) -> bool {
    // SAFETY: the function's contract: the engine's own descriptors and
    // buffers, on the thread that steps it.
    unsafe {
        let mut had_work = false;

        // Retry any control frames a back-pressured consumer dropped earlier, so
        // terminal results (MSG_CONNECTED / CLOSED / ERROR) are never lost.
        if !st.flush_pending_ctrl() {
            had_work = true; // still draining — keep getting scheduled
        }

        // Drain per-connection write backlogs first. If any connection
        // is sitting on a full backlog, defer acting on new commands — the
        // lanes' rings are the back-pressure point for `CMD_SEND`. Lighter
        // backlogs don't gate, so parallel `CMD_CLOSE` etc. still flow.
        sweep_held_slots(st);
        if drain_resolved(st) {
            had_work = true;
        }
        let heavy_pending = drain_writes(st);
        if heavy_pending {
            had_work = true;
        }

        if !heavy_pending {
            let mut gated = false;
            // Lanes in attach order: the node graph's first, in wiring
            // order, then each workload's.
            for k in 0..st.order.len() {
                if gated {
                    break;
                }
                let lane = st.order[k];
                // A lane acts once the runtime has said what its owner may
                // claim.
                if st.inbox(lane).is_none() || st.lane_gate(lane).is_none() {
                    continue;
                }
                loop {
                    // Every command may owe the lane a control frame; at
                    // the queue's cap the rest wait on the lane's ring
                    // until the consumer reads its events.
                    if st.lane_paused(lane) {
                        had_work = true;
                        break;
                    }
                    let Some(rec) = st.inbox_mut(lane).and_then(Inbox::pop) else {
                        break;
                    };
                    st.moved = true;
                    if rec.len() < 3 {
                        log::warn!(
                            "[linux_net] lane {lane}: a {} B record has no frame header",
                            rec.len()
                        );
                        continue;
                    }
                    let msg_type = rec[0];
                    let payload_len = (rec[1] as u16 | ((rec[2] as u16) << 8)) as usize;
                    if payload_len != rec.len() - 3 {
                        log::warn!(
                            "[linux_net] lane {lane}: command 0x{msg_type:02x} states {payload_len} B \
                             in a {} B record",
                            rec.len()
                        );
                        continue;
                    }
                    if payload_len > st.cmd_buf.len() {
                        // Oversized command (past `accepts_record`): answer
                        // it with the bytes its requester is named by (a conn
                        // id or endpoint at the front, a dial's tag at the
                        // end).
                        let payload = &rec[3..];
                        let mut head = [0u8; OVERSIZED_HEAD];
                        head.copy_from_slice(&payload[..OVERSIZED_HEAD]);
                        let tail = [payload[payload_len - 2], payload[payload_len - 1]];
                        refuse_oversized(st, lane, msg_type, payload_len, &head, tail);
                        had_work = true;
                        continue;
                    }
                    st.cmd_buf[..payload_len].copy_from_slice(&rec[3..]);

                    match msg_type {
                        CMD_BIND => {
                            match np::bind_parts(&st.cmd_buf[..payload_len]) {
                                Some((port, flags)) if flags_defined(flags) => {
                                    cmd_bind(st, port, lane);
                                }
                                _ => {
                                    log::warn!(
                                        "[linux_net] lane {lane}: malformed CMD_BIND \
                                         ({payload_len} B)"
                                    );
                                    let msg = error_frame(0, 22, np::REQUESTER_TAG_NONE);
                                    send_msg(st, lane, &msg);
                                }
                            }
                            had_work = true;
                        }
                        CMD_CONNECT_TO => {
                            // Decode against a copy so the record's borrowed name does
                            // not hold `cmd_buf` while the state is mutated.
                            let mut rec = [0u8; np::CONNECT_TO_MAX];
                            let n = payload_len.min(rec.len());
                            rec[..n].copy_from_slice(&st.cmd_buf[..n]);
                            match np::read_connect_to(&rec[..n]) {
                                Some(c) if n == payload_len && flags_defined(c.flags) => {
                                    cmd_connect_to(
                                        st,
                                        c.sock_type,
                                        c.port,
                                        c.target,
                                        c.requester_tag,
                                        lane,
                                    );
                                }
                                _ => {
                                    // Malformed or an undefined flag: EINVAL goes to
                                    // the tag the record's last two bytes spell, as
                                    // `read_connect_to` states.
                                    let tag =
                                        np::malformed_connect_to_tag(&st.cmd_buf[..payload_len]);
                                    log::warn!(
                                        "[linux_net] malformed CMD_CONNECT_TO ({payload_len} B)"
                                    );
                                    let msg = error_frame(0, 22u8, tag);
                                    send_msg(st, lane, &msg);
                                }
                            }
                            had_work = true;
                        }
                        CMD_SEND if payload_len > np::DATA_HEAD => {
                            let conn_id = u16::from_le_bytes([st.cmd_buf[0], st.cmd_buf[1]]);
                            if !lane_may_touch(st, lane, conn_id as usize) {
                                log::warn!(
                                    "[linux_net] lane {lane} CMD_SEND on conn {conn_id} refused: \
                                     opened by lane {}",
                                    st.conns[conn_id as usize].lane
                                );
                                had_work = true;
                                continue;
                            }
                            let data_len = payload_len - 2;
                            let data_slice =
                                core::slice::from_raw_parts(st.cmd_buf.as_ptr().add(2), data_len);
                            cmd_send(st, conn_id, data_slice);
                            had_work = true;
                            // This connection's backlog can take no further
                            // frame: stop reading until it drains, as the
                            // pass above would have.
                            if let Some(c) = st.conns.get(conn_id as usize) {
                                let pending = (c.write_len - c.write_offset) as usize;
                                if backlog_full(st.write_buf_max, pending) {
                                    gated = true;
                                    break;
                                }
                            }
                        }
                        CMD_CLOSE => {
                            let Some((conn_id, abort)) =
                                np::close_parts(&st.cmd_buf[..payload_len])
                            else {
                                log::warn!(
                                    "[linux_net] lane {lane}: malformed CMD_CLOSE ({payload_len} B)"
                                );
                                had_work = true;
                                continue;
                            };
                            if !lane_may_touch(st, lane, conn_id as usize) {
                                log::warn!(
                                    "[linux_net] lane {lane} CMD_CLOSE on conn {conn_id} refused: \
                                     opened by lane {}",
                                    st.conns[conn_id as usize].lane
                                );
                                had_work = true;
                                continue;
                            }
                            cmd_close(st, conn_id, abort);
                            had_work = true;
                        }
                        DG_CMD_BIND => {
                            match dgc::bind_parts(&st.cmd_buf[..payload_len]) {
                                Some((port, _flags)) => dg_cmd_bind(st, port, lane),
                                None => send_dg_error(st, lane, 22), // EINVAL
                            }
                            had_work = true;
                        }
                        DG_CMD_SEND_TO if payload_len >= 2 => {
                            // Datagram contract:
                            //   [ep_id:1][af:1=4][addr:4 BE][port:2 LE][data...]
                            //   [ep_id:1][af:1=1][len:1][name…][port:2 LE][data...]
                            let dest_off = 1;
                            let ep = st.cmd_buf[0] as i16;
                            if !dg_endpoint_admits(st, lane, ep) {
                                had_work = true;
                                continue;
                            }
                            let af = if dest_off < payload_len {
                                st.cmd_buf[dest_off]
                            } else {
                                0
                            };
                            let ap = dest_off + 1;
                            let (ip, port_at) = match af {
                                DG_AF_INET if payload_len >= ap + 6 => (
                                    [
                                        st.cmd_buf[ap],
                                        st.cmd_buf[ap + 1],
                                        st.cmd_buf[ap + 2],
                                        st.cmd_buf[ap + 3],
                                    ],
                                    ap + 4,
                                ),
                                DG_AF_NAME if payload_len > ap => {
                                    let len = st.cmd_buf[ap] as usize;
                                    let name_end = ap + 1 + len;
                                    if len == 0 || payload_len < name_end + 2 {
                                        had_work = true;
                                        continue;
                                    }
                                    let name = &st.cmd_buf[ap + 1..name_end];
                                    match st.dns_cache_get(name).and_then(|addrs| {
                                        addrs.into_iter().find_map(|a| match a {
                                            Resolved::V4(v4) => Some(v4),
                                            Resolved::V6(_) => None,
                                        })
                                    }) {
                                        Some(a) => (a, name_end),
                                        _ => {
                                            // Not in hand: start the lookup and drop this
                                            // datagram; the sender's retransmit finds the
                                            // answer in the cache.
                                            let name = name.to_vec();
                                            let _ = st.resolve_async(&name, None, true);
                                            had_work = true;
                                            continue;
                                        }
                                    }
                                }
                                _ => {
                                    send_dg_error(st, lane, 97); // EAFNOSUPPORT
                                    had_work = true;
                                    continue;
                                }
                            };
                            let port =
                                u16::from_le_bytes([st.cmd_buf[port_at], st.cmd_buf[port_at + 1]]);
                            let data_off = port_at + 2;
                            let data_len = payload_len - data_off;
                            let data = core::slice::from_raw_parts(
                                st.cmd_buf.as_ptr().add(data_off),
                                data_len,
                            );
                            dg_cmd_send_to(st, ep, ip, port, data);
                            had_work = true;
                        }
                        DG_CMD_CLOSE if payload_len == dgc::CLOSE_LEN => {
                            let ep = st.cmd_buf[0] as i16;
                            // A lane's datagram close must not free a slot
                            // another lane opened: another lane's endpoint
                            // is answered `EPERM`, as a send on it is, and
                            // any other slot of another lane is not touched.
                            let endpoint = st.conns.get(ep as usize).is_some_and(|c| {
                                c.state == 3 && c.conn_type == CONN_TYPE_UDP_BOUND
                            });
                            if !endpoint && !lane_may_touch(st, lane, ep as usize) {
                                log::warn!(
                                    "[linux_net] lane {lane} DG_CMD_CLOSE on slot {ep} refused: \
                                     opened by lane {}",
                                    st.conns[ep as usize].lane
                                );
                                had_work = true;
                                continue;
                            }
                            dg_cmd_close(st, lane, ep);
                            had_work = true;
                        }
                        _ => {
                            log::warn!("[linux_net] unknown cmd 0x{msg_type:02x} pl={payload_len}");
                        }
                    }
                }
            }
        }

        st.poll_ready();
        if poll_accept(st) {
            had_work = true;
        }
        if poll_recv(st) {
            had_work = true;
        }
        if dg_poll_recv(st) {
            had_work = true;
        }

        had_work
    }
}
