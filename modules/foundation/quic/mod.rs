//! QUIC v1 (RFC 9000 / RFC 9001 / RFC 9002).
//!
//! Submodules:
//!
//! - [`packet`](packet.rs) — long/short header parsing, packet number
//!   reconstruction, and header protection (RFC 9000 §17, RFC 9001 §5.4).
//! - [`frame`](frame.rs) — frame type table, parsers and builders for
//!   CRYPTO, STREAM, ACK, CONNECTION_CLOSE, RESET_STREAM, NEW_CONNECTION_ID,
//!   MAX_DATA / MAX_STREAM_DATA / DATA_BLOCKED.
//! - [`ack`](ack.rs) — sliding ACK range tracker (RFC 9000 §13, §19.3).
//! - [`keys`](keys.rs) — Initial-keys derivation, AEAD key schedule,
//!   key update next-phase derivation (RFC 9001 §5–§6).
//! - [`pump`](pump.rs) — handshake state pump driving the shared
//!   `HandshakeDriver` across Initial / Handshake / 1-RTT levels.
//!
//! # Where this module stops
//!
//! It carries connections and streams. It does not speak the protocols on
//! them, and it does not know which protocol is on them.
//!
//! Every application stream is surfaced over the `mux` contract
//! (`contracts/net/mux.rs`) and answered by whatever is wired to `app_out` /
//! `app_in`: sessions, bidirectional and unidirectional streams, ordered
//! bytes, FIN, reset, stop-sending, flow-control credit, and datagrams. The
//! negotiated ALPN crosses that surface as an opaque byte string; this module
//! performs the negotiation but never compares the result against a token or
//! branches on its value.
//!
//! Nothing here parses application bytes — including the leading varint some
//! protocols place on a unidirectional stream to type it. A stream's contents
//! are the application's, first byte included. HTTP semantics (methods, paths,
//! header compression, HTTP/3 SETTINGS and QPACK, routing, WebSocket tunnels,
//! request spans) live in whichever module consumes this one. See
//! `docs/architecture/protocol_surfaces.md`, and
//! `examples/test_harness/linux/quic/README.md` for how the transport proves
//! itself without borrowing a protocol to do it.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![cfg_attr(not(feature = "host-test"), no_main)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
// Bound-endpoint bind lifecycle + addressed send, shared with dns / dtls /
// log_net / transport_buffer. quic keeps its own connection-id demux on the
// inbound path; the core owns bind + send only.
include!("../../sdk/cores/datagram_endpoint.rs");
include!("../../sdk/cores/ticket_replay.rs");
// Windowed 1-RTT send packet-number reservation with epoch fencing
//: QUIC is this core's first on-wire-sequence consumer.
include!("../../sdk/cores/nonce_reservation.rs");
// CRC32 chunking reused for continuity checkpoint chunks.
include!("../../sdk/cores/session_handoff.rs");
include!("../../sdk/wire/varint.rs");

// Crypto primitives (also used by tls/dtls modules — duplicated PIC
// inclusion is the convention since each module compiles standalone).
include!("../../sdk/crypto/sha256.rs");
include!("../../sdk/crypto/sha384.rs");
include!("../../sdk/crypto/hmac.rs");
include!("../../sdk/crypto/aes_gcm.rs");
include!("../../sdk/crypto/chacha20.rs");
include!("../../sdk/crypto/p256.rs");
include!("../../sdk/crypto/sha3.rs");
// ml_dsa.rs needs sha3.rs's SHAKE in scope; x509.rs needs ml_dsa.rs for
// post-quantum certificate suites. Order matters for all three.
include!("../../sdk/crypto/ml_dsa.rs");

// Shared TLS / DTLS source — QUIC drives the same TLS 1.3 handshake
// state machine via CRYPTO frames instead of records.
include!("../tls/x509.rs");
include!("../tls/alert.rs");
include!("../tls/record.rs");
include!("../tls/key_schedule.rs");
include!("../tls/handshake.rs");
include!("../tls/handshake_driver.rs");

include!("packet.rs");
include!("frame.rs");
include!("ack.rs");
include!("keys.rs");
include!("connection.rs");
include!("wire.rs");
include!("pump.rs");
// Transport continuity (CT_QUIC): checkpoint/delta codec + shadow takeover
// state machine on the cont_in / cont_out ports.
include!("continuity.rs");

// Concurrent connections this endpoint will hold. Per-connection state is
// ~20 KB — dominated by the datagram/stream buffers and the TLS handshake
// driver's 4 KB scratch — so the table costs ~160 KB of module state, which
// bcm2712 (this module's only target) carries without pressure.
//
// It is a deliberate envelope rather than a wedge, and what makes it safe to
// state as one is the behaviour AT the ceiling: a connection past it is
// REFUSED with a stateless CONNECTION_REFUSED Initial
// (`emit_stateless_refusal`), never silently ignored. A client that is
// refused fails in one round trip; a client that is ignored hangs to its own
// handshake deadline, which is indistinguishable from an unreachable server.
// Published in the SDK profile (`abi::config::quic::MAX_CONNS`) so a consumer
// can read the QUIC envelope beside the TCP and TLS ones.
use abi::config::quic::MAX_CONNS;
/// Handshake work one step may do for one connection, in microseconds.
///
/// The pump loops below re-drive a handshaking connection until it stops
/// progressing, up to 64 times per step. That defeats `ecdh_bits_per_step`:
/// the ECDH ladder it splits into eight chunks ran all eight in one step,
/// beside the run-to-completion ECDSA CertificateVerify (501 µs on the Pi 5,
/// `fcs=8 fcu=501` in the heartbeat). Unbounded, the whole first contact
/// lands in a single step and the kernel's 2 ms guard faults the module —
/// which leaves the board deaf to QUIC from its very first client. Half the
/// guard: one signature still fits, the ladder spreads across ticks, and a
/// state that legitimately needs more resumes next step.
const HANDSHAKE_STEP_BUDGET_US: u64 = 1_000;

/// Whether this step's handshake budget for a connection is spent.
#[inline(always)]
unsafe fn handshake_budget_spent(sys: &SyscallTable, t_start: u64) -> bool {
    dev_micros(sys).wrapping_sub(t_start) >= HANDSHAKE_STEP_BUDGET_US
}
/// Configured ALPN list buffer (comma-separated raw tokens, e.g.
/// `mqtt,h3`). 64 bytes holds several protocol names with separators.
const MAX_ALPN_CFG: usize = 64;
/// Abandon an in-progress path validation after this long without a
/// matching PATH_RESPONSE (RFC 9000 §8.2.4).
const PATH_VALIDATE_TIMEOUT_MS: u64 = 3_000;

// The application surface is the multiplexed-session contract
// (`abi::contracts::net::mux`, opcode range 0xB0..0xCF) — the channel
// surface reserved for QUIC. Every message is the universal
// `[msg_type:u8][len:u16 LE][payload]` TLV (written via `net_write_frame`,
// read via `net_read_frame`), so back-to-back stream writes / datagrams
// never coalesce on the byte-stream FIFO. We map our small `conn_id` to a
// `session_id: u32 LE`, and each stream to an opaque `stream_id: u32 LE`
// handle whose transport identity travels alongside it as metadata.
//
//   quic → app: MSG_MUX_SESSION_OPENED  [session][status][flags][alpn]
//   quic → app: MSG_MUX_SESSION_CLOSED  [session][reason]
//   quic → app: MSG_MUX_PEER_IDENTITY   typed peer-identity record
//   quic → app: MSG_MUX_STREAM_ACCEPTED [session][stream][flags][quic_id]
//   quic → app: MSG_MUX_STREAM_OPENED   [session][stream][status][flags][quic_id]
//   quic → app: MSG_MUX_STREAM_RX       [session][stream][data]
//   quic → app: MSG_MUX_STREAM_CLOSED   [session][stream][reason]  (FIN)
//   quic → app: MSG_MUX_STREAM_RESET    [session][stream][app_error]
//   quic → app: MSG_MUX_STREAM_STOPPED  [session][stream][app_error]
//   quic → app: MSG_MUX_STREAM_READY    [session][stream][bytes]
//   quic → app: MSG_MUX_STREAM_ERROR    [session][stream][errno]
//   quic → app: MSG_MUX_DATAGRAM_RX     [session][data]
//   app → quic: CMD_MUX_STREAM_OPEN     [session][flags]
//   app → quic: CMD_MUX_STREAM_SEND     [session][stream][data]
//   app → quic: CMD_MUX_STREAM_CLOSE    [session][stream][flags]
//   app → quic: CMD_MUX_STREAM_RESET    [session][stream][app_error]
//   app → quic: CMD_MUX_STREAM_STOP_SENDING [session][stream][app_error]
//   app → quic: CMD_MUX_STREAM_ACK      [session][stream][bytes]
//   app → quic: CMD_MUX_DATAGRAM_SEND   [session][data]
//   app → quic: CMD_MUX_SESSION_CLOSE   [session][reason]
//
// This is the surface for EVERY session, whatever ALPN it negotiated.
// (The transparent-echo path — no `alpn` configured at all — is a
// different channel ENCODING, not a different protocol: it keeps its
// net_proto MSG_DATA 0x02 framing and carries one raw byte stream.)
use abi::contracts::net::mux;
const MAX_CERT_LEN: usize = 1024;
const MAX_KEY_LEN: usize = 160;
const NET_BUF_SIZE: usize = 1600;
const MAX_TICKETS: usize = 4;

/// Resumption tickets are stateless: the ticket IS the session state,
/// sealed under a vault-held key (`KEY_VAULT::AEAD_SEAL`) that never
/// leaves the vault. Two labelled keys alternate by parity so a rotation
/// leaves the previous generation openable until its tickets age out; a
/// ticket names the parity that sealed it.
///
/// A ticket may not outlive the replay store that enforces its single use,
/// and nothing else here enforces that: the sealing key is persistent
/// across both a restart and a re-instantiation, while the store is RAM
/// that starts empty. `issue_ms` does not cover the gap either — it is an
/// uptime reading a restart moves backwards, which pins `elapsed` at zero
/// and satisfies the lifetime check for good.
///
/// So the AAD carries this instance's replay domain, drawn once from the
/// CSPRNG and living exactly as long as the store beside it. A ticket
/// minted under any other domain — another boot, or another instance in
/// this one — does not fail a check: it does not open. Anything longer
/// lived than the store would not do: a value scoped to the boot, say,
/// survives a re-instantiation and would let the replacement re-open every
/// ticket its predecessor had already spent (RFC 8446 §8, RFC 9001 §9.2).
const TICKET_AAD: &[u8] = b"quic-ticket-v1";
const TICKET_LABEL: [&[u8]; 2] = [b"quic-resume-0", b"quic-resume-1"];
/// `TICKET_AAD` + parity + this instance's replay domain. Derived from the
/// label rather than written out, so changing the label cannot leave a
/// stale length behind that still compiles.
const TICKET_AAD_LEN: usize = TICKET_AAD.len() + 1 + 16;
/// Tickets claimed against replay, held for the claim's whole acceptance
/// window and never reclaimed under pressure — that window is precisely
/// where a replay lands.
///
/// Every resumption takes a slot, not only one carrying early data: a
/// ticket accepted twice also correlates two connections as one client.
/// A full store costs a resumption its round-trip saving, never its
/// safety.
///
/// Depth is sized against `lifetime_s` in `emit_new_session_ticket`, since
/// a claim lives as long as its ticket can still be replayed: the store
/// bounds resumptions per ticket lifetime, and buying more of them means
/// shortening the lifetime rather than widening the replay window.
const TICKET_SEEN: usize = 64;

/// Sealed ticket plaintext: suite(2) rms_len(1) rms(48) age_add(4)
/// issue_ms(8) lifetime_s(4) nonce(8).
const TICKET_PT_LEN: usize = 2 + 1 + 48 + 4 + 8 + 4 + 8;

/// Client-side ticket cache entry. Stored after receiving
/// NewSessionTicket; used to populate `pre_shared_key` extension on
/// the next ClientHello to the same peer.
#[repr(C)]
#[derive(Clone, Copy)]
struct ClientTicketEntry {
    used: bool,
    /// Peer the ticket is bound to (RFC 8446 §4.6.1 — we only resume
    /// to the exact same IP/port pair).
    peer_ip: [u8; 4],
    peer_port: u16,
    /// Opaque ticket bytes received from the server (we echo as PSK
    /// identity).
    ticket: [u8; MAX_TICKET_LEN],
    ticket_len: u8,
    /// Resumption master secret (RFC 8446 §7.1).
    rms: [u8; 48],
    rms_len: u8,
    suite_id: u16,
    issue_ms: u64,
    ticket_age_add: u32,
    lifetime_s: u32,
}

#[repr(C)]
pub(crate) struct QuicState {
    syscalls: *const SyscallTable,
    /// Connections refused at the table ceiling (stateless CONNECTION_REFUSED).
    refused_conns: u32,
    /// Connection IDs or reset tokens the CSPRNG could not fill non-zero
    /// across every retry — a reseed the source did not recover from within
    /// the attempt bound. Reported as `cidfail=` in the heartbeat; non-zero
    /// means a CID was declined rather than emitted zero.
    rng_cid_fail: u32,
    /// Times a 1-RTT emit stalled because the send packet-number
    /// reservation had no granted value left. Non-zero means
    /// the directory's grants ran dry and emission held rather than
    /// reusing a number. Reported as `rstall=` in the heartbeat.
    reservation_exhausted_stall: u32,
    /// Longest single handshake-pump step since boot, in microseconds, and
    /// the `HandshakeState` it ran (first-contact attribution; see
    /// `pump::pump_session`). Reported as `fcs=`/`fcu=` in the heartbeat.
    fc_max_us: u32,
    fc_max_state: u8,
    /// Longest single inbound-datagram drain (`drain_inbound_one`) since
    /// boot, in microseconds: the packet-level work — Initial key derivation,
    /// AEAD, coalesced-packet parsing — that precedes the handshake pump.
    fc_max_drain_us: u32,
    net_in: i32,
    net_out: i32,
    app_in: i32,
    app_out: i32,
    /// Transport-continuity control ports. `cont_in` receives
    /// checkpoint/delta/cut-over commands and durable reservation grants;
    /// `cont_out` emits `MSG_SC_CONTINUITY` replies and mirror deltas.
    /// Both -1 when unwired — the module then runs in local self-grant
    /// mode and never stalls emission on a missing directory.
    cont_in: i32,
    cont_out: i32,
    /// Shadow slots + in-flight checkpoint/delta state for CT_QUIC takeover.
    continuity: ContinuityState,
    /// Vault handle for the labelled `quic-continuity` sealing key; -1
    /// until first use (opened lazily, like the ticket keys).
    cont_vault_key: i32,
    /// Operational key-rotation knob (RFC 9001 §6): initiate a 1-RTT key
    /// update after this many packets sent in the current phase. 0 = never.
    key_update_pkts: u32,
    /// Single bound UDP endpoint (shared `datagram_endpoint` core) for all QUIC
    /// connections; they are demuxed above it by connection id.
    endpoint: DatagramEndpoint,
    port: u16,
    mode: u8,       // 0 = client, 1 = server
    peer_ip: u32,   // client mode: peer IPv4 (LE)
    peer_port: u16, // client mode: peer port
    client_started: bool,
    cert: [u8; MAX_CERT_LEN],
    cert_len: usize,
    key: [u8; MAX_KEY_LEN],
    key_len: usize,
    eph_private: [[u8; 32]; MAX_CONNS],
    eph_public: [[u8; 65]; MAX_CONNS],
    eph_used: [bool; MAX_CONNS],
    conns: [QuicConnection; MAX_CONNS],
    net_scratch: [u8; NET_BUF_SIZE],
    /// Server: required for first Initial w/o token? (1 = yes)
    /// Client: enable use of received Retry packets? (always true)
    require_retry: u8,
    /// 0-RTT enable: 0 = disabled, 1 = enabled (server may issue
    /// NewSessionTicket; client may attempt resumption + early data).
    enable_0rtt: u8,
    /// Server: HMAC key for retry tokens. Generated at boot.
    retry_secret: [u8; 32],
    /// Server: the vault handles of the two ticket-sealing key
    /// generations, by parity; -1 when the vault refused (no tickets
    /// are issued then, and every handshake is a full one).
    ticket_key: [i32; 2],
    /// Parity of the generation sealing new tickets.
    ticket_parity: u8,
    ticket_vault_warned: bool,
    /// Seconds between key rotations; 0 = never.
    ticket_rotate_s: u32,
    ticket_rotated_ms: u64,
    /// Accepted tickets held against replay for their acceptance window.
    ticket_seen: [TicketClaim; TICKET_SEEN],
    /// The domain the store above defends, mixed into every ticket's AAD.
    /// Drawn on first use rather than at construction, since the entropy
    /// source need not have answered by then; all-zero means undrawn.
    replay_domain: [u8; 16],
    /// Client-side ticket cache (per-peer).
    client_tickets: [ClientTicketEntry; MAX_TICKETS],
    /// Set after the client kicks off a 0-RTT resumption attempt so
    /// the loop doesn't restart it every step.
    pending_resumption_test: bool,
    /// Client-side cert chain validation toggle (RFC 5280 + RFC 6125).
    /// 0 = parse the peer cert for its public key only; 1 = also
    /// validate against `trust_cert` and require the leaf SAN/CN to
    /// match `verify_hostname`.
    verify_peer: u8,
    /// Trust anchor DER. For self-signed deployments this is the
    /// leaf; for CA-issued chains it's the root CA.
    trust_cert: [u8; MAX_CERT_LEN],
    trust_cert_len: usize,
    /// Expected server hostname checked against the leaf's SAN
    /// dNSName entries (with leftmost-wildcard support per RFC 6125
    /// §6.4.3) or, as fallback, Subject CN (§6.4.4).
    verify_hostname: [u8; 64],
    verify_hostname_len: usize,
    /// Optional telemetry output (out[2]) to the `observe` collector; -1 when
    /// unwired, so module-scope metrics are zero-cost when disabled.
    /// Cumulative application-stream byte counters + last-emit wallclock
    /// (cadence gated on `dev_millis` — quic has no per-step counter).
    tlm: TlmCounters,
    tlm_last_ms: u64,
    /// Head-sampling rate (per-mille) for `quic.connection` spans. Target-tier
    /// default: 50‰ on aarch64 (pi5-class), 0‰ on MCUs. Decided per accepted
    /// connection from its minted trace id.
    sample_permille: u16,
    /// Configured ALPN list (RFC 7301), comma-separated raw bytes as supplied
    /// by the `alpn` config param — e.g. `mqtt,h3`. The server offers the
    /// FIRST configured entry that the client also offered (server-preference
    /// order). Empty = no ALPN configured, which selects the transparent
    /// byte-stream surface instead of the framed mux one.
    ///
    /// The tokens are opaque to this module. It matches them against the
    /// peer's offer as byte strings and reports the winner to the
    /// application; it never tests one for a particular value.
    alpn_cfg: [u8; MAX_ALPN_CFG],
    alpn_cfg_len: usize,
    /// P-256 scalar-multiplication chunking, in ladder bits per step.
    ///
    /// The handshake does two full 256-bit constant-time ladders — the
    /// ECDH key agreement and the CertificateVerify signature — and both
    /// are resumable. This caps how much of one a single `module_step`
    /// performs, so a handshake cannot monopolise a scheduler tick.
    ///
    /// 256 (the default) means run to completion in one step, which is
    /// right on a host where a millisecond step costs nothing. On a
    /// bare-metal target with a short tick it is NOT: the pi5 graphs run
    /// `tick_us = 50`, a run-to-completion ladder takes ~2 ms, and the
    /// scheduler's step guard terminates the module with `rc=-110` — the
    /// transport simply disappears, which presents as a board that
    /// completes DHCP and then never answers.
    ///
    /// 32 splits each ladder into 8 chunks. Mirrors `tls`'s
    /// `ecdh_bits_per_step`, which exists for exactly this reason and
    /// which this module went without.
    ecdh_bits_per_step: u16,
    /// Connection-migration policy (RFC 9000 §9). 0 (default) = migration
    /// enabled: we do NOT advertise `disable_active_migration`, and we
    /// validate + switch to a new client 4-tuple via PATH_CHALLENGE /
    /// PATH_RESPONSE. 1 = advertise `disable_active_migration` and ignore
    /// path changes (the pre-migration behaviour).
    disable_migration: u8,
}

define_params! {
    QuicState;

    1, port, u16, 4443
        => |s, d, len| { s.port = p_u16(d, len, 0, 4443); };

    2, mode, u8, 1
        => |s, d, len| { s.mode = p_u8(d, len, 0, 1); };

    3, peer_ip, u32, 0x0100007f
        => |s, d, len| { s.peer_ip = p_u32(d, len, 0, 0x0100007f); };

    4, peer_port, u16, 4443
        => |s, d, len| { s.peer_port = p_u16(d, len, 0, 4443); };

    5, require_retry, u8, 0
        => |s, d, len| { s.require_retry = p_u8(d, len, 0, 0); };

    6, enable_0rtt, u8, 0
        => |s, d, len| { s.enable_0rtt = p_u8(d, len, 0, 0); };

    // Tags 7, 8, 10 and 13 are RETIRED and must not be reused: a graph still
    // naming a retired param gets a clean "unknown param" from the composer,
    // where a reused tag would silently bind it to an unrelated value.
    9, verify_peer, u8, 0
        => |s, d, len| { s.verify_peer = p_u8(d, len, 0, 0); };

    // Head-sampling rate (per-mille, 0..=1000) for the connection/request
    // spans. Default sentinel `0xFFFF` ("unset") so `module_new` applies the
    // target-tier default (aarch64 50‰ / MCU 0‰) only when not given.
    11, trace_sample_permille, u16, 0xFFFF
        => |s, d, len| { s.sample_permille = p_u16(d, len, 0, 0xFFFF); };

    12, disable_migration, u8, 0
        => |s, d, len| { s.disable_migration = p_u8(d, len, 0, 0); };

    // Seconds between rotations of the ticket-sealing key. Each rotation
    // is a new key generation; the previous stays openable until its
    // tickets age out. 0 = never rotate.
    16, ticket_rotate_s, u32, 3600
        => |s, d, len| { s.ticket_rotate_s = p_u32(d, len, 0, 3600); };

    // Ladder bits per step for the two P-256 scalar multiplications in the
    // handshake. Clamped to [1, 256]: 0 would stall the ladder forever, and
    // above 256 is a whole ladder anyway.
    //
    // Tag 15 — 14 is the extended-TLV `alpn` key (see `parse_extended_params`).
    15, ecdh_bits_per_step, u16, 256
        => |s, d, len| {
            let v = p_u16(d, len, 0, 256);
            s.ecdh_bits_per_step = if v == 0 { 1 } else if v > 256 { 256 } else { v };
        };

    // Operational key-rotation knob (RFC 9001 §6) and the key-update test
    // hook. 0 (default) = never initiate; N>0 = after N 1-RTT packets sent
    // in the current phase, initiate a key update — provided the handshake
    // is confirmed and any prior update has been acknowledged. Reservations
    // are not reset on key update.
    17, key_update_pkts, u32, 0
        => |s, d, len| { s.key_update_pkts = p_u32(d, len, 0, 0); };
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<QuicState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub extern "C" fn module_arena_size() -> u32 {
    65536
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub extern "C" fn module_init(_syscalls: *const core::ffi::c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    _state_size: usize,
    syscalls: *const SyscallTable,
) -> i32 {
    let s = &mut *(state as *mut QuicState);
    s.syscalls = syscalls;
    s.cert_len = 0;
    s.key_len = 0;
    s.endpoint = DatagramEndpoint::new();
    s.port = 4443;
    s.mode = 1;
    s.peer_ip = 0x0100007f;
    s.peer_port = 4443;
    s.client_started = false;
    s.require_retry = 0;
    s.enable_0rtt = 0;
    s.ecdh_bits_per_step = 256;
    s.key_update_pkts = 0;
    s.verify_peer = 0;
    s.trust_cert_len = 0;
    s.verify_hostname_len = 0;
    s.verify_peer = 0;
    s.trust_cert_len = 0;
    s.verify_hostname_len = 0;
    s.ticket_key = [-1, -1];
    s.ticket_parity = 0;
    s.ticket_vault_warned = false;
    s.ticket_rotate_s = 3600;
    s.ticket_rotated_ms = 0;
    s.ticket_seen = [TicketClaim::EMPTY; TICKET_SEEN];
    s.replay_domain = [0u8; 16];
    s.pending_resumption_test = false;
    s.alpn_cfg_len = 0;
    let mut t = 0;
    while t < MAX_TICKETS {
        s.client_tickets[t] = ClientTicketEntry {
            used: false,
            peer_ip: [0; 4],
            peer_port: 0,
            ticket: [0; MAX_TICKET_LEN],
            ticket_len: 0,
            rms: [0; 48],
            rms_len: 0,
            suite_id: 0,
            issue_ms: 0,
            ticket_age_add: 0,
            lifetime_s: 0,
        };
        t += 1;
    }

    let sys = &*s.syscalls;
    s.net_in = dev_channel_port(sys, 0, 0);
    s.app_in = dev_channel_port(sys, 0, 1);
    s.net_out = dev_channel_port(sys, 1, 0);
    s.app_out = dev_channel_port(sys, 1, 1);
    // in[2] / out[2] = continuity control (-1 when unwired). Optional
    // module-scope telemetry is auto-appended after these, at out[3].
    s.cont_in = dev_channel_port(sys, 0, 2);
    s.cont_out = dev_channel_port(sys, 1, 2);
    continuity_init(s);
    s.cont_vault_key = -1;
    s.tlm = TlmCounters::new();
    s.tlm_last_ms = 0;
    s.refused_conns = 0;
    s.rng_cid_fail = 0;
    s.reservation_exhausted_stall = 0;
    // `sample_permille` resolved after param parsing below (set_defaults would
    // clobber a value set here) via the `trace_sample_permille` 0xFFFF sentinel.

    let mut i = 0;
    while i < MAX_CONNS {
        s.conns[i] = QuicConnection::new();
        i += 1;
    }

    set_defaults(s);
    if params_len >= 4 {
        let p = core::slice::from_raw_parts(params, params_len);
        if p[0] == 0xFE && p[1] == 0x01 {
            parse_tlv(s, params, params_len);
        }
    }
    parse_extended_params(s, params, params_len);

    // Resolve the target-tier head-sampling default only when
    // `trace_sample_permille` was not explicitly supplied (still the sentinel):
    // aarch64 (pi5-class) 50‰, MCUs 0‰. An explicit value (incl. 0) is honoured.
    if s.sample_permille == 0xFFFF {
        #[cfg(target_arch = "aarch64")]
        {
            s.sample_permille = 50;
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            s.sample_permille = 0;
        }
    }

    // Initialise the per-server retry secret from the CSPRNG.
    if dev_csprng_fill(sys, s.retry_secret.as_mut_ptr(), 32) < 0 {
        return -1;
    }
    // The ticket-sealing keys live in the vault; without them no ticket
    // is issued and every handshake is a full one.
    ticket_keys_open(s);

    // Pre-compute ECDH keys for each connection slot.
    let mut i = 0;
    while i < MAX_CONNS {
        let mut random = [0u8; 32];
        if dev_csprng_fill(sys, random.as_mut_ptr(), 32) < 0 {
            return -1;
        }
        let (priv_key, pub_key) = ecdh_keygen(&random);
        s.eph_private[i] = priv_key;
        s.eph_public[i] = pub_key;
        s.eph_used[i] = false;
        let mut j = 0;
        while j < 32 {
            core::ptr::write_volatile(&mut random[j], 0);
            j += 1;
        }
        i += 1;
    }

    if rfc9001_a1_self_check() {
        dev_log(
            sys,
            3,
            b"[quic] RFC 9001 A.1 keys OK".as_ptr(),
            b"[quic] RFC 9001 A.1 keys OK".len(),
        );
    } else {
        dev_log(
            sys,
            2,
            b"[quic] RFC 9001 A.1 keys MISMATCH".as_ptr(),
            b"[quic] RFC 9001 A.1 keys MISMATCH".len(),
        );
    }
    0
}

// ---------------------------------------------------------------------
// Retry token (RFC 9000 §8.1) — server-only.
//
// Format:
//   expiry_ms_le[8] || peer_ip[4] || peer_port_le[2] || odcid_len[1]
//                  || odcid[N (0..20)] || hmac_sha256(retry_secret, all_above)[..16]
// Total: 8 + 4 + 2 + 1 + N + 16 ≤ 51 bytes for N ≤ 20.
// ---------------------------------------------------------------------

const RETRY_TOKEN_LIFETIME_MS: u64 = 5_000;

unsafe fn build_retry_token(
    s: &QuicState,
    peer_ip: &[u8; 4],
    peer_port: u16,
    odcid: &[u8],
    out: &mut [u8],
) -> usize {
    if odcid.len() > MAX_CID_LEN || out.len() < 8 + 4 + 2 + 1 + odcid.len() + 16 {
        return 0;
    }
    let now = dev_millis(&*s.syscalls);
    let expiry = now.wrapping_add(RETRY_TOKEN_LIFETIME_MS);
    let mut p = 0;
    let exp_bytes = expiry.to_le_bytes();
    out[p..p + 8].copy_from_slice(&exp_bytes);
    p += 8;
    out[p..p + 4].copy_from_slice(peer_ip);
    p += 4;
    out[p..p + 2].copy_from_slice(&peer_port.to_le_bytes());
    p += 2;
    out[p] = odcid.len() as u8;
    p += 1;
    if !odcid.is_empty() {
        out[p..p + odcid.len()].copy_from_slice(odcid);
        p += odcid.len();
    }
    let mut tag = [0u8; 32];
    hmac(HashAlg::Sha256, &s.retry_secret, &out[..p], &mut tag);
    out[p..p + 16].copy_from_slice(&tag[..16]);
    p + 16
}

/// Validate a retry token. Returns the embedded ODCID slice (length
/// stored in `*odcid_len`) on success, or None on integrity / expiry
/// / source-mismatch failure.
unsafe fn validate_retry_token(
    s: &QuicState,
    token: &[u8],
    peer_ip: &[u8; 4],
    peer_port: u16,
    odcid_out: &mut [u8; MAX_CID_LEN],
) -> Option<usize> {
    if token.len() < 8 + 4 + 2 + 1 + 16 {
        return None;
    }
    let odcid_len_off = 8 + 4 + 2;
    let odcid_len = token[odcid_len_off] as usize;
    if odcid_len > MAX_CID_LEN {
        return None;
    }
    let body_len = 8 + 4 + 2 + 1 + odcid_len;
    if token.len() < body_len + 16 {
        return None;
    }
    // Recompute HMAC.
    let mut tag = [0u8; 32];
    hmac(
        HashAlg::Sha256,
        &s.retry_secret,
        &token[..body_len],
        &mut tag,
    );
    let mut diff = 0u8;
    let mut i = 0;
    while i < 16 {
        diff |= tag[i] ^ token[body_len + i];
        i += 1;
    }
    if diff != 0 {
        return None;
    }
    // Check expiry.
    let mut expiry_bytes = [0u8; 8];
    expiry_bytes.copy_from_slice(&token[..8]);
    let expiry = u64::from_le_bytes(expiry_bytes);
    let now = dev_millis(&*s.syscalls);
    if now > expiry {
        return None;
    }
    // Check peer match.
    if &token[8..12] != peer_ip {
        return None;
    }
    let port_bytes: [u8; 2] = [token[12], token[13]];
    let token_port = u16::from_le_bytes(port_bytes);
    if token_port != peer_port {
        return None;
    }
    // Extract ODCID.
    let odcid_off = odcid_len_off + 1;
    if odcid_len > 0 {
        odcid_out[..odcid_len].copy_from_slice(&token[odcid_off..odcid_off + odcid_len]);
    }
    Some(odcid_len)
}

unsafe fn parse_extended_params(s: &mut QuicState, params: *const u8, params_len: usize) {
    if params.is_null() || params_len < 4 {
        return;
    }
    let data = core::slice::from_raw_parts(params, params_len);
    // Start scanning past the basic-TLV section (FE 01 PP_LO PP_HI ...).
    // Its payload_len bytes can otherwise alias an extended-TLV header
    // (e.g. payload_len = 0x000c → bytes `0c 00 ..`).
    let mut pos = 0;
    if params_len >= 4 && data[0] == TLV_MAGIC && data[1] == TLV_VERSION {
        let payload_len = ((data[3] as usize) << 8) | (data[2] as usize);
        let basic_end = 4 + payload_len;
        if basic_end <= params_len {
            pos = basic_end;
        }
    }
    while pos + 4 <= params_len {
        let tag = data[pos];
        let ext = tag == 10 || tag == 11 || tag == 12 || tag == 13 || tag == 14;
        if ext && pos + 4 <= params_len && data[pos + 1] == 0x00 {
            let len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
            let start = pos + 4;
            if start + len > params_len {
                break;
            }
            match tag {
                10 => {
                    let n = if len < MAX_CERT_LEN {
                        len
                    } else {
                        MAX_CERT_LEN
                    };
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr().add(start),
                        s.cert.as_mut_ptr(),
                        n,
                    );
                    s.cert_len = n;
                }
                11 => {
                    let n = if len < MAX_KEY_LEN { len } else { MAX_KEY_LEN };
                    core::ptr::copy_nonoverlapping(data.as_ptr().add(start), s.key.as_mut_ptr(), n);
                    s.key_len = n;
                }
                12 => {
                    let n = if len < MAX_CERT_LEN {
                        len
                    } else {
                        MAX_CERT_LEN
                    };
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr().add(start),
                        s.trust_cert.as_mut_ptr(),
                        n,
                    );
                    s.trust_cert_len = n;
                }
                13 => {
                    let n = if len < s.verify_hostname.len() {
                        len
                    } else {
                        s.verify_hostname.len()
                    };
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr().add(start),
                        s.verify_hostname.as_mut_ptr(),
                        n,
                    );
                    s.verify_hostname_len = n;
                }
                14 => {
                    // ALPN config list (RFC 7301): comma-separated raw
                    // tokens, e.g. `mqtt,h3`. Stored verbatim; selection
                    // splits on ',' at ClientHello time.
                    let n = if len < MAX_ALPN_CFG {
                        len
                    } else {
                        MAX_ALPN_CFG
                    };
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr().add(start),
                        s.alpn_cfg.as_mut_ptr(),
                        n,
                    );
                    s.alpn_cfg_len = n;
                }
                _ => {}
            }
            pos = start + len;
        } else {
            pos += 1;
        }
    }
}

// ── Stateless resumption tickets ────────────────────────────────────
//
// The vault holds the sealing key; this module holds two handles and a
// parity. `KEY_VAULT` is a kernel contract class every module may call.

/// `OPEN_OR_GENERATE` an AEAD key under `label`; the handle, or -1.
unsafe fn vault_open_or_generate_aead(sys: &SyscallTable, label: &[u8]) -> i32 {
    let mut arg = [0u8; 8 + 64 + 12];
    arg[0..2].copy_from_slice(&8u16.to_le_bytes()); // suite::AEAD_KEY
    let usage: u32 = (1 << 6) | (1 << 7) | (1 << 4) | (1 << 5); // SEAL|OPEN|PERSIST|WRAP
    arg[2..6].copy_from_slice(&usage.to_le_bytes());
    arg[6] = 0;
    arg[7] = label.len() as u8;
    arg[8..8 + label.len()].copy_from_slice(label);
    let n = 8 + label.len() + 12;
    let rc = (sys.provider_call)(-1, 0x1009, arg.as_mut_ptr(), n);
    if rc < 0 {
        -1
    } else {
        rc
    }
}

unsafe fn vault_destroy_by_label(sys: &SyscallTable, label: &[u8]) {
    let mut arg = [0u8; 1 + 64];
    arg[0] = label.len() as u8;
    arg[1..1 + label.len()].copy_from_slice(label);
    let _ = (sys.provider_call)(-1, 0x100B, arg.as_mut_ptr(), 1 + label.len());
}

/// `AEAD_SEAL` `pt` under `handle` with `aad`; bytes written to `out`, or 0.
unsafe fn vault_seal(
    sys: &SyscallTable,
    handle: i32,
    aad: &[u8],
    pt: &[u8],
    out: &mut [u8],
) -> usize {
    let mut arg = [0u8; 2 + 32 + 2 + TICKET_PT_LEN + 12];
    let mut p = 0;
    arg[p..p + 2].copy_from_slice(&(aad.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + aad.len()].copy_from_slice(aad);
    p += aad.len();
    arg[p..p + 2].copy_from_slice(&(pt.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + pt.len()].copy_from_slice(pt);
    p += pt.len();
    arg[p..p + 8].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    arg[p + 8..p + 10].copy_from_slice(&(out.len() as u16).to_le_bytes());
    let rc = (sys.provider_call)(handle, 0x1012, arg.as_mut_ptr(), p + 12);
    if rc < 0 {
        return 0;
    }
    u16::from_le_bytes([arg[p + 10], arg[p + 11]]) as usize
}

/// `AEAD_OPEN` `blob` under `handle` with `aad`; bytes written to `out`, or 0.
unsafe fn vault_open(
    sys: &SyscallTable,
    handle: i32,
    aad: &[u8],
    blob: &[u8],
    out: &mut [u8],
) -> usize {
    let mut arg = [0u8; 2 + 32 + 2 + MAX_TICKET_LEN + 12];
    let mut p = 0;
    arg[p..p + 2].copy_from_slice(&(aad.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + aad.len()].copy_from_slice(aad);
    p += aad.len();
    arg[p..p + 2].copy_from_slice(&(blob.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + blob.len()].copy_from_slice(blob);
    p += blob.len();
    arg[p..p + 8].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    arg[p + 8..p + 10].copy_from_slice(&(out.len() as u16).to_le_bytes());
    let rc = (sys.provider_call)(handle, 0x1013, arg.as_mut_ptr(), p + 12);
    if rc < 0 {
        return 0;
    }
    u16::from_le_bytes([arg[p + 10], arg[p + 11]]) as usize
}

/// Open both ticket-key generations. Without a vault no ticket is ever
/// issued: resumption that cannot be sealed is not offered.
unsafe fn ticket_keys_open(s: &mut QuicState) {
    if s.mode != 1 {
        return;
    }
    let sys = &*s.syscalls;
    s.ticket_key[0] = vault_open_or_generate_aead(sys, TICKET_LABEL[0]);
    s.ticket_key[1] = vault_open_or_generate_aead(sys, TICKET_LABEL[1]);
    s.ticket_rotated_ms = dev_millis(sys);
    if s.ticket_key[0] < 0 || s.ticket_key[1] < 0 {
        s.ticket_key = [-1, -1];
        if !s.ticket_vault_warned {
            s.ticket_vault_warned = true;
            let msg = b"[quic] no vault ticket key: resumption not offered";
            dev_log(sys, 2, msg.as_ptr(), msg.len());
        }
    }
}

/// Rotate the sealing key when due: the other parity gets a fresh key
/// and becomes current; tickets under the old current stay openable.
unsafe fn ticket_rotate_if_due(s: &mut QuicState) {
    if s.mode != 1 || s.ticket_rotate_s == 0 || s.ticket_key[0] < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let now = dev_millis(sys);
    if now.saturating_sub(s.ticket_rotated_ms) < u64::from(s.ticket_rotate_s) * 1000 {
        return;
    }
    let next = (s.ticket_parity ^ 1) as usize;
    vault_destroy_by_label(sys, TICKET_LABEL[next]);
    let h = vault_open_or_generate_aead(sys, TICKET_LABEL[next]);
    if h < 0 {
        return;
    }
    s.ticket_key[next] = h;
    s.ticket_parity = next as u8;
    s.ticket_rotated_ms = now;
    let msg = b"[quic] ticket key rotated";
    dev_log(sys, 3, msg.as_ptr(), msg.len());
}

/// The AAD both seal and open must agree on: label, parity, and the replay
/// domain that ties a ticket to the store enforcing its single use.
fn ticket_aad(parity: u8, domain: &[u8; 16]) -> [u8; TICKET_AAD_LEN] {
    let mut aad = [0u8; TICKET_AAD_LEN];
    aad[..TICKET_AAD.len()].copy_from_slice(TICKET_AAD);
    aad[TICKET_AAD.len()] = parity;
    aad[TICKET_AAD.len() + 1..].copy_from_slice(domain);
    aad
}

/// This instance's replay domain, drawn on first use. `None` while the
/// entropy source has not answered: a domain of zeros is the absence of
/// one, and issuing or accepting under it would let any instance open
/// another's tickets.
///
/// Takes the domain itself rather than the state, so the borrow stays
/// disjoint from a connection being driven — the same shape
/// [`ticket_claim_held`] uses for the store beside it.
unsafe fn replay_domain(domain: &mut [u8; 16], sys: &SyscallTable) -> Option<[u8; 16]> {
    if *domain != [0u8; 16] {
        return Some(*domain);
    }
    let mut v = [0u8; 16];
    if dev_csprng_fill(sys, v.as_mut_ptr(), 16) < 0 || v == [0u8; 16] {
        return None;
    }
    *domain = v;
    Some(v)
}

/// First 16 bytes of SHA-256 over a ticket: what the replay store holds.
fn ticket_digest(identity: &[u8]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(identity);
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub unsafe extern "C" fn module_step(state: *mut u8) -> i32 {
    let s = &mut *(state as *mut QuicState);
    let sys = &*s.syscalls;

    // Module-scope metrics (~5s cadence): a bounded log beat always, plus the
    // telemetry-port counters when that port is wired.
    maybe_emit_telemetry(s);
    ticket_rotate_if_due(s);
    // Drain any transport-continuity control commands (checkpoint / delta /
    // cut-over / reservation grants) on `cont_in`; no-op when unwired.
    cont_pump(s);

    // Drive the bind handshake (shared core): emits CMD_DG_BIND while unbound,
    // with backoff/retry. MSG_DG_BOUND is consumed in the recv loop below.
    s.endpoint.poll_bind(
        sys,
        s.net_out,
        s.port,
        s.net_scratch.as_mut_ptr(),
        NET_BUF_SIZE,
    );

    // Client mode: kick off the handshake by allocating a connection,
    // queueing a ClientHello in driver.out_buf, and emitting the
    // first Initial packet.
    if s.mode == 0 && !s.client_started && s.endpoint.is_ready() {
        let ip_bytes = s.peer_ip.to_le_bytes();
        let ip = [ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]];
        if let Some(idx) = alloc_client_connection(s, &ip, s.peer_port) {
            // Drive far enough to get the ClientHello queued.
            let mut steps = 0;
            let t_start = dev_micros(&*s.syscalls);
            while steps < 64
                && s.conns[idx].phase == ConnPhase::Handshaking
                && !handshake_budget_spent(&*s.syscalls, t_start)
            {
                let progressed = pump_session(s, idx);
                drain_outbound(s, idx);
                if !progressed {
                    break;
                }
                steps += 1;
            }
            s.client_started = true;
        }
    }

    // Drive every active connection through the queue path.
    let mut i = 0;
    while i < MAX_CONNS {
        if s.conns[i].phase == ConnPhase::Handshaking {
            let mut steps = 0;
            let t_start = dev_micros(&*s.syscalls);
            while steps < 64
                && s.conns[i].phase == ConnPhase::Handshaking
                && !handshake_budget_spent(&*s.syscalls, t_start)
            {
                let t0 = dev_micros(sys);
                let drained = drain_inbound_one(s, i);
                let dt = dev_micros(sys).wrapping_sub(t0) as u32;
                if dt > s.fc_max_drain_us {
                    s.fc_max_drain_us = dt;
                }
                let progressed = pump_session(s, i);
                drain_outbound(s, i);
                if !drained && !progressed {
                    break;
                }
                steps += 1;
            }
        }
        i += 1;
    }

    // Read incoming datagrams.
    let poll = (sys.channel_poll)(s.net_in, POLL_IN);
    if poll > 0 && (poll as u32 & POLL_IN) != 0 {
        let mut hdr = [0u8; 3];
        let n = (sys.channel_read)(s.net_in, hdr.as_mut_ptr(), 3);
        if n == 3 {
            let opcode = hdr[0];
            let payload_len = (hdr[1] as usize) | ((hdr[2] as usize) << 8);
            match opcode {
                x if x == DG_MSG_BOUND => {
                    // MSG_DG_BOUND payload: [ep_id:1][local_port:2 LE].
                    // Filter by local_port — the provider broadcasts BOUND
                    // for every consumer on the shared net_out channel.
                    let mut buf = [0u8; 16];
                    let take = if payload_len < 16 { payload_len } else { 16 };
                    if take > 0 {
                        (sys.channel_read)(s.net_in, buf.as_mut_ptr(), take);
                    }
                    if payload_len > take {
                        discard_bytes(sys, s.net_in, payload_len - take);
                    }
                    if take >= 3 {
                        let bound_port = (buf[1] as u16) | ((buf[2] as u16) << 8);
                        // Port-filter our own BOUND off the (possibly broadcast)
                        // channel, then hand the ep_id to the endpoint.
                        if bound_port == s.port && !s.endpoint.is_ready() {
                            s.endpoint.on_bound(buf[0]);
                            dev_log(sys, 3, b"[quic] bound".as_ptr(), b"[quic] bound".len());
                        }
                    }
                }
                x if x == DG_MSG_RX_FROM => {
                    // MSG_DG_RX_FROM IPv4 payload (datagram contract):
                    //   [ep_id:1][af:1=4][src_addr:4 BE][src_port:2 LE][data].
                    if payload_len >= 8 {
                        let mut hb = [0u8; 8];
                        (sys.channel_read)(s.net_in, hb.as_mut_ptr(), 8);
                        let ip = [hb[2], hb[3], hb[4], hb[5]];
                        let port = (hb[6] as u16) | ((hb[7] as u16) << 8);
                        let dlen = payload_len - 8;
                        if dlen <= QUIC_DGRAM_MAX {
                            // Peek the first 32 bytes to extract DCID
                            // for connection demux.
                            let mut peek = [0u8; 32];
                            let peek_len = dlen.min(peek.len());
                            (sys.channel_read)(s.net_in, peek.as_mut_ptr(), peek_len);
                            let mut dcid_buf = [0u8; MAX_CID_LEN];
                            let mut dcid_len = 0usize;
                            if peek_len >= 7 {
                                let first = peek[0];
                                let is_long = first & 0x80 != 0;
                                if is_long {
                                    let dl = peek[5] as usize;
                                    if dl <= MAX_CID_LEN && 6 + dl <= peek_len {
                                        dcid_len = dl;
                                        dcid_buf[..dl].copy_from_slice(&peek[6..6 + dl]);
                                    }
                                } else if 8 < peek_len {
                                    dcid_len = 8;
                                    dcid_buf[..8].copy_from_slice(&peek[1..9]);
                                }
                            }
                            let mut idx = if dcid_len > 0 {
                                find_conn_by_dcid(s, &dcid_buf[..dcid_len])
                            } else {
                                -1
                            };
                            if idx < 0 && s.mode == 1 {
                                // Only a server accepts an unmatched datagram as
                                // a NEW connection. A client that can't match an
                                // inbound packet to one of its own connections
                                // drops it (RFC 9000 §5.2) — it must never spin
                                // up a server-side connection for stray traffic,
                                // which would otherwise error out and emit a
                                // spurious CONNECTION_CLOSE.
                                if let Some(new) = alloc_server_connection(s, &ip, port) {
                                    idx = new as i32;
                                } else {
                                    let mc = find_conn(s, &ip, port);
                                    if mc >= 0 {
                                        idx = mc;
                                    } else {
                                        // Table full: refuse STATELESSLY so
                                        // the client fails in one round trip
                                        // rather than hanging to its own
                                        // handshake deadline. Stateless
                                        // because allocating for a
                                        // connection being refused is what
                                        // makes a full table an amplifier.
                                        emit_stateless_refusal(s, &ip, port, &peek[..peek_len]);
                                    }
                                }
                            }
                            if idx >= 0 {
                                let conn = &mut s.conns[idx as usize];
                                // Record the datagram source. Migration is
                                // NOT armed here: a visible DCID is not proof
                                // of authenticity, so a spoofed packet must
                                // never redirect challenge traffic or clobber
                                // validation state. Path validation is armed
                                // only after the packet decrypts, in
                                // `drain_inbound_one` (RFC 9000 §9.3 — an
                                // endpoint initiates validation on a
                                // *non-probing* packet from a new address,
                                // which requires processing it, i.e.
                                // authenticating it, first). The source is
                                // also used to path-associate PATH_CHALLENGE /
                                // PATH_RESPONSE (§8.2.2 / §8.2.3).
                                conn.recv_ip = ip;
                                conn.recv_port = port;
                                let take_peek = if peek_len <= QUIC_DGRAM_MAX {
                                    peek_len
                                } else {
                                    QUIC_DGRAM_MAX
                                };
                                conn.inbound[..take_peek].copy_from_slice(&peek[..take_peek]);
                                let remain = dlen - peek_len;
                                let want_remain = if remain + take_peek <= QUIC_DGRAM_MAX {
                                    remain
                                } else {
                                    QUIC_DGRAM_MAX - take_peek
                                };
                                if want_remain > 0 {
                                    (sys.channel_read)(
                                        s.net_in,
                                        conn.inbound.as_mut_ptr().add(take_peek),
                                        want_remain,
                                    );
                                }
                                conn.inbound_len = take_peek + want_remain;
                                // The datagram is written from offset 0, so the
                                // parse cursor must restart there. Without this
                                // reset, once the first datagram is consumed
                                // (inbound_off advances to inbound_len) every
                                // subsequent datagram is skipped by
                                // drain_inbound_one's `inbound_off >= inbound_len`
                                // guard, so retransmits and Handshake/1-RTT
                                // packets are silently dropped.
                                conn.inbound_off = 0;
                                let leftover = dlen - take_peek - want_remain;
                                if leftover > 0 {
                                    discard_bytes(sys, s.net_in, leftover);
                                }
                            } else {
                                let remain = dlen - peek_len;
                                if remain > 0 {
                                    discard_bytes(sys, s.net_in, remain);
                                }
                            }
                        } else {
                            discard_bytes(sys, s.net_in, dlen);
                        }
                    } else {
                        discard_bytes(sys, s.net_in, payload_len);
                    }
                }
                _ => {
                    discard_bytes(sys, s.net_in, payload_len);
                }
            }
        }
    }

    // Drive newly-arrived bytes through the queue path again.
    let mut i = 0;
    while i < MAX_CONNS {
        if s.conns[i].phase == ConnPhase::Handshaking && s.conns[i].inbound_len > 0 {
            let mut steps = 0;
            let t_start = dev_micros(&*s.syscalls);
            while steps < 64
                && s.conns[i].phase == ConnPhase::Handshaking
                && !handshake_budget_spent(&*s.syscalls, t_start)
            {
                let drained = drain_inbound_one(s, i);
                let progressed = pump_session(s, i);
                drain_outbound(s, i);
                if !drained && !progressed {
                    break;
                }
                steps += 1;
            }
        }
        i += 1;
    }

    // Drain Errored connections by emitting a CONNECTION_CLOSE frame
    // (RFC 9000 §10.2) with PROTOCOL_VIOLATION (0x0a, §20.1), then
    // transition to Closed.
    let mut i = 0;
    while i < MAX_CONNS {
        if s.conns[i].phase == ConnPhase::Errored {
            emit_connection_close(s, i, 0x0a, 0, b"protocol violation");
            s.conns[i].phase = ConnPhase::Closed;
        }
        i += 1;
    }

    // PTO timer + idle-timeout sweep (RFC 9000 §10.1).
    let now_ms_top = dev_millis(sys);
    let mut i = 0;
    while i < MAX_CONNS {
        if s.conns[i].phase == ConnPhase::Handshaking || s.conns[i].phase == ConnPhase::Established
        {
            quic_pto_check(s, i);
            // Silently close on `idle_timeout_ms` of no activity
            // (RFC 9000 §10.1 allows closing without notification).
            let last = s.conns[i].last_activity_ms;
            let limit = s.conns[i].idle_timeout_ms;
            if last > 0 && limit > 0 && now_ms_top.saturating_sub(last) > limit {
                s.conns[i].phase = ConnPhase::Closed;
                let msg = b"[quic] idle timeout";
                dev_log(sys, 3, msg.as_ptr(), msg.len());
            }
            // RFC 9000 §8.2.4: abandon a path validation that hasn't
            // completed within the timeout so the flag doesn't latch
            // forever (which would block a later genuine migration to the
            // same address). The active path is unchanged — we simply stop
            // waiting on this candidate.
            if s.conns[i].path_validating
                && s.conns[i].path_validate_ms > 0
                && now_ms_top.saturating_sub(s.conns[i].path_validate_ms) > PATH_VALIDATE_TIMEOUT_MS
            {
                s.conns[i].path_validating = false;
                s.conns[i].path_challenge_tx_pending = false;
            }
        }
        i += 1;
    }

    // Observability reaper: emit the `quic.connection` span for any
    // server-accepted connection that has reached `Closed` (via received
    // CONNECTION_CLOSE, protocol error, or idle timeout) and still has a
    // pending span. `emit_conn_span` is idempotent — it emits once and clears
    // the marker, so a lingering Closed slot is not re-emitted. No-op when
    // telemetry is unwired or the connection wasn't head-sampled.
    let mut i = 0;
    while i < MAX_CONNS {
        if s.conns[i].phase == ConnPhase::Closed {
            emit_conn_span(s, i);
            // Tell the application its session ended. Emitted here rather
            // than in the established-connection sweep because by now the
            // connection is no longer Established and that sweep no
            // longer visits it — an application otherwise learns nothing
            // and holds per-session state for a session that is gone.
            //
            // One-shot and retryable: it latches only on a successful
            // enqueue, so a backpressured close is retried on the next
            // step rather than dropped.
            mux_emit_session_closed(s, i, mux::STATUS_CLOSED);
            // RECYCLE the slot once everything owed has gone out (the span
            // is emitted above; the app notification has latched, or was
            // never owed because the session was never announced).
            // Returning the slot to Idle is what makes it reusable at all:
            // `alloc_server_connection` takes only Idle, so a slot left
            // Closed is consumed for good and the table exhausts after
            // MAX_CONNS dials — which anything redialing repeatedly reaches
            // in seconds. The slot's ECDH keypair is REGENERATED: an
            // "ephemeral" reused across connections is not one.
            let owed_app = s.conns[i].session_opened_sent && !s.conns[i].session_closed_sent;
            if !owed_app && s.conns[i].span_start_us == 0 {
                let mut random = [0u8; 32];
                if dev_csprng_fill(sys, random.as_mut_ptr(), 32) >= 0 {
                    let (priv_key, pub_key) = ecdh_keygen(&random);
                    s.eph_private[i] = priv_key;
                    s.eph_public[i] = pub_key;
                    s.eph_used[i] = false;
                    let mut j = 0;
                    while j < 32 {
                        core::ptr::write_volatile(&mut random[j], 0);
                        j += 1;
                    }
                    s.conns[i].reset();
                }
            }
        }
        i += 1;
    }

    // Client-side 0-RTT resumption: once the first connection is
    // Established and a ticket is cached, open a second handshake on a
    // free slot using that ticket so the PSK + early_data path runs
    // end-to-end in a single fluxor process.
    if s.mode == 0 && s.enable_0rtt != 0 && s.endpoint.is_ready() {
        let mut have_ticket = false;
        let mut active_count = 0;
        let mut t = 0;
        while t < MAX_TICKETS {
            if s.client_tickets[t].used {
                have_ticket = true;
                break;
            }
            t += 1;
        }
        let mut k = 0;
        while k < MAX_CONNS {
            if s.conns[k].phase != ConnPhase::Idle {
                active_count += 1;
            }
            k += 1;
        }
        if have_ticket && active_count == 1 && !s.pending_resumption_test {
            let ip_bytes = s.peer_ip.to_le_bytes();
            let ip = [ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]];
            if let Some(idx) = alloc_resumption_connection(s, &ip, s.peer_port) {
                s.pending_resumption_test = true;
                let mut steps = 0;
                let t_start = dev_micros(&*s.syscalls);
                while steps < 64
                    && s.conns[idx].phase == ConnPhase::Handshaking
                    && !handshake_budget_spent(&*s.syscalls, t_start)
                {
                    let progressed = pump_session(s, idx);
                    drain_outbound(s, idx);
                    if !progressed {
                        break;
                    }
                    steps += 1;
                }
                dev_log(
                    sys,
                    3,
                    b"[quic] resume started".as_ptr(),
                    b"[quic] resume started".len(),
                );
            }
        }
    }

    // Persist any received NewSessionTicket from a post-handshake
    // CRYPTO frame into the client-side ticket cache.
    let mut i = 0;
    while i < MAX_CONNS {
        if !s.conns[i].is_server && s.conns[i].session_ticket_handled && s.conns[i].psk_len > 0 {
            let psk_id_len = s.conns[i].psk_identity_len as usize;
            let mut already = false;
            let mut t = 0;
            while t < MAX_TICKETS {
                if s.client_tickets[t].used
                    && s.client_tickets[t].peer_ip == s.conns[i].peer.ip
                    && s.client_tickets[t].peer_port == s.conns[i].peer.port
                {
                    already = true;
                    break;
                }
                t += 1;
            }
            if !already {
                let mut t = 0;
                while t < MAX_TICKETS {
                    if !s.client_tickets[t].used {
                        let mut entry = ClientTicketEntry {
                            used: true,
                            peer_ip: s.conns[i].peer.ip,
                            peer_port: s.conns[i].peer.port,
                            ticket: [0; MAX_TICKET_LEN],
                            ticket_len: psk_id_len as u8,
                            rms: [0; 48],
                            rms_len: s.conns[i].psk_len,
                            suite_id: 0x1303,
                            issue_ms: dev_millis(sys),
                            ticket_age_add: 0,
                            lifetime_s: 7200,
                        };
                        let n = psk_id_len.min(entry.ticket.len());
                        entry.ticket[..n].copy_from_slice(&s.conns[i].psk_identity[..n]);
                        let pl = s.conns[i].psk_len as usize;
                        entry.rms[..pl].copy_from_slice(&s.conns[i].psk[..pl]);
                        s.client_tickets[t] = entry;
                        dev_log(
                            sys,
                            3,
                            b"[quic] ticket cached".as_ptr(),
                            b"[quic] ticket cached".len(),
                        );
                        break;
                    }
                    t += 1;
                }
            }
            // Mark this conn's ticket as fully drained so we don't
            // re-cache on every step.
            s.conns[i].psk_len = 0;
        }
        i += 1;
    }

    // Post-handshake: drain remaining inbound 1-RTT packets and
    // shuttle stream data between clear_in / clear_out.
    let mut i = 0;
    // The app-surface read happens ONCE per step, but it must not be pinned to
    // connection index 0: that block sits inside `phase == Established`, so
    // when connection 0 closes the app surface stops being read at all and
    // every later connection hangs waiting for its response. Latch on the first
    // established connection of the step instead.
    let mut app_in_read_done = false;
    // Which application-channel ENCODING this module was configured for.
    // `alpn` configured => the framed mux contract; otherwise the
    // transparent byte stream. This is a length test, never a comparison
    // against a protocol token: the transport does not recognise any.
    let mux_mode = s.alpn_cfg_len > 0;
    while i < MAX_CONNS {
        if s.conns[i].phase == ConnPhase::Established {
            // NEW_CONNECTION_ID issuance (RFC 9000 §5.1.1 / §19.15): once
            // the handshake is confirmed, mint one spare local CID
            // (sequence 1) and queue a NEW_CONNECTION_ID so a migrating
            // peer can present a fresh DCID on its new path. Gated on
            // migration being enabled (no point issuing CIDs we forbid
            // the peer from using) and our advertised
            // active_connection_id_limit = 2 (one spare).
            if s.disable_migration == 0
                && s.conns[i].handshake_confirmed
                && !s.conns[i].alt_cid_issued
            {
                let conn = &mut s.conns[i];
                // The spare CID and its stateless-reset token are minted from
                // the CSPRNG, and BOTH fills must succeed before the frame is
                // queued. On a platform whose entropy source can fail
                // transiently under load (the Pi 5's RNG200 times out and
                // returns an error), an unchecked fill leaves these buffers
                // zero, and the server then emits a NEW_CONNECTION_ID carrying
                // an all-zero CID and an all-zero reset token — which a
                // conforming peer rejects with a FRAME_ENCODING_ERROR
                // CONNECTION_CLOSE, killing a connection whose handshake had
                // just completed (measured: quiche closes err=7 right after
                // HANDSHAKE_DONE against the Pi 5 h3 server). When entropy is
                // unavailable the spare CID is simply not issued this step and
                // is retried on the next — the peer's active_connection_id_limit
                // is an offer this endpoint may decline, so declining until the
                // CSPRNG recovers is correct rather than sending zeros.
                // One-shot per connection: `alt_cid_issued` latches whether it
                // succeeds or not, so a connection whose spare CID cannot be
                // minted does NOT re-attempt every step. Retrying forever is a
                // hot loop — at a 50 us tick a single such connection burns
                // ~20000 fills a second — and it starved h3 connection setup on
                // the Pi 5, whose RNG200 re-presents zero words heavily
                // (`cidfail=` counted 326538 declines in one load run before
                // this). The spare CID is an offer the peer's
                // active_connection_id_limit invites but does not require, so
                // declining it for the connection's lifetime is correct; the
                // fill already retried past a transient reseed-zero within the
                // one attempt.
                let cid_ok = csprng_fill_nonzero(sys, conn.alt_cid.as_mut_ptr(), 8);
                let tok_ok = csprng_fill_nonzero(sys, conn.alt_cid_reset_token.as_mut_ptr(), 16);
                conn.alt_cid_issued = true;
                if cid_ok && tok_ok {
                    conn.alt_cid_len = 8;
                    conn.alt_cid_seq = 1;
                    conn.new_cid_tx_pending = true;
                } else {
                    // Declined for this connection: nothing queued, no retry.
                    conn.alt_cid_len = 0;
                    s.rng_cid_fail = s.rng_cid_fail.wrapping_add(1);
                }
            }
            // Inbound 1-RTT packets.
            if s.conns[i].inbound_len > 0 {
                let _ = drain_inbound_one(s, i);
            }
            if mux_mode {
                // Framed mux surface: everything the application can
                // observe about this session goes out here — session
                // lifecycle, peer identity, every stream's accept /
                // bytes / FIN / reset / stop, credit, and datagrams.
                //
                // One path for every session. There is no branch on the
                // negotiated protocol, because the transport does not
                // know what the protocol is.
                mux_pump_downstream(s, i);
            } else {
                // Transparent byte-stream surface (no `alpn` configured):
                // one raw stream, net_proto MSG_DATA framing, with the
                // server echoing what it receives. A different channel
                // ENCODING, not a different protocol — the mux contract
                // is simply not in play on this port.
                legacy_stream_forward(s, i);
                // Client-side auto-probe for the transparent path only.
                if !s.conns[i].is_server
                    && !s.conns[i].test_sent
                    && s.conns[i].stream_send_off == 0
                    && s.conns[i].stream_send_buf_len == 0
                {
                    let msg = b"hello quic stream";
                    let n = msg.len();
                    let conn = &mut s.conns[i];
                    core::ptr::copy_nonoverlapping(
                        msg.as_ptr(),
                        conn.stream_send_buf.as_mut_ptr(),
                        n,
                    );
                    conn.stream_send_buf_len = n;
                    conn.test_sent = true;
                }
            }
            // Read app→quic commands.
            //
            // Framed mux surface: drain a BOUNDED NUMBER of commands per
            // step rather than exactly one. One-per-step made the
            // connection preamble of any protocol that opens several
            // streams before it can speak cost one scheduler round trip
            // per stream; the bound keeps the step time fixed while
            // letting a burst of small commands clear together.
            //
            // A transparent module (no ALPN) reads app_in as a raw byte
            // stream into the current connection instead.
            if s.app_in >= 0 && mux_mode {
                if !app_in_read_done {
                    app_in_read_done = true;
                    mux_pump_upstream(s);
                }
            } else if s.app_in >= 0 {
                // Transparent (no-ALPN) raw byte stream → conn[i] stream.
                // Only read when the send buffer is drained so the whole
                // read fits (reliable); otherwise app_in backpressures.
                if s.conns[i].stream_send_buf_len == 0 {
                    let poll = (sys.channel_poll)(s.app_in, POLL_IN);
                    if poll > 0 && (poll as u32 & POLL_IN) != 0 {
                        let conn = &mut s.conns[i];
                        let mut tmp = [0u8; 1200];
                        let cap = tmp.len().min(conn.stream_send_buf.len());
                        let r = (sys.channel_read)(s.app_in, tmp.as_mut_ptr(), cap);
                        if r > 0 {
                            let n = r as usize;
                            core::ptr::copy_nonoverlapping(
                                tmp.as_ptr(),
                                conn.stream_send_buf.as_mut_ptr(),
                                n,
                            );
                            conn.stream_send_buf_len = n;
                            s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add(n as u32);
                        }
                    }
                }
            }
            // Emit any pending outbound stream data / ACKs (+ DATAGRAM).
            drain_outbound(s, i);
        }
        i += 1;
    }

    // StepOutcome::Continue (0). A `1` return maps to StepOutcome::Done
    // and would finalize the module; quic is a long-lived server/client
    // that must be stepped every tick to drain net_in and pump handshakes.
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub unsafe extern "C" fn module_destroy(_state: *mut u8) {}

/// Largest stream/datagram payload carried in one mux frame on the app
/// surface (bounds the per-call stack scratch). Matches the inbound
/// stream-reassembly + datagram staging buffers.
// The contract publishes this bound so a consumer can size its receive
// scratch from the same number the provider emits; deriving it here is what
// keeps the two from drifting apart.
const MUX_DATA_MAX: usize = mux::MUX_QUIC_STREAM_RX_MAX;

/// True when every connection's outbound stream buffer is drained, so a
/// freshly-read CMD_MUX_STREAM_SEND payload is guaranteed to land in full
/// (reliable backpressure: we don't consume an app frame we can't store).
unsafe fn drained_for_app_in(s: &QuicState) -> bool {
    let mut i = 0;
    while i < MAX_CONNS {
        // Only a LIVE connection can hold the surface up. A closed or errored
        // one keeps whatever was in its send buffer — nothing will ever
        // acknowledge it — and gating on that stalls the app surface for every
        // later connection: the first request works and the second never gets
        // its response read.
        let live = matches!(
            s.conns[i].phase,
            ConnPhase::Handshaking | ConnPhase::Established
        );
        if live && s.conns[i].stream_send_buf_len != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// Emit one length-prefixed mux frame (`abi::contracts::net::mux`) on
/// `app_out`: the universal `[msg_type:u8][len:u16 LE]` TLV header
/// followed by `[session_id:4 LE]`, an optional `[stream_id:4 LE]`, and
/// `data`. Returns true iff the whole frame was written. Channel writes
/// are all-or-nothing, so `false` means the channel was full and NOTHING
/// was written — the caller may safely retain the source bytes and retry.
unsafe fn mux_emit(
    sys: &SyscallTable,
    app_out: i32,
    msg_type: u8,
    session: u32,
    stream: Option<u32>,
    data: &[u8],
) -> bool {
    if app_out < 0 {
        return false;
    }
    let mut payload = [0u8; mux::STREAM_DATA_PREFIX + MUX_DATA_MAX];
    payload[0..4].copy_from_slice(&session.to_le_bytes());
    let mut p = mux::SESSION_ID_BYTES;
    if let Some(st) = stream {
        payload[p..p + 4].copy_from_slice(&st.to_le_bytes());
        p += mux::STREAM_ID_BYTES;
    }
    let n = data.len().min(payload.len() - p);
    payload[p..p + n].copy_from_slice(&data[..n]);
    let mut scratch = [0u8; NET_FRAME_HDR + mux::STREAM_DATA_PREFIX + MUX_DATA_MAX];
    net_write_frame(
        sys,
        app_out,
        msg_type,
        payload.as_ptr(),
        p + n,
        scratch.as_mut_ptr(),
        scratch.len(),
    ) != 0
}
/// A read-only snapshot of one stream slot, taken so the emission path
/// can decide what to send without holding a borrow on `s` across the
/// channel writes.
///
/// Copying ~60 bytes per stream per step is cheaper than the
/// alternatives: threading a borrow through the emit calls fights the
/// fixed-array layout, and dispatching over the two pool shapes through
/// a trait object is not available here at all — these modules are
/// position-independent with no relocation processing for a vtable, so a
/// trait-object call jumps to an unrelocated address and faults the
/// runtime rather than failing the build.
#[derive(Clone, Copy)]
struct StreamSnap {
    handle: u32,
    quic_id: u64,
    locally_initiated: bool,
    is_bidi: bool,
    recv_buf_len: usize,
    recv_fin: bool,
    send_buf_len: usize,
    send_fin_emitted: bool,
    open_sent: bool,
    close_sent: bool,
    reset_sent: bool,
    stopped_sent: bool,
    recv_reset: bool,
    recv_reset_error: u64,
    recv_stop: bool,
    recv_stop_error: u64,
    reset_emitted: bool,
    reset_pending: bool,
}

/// Snapshot an allocated slot, or `None` when the slot is free.
unsafe fn stream_snap(conn: &QuicConnection, loc: StreamLoc) -> Option<StreamSnap> {
    match loc {
        StreamLoc::Bidi(k) => {
            let st = &conn.bidi_streams[k];
            if !st.allocated {
                return None;
            }
            Some(StreamSnap {
                handle: st.app.handle,
                quic_id: st.stream_id,
                locally_initiated: st.locally_initiated,
                is_bidi: true,
                recv_buf_len: st.recv_buf_len,
                recv_fin: st.recv_fin,
                send_buf_len: st.send_buf_len,
                send_fin_emitted: st.send_fin_emitted,
                open_sent: st.app.open_sent,
                close_sent: st.app.close_sent,
                reset_sent: st.app.reset_sent,
                stopped_sent: st.app.stopped_sent,
                recv_reset: st.abort.recv_reset,
                recv_reset_error: st.abort.recv_reset_error,
                recv_stop: st.abort.recv_stop,
                recv_stop_error: st.abort.recv_stop_error,
                reset_emitted: st.abort.reset_emitted,
                reset_pending: st.abort.reset_pending,
            })
        }
        StreamLoc::Uni(k) => {
            let st = &conn.uni_streams[k];
            if !st.allocated {
                return None;
            }
            Some(StreamSnap {
                handle: st.app.handle,
                quic_id: st.stream_id,
                locally_initiated: st.locally_initiated,
                is_bidi: false,
                recv_buf_len: st.recv_buf_len,
                recv_fin: st.recv_fin,
                send_buf_len: st.send_buf_len,
                send_fin_emitted: st.send_fin_emitted,
                open_sent: st.app.open_sent,
                close_sent: st.app.close_sent,
                reset_sent: st.app.reset_sent,
                stopped_sent: st.app.stopped_sent,
                recv_reset: st.abort.recv_reset,
                recv_reset_error: st.abort.recv_reset_error,
                recv_stop: st.abort.recv_stop,
                recv_stop_error: st.abort.recv_stop_error,
                reset_emitted: st.abort.reset_emitted,
                reset_pending: st.abort.reset_pending,
            })
        }
    }
}

/// Mutable access to the per-slot `AppStreamView`, which is the only
/// part of a slot the emission path writes back.
unsafe fn stream_app_mut(conn: &mut QuicConnection, loc: StreamLoc) -> &mut AppStreamView {
    match loc {
        StreamLoc::Bidi(k) => &mut conn.bidi_streams[k].app,
        StreamLoc::Uni(k) => &mut conn.uni_streams[k].app,
    }
}

/// Copy up to `cap` bytes out of a slot's receive buffer.
unsafe fn stream_peek_recv(conn: &QuicConnection, loc: StreamLoc, out: &mut [u8]) -> usize {
    let (src, len) = match loc {
        StreamLoc::Bidi(k) => (
            conn.bidi_streams[k].recv_buf.as_ptr(),
            conn.bidi_streams[k].recv_buf_len,
        ),
        StreamLoc::Uni(k) => (
            conn.uni_streams[k].recv_buf.as_ptr(),
            conn.uni_streams[k].recv_buf_len,
        ),
    };
    let n = len.min(out.len());
    core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), n);
    n
}

/// Drop `n` delivered bytes off the front of a slot's receive buffer,
/// keeping any tail that did not fit in one mux frame.
unsafe fn stream_consume_recv(conn: &mut QuicConnection, loc: StreamLoc, n: usize) {
    let (buf, len) = match loc {
        StreamLoc::Bidi(k) => (
            conn.bidi_streams[k].recv_buf.as_mut_ptr(),
            &mut conn.bidi_streams[k].recv_buf_len,
        ),
        StreamLoc::Uni(k) => (
            conn.uni_streams[k].recv_buf.as_mut_ptr(),
            &mut conn.uni_streams[k].recv_buf_len,
        ),
    };
    let rest = len.saturating_sub(n);
    if rest > 0 {
        core::ptr::copy(buf.add(n), buf, rest);
    }
    *len = rest;
}

/// The direction/initiator flag byte for an opened or accepted event.
fn stream_flags(snap: &StreamSnap) -> u8 {
    let mut f = if snap.is_bidi {
        mux::STREAM_FLAG_BIDI
    } else {
        mux::STREAM_FLAG_UNI
    };
    if snap.locally_initiated {
        f |= mux::STREAM_FLAG_LOCAL_INIT;
    }
    f
}

/// Free a slot and hand the peer credit for another stream of that kind.
unsafe fn stream_release(conn: &mut QuicConnection, loc: StreamLoc) {
    match loc {
        StreamLoc::Bidi(k) => {
            let peer_opened = !conn.bidi_streams[k].locally_initiated;
            conn.bidi_streams[k] = BidiStream::empty();
            // Freeing the slot is only half of it. The peer's ability to
            // OPEN another stream is governed by MAX_STREAMS credit (RFC
            // 9000 §4.6), which is cumulative — so without this a
            // connection is limited to its initial allowance for life,
            // and simply stops serving with no error on either side.
            // Only a slot the PEER used consumed peer credit.
            if peer_opened {
                conn.max_streams_bidi_granted = conn.max_streams_bidi_granted.saturating_add(1);
                conn.max_streams_tx_pending = true;
            }
        }
        StreamLoc::Uni(k) => {
            let peer_opened = !conn.uni_streams[k].locally_initiated;
            conn.uni_streams[k] = UniStream::empty();
            if peer_opened {
                conn.max_streams_uni_granted = conn.max_streams_uni_granted.saturating_add(1);
                conn.max_streams_uni_tx_pending = true;
            }
        }
    }
}

/// Deliver everything one stream currently owes the application, in the
/// order the contract requires: existence first, then bytes, then a
/// terminal event.
///
/// Returns false when the app channel refused a write. The caller stops
/// the whole sweep on false — every event here is reliable, so the slot
/// keeps its state and the identical sequence is retried next step. What
/// makes that safe is that each latch is set ONLY after its own
/// successful enqueue, and receive bytes are consumed the moment
/// STREAM_RX lands: a later backpressured terminal event can therefore
/// never cause already-delivered bytes to be emitted twice.
#[must_use]
unsafe fn stream_deliver(s: &mut QuicState, idx: usize, loc: StreamLoc) -> bool {
    let sys = &*s.syscalls;
    let session = idx as u32;
    let snap = match stream_snap(&s.conns[idx], loc) {
        Some(v) => v,
        None => return true,
    };

    // 1. The application must know the stream exists before anything
    //    about it can mean something. A locally-opened stream already
    //    got its MSG_MUX_STREAM_OPENED when the open was answered; a
    //    peer-opened one is announced here.
    if !snap.open_sent {
        if snap.locally_initiated {
            // Answered synchronously by the open command; nothing owed.
            stream_app_mut(&mut s.conns[idx], loc).open_sent = true;
        } else {
            let mut body = [0u8; mux::STREAM_ACCEPTED_BODY];
            body[0] = stream_flags(&snap);
            body[1..9].copy_from_slice(&snap.quic_id.to_le_bytes());
            if !mux_emit(
                sys,
                s.app_out,
                mux::MSG_MUX_STREAM_ACCEPTED,
                session,
                Some(snap.handle),
                &body,
            ) {
                return false;
            }
            stream_app_mut(&mut s.conns[idx], loc).open_sent = true;
        }
    }

    // 2. Ordered bytes. Every byte the peer sent, including the first —
    //    this transport does not read, classify, or strip a leading
    //    varint that an application protocol may use as a stream type.
    if snap.recv_buf_len > 0 {
        let mut data = [0u8; MUX_DATA_MAX];
        let cn = stream_peek_recv(&s.conns[idx], loc, &mut data);
        if cn > 0 {
            if !mux_emit(
                sys,
                s.app_out,
                mux::MSG_MUX_STREAM_RX,
                session,
                Some(snap.handle),
                &data[..cn],
            ) {
                return false;
            }
            s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(cn as u32);
            stream_consume_recv(&mut s.conns[idx], loc, cn);
        }
    }

    // 3. A peer STOP_SENDING is not terminal for the stream — it asks us
    //    to stop producing — so it is delivered before any close.
    if snap.recv_stop && !snap.stopped_sent {
        let mut body = [0u8; mux::STREAM_APP_ERROR_BODY];
        body.copy_from_slice(&snap.recv_stop_error.to_le_bytes());
        if !mux_emit(
            sys,
            s.app_out,
            mux::MSG_MUX_STREAM_STOPPED,
            session,
            Some(snap.handle),
            &body,
        ) {
            return false;
        }
        stream_app_mut(&mut s.conns[idx], loc).stopped_sent = true;
    }

    // 4. Terminal events. A reset supersedes a clean close: the peer
    //    abandoned the stream rather than finishing it, and telling the
    //    application it ended cleanly would be a lie about whether the
    //    bytes it did not receive were ever coming.
    let refreshed = match stream_snap(&s.conns[idx], loc) {
        Some(v) => v,
        None => return true,
    };
    if refreshed.recv_reset && !refreshed.reset_sent {
        let mut body = [0u8; mux::STREAM_APP_ERROR_BODY];
        body.copy_from_slice(&refreshed.recv_reset_error.to_le_bytes());
        if !mux_emit(
            sys,
            s.app_out,
            mux::MSG_MUX_STREAM_RESET,
            session,
            Some(refreshed.handle),
            &body,
        ) {
            return false;
        }
        stream_app_mut(&mut s.conns[idx], loc).reset_sent = true;
    } else if refreshed.recv_fin && refreshed.recv_buf_len == 0 && !refreshed.close_sent {
        // Emitted for an empty FIN too — a stream the peer opens and
        // closes without payload still owes its close, or the
        // application waits forever for a stream that is already over.
        let reason = [mux::STATUS_OK];
        if !mux_emit(
            sys,
            s.app_out,
            mux::MSG_MUX_STREAM_CLOSED,
            session,
            Some(refreshed.handle),
            &reason,
        ) {
            return false;
        }
        stream_app_mut(&mut s.conns[idx], loc).close_sent = true;
    }

    // 5. Reclaim. Only once BOTH halves are finished AND every
    //    notification about them has actually been delivered — recycling
    //    a slot earlier would hand its handle to a new stream while the
    //    application still believed the old one was live.
    let done = match stream_snap(&s.conns[idx], loc) {
        Some(v) => v,
        None => return true,
    };
    let recv_done = (done.recv_fin && done.close_sent) || (done.recv_reset && done.reset_sent);
    // A peer-initiated unidirectional stream has no send half, and a
    // locally-initiated one has no recv half.
    let send_half_applies = done.is_bidi || done.locally_initiated;
    let send_done = !send_half_applies
        || (done.send_buf_len == 0 && done.send_fin_emitted)
        || (done.reset_emitted && !done.reset_pending);
    let recv_half_applies = done.is_bidi || !done.locally_initiated;
    if send_done && (!recv_half_applies || recv_done) {
        stream_release(&mut s.conns[idx], loc);
    }
    true
}

/// Everything this connection owes the application this step, on the
/// framed mux surface.
///
/// One path for every session. There is no branch on the negotiated
/// protocol anywhere below, because the transport does not know what the
/// protocol is — it knows there is a session, that the session has
/// streams, and that bytes on those streams belong to somebody else.
unsafe fn mux_pump_downstream(s: &mut QuicState, idx: usize) {
    if s.app_out < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let session = idx as u32;

    // 1. The session itself, before anything that belongs to it. An
    //    application must never have to assume session 0, discover a
    //    session from the first stream that arrives on it, or reach into
    //    the transport's connection table.
    if !s.conns[idx].session_opened_sent {
        let alpn_len = s.conns[idx].alpn_selected_len as usize;
        let mut body = [0u8; mux::SESSION_OPENED_BODY_MIN + MAX_ALPN];
        body[0] = mux::STATUS_OK;
        body[1] = if s.conns[idx].is_server {
            0
        } else {
            mux::SESSION_FLAG_LOCAL_INIT
        };
        body[2] = alpn_len as u8;
        body[3..3 + alpn_len].copy_from_slice(&s.conns[idx].alpn_selected[..alpn_len]);
        if !mux_emit(
            sys,
            s.app_out,
            mux::MSG_MUX_SESSION_OPENED,
            session,
            None,
            &body[..mux::SESSION_OPENED_BODY_MIN + alpn_len],
        ) {
            return; // retry the whole session next step
        }
        s.conns[idx].session_opened_sent = true;
    }

    // 2. Peer identity, for every session — the authenticated binding is
    //    a property of the secure transport, not of any one protocol
    //    that runs over it. Minimal form: no client cert → verified=0.
    if s.conns[idx].handshake_confirmed && !s.conns[idx].peer_identity_sent {
        // The full record, reporting NO_CREDENTIAL. This provider does
        // not request a client certificate, so there is nothing to
        // verify and no check ran — which is what the zeroed
        // `verification_flags` says. An application reading this
        // learns "no identity was established here", not "an identity
        // was established and it is anonymous"; the previous
        // `verified=0` byte could not tell those apart from a
        // credential that failed.
        //
        // `mux_emit` writes the session id, so the body starts at the
        // record's second field.
        const RESULT_NO_CREDENTIAL: u8 = 1;
        let mut body = [0u8; mux::PEER_IDENTITY_FIXED_LEN - 4];
        body[0] = RESULT_NO_CREDENTIAL;
        if !mux_emit(
            sys,
            s.app_out,
            mux::MSG_MUX_PEER_IDENTITY,
            session,
            None,
            &body,
        ) {
            return;
        }
        s.conns[idx].peer_identity_sent = true;
    }

    // 3. Every stream, both pools, bidirectional and unidirectional
    //    alike, whoever opened it.
    let mut k = 0;
    while k < MAX_BIDI_STREAMS {
        if !stream_deliver(s, idx, StreamLoc::Bidi(k)) {
            return;
        }
        k += 1;
    }
    let mut k = 0;
    while k < MAX_UNI_STREAMS {
        if !stream_deliver(s, idx, StreamLoc::Uni(k)) {
            return;
        }
        k += 1;
    }

    // 4. Inbound datagrams (RFC 9221), on every session. Unreliable by
    //    contract: the single slot is cleared whether or not the
    //    forward succeeds, because a retained datagram is a datagram
    //    delivered late, which §5.2 does not promise and an application
    //    reading them must not be given.
    if s.conns[idx].dgram_rx_pending {
        let dn = s.conns[idx].dgram_rx_len;
        let mut data = [0u8; QUIC_MAX_DATAGRAM_SIZE];
        core::ptr::copy_nonoverlapping(s.conns[idx].dgram_rx.as_ptr(), data.as_mut_ptr(), dn);
        if mux_emit(
            sys,
            s.app_out,
            mux::MSG_MUX_DATAGRAM_RX,
            session,
            None,
            &data[..dn],
        ) {
            s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(dn as u32);
        }
        s.conns[idx].dgram_rx_pending = false;
        s.conns[idx].dgram_rx_len = 0;
    }
}

/// Announce a session's end exactly once, to an application that was
/// told the session began.
///
/// Called from the close paths rather than the established-connection
/// sweep, because by then the connection is no longer Established and
/// the sweep does not run for it.
unsafe fn mux_emit_session_closed(s: &mut QuicState, idx: usize, reason: u8) {
    if s.app_out < 0 || !s.conns[idx].framed_app_surface {
        return;
    }
    if !s.conns[idx].session_opened_sent || s.conns[idx].session_closed_sent {
        return;
    }
    let sys = &*s.syscalls;
    let body = [reason];
    if mux_emit(
        sys,
        s.app_out,
        mux::MSG_MUX_SESSION_CLOSED,
        idx as u32,
        None,
        &body,
    ) {
        s.conns[idx].session_closed_sent = true;
    }
}

/// Report a refused reliable command, so the application learns its
/// bytes did not go out instead of watching them vanish.
unsafe fn mux_emit_stream_error(s: &mut QuicState, idx: usize, handle: u32, errno: i8) {
    let sys = &*s.syscalls;
    let body = [errno as u8];
    let _ = mux_emit(
        sys,
        s.app_out,
        mux::MSG_MUX_STREAM_ERROR,
        idx as u32,
        Some(handle),
        &body,
    );
}

// ---------------------------------------------------------------------
// Application commands (app → quic)
// ---------------------------------------------------------------------

/// Open a stream locally, in whichever direction was asked for.
///
/// Returns the app handle and the QUIC stream id, or None when there is
/// no slot or no peer MAX_STREAMS credit. A refused open is reported to
/// the application as STATUS_NO_CAPACITY and, where the peer is the
/// limit, a STREAMS_BLOCKED frame tells the peer we wanted one — so a
/// stalled application has a cause on both sides rather than silence.
unsafe fn stream_open_local(s: &mut QuicState, cid: usize, flags: u8) -> Option<(u32, u64)> {
    if cid >= MAX_CONNS {
        return None;
    }
    let is_server = s.conns[cid].is_server;
    let want_uni = flags & mux::STREAM_FLAG_UNI != 0;
    let conn = &mut s.conns[cid];
    if want_uni {
        if conn.local_uni_opened >= conn.peer_max_streams_uni {
            conn.streams_blocked_uni_pending = true;
            return None;
        }
        let id = if is_server {
            next_server_uni_id(conn.next_uni_idx)
        } else {
            next_client_uni_id(conn.next_uni_idx)
        };
        let slot = uni_alloc(conn, id, true)?;
        conn.next_uni_idx = conn.next_uni_idx.wrapping_add(1);
        conn.local_uni_opened = conn.local_uni_opened.saturating_add(1);
        return Some((conn.uni_streams[slot].app.handle, id));
    }
    if conn.local_bidi_opened >= conn.peer_max_streams_bidi {
        conn.streams_blocked_bidi_pending = true;
        return None;
    }
    let id = if is_server {
        next_server_bidi_id(conn.next_bidi_idx)
    } else {
        next_client_bidi_id(conn.next_bidi_idx)
    };
    let slot = bidi_alloc(conn, id, true)?;
    conn.next_bidi_idx = conn.next_bidi_idx.wrapping_add(1);
    conn.local_bidi_opened = conn.local_bidi_opened.saturating_add(1);
    Some((conn.bidi_streams[slot].app.handle, id))
}

/// Stage application bytes onto a stream's send buffer.
///
/// All-or-nothing: a write that does not fit whole is refused, never
/// truncated and never partially applied. Truncating a reliable write is
/// worse than refusing it — the application has no way to learn which
/// suffix was dropped, and the stream carries a silently corrupted
/// message from then on.
unsafe fn stream_stage_send(s: &mut QuicState, cid: usize, handle: u32, data: &[u8]) -> bool {
    if cid >= MAX_CONNS {
        return false;
    }
    let loc = match locate_handle(&s.conns[cid], handle) {
        Some(l) => l,
        None => return false,
    };
    // Connection-level flow control (RFC 9000 §4.1) applies across every
    // stream, so a write can be refused by the aggregate window even
    // when its own stream has room.
    let conn = &mut s.conns[cid];
    let need = data.len() as u64;
    if conn.send_data_used.saturating_add(need) > conn.send_max_data {
        conn.data_blocked_pending = true;
        return false;
    }
    let ok = match loc {
        StreamLoc::Bidi(k) => {
            let st = &mut conn.bidi_streams[k];
            let space = st.send_buf.len() - st.send_buf_len;
            let window_left = st.flow.send_max_data.saturating_sub(st.send_off);
            if need > window_left {
                st.flow.send_blocked_pending = true;
                false
            } else if data.len() > space {
                false
            } else {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    st.send_buf.as_mut_ptr().add(st.send_buf_len),
                    data.len(),
                );
                st.send_buf_len += data.len();
                true
            }
        }
        StreamLoc::Uni(k) => {
            let st = &mut conn.uni_streams[k];
            if !st.locally_initiated {
                // A unidirectional stream the PEER opened is receive-only
                // for us; there is no send half to write to.
                false
            } else {
                let space = st.send_buf.len() - st.send_buf_len;
                let window_left = st.flow.send_max_data.saturating_sub(st.send_off);
                if need > window_left {
                    st.flow.send_blocked_pending = true;
                    false
                } else if data.len() > space {
                    false
                } else {
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr(),
                        st.send_buf.as_mut_ptr().add(st.send_buf_len),
                        data.len(),
                    );
                    st.send_buf_len += data.len();
                    true
                }
            }
        }
    };
    if ok {
        conn.send_data_used = conn.send_data_used.saturating_add(need);
        s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add(data.len() as u32);
    }
    ok
}

/// Mark a stream's local send half finished, so a STREAM frame with FIN
/// goes out once its buffer drains.
unsafe fn stream_fin_local(s: &mut QuicState, cid: usize, handle: u32) -> bool {
    if cid >= MAX_CONNS {
        return false;
    }
    match locate_handle(&s.conns[cid], handle) {
        Some(StreamLoc::Bidi(k)) => {
            s.conns[cid].bidi_streams[k].send_fin_pending = true;
            true
        }
        Some(StreamLoc::Uni(k)) => {
            if !s.conns[cid].uni_streams[k].locally_initiated {
                return false;
            }
            s.conns[cid].uni_streams[k].send_fin_pending = true;
            true
        }
        None => false,
    }
}

/// Queue a RESET_STREAM carrying the application's opaque error code,
/// discarding whatever was still buffered for that stream.
unsafe fn stream_reset_local(s: &mut QuicState, cid: usize, handle: u32, app_error: u64) -> bool {
    if cid >= MAX_CONNS {
        return false;
    }
    match locate_handle(&s.conns[cid], handle) {
        Some(StreamLoc::Bidi(k)) => {
            let st = &mut s.conns[cid].bidi_streams[k];
            st.abort.reset_pending = true;
            st.abort.reset_error = app_error;
            st.send_buf_len = 0;
            true
        }
        Some(StreamLoc::Uni(k)) => {
            let st = &mut s.conns[cid].uni_streams[k];
            if !st.locally_initiated {
                return false;
            }
            st.abort.reset_pending = true;
            st.abort.reset_error = app_error;
            st.send_buf_len = 0;
            true
        }
        None => false,
    }
}

/// Queue a STOP_SENDING carrying the application's opaque error code.
unsafe fn stream_stop_local(s: &mut QuicState, cid: usize, handle: u32, app_error: u64) -> bool {
    if cid >= MAX_CONNS {
        return false;
    }
    match locate_handle(&s.conns[cid], handle) {
        Some(StreamLoc::Bidi(k)) => {
            let st = &mut s.conns[cid].bidi_streams[k];
            st.abort.stop_pending = true;
            st.abort.stop_error = app_error;
            true
        }
        Some(StreamLoc::Uni(k)) => {
            let st = &mut s.conns[cid].uni_streams[k];
            if st.locally_initiated {
                // Our own unidirectional stream: nothing is arriving on
                // it to ask the peer to stop.
                return false;
            }
            st.abort.stop_pending = true;
            st.abort.stop_error = app_error;
            true
        }
        None => false,
    }
}

/// Record that the application has consumed `bytes` from a stream, and
/// advance the receive windows if that has opened enough room to be
/// worth a frame.
///
/// This is the only thing that moves MAX_STREAM_DATA and MAX_DATA. The
/// transport does not invent credit on the application's behalf: doing
/// so would advertise buffer space that the application has not actually
/// freed, and the peer would fill it.
unsafe fn stream_ack_credit(s: &mut QuicState, cid: usize, handle: u32, bytes: u32) -> bool {
    if cid >= MAX_CONNS {
        return false;
    }
    let loc = match locate_handle(&s.conns[cid], handle) {
        Some(l) => l,
        None => return false,
    };
    let conn = &mut s.conns[cid];
    let n = bytes as u64;
    let flow = match loc {
        StreamLoc::Bidi(k) => &mut conn.bidi_streams[k].flow,
        StreamLoc::Uni(k) => &mut conn.uni_streams[k].flow,
    };
    flow.recv_consumed = flow.recv_consumed.saturating_add(n);
    // Advance by a whole window once the application is half way through
    // one — one frame per window rather than one per read.
    if flow.recv_consumed + LOCAL_STREAM_WINDOW / FLOW_UPDATE_DIVISOR >= flow.recv_max_data {
        flow.recv_max_data = flow.recv_consumed.saturating_add(LOCAL_STREAM_WINDOW);
        flow.recv_max_data_tx_pending = true;
    }
    conn.recv_data_consumed = conn.recv_data_consumed.saturating_add(n);
    if conn.recv_data_consumed + LOCAL_CONN_WINDOW / FLOW_UPDATE_DIVISOR >= conn.recv_max_data {
        conn.recv_max_data = conn.recv_data_consumed.saturating_add(LOCAL_CONN_WINDOW);
        conn.max_data_tx_pending = true;
    }
    true
}

/// Largest number of application commands consumed in one step.
///
/// Bounded rather than unbounded so one busy application cannot starve
/// the packet path, and more than one so a protocol whose connection
/// preamble opens several streams before it can speak does not pay a
/// scheduler round trip per stream.
const MUX_CMDS_PER_STEP: usize = 8;

/// Drain up to [`MUX_CMDS_PER_STEP`] application commands.
unsafe fn mux_pump_upstream(s: &mut QuicState) {
    let sys = &*s.syscalls;
    let mut budget = 0usize;
    while budget < MUX_CMDS_PER_STEP {
        budget += 1;
        if !drained_for_app_in(s) {
            // Reliable backpressure: we only take a command when the
            // addressed connection can store its payload in full, so a
            // CMD_MUX_STREAM_SEND always lands whole. Until then app_in
            // fills and the application blocks.
            return;
        }
        let p = (sys.channel_poll)(s.app_in, POLL_IN);
        if p <= 0 || (p as u32 & POLL_IN) == 0 {
            return;
        }
        // Largest frame we accept on this surface. The
        // alignment-preserving reader drains any payload beyond this so
        // an oversize frame can neither desync the FIFO (its tail being
        // mis-parsed as the next header) nor be silently truncated.
        let mut buf =
            [0u8; NET_FRAME_HDR + mux::STREAM_DATA_PREFIX + mux::MUX_QUIC_STREAM_SEND_MAX];
        let (mt, plen, full_plen) =
            net_read_frame_aligned(sys, s.app_in, buf.as_mut_ptr(), buf.len());
        if plen == 0 && full_plen == 0 {
            return;
        }
        if plen < full_plen {
            // Oversize reliable write: the reader already drained the
            // tail to stay frame-aligned. Refuse the whole frame rather
            // than act on a truncated prefix.
            let m = b"[quic] mux frame over max - rejected";
            dev_log(sys, 2, m.as_ptr(), m.len());
            continue;
        }
        let payload = &buf[NET_FRAME_HDR..NET_FRAME_HDR + plen];
        mux_apply_command(s, mt, payload);
    }
}

/// Apply one decoded application command.
unsafe fn mux_apply_command(s: &mut QuicState, mt: u8, payload: &[u8]) {
    let sys = &*s.syscalls;
    if plen_lt(payload, mux::SESSION_ID_BYTES) {
        return;
    }
    let cid = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if cid >= MAX_CONNS {
        return;
    }
    // Stream-scoped commands share a prefix; decode it once.
    let handle = if payload.len() >= mux::STREAM_DATA_PREFIX {
        u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]])
    } else {
        0
    };
    match mt {
        mux::CMD_MUX_STREAM_OPEN => {
            let flags = if payload.len() > mux::SESSION_ID_BYTES {
                payload[mux::SESSION_ID_BYTES]
            } else {
                mux::STREAM_FLAG_BIDI
            };
            let opened = stream_open_local(s, cid, flags);
            let mut body = [0u8; mux::STREAM_OPENED_BODY];
            match opened {
                Some((h, quic_id)) => {
                    body[0] = mux::STATUS_OK;
                    body[1] = flags | mux::STREAM_FLAG_LOCAL_INIT;
                    body[2..10].copy_from_slice(&quic_id.to_le_bytes());
                    let _ = mux_emit(
                        sys,
                        s.app_out,
                        mux::MSG_MUX_STREAM_OPENED,
                        cid as u32,
                        Some(h),
                        &body,
                    );
                }
                None => {
                    body[0] = mux::STATUS_NO_CAPACITY;
                    body[1] = flags | mux::STREAM_FLAG_LOCAL_INIT;
                    let _ = mux_emit(
                        sys,
                        s.app_out,
                        mux::MSG_MUX_STREAM_OPENED,
                        cid as u32,
                        Some(0),
                        &body,
                    );
                }
            }
        }
        mux::CMD_MUX_STREAM_SEND => {
            if payload.len() < mux::STREAM_DATA_PREFIX {
                return;
            }
            let data = &payload[mux::STREAM_DATA_PREFIX..];
            if !stream_stage_send(s, cid, handle, data) {
                // Never silently dropped: the application is told the
                // bytes did not go out, so it can retry them.
                mux_emit_stream_error(s, cid, handle, abi::errno::EAGAIN as i8);
            }
        }
        mux::CMD_MUX_STREAM_CLOSE => {
            if payload.len() < mux::STREAM_DATA_PREFIX {
                return;
            }
            if !stream_fin_local(s, cid, handle) {
                mux_emit_stream_error(s, cid, handle, abi::errno::EINVAL as i8);
            }
        }
        mux::CMD_MUX_STREAM_RESET => {
            if payload.len() < mux::STREAM_DATA_PREFIX + mux::STREAM_APP_ERROR_BODY {
                return;
            }
            let app_error = le_u64(&payload[mux::STREAM_DATA_PREFIX..]);
            if !stream_reset_local(s, cid, handle, app_error) {
                mux_emit_stream_error(s, cid, handle, abi::errno::EINVAL as i8);
            }
        }
        mux::CMD_MUX_STREAM_STOP_SENDING => {
            if payload.len() < mux::STREAM_DATA_PREFIX + mux::STREAM_APP_ERROR_BODY {
                return;
            }
            let app_error = le_u64(&payload[mux::STREAM_DATA_PREFIX..]);
            if !stream_stop_local(s, cid, handle, app_error) {
                mux_emit_stream_error(s, cid, handle, abi::errno::EINVAL as i8);
            }
        }
        mux::CMD_MUX_STREAM_ACK => {
            if payload.len() < mux::STREAM_DATA_PREFIX + 4 {
                return;
            }
            let n = u32::from_le_bytes([
                payload[mux::STREAM_DATA_PREFIX],
                payload[mux::STREAM_DATA_PREFIX + 1],
                payload[mux::STREAM_DATA_PREFIX + 2],
                payload[mux::STREAM_DATA_PREFIX + 3],
            ]);
            let _ = stream_ack_credit(s, cid, handle, n);
        }
        mux::CMD_MUX_DATAGRAM_SEND => {
            let data = &payload[mux::SESSION_ID_BYTES..];
            // Available on every session. The negotiated max is enforced
            // and the payload is never inspected.
            let pmax = s.conns[cid].peer_max_datagram_frame_size as usize;
            if pmax > 0 && data.len() <= pmax && data.len() <= QUIC_MAX_DATAGRAM_SIZE {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    s.conns[cid].dgram_tx.as_mut_ptr(),
                    data.len(),
                );
                s.conns[cid].dgram_tx_len = data.len();
                s.conns[cid].dgram_tx_pending = true;
                s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add(data.len() as u32);
            }
        }
        mux::CMD_MUX_SESSION_CLOSE => {
            // The application is done with the session. Move it to
            // Closed; the idle sweep emits the close frame and frees the
            // slot, and `mux_emit_session_closed` tells the application
            // it happened.
            s.conns[cid].phase = ConnPhase::Closed;
        }
        _ => {}
    }
}

/// Length guard shared by the command decoders.
#[inline(always)]
fn plen_lt(payload: &[u8], need: usize) -> bool {
    payload.len() < need
}

/// Read a little-endian u64 from the front of `b`, or 0 if it is short.
#[inline(always)]
fn le_u64(b: &[u8]) -> u64 {
    if b.len() < 8 {
        return 0;
    }
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// The transparent (no-ALPN) byte-stream surface: log inbound bytes,
/// echo them back on the server, and forward them to `app_out` with
/// net_proto MSG_DATA framing.
///
/// Kept apart from the mux path on purpose. It is one raw stream with no
/// session or stream identity of its own, so it has nothing to say on a
/// contract built around both.
unsafe fn legacy_stream_forward(s: &mut QuicState, idx: usize) {
    let sys = &*s.syscalls;
    let n = s.conns[idx].stream_recv_buf_len;
    if n == 0 {
        return;
    }
    let mut log_buf = [0u8; 96];
    let prefix = b"[quic] stream rx=";
    let mut p = 0;
    for &c in prefix {
        log_buf[p] = c;
        p += 1;
    }
    let copy_n = n.min(log_buf.len() - p);
    core::ptr::copy_nonoverlapping(
        s.conns[idx].stream_recv_buf.as_ptr(),
        log_buf.as_mut_ptr().add(p),
        copy_n,
    );
    p += copy_n;
    dev_log(sys, 3, log_buf.as_ptr(), p);
    if s.conns[idx].is_server {
        let conn = &mut s.conns[idx];
        let space = conn.stream_send_buf.len() - conn.stream_send_buf_len;
        let to_copy = n.min(space);
        core::ptr::copy_nonoverlapping(
            conn.stream_recv_buf.as_ptr(),
            conn.stream_send_buf
                .as_mut_ptr()
                .add(conn.stream_send_buf_len),
            to_copy,
        );
        conn.stream_send_buf_len += to_copy;
    }
    if s.app_out >= 0 {
        let mut frame = [0u8; 1600];
        if 3 + n <= frame.len() {
            frame[0] = 0x02;
            frame[1] = n as u8;
            frame[2] = (n >> 8) as u8;
            core::ptr::copy_nonoverlapping(
                s.conns[idx].stream_recv_buf.as_ptr(),
                frame.as_mut_ptr().add(3),
                n,
            );
            (sys.channel_write)(s.app_out, frame.as_ptr(), 3 + n);
            s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(n as u32);
        }
    }
    s.conns[idx].stream_recv_buf_len = 0;
}

unsafe fn discard_bytes(sys: &SyscallTable, ch: i32, mut count: usize) {
    let mut buf = [0u8; 64];
    while count > 0 {
        let take = if count < 64 { count } else { 64 };
        (sys.channel_read)(ch, buf.as_mut_ptr(), take);
        count -= take;
    }
}

/// Module-scope telemetry: emit cumulative `bytes_in` / `bytes_out` counters to
/// the `observe` collector when the telemetry port is wired (no-op otherwise),
/// at a ~5s wallclock cadence. Metric ids follow `[observability].metrics`
/// order: 0 = bytes_in, 1 = bytes_out. Counter semantics are monotonic, so the
/// deltas are NOT reset here.
#[inline(never)]
unsafe fn maybe_emit_telemetry(s: &mut QuicState) {
    let sys = &*s.syscalls;
    // Ring-based emission (§5.2): zero-cost when no consumer is subscribed.
    let now = dev_millis(sys);
    if now.wrapping_sub(s.tlm_last_ms) < 5000 {
        return;
    }
    s.tlm_last_ms = now;
    // Bounded state beat, telemetry-wired or not: one-shot records at
    // module_new/bind are emitted before DHCP binds and never leave a board
    // over UDP telemetry, so the evidence a rig capture keys on must RECUR
    // (the SIP/RTP §4.2 lesson; the h3 rig regression sat undiagnosable for
    // four days for want of exactly this line). Endpoint id, conn count,
    // refusals, and the ingress counter only.
    {
        let mut active: u32 = 0;
        let mut i = 0;
        while i < MAX_CONNS {
            if s.conns[i].phase != ConnPhase::Idle {
                active += 1;
            }
            i += 1;
        }
        let mut l = [0u8; 128];
        let msg = b"[quic] hb ep=";
        l[..13].copy_from_slice(msg);
        let mut pos = 13;
        pos += fmt_u32_raw(l.as_mut_ptr().add(pos), s.endpoint.ep_id() as u32);
        l[pos..pos + 6].copy_from_slice(b" conns");
        pos += 6;
        l[pos] = b'=';
        pos += 1;
        pos += fmt_u32_raw(l.as_mut_ptr().add(pos), active);
        l[pos..pos + 4].copy_from_slice(b" rx=");
        pos += 4;
        pos += fmt_u32_raw(l.as_mut_ptr().add(pos), s.tlm.bytes_in);
        l[pos..pos + 5].copy_from_slice(b" ref=");
        pos += 5;
        pos += fmt_u32_raw(l.as_mut_ptr().add(pos), s.refused_conns);
        l[pos..pos + 9].copy_from_slice(b" cidfail=");
        pos += 9;
        pos += fmt_u32_raw(l.as_mut_ptr().add(pos), s.rng_cid_fail);
        l[pos..pos + 5].copy_from_slice(b" fcs=");
        pos += 5;
        pos += fmt_u32_raw(l.as_mut_ptr().add(pos), u32::from(s.fc_max_state));
        l[pos..pos + 5].copy_from_slice(b" fcu=");
        pos += 5;
        pos += fmt_u32_raw(l.as_mut_ptr().add(pos), s.fc_max_us);
        l[pos..pos + 5].copy_from_slice(b" fcd=");
        pos += 5;
        pos += fmt_u32_raw(l.as_mut_ptr().add(pos), s.fc_max_drain_us);
        l[pos..pos + 8].copy_from_slice(b" rstall=");
        pos += 8;
        pos += fmt_u32_raw(l.as_mut_ptr().add(pos), s.reservation_exhausted_stall);
        dev_log(sys, 3, l.as_ptr(), pos);
    }
    if !dev_telemetry_enabled(sys) {
        return;
    }
    let me = dev_self_index(sys);
    if me < 0 {
        return;
    }
    let midx = me as u16;
    let t = dev_micros(sys);
    let counter = abi::contracts::telemetry::METRIC_COUNTER;
    dev_telemetry_metric(sys, -1, midx, t, counter, 0, s.tlm.bytes_in as u64);
    dev_telemetry_metric(sys, -1, midx, t, counter, 1, s.tlm.bytes_out as u64);
}

/// Head-sampling decision for a new `quic.connection` root, drawn
/// deterministically from the (random) minted trace id and compared to
/// `permille`. Returns the W3C trace-flags to stamp. Mirrors ip/dns.
#[inline(always)]
fn ingress_sample_decision(permille: u16, trace_id: &[u8; 16]) -> u8 {
    let draw = u16::from_le_bytes([trace_id[0], trace_id[1]]) % 1000;
    if draw < permille {
        abi::contracts::telemetry::TRACE_FLAGS_SAMPLED
    } else {
        0
    }
}

/// Emit the finished `quic.connection` span (name_id 0, SERVER kind) for a
/// server-accepted connection, then clear its pending marker (idempotent — safe
/// to call at every close path). No-op for client conns, an already-emitted
/// span, an unsampled connection, or an unwired telemetry port. The sample-bit
/// test runs before the clock read so an unsampled conn does no work.
#[inline(never)]
unsafe fn emit_conn_span(s: &mut QuicState, idx: usize) {
    if !s.conns[idx].is_server || s.conns[idx].span_start_us == 0 {
        return;
    }
    let flags = s.conns[idx].sampled_flags;
    let start = s.conns[idx].span_start_us;
    s.conns[idx].span_start_us = 0; // mark emitted before any early return
    if flags & abi::contracts::telemetry::TRACE_FLAGS_SAMPLED == 0
        || !dev_telemetry_enabled(&*s.syscalls)
    {
        return;
    }
    let trace_id = s.conns[idx].trace_id;
    let span_id = s.conns[idx].span_id;
    let sys = &*s.syscalls;
    let me = dev_self_index(sys);
    if me < 0 {
        return;
    }
    let end_raw = dev_micros(sys);
    let end = if end_raw < start { start } else { end_raw };
    let ctx = abi::contracts::telemetry::SpanContext {
        trace_id,
        span_id,
        parent_id: [0u8; 8], // quic is the ingress for this connection → root
        flags,
    };
    dev_telemetry_span(
        sys,
        -1,
        me as u16,
        0, // name_id 0 = quic.connection
        abi::contracts::telemetry::SPAN_SERVER,
        abi::contracts::telemetry::STATUS_OK,
        &ctx,
        start,
        end,
    );
}

/// Emit one datagram (`CMD_DG_SEND_TO`) toward `peer` via the shared
/// `datagram_endpoint` core. Returns `true` iff the whole frame was accepted
/// (all-or-nothing write). Callers holding reliable control state
/// (PATH_CHALLENGE / PATH_RESPONSE / NEW_CONNECTION_ID) MUST keep that state
/// pending until this returns `true`, so a backpressured write is retried, not
/// lost. No-ops (returns `false`) until the endpoint is bound.
/// Server at capacity: answer a client Initial with a stateless
/// CONNECTION_REFUSED close, sealed under the Initial keys every client can
/// derive from its own DCID (RFC 9001 §5.2), holding no state. The refusal
/// is what makes the connection ceiling a bounded envelope rather than a
/// hang (RFC 9000 §5.2.2 permits a stateless close for an unwanted
/// connection attempt).
unsafe fn emit_stateless_refusal(s: &mut QuicState, ip: &[u8; 4], port: u16, dgram: &[u8]) {
    // Only a long-header v1 Initial earns a reply; anything else is stray
    // traffic and stays dropped.
    if dgram.len() < 7 || dgram[0] & 0xF0 != 0xC0 {
        return;
    }
    if dgram[1..5] != [0, 0, 0, 1] {
        return;
    }
    let dcid_len = dgram[5] as usize;
    if dcid_len == 0 || dcid_len > MAX_CID_LEN || 6 + dcid_len + 1 > dgram.len() {
        return;
    }
    let dcid = &dgram[6..6 + dcid_len];
    let scid_off = 6 + dcid_len;
    let scid_len = dgram[scid_off] as usize;
    if scid_len > MAX_CID_LEN || scid_off + 1 + scid_len > dgram.len() {
        return;
    }
    let scid = &dgram[scid_off + 1..scid_off + 1 + scid_len];

    let (_client, server) = derive_initial_keys(dcid);
    let hp = Aes128Hp::new(&server.hp);
    let mut close = [0u8; 32];
    // 0x02 CONNECTION_REFUSED, no offending frame, no reason phrase — the
    // code is the whole message and a phrase would cost bytes on a path that
    // exists because resources ran out.
    let n = build_connection_close(0x02, 0, &[], false, &mut close);
    if n == 0 {
        return;
    }
    let mut pkt = [0u8; 256];
    // Our DCID is the client's SCID; our SCID echoes the client's DCID, as a
    // server's first Initial does before it chooses its own.
    let m = build_initial_packet(&server, &hp, 0, 1, scid, dcid, &[], &close[..n], &mut pkt);
    if m == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let peer = PeerAddr { ip: *ip, port };
    let _ = send_datagram(
        sys,
        s.net_out,
        &s.endpoint,
        &peer,
        &pkt[..m],
        &mut s.net_scratch,
    );
    s.refused_conns = s.refused_conns.wrapping_add(1);
    // Bounded evidence: log the 1st, 2nd, 4th, 8th… refusal, so a flood of
    // refused dials cannot flood the log while the count stays observable.
    if s.refused_conns & (s.refused_conns - 1) == 0 {
        dev_log(sys, 2, b"[quic] conn refused (table full)".as_ptr(), 31);
    }
}

#[must_use]
unsafe fn send_datagram(
    sys: &SyscallTable,
    net_out: i32,
    ep: &DatagramEndpoint,
    peer: &PeerAddr,
    bytes: &[u8],
    scratch: &mut [u8; NET_BUF_SIZE],
) -> bool {
    // `peer.ip` is wire-order octets; `send_to` re-serialises via `to_be_bytes`.
    let dst_ip = u32::from_be_bytes(peer.ip);
    ep.send_to(
        sys,
        net_out,
        dst_ip,
        peer.port,
        bytes.as_ptr(),
        bytes.len(),
        scratch.as_mut_ptr(),
        NET_BUF_SIZE,
    ) != 0
}

// ---------------------------------------------------------------------
// Connection allocation / lookup
// ---------------------------------------------------------------------

fn find_conn(s: &QuicState, ip: &[u8; 4], port: u16) -> i32 {
    let mut i = 0;
    while i < MAX_CONNS {
        if s.conns[i].phase != ConnPhase::Idle && s.conns[i].peer.matches(ip, port) {
            return i as i32;
        }
        i += 1;
    }
    -1
}

/// Connection demux by Destination Connection ID. RFC 9000 §5.1: the
/// peer's packets carry the DCID we picked for the connection. We
/// match against `our_cid` (post-handshake) and `original_dcid`
/// (during the first Initial flight before the server has chosen a
/// CID). Long-header packets always carry a DCID byte sequence; short
/// headers carry one of fixed length too. This is the right key for
/// disambiguating multiple simultaneous connections from the same
/// (ip, port) — clients commonly multiplex over a single UDP socket.
unsafe fn find_conn_by_dcid(s: &QuicState, dcid: &[u8]) -> i32 {
    let mut i = 0;
    while i < MAX_CONNS {
        if s.conns[i].phase != ConnPhase::Idle {
            let our_len = s.conns[i].our_cid_len as usize;
            if our_len > 0 && dcid.len() >= our_len {
                let mut diff = 0u8;
                let mut k = 0;
                while k < our_len {
                    diff |= s.conns[i].our_cid[k] ^ dcid[k];
                    k += 1;
                }
                if diff == 0 {
                    return i as i32;
                }
            }
            // Also match the issued alternate CID (RFC 9000 §5.1.1): a
            // migrating peer may switch its DCID to the spare we gave it.
            let alt_len = s.conns[i].alt_cid_len as usize;
            if alt_len > 0 && dcid.len() >= alt_len {
                let mut diff = 0u8;
                let mut k = 0;
                while k < alt_len {
                    diff |= s.conns[i].alt_cid[k] ^ dcid[k];
                    k += 1;
                }
                if diff == 0 {
                    return i as i32;
                }
            }
        }
        i += 1;
    }
    -1
}

/// Fill `buf` with CSPRNG bytes that are not all zero.
///
/// A connection ID or reset token of all zeros is not a value this endpoint
/// may put on the wire: a zero server CID, or a NEW_CONNECTION_ID carrying a
/// zero CID, is rejected by a conforming peer (quiche closes with
/// FRAME_ENCODING_ERROR the moment the handshake completes). The kernel CSPRNG
/// seeds its source before the first read, but a hardware source can briefly
/// re-present zero words when it reseeds mid-run, and the fill then SUCCEEDS
/// while writing zeros. Re-fill on an all-zero result — the source recovers
/// within a read or two — and report whether a non-zero fill was obtained.
/// Returns false if a fill failed or stayed zero across every attempt; the
/// caller then declines (refuses a connection, or does not offer a spare CID)
/// rather than emitting zeros.
#[inline]
unsafe fn csprng_fill_nonzero(sys: &SyscallTable, buf: *mut u8, len: usize) -> bool {
    let mut attempt = 0;
    while attempt < 8 {
        if dev_csprng_fill(sys, buf, len) < 0 {
            return false;
        }
        let mut k = 0;
        while k < len {
            if *buf.add(k) != 0 {
                return true;
            }
            k += 1;
        }
        attempt += 1;
    }
    false
}

unsafe fn alloc_server_connection(s: &mut QuicState, ip: &[u8; 4], port: u16) -> Option<usize> {
    let framed = s.alpn_cfg_len > 0;
    // Snapshot the sampling rate before borrowing a connection slot mutably.
    let permille = s.sample_permille;
    let mut i = 0;
    while i < MAX_CONNS {
        // A CLOSED or ERRORED slot is reusable: its span has been emitted
        // (`emit_conn_span` runs on the Closed pass) and `reset()` clears the
        // slot wholesale. Without this the pool is one-shot — with MAX_CONNS=2
        // a server stops accepting after its second connection ever.
        // A slot that still owes its MSG_MUX_SESSION_CLOSED is not free
        // yet. Handing it to a new connection first would reuse the
        // session id while the application still believes the previous
        // session is live — every event for the new one would be read as
        // belonging to the old.
        let owes_close = s.conns[i].session_opened_sent && !s.conns[i].session_closed_sent;
        let reusable = matches!(
            s.conns[i].phase,
            ConnPhase::Idle | ConnPhase::Closed | ConnPhase::Errored
        ) && !owes_close;
        if reusable {
            let conn = &mut s.conns[i];
            conn.reset();
            conn.peer.ip = *ip;
            conn.peer.port = port;
            conn.phase = ConnPhase::Handshaking;
            conn.is_server = true;
            conn.driver.is_server = true;
            // Which application-channel encoding this connection uses.
            // Latched per connection at allocation rather than read from
            // module state at every use, so the frame path never has to
            // reach back up to `QuicState` to know where a stream's
            // bytes belong.
            conn.framed_app_surface = framed;
            conn.driver.hs_state = HandshakeState::RecvClientHello;
            conn.driver.suite = CipherSuite::ChaCha20Poly1305;

            // Pick our SCID (random 8 bytes).
            let sys = &*s.syscalls;
            if !csprng_fill_nonzero(sys, conn.our_cid.as_mut_ptr(), 8) {
                s.rng_cid_fail = s.rng_cid_fail.wrapping_add(1);
            }
            conn.our_cid_len = 8;

            // Observability: mint the `quic.connection` root trace context and
            // start the span clock when telemetry is wired. Head-sampling is
            // decided once here and latched in `sampled_flags`; the close path
            // emits the span. Zero-cost (no mint) when no consumer is subscribed.
            if dev_telemetry_enabled(sys) {
                dev_csprng_fill(sys, conn.trace_id.as_mut_ptr(), 16);
                dev_csprng_fill(sys, conn.span_id.as_mut_ptr(), 8);
                conn.sampled_flags = ingress_sample_decision(permille, &conn.trace_id);
                conn.span_start_us = dev_micros(sys);
            }

            // Assign ECDH keypair.
            conn.driver.ecdh_private = s.eph_private[i];
            conn.driver.ecdh_public = s.eph_public[i];
            s.eph_used[i] = true;

            // Initial keys are derived once we see the client's Initial
            // (we need its DCID). Mark not-yet.
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Allocate a fresh client connection seeded for a PSK resumption.
/// Looks up the cached ticket for `(ip, port)`, copies the PSK +
/// identity into the new conn, and stages a 0-RTT payload for
/// emission as soon as the early-traffic keys are installed.
unsafe fn alloc_resumption_connection(s: &mut QuicState, ip: &[u8; 4], port: u16) -> Option<usize> {
    let framed = s.alpn_cfg_len > 0;
    // Find the matching client_ticket entry.
    let mut tix = MAX_TICKETS;
    let mut t = 0;
    while t < MAX_TICKETS {
        if s.client_tickets[t].used
            && s.client_tickets[t].peer_ip == *ip
            && s.client_tickets[t].peer_port == port
        {
            tix = t;
            break;
        }
        t += 1;
    }
    if tix == MAX_TICKETS {
        return None;
    }
    let entry = s.client_tickets[tix];
    // Allocate a free conn slot.
    let mut i = 0;
    while i < MAX_CONNS {
        if s.conns[i].phase == ConnPhase::Idle {
            let conn = &mut s.conns[i];
            conn.reset();
            conn.peer.ip = *ip;
            conn.peer.port = port;
            conn.phase = ConnPhase::Handshaking;
            conn.is_server = false;
            conn.driver.is_server = false;
            // Which application-channel encoding this connection uses.
            // Latched per connection at allocation rather than read from
            // module state at every use, so the frame path never has to
            // reach back up to `QuicState` to know where a stream's
            // bytes belong.
            conn.framed_app_surface = framed;
            conn.driver.hs_state = HandshakeState::SendClientHello;
            conn.driver.suite = CipherSuite::ChaCha20Poly1305;
            // Pick fresh CIDs.
            let sys = &*s.syscalls;
            if !csprng_fill_nonzero(sys, conn.our_cid.as_mut_ptr(), 8) {
                s.rng_cid_fail = s.rng_cid_fail.wrapping_add(1);
            }
            conn.our_cid_len = 8;
            dev_csprng_fill(sys, conn.peer_cid.as_mut_ptr(), 8);
            conn.peer_cid_len = 8;
            conn.original_dcid[..8].copy_from_slice(&conn.peer_cid[..8]);
            conn.original_dcid_len = 8;
            // Install Initial keys from the original DCID.
            let mut dcid_copy = [0u8; MAX_CID_LEN];
            core::ptr::copy_nonoverlapping(conn.peer_cid.as_ptr(), dcid_copy.as_mut_ptr(), 8);
            install_initial_keys(conn, &dcid_copy[..8]);
            // Install the PSK + identity from the ticket entry.
            let pl = entry.rms_len as usize;
            conn.psk[..pl].copy_from_slice(&entry.rms[..pl]);
            conn.psk_len = pl as u8;
            let il = entry.ticket_len as usize;
            conn.psk_identity[..il].copy_from_slice(&entry.ticket[..il]);
            conn.psk_identity_len = il as u8;
            conn.zero_rtt_offered = true;
            // Stage a 0-RTT payload.
            let msg = b"early data hello";
            conn.zero_rtt_payload[..msg.len()].copy_from_slice(msg);
            conn.zero_rtt_payload_len = msg.len();
            // Re-use the precomputed ECDH for this slot.
            conn.driver.ecdh_private = s.eph_private[i];
            conn.driver.ecdh_public = s.eph_public[i];
            s.eph_used[i] = true;
            return Some(i);
        }
        i += 1;
    }
    None
}

unsafe fn alloc_client_connection(s: &mut QuicState, ip: &[u8; 4], port: u16) -> Option<usize> {
    let framed = s.alpn_cfg_len > 0;
    let mut i = 0;
    while i < MAX_CONNS {
        if s.conns[i].phase == ConnPhase::Idle {
            let conn = &mut s.conns[i];
            conn.reset();
            conn.peer.ip = *ip;
            conn.peer.port = port;
            conn.phase = ConnPhase::Handshaking;
            conn.is_server = false;
            conn.driver.is_server = false;
            // Which application-channel encoding this connection uses.
            // Latched per connection at allocation rather than read from
            // module state at every use, so the frame path never has to
            // reach back up to `QuicState` to know where a stream's
            // bytes belong.
            conn.framed_app_surface = framed;
            conn.driver.hs_state = HandshakeState::SendClientHello;
            conn.driver.suite = CipherSuite::ChaCha20Poly1305;

            // Client picks BOTH connection IDs initially:
            //   our_cid (SCID we send) — random
            //   peer_cid placeholder (DCID we send) — also random; this
            //     becomes the server-side "original DCID" used to derive
            //     Initial keys on both sides.
            let sys = &*s.syscalls;
            if !csprng_fill_nonzero(sys, conn.our_cid.as_mut_ptr(), 8) {
                s.rng_cid_fail = s.rng_cid_fail.wrapping_add(1);
            }
            conn.our_cid_len = 8;
            dev_csprng_fill(sys, conn.peer_cid.as_mut_ptr(), 8);
            conn.peer_cid_len = 8;
            conn.original_dcid[..8].copy_from_slice(&conn.peer_cid[..8]);
            conn.original_dcid_len = 8;

            // Install Initial keys from the original DCID. Snapshot
            // into a stack array so we don't borrow conn while passing
            // a slice to a function that also takes &mut conn.
            let mut dcid_copy = [0u8; MAX_CID_LEN];
            let n = conn.peer_cid_len as usize;
            core::ptr::copy_nonoverlapping(conn.peer_cid.as_ptr(), dcid_copy.as_mut_ptr(), n);
            install_initial_keys(conn, &dcid_copy[..n]);

            conn.driver.ecdh_private = s.eph_private[i];
            conn.driver.ecdh_public = s.eph_public[i];
            s.eph_used[i] = true;

            return Some(i);
        }
        i += 1;
    }
    None
}

fn eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(feature = "host-test")]
pub mod test_helpers {
    //! Helpers for host-side test harnesses. Not compiled into PIC firmware
    //! (`cfg(feature = "host-test")`). They let a test observe and drive the
    //! connection lifecycle without standing up a full QUIC crypto handshake.

    use super::{
        promote_key_phase, drain_inbound_one, emit_connection_close, BidiStream, MAX_BIDI_STREAMS,ConnPhase, QuicState, MAX_CONNS};

    /// Run the server admission decision for one inbound datagram, exactly
    /// as the RX path does: match by DCID, else allocate, else emit the
    /// stateless CONNECTION_REFUSED and return -1. Lets the ceiling test
    /// fill the table and observe the refusal without nine real handshakes.
    ///
    /// # Safety
    /// `state` must point to a fully-initialised `QuicState`.
    pub unsafe fn admit_from(state: *mut u8, ip: [u8; 4], port: u16, dgram: &[u8]) -> i32 {
        let s = &mut *(state as *mut QuicState);
        let mut dcid_buf = [0u8; super::MAX_CID_LEN];
        let mut dcid_len = 0usize;
        if dgram.len() > 6 && dgram[0] & 0x80 != 0 {
            let dl = dgram[5] as usize;
            if dl <= super::MAX_CID_LEN && 6 + dl <= dgram.len() {
                dcid_buf[..dl].copy_from_slice(&dgram[6..6 + dl]);
                dcid_len = dl;
            }
        }
        let mut idx = if dcid_len > 0 {
            super::find_conn_by_dcid(s, &dcid_buf[..dcid_len])
        } else {
            -1
        };
        if idx < 0 {
            if let Some(new) = super::alloc_server_connection(s, &ip, port) {
                idx = new as i32;
            } else {
                let mc = super::find_conn(s, &ip, port);
                if mc >= 0 {
                    idx = mc;
                } else {
                    super::emit_stateless_refusal(s, &ip, port, dgram);
                }
            }
        }
        idx
    }

    /// Connections refused at the ceiling so far.
    ///
    /// # Safety
    /// `state` must point to a fully-initialised `QuicState`.
    pub unsafe fn refused_count(state: *const u8) -> u32 {
        (*(state as *const QuicState)).refused_conns
    }

    /// The connection-table ceiling, for tests that fill it.
    pub fn max_conns() -> usize {
        MAX_CONNS
    }

    /// Mark the datagram endpoint bound, as MSG_DG_BOUND would — the refusal
    /// path sends through it, and the ceiling test starts past the bind
    /// handshake.
    ///
    /// # Safety
    /// `state` must point to a fully-initialised `QuicState`.
    pub unsafe fn force_endpoint_bound(state: *mut u8, ep_id: u8) {
        (*(state as *mut QuicState)).endpoint.bind_static(ep_id);
    }

    /// Number of server-accepted connections currently occupying a slot
    /// (anything past `Idle`). After the RX path allocates a server
    /// connection this is ≥ 1 — and its `quic.connection` span has been
    /// minted.
    ///
    /// # Safety
    /// `state` must point to a fully-initialised `QuicState`.
    /// The configured P-256 ladder chunk size, as the module actually
    /// parsed it.
    ///
    /// Exposed because the difference between "the param is declared" and
    /// "the param reaches the state" is invisible from outside: a
    /// mis-tagged or mis-typed param leaves the default in place and the
    /// handshake still works — just in one enormous step, which only a
    /// board with a step guard ever complains about.
    ///
    /// # Safety
    /// `state` must point to a fully-initialised `QuicState`.
    pub unsafe fn configured_ladder_bits(state: *mut u8) -> u16 {
        (*(state as *const QuicState)).ecdh_bits_per_step
    }

    pub unsafe fn server_conn_count(state: *mut u8) -> usize {
        let s = &*(state as *const QuicState);
        let mut n = 0;
        let mut i = 0;
        while i < MAX_CONNS {
            if s.conns[i].is_server && s.conns[i].phase != ConnPhase::Idle {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Force every live server connection to `Closed`. The real close paths
    /// (received `CONNECTION_CLOSE`, protocol error, idle timeout) all do
    /// exactly this; the next `module_step`'s close reaper then emits each
    /// connection's `quic.connection` span. Lets a test exercise the span
    /// emit/close path deterministically without driving a real handshake to
    /// completion.
    ///
    /// # Safety
    /// `state` must point to a fully-initialised `QuicState`.
    pub unsafe fn close_server_conns(state: *mut u8) {
        let s = &mut *(state as *mut QuicState);
        let mut i = 0;
        while i < MAX_CONNS {
            if s.conns[i].is_server && s.conns[i].phase != ConnPhase::Idle {
                s.conns[i].phase = ConnPhase::Closed;
            }
            i += 1;
        }
    }

    /// True if any connection has completed the handshake (Established +
    /// `handshake_confirmed`). Lets a loopback interop test wait for the
    /// real QUIC + TLS 1.3 handshake to finish before exercising
    /// application traffic.
    ///
    /// # Safety
    /// `state` must point to a fully-initialised `QuicState`.
    pub unsafe fn handshake_complete(state: *const u8) -> bool {
        let s = &*(state as *const QuicState);
        let mut i = 0;
        while i < MAX_CONNS {
            if s.conns[i].phase == ConnPhase::Established && s.conns[i].handshake_confirmed {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Copy the negotiated ALPN token for connection `idx` into `out`,
    /// returning its length (0 = none negotiated). Lets an interop test
    /// assert the server echoed the client's requested protocol.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `out` is valid for
    /// `cap` bytes.
    pub unsafe fn alpn_of(state: *const u8, idx: usize, out: *mut u8, cap: usize) -> usize {
        let s = &*(state as *const QuicState);
        if idx >= MAX_CONNS {
            return 0;
        }
        let n = (s.conns[idx].alpn_selected_len as usize).min(cap);
        core::ptr::copy_nonoverlapping(s.conns[idx].alpn_selected.as_ptr(), out, n);
        n
    }

    /// The current peer UDP port for connection `idx` (the active path).
    /// After a successful migration this reflects the new 4-tuple.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`.
    pub unsafe fn peer_port_of(state: *const u8, idx: usize) -> u16 {
        let s = &*(state as *const QuicState);
        if idx >= MAX_CONNS {
            return 0;
        }
        s.conns[idx].peer.port
    }

    /// Whether connection `idx` is currently validating a migrated path
    /// (a PATH_CHALLENGE is outstanding). Lets a test observe that
    /// migration validation was triggered.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`.
    pub unsafe fn path_validating(state: *const u8, idx: usize) -> bool {
        let s = &*(state as *const QuicState);
        idx < MAX_CONNS && s.conns[idx].path_validating
    }

    /// Debug snapshot of connection `idx`: `(phase_code, handshake_confirmed)`.
    /// phase_code: 0=Idle 1=Handshaking 2=Established 3=Closed 4=Errored.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`.
    pub unsafe fn conn_debug(state: *const u8, idx: usize) -> (u8, bool) {
        let s = &*(state as *const QuicState);
        if idx >= MAX_CONNS {
            return (255, false);
        }
        let p = match s.conns[idx].phase {
            ConnPhase::Idle => 0,
            ConnPhase::Handshaking => 1,
            ConnPhase::Established => 2,
            ConnPhase::Closed => 3,
            ConnPhase::Errored => 4,
        };
        (p, s.conns[idx].handshake_confirmed)
    }

    use super::{EncLevel, PeerAddr, MAX_ALPN, QUIC_MAX_DATAGRAM_SIZE};

    /// Run the real ALPN selection (RFC 7301 §3.2) over a configured list
    /// + a client-offered ProtocolNameList, copying the negotiated token
    ///   into `out` and returning its length (0 = none). Wraps the
    ///   module-internal `select_alpn`.
    ///
    /// # Safety
    /// `out` is valid for `cap` bytes.
    pub unsafe fn select_alpn(cfg: &[u8], offered: &[u8], out: *mut u8, cap: usize) -> usize {
        match super::select_alpn(cfg, offered) {
            Some(t) => {
                let n = t.len().min(cap);
                core::ptr::copy_nonoverlapping(t.as_ptr(), out, n);
                n
            }
            None => 0,
        }
    }

    /// Force connection `idx` into a post-handshake Established state with
    /// the given peer 4-tuple + negotiated ALPN, so the application-facing
    /// feature paths (datagram / raw-stream forwarding, peer identity,
    /// migration) run deterministically without standing up a full
    /// handshake. Sets `peer_max_datagram_frame_size` so outbound
    /// datagrams up to the max are admitted.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn setup_established(
        state: *mut u8,
        idx: usize,
        is_server: bool,
        peer_ip: [u8; 4],
        peer_port: u16,
        alpn: &[u8],
    ) {
        let s = &mut *(state as *mut QuicState);
        // Clear the bind gate so module_step reaches the per-connection
        // post-handshake loop (no real datagram provider in this path).
        s.endpoint.bind_static(0);
        // Reflect a real ALPN-configured module: a non-empty ALPN means
        // the module offers ALPN, which switches the app surface to the
        // framed `mux` envelope (see the `mux_mode` gate in module_step).
        let cfg_n = alpn.len().min(super::MAX_ALPN_CFG);
        s.alpn_cfg[..cfg_n].copy_from_slice(&alpn[..cfg_n]);
        s.alpn_cfg_len = cfg_n;
        let conn = &mut s.conns[idx];
        conn.reset();
        conn.phase = ConnPhase::Established;
        conn.is_server = is_server;
        conn.handshake_confirmed = true;
        conn.peer = PeerAddr {
            ip: peer_ip,
            port: peer_port,
        };
        conn.our_cid_len = 8;
        conn.our_cid[..8].copy_from_slice(&[0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8]);
        conn.peer_cid_len = 8;
        conn.peer_cid[..8].copy_from_slice(&[0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8]);
        let n = alpn.len().min(MAX_ALPN);
        conn.alpn_selected[..n].copy_from_slice(&alpn[..n]);
        conn.alpn_selected_len = n as u8;
        conn.framed_app_surface = cfg_n > 0;
        conn.peer_max_datagram_frame_size = QUIC_MAX_DATAGRAM_SIZE as u64;
        conn.one_rtt.keys_set = true;
        conn.last_activity_ms = 1;
        conn.idle_timeout_ms = 0; // never idle-close during a test
    }

    /// Feed a 1-RTT frame payload through the real `process_frames`
    /// dispatcher on connection `idx` (as the RX path does after
    /// decrypting a 1-RTT packet). Lets a test inject DATAGRAM / STREAM /
    /// PATH_RESPONSE frames and observe their effects.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn feed_one_rtt_frames(state: *mut u8, idx: usize, payload: &[u8]) {
        let s = &mut *(state as *mut QuicState);
        // Default: the frames arrive on the active (validated) path, just
        // as the RX demux records the source before dispatch.
        s.conns[idx].recv_ip = s.conns[idx].peer.ip;
        s.conns[idx].recv_port = s.conns[idx].peer.port;
        let mut np = false;
        super::process_frames(&mut s.conns[idx], EncLevel::OneRtt, payload, 1, &mut np);
    }

    /// Like [`feed_one_rtt_frames`] but with an explicit datagram source
    /// 4-tuple, so a test can exercise path-associated frame handling
    /// (PATH_CHALLENGE / PATH_RESPONSE, RFC 9000 §8.2.2 / §8.2.3) where
    /// the source is not the currently-validated `peer`.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn feed_one_rtt_frames_from(
        state: *mut u8,
        idx: usize,
        src_ip: [u8; 4],
        src_port: u16,
        payload: &[u8],
    ) {
        let s = &mut *(state as *mut QuicState);
        s.conns[idx].recv_ip = src_ip;
        s.conns[idx].recv_port = src_port;
        let mut np = false;
        super::process_frames(&mut s.conns[idx], EncLevel::OneRtt, payload, 1, &mut np);
    }

    /// Feed 1-RTT frames as an AUTHENTICATED packet from `src`, then run
    /// the same post-auth migration-arming decision the real receive path
    /// uses (`arm_migration_if_new_path`). Lets a test verify that only a
    /// NON-probing packet from a new path arms validation (RFC 9000 §9.1).
    /// Returns whether path validation is now armed.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn feed_authenticated_1rtt_from(
        state: *mut u8,
        idx: usize,
        src_ip: [u8; 4],
        src_port: u16,
        payload: &[u8],
    ) -> bool {
        let s = &mut *(state as *mut QuicState);
        let migration_enabled = s.disable_migration == 0;
        s.conns[idx].recv_ip = src_ip;
        s.conns[idx].recv_port = src_port;
        let mut non_probing = false;
        super::process_frames(
            &mut s.conns[idx],
            EncLevel::OneRtt,
            payload,
            1,
            &mut non_probing,
        );
        super::arm_migration_if_new_path(
            &mut s.conns[idx],
            &*s.syscalls,
            migration_enabled,
            non_probing,
        );
        s.conns[idx].path_validating
    }

    /// Override connection `idx`'s peer `max_datagram_frame_size` so a
    /// test can exercise the RFC 9221 oversize-drop with a payload that
    /// still fits the read buffer.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`.
    pub unsafe fn set_peer_max_datagram(state: *mut u8, idx: usize, v: u64) {
        let s = &mut *(state as *mut QuicState);
        if idx < MAX_CONNS {
            s.conns[idx].peer_max_datagram_frame_size = v;
        }
    }

    /// Whether connection `idx` has an outbound DATAGRAM staged (the app
    /// wrote a MSG_QUIC_DATAGRAM_TX the encoder accepted).
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`.
    pub unsafe fn dgram_tx_pending(state: *const u8, idx: usize) -> bool {
        let s = &*(state as *const QuicState);
        idx < MAX_CONNS && s.conns[idx].dgram_tx_pending
    }

    /// The spare-CID state: `None` before one is issued, `Some(true)` once a
    /// spare CID has been issued whose value is all zeros — the degenerate
    /// NEW_CONNECTION_ID a peer rejects with FRAME_ENCODING_ERROR — and
    /// `Some(false)` once one is issued with a non-zero value. `alt_cid_issued`
    /// latches, so this is stable across steps (unlike the transient
    /// `new_cid_tx_pending`, cleared the moment the frame is sent). The
    /// invariant the CSPRNG-failure regression asserts is that this is NEVER
    /// `Some(true)`: a spare CID is issued only from a successful fill.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`.
    pub unsafe fn new_cid_pending_all_zero(state: *const u8, idx: usize) -> Option<bool> {
        let s = &*(state as *const QuicState);
        // Keyed on what is actually QUEUED (`alt_cid_len`), not the one-shot
        // `alt_cid_issued` latch: a connection that attempted and DECLINED the
        // spare CID latches `alt_cid_issued` but queues nothing
        // (`alt_cid_len == 0`), which reads as `None` — no spare CID offered.
        if idx >= MAX_CONNS || s.conns[idx].alt_cid_len == 0 {
            return None;
        }
        let len = s.conns[idx].alt_cid_len as usize;
        let all_zero = s.conns[idx].alt_cid[..len].iter().all(|&b| b == 0);
        Some(all_zero)
    }

    /// Arm a migration on connection `idx`: record the candidate 4-tuple,
    /// mint the PATH_CHALLENGE data, and mark validation in progress —
    /// exactly what the RX demux does on a 4-tuple change. Returns the
    /// challenge bytes so a test can build the matching PATH_RESPONSE.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn arm_migration(
        state: *mut u8,
        idx: usize,
        cand_ip: [u8; 4],
        cand_port: u16,
    ) -> [u8; 8] {
        let s = &mut *(state as *mut QuicState);
        let conn = &mut s.conns[idx];
        conn.cand_ip = cand_ip;
        conn.cand_port = cand_port;
        conn.path_challenge_data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        conn.path_validating = true;
        conn.path_challenge_data
    }

    /// The handshake driver's current `hs_state` discriminant for
    /// connection `idx` (the `HandshakeState` enum order). Lets a test
    /// observe where a handshake stalls or errors.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`.
    pub unsafe fn driver_hs_state(state: *const u8, idx: usize) -> u8 {
        let s = &*(state as *const QuicState);
        if idx >= MAX_CONNS {
            return 255;
        }
        s.conns[idx].driver.hs_state as u8
    }

    // ── Reservation + continuity helpers ──────────────
    use super::{
        activate_shadow, import_checkpoint, next_keys, next_traffic_secret, parse_one_rtt_packet,
        retire_connection, secret_to_keys, serialize_checkpoint, Aes128Hp, NonceReservation,
        CONT_FLOW_ID_BYTES,
    };

    /// Configure connection `idx` as a post-handshake 1-RTT peer with real,
    /// deterministic mirrored traffic secrets and preserved CIDs — enough
    /// for a real packet-protection round trip across a takeover without a
    /// live handshake. `c2s` is the client→server secret, `s2c` the
    /// reverse; a server reads `c2s` and writes `s2c`.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    #[allow(
        clippy::too_many_arguments,
        reason = "a test helper that installs every half of a keyed connection at once; the arguments are the record's fields"
    )]
    pub unsafe fn cont_setup_keyed(
        state: *mut u8,
        idx: usize,
        is_server: bool,
        c2s: &[u8; 32],
        s2c: &[u8; 32],
        our_cid: &[u8],
        peer_cid: &[u8],
        odcid: &[u8],
        flow: &[u8; CONT_FLOW_ID_BYTES],
        epoch: u32,
        peer_ip: [u8; 4],
        peer_port: u16,
    ) {
        let s = &mut *(state as *mut QuicState);
        let c = &mut s.conns[idx];
        c.reset();
        c.phase = ConnPhase::Established;
        c.is_server = is_server;
        c.handshake_confirmed = true;
        c.framed_app_surface = true;
        c.peer = PeerAddr {
            ip: peer_ip,
            port: peer_port,
        };
        c.recv_ip = peer_ip;
        c.recv_port = peer_port;
        let on = our_cid.len().min(super::MAX_CID_LEN);
        c.our_cid[..on].copy_from_slice(&our_cid[..on]);
        c.our_cid_len = on as u8;
        let pnn = peer_cid.len().min(super::MAX_CID_LEN);
        c.peer_cid[..pnn].copy_from_slice(&peer_cid[..pnn]);
        c.peer_cid_len = pnn as u8;
        let od = odcid.len().min(super::MAX_CID_LEN);
        c.original_dcid[..od].copy_from_slice(&odcid[..od]);
        c.original_dcid_len = od as u8;
        let (rd, wr): (&[u8; 32], &[u8; 32]) = if is_server { (c2s, s2c) } else { (s2c, c2s) };
        c.one_rtt.read_secret[..32].copy_from_slice(rd);
        c.one_rtt.write_secret[..32].copy_from_slice(wr);
        c.one_rtt.secret_len = 32;
        c.one_rtt.read_keys = secret_to_keys(&rd[..]);
        c.one_rtt.write_keys = secret_to_keys(&wr[..]);
        c.one_rtt.keys_set = true;
        c.one_rtt.key_phase = 0;
        let mut nr = [0u8; 48];
        next_traffic_secret(&rd[..], &mut nr[..32]);
        let mut nw = [0u8; 48];
        next_traffic_secret(&wr[..], &mut nw[..32]);
        c.one_rtt.next_read_secret[..32].copy_from_slice(&nr[..32]);
        c.one_rtt.next_write_secret[..32].copy_from_slice(&nw[..32]);
        c.one_rtt.next_read_keys = next_keys(&nr[..32], c.one_rtt.read_keys.hp);
        c.one_rtt.next_write_keys = next_keys(&nw[..32], c.one_rtt.write_keys.hp);
        c.one_rtt.next_keys_ready = true;
        c.cont_flow_id = *flow;
        c.cont_epoch = epoch;
        c.idle_timeout_ms = 0;
        c.last_activity_ms = 1;
    }

    /// Attempt to emit one 1-RTT packet through the reservation gate.
    /// Returns the packet number allocated, or -1 when emission stalled
    /// (durable mode with the granted blocks spent).
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn res_try_emit(state: *mut u8, idx: usize) -> i64 {
        let s = &mut *(state as *mut QuicState);
        if !s.conns[idx].one_rtt_pn_ok() {
            s.reservation_exhausted_stall = s.reservation_exhausted_stall.wrapping_add(1);
            return -1;
        }
        let pn = s.conns[idx].one_rtt.next_send_pn;
        s.conns[idx].one_rtt.next_send_pn = pn + 1;
        s.conns[idx].one_rtt_pn_commit();
        pn as i64
    }

    /// Put connection `idx` into durable-grant mode (a `cont_in` port is
    /// wired): self-granting stops and emission needs directory grants.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn res_set_durable(state: *mut u8, idx: usize, durable: bool) {
        let s = &mut *(state as *mut QuicState);
        s.conns[idx].pn_res_durable = durable;
    }

    /// Install a durable reservation grant directly (bypassing the wire),
    /// returning 0 on success or a non-zero `ReservationError` discriminant
    /// (1 = stale epoch, 5 = epoch not bumped after void).
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn res_install_grant(
        state: *mut u8,
        idx: usize,
        epoch: u32,
        start: u64,
        len: u64,
    ) -> i32 {
        let s = &mut *(state as *mut QuicState);
        match s.conns[idx].install_pn_grant(epoch, start, len) {
            Ok(()) => 0,
            Err(super::ReservationError::StaleEpoch) => 1,
            Err(super::ReservationError::Overlap) => 2,
            Err(super::ReservationError::ZeroLen) => 3,
            Err(super::ReservationError::Busy) => 4,
            Err(super::ReservationError::EpochNotBumped) => 5,
            Err(super::ReservationError::SpaceExhausted) => 6,
        }
    }

    /// Invalidate outstanding blocks (unsafe-recovery void, R2).
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn res_void(state: *mut u8, idx: usize) {
        let s = &mut *(state as *mut QuicState);
        s.conns[idx].send_pn_res.void_outstanding();
    }

    /// The cumulative reservation-exhaustion stall count.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`.
    pub unsafe fn res_stall_count(state: *const u8) -> u32 {
        (*(state as *const QuicState)).reservation_exhausted_stall
    }

    /// The current 1-RTT next-send packet number.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn res_next_pn(state: *const u8, idx: usize) -> u64 {
        (*(state as *const QuicState)).conns[idx]
            .one_rtt
            .next_send_pn
    }

    /// Bind a continuity flow id + epoch onto a live connection.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_bind_flow(
        state: *mut u8,
        idx: usize,
        flow: &[u8; CONT_FLOW_ID_BYTES],
        epoch: u32,
    ) {
        let s = &mut *(state as *mut QuicState);
        s.conns[idx].cont_flow_id = *flow;
        s.conns[idx].cont_epoch = epoch;
    }

    /// Feed one framed continuity command through the real dispatcher
    /// (`cont_apply`), as the `cont_in` pump would.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`.
    pub unsafe fn cont_feed(state: *mut u8, msg_type: u8, payload: &[u8]) {
        let s = &mut *(state as *mut QuicState);
        super::cont_apply(s, msg_type, payload);
    }

    /// Serialize connection `idx`'s checkpoint record into `out`, returning
    /// its length (0 = refused, e.g. a non-established state).
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `out` valid for `cap`.
    pub unsafe fn cont_serialize(
        state: *mut u8,
        idx: usize,
        flow: &[u8; CONT_FLOW_ID_BYTES],
        epoch: u32,
        out: *mut u8,
        cap: usize,
    ) -> usize {
        let s = &mut *(state as *mut QuicState);
        let buf = core::slice::from_raw_parts_mut(out, cap);
        serialize_checkpoint(s, idx, flow, epoch, buf)
    }

    /// Import a checkpoint record into connection slot `idx`, leaving it a
    /// NON-EMITTING shadow (phase Idle) with keys installed. Returns the
    /// `sc::STATUS_*` code.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_import_to_slot(
        state: *mut u8,
        idx: usize,
        flow: &[u8; CONT_FLOW_ID_BYTES],
        epoch: u32,
        record: &[u8],
    ) -> u8 {
        let s = &mut *(state as *mut QuicState);
        let mut staged = super::QuicConnection::new();
        let st = import_checkpoint(s, &mut staged, flow, epoch, record);
        if st == 0 {
            s.conns[idx] = staged;
            s.conns[idx].phase = ConnPhase::Idle; // shadow: never emits
        }
        st
    }

    /// Promote the imported shadow at slot `idx` to live under `new_epoch`
    /// with `fence_gen`. Returns true on success; false if refused (fence 0,
    /// non-increasing epoch).
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_activate_slot(
        state: *mut u8,
        idx: usize,
        new_epoch: u32,
        fence_gen: u32,
        prior_epoch: u32,
    ) -> bool {
        let s = &mut *(state as *mut QuicState);
        if fence_gen == 0 || new_epoch <= prior_epoch {
            return false;
        }
        let floor = s.conns[idx]
            .send_pn_res
            .high_water()
            .max(s.conns[idx].one_rtt.next_send_pn);
        let c = &mut s.conns[idx];
        c.phase = ConnPhase::Established;
        c.cont_epoch = new_epoch;
        c.send_pn_res = NonceReservation::resume(new_epoch, floor);
        c.pn_res_durable = false;
        c.bytes_in_flight = 0;
        c.last_activity_ms = 1;
        true
    }

    /// The move-a-shadow-into-a-free-slot activate path, driven directly
    /// (the ACTIVATE opcode uses this). Returns the new live index or -1.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`.
    pub unsafe fn cont_activate_move(
        state: *mut u8,
        src_idx: usize,
        new_epoch: u32,
        fence_gen: u32,
        prior_epoch: u32,
    ) -> i32 {
        let s = &mut *(state as *mut QuicState);
        let mut moved = super::QuicConnection::new();
        core::mem::swap(&mut moved, &mut s.conns[src_idx]);
        activate_shadow(s, moved, new_epoch, fence_gen, prior_epoch)
    }

    /// Build a 1-RTT PING packet from connection `idx` (advancing its send
    /// pn), returning `(bytes, len, pn)`.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_build_ping(state: *mut u8, idx: usize) -> ([u8; 1500], usize, u64) {
        let s = &mut *(state as *mut QuicState);
        let c = &mut s.conns[idx];
        let keys = c.one_rtt.write_keys;
        let hp = Aes128Hp::new(&c.one_rtt.write_keys.hp);
        let pn = c.one_rtt.next_send_pn;
        let kp = c.one_rtt.key_phase;
        let pcl = c.peer_cid_len as usize;
        let mut dcid = [0u8; super::MAX_CID_LEN];
        dcid[..pcl].copy_from_slice(&c.peer_cid[..pcl]);
        let payload = [0x01u8]; // PING
        let mut pkt = [0u8; 1500];
        let n =
            super::build_one_rtt_packet(&keys, &hp, pn, 4, kp, &dcid[..pcl], &payload, &mut pkt);
        c.one_rtt.next_send_pn = pn + 1;
        c.one_rtt_pn_commit();
        (pkt, n, pn)
    }

    /// Parse/decrypt a 1-RTT packet at connection `idx`. Returns the packet
    /// number on success, or -1 on AEAD failure (keys did not survive the
    /// takeover).
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_parse_1rtt(state: *mut u8, idx: usize, dgram: &[u8]) -> i64 {
        let s = &mut *(state as *mut QuicState);
        let c = &mut s.conns[idx];
        let dcid_len = c.our_cid_len as usize;
        let keys = c.one_rtt.read_keys;
        let hp = Aes128Hp::new(&c.one_rtt.read_keys.hp);
        let mut copy = [0u8; 1500];
        let n = dgram.len().min(copy.len());
        copy[..n].copy_from_slice(&dgram[..n]);
        match parse_one_rtt_packet(
            &keys,
            &hp,
            dcid_len,
            c.one_rtt.largest_recv_pn,
            &mut copy[..n],
        ) {
            Some((_, _, pn)) => pn as i64,
            None => -1,
        }
    }

    /// The connection's key phase.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_key_phase(state: *const u8, idx: usize) -> u8 {
        (*(state as *const QuicState)).conns[idx].one_rtt.key_phase
    }

    /// Copy connection `idx`'s CIDs out for an unchanged-across-takeover
    /// assertion: `(our_cid_bytes, peer_cid_bytes, odcid_bytes)`.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_cids(state: *const u8, idx: usize) -> ([u8; 20], [u8; 20], [u8; 20]) {
        let c = &(*(state as *const QuicState)).conns[idx];
        (c.our_cid, c.peer_cid, c.original_dcid)
    }

    /// RETIRE connection `idx`, zeroizing its secrets.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_retire(state: *mut u8, idx: usize) {
        let s = &mut *(state as *mut QuicState);
        retire_connection(&mut s.conns[idx]);
    }

    /// True iff every 1-RTT traffic secret at connection `idx` is zero.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_secrets_zeroed(state: *const u8, idx: usize) -> bool {
        let c = &(*(state as *const QuicState)).conns[idx];
        c.one_rtt.read_secret.iter().all(|&b| b == 0)
            && c.one_rtt.write_secret.iter().all(|&b| b == 0)
            && c.one_rtt.next_read_secret.iter().all(|&b| b == 0)
            && c.one_rtt.next_write_secret.iter().all(|&b| b == 0)
            && c.psk.iter().all(|&b| b == 0)
    }

    /// Queue application bytes on connection `idx`'s transparent stream, so
    /// the next step builds and emits a real 1-RTT packet through the
    /// pump — the path the mirror hooks into.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_queue_app_data(state: *mut u8, idx: usize, bytes: &[u8]) -> bool {
        let s = &mut *(state as *mut QuicState);
        let c = &mut s.conns[idx];
        // A framed surface sends from the stream pool, never the transparent
        // stream: queue on a locally-initiated bidirectional stream, or on
        // one already open.
        let mut k = 0;
        while k < MAX_BIDI_STREAMS {
            let st = &mut c.bidi_streams[k];
            if st.allocated && st.locally_initiated && st.send_buf_len == 0 {
                break;
            }
            if !st.allocated {
                *st = BidiStream::empty();
                st.allocated = true;
                st.locally_initiated = true;
                st.stream_id = (k as u64) * 4 + 1;
                st.app.open_sent = true;
                break;
            }
            k += 1;
        }
        if k == MAX_BIDI_STREAMS {
            return false;
        }
        let st = &mut c.bidi_streams[k];
        if bytes.len() > st.send_buf.len() {
            return false;
        }
        st.send_buf[..bytes.len()].copy_from_slice(bytes);
        st.send_buf_len = bytes.len();
        true
    }

    /// Hand a datagram to connection `idx` as the pump would after the RX
    /// demux, and consume it through the real 1-RTT receive path — the
    /// path the mirror hooks into. Answers whether a packet was consumed.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_feed_datagram(state: *mut u8, idx: usize, dgram: &[u8]) -> bool {
        let s = &mut *(state as *mut QuicState);
        {
            let c = &mut s.conns[idx];
            if dgram.len() > c.inbound.len() {
                return false;
            }
            c.inbound[..dgram.len()].copy_from_slice(dgram);
            c.inbound_len = dgram.len();
            c.inbound_off = 0;
            c.recv_ip = c.peer.ip;
            c.recv_port = c.peer.port;
        }
        drain_inbound_one(s, idx)
    }

    /// Bytes still queued on connection `idx`'s transparent stream.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_app_queued(state: *const u8, idx: usize) -> usize {
        let c = &(*(state as *const QuicState)).conns[idx];
        let mut n = 0;
        let mut k = 0;
        while k < MAX_BIDI_STREAMS {
            if c.bidi_streams[k].allocated {
                n += c.bidi_streams[k].send_buf_len;
            }
            k += 1;
        }
        n
    }

    /// Largest 1-RTT packet number connection `idx` has received.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_largest_recv_pn(state: *const u8, idx: usize) -> u64 {
        (*(state as *const QuicState)).conns[idx].one_rtt.largest_recv_pn
    }

    /// Continuity profile connection `idx` was paired under (0 = none).
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_profile(state: *const u8, idx: usize) -> u8 {
        (*(state as *const QuicState)).conns[idx].cont_profile
    }

    /// Whether connection `idx` has a key update awaiting the peer's
    /// acknowledgement.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_key_update_awaiting(state: *const u8, idx: usize) -> bool {
        (*(state as *const QuicState)).conns[idx].key_update_awaiting_ack
    }

    /// Whether connection `idx` still holds its previous read phase's keys.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_prev_read_valid(state: *const u8, idx: usize) -> bool {
        (*(state as *const QuicState)).conns[idx].one_rtt.prev_read_valid
    }

    /// Emit a CONNECTION_CLOSE for connection `idx` through the real emit
    /// path, so a test can see whether the close draws on the reservation.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_emit_close(state: *mut u8, idx: usize) {
        let s = &mut *(state as *mut QuicState);
        emit_connection_close(s, idx, 0x00, 0, b"closing");
    }

    /// Whether connection `idx` is mirroring to a standby.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_mirroring(state: *const u8, idx: usize) -> bool {
        (*(state as *const QuicState)).conns[idx].cont_mirror
    }

    /// Inbound packet numbers the strict receive horizon is holding back
    /// from acknowledgement on connection `idx`.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_recv_held(state: *const u8, idx: usize) -> usize {
        (*(state as *const QuicState)).conns[idx].cont_recv_hold_len as usize
    }

    /// Whether connection `idx`'s 1-RTT emission is currently held.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_emission_held(state: *const u8, idx: usize) -> bool {
        (*(state as *const QuicState)).conns[idx].cont_emission_held
    }

    /// The exact predicate `emit_crypto_packet` uses to decide whether a
    /// 1-RTT packet may go out this tick: not held by a strict-profile
    /// horizon, and a reservation value is available.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_would_emit(state: *mut u8, idx: usize) -> bool {
        let s = &mut *(state as *mut QuicState);
        !s.conns[idx].cont_emission_held && s.conns[idx].one_rtt_pn_ok()
    }

    /// Promote connection `idx` to the next 1-RTT key phase (the local half
    /// of an RFC 9001 §6 key update), so a test can checkpoint a connection
    /// that is already in phase 1.
    ///
    /// # Safety
    /// `state` points to an initialised `QuicState`; `idx < MAX_CONNS`.
    pub unsafe fn cont_promote_key_phase(state: *mut u8, idx: usize) {
        let s = &mut *(state as *mut QuicState);
        promote_key_phase(&mut s.conns[idx]);
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");
