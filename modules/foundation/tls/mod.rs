//! TLS 1.3 PIC Module for Fluxor
//!
//! Pure Rust implementation — no C, no GOT, no data relocations.
//! Channel-based graph node sitting between IP and HTTP:
//!   IP <--cipher_in/cipher_out--> TLS <--clear_in/clear_out--> HTTP
//!
//! Cipher suites: TLS_CHACHA20_POLY1305_SHA256 (preferred),
//!                TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384

// `no_std` / `no_main` are stripped under EITHER the host-test
// feature (the explicit "build me as a host rlib" knob) OR
// `cfg(test)` (cargo's own test-runner harness). The PIC build
// sets neither, so the firmware blob stays bare-metal.
//
// The `cfg(test)` arm matters because `cargo test -p
// fluxor-mod-tls --target aarch64-unknown-linux-gnu` without
// `--features host-test` would otherwise fail with `undefined
// reference to main` — cargo's test harness needs a normal
// `main` entrypoint to instantiate `#[test]` functions, which
// `#![no_main]` suppresses.
#![cfg_attr(not(any(feature = "host-test", test)), no_std)]
#![cfg_attr(not(any(feature = "host-test", test)), no_main)]
#![allow(
    unsafe_code,
    reason = "PIC module: ABI shim and crypto primitives over raw buffers"
)]
// PIC library code must not panic; surface errors through the ABI.
#![deny(clippy::unwrap_used)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

// PIC runtime (syscalls, helpers, intrinsics)
include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

// Crypto primitives
include!("../../sdk/sha256.rs");
include!("../../sdk/sha384.rs");
include!("../../sdk/hmac.rs");
include!("../../sdk/chacha20.rs");
include!("../../sdk/aes_gcm.rs");
include!("../../sdk/p256.rs");
include!("x509.rs");

// TLS protocol
include!("alert.rs");
include!("record.rs");
include!("key_schedule.rs");
include!("handshake.rs");
include!("handshake_driver.rs");
include!("handshake_pump.rs");
include!("dtls_record.rs");
include!("dtls_state.rs");

// ============================================================================
// Module constants
// ============================================================================

/// Concurrent TLS sessions. Must be ≥ peak in-flight TCP connections
/// upstream; otherwise SYNs are accepted at IP but stall at TLS
/// allocation (surfaces as a probe-side connect timeout).
/// Per-tick work is O(MAX_SESSIONS), so oversizing trades concurrency
/// for tick overhead. Each `TlsSession` is ~13 KB.
const MAX_SESSIONS: usize = 16;
const MAX_CERT_LEN: usize = 1024;
const MAX_KEY_LEN: usize = 160;

/// `transport` parameter values selecting which I/O path runs.
const TRANSPORT_TCP: u8 = 0; // TLS records over a net_proto stream channel.
const TRANSPORT_UDP: u8 = 1; // DTLS records over a datagram channel (RFC 9147).

/// Per-peer datagram session count (DTLS mode).
const MAX_PEERS: usize = 4;
/// Maximum DTLS datagram payload.
const DGRAM_MAX: usize = 1500;
const RECV_BUF_SIZE: usize = 4096;
const SEND_BUF_SIZE: usize = 2048;
// SCRATCH_SIZE is defined in handshake_driver.rs.
const NET_SCRATCH_SIZE: usize = 1600;
/// Ciphertext retention window for TCP-level retransmission. Holds the
/// encrypted net_proto frames TLS has written to `cipher_out` so they can
/// be replayed on MSG_RETRANSMIT without re-encryption.
const RETX_BUF_SIZE: usize = 4096;

// Net protocol message types (downstream: IP -> TLS -> HTTP)
const NET_MSG_ACCEPTED: u8 = 0x01;
const NET_MSG_DATA: u8 = 0x02;
const NET_MSG_CLOSED: u8 = 0x03;
const NET_MSG_BOUND: u8 = 0x04;
const NET_MSG_CONNECTED: u8 = 0x05;
const NET_MSG_ERROR: u8 = 0x06;
const NET_MSG_RETRANSMIT: u8 = 0x07;
const NET_MSG_ACK: u8 = 0x08;
/// Observability trace context (see contracts/net/net_proto.rs). Received from
/// IP on cipher_in; re-emitted to HTTP on clear_out with TLS's own span id.
const NET_MSG_TRACE_CTX: u8 = 0x09;

// Net protocol command types (upstream: HTTP -> TLS -> IP)
const NET_CMD_BIND: u8 = 0x10;
const NET_CMD_SEND: u8 = 0x11;
const NET_CMD_CLOSE: u8 = 0x12;
const NET_CMD_CONNECT: u8 = 0x13;

// ============================================================================
// Session state
// ============================================================================

#[derive(Clone, Copy, PartialEq)]
enum SessionState {
    Idle,
    Allocated,
    Connecting,
    AcceptPending,
    Handshaking,
    Ready,
    Closing,
    Closed,
    Error,
}

struct TlsSession {
    state: SessionState,
    conn_id: u8,       // net_proto connection ID
    held_msg_type: u8, // held ACCEPTED/CONNECTED msg type to forward after handshake

    /// Record-agnostic handshake state machine (Phase A — extracted into
    /// HandshakeDriver). Owns the key schedule, transcript, ECDH state,
    /// peer key share, peer cert pubkey, server random, ALPN selection,
    /// and handshake-message reassembly scratch. DTLS (Phase B) and
    /// QUIC (Phase C) reuse it verbatim with their own record /
    /// packet protection layers.
    driver: HandshakeDriver,

    // Traffic keys (record-coupled — derived from `driver.key_schedule`
    // secrets via TrafficKeys::from_secret; held here because the
    // record layer applies them to inbound/outbound records).
    read_keys: TrafficKeys,
    write_keys: TrafficKeys,

    // Record reassembly buffer
    recv_buf: [u8; RECV_BUF_SIZE],
    recv_len: usize,
    recv_expected: usize, // expected record payload size (0 = reading header)

    // Send buffer (for fragmented sends)
    send_buf: [u8; SEND_BUF_SIZE],
    send_len: usize,
    send_offset: usize,

    // Retransmit buffer — retains ciphertext (including the net_proto
    // CMD_SEND framing bytes) so MSG_RETRANSMIT can replay unacked bytes
    // without re-encrypting. `retx_base_seq` is the TCP sequence number
    // of `retx_buf[0]`, anchored on the first MSG_ACK for this connection.
    retx_buf: [u8; RETX_BUF_SIZE],
    retx_len: u16,
    retx_base_seq: u32,
    retx_seq_anchored: bool,

    /// Middlebox-compat CCS injection (RFC 8446 §5). Set by
    /// `pump_send_server_hello` / `pump_send_hello_retry` to ask the
    /// outbound record bridge to append a 1-byte CCS record after the
    /// next plaintext record so they ship in the same TCP segment.
    pending_ccs: bool,
    /// Mirror of pending_ccs for the client side, set after the client
    /// emits ClientHello so the bridge can inject a CCS record before
    /// the first encrypted client flight.
    pending_ccs_client: bool,

    /// Latched MSG_PEER_IDENTITY envelope for sessions whose
    /// peer_identity output port was full at handshake completion.
    /// `pending_peer_identity_len > 0` means a retry is scheduled;
    /// `module_step` walks active sessions and retries the write
    /// each tick until either the channel accepts the envelope or
    /// the session is released. Sized for the MSG_PEER_IDENTITY
    /// envelope: 3 B header + 4 B fixed + 32 B SVID = 39 B max.
    pending_peer_identity: [u8; 39],
    pending_peer_identity_len: u8,

    /// Observability: monotonic-micros start of this session's `tls.handshake`
    /// span, latched when the handshake begins and the telemetry port is wired
    /// (`0` = no span). See `standards/observability.md`.
    span_start_us: u64,
    /// Cross-module trace context. `trace_ctx_trace`/`trace_ctx_parent` are the
    /// trace id + IP's span id received via `MSG_TRACE_CTX` (all-zero trace =
    /// none → root). `span_id` is this session's own span id, minted at
    /// handshake start, used for the `tls.handshake` span AND forwarded
    /// downstream so HTTP parents under it.
    trace_ctx_trace: [u8; 16],
    trace_ctx_parent: [u8; 8],
    /// W3C trace-flags byte latched from IP's `MSG_TRACE_CTX` (low bit =
    /// `sampled`), re-emitted downstream so the sampling decision survives.
    trace_ctx_flags: u8,
    /// Original downstream requester tag for a TLS-mediated CLIENT connect — the
    /// tag the clear-side consumer put on its `CMD_CONNECT` before TLS rewrote it
    /// to TLS's own tag toward IP. Echoed when TLS forwards `MSG_CONNECTED`
    /// downstream so the original requester routes it on a fanned clear_out.
    /// `0` for inbound (server) sessions.
    downstream_tag: u8,
    span_id: [u8; 8],
}

impl TlsSession {
    const fn empty() -> Self {
        Self {
            state: SessionState::Idle,
            conn_id: 0,
            held_msg_type: 0,
            driver: HandshakeDriver::empty(),
            read_keys: TrafficKeys::empty(),
            write_keys: TrafficKeys::empty(),
            recv_buf: [0; RECV_BUF_SIZE],
            recv_len: 0,
            recv_expected: 0,
            send_buf: [0; SEND_BUF_SIZE],
            send_len: 0,
            send_offset: 0,
            retx_buf: [0; RETX_BUF_SIZE],
            retx_len: 0,
            retx_base_seq: 0,
            retx_seq_anchored: false,
            pending_ccs: false,
            pending_ccs_client: false,
            pending_peer_identity: [0; 39],
            pending_peer_identity_len: 0,
            span_start_us: 0,
            trace_ctx_trace: [0; 16],
            trace_ctx_parent: [0; 8],
            trace_ctx_flags: 0,
            downstream_tag: 0,
            span_id: [0; 8],
        }
    }

    fn reset(&mut self) {
        // Zeroize traffic key material here; driver.reset() handles
        // its own sensitive material (ECDH private, server random).
        // SAFETY: forwarded to the runtime helper which validates the
        // pointer + length contract documented at its declaration.
        unsafe {
            let mut i = 0;
            while i < 32 {
                core::ptr::write_volatile(&mut self.read_keys.key[i], 0);
                core::ptr::write_volatile(&mut self.write_keys.key[i], 0);
                i += 1;
            }
        }
        self.driver.reset();
        self.state = SessionState::Idle;
        self.conn_id = 0;
        self.held_msg_type = 0;
        self.recv_len = 0;
        self.recv_expected = 0;
        self.send_len = 0;
        self.retx_len = 0;
        self.retx_base_seq = 0;
        self.retx_seq_anchored = false;
        self.send_offset = 0;
        self.pending_ccs = false;
        self.pending_ccs_client = false;
        self.pending_peer_identity_len = 0;
        self.span_start_us = 0;
        self.trace_ctx_trace = [0; 16];
        self.trace_ctx_parent = [0; 8];
        self.trace_ctx_flags = 0;
        self.downstream_tag = 0;
        self.span_id = [0; 8];
        self.read_keys = TrafficKeys::empty();
        self.write_keys = TrafficKeys::empty();
    }
}

// ============================================================================
// DTLS-mode types (RFC 9147)
// ============================================================================

#[derive(Clone, Copy, PartialEq)]
enum DtlsPhase {
    Idle,
    Handshaking,
    Ready,
    Closed,
    Errored,
}

#[derive(Clone, Copy)]
struct PeerAddr {
    ip: [u8; 4],
    port: u16,
}

impl PeerAddr {
    const fn unset() -> Self {
        Self {
            ip: [0; 4],
            port: 0,
        }
    }
    fn matches(&self, ip: &[u8; 4], port: u16) -> bool {
        self.ip[0] == ip[0]
            && self.ip[1] == ip[1]
            && self.ip[2] == ip[2]
            && self.ip[3] == ip[3]
            && self.port == port
    }
    fn is_unset(&self) -> bool {
        self.port == 0
    }
}

/// Max DTLS records we'll cache for retransmission of the last flight.
/// A full TLS-1.3 server flight is at most 5 records (ServerHello,
/// EncryptedExtensions, Certificate, CertificateVerify, Finished); 8
/// gives headroom for HRR + cert-request flows.
const MAX_FLIGHT_RECORDS: usize = 8;

struct PeerSession {
    phase: DtlsPhase,
    peer: PeerAddr,
    endpoint: DtlsEndpoint,
    inbound_buf: [u8; DGRAM_MAX],
    inbound_len: usize,
    /// Concatenated bytes of every record in the last emitted flight,
    /// for retransmission on RFC 9147 §5.8 retx-timer expiry. Each
    /// record's individual length is tracked in `last_flight_record_lens`
    /// so retransmission can re-send them as separate datagrams instead
    /// of a single coalesced datagram (the receive bridge processes one
    /// record per inbound datagram).
    last_flight: [u8; NET_SCRATCH_SIZE * 2],
    last_flight_len: usize,
    last_flight_record_lens: [u16; MAX_FLIGHT_RECORDS],
    last_flight_record_count: u8,
    /// `step_count` snapshot at the moment this peer entered the
    /// `Handshaking` phase. The DTLS module sweep transitions the
    /// peer to `Errored` after `DTLS_HANDSHAKE_TIMEOUT_STEPS` so a
    /// stuck handshake can't pin a slot in the 4-peer table.
    handshake_start_step: u32,
    /// MSG_PEER_IDENTITY latch — same shape as TlsSession's, but
    /// scoped to a DTLS peer. The conn_id field of the envelope
    /// carries the peer-slot index (0..MAX_PEERS-1) since DTLS
    /// has no IP-module conn_id; downstream consumers
    /// distinguish DTLS vs TCP peers by the peer_identity
    /// channel routing alone, so the slot index is a stable per-
    /// transport identifier.
    pending_peer_identity: [u8; 39],
    pending_peer_identity_len: u8,
}

impl PeerSession {
    const fn empty() -> Self {
        Self {
            phase: DtlsPhase::Idle,
            peer: PeerAddr::unset(),
            endpoint: DtlsEndpoint::new(),
            inbound_buf: [0; DGRAM_MAX],
            inbound_len: 0,
            last_flight: [0; NET_SCRATCH_SIZE * 2],
            last_flight_len: 0,
            last_flight_record_lens: [0; MAX_FLIGHT_RECORDS],
            last_flight_record_count: 0,
            handshake_start_step: 0,
            pending_peer_identity: [0; 39],
            pending_peer_identity_len: 0,
        }
    }

    fn reset(&mut self) {
        self.phase = DtlsPhase::Idle;
        self.peer = PeerAddr::unset();
        self.endpoint = DtlsEndpoint::new();
        self.inbound_len = 0;
        self.last_flight_len = 0;
        self.last_flight_record_count = 0;
        self.handshake_start_step = 0;
        self.pending_peer_identity_len = 0;
    }
}

// ============================================================================
// Module state
// ============================================================================

#[repr(C)]
struct TlsState {
    syscalls: *const SyscallTable,
    mode: u8, // 0=client, 1=server
    verify_peer: u8,
    /// Bits of the P-256 ladder to process per pump tick. 256 runs the full
    /// ladder in one call; smaller values yield between chunks so a second
    /// concurrent handshake doesn't wait for the first to finish.
    ecdh_bits_per_step: u16,
    /// Emit per-phase `[tls] heavy ...` timing. Adds five
    /// `dev_micros` syscalls per tick (~25 µs at default tick_us);
    /// leave off for perf runs, on only when triaging step costs.
    diag_phase_timing: u8,

    // Channel ports (4-port node: cipher side facing IP, clear side facing HTTP)
    cipher_in: i32,  // from IP: ciphertext net_proto frames
    cipher_out: i32, // to IP: ciphertext net_proto frames
    clear_in: i32,   // from HTTP: cleartext net_proto frames (commands)
    clear_out: i32,  // to HTTP: cleartext net_proto frames (events)
    /// Optional peer-identity output (clustor phase-3 RFC §5.1).
    /// Emits `MSG_PEER_IDENTITY` (msg_type 0x5A) per accepted
    /// TLS session after Finished. Wired only when a downstream
    /// consumer needs it; -1 when the port is unwired makes the
    /// emit a no-op. Channel slot: out[2].
    peer_identity: i32,
    /// Optional telemetry output (out[3]) to the `observe` collector; -1 when
    /// unwired. Cumulative crypto/backpressure counters on the 50k cadence.
    telemetry_chan: i32,

    // Pre-computed ephemeral ECDH key pairs (one per session, computed in module_new)
    eph_private: [[u8; 32]; MAX_SESSIONS],
    eph_public: [[u8; 65]; MAX_SESSIONS],
    eph_used: [bool; MAX_SESSIONS], // true if key has been consumed
    // Lifetime counters surfaced on the `[tls] hb` line. The pool
    // cliff signal is `ecdh_fallback_keygen > 0`: once seen, every
    // new session pays the synchronous keygen cost.
    ecdh_pool_hit: u32,
    ecdh_fallback_keygen: u32,
    /// `tls_write_frame` failures across cipher_out / clear_out;
    /// non-zero in steady state means a downstream consumer is
    /// back-pressuring TLS. Emitted on the `[tls] hb` line.
    frame_write_dropped: u32,

    /// Downstream requester tag of the in-flight clear-side `CMD_CONNECT`,
    /// transferred to a session's `downstream_tag` on `MSG_CONNECTED` or used to
    /// translate a connect-failure `MSG_ERROR` back downstream.
    pending_downstream_tag: u8,
    /// True while a clear-side `CMD_CONNECT` is forwarded but not yet completed
    /// (`MSG_CONNECTED` or `MSG_ERROR`). TLS serialises outbound connects through
    /// its single tag, so a SECOND concurrent connect is rejected with EAGAIN
    /// (translated downstream) rather than silently overwriting the pending slot.
    pending_connect_active: bool,

    // Certificate and key (DER-encoded, loaded from params)
    cert: [u8; MAX_CERT_LEN],
    cert_len: usize,
    key: [u8; MAX_KEY_LEN],
    key_len: usize,

    // Trust anchor: public key extracted from a CA certificate provided via
    // params. When require_ca is true and ca_pubkey is populated, every peer
    // certificate's ECDSA signature is verified against this key before the
    // handshake is allowed to proceed.
    ca_pubkey: [u8; 65],
    ca_pubkey_len: u8,
    require_ca: bool,

    // Trust domain for SPIFFE validation
    trust_domain: [u8; 64],
    trust_domain_len: usize,

    /// KEY_VAULT slot handle for the identity private key, or -1 if the
    /// vault is unavailable. When >= 0, CertificateVerify signs via the
    /// vault and falls back to the in-module `key` on ENOSYS.
    key_vault_handle: i32,

    // Sessions
    sessions: [TlsSession; MAX_SESSIONS],

    // ------------------------------------------------------------------
    // DTLS mode (`transport == TRANSPORT_UDP`). The fields below are
    // unused (zero-initialised) when `transport == TRANSPORT_TCP`.
    // ------------------------------------------------------------------
    /// `TRANSPORT_TCP` (TLS records on a stream channel) or
    /// `TRANSPORT_UDP` (DTLS records on a datagram channel).
    transport: u8,
    /// DTLS listener endpoint id returned by `CMD_DG_BIND`.
    dtls_listen_ep: i16,
    /// DTLS listening UDP port (server) or local source port (client).
    dtls_port: u16,
    /// Client-mode peer IPv4 (LE) and UDP port.
    dtls_peer_ip: u32,
    dtls_peer_port: u16,
    /// `CMD_DG_BIND` has been issued and `MSG_DG_BOUND` received.
    dtls_bound: bool,
    /// Client-mode flag: have we kicked off the first ClientHello yet?
    dtls_client_started: bool,
    /// Per-peer DTLS sessions.
    peer_sessions: [PeerSession; MAX_PEERS],

    // Scratch buffer for net_proto frame assembly
    net_scratch: [u8; NET_SCRATCH_SIZE],
    /// Module step counter, incremented at the top of every
    /// `module_step` (regardless of TCP / DTLS path). Used as the
    /// monotonic clock source for the DTLS half-open handshake
    /// idle timeout — DTLS sessions don't have access to
    /// `dev_get_ticks` and the host syscall surface is the same.
    step_count: u32,
}

/// DTLS half-open handshake idle timeout in module steps. At the
/// 1 ms scheduler tick, this is 60 s — long enough to ride out a
/// slow handshake on a high-latency link, short enough that a
/// stuck peer can't pin a `peer_sessions[]` slot indefinitely.
/// Triggers a transition `Handshaking → Errored` so the slot is
/// reclaimed on the next free-slot scan.
const DTLS_HANDSHAKE_TIMEOUT_STEPS: u32 = 60_000;

// ============================================================================
// Parameter definitions
// ============================================================================

define_params! {
    TlsState;

    1, mode, u8, 0
        => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };

    2, verify_peer, u8, 1
        => |s, d, len| { s.verify_peer = p_u8(d, len, 0, 1); };

    3, ecdh_bits_per_step, u16, 256
        => |s, d, len| {
            let v = p_u16(d, len, 0, 256);
            s.ecdh_bits_per_step = if v == 0 { 1 } else if v > 256 { 256 } else { v };
        };

    4, transport, u8, 0
        => |s, d, len| { s.transport = p_u8(d, len, 0, 0); };

    5, dtls_port, u16, 4433
        => |s, d, len| { s.dtls_port = p_u16(d, len, 0, 4433); };

    6, dtls_peer_ip, u32, 0x0100007f
        => |s, d, len| { s.dtls_peer_ip = p_u32(d, len, 0, 0x0100007f); };

    7, dtls_peer_port, u16, 4433
        => |s, d, len| { s.dtls_peer_port = p_u16(d, len, 0, 4433); };

    8, diag_phase_timing, u8, 0
        => |s, d, len| { s.diag_phase_timing = p_u8(d, len, 0, 0); };
}

// ============================================================================
// Module ABI exports
// ============================================================================

#[no_mangle]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<TlsState>() as u32
}

#[no_mangle]
pub extern "C" fn module_arena_size() -> u32 {
    65536 // 64KB heap for handshake scratch
}

#[no_mangle]
pub extern "C" fn module_init(_syscalls: *const core::ffi::c_void) {}

/// PIC module ABI entry: construct module state in `state`.
///
/// # Safety
/// `state` / `params` / `syscalls` are kernel-owned buffers passed
/// across the module ABI. The kernel guarantees `state` is at least
/// `_state_size` bytes and zero-initialised, and `params` covers
/// `params_len` bytes.
#[no_mangle]
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
    let s = &mut *(state as *mut TlsState);
    s.syscalls = syscalls;
    s.cert_len = 0;
    s.key_len = 0;
    s.trust_domain_len = 0;
    s.ca_pubkey_len = 0;
    s.require_ca = false;
    s.key_vault_handle = -1;
    s.ecdh_pool_hit = 0;
    s.ecdh_fallback_keygen = 0;
    s.frame_write_dropped = 0;
    s.pending_downstream_tag = 0;
    s.pending_connect_active = false;
    s.transport = TRANSPORT_TCP;
    s.dtls_listen_ep = -1;
    s.dtls_port = 4433;
    s.dtls_peer_ip = 0x0100007f;
    s.dtls_peer_port = 4433;
    s.dtls_bound = false;
    s.dtls_client_started = false;
    s.step_count = 0;
    let mut i = 0;
    while i < MAX_PEERS {
        s.peer_sessions[i] = PeerSession::empty();
        i += 1;
    }

    let sys = &*s.syscalls;

    // Discover 4 channel ports
    // in[0] = cipher_in (from IP), in[1] = clear_in (from HTTP)
    // out[0] = cipher_out (to IP), out[1] = clear_out (to HTTP)
    s.cipher_in = dev_channel_port(sys, 0, 0);
    s.clear_in = dev_channel_port(sys, 0, 1);
    s.cipher_out = dev_channel_port(sys, 1, 0);
    s.clear_out = dev_channel_port(sys, 1, 1);
    s.peer_identity = dev_channel_port(sys, 1, 2);
    s.telemetry_chan = dev_channel_port(sys, 1, 3); // out[3]: telemetry (optional)

    // Initialize sessions
    let mut i = 0;
    while i < MAX_SESSIONS {
        s.sessions[i] = TlsSession::empty();
        i += 1;
    }

    // Parse standard params
    set_defaults(s);
    if params_len >= 4 {
        let p = core::slice::from_raw_parts(params, params_len);
        if p[0] == 0xFE && p[1] == 0x01 {
            parse_tlv(s, params, params_len);
        }
    }

    // Parse extended TLV for cert/key blobs
    parse_extended_params(s, params, params_len);

    // Pre-compute ephemeral ECDH key pairs (one per session) during module_new.
    // This runs on the full kernel stack, avoiding PIC stack overflow.
    {
        let mut i = 0;
        while i < MAX_SESSIONS {
            let mut random = [0u8; 32];
            let rc = dev_csprng_fill(sys, random.as_mut_ptr(), 32);
            if rc < 0 {
                return -1;
            } // CSPRNG failure is fatal
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
    }

    // Deposit the private scalar into the kernel KEY_VAULT so
    // CertificateVerify signs via `KV_SIGN` and `s.key` can be
    // wiped. Bypassed when `ecdh_bits_per_step < 256` — KV_SIGN
    // runs to completion in one syscall, which would short-circuit
    // the in-module incremental signer the user opted into.
    const KV_PROBE: u32 = 0x1000;
    const KV_STORE: u32 = 0x1001;
    let use_vault = s.ecdh_bits_per_step >= 256;
    if use_vault && s.key_len >= 32 {
        let present = (sys.provider_call)(-1, KV_PROBE, core::ptr::null_mut(), 0);
        if present == 1 {
            let mut raw = [0u8; 32];
            if s.key_len == 32 {
                core::ptr::copy_nonoverlapping(s.key.as_ptr(), raw.as_mut_ptr(), 32);
            } else {
                extract_ec_private_key(&s.key[..s.key_len], &mut raw);
            }
            let mut store_arg = [0u8; 4 + 32];
            store_arg[0] = 1; // key_type = P-256 scalar
            store_arg[1] = 32; // key_len
            core::ptr::copy_nonoverlapping(raw.as_ptr(), store_arg.as_mut_ptr().add(4), 32);
            let h = (sys.provider_call)(-1, KV_STORE, store_arg.as_mut_ptr(), store_arg.len());
            if h >= 0 {
                s.key_vault_handle = h;
                // Vault now holds the authoritative copy; wipe the
                // in-module key material so pump_send_certificate_verify
                // must sign through the vault (and can't silently fall
                // back to a plaintext key).
                let mut j = 0;
                while j < s.key_len {
                    core::ptr::write_volatile(&mut s.key[j], 0);
                    j += 1;
                }
                s.key_len = 0;
            }
            let mut j = 0;
            while j < 32 {
                core::ptr::write_volatile(&mut raw[j], 0);
                core::ptr::write_volatile(&mut store_arg[4 + j], 0);
                j += 1;
            }
        }
    }

    0
}

/// Parse extended TLV entries (cert_file tag 10, key_file tag 11, trust_domain tag 3)
/// Scans the entire params blob. Extended entries use: tag + 0x00 + len_hi + len_lo format.
unsafe fn parse_extended_params(s: &mut TlsState, params: *const u8, params_len: usize) {
    if params.is_null() || params_len < 4 {
        return;
    }
    let data = core::slice::from_raw_parts(params, params_len);

    // Start scanning past the basic-TLV section. Its payload_len bytes
    // at offsets 2-3 can otherwise alias an extended-TLV header
    // (e.g. payload_len = 0x000c → bytes `0c 00 ..` matches tag 12).
    let mut pos = 0;
    if params_len >= 4 && data[0] == TLV_MAGIC && data[1] == TLV_VERSION {
        let payload_len = ((data[3] as usize) << 8) | (data[2] as usize);
        let basic_end = 4 + payload_len;
        if basic_end <= params_len {
            pos = basic_end;
        }
    }
    let end = params_len;

    // Search for extended TLV pattern: tag + 0x00 + len_hi + len_lo
    while pos + 4 <= end {
        let tag = data[pos];
        let ext_tags = tag == 3 || tag == 10 || tag == 11 || tag == 12;
        if ext_tags && pos + 1 < end && data[pos + 1] == 0x00 && pos + 4 <= end {
            let len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
            let data_start = pos + 4;
            if data_start + len > end {
                break;
            }

            match tag {
                3 => {
                    let n = if len < 64 { len } else { 64 };
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr().add(data_start),
                        s.trust_domain.as_mut_ptr(),
                        n,
                    );
                    s.trust_domain_len = n;
                }
                10 => {
                    let n = if len < MAX_CERT_LEN {
                        len
                    } else {
                        MAX_CERT_LEN
                    };
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr().add(data_start),
                        s.cert.as_mut_ptr(),
                        n,
                    );
                    s.cert_len = n;
                }
                11 => {
                    let n = if len < MAX_KEY_LEN { len } else { MAX_KEY_LEN };
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr().add(data_start),
                        s.key.as_mut_ptr(),
                        n,
                    );
                    s.key_len = n;
                }
                12 => {
                    // Trust anchor: parse the supplied CA certificate and
                    // extract its subject public key for later verification
                    // of peer certs. Enables require_ca.
                    let ca_der = core::slice::from_raw_parts(data.as_ptr().add(data_start), len);
                    if let Some(ca) = parse_certificate(ca_der) {
                        let pk = ca.public_key;
                        let n = if pk.len() <= 65 { pk.len() } else { 65 };
                        core::ptr::copy_nonoverlapping(pk.as_ptr(), s.ca_pubkey.as_mut_ptr(), n);
                        s.ca_pubkey_len = n as u8;
                        s.require_ca = true;
                    }
                }
                _ => {}
            }
            pos = data_start + len;
        } else {
            pos += 1;
        }
    }
}

/// PIC module ABI entry: per-tick cooperative step.
///
/// # Safety
/// `state` must point to an initialised `TlsState`. The scheduler
/// guarantees no concurrent step invocation, so the unique re-borrow
/// is sound.
#[no_mangle]
pub unsafe extern "C" fn module_step(state: *mut u8) -> i32 {
    let s = &mut *(state as *mut TlsState);
    s.step_count = s.step_count.wrapping_add(1);
    if s.transport == TRANSPORT_UDP {
        return dtls_module_step(s);
    }
    // Retry any peer-identity envelopes that couldn't ship at
    // handshake completion because the consumer was backed up.
    // Runs every tick to bound delivery latency without busy-
    // waiting — the inner `try_drain_pending_peer_identity` polls
    // first so quiet steps cost a single syscall per latched
    // session.
    service_pending_peer_identity(s);

    let sys = &*s.syscalls;
    let mut did_work = false;

    // `[tls] hb` heartbeat — same cadence as `[ip] tlm` / `[http] tlm`.
    if s.step_count.is_multiple_of(50_000) {
        // Module-scope telemetry: emit cumulative crypto-pool / backpressure
        // counters to the `observe` collector (no-op when unwired). ids follow
        // `[observability].metrics`: 0=ecdh_pool_hit, 1=ecdh_fallback_keygen,
        // 2=frame_write_dropped.
        if s.telemetry_chan >= 0 {
            let tsys = &*s.syscalls;
            let me = dev_self_index(tsys);
            if me >= 0 {
                let midx = me as u16;
                let t = dev_micros(tsys);
                let c = abi::contracts::telemetry::METRIC_COUNTER;
                dev_telemetry_metric(
                    tsys,
                    s.telemetry_chan,
                    midx,
                    t,
                    c,
                    0,
                    s.ecdh_pool_hit as u64,
                );
                dev_telemetry_metric(
                    tsys,
                    s.telemetry_chan,
                    midx,
                    t,
                    c,
                    1,
                    s.ecdh_fallback_keygen as u64,
                );
                dev_telemetry_metric(
                    tsys,
                    s.telemetry_chan,
                    midx,
                    t,
                    c,
                    2,
                    s.frame_write_dropped as u64,
                );
            }
        }
        let buf = s.net_scratch.as_mut_ptr();
        let buf_max = s.net_scratch.len();
        let mut pos = 0usize;
        let emit = |bytes: &[u8], pos: &mut usize| {
            let mut k = 0;
            while k < bytes.len() && *pos < buf_max {
                *buf.add(*pos) = bytes[k];
                *pos += 1;
                k += 1;
            }
        };
        emit(b"[tls] hb pool_hit=", &mut pos);
        pos += fmt_u32_dec(s.ecdh_pool_hit, buf.add(pos));
        emit(b" fallback_keygen=", &mut pos);
        pos += fmt_u32_dec(s.ecdh_fallback_keygen, buf.add(pos));
        emit(b" frame_write_dropped=", &mut pos);
        pos += fmt_u32_dec(s.frame_write_dropped, buf.add(pos));
        dev_log(sys, 3, buf, pos);
    }

    // Per-phase timing for the heavy-step diagnostic; see the field
    // docstring for the perf trade-off.
    let diag_on = s.diag_phase_timing != 0;
    let t0 = if diag_on { dev_micros(sys) } else { 0 };

    // ── Phase 1: Drive active handshake sessions ──
    //
    // For each handshaking session, the queue bridge runs:
    //   record_drain_inbound  — drain records → driver.in_buf
    //   pump_session          — drive the handshake state machine
    //                           (reads from in_buf, writes to out_buf)
    //   record_drain_outbound — drain driver.out_buf → records on cipher_out
    //
    // The outbound drain MUST run after every pump step, not just at the
    // end of the inner loop: e.g. ServerHello is queued at Initial level
    // (plaintext), and immediately afterward `pump_derive_handshake_keys`
    // installs `write_keys`. Draining only at the end would encrypt
    // ServerHello with handshake keys — the peer can't decrypt that.
    let mut i = 0;
    while i < MAX_SESSIONS {
        // Observability: emit the `tls.handshake` span once the handshake has
        // resolved (Ready = ok, Error = failed). Done before the Closed/Error
        // branches below reset the slot. Zero-cost when the port is unwired.
        if s.telemetry_chan >= 0 && s.sessions[i].span_start_us != 0 {
            let st = s.sessions[i].state;
            let resolved = st == SessionState::Ready
                || st == SessionState::Closing
                || st == SessionState::Closed
                || st == SessionState::Error;
            if resolved {
                emit_handshake_span(s, i, st != SessionState::Error);
                s.sessions[i].span_start_us = 0;
            }
        }
        if s.sessions[i].state == SessionState::Handshaking {
            // Yield after one state transition per tick so a heavy
            // handshake step doesn't starve the IP/rp1_gem RX path
            // long enough to drop arriving SYNs.
            let mut steps = 0;
            const PUMP_BUDGET: u32 = 1;
            while steps < PUMP_BUDGET && s.sessions[i].state == SessionState::Handshaking {
                let drained = record_drain_inbound_one(s, i);
                let progressed = pump_session(s, i);
                record_drain_outbound(s, i);
                if !drained && !progressed {
                    break;
                }
                did_work = true;
                steps += 1;
            }
        } else if s.sessions[i].state == SessionState::Closed {
            s.sessions[i].reset();
        } else if s.sessions[i].state == SessionState::Error {
            // Best-effort close notifications; if the channel is
            // full `tls_write_or_count` bumps `frame_write_dropped`
            // and the peer / HTTP consumer eventually times out.
            let cid = s.sessions[i].conn_id;
            let _ = tls_write_or_count(s, s.cipher_out, NET_CMD_CLOSE, cid, core::ptr::null(), 0);
            let _ = tls_write_or_count(s, s.clear_out, NET_MSG_CLOSED, cid, core::ptr::null(), 0);
            s.sessions[i].reset();
        }
        i += 1;
    }

    let t1 = if diag_on { dev_micros(sys) } else { 0 };

    // ── Phase 2: Read from cipher_in (downstream: IP → TLS) ──
    let poll_ci = (sys.channel_poll)(s.cipher_in, POLL_IN);
    if poll_ci > 0 && (poll_ci as u32 & POLL_IN) != 0 {
        let (msg_type, payload_len) = tls_read_header(sys, s.cipher_in);
        if msg_type != 0 {
            did_work = true;
            match msg_type {
                t if t == NET_MSG_ACCEPTED || t == NET_MSG_CONNECTED => {
                    // Read conn_id from payload
                    let mut payload = [0u8; 256];
                    let pl = payload_len as usize;
                    if pl > 0 {
                        let rd = if pl < 256 { pl } else { 256 };
                        (sys.channel_read)(s.cipher_in, payload.as_mut_ptr(), rd);
                        // Discard excess
                        if pl > 256 {
                            tls_discard(sys, s.cipher_in, pl - 256);
                        }
                    }
                    let conn_id = if pl > 0 {
                        // SAFETY: forwarded to the runtime helper which validates the
                        // pointer + length contract documented at its declaration.
                        unsafe { *payload.as_ptr() }
                    } else {
                        0
                    };
                    // Stream-surface routing: `MSG_CONNECTED` carries a requester
                    // tag at payload[1]. When `ip.net_out` is fanned to TLS plus
                    // another stream consumer (e.g. an OTLP exporter), claim an
                    // outbound connect ONLY if its tag is ours (or untagged, for
                    // single-consumer / legacy graphs) — otherwise it belongs to
                    // the other consumer and starting a handshake on its plaintext
                    // socket would corrupt it. Inbound accepts (MSG_ACCEPTED) are
                    // unaffected: TLS is the sole accept-claimant on its channel.
                    let claim = if t == NET_MSG_CONNECTED {
                        let tag = if pl >= 2 { payload[1] } else { 0 };
                        let me = dev_requester_tag(sys);
                        tag == 0 || tag == me
                    } else {
                        true
                    };
                    // Allocate a session only for connections we claim. A
                    // MSG_CONNECTED tagged for another consumer is consumed
                    // (frame already read) but otherwise ignored.
                    if claim {
                        match alloc_session_for_conn(s, conn_id) {
                            Some(idx) => {
                                s.sessions[idx].driver.is_server = t == NET_MSG_ACCEPTED;
                                s.sessions[idx].held_msg_type = t;
                                s.sessions[idx].state = SessionState::Handshaking;
                                // For a client connect, carry the clear-side
                                // consumer's original tag so the forwarded
                                // MSG_CONNECTED routes back to it. Accepts: 0.
                                s.sessions[idx].downstream_tag = if t == NET_MSG_CONNECTED {
                                    let dt = s.pending_downstream_tag;
                                    s.pending_downstream_tag = 0;
                                    s.pending_connect_active = false; // connect completed
                                    dt
                                } else {
                                    0
                                };
                                // Observability: start the `tls.handshake` span and
                                // mint this session's own span id (used for the span
                                // AND forwarded downstream so HTTP parents under it).
                                // Gated on a wired telemetry port — no clock read,
                                // no span, when tracing is off.
                                if s.telemetry_chan >= 0 {
                                    let sys = &*s.syscalls;
                                    let now = dev_micros(sys);
                                    s.sessions[idx].span_start_us = if now == 0 { 1 } else { now };
                                    dev_csprng_fill(sys, s.sessions[idx].span_id.as_mut_ptr(), 8);
                                }
                                if s.sessions[idx].driver.is_server {
                                    s.sessions[idx].driver.hs_state =
                                        HandshakeState::RecvClientHello;
                                } else {
                                    s.sessions[idx].driver.hs_state =
                                        HandshakeState::SendClientHello;
                                }
                                init_session_crypto(s, idx);
                            }
                            None => {
                                // No session slots — close the socket upstream
                                // (best-effort; a full channel still RSTs/times
                                // out on the peer).
                                let _ = tls_write_or_count(
                                    s,
                                    s.cipher_out,
                                    NET_CMD_CLOSE,
                                    conn_id,
                                    core::ptr::null(),
                                    0,
                                );
                                // For a CLIENT connect the clear-side requester is
                                // waiting on this completion — emit a TAGGED
                                // terminal failure downstream and clear the pending
                                // slot so it doesn't wedge. (Accepts aren't visible
                                // downstream until the held handshake completes.)
                                if t == NET_MSG_CONNECTED {
                                    let dtag = s.pending_downstream_tag;
                                    s.pending_connect_active = false;
                                    s.pending_downstream_tag = 0;
                                    let err = [(-12i8) as u8, dtag]; // ENOMEM + tag
                                    let _ = tls_write_or_count(
                                        s,
                                        s.clear_out,
                                        NET_MSG_ERROR,
                                        conn_id,
                                        err.as_ptr(),
                                        err.len() as u16,
                                    );
                                }
                            }
                        }
                    }
                }
                t if t == NET_MSG_DATA => {
                    // Read conn_id + ciphertext payload
                    let pl = payload_len as usize;
                    if pl < 1 {
                        // Malformed — skip
                    } else {
                        let mut conn_id_buf = [0u8; 1];
                        (sys.channel_read)(s.cipher_in, conn_id_buf.as_mut_ptr(), 1);
                        // SAFETY: forwarded to the runtime helper which validates the
                        // pointer + length contract documented at its declaration.
                        let conn_id = unsafe { *conn_id_buf.as_ptr() };
                        let data_len = pl - 1;
                        let si = find_session_by_conn_id(s, conn_id);
                        if si >= 0 {
                            let idx = si as usize;
                            if s.sessions[idx].state == SessionState::Handshaking {
                                // Feed ciphertext into handshake recv_buf
                                let space = RECV_BUF_SIZE - s.sessions[idx].recv_len;
                                let to_read = if data_len < space { data_len } else { space };
                                if to_read > 0 {
                                    (sys.channel_read)(
                                        s.cipher_in,
                                        s.sessions[idx]
                                            .recv_buf
                                            .as_mut_ptr()
                                            .add(s.sessions[idx].recv_len),
                                        to_read,
                                    );
                                    s.sessions[idx].recv_len += to_read;
                                }
                                if data_len > to_read {
                                    tls_discard(sys, s.cipher_in, data_len - to_read);
                                }
                            } else if s.sessions[idx].state == SessionState::Ready {
                                // Feed ciphertext into recv_buf for decryption
                                let space = RECV_BUF_SIZE - s.sessions[idx].recv_len;
                                let to_read = if data_len < space { data_len } else { space };
                                if to_read > 0 {
                                    (sys.channel_read)(
                                        s.cipher_in,
                                        s.sessions[idx]
                                            .recv_buf
                                            .as_mut_ptr()
                                            .add(s.sessions[idx].recv_len),
                                        to_read,
                                    );
                                    s.sessions[idx].recv_len += to_read;
                                }
                                if data_len > to_read {
                                    tls_discard(sys, s.cipher_in, data_len - to_read);
                                }
                                // Try to decrypt and forward
                                try_decrypt_forward(s, idx);
                            } else {
                                tls_discard(sys, s.cipher_in, data_len);
                            }
                        } else {
                            tls_discard(sys, s.cipher_in, data_len);
                        }
                    }
                }
                t if t == NET_MSG_CLOSED => {
                    // Read conn_id and forward to clear_out
                    let pl = payload_len as usize;
                    let mut payload = [0u8; 16];
                    let rd = if pl < 16 { pl } else { 16 };
                    if rd > 0 {
                        (sys.channel_read)(s.cipher_in, payload.as_mut_ptr(), rd);
                    }
                    if pl > 16 {
                        tls_discard(sys, s.cipher_in, pl - 16);
                    }
                    let conn_id = if pl > 0 { payload[0] } else { 0 };
                    // Clean up session
                    let si = find_session_by_conn_id(s, conn_id);
                    if si >= 0 {
                        s.sessions[si as usize].reset();
                    }
                    // Forward to HTTP — best-effort close notification.
                    let _ = tls_write_or_count(
                        s,
                        s.clear_out,
                        NET_MSG_CLOSED,
                        conn_id,
                        core::ptr::null(),
                        0,
                    );
                }
                t if t == NET_MSG_BOUND || t == NET_MSG_ERROR => {
                    let pl = payload_len as usize;
                    let rd = if pl < NET_SCRATCH_SIZE {
                        pl
                    } else {
                        NET_SCRATCH_SIZE
                    };
                    if rd > 0 {
                        (sys.channel_read)(s.cipher_in, s.net_scratch.as_mut_ptr(), rd);
                    }
                    if pl > rd {
                        tls_discard(sys, s.cipher_in, pl - rd);
                    }
                    // MSG_ERROR `[conn_id][errno][tag]` carries IP's tag (TLS's own
                    // tag). TRANSLATE it to the original downstream tag so the
                    // clear-side requester recognises the failure — otherwise it
                    // ignores the error and waits for a timeout. For an established
                    // conn the tag comes from its session; for a connect failure
                    // (no session yet) from the pending connect slot. MSG_BOUND has
                    // no tag and passes through unchanged.
                    let mut forward = true;
                    if t == NET_MSG_ERROR && rd >= 3 {
                        let conn_id = s.net_scratch[0];
                        let in_tag = s.net_scratch[2]; // IP-echoed requester tag
                        let si = find_session_by_conn_id(s, conn_id);
                        if si >= 0 {
                            // Established-connection error → its session's tag.
                            s.net_scratch[2] = s.sessions[si as usize].downstream_tag;
                        } else if s.pending_connect_active && in_tag == dev_requester_tag(sys) {
                            // A CONNECT failure routed to TLS carries TLS's own
                            // tag (TLS stamped it). Only THEN consume the pending
                            // slot — a co-wired consumer's failure (different tag)
                            // must not cancel our connect.
                            s.pending_connect_active = false;
                            s.net_scratch[2] = s.pending_downstream_tag;
                            s.pending_downstream_tag = 0;
                        } else {
                            // Another consumer's error on the shared fan, or an
                            // error for a conn we don't own — not for HTTP. Drop.
                            forward = false;
                        }
                    }
                    if forward {
                        tls_write_raw_frame(sys, s.clear_out, t, s.net_scratch.as_ptr(), rd as u16);
                    }
                }
                t if t == NET_MSG_ACK => {
                    // Payload: [conn_id:1][acked_seq:4 LE].
                    let pl = payload_len as usize;
                    let mut payload = [0u8; 5];
                    let rd = if pl < 5 { pl } else { 5 };
                    if rd > 0 {
                        (sys.channel_read)(s.cipher_in, payload.as_mut_ptr(), rd);
                    }
                    if pl > rd {
                        tls_discard(sys, s.cipher_in, pl - rd);
                    }
                    if rd == 5 {
                        let conn_id = payload[0];
                        let acked_seq =
                            u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                        let si = find_session_by_conn_id(s, conn_id);
                        if si >= 0 {
                            retx_ack(&mut s.sessions[si as usize], acked_seq);
                        }
                    }
                }
                t if t == NET_MSG_RETRANSMIT => {
                    // Payload: [conn_id:1][from_seq:4 LE].
                    let pl = payload_len as usize;
                    let mut payload = [0u8; 5];
                    let rd = if pl < 5 { pl } else { 5 };
                    if rd > 0 {
                        (sys.channel_read)(s.cipher_in, payload.as_mut_ptr(), rd);
                    }
                    if pl > rd {
                        tls_discard(sys, s.cipher_in, pl - rd);
                    }
                    if rd == 5 {
                        let conn_id = payload[0];
                        let from_seq =
                            u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                        let si = find_session_by_conn_id(s, conn_id);
                        if si >= 0 {
                            retx_replay(s, si as usize, from_seq);
                        }
                    }
                }
                t if t == NET_MSG_TRACE_CTX => {
                    // Observability: IP's trace context for this connection.
                    // Parent the `tls.handshake` span under IP's span, then
                    // forward downstream (clear_out → HTTP) with TLS's own span
                    // id so HTTP parents under it. Best-effort; payload always
                    // consumed to stay frame-aligned.
                    let pl = payload_len as usize;
                    let mut pbuf = [0u8; 32];
                    let rd = if pl < 32 { pl } else { 32 };
                    if rd > 0 {
                        (sys.channel_read)(s.cipher_in, pbuf.as_mut_ptr(), rd);
                    }
                    if pl > 32 {
                        tls_discard(sys, s.cipher_in, pl - 32);
                    }
                    if pl >= abi::contracts::net::net_proto::TRACE_CTX_LEN && s.telemetry_chan >= 0
                    {
                        let conn_id = pbuf[0];
                        let si = find_session_by_conn_id(s, conn_id);
                        if si >= 0 {
                            let idx = si as usize;
                            // Latch IP's trace context. It is forwarded to HTTP
                            // only AFTER the held MSG_ACCEPTED (at handshake
                            // completion) — HTTP drops context for a conn_id it
                            // hasn't accepted yet, so forwarding it now (before
                            // the held accept) would lose the parenting.
                            s.sessions[idx]
                                .trace_ctx_trace
                                .copy_from_slice(&pbuf[1..17]);
                            s.sessions[idx]
                                .trace_ctx_parent
                                .copy_from_slice(&pbuf[17..25]);
                            s.sessions[idx].trace_ctx_flags = pbuf[25];
                        }
                    }
                }
                _ => {
                    // Unknown — discard
                    tls_discard(sys, s.cipher_in, payload_len as usize);
                }
            }
        }
    }

    let t2 = if diag_on { dev_micros(sys) } else { 0 };

    // ── Phase 3: Read from clear_in (upstream: HTTP → TLS) ──
    let poll_cl = (sys.channel_poll)(s.clear_in, POLL_IN);
    if poll_cl > 0 && (poll_cl as u32 & POLL_IN) != 0 {
        let (msg_type, payload_len) = tls_read_header(sys, s.clear_in);
        if msg_type != 0 {
            did_work = true;
            match msg_type {
                t if t == NET_CMD_SEND => {
                    // Encrypt and forward as CMD_SEND on cipher_out
                    let pl = payload_len as usize;
                    if pl < 1 {
                        // Malformed
                    } else {
                        let mut conn_id_buf = [0u8; 1];
                        (sys.channel_read)(s.clear_in, conn_id_buf.as_mut_ptr(), 1);
                        let conn_id = conn_id_buf[0];
                        let data_len = pl - 1;
                        let si = find_session_by_conn_id(s, conn_id);
                        if si >= 0 {
                            let idx = si as usize;
                            if s.sessions[idx].state == SessionState::Ready && data_len > 0 {
                                // Split bodies larger than one wire
                                // record into multiple application_data
                                // records. Chunk size leaves room for
                                // the 5-byte record header, content-type
                                // trailer, AEAD tag, and outer framing.
                                const CLEAR_CHUNK_MAX: usize = NET_SCRATCH_SIZE - 5 - 16 - 1 - 4;
                                let mut remaining = data_len;
                                while remaining > 0 {
                                    let rd = remaining.min(CLEAR_CHUNK_MAX);

                                    // Read plaintext directly into the
                                    // wire-record buffer so encrypt
                                    // happens in place (saves two memcpys
                                    // vs the prior staged path).
                                    let mut rec = [0u8; SEND_BUF_SIZE + 5];
                                    (sys.channel_read)(s.clear_in, rec.as_mut_ptr().add(5), rd);

                                    let sess = &mut s.sessions[idx];
                                    let enc_payload_len = encrypt_record_in_place(
                                        sess.driver.suite,
                                        &mut sess.write_keys,
                                        CT_APPLICATION_DATA,
                                        rd,
                                        &mut rec[5..],
                                    );
                                    // Header written AFTER encrypt so
                                    // length reflects the actual
                                    // payload, including seq-wrap
                                    // (enc_payload_len == 0).
                                    *rec.as_mut_ptr() = CT_APPLICATION_DATA;
                                    *rec.as_mut_ptr().add(1) = 0x03;
                                    *rec.as_mut_ptr().add(2) = 0x03;
                                    *rec.as_mut_ptr().add(3) = (enc_payload_len >> 8) as u8;
                                    *rec.as_mut_ptr().add(4) = enc_payload_len as u8;
                                    let total = 5 + enc_payload_len;

                                    // The AEAD seq has already advanced;
                                    // dropping this record would desync
                                    // the peer permanently. Fail the
                                    // session loudly instead.
                                    let sent = tls_write_frame(
                                        sys,
                                        s.cipher_out,
                                        NET_CMD_SEND,
                                        conn_id,
                                        rec.as_ptr(),
                                        total as u16,
                                        &mut s.net_scratch,
                                    );
                                    if !sent {
                                        let msg: &[u8] =
                                            b"[tls] cipher_out full mid-record; session->Error";
                                        dev_log(sys, 3, msg.as_ptr(), msg.len());
                                        s.frame_write_dropped =
                                            s.frame_write_dropped.wrapping_add(1);
                                        s.sessions[idx].state = SessionState::Error;
                                        if remaining > rd {
                                            // Drop the rest of the
                                            // incoming clear send;
                                            // session is already
                                            // Errored.
                                            tls_discard(sys, s.clear_in, remaining - rd);
                                        }
                                        break;
                                    }
                                    retx_push(&mut s.sessions[idx], rec.as_ptr(), total as u16);
                                    remaining -= rd;
                                }
                            } else {
                                tls_discard(sys, s.clear_in, data_len);
                            }
                        } else {
                            tls_discard(sys, s.clear_in, data_len);
                        }
                    }
                }
                t if t == NET_CMD_CLOSE => {
                    let pl = payload_len as usize;
                    let mut payload = [0u8; 16];
                    let rd = if pl < 16 { pl } else { 16 };
                    if rd > 0 {
                        (sys.channel_read)(s.clear_in, payload.as_mut_ptr(), rd);
                    }
                    if pl > 16 {
                        tls_discard(sys, s.clear_in, pl - 16);
                    }
                    let conn_id = if pl > 0 { payload[0] } else { 0 };
                    // Send close_notify alert if session is ready
                    let si = find_session_by_conn_id(s, conn_id);
                    if si >= 0 {
                        let idx = si as usize;
                        if s.sessions[idx].state == SessionState::Ready {
                            send_alert(s, idx, ALERT_CLOSE_NOTIFY);
                        }
                        s.sessions[idx].reset();
                    }
                    // Forward CMD_CLOSE to cipher_out — best-effort.
                    let _ = tls_write_or_count(
                        s,
                        s.cipher_out,
                        NET_CMD_CLOSE,
                        conn_id,
                        core::ptr::null(),
                        0,
                    );
                }
                t if t == NET_CMD_BIND || t == NET_CMD_CONNECT => {
                    // Forward to cipher_out (toward IP). For CMD_CONNECT, STAMP
                    // the requester tag (byte 7) with TLS's own module index so
                    // IP echoes it in MSG_CONNECTED and TLS — not a co-wired
                    // exporter sharing ip.net_out — claims the resulting outbound
                    // connection. CMD_BIND passes through unchanged.
                    let pl = payload_len as usize;
                    let mut rd = if pl < NET_SCRATCH_SIZE {
                        pl
                    } else {
                        NET_SCRATCH_SIZE
                    };
                    if rd > 0 {
                        (sys.channel_read)(s.clear_in, s.net_scratch.as_mut_ptr(), rd);
                    }
                    if pl > rd {
                        tls_discard(sys, s.clear_in, pl - rd);
                    }
                    let mut forward = true;
                    // For a CMD_CONNECT we're about to forward: the downstream tag
                    // to latch, deferred until the upstream write actually lands.
                    let mut arm_pending: Option<u8> = None;
                    if t == NET_CMD_CONNECT && rd >= 7 && rd < NET_SCRATCH_SIZE {
                        let new_tag = if rd >= 8 { s.net_scratch[7] } else { 0 };
                        if s.pending_connect_active {
                            // SERIALIZE: a connect is already in flight and TLS
                            // routes all mediated connects through its single tag,
                            // so a second concurrent connect would clobber the
                            // pending correlation. Reject it downstream with EAGAIN
                            // (translated to the new request's tag) and DON'T
                            // forward — the clear-side consumer retries.
                            let err = [(-11i8) as u8, new_tag]; // EAGAIN + downstream tag
                            let _ = tls_write_or_count(
                                s,
                                s.clear_out,
                                NET_MSG_ERROR,
                                0,
                                err.as_ptr(),
                                err.len() as u16,
                            );
                            forward = false;
                        } else {
                            // Remember the clear-side consumer's original tag, then
                            // overwrite byte 7 with TLS's own tag so IP routes the
                            // completion to TLS. Defer marking the connect pending
                            // until the forward below actually succeeds.
                            if rd == 7 {
                                rd = 8;
                            }
                            s.net_scratch[7] = dev_requester_tag(sys);
                            arm_pending = Some(new_tag);
                        }
                    }
                    if forward {
                        let wrote = tls_write_raw_frame(
                            sys,
                            s.cipher_out,
                            t,
                            s.net_scratch.as_ptr(),
                            rd as u16,
                        );
                        // Latch pending ONLY after the connect was actually
                        // written upstream — a dropped write must not wedge the
                        // single pending slot (the consumer retries).
                        if wrote {
                            if let Some(dtag) = arm_pending {
                                s.pending_downstream_tag = dtag;
                                s.pending_connect_active = true;
                            }
                        }
                    }
                }
                _ => {
                    tls_discard(sys, s.clear_in, payload_len as usize);
                }
            }
        }
    }

    let t3 = if diag_on { dev_micros(sys) } else { 0 };

    // ── Phase 4: For Ready sessions, try to decrypt any buffered data ──
    i = 0;
    while i < MAX_SESSIONS {
        if s.sessions[i].state == SessionState::Ready {
            // Retry any held completion that a back-pressured clear_out dropped
            // at handshake-complete, so the consumer always learns of the accept.
            if s.sessions[i].held_msg_type != 0 {
                forward_held_completion(s, i);
            }
            if s.sessions[i].recv_len >= 5 {
                try_decrypt_forward(s, i);
            }
        }
        i += 1;
    }
    let t4 = if diag_on { dev_micros(sys) } else { 0 };

    // Emit a per-phase breakdown only when the step crossed the
    // heavy threshold and the diagnostic is on. Threshold keeps
    // the fast path silent.
    const TLS_STEP_HEAVY_US: u64 = 200;
    let total = t4.wrapping_sub(t0);
    if diag_on && total >= TLS_STEP_HEAVY_US {
        let p1 = (t1.wrapping_sub(t0)) as u32;
        let p2 = (t2.wrapping_sub(t1)) as u32;
        let p3 = (t3.wrapping_sub(t2)) as u32;
        let p4 = (t4.wrapping_sub(t3)) as u32;
        let buf = s.net_scratch.as_mut_ptr();
        let buf_max = s.net_scratch.len();
        let mut pos = 0usize;
        let emit = |bytes: &[u8], pos: &mut usize| {
            let mut i = 0;
            while i < bytes.len() && *pos < buf_max {
                *buf.add(*pos) = bytes[i];
                *pos += 1;
                i += 1;
            }
        };
        emit(b"[tls] heavy total_us=", &mut pos);
        pos += fmt_u32_dec(total as u32, buf.add(pos));
        emit(b" hs=", &mut pos);
        pos += fmt_u32_dec(p1, buf.add(pos));
        emit(b" cipher_in=", &mut pos);
        pos += fmt_u32_dec(p2, buf.add(pos));
        emit(b" clear_in=", &mut pos);
        pos += fmt_u32_dec(p3, buf.add(pos));
        emit(b" ready=", &mut pos);
        pos += fmt_u32_dec(p4, buf.add(pos));
        dev_log(sys, 3, buf, pos);
    }

    if did_work {
        2
    } else {
        0
    } // Burst or Continue
}

// ============================================================================
// Session management
// ============================================================================

/// Emit a finished `tls.handshake` span. When IP propagated a `MSG_TRACE_CTX`
/// for this connection, the span joins that trace as a child of IP's span
/// (using this session's own minted `span_id`); otherwise it's a root. `ok`
/// maps to OTLP status OK / ERROR. `name_id = 0` is the first
/// `[observability].spans` entry.
#[inline(never)]
unsafe fn emit_handshake_span(s: &mut TlsState, idx: usize, ok: bool) {
    // Head-sampling gate FIRST — before any clock read or RNG. A propagated
    // context carries the ingress decision in its flags; a root (no propagation)
    // is sampled. An unsampled flow emits nothing (RFC observability §sampling).
    let propagated = s.sessions[idx].trace_ctx_trace != [0u8; 16];
    let eff_flags = if propagated {
        s.sessions[idx].trace_ctx_flags
    } else {
        abi::contracts::telemetry::TRACE_FLAGS_SAMPLED
    };
    if eff_flags & abi::contracts::telemetry::TRACE_FLAGS_SAMPLED == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let me = dev_self_index(sys);
    if me < 0 {
        return;
    }
    let start = s.sessions[idx].span_start_us;
    let end_raw = dev_micros(sys);
    let end = if end_raw < start { start } else { end_raw };
    let mut ctx = abi::contracts::telemetry::SpanContext {
        trace_id: [0u8; 16],
        span_id: s.sessions[idx].span_id,
        parent_id: [0u8; 8],
        flags: eff_flags,
    };
    // A non-zero received trace id means IP propagated context — join its trace
    // under IP's span; otherwise this handshake is its own root.
    if propagated {
        ctx.trace_id = s.sessions[idx].trace_ctx_trace;
        ctx.parent_id = s.sessions[idx].trace_ctx_parent;
    } else {
        dev_csprng_fill(sys, ctx.trace_id.as_mut_ptr(), 16);
    }
    // `span_id` was minted at handshake start; if somehow unset (all-zero),
    // fall back to a fresh one so the span always has an id.
    if ctx.span_id == [0u8; 8] {
        dev_csprng_fill(sys, ctx.span_id.as_mut_ptr(), 8);
    }
    let status = if ok {
        abi::contracts::telemetry::STATUS_OK
    } else {
        abi::contracts::telemetry::STATUS_ERROR
    };
    dev_telemetry_span(
        sys,
        s.telemetry_chan,
        me as u16,
        0, // name_id 0 = tls.handshake
        abi::contracts::telemetry::SPAN_INTERNAL,
        status,
        &ctx,
        start,
        end,
    );
}

fn alloc_session_for_conn(s: &mut TlsState, conn_id: u8) -> Option<usize> {
    let mut i = 0;
    while i < MAX_SESSIONS {
        if s.sessions[i].state == SessionState::Idle {
            s.sessions[i].state = SessionState::Allocated;
            s.sessions[i].conn_id = conn_id;
            s.sessions[i].held_msg_type = 0;
            s.sessions[i].recv_len = 0;
            s.sessions[i].send_len = 0;
            s.sessions[i].send_offset = 0;
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_session_by_conn_id(s: &TlsState, conn_id: u8) -> i32 {
    let mut i = 0;
    while i < MAX_SESSIONS {
        if s.sessions[i].state != SessionState::Idle && s.sessions[i].conn_id == conn_id {
            return i as i32;
        }
        i += 1;
    }
    -1
}

// Peer certificate verification is deferred — requires larger module binary.
/// Verify CertificateVerify signature from peer. Returns true on success.
unsafe fn verify_peer_cert_verify(s: &TlsState, idx: usize, data: &[u8], len: usize) -> bool {
    let sess = &s.sessions[idx];
    // No peer cert means nothing to verify against. If mTLS is required
    // (server with verify_peer=1, or client always), the caller must
    // have already rejected an empty Certificate message — by the time
    // we get here, a zero pubkey means the chain of trust is broken.
    if sess.driver.peer_cert_pubkey_len == 0 {
        return false;
    }
    let hl = sess.driver.suite.hash_len();
    let transcript_hash = match &sess.driver.transcript {
        Some(t) => t.current_hash(),
        None => return false,
    };
    let context: &[u8] = if sess.driver.is_server {
        b"TLS 1.3, client CertificateVerify"
    } else {
        b"TLS 1.3, server CertificateVerify"
    };
    let mut vc = [0u8; 200];
    let vc_len = build_verify_content(context, &transcript_hash[..hl], hl, &mut vc);
    let vc_hash = sha256(&vc[..vc_len]);
    let cv_body = &data[4..len];
    if let Some((_scheme, sig_der)) = parse_certificate_verify(cv_body) {
        if let Some(raw_sig) = parse_der_signature(sig_der) {
            let pk = &sess.driver.peer_cert_pubkey[..sess.driver.peer_cert_pubkey_len as usize];
            return ecdsa_verify(pk, &vc_hash, &raw_sig);
        }
    }
    false
}

/// Shared peer-certificate validation. Used by both the TCP-TLS
/// path (`extract_peer_cert_key`) and the DTLS path
/// (`dtls_state.rs::dtls_extract_peer_cert_pubkey`) so the same
/// chain-of-trust + SPIFFE rules apply to every transport.
///
/// Returns false on any parse / validation failure — empty
/// Certificate list, malformed leaf cert, signature failure
/// against the configured CA, empty pubkey, or SPIFFE SAN
/// mismatch. On success, the peer's raw subjectPublicKey is
/// written into `driver.peer_cert_pubkey` (length in
/// `peer_cert_pubkey_len`).
///
/// Pass `None` for `ca_pubkey` to skip CA verification, or
/// `None` for `trust_domain` to skip SPIFFE SAN matching.
/// Downstream code (`verify_peer_cert_verify`, `emit_peer_identity`)
/// relies on `peer_cert_pubkey_len > 0` as the marker that a real
/// identity was bound; this helper guarantees that property
/// only when *every* configured check passes.
unsafe fn validate_and_extract_peer_cert(
    hs_body: &[u8],
    driver: &mut HandshakeDriver,
    ca_pubkey: Option<&[u8]>,
    trust_domain: Option<&[u8]>,
) -> bool {
    let cert_der = match parse_certificate_msg(hs_body) {
        Some(d) => d,
        None => return false,
    };
    let cert = match parse_certificate(cert_der) {
        Some(c) => c,
        None => return false,
    };
    if let Some(ca_pk) = ca_pubkey {
        if !ca_pk.is_empty() {
            // Chain-of-one path validation: leaf must be signed
            // directly by the configured CA.
            let tbs_hash = sha256(cert.tbs_raw);
            let raw_sig = match parse_der_signature(cert.signature) {
                Some(r) => r,
                None => return false,
            };
            if !ecdsa_verify(ca_pk, &tbs_hash, &raw_sig) {
                return false;
            }
        }
    }
    let pk = cert.public_key;
    if pk.is_empty() || pk.len() > 65 {
        return false;
    }
    core::ptr::copy_nonoverlapping(pk.as_ptr(), driver.peer_cert_pubkey.as_mut_ptr(), pk.len());
    driver.peer_cert_pubkey_len = pk.len() as u8;
    if let Some(td) = trust_domain {
        if !td.is_empty() {
            let mut spiffe_ok = false;
            extract_san_uris(cert_der, |uri| {
                if is_spiffe_match(uri, td) {
                    spiffe_ok = true;
                }
                spiffe_ok
            });
            if !spiffe_ok {
                return false;
            }
        }
    }
    true
}

/// TCP-TLS adapter: pulls the configured CA pubkey + trust domain
/// off `TlsState` and delegates to `validate_and_extract_peer_cert`.
unsafe fn extract_peer_cert_key(s: &mut TlsState, idx: usize, hs_body: &[u8]) -> bool {
    let ca_pk = if s.require_ca && s.ca_pubkey_len > 0 {
        Some(&s.ca_pubkey[..s.ca_pubkey_len as usize])
    } else {
        None
    };
    let td = if s.trust_domain_len > 0 {
        Some(&s.trust_domain[..s.trust_domain_len])
    } else {
        None
    };
    validate_and_extract_peer_cert(hs_body, &mut s.sessions[idx].driver, ca_pk, td)
}

/// Skip any CCS records at the front of a session's recv_buf.
unsafe fn skip_ccs(sess: &mut TlsSession) {
    while sess.recv_len >= 5 && *sess.recv_buf.as_ptr() == CT_CHANGE_CIPHER_SPEC {
        let p = sess.recv_buf.as_ptr();
        let ccs_len = ((*p.add(3) as usize) << 8) | (*p.add(4) as usize);
        let consumed = 5 + ccs_len;
        if sess.recv_len < consumed || consumed > RECV_BUF_SIZE {
            break;
        }
        let remain = sess.recv_len - consumed;
        if remain > 0 {
            core::ptr::copy(
                sess.recv_buf.as_ptr().add(consumed),
                sess.recv_buf.as_mut_ptr(),
                remain,
            );
        }
        sess.recv_len = remain;
    }
}

/// Assign a fresh ephemeral ECDH key pair to `driver`. Single
/// source of truth for both TCP-TLS and DTLS — pre-computing
/// keys at `module_new` and reusing them across sessions would
/// weaken forward secrecy (a memory disclosure after session N
/// reveals the private key of every subsequent session that
/// reuses it). Calls CSPRNG; on failure, falls back to the
/// pre-computed pool slot, consuming it at most once. Returns
/// true on success, false if neither a fresh key nor a free pool
/// slot is available — in that case the caller must abort
/// session setup (do NOT carry on with a zero-initialised
/// private key).
unsafe fn assign_fresh_ecdh_key(
    sys: &SyscallTable,
    driver: &mut HandshakeDriver,
    eph_private: &mut [[u8; 32]; MAX_SESSIONS],
    eph_public: &[[u8; 65]; MAX_SESSIONS],
    eph_used: &mut [bool; MAX_SESSIONS],
    pool_hit: &mut u32,
    fallback_keygen: &mut u32,
) -> bool {
    // Pool first — each entry was CSPRNG-generated at `module_new`
    // and is consumed once. Drops the per-accept cost from ~900 µs
    // (scalar-mult-base) to a memcpy. Pool slot is wiped on hand-off
    // so a future memory read can't recover the scalar.
    let mut key_idx: Option<usize> = None;
    let mut k = 0;
    while k < MAX_SESSIONS {
        if !eph_used[k] {
            key_idx = Some(k);
            break;
        }
        k += 1;
    }
    if let Some(idx) = key_idx {
        driver.ecdh_private = eph_private[idx];
        driver.ecdh_public = eph_public[idx];
        // Wipe the pool slot's private scalar — the public point
        // is fine to leave (it's already on the wire).
        let mut j = 0;
        while j < 32 {
            core::ptr::write_volatile(&mut eph_private[idx][j], 0);
            j += 1;
        }
        eph_used[idx] = true;
        *pool_hit = pool_hit.wrapping_add(1);
        return true;
    }

    // Pool exhausted — synchronous keygen. Counter bumps before
    // the keygen so a CSPRNG outage still surfaces on telemetry.
    *fallback_keygen = fallback_keygen.wrapping_add(1);
    let mut random = [0u8; 32];
    if dev_csprng_fill(sys, random.as_mut_ptr(), 32) < 0 {
        return false;
    }
    let (mut priv_key, pub_key) = ecdh_keygen(&random);
    driver.ecdh_private = priv_key;
    driver.ecdh_public = pub_key;
    let mut i = 0;
    while i < 32 {
        core::ptr::write_volatile(random.as_mut_ptr().add(i), 0);
        core::ptr::write_volatile(priv_key.as_mut_ptr().add(i), 0);
        i += 1;
    }
    true
}

/// Post-handshake key-material cleanup. Zeroes the ECDH private
/// scalar and the handshake-tier secrets once application keys
/// are derived. Neither piece of material is recoverable from
/// the on-wire transcript (forward secrecy holds against a passive
/// observer regardless of what we wipe), but leaving these
/// resident widens the *compromise* window — any attacker who
/// later reads our memory recovers the handshake secrets and
/// from them the application traffic keys, breaking confidentiality
/// of every record we've sent or will send under this session.
/// Scrubbing them as soon as the next-tier keys exist bounds that
/// window to the lifetime of `application_traffic_secret_N` itself.
///
/// Called by both the TCP-TLS and DTLS app-keys-derivation paths
/// so the rule is uniform across transports.
unsafe fn zeroize_post_app_keys(driver: &mut HandshakeDriver) {
    if let Some(ref mut ks) = driver.key_schedule {
        let mut i = 0;
        while i < 48 {
            core::ptr::write_volatile(&mut ks.client_hs_secret[i], 0);
            core::ptr::write_volatile(&mut ks.server_hs_secret[i], 0);
            i += 1;
        }
    }
    let mut i = 0;
    while i < 32 {
        core::ptr::write_volatile(&mut driver.ecdh_private[i], 0);
        i += 1;
    }
}

unsafe fn init_session_crypto(s: &mut TlsState, idx: usize) {
    let sys = &*s.syscalls;
    let ok = assign_fresh_ecdh_key(
        sys,
        &mut s.sessions[idx].driver,
        &mut s.eph_private,
        &s.eph_public,
        &mut s.eph_used,
        &mut s.ecdh_pool_hit,
        &mut s.ecdh_fallback_keygen,
    );
    if !ok {
        s.sessions[idx].state = SessionState::Error;
        return;
    }
    // Default suite (will be set during handshake)
    s.sessions[idx].driver.suite = CipherSuite::ChaCha20Poly1305;
}

// ============================================================================
// Record / driver-queue bridge
//
// The handshake state machine inside `HandshakeDriver` consumes plain
// handshake bytes from `driver.in_buf` and produces plain handshake
// bytes into `driver.out_buf`. The bridge below moves those bytes
// across the record boundary:
//
//   cipher_in MSG_DATA → recv_buf → record_drain_inbound  → driver.in_buf
//   driver.out_buf     → record_drain_outbound → cipher_out CMD_SEND
//
// When `read_keys.key_len == 0` the inbound level is Initial (records
// are plaintext CT_HANDSHAKE); otherwise records are
// CT_APPLICATION_DATA and decrypt under `read_keys`. Symmetrically for
// `write_keys` on the outbound side. DTLS (Phase B) and QUIC (Phase C)
// reuse the same driver via their own bridges — the in/out queues are
// the only handshake-driver entry points either transport sees.
// ============================================================================

/// True if the inbound record level is Initial — i.e. read_keys haven't
/// been derived yet, so records arrive as plaintext CT_HANDSHAKE.
fn recv_level_is_initial(sess: &TlsSession) -> bool {
    sess.read_keys.key_len == 0
}

/// True if the outbound record level is Initial — write_keys haven't
/// been derived yet, so handshake messages ship as plaintext records.
fn send_level_is_initial(sess: &TlsSession) -> bool {
    sess.write_keys.key_len == 0
}

/// Drain one inbound record from `recv_buf` into `driver.in_buf`,
/// decrypting if read_keys are set. Returns true if a record was
/// successfully processed. Caller (`module_step`'s inner loop)
/// re-invokes drain after every pump tick so key rotations
/// (`pump_derive_app_keys`) take effect before the next record is
/// decrypted — draining everything up front would use stale keys.
unsafe fn record_drain_inbound_one(s: &mut TlsState, idx: usize) -> bool {
    let _sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];
    skip_ccs(sess);
    if sess.recv_len < 5 {
        return false;
    }
    let rec_type = sess.recv_buf[0];
    let rec_len = ((sess.recv_buf[3] as usize) << 8) | (sess.recv_buf[4] as usize);
    if rec_len > MAX_CIPHERTEXT || rec_len > RECV_BUF_SIZE {
        sess.state = SessionState::Error;
        return false;
    }
    if sess.recv_len < 5 + rec_len {
        return false;
    }

    if recv_level_is_initial(sess) {
        if rec_type != CT_HANDSHAKE {
            sess.state = SessionState::Error;
            return false;
        }
        let space = HS_IO_BUF_SIZE - sess.driver.in_len;
        if rec_len > space {
            return false; // in_buf full — caller must drain via pump_session.
        }
        core::ptr::copy_nonoverlapping(
            sess.recv_buf.as_ptr().add(5),
            sess.driver.in_buf.as_mut_ptr().add(sess.driver.in_len),
            rec_len,
        );
        sess.driver.in_len += rec_len;
    } else {
        if rec_type != CT_APPLICATION_DATA {
            // Plaintext records after handshake keys are derived
            // shouldn't appear; drop the record and signal progress.
            let consumed = 5 + rec_len;
            let remain = sess.recv_len - consumed;
            if remain > 0 {
                core::ptr::copy(
                    sess.recv_buf.as_ptr().add(consumed),
                    sess.recv_buf.as_mut_ptr(),
                    remain,
                );
            }
            sess.recv_len = remain;
            return true;
        }
        let mut hdr = [0u8; 5];
        core::ptr::copy_nonoverlapping(sess.recv_buf.as_ptr(), hdr.as_mut_ptr(), 5);
        let mut ct = [0u8; RECV_BUF_SIZE];
        core::ptr::copy_nonoverlapping(sess.recv_buf.as_ptr().add(5), ct.as_mut_ptr(), rec_len);
        match decrypt_record(
            sess.driver.suite,
            &mut sess.read_keys,
            &hdr,
            &mut ct[..rec_len],
        ) {
            Some((pt_len, inner_type)) => {
                if inner_type == CT_HANDSHAKE {
                    let space = HS_IO_BUF_SIZE - sess.driver.in_len;
                    if pt_len > space {
                        return false;
                    }
                    core::ptr::copy_nonoverlapping(
                        ct.as_ptr(),
                        sess.driver.in_buf.as_mut_ptr().add(sess.driver.in_len),
                        pt_len,
                    );
                    sess.driver.in_len += pt_len;
                }
                // Other inner types (alert, app data) are handled
                // outside the handshake path; drop here.
            }
            None => {
                sess.state = SessionState::Error;
                return false;
            }
        }
    }

    let consumed = 5 + rec_len;
    let remain = sess.recv_len - consumed;
    if remain > 0 {
        core::ptr::copy(
            sess.recv_buf.as_ptr().add(consumed),
            sess.recv_buf.as_mut_ptr(),
            remain,
        );
    }
    sess.recv_len = remain;
    true
}

/// Drain complete handshake messages from `driver.out_buf`, wrap each
/// into a record (plaintext if write_keys haven't been derived,
/// AEAD-sealed otherwise), and write to `cipher_out`. Honors the
/// pending_ccs flags by appending a CHANGE_CIPHER_SPEC record after
/// the next plaintext record so it ships in the same TCP segment.
unsafe fn record_drain_outbound(s: &mut TlsState, idx: usize) {
    loop {
        let sess = &s.sessions[idx];
        if sess.driver.out_len < 4 {
            return;
        }
        let msg_body_len = ((sess.driver.out_buf[1] as usize) << 16)
            | ((sess.driver.out_buf[2] as usize) << 8)
            | (sess.driver.out_buf[3] as usize);
        let total = 4 + msg_body_len;
        if total > sess.driver.out_len {
            return; // Wait for the rest of the message.
        }
        if total > SEND_BUF_SIZE {
            // A single handshake message larger than SEND_BUF_SIZE
            // would need TLS-level fragmentation across records — we
            // don't emit fragmented handshakes today.
            s.sessions[idx].state = SessionState::Error;
            return;
        }

        let mut rec = [0u8; SEND_BUF_SIZE + 32];
        let rec_len: usize;

        if send_level_is_initial(&s.sessions[idx]) {
            rec[0] = CT_HANDSHAKE;
            rec[1] = 0x03;
            rec[2] = 0x03;
            rec[3] = (total >> 8) as u8;
            rec[4] = total as u8;
            core::ptr::copy_nonoverlapping(
                s.sessions[idx].driver.out_buf.as_ptr(),
                rec.as_mut_ptr().add(5),
                total,
            );
            rec_len = 5 + total;
        } else {
            let suite = s.sessions[idx].driver.suite;
            let mut enc_buf = [0u8; SEND_BUF_SIZE];
            let enc_len = encrypt_record(
                suite,
                &mut s.sessions[idx].write_keys,
                CT_HANDSHAKE,
                &s.sessions[idx].driver.out_buf[..total],
                &mut enc_buf,
            );
            rec[0] = CT_APPLICATION_DATA;
            rec[1] = 0x03;
            rec[2] = 0x03;
            rec[3] = (enc_len >> 8) as u8;
            rec[4] = enc_len as u8;
            core::ptr::copy_nonoverlapping(enc_buf.as_ptr(), rec.as_mut_ptr().add(5), enc_len);
            rec_len = 5 + enc_len;
        }

        // Append CCS into the same record buffer if a flag is pending
        // and this was a plaintext record (Initial level). Per RFC 8446
        // §5 the CCS is dropped on the wire; preserving the same TCP
        // segment matters for middlebox compatibility.
        let mut total_len = rec_len;
        if send_level_is_initial(&s.sessions[idx])
            && (s.sessions[idx].pending_ccs || s.sessions[idx].pending_ccs_client)
        {
            rec[total_len] = CT_CHANGE_CIPHER_SPEC;
            rec[total_len + 1] = 0x03;
            rec[total_len + 2] = 0x03;
            rec[total_len + 3] = 0x00;
            rec[total_len + 4] = 0x01;
            rec[total_len + 5] = 0x01;
            total_len += 6;
            s.sessions[idx].pending_ccs = false;
            s.sessions[idx].pending_ccs_client = false;
        }

        let conn_id = s.sessions[idx].conn_id;
        let sys = &*s.syscalls;
        // AEAD seq already advanced; a dropped write would desync
        // the peer permanently. Fail the session if the write fails.
        let sent = tls_write_frame(
            sys,
            s.cipher_out,
            NET_CMD_SEND,
            conn_id,
            rec.as_ptr(),
            total_len as u16,
            &mut s.net_scratch,
        );
        if !sent {
            s.frame_write_dropped = s.frame_write_dropped.wrapping_add(1);
            let msg: &[u8] = b"[tls] handshake out drop; session->Error";
            dev_log(sys, 3, msg.as_ptr(), msg.len());
            s.sessions[idx].state = SessionState::Error;
            return;
        }
        retx_push(&mut s.sessions[idx], rec.as_ptr(), total_len as u16);

        let sess = &mut s.sessions[idx];
        let remain = sess.driver.out_len - total;
        if remain > 0 {
            core::ptr::copy(
                sess.driver.out_buf.as_ptr().add(total),
                sess.driver.out_buf.as_mut_ptr(),
                remain,
            );
        }
        sess.driver.out_len = remain;
    }
}

/// Thin facade — kept so existing callers compile. The real logic
/// lives on `HandshakeDriver::read_handshake_message`. Mirrors the
/// driver-level error-state convention by translating the driver's
/// `HandshakeState::Error` into `SessionState::Error` if it's set.
unsafe fn driver_read_handshake_message(
    sess: &mut TlsSession,
) -> Option<([u8; SCRATCH_SIZE], usize, u8)> {
    let result = sess.driver.read_handshake_message();
    if sess.driver.is_handshake_error() {
        sess.state = SessionState::Error;
    }
    result
}

unsafe fn driver_write_handshake_message(sess: &mut TlsSession, msg: &[u8]) -> bool {
    sess.driver.write_handshake_message(msg)
}

// ============================================================================
// Handshake state machine pump
// ============================================================================

unsafe fn pump_session(s: &mut TlsState, idx: usize) -> bool {
    let _sys = &*s.syscalls;

    let r = match s.sessions[idx].driver.hs_state {
        // ── Server flow ──
        HandshakeState::RecvClientHello | HandshakeState::RecvSecondClientHello => {
            pump_recv_client_hello(s, idx)
        }
        HandshakeState::SendHelloRetryRequest => pump_send_hello_retry(s, idx),
        HandshakeState::SendServerHello => pump_send_server_hello(s, idx),
        HandshakeState::DeriveHandshakeKeys => pump_derive_handshake_keys(s, idx),
        HandshakeState::SendEncryptedExtensions => pump_send_encrypted_extensions(s, idx),
        HandshakeState::SendCertificateRequest => pump_send_certificate_request(s, idx),
        HandshakeState::SendCertificate => pump_send_certificate(s, idx),
        HandshakeState::SendCertificateVerify => pump_send_certificate_verify(s, idx),
        HandshakeState::SendFinished => pump_send_finished(s, idx),
        HandshakeState::RecvClientCert => pump_recv_client_cert(s, idx),
        HandshakeState::RecvClientCertVerify => pump_recv_client_cert_verify(s, idx),
        HandshakeState::RecvClientFinished => pump_recv_client_finished(s, idx),
        HandshakeState::DeriveAppKeys => pump_derive_app_keys(s, idx),

        // ── Client flow ──
        HandshakeState::SendClientHello => pump_send_client_hello(s, idx),
        HandshakeState::RecvServerHello => pump_recv_server_hello(s, idx),
        HandshakeState::ClientDeriveHandshakeKeys => pump_derive_handshake_keys(s, idx),
        HandshakeState::RecvEncryptedExtensions => pump_recv_encrypted(
            s,
            idx,
            HT_ENCRYPTED_EXTENSIONS,
            HandshakeState::RecvCertificate,
        ),
        HandshakeState::RecvCertificate => pump_recv_certificate(s, idx),
        HandshakeState::RecvCertificateVerify => pump_recv_certificate_verify(s, idx),
        HandshakeState::RecvFinished => pump_recv_server_finished(s, idx),
        HandshakeState::SendClientFinished => pump_send_client_finished(s, idx),
        HandshakeState::ClientDeriveAppKeys => pump_derive_app_keys(s, idx),

        HandshakeState::Complete => {
            s.sessions[idx].state = SessionState::Ready;
            true
        }
        _ => false,
    };
    // Centralised error promotion: any pump step that flipped the
    // driver into Error transitions the outer session state too.
    if s.sessions[idx].driver.is_handshake_error() {
        s.sessions[idx].state = SessionState::Error;
    }
    r
}

// ============================================================================
// Server handshake steps
// ============================================================================

unsafe fn pump_recv_client_hello(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    let (msg, total, msg_type) = match driver_read_handshake_message(sess) {
        Some(t) => t,
        None => return false,
    };
    if msg_type != HT_CLIENT_HELLO {
        sess.state = SessionState::Error;
        return true;
    }
    let hs_data = &msg[..total];
    let ch_body = &msg[4..total];
    let ch = match parse_client_hello(ch_body) {
        Some(c) => c,
        None => {
            sess.state = SessionState::Error;
            return true;
        }
    };

    // Validate TLS 1.3
    if ch.supported_versions != Some(0x0304) {
        dev_log(
            sys,
            2,
            b"[tls] client not TLS 1.3".as_ptr(),
            b"[tls] client not TLS 1.3".len(),
        );
        sess.state = SessionState::Error;
        return true;
    }

    // Select cipher suite
    sess.driver.suite = match select_cipher_suite(ch.cipher_suites) {
        Some(cs) => cs,
        None => {
            dev_log(
                sys,
                2,
                b"[tls] no common cipher suite".as_ptr(),
                b"[tls] no common cipher suite".len(),
            );
            sess.state = SessionState::Error;
            return true;
        }
    };

    // Save session_id for echo
    if ch.session_id.len() <= 32 {
        core::ptr::copy_nonoverlapping(
            ch.session_id.as_ptr(),
            sess.driver.peer_session_id.as_mut_ptr(),
            ch.session_id.len(),
        );
        sess.driver.peer_session_id_len = ch.session_id.len() as u8;
    }

    // Initialize or update transcript
    if sess.driver.transcript.is_none() {
        sess.driver.transcript = Some(Transcript::new(sess.driver.suite.hash_alg()));
    }

    // ALPN selection (RFC 7301 + RFC 8446 §4.6.1). The server's
    // preference order is `h2` then `http/1.1`; if the client's ALPN
    // extension overlaps with that list, we record the chosen
    // protocol so the EncryptedExtensions builder can echo it back.
    sess.driver.alpn_selected_len = 0;
    if let Some(list) = ch.alpn_protos {
        for offered in alpn_iter(list) {
            if offered == b"h2" || offered == b"http/1.1" {
                let n = offered.len();
                if n <= sess.driver.alpn_selected.len() {
                    core::ptr::copy_nonoverlapping(
                        offered.as_ptr(),
                        sess.driver.alpn_selected.as_mut_ptr(),
                        n,
                    );
                    sess.driver.alpn_selected_len = n as u8;
                    break;
                }
            }
        }
    }

    match ch.key_share {
        Some((_, key_data)) if key_data.len() <= 65 => {
            core::ptr::copy_nonoverlapping(
                key_data.as_ptr(),
                sess.driver.peer_key_share.as_mut_ptr(),
                key_data.len(),
            );
            sess.driver.peer_key_share_len = key_data.len() as u8;
        }
        _ => {
            if sess.driver.hrr_sent {
                // Second ClientHello still has no P-256 → fatal
                sess.state = SessionState::Error;
                return true;
            }
            // No P-256 key share → send HelloRetryRequest
            if let Some(ref mut t) = sess.driver.transcript {
                t.update(hs_data);
            }
            sess.driver.hs_state = HandshakeState::SendHelloRetryRequest;
            return true;
        }
    }

    // Update transcript with ClientHello (for normal flow or 2nd CH after HRR)
    if let Some(ref mut t) = sess.driver.transcript {
        t.update(hs_data);
    }

    // Generate server random (entropy failure is fatal)
    if dev_csprng_fill(sys, sess.driver.server_random.as_mut_ptr(), 32) < 0 {
        sess.state = SessionState::Error;
        return true;
    }

    sess.driver.hs_state = HandshakeState::SendServerHello;
    true
}

unsafe fn pump_send_server_hello(s: &mut TlsState, idx: usize) -> bool {
    let sess = &mut s.sessions[idx];
    if !pump_send_server_hello_core(&mut sess.driver) {
        return false;
    }
    // Middlebox-compat CCS rides the same TCP segment as ServerHello
    // when no HRR preceded it (RFC 8446 §5).
    if !sess.driver.hrr_sent {
        sess.pending_ccs = true;
    }
    true
}

unsafe fn pump_send_hello_retry(s: &mut TlsState, idx: usize) -> bool {
    let sess = &mut s.sessions[idx];
    if !pump_send_hello_retry_core(&mut sess.driver) {
        return false;
    }
    sess.pending_ccs = true; // Always CCS after HRR for compat-mode peers.
    true
}

unsafe fn pump_send_certificate_request(s: &mut TlsState, idx: usize) -> bool {
    let mut buf = [0u8; SCRATCH_SIZE];
    let msg_len;
    {
        let sess = &mut s.sessions[idx];
        msg_len = build_certificate_request(&mut sess.driver.scratch);
        if let Some(ref mut t) = sess.driver.transcript {
            t.update(&sess.driver.scratch[..msg_len]);
        }
        core::ptr::copy_nonoverlapping(sess.driver.scratch.as_ptr(), buf.as_mut_ptr(), msg_len);
    }
    send_encrypted_handshake(s, idx, &buf, msg_len);
    s.sessions[idx].driver.hs_state = HandshakeState::SendCertificate;
    true
}

unsafe fn pump_recv_client_cert(s: &mut TlsState, idx: usize) -> bool {
    match recv_encrypted_handshake(s, idx) {
        Some((data, len, msg_type)) => {
            // We only reach this state when verify_peer != 0 (mTLS).
            // RFC 8446 §4.4.2.4: the client MUST send a Certificate
            // message. Anything else — including a client sending
            // Finished directly to skip auth — is a protocol error.
            if msg_type != HT_CERTIFICATE {
                s.sessions[idx].state = SessionState::Error;
                return true;
            }
            if let Some(ref mut t) = s.sessions[idx].driver.transcript {
                t.update(&data[..len]);
            }
            if !extract_peer_cert_key(s, idx, &data[4..len]) {
                s.sessions[idx].state = SessionState::Error;
                return true;
            }
            s.sessions[idx].driver.hs_state = HandshakeState::RecvClientCertVerify;
            true
        }
        None => false,
    }
}

unsafe fn pump_recv_client_cert_verify(s: &mut TlsState, idx: usize) -> bool {
    match recv_encrypted_handshake(s, idx) {
        Some((data, len, msg_type)) => {
            if msg_type != 15 {
                s.sessions[idx].state = SessionState::Error;
                return true;
            }
            if !verify_peer_cert_verify(s, idx, &data, len) {
                s.sessions[idx].state = SessionState::Error;
                return true;
            }
            if let Some(ref mut t) = s.sessions[idx].driver.transcript {
                t.update(&data[..len]);
            }
            s.sessions[idx].driver.hs_state = HandshakeState::RecvClientFinished;
            true
        }
        None => false,
    }
}

unsafe fn pump_derive_handshake_keys(s: &mut TlsState, idx: usize) -> bool {
    let bits_per_step = if s.ecdh_bits_per_step >= 256 {
        0u8
    } else {
        s.ecdh_bits_per_step as u8
    };
    let sess = &mut s.sessions[idx];
    if let Some((wk, rk)) = pump_derive_handshake_keys_core(&mut sess.driver, bits_per_step) {
        sess.write_keys = wk;
        sess.read_keys = rk;
    }
    true
}

unsafe fn pump_send_encrypted_extensions(s: &mut TlsState, idx: usize) -> bool {
    let mut buf = [0u8; SCRATCH_SIZE];
    let msg_len;
    {
        let sess = &mut s.sessions[idx];
        let alpn_len = sess.driver.alpn_selected_len as usize;
        let alpn = if alpn_len > 0 {
            core::slice::from_raw_parts(sess.driver.alpn_selected.as_ptr(), alpn_len)
        } else {
            &[][..]
        };
        msg_len = build_encrypted_extensions(&mut sess.driver.scratch, alpn);
        if let Some(ref mut t) = sess.driver.transcript {
            t.update(&sess.driver.scratch[..msg_len]);
        }
        core::ptr::copy_nonoverlapping(sess.driver.scratch.as_ptr(), buf.as_mut_ptr(), msg_len);
    }
    send_encrypted_handshake(s, idx, &buf, msg_len);
    // If mTLS (verify_peer), send CertificateRequest before Certificate
    if s.verify_peer != 0 {
        s.sessions[idx].driver.hs_state = HandshakeState::SendCertificateRequest;
    } else {
        s.sessions[idx].driver.hs_state = HandshakeState::SendCertificate;
    }
    true
}

unsafe fn pump_send_certificate(s: &mut TlsState, idx: usize) -> bool {
    let cert_len = if s.cert_len <= MAX_CERT_LEN {
        s.cert_len
    } else {
        0
    };
    let cert = core::slice::from_raw_parts(s.cert.as_ptr(), cert_len);
    pump_send_certificate_core(&mut s.sessions[idx].driver, cert)
}

unsafe fn pump_send_certificate_verify(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let bits_per_step = if s.ecdh_bits_per_step >= 256 {
        0u8
    } else {
        s.ecdh_bits_per_step as u8
    };

    // ── Stage 1 — hash the transcript + try the key-vault signer.
    //
    // Runs once per CertificateVerify (gated by `cert_verify_hash_ready`).
    // Hashing is cheap (~20 µs); the expensive part is the ECDSA
    // scalar mul which subsequent stages split across multiple
    // `tls.step()` calls. The vault path is treated as fast-and-
    // opaque — if it succeeds we emit immediately. Otherwise we
    // initialise the in-module signer state and yield.
    if s.sessions[idx].driver.cert_verify_hash_ready == 0 {
        let sess = &mut s.sessions[idx];
        let hl = sess.driver.suite.hash_len();
        let transcript_hash = match &sess.driver.transcript {
            Some(t) => t.current_hash(),
            None => {
                sess.state = SessionState::Error;
                return true;
            }
        };
        let context = b"TLS 1.3, server CertificateVerify";
        let mut verify_content = [0u8; 200];
        let vc_len = build_verify_content(context, &transcript_hash[..hl], hl, &mut verify_content);
        let vc_hash = sha256(&verify_content[..vc_len]);
        core::ptr::copy_nonoverlapping(
            vc_hash.as_ptr(),
            sess.driver.cert_verify_hash.as_mut_ptr(),
            32,
        );
        sess.driver.cert_verify_hash_ready = 1;

        // Try kernel KEY_VAULT first. The vault provider returns a
        // 64-byte raw signature directly and is responsible for its
        // own scheduler discipline — no resumable contract on the
        // vault side yet.
        const KV_SIGN: u32 = 0x1003;
        if s.key_vault_handle >= 0 {
            let mut sign_arg = [0u8; 4 + 32 + 64];
            sign_arg[0] = 32;
            core::ptr::copy_nonoverlapping(vc_hash.as_ptr(), sign_arg.as_mut_ptr().add(4), 32);
            let rc = (sys.provider_call)(
                s.key_vault_handle,
                KV_SIGN,
                sign_arg.as_mut_ptr(),
                sign_arg.len(),
            );
            if rc == 0 {
                let mut raw_sig = [0u8; 64];
                core::ptr::copy_nonoverlapping(
                    sign_arg.as_ptr().add(4 + 32),
                    raw_sig.as_mut_ptr(),
                    64,
                );
                return finalise_certificate_verify(s, idx, &raw_sig);
            }
        }

        // No vault — initialise the resumable in-module signer.
        // Subsequent calls drive `scalar_mul.step()` until complete,
        // then `ecdsa_sign_finalise` builds the signature.
        let mut priv_key = [0u8; 32];
        if s.key_len == 32 {
            core::ptr::copy_nonoverlapping(s.key.as_ptr(), priv_key.as_mut_ptr(), 32);
        } else if s.key_len > 32 {
            extract_ec_private_key(&s.key[..s.key_len], &mut priv_key);
        }
        sess.driver.ecdsa_sign_state = ecdsa_sign_init(&priv_key, &vc_hash, bits_per_step);
        let mut j = 0;
        while j < 32 {
            core::ptr::write_volatile(&mut priv_key[j], 0);
            j += 1;
        }
        return true;
    }

    // ── Stage 2 — advance the scalar-mul ladder one budget step.
    //
    // `bits_per_step` (from the same `ecdh_bits_per_step` param) caps
    // how much work this step does. If the ladder finishes inside one
    // step (e.g. ecdh_bits_per_step=256) we fall through immediately
    // to stage 3.
    let sess = &mut s.sessions[idx];
    if !sess.driver.ecdsa_sign_state.scalar_mul.complete() {
        sess.driver.ecdsa_sign_state.scalar_mul.step();
        if !sess.driver.ecdsa_sign_state.scalar_mul.complete() {
            return true;
        }
    }

    // ── Stage 3 — finalise the signature + emit the message.
    //
    // `ecdsa_sign_finalise` consumes the state and zeroises secrets,
    // so we swap it out by value. Both the vault path above and this
    // path converge on `finalise_certificate_verify` below.
    let state = core::mem::replace(&mut sess.driver.ecdsa_sign_state, EcdsaSignState::empty());
    let raw_sig = ecdsa_sign_finalise(state);
    finalise_certificate_verify(s, idx, &raw_sig)
}

/// Build the CertificateVerify message + update transcript + send.
/// Shared by both the vault-sign and incremental-in-module paths in
/// `pump_send_certificate_verify`. Returns true to signal handshake
/// progress (transitions state to `SendFinished`).
#[inline]
unsafe fn finalise_certificate_verify(s: &mut TlsState, idx: usize, raw_sig: &[u8; 64]) -> bool {
    let sess = &mut s.sessions[idx];
    let (der_sig, der_len) = encode_der_signature(raw_sig);
    let msg_len = build_certificate_verify(&der_sig, der_len, &mut sess.driver.scratch);

    if let Some(ref mut t) = sess.driver.transcript {
        t.update(&sess.driver.scratch[..msg_len]);
    }

    let mut buf = [0u8; SCRATCH_SIZE];
    core::ptr::copy_nonoverlapping(sess.driver.scratch.as_ptr(), buf.as_mut_ptr(), msg_len);
    send_encrypted_handshake(s, idx, &buf, msg_len);

    // Reset the per-handshake stage flag so a future renegotiation
    // / session reuse starts fresh.
    s.sessions[idx].driver.cert_verify_hash_ready = 0;
    s.sessions[idx].driver.hs_state = HandshakeState::SendFinished;
    true
}

unsafe fn pump_send_finished(s: &mut TlsState, idx: usize) -> bool {
    let sess = &mut s.sessions[idx];
    if !pump_send_finished_core(&mut sess.driver) {
        return false;
    }
    // mTLS: server expects client Cert + CertVerify before Finished.
    if sess.driver.is_server && s.verify_peer != 0 {
        sess.driver.hs_state = HandshakeState::RecvClientCert;
    }
    true
}

unsafe fn pump_recv_client_finished(s: &mut TlsState, idx: usize) -> bool {
    pump_recv_client_finished_core(&mut s.sessions[idx].driver)
}

/// Forward a session's held `MSG_ACCEPTED` / `MSG_CONNECTED` to clear_out,
/// clearing the latch ONLY if the write lands. A dropped completion stays
/// latched and is retried per-step (the Ready-session loop) so the clear-side
/// consumer is never stranded waiting for the accept.
unsafe fn forward_held_completion(s: &mut TlsState, idx: usize) {
    let held = s.sessions[idx].held_msg_type;
    if held == 0 {
        return;
    }
    let conn_id = s.sessions[idx].conn_id;
    let ok = if held == NET_MSG_CONNECTED {
        let dtag = [s.sessions[idx].downstream_tag];
        tls_write_or_count(s, s.clear_out, held, conn_id, dtag.as_ptr(), 1)
    } else {
        tls_write_or_count(s, s.clear_out, held, conn_id, core::ptr::null(), 0)
    };
    if ok {
        s.sessions[idx].held_msg_type = 0;
    }
}

unsafe fn pump_derive_app_keys(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];
    if let Some((wk, rk)) = pump_derive_app_keys_core(&mut sess.driver) {
        sess.write_keys = wk;
        sess.read_keys = rk;
    }
    // Drop handshake secrets + ECDH private. Shared with DTLS via
    // `zeroize_post_app_keys` — the secret-scrubbing rule is one
    // policy, applied identically across transports.
    zeroize_post_app_keys(&mut sess.driver);
    sess.state = SessionState::Ready;
    dev_log(
        sys,
        3,
        b"[tls] handshake complete".as_ptr(),
        b"[tls] handshake complete".len(),
    );
    emit_peer_identity(s, idx);
    let conn_id = s.sessions[idx].conn_id;
    if s.sessions[idx].held_msg_type != 0 {
        // Forward the held NET_MSG_ACCEPTED / NET_MSG_CONNECTED now that the
        // handshake is complete. Clear the latch ONLY if the write lands — a
        // dropped completion is retried per-step (see the Ready-session loop) so
        // the clear-side consumer is never stranded waiting for the accept.
        forward_held_completion(s, idx);
        // Observability: forward IP's trace context to HTTP immediately AFTER
        // the accept, parented under this session's own span id, so HTTP's slot
        // exists when it arrives. Only when IP propagated a trace.
        if s.telemetry_chan >= 0 && s.sessions[idx].trace_ctx_trace != [0u8; 16] {
            let trace = s.sessions[idx].trace_ctx_trace;
            let own = s.sessions[idx].span_id;
            let flags = s.sessions[idx].trace_ctx_flags;
            let sys = &*s.syscalls;
            let mut scratch = [0u8; NET_FRAME_HDR + abi::contracts::net::net_proto::TRACE_CTX_LEN];
            dev_net_send_trace_ctx(
                sys,
                s.clear_out,
                conn_id,
                &trace,
                &own,
                flags,
                scratch.as_mut_ptr(),
                scratch.len(),
            );
        }
    }
    true
}

/// Fluxor-owned wire constants for `MSG_PEER_IDENTITY`. The
/// envelope is a fluxor-graph primitive (foundation/tls emits it,
/// any consumer module — peer_router, RBAC, log, audit — can read
/// it); the format is documented here, not in any downstream
/// consumer's repo. clustor's `peer_router` mirrors these
/// constants but is one valid consumer among many.
///
/// Wire format: `[msg_type:1][payload_len:2 LE]
/// [conn_id:1][replica_id:1=0xFF][verified:1][svid_len:1][svid…]`
/// (payload_len excludes the 3-byte header).
///
/// `verified == 1` iff `svid_len > 0`. `svid` is the SHA-256 of
/// the peer's raw cert subjectPublicKey (always 32 bytes for
/// ECDSA-P-256). A peer with no cert (plaintext / anonymous
/// handshake) gets `verified=0, svid_len=0`.
pub const MSG_PEER_IDENTITY: u8 = 0x5A;
pub const PEER_IDENTITY_REPLICA_UNKNOWN: u8 = 0xFF;
pub const PEER_IDENTITY_HEADER_LEN: usize = 3;
pub const PEER_IDENTITY_FIXED_PAYLOAD_LEN: usize = 4; // conn_id + replica + verified + svid_len
pub const PEER_IDENTITY_MAX_SVID: usize = 32;
pub const PEER_IDENTITY_MAX_TOTAL: usize =
    PEER_IDENTITY_HEADER_LEN + PEER_IDENTITY_FIXED_PAYLOAD_LEN + PEER_IDENTITY_MAX_SVID;

/// Build the `MSG_PEER_IDENTITY` envelope into `out`. Returns the
/// total byte count. Pure formatter — no I/O. Separated from the
/// emit path so the latch/retry logic can re-send byte-identical
/// envelopes across ticks.
pub fn build_peer_identity_envelope(
    conn_id: u8,
    svid: &[u8],
    out: &mut [u8; PEER_IDENTITY_MAX_TOTAL],
) -> usize {
    let svid_len = if svid.len() > PEER_IDENTITY_MAX_SVID {
        PEER_IDENTITY_MAX_SVID
    } else {
        svid.len()
    };
    let verified: u8 = if svid_len > 0 { 1 } else { 0 };
    let payload_len = PEER_IDENTITY_FIXED_PAYLOAD_LEN + svid_len;
    out[0] = MSG_PEER_IDENTITY;
    out[1] = (payload_len & 0xFF) as u8;
    out[2] = ((payload_len >> 8) & 0xFF) as u8;
    out[3] = conn_id;
    out[4] = PEER_IDENTITY_REPLICA_UNKNOWN;
    out[5] = verified;
    out[6] = svid_len as u8;
    if svid_len > 0 {
        out[7..7 + svid_len].copy_from_slice(&svid[..svid_len]);
    }
    PEER_IDENTITY_HEADER_LEN + payload_len
}

/// Build a `MSG_PEER_IDENTITY` envelope for the session and try to
/// write it on the optional `peer_identity` output port. If the
/// channel is full at handshake completion, latch the envelope in
/// `pending_peer_identity` so `service_pending_peer_identity` can
/// retry from `module_step` on subsequent ticks. The contract is
/// at-least-once delivery: downstream consumers may safely receive
/// the same envelope twice (idempotent identity binding).
unsafe fn emit_peer_identity(s: &mut TlsState, idx: usize) {
    if s.peer_identity < 0 {
        return;
    }
    // Hash the peer pubkey into a 32-byte SVID. Plaintext peers
    // (no cert) yield an empty slice → verified=0.
    let pk_len = s.sessions[idx].driver.peer_cert_pubkey_len as usize;
    let mut svid_buf = [0u8; PEER_IDENTITY_MAX_SVID];
    let svid_slice: &[u8] = if pk_len > 0 {
        let digest = sha256(&s.sessions[idx].driver.peer_cert_pubkey[..pk_len]);
        svid_buf.copy_from_slice(&digest);
        &svid_buf[..]
    } else {
        &svid_buf[..0]
    };
    let conn_id = s.sessions[idx].conn_id;
    let mut envelope = [0u8; PEER_IDENTITY_MAX_TOTAL];
    let total = build_peer_identity_envelope(conn_id, svid_slice, &mut envelope);

    // Latch first, then attempt an immediate write. If the write
    // accepts the full envelope we clear the latch in the same
    // pass; otherwise `service_pending_peer_identity` picks it up
    // on the next tick. Latching unconditionally avoids races
    // where another producer fills the channel between our poll
    // and our write.
    {
        let sess = &mut s.sessions[idx];
        sess.pending_peer_identity[..total].copy_from_slice(&envelope[..total]);
        sess.pending_peer_identity_len = total as u8;
    }
    try_drain_pending_peer_identity(s, idx);
}

/// Attempt one write of any pending peer-identity envelope. Used
/// both at handshake completion (via `emit_peer_identity`) and
/// from the module-step sweep when the channel was previously
/// full.
unsafe fn try_drain_pending_peer_identity(s: &mut TlsState, idx: usize) {
    if s.peer_identity < 0 {
        return;
    }
    let len = s.sessions[idx].pending_peer_identity_len as usize;
    if len == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.peer_identity, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return;
    }
    let ptr = s.sessions[idx].pending_peer_identity.as_ptr();
    let written = (sys.channel_write)(s.peer_identity, ptr, len);
    if written == len as i32 {
        s.sessions[idx].pending_peer_identity_len = 0;
    }
    // Partial-write isn't allowed by the channel ABI (writes are
    // atomic-FIFO — accepted wholesale or rejected). On rejection
    // the latch is preserved and we retry next tick.
}

/// Sweep every Ready session and retry latched peer-identity
/// envelopes. Called once per `module_step` after the handshake
/// pump runs. O(MAX_SESSIONS) per tick — fine at MAX_SESSIONS=4.
unsafe fn service_pending_peer_identity(s: &mut TlsState) {
    if s.peer_identity < 0 {
        return;
    }
    let mut i = 0;
    while i < MAX_SESSIONS {
        if s.sessions[i].pending_peer_identity_len > 0 {
            try_drain_pending_peer_identity(s, i);
        }
        i += 1;
    }
}

// ============================================================================
// Client handshake steps
// ============================================================================

unsafe fn pump_send_client_hello(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    let mut random = [0u8; 32];
    dev_csprng_fill(sys, random.as_mut_ptr(), 32);

    let mut session_id = [0u8; 32];
    dev_csprng_fill(sys, session_id.as_mut_ptr(), 32);
    sess.driver.peer_session_id = session_id;
    sess.driver.peer_session_id_len = 32;

    let msg_len = build_client_hello(
        &random,
        &session_id,
        &sess.driver.ecdh_public,
        &mut sess.driver.scratch,
    );

    // Init transcript (will switch if AES-256-GCM selected)
    sess.driver.transcript = Some(Transcript::new(HashAlg::Sha256));
    if let Some(ref mut t) = sess.driver.transcript {
        t.update(&sess.driver.scratch[..msg_len]);
    }

    let mut local = [0u8; SCRATCH_SIZE];
    core::ptr::copy_nonoverlapping(sess.driver.scratch.as_ptr(), local.as_mut_ptr(), msg_len);
    if !driver_write_handshake_message(sess, &local[..msg_len]) {
        return false;
    }
    sess.pending_ccs_client = true; // Middlebox-compat CCS after first ClientHello.
    sess.driver.hs_state = HandshakeState::RecvServerHello;
    true
}

unsafe fn pump_recv_server_hello(s: &mut TlsState, idx: usize) -> bool {
    pump_recv_server_hello_core(&mut s.sessions[idx].driver)
}

unsafe fn pump_recv_encrypted(
    s: &mut TlsState,
    idx: usize,
    expected_type: u8,
    next_state: HandshakeState,
) -> bool {
    match recv_encrypted_handshake(s, idx) {
        Some((data, len, msg_type)) => {
            if msg_type != expected_type {
                s.sessions[idx].state = SessionState::Error;
                return true;
            }
            // Update transcript
            if let Some(ref mut t) = s.sessions[idx].driver.transcript {
                t.update(&data[..len]);
            }
            s.sessions[idx].driver.hs_state = next_state;
            true
        }
        None => false,
    }
}

unsafe fn pump_recv_certificate(s: &mut TlsState, idx: usize) -> bool {
    match recv_encrypted_handshake(s, idx) {
        Some((data, len, msg_type)) => {
            if msg_type != 11 {
                s.sessions[idx].state = SessionState::Error;
                return true;
            }
            if let Some(ref mut t) = s.sessions[idx].driver.transcript {
                t.update(&data[..len]);
            }
            if !extract_peer_cert_key(s, idx, &data[4..len]) {
                s.sessions[idx].state = SessionState::Error;
                return true;
            }
            s.sessions[idx].driver.hs_state = HandshakeState::RecvCertificateVerify;
            true
        }
        None => false,
    }
}

unsafe fn pump_recv_certificate_verify(s: &mut TlsState, idx: usize) -> bool {
    pump_recv_certificate_verify_core(&mut s.sessions[idx].driver)
}

unsafe fn pump_recv_server_finished(s: &mut TlsState, idx: usize) -> bool {
    pump_recv_server_finished_core(&mut s.sessions[idx].driver)
}

unsafe fn pump_send_client_finished(s: &mut TlsState, idx: usize) -> bool {
    pump_send_client_finished_core(&mut s.sessions[idx].driver)
}

// ============================================================================
// Encrypted record helpers — now thin queue facades.
//
// Both functions used to do their own record I/O. Phase A.next moves
// encryption/decryption out into `record_drain_inbound` /
// `record_drain_outbound`, leaving these as queue helpers so the
// existing pump_* callers don't need to be touched.
// ============================================================================

/// Append a complete handshake message (4-byte header + body) to the
/// driver's outbound plaintext queue. The record bridge encrypts and
/// frames it into a CT_APPLICATION_DATA record on the next outbound
/// drain. Caller drops the message on overflow — the next pump tick
/// will retry.
unsafe fn send_encrypted_handshake(s: &mut TlsState, idx: usize, msg: &[u8], msg_len: usize) {
    let sess = &mut s.sessions[idx];
    if !driver_write_handshake_message(sess, &msg[..msg_len]) {
        // Out queue full — drop. The pump_send_* call will be retried
        // by pump_session next tick (it didn't advance hs_state when
        // the queue overflowed, because pump_send_* always advances
        // after this function — we'd need a Result-returning variant
        // to model overflow cleanly. For TLS sessions the queue is
        // sized to fit a full server flight so overflow is unreachable
        // in practice.)
    }
}

/// Drain one complete handshake message from the driver's inbound
/// plaintext queue. Returns (msg_buf, total_len, hs_msg_type) or None
/// if a complete message hasn't arrived yet. The bridge has already
/// decrypted records and stripped record headers; this function is
/// pure queue plumbing.
unsafe fn recv_encrypted_handshake(
    s: &mut TlsState,
    idx: usize,
) -> Option<([u8; SCRATCH_SIZE], usize, u8)> {
    driver_read_handshake_message(&mut s.sessions[idx])
}

/// Send an encrypted alert via cipher_out channel
unsafe fn send_alert(s: &mut TlsState, idx: usize, description: u8) {
    let alert_body = build_alert(description);
    let mut enc_buf = [0u8; 64];
    let (enc_len, conn_id) = {
        let sess = &mut s.sessions[idx];
        let n = encrypt_record(
            sess.driver.suite,
            &mut sess.write_keys,
            CT_ALERT,
            &alert_body,
            &mut enc_buf,
        );
        (n, sess.conn_id)
    };

    let mut rec = [0u8; 69];
    *rec.as_mut_ptr() = CT_APPLICATION_DATA;
    *rec.as_mut_ptr().add(1) = 0x03;
    *rec.as_mut_ptr().add(2) = 0x03;
    *rec.as_mut_ptr().add(3) = (enc_len >> 8) as u8;
    *rec.as_mut_ptr().add(4) = enc_len as u8;
    core::ptr::copy_nonoverlapping(enc_buf.as_ptr(), rec.as_mut_ptr().add(5), enc_len);

    let total = 5 + enc_len;
    // Alerts are advisory (RFC 8446 §6) — best-effort is fine.
    let cipher_chan = s.cipher_out;
    let _ = tls_write_or_count(
        s,
        cipher_chan,
        NET_CMD_SEND,
        conn_id,
        rec.as_ptr(),
        total as u16,
    );
}

// ============================================================================
// Net protocol frame helpers
// ============================================================================

/// Read a net_proto frame header from a channel.
/// Frame format: [msg_type: u8] [len: u16 LE]
/// Returns (msg_type, payload_len). (0, 0) if no complete header.
/// Read net_proto frame header only (type + length). Payload is read
/// separately because TLS needs to route it to the correct session buffer.
unsafe fn tls_read_header(sys: &SyscallTable, chan: i32) -> (u8, u16) {
    let mut hdr = [0u8; 3];
    let n = (sys.channel_read)(chan, hdr.as_mut_ptr(), 3);
    if n < 3 {
        return (0, 0);
    }
    let p = hdr.as_ptr();
    let msg_type = *p;
    let payload_len = (*p.add(1) as u16) | ((*p.add(2) as u16) << 8);
    (msg_type, payload_len)
}

/// Write a net_proto frame with conn_id prefix, atomically.
/// Frame: [msg_type: u8] [len: u16 LE] [conn_id: u8] [data...]
/// len = 1 + data_len (conn_id byte + payload bytes)
/// Assembled in scratch buffer and written in a single channel_write to
/// prevent split-read issues on byte-stream FIFO channels.
#[must_use = "may fail under backpressure; fail the session or use tls_write_or_count for best-effort sends"]
unsafe fn tls_write_frame(
    sys: &SyscallTable,
    chan: i32,
    msg_type: u8,
    conn_id: u8,
    data: *const u8,
    data_len: u16,
    scratch: &mut [u8; NET_SCRATCH_SIZE],
) -> bool {
    let total_payload = 1u16 + data_len; // conn_id + data
    let frame_len = 3 + total_payload as usize;
    if frame_len > NET_SCRATCH_SIZE {
        // Frame larger than the per-write scratch; chunk in the
        // caller. False makes the loss visible.
        return false;
    }
    *scratch.as_mut_ptr() = msg_type;
    *scratch.as_mut_ptr().add(1) = total_payload as u8;
    *scratch.as_mut_ptr().add(2) = (total_payload >> 8) as u8;
    *scratch.as_mut_ptr().add(3) = conn_id;
    if data_len > 0 && !data.is_null() {
        core::ptr::copy_nonoverlapping(data, scratch.as_mut_ptr().add(4), data_len as usize);
    }
    // `channel_write` is atomic-or-nothing: returns frame_len on
    // success, 0 on backpressure. A silent loss would advance the
    // peer's expected AEAD seq into a permanent mismatch — surface it.
    let n = (sys.channel_write)(chan, scratch.as_ptr(), frame_len);
    n as usize == frame_len
}

/// Best-effort `tls_write_frame`: on failure, bumps the periodic
/// `frame_write_dropped` counter and returns false. Use for sends
/// where the peer / HTTP consumer can recover by timeout
/// (close notifications, alerts, CMD_BIND pass-through).
#[allow(clippy::too_many_arguments, reason = "mirrors tls_write_frame")]
unsafe fn tls_write_or_count(
    s: &mut TlsState,
    chan: i32,
    msg_type: u8,
    conn_id: u8,
    data: *const u8,
    data_len: u16,
) -> bool {
    let sys = &*s.syscalls;
    let ok = tls_write_frame(
        sys,
        chan,
        msg_type,
        conn_id,
        data,
        data_len,
        &mut s.net_scratch,
    );
    if !ok {
        s.frame_write_dropped = s.frame_write_dropped.wrapping_add(1);
    }
    ok
}

/// Retain `n` bytes of encrypted record in the session's retransmit buffer.
/// Overflow is ignored — the record has already been emitted, so TCP's ARQ
/// still delivers the stream; only the retransmit fast-path degrades.
unsafe fn retx_push(sess: &mut TlsSession, rec: *const u8, n: u16) {
    let free = RETX_BUF_SIZE - sess.retx_len as usize;
    if (n as usize) <= free {
        core::ptr::copy_nonoverlapping(
            rec,
            sess.retx_buf.as_mut_ptr().add(sess.retx_len as usize),
            n as usize,
        );
        sess.retx_len = sess.retx_len.wrapping_add(n);
    }
}

/// Drop bytes up to `acked_seq` from the session's retransmit buffer.
/// Anchors `retx_base_seq` to `acked_seq - retx_len` on the first ACK for
/// this connection — IP supplies the absolute TCP sequence number.
unsafe fn retx_ack(sess: &mut TlsSession, acked_seq: u32) {
    if !sess.retx_seq_anchored {
        sess.retx_base_seq = acked_seq.wrapping_sub(sess.retx_len as u32);
        sess.retx_seq_anchored = true;
    }
    let delta = acked_seq.wrapping_sub(sess.retx_base_seq);
    if delta == 0 || delta > sess.retx_len as u32 {
        return;
    }
    let d = delta as usize;
    let remain = sess.retx_len as usize - d;
    if remain > 0 {
        core::ptr::copy(
            sess.retx_buf.as_ptr().add(d),
            sess.retx_buf.as_mut_ptr(),
            remain,
        );
    }
    sess.retx_len = remain as u16;
    sess.retx_base_seq = acked_seq;
}

/// Replay retained ciphertext from `from_seq` to end of retx buffer.
unsafe fn retx_replay(s: &mut TlsState, idx: usize, from_seq: u32) {
    let (offset, len) = {
        let sess = &s.sessions[idx];
        if !sess.retx_seq_anchored {
            return;
        }
        let off = from_seq.wrapping_sub(sess.retx_base_seq);
        if off >= sess.retx_len as u32 {
            return;
        }
        (off as usize, sess.retx_len as usize)
    };
    let bytes = len - offset;
    let mut local = [0u8; RETX_BUF_SIZE];
    core::ptr::copy_nonoverlapping(
        s.sessions[idx].retx_buf.as_ptr().add(offset),
        local.as_mut_ptr(),
        bytes,
    );
    let conn_id = s.sessions[idx].conn_id;
    // Best-effort: replaying already-encrypted ciphertext, no
    // AEAD seq to keep in sync. TCP's RTO will retry on drop.
    let _ = tls_write_or_count(
        s,
        s.cipher_out,
        NET_CMD_SEND,
        conn_id,
        local.as_ptr(),
        bytes as u16,
    );
}

/// Write a raw net_proto frame (no conn_id prefix — used for pass-through).
/// Payload must already be in a buffer that can be prepended with a 3-byte
/// header. Uses a stack buffer to assemble atomically.
/// Returns true iff the full frame was written to `chan` (used to gate pending
/// connect state on a successful upstream write).
unsafe fn tls_write_raw_frame(
    sys: &SyscallTable,
    chan: i32,
    msg_type: u8,
    payload: *const u8,
    payload_len: u16,
) -> bool {
    let frame_len = 3 + payload_len as usize;
    let mut frame = [0u8; 256];
    if frame_len > 256 {
        return false;
    }
    frame[0] = msg_type;
    frame[1] = payload_len as u8;
    frame[2] = (payload_len >> 8) as u8;
    if payload_len > 0 && !payload.is_null() {
        core::ptr::copy_nonoverlapping(payload, frame.as_mut_ptr().add(3), payload_len as usize);
    }
    (sys.channel_write)(chan, frame.as_ptr(), frame_len) == frame_len as i32
}

/// Discard bytes from a channel.
unsafe fn tls_discard(sys: &SyscallTable, chan: i32, mut count: usize) {
    let mut discard = [0u8; 64];
    while count > 0 {
        let chunk = if count < 64 { count } else { 64 };
        (sys.channel_read)(chan, discard.as_mut_ptr(), chunk);
        count -= chunk;
    }
}

/// Try to decrypt a complete TLS record from a Ready session's recv_buf
/// and forward the plaintext as MSG_DATA to clear_out.
unsafe fn try_decrypt_forward(s: &mut TlsState, idx: usize) {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    if sess.recv_len < 5 {
        return;
    }

    let rec_type = *sess.recv_buf.as_ptr();
    let rec_len = ((*sess.recv_buf.as_ptr().add(3) as usize) << 8)
        | (*sess.recv_buf.as_ptr().add(4) as usize);
    if sess.recv_len < 5 + rec_len {
        return;
    }

    if rec_type == CT_CHANGE_CIPHER_SPEC {
        // Skip CCS
        let consumed = 5 + rec_len;
        let remain = sess.recv_len - consumed;
        if remain > 0 {
            core::ptr::copy(
                sess.recv_buf.as_ptr().add(consumed),
                sess.recv_buf.as_mut_ptr(),
                remain,
            );
        }
        sess.recv_len = remain;
        return;
    }

    if rec_type != CT_APPLICATION_DATA {
        return;
    }

    // Copy header + ciphertext for decryption
    let mut hdr = [0u8; 5];
    core::ptr::copy_nonoverlapping(sess.recv_buf.as_ptr(), hdr.as_mut_ptr(), 5);
    let mut ct = [0u8; RECV_BUF_SIZE];
    core::ptr::copy_nonoverlapping(sess.recv_buf.as_ptr().add(5), ct.as_mut_ptr(), rec_len);

    // Consume record from recv_buf
    let consumed = 5 + rec_len;
    let remain = sess.recv_len - consumed;
    if remain > 0 {
        core::ptr::copy(
            sess.recv_buf.as_ptr().add(consumed),
            sess.recv_buf.as_mut_ptr(),
            remain,
        );
    }
    sess.recv_len = remain;

    match decrypt_record(
        sess.driver.suite,
        &mut sess.read_keys,
        &hdr,
        &mut ct[..rec_len],
    ) {
        Some((pt_len, inner_type)) => {
            if inner_type == CT_ALERT {
                if pt_len >= 2 && *ct.as_ptr().add(1) == ALERT_CLOSE_NOTIFY {
                    sess.state = SessionState::Closed;
                    let conn_id = sess.conn_id;
                    // Best-effort close notification (sess borrow
                    // prevents tls_write_or_count; count inline).
                    let ok = tls_write_frame(
                        sys,
                        s.clear_out,
                        NET_MSG_CLOSED,
                        conn_id,
                        core::ptr::null(),
                        0,
                        &mut s.net_scratch,
                    );
                    if !ok {
                        s.frame_write_dropped = s.frame_write_dropped.wrapping_add(1);
                    }
                    return;
                }
                sess.state = SessionState::Error;
                return;
            }
            if inner_type == CT_APPLICATION_DATA && pt_len > 0 {
                // Forward decrypted bytes as MSG_DATA. The plaintext
                // isn't retained — a dropped write would silently
                // lose bytes the peer thinks were delivered, so we
                // fail the session.
                let conn_id = sess.conn_id;
                let sent = tls_write_frame(
                    sys,
                    s.clear_out,
                    NET_MSG_DATA,
                    conn_id,
                    ct.as_ptr(),
                    pt_len as u16,
                    &mut s.net_scratch,
                );
                if !sent {
                    s.frame_write_dropped = s.frame_write_dropped.wrapping_add(1);
                    let msg: &[u8] = b"[tls] clear_out full mid-record; session->Error";
                    dev_log(sys, 3, msg.as_ptr(), msg.len());
                    s.sessions[idx].state = SessionState::Error;
                }
            }
        }
        None => {
            sess.state = SessionState::Error;
        }
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");

// ============================================================================
// Test helpers (host-test feature only)
// ============================================================================

#[cfg(feature = "host-test")]
pub mod test_helpers {
    //! Host-side introspection for the harness. Not compiled into PIC firmware.

    use super::{SessionState, TlsState};

    /// Count sessions that are not Idle — i.e. allocated for a connection.
    /// A claimed `MSG_ACCEPTED` / `MSG_CONNECTED` allocates one; an ignored
    /// (foreign-tagged) `MSG_CONNECTED` allocates none.
    ///
    /// # Safety
    /// `state` must point to an initialised `TlsState` (post-`module_new`).
    pub unsafe fn active_session_count(state: *const u8) -> usize {
        let s = &*(state as *const TlsState);
        s.sessions
            .iter()
            .filter(|sess| sess.state != SessionState::Idle)
            .count()
    }

    /// True if some session is bound to `conn_id` (claimed it).
    ///
    /// # Safety
    /// `state` must point to an initialised `TlsState`.
    pub unsafe fn has_session_for_conn(state: *const u8, conn_id: u8) -> bool {
        let s = &*(state as *const TlsState);
        s.sessions
            .iter()
            .any(|sess| sess.state != SessionState::Idle && sess.conn_id == conn_id)
    }
}
