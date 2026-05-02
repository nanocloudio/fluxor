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
//! - [`streams`](streams.rs) — bidirectional/unidirectional stream slot
//!   table.
//! - [`keys`](keys.rs) — Initial-keys derivation, AEAD key schedule,
//!   key update next-phase derivation (RFC 9001 §5–§6).
//! - [`pump`](pump.rs) — handshake state pump driving the shared
//!   `HandshakeDriver` across Initial / Handshake / 1-RTT levels.
//! - [`qpack`](qpack.rs) — QPACK encoder/decoder with the full
//!   RFC 7541 Appendix B Huffman alphabet (RFC 9204).
//! - [`h3`](h3.rs) — HTTP/3 frame layer + control-stream SETTINGS /
//!   GOAWAY / PRIORITY_UPDATE (RFC 9114, RFC 9218).
//! - [`ws`](ws.rs) — WebSocket frame codec, UTF-8 streaming validation,
//!   permessage-deflate (full RFC 1951 / RFC 6455 / RFC 7692 / RFC 9220).

#![no_std]
#![no_main]

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");
include!("../../sdk/varint.rs");

// Crypto primitives (also used by tls/dtls modules — duplicated PIC
// inclusion is the convention since each module compiles standalone).
include!("../../sdk/sha256.rs");
include!("../../sdk/sha384.rs");
include!("../../sdk/hmac.rs");
include!("../../sdk/aes_gcm.rs");
include!("../../sdk/chacha20.rs");
include!("../../sdk/p256.rs");

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
include!("streams.rs");
include!("keys.rs");
include!("connection.rs");
include!("wire.rs");
include!("qpack.rs");
include!("h3.rs");
include!("ws.rs");
include!("pump.rs");

const MAX_CONNS: usize = 2;
const MAX_CERT_LEN: usize = 1024;
const MAX_KEY_LEN: usize = 160;
const NET_BUF_SIZE: usize = 1600;
const MAX_TICKETS: usize = 4;

/// Server-side ticket cache entry. Stores the resumption_master_secret
/// the server gave the client plus a fresh ticket nonce. On resumption
/// the server looks up by the `psk_identity` the client echoes back.
///
/// Tickets are single-use as a 0-RTT replay defense (RFC 8446 §8 +
/// RFC 9001 §9.2): the first successful resumption sets `consumed`
/// and any later attempt with the same identity is rejected.
#[repr(C)]
#[derive(Clone, Copy)]
struct ServerTicketEntry {
    used: bool,
    consumed: bool,
    /// Opaque PSK identity the client echoes back; we use this index
    /// (encoded as 4 BE bytes) plus a 16-byte random tag for unguessability.
    /// Layout: [u32 BE: index][u8;16: random_tag] = 20 bytes.
    identity: [u8; 20],
    /// Resumption master secret (TLS 1.3 §7.1, hash_len bytes).
    rms: [u8; 48],
    rms_len: u8,
    /// Cipher suite the original handshake negotiated.
    suite_id: u16,
    /// Issue time in millis (for expiry / ticket_age_add).
    issue_ms: u64,
    /// Random additive added to the ticket_age (RFC 8446 §4.6.1).
    ticket_age_add: u32,
    /// Lifetime in seconds.
    lifetime_s: u32,
}

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
    ticket: [u8; 32],
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
struct QuicState {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,
    app_in: i32,
    app_out: i32,
    listen_ep: i16,
    port: u16,
    mode: u8,           // 0 = client, 1 = server
    peer_ip: u32,       // client mode: peer IPv4 (LE)
    peer_port: u16,     // client mode: peer port
    bound: bool,
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
    /// HTTP/3 mode (RFC 9114 / RFC 9204): 0 = transparent stream echo,
    /// 1 = h3 framing on bidi stream 0. The server dispatches HEADERS
    /// frames as HTTP requests and emits HEADERS+DATA responses; the
    /// client emits a `GET /` after the handshake and logs the
    /// decoded `:status` and body.
    enable_h3: u8,
    /// WebSocket-over-HTTP/3 (RFC 9220). Requires `enable_h3 = 1`.
    /// Client: emits an extended CONNECT (`:method = CONNECT`,
    /// `:protocol = websocket`) instead of GET. Server: accepts
    /// extended CONNECT with 200 + interprets DATA frame payloads as
    /// WS frames, echoing TEXT uppercase.
    enable_ws: u8,
    /// Client-side: when `enable_h3 = 1` and this flag is set, emit a
    /// second `GET /two` request on bidi stream id 4 alongside the
    /// `GET /` on stream id 0. Both requests round-trip via the
    /// `bidi_extra_streams` pool.
    enable_concurrent_bidi: u8,
    /// Server: HMAC key for retry tokens. Generated at boot.
    retry_secret: [u8; 32],
    /// Server: key for ticket encryption. Generated at boot;
    /// production deployments rotate periodically.
    ticket_secret: [u8; 32],
    /// Server-side ticket cache.
    server_tickets: [ServerTicketEntry; MAX_TICKETS],
    server_ticket_next: u32,
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

    7, enable_h3, u8, 0
        => |s, d, len| { s.enable_h3 = p_u8(d, len, 0, 0); };

    8, enable_ws, u8, 0
        => |s, d, len| { s.enable_ws = p_u8(d, len, 0, 0); };

    10, enable_concurrent_bidi, u8, 0
        => |s, d, len| { s.enable_concurrent_bidi = p_u8(d, len, 0, 0); };

    9, verify_peer, u8, 0
        => |s, d, len| { s.verify_peer = p_u8(d, len, 0, 0); };
}

#[no_mangle]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<QuicState>() as u32
}

#[no_mangle]
pub extern "C" fn module_arena_size() -> u32 {
    65536
}

#[no_mangle]
pub extern "C" fn module_init(_syscalls: *const core::ffi::c_void) {}

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
    let s = &mut *(state as *mut QuicState);
    s.syscalls = syscalls;
    s.cert_len = 0;
    s.key_len = 0;
    s.listen_ep = -1;
    s.port = 4443;
    s.mode = 1;
    s.peer_ip = 0x0100007f;
    s.peer_port = 4443;
    s.bound = false;
    s.client_started = false;
    s.require_retry = 0;
    s.enable_0rtt = 0;
    s.enable_h3 = 0;
    s.enable_ws = 0;
    s.enable_concurrent_bidi = 0;
    s.verify_peer = 0;
    s.trust_cert_len = 0;
    s.verify_hostname_len = 0;
    s.verify_peer = 0;
    s.trust_cert_len = 0;
    s.verify_hostname_len = 0;
    s.server_ticket_next = 0;
    s.pending_resumption_test = false;
    let mut t = 0;
    while t < MAX_TICKETS {
        s.server_tickets[t] = ServerTicketEntry {
            used: false,
            consumed: false,
            identity: [0; 20],
            rms: [0; 48],
            rms_len: 0,
            suite_id: 0,
            issue_ms: 0,
            ticket_age_add: 0,
            lifetime_s: 0,
        };
        s.client_tickets[t] = ClientTicketEntry {
            used: false,
            peer_ip: [0; 4],
            peer_port: 0,
            ticket: [0; 32],
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

    // Initialise per-server retry + ticket secrets from the CSPRNG.
    if dev_csprng_fill(sys, s.retry_secret.as_mut_ptr(), 32) < 0 {
        return -1;
    }
    if dev_csprng_fill(sys, s.ticket_secret.as_mut_ptr(), 32) < 0 {
        return -1;
    }

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
    if qpack_huffman_self_check() {
        dev_log(
            sys,
            3,
            b"[quic] QPACK Huffman OK".as_ptr(),
            b"[quic] QPACK Huffman OK".len(),
        );
    } else {
        dev_log(
            sys,
            2,
            b"[quic] QPACK Huffman MISMATCH".as_ptr(),
            b"[quic] QPACK Huffman MISMATCH".len(),
        );
    }
    if pmd_decode_self_check() {
        dev_log(
            sys,
            3,
            b"[quic] DEFLATE OK".as_ptr(),
            b"[quic] DEFLATE OK".len(),
        );
    } else {
        dev_log(
            sys,
            2,
            b"[quic] DEFLATE MISMATCH".as_ptr(),
            b"[quic] DEFLATE MISMATCH".len(),
        );
    }
    0
}

/// Decode known-good RFC 7541 Appendix B Huffman vectors at
/// module-init to catch table transcription errors.
fn qpack_huffman_self_check() -> bool {
    const CASES: &[(&[u8], &[u8])] = &[
        (&[0xc5, 0x83, 0x7f], b"GET"),
        (&[0x63], b"/"),
        (&[0x60, 0xd5, 0x48, 0x5f, 0x2b, 0xce, 0x9a, 0x68], b"/index.html"),
        (&[0xb9, 0x49, 0x53, 0x39, 0xe4], b":method"),
        (&[0xb9, 0x58, 0xd3, 0x3f], b":path"),
        (&[0x9c, 0xb4, 0x50, 0x75, 0x3c, 0x1e, 0xca, 0x24], b"hello world"),
        (&[0x49, 0x7c, 0xa5, 0x8a, 0xe8, 0x19, 0xaa], b"text/plain"),
        (&[0xa0, 0xe4, 0x1d, 0x13, 0x9d, 0x09], b"localhost"),
        (&[0xf0, 0x58, 0xd0, 0x72, 0x75, 0x2a, 0x7f], b"websocket"),
    ];
    let mut buf = [0u8; 64];
    let mut i = 0;
    while i < CASES.len() {
        let (enc, want) = CASES[i];
        let n = match qpack_huffman_decode(enc, &mut buf) {
            Some(n) => n,
            None => return false,
        };
        if n != want.len() {
            return false;
        }
        let mut k = 0;
        while k < n {
            if buf[k] != want[k] {
                return false;
            }
            k += 1;
        }
        i += 1;
    }
    true
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
    hmac(HashAlg::Sha256, &s.retry_secret, &token[..body_len], &mut tag);
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
        let ext = tag == 10 || tag == 11 || tag == 12 || tag == 13;
        if ext && pos + 4 <= params_len && data[pos + 1] == 0x00 {
            let len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
            let start = pos + 4;
            if start + len > params_len {
                break;
            }
            match tag {
                10 => {
                    let n = if len < MAX_CERT_LEN { len } else { MAX_CERT_LEN };
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr().add(start),
                        s.cert.as_mut_ptr(),
                        n,
                    );
                    s.cert_len = n;
                }
                11 => {
                    let n = if len < MAX_KEY_LEN { len } else { MAX_KEY_LEN };
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr().add(start),
                        s.key.as_mut_ptr(),
                        n,
                    );
                    s.key_len = n;
                }
                12 => {
                    let n = if len < MAX_CERT_LEN { len } else { MAX_CERT_LEN };
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
                _ => {}
            }
            pos = start + len;
        } else {
            pos += 1;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn module_step(state: *mut u8) -> i32 {
    let s = &mut *(state as *mut QuicState);
    let sys = &*s.syscalls;

    if !s.bound {
        send_bind(s);
        s.bound = true;
        return 1;
    }

    // Client mode: kick off the handshake by allocating a connection,
    // queueing a ClientHello in driver.out_buf, and emitting the
    // first Initial packet.
    if s.mode == 0 && !s.client_started && s.listen_ep >= 0 {
        let ip_bytes = s.peer_ip.to_le_bytes();
        let ip = [ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]];
        if let Some(idx) = alloc_client_connection(s, &ip, s.peer_port) {
            // Drive far enough to get the ClientHello queued.
            let mut steps = 0;
            while steps < 64 && s.conns[idx].phase == ConnPhase::Handshaking {
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
            while steps < 64 && s.conns[i].phase == ConnPhase::Handshaking {
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
                        if bound_port == s.port && s.listen_ep < 0 {
                            s.listen_ep = buf[0] as i16;
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
                                } else if 1 + 8 <= peek_len {
                                    dcid_len = 8;
                                    dcid_buf[..8].copy_from_slice(&peek[1..9]);
                                }
                            }
                            let mut idx = if dcid_len > 0 {
                                find_conn_by_dcid(s, &dcid_buf[..dcid_len])
                            } else {
                                -1
                            };
                            if idx < 0 {
                                if let Some(new) = alloc_server_connection(s, &ip, port) {
                                    idx = new as i32;
                                } else {
                                    let mc = find_conn(s, &ip, port);
                                    if mc >= 0 {
                                        idx = mc;
                                    }
                                }
                            }
                            if idx >= 0 {
                                let conn = &mut s.conns[idx as usize];
                                let take_peek =
                                    if peek_len <= QUIC_DGRAM_MAX { peek_len } else { QUIC_DGRAM_MAX };
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
            while steps < 64 && s.conns[i].phase == ConnPhase::Handshaking {
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
        if s.conns[i].phase == ConnPhase::Handshaking
            || s.conns[i].phase == ConnPhase::Established
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
        }
        i += 1;
    }

    // Client-side 0-RTT resumption: once the first connection is
    // Established and a ticket is cached, open a second handshake on a
    // free slot using that ticket so the PSK + early_data path runs
    // end-to-end in a single fluxor process.
    if s.mode == 0 && s.enable_0rtt != 0 && s.listen_ep >= 0 {
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
                while steps < 64 && s.conns[idx].phase == ConnPhase::Handshaking {
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
        if !s.conns[i].is_server
            && s.conns[i].session_ticket_handled
            && s.conns[i].psk_len > 0
        {
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
                            ticket: [0; 32],
                            ticket_len: psk_id_len as u8,
                            rms: [0; 48],
                            rms_len: s.conns[i].psk_len,
                            suite_id: 0x1303,
                            issue_ms: dev_millis(sys),
                            ticket_age_add: 0,
                            lifetime_s: 7200,
                        };
                        let n = psk_id_len.min(entry.ticket.len());
                        entry.ticket[..n].copy_from_slice(
                            &s.conns[i].psk_identity[..n],
                        );
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
    while i < MAX_CONNS {
        if s.conns[i].phase == ConnPhase::Established {
            // HTTP/3: ensure the three required uni streams (control,
            // qpack-enc, qpack-dec) are open with their type prefix +
            // SETTINGS frame on control, before any other emission.
            if s.enable_h3 != 0 && !s.conns[i].h3_uni_streams_opened {
                h3_open_uni_streams(s, i);
            }
            // Inbound 1-RTT packets.
            if s.conns[i].inbound_len > 0 {
                let _ = drain_inbound_one(s, i);
            }
            // HTTP/3: drain any peer-initiated unidirectional streams
            // (control + qpack-enc + qpack-dec) + the bidi pool used
            // for additional concurrent request streams.
            if s.enable_h3 != 0 {
                h3_pump_extra_streams(s, i);
                h3_handle_bidi_extra_recv(s, i);
            }
            // Forward inbound stream bytes to clear_out.
            if s.conns[i].stream_recv_buf_len > 0 {
                let n = s.conns[i].stream_recv_buf_len;
                if s.enable_h3 != 0 {
                    // HTTP/3 framing on stream 0. Server: parse a
                    // HEADERS frame + emit response; client: log.
                    h3_handle_stream_recv(s, i);
                } else {
                    // Legacy echo / log behaviour.
                    let mut log_buf = [0u8; 96];
                    let prefix = b"[quic] stream rx=";
                    let mut p = 0;
                    for &c in prefix { log_buf[p] = c; p += 1; }
                    let copy_n = n.min(log_buf.len() - p);
                    core::ptr::copy_nonoverlapping(
                        s.conns[i].stream_recv_buf.as_ptr(),
                        log_buf.as_mut_ptr().add(p),
                        copy_n,
                    );
                    p += copy_n;
                    dev_log(sys, 3, log_buf.as_ptr(), p);
                    // Echo path on the server: forward inbound bytes to
                    // stream_send_buf so they round-trip back to the client.
                    if s.conns[i].is_server {
                        let conn = &mut s.conns[i];
                        let space = conn.stream_send_buf.len() - conn.stream_send_buf_len;
                        let to_copy = n.min(space);
                        core::ptr::copy_nonoverlapping(
                            conn.stream_recv_buf.as_ptr(),
                            conn.stream_send_buf.as_mut_ptr().add(conn.stream_send_buf_len),
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
                                s.conns[i].stream_recv_buf.as_ptr(),
                                frame.as_mut_ptr().add(3),
                                n,
                            );
                            (sys.channel_write)(s.app_out, frame.as_ptr(), 3 + n);
                        }
                    }
                    s.conns[i].stream_recv_buf_len = 0;
                }
            }
            // Client-side auto-test (transparent path only).
            if s.enable_h3 == 0
                && !s.conns[i].is_server
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
            // HTTP/3 client: emit `GET /` once the handshake completes.
            if s.enable_h3 != 0
                && !s.conns[i].is_server
                && !s.conns[i].test_sent
                && s.conns[i].stream_send_off == 0
                && s.conns[i].stream_send_buf_len == 0
            {
                h3_emit_client_request(s, i);
                s.conns[i].test_sent = true;
                if s.enable_concurrent_bidi != 0 && !s.conns[i].concurrent_bidi_sent {
                    h3_emit_concurrent_bidi_request(s, i);
                    s.conns[i].concurrent_bidi_sent = true;
                }
            }
            // WS-on-h3 client: once the server's 200 flips us into
            // ws_mode, send one TEXT frame and log the echo.
            if s.enable_ws != 0
                && !s.conns[i].is_server
                && s.conns[i].ws_mode
                && !s.conns[i].ws_test_sent
            {
                let payload = b"hello ws";
                h3_ws_send(s, i, WS_OPCODE_TEXT, payload);
                s.conns[i].ws_test_sent = true;
            }
            // Read clear_in into stream_send_buf (when wired).
            if s.app_in >= 0 {
                let poll = (sys.channel_poll)(s.app_in, POLL_IN);
                if poll > 0 && (poll as u32 & POLL_IN) != 0 {
                    let mut tmp = [0u8; 1024];
                    let r = (sys.channel_read)(s.app_in, tmp.as_mut_ptr(), tmp.len());
                    if r > 0 {
                        let conn = &mut s.conns[i];
                        let space = conn.stream_send_buf.len() - conn.stream_send_buf_len;
                        let n = (r as usize).min(space);
                        core::ptr::copy_nonoverlapping(
                            tmp.as_ptr(),
                            conn.stream_send_buf.as_mut_ptr().add(conn.stream_send_buf_len),
                            n,
                        );
                        conn.stream_send_buf_len += n;
                    }
                }
            }
            // Emit any pending outbound stream data / ACKs.
            drain_outbound(s, i);
        }
        i += 1;
    }

    1
}

#[no_mangle]
pub unsafe extern "C" fn module_destroy(_state: *mut u8) {}

unsafe fn discard_bytes(sys: &SyscallTable, ch: i32, mut count: usize) {
    let mut buf = [0u8; 64];
    while count > 0 {
        let take = if count < 64 { count } else { 64 };
        (sys.channel_read)(ch, buf.as_mut_ptr(), take);
        count -= take;
    }
}

unsafe fn send_bind(s: &mut QuicState) {
    let sys = &*s.syscalls;
    // CMD_DG_BIND payload (modules/sdk/contracts/net/datagram.rs):
    //   [port: u16 LE] [flags: u8].
    let payload: [u8; 3] = [
        (s.port & 0xFF) as u8,
        (s.port >> 8) as u8,
        0,
    ];
    let frame_len = 3 + payload.len();
    let mut frame = [0u8; 8];
    frame[0] = DG_CMD_BIND;
    frame[1] = payload.len() as u8;
    frame[2] = (payload.len() >> 8) as u8;
    let mut i = 0;
    while i < payload.len() {
        frame[3 + i] = payload[i];
        i += 1;
    }
    (sys.channel_write)(s.net_out, frame.as_ptr(), frame_len);
}

unsafe fn send_datagram(
    sys: &SyscallTable,
    net_out: i32,
    ep: i16,
    peer: &PeerAddr,
    bytes: &[u8],
    scratch: &mut [u8; NET_BUF_SIZE],
) {
    if ep < 0 {
        return;
    }
    // CMD_DG_SEND_TO IPv4 (datagram contract):
    //   [ep_id:1][af:1=4][addr:4 BE][port:2 LE][data].
    let payload_len = 1 + 1 + 4 + 2 + bytes.len();
    let frame_len = 3 + payload_len;
    if frame_len > scratch.len() {
        return;
    }
    scratch[0] = DG_CMD_SEND_TO;
    scratch[1] = payload_len as u8;
    scratch[2] = (payload_len >> 8) as u8;
    scratch[3] = ep as u8;
    scratch[4] = DG_AF_INET;
    scratch[5] = peer.ip[0];
    scratch[6] = peer.ip[1];
    scratch[7] = peer.ip[2];
    scratch[8] = peer.ip[3];
    scratch[9] = (peer.port & 0xFF) as u8;
    scratch[10] = (peer.port >> 8) as u8;
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), scratch.as_mut_ptr().add(11), bytes.len());
    (sys.channel_write)(net_out, scratch.as_ptr(), frame_len);
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
        }
        i += 1;
    }
    -1
}

unsafe fn alloc_server_connection(
    s: &mut QuicState,
    ip: &[u8; 4],
    port: u16,
) -> Option<usize> {
    let mut i = 0;
    while i < MAX_CONNS {
        if s.conns[i].phase == ConnPhase::Idle {
            let conn = &mut s.conns[i];
            conn.reset();
            conn.peer.ip = *ip;
            conn.peer.port = port;
            conn.phase = ConnPhase::Handshaking;
            conn.is_server = true;
            conn.driver.is_server = true;
            conn.driver.hs_state = HandshakeState::RecvClientHello;
            conn.driver.suite = CipherSuite::ChaCha20Poly1305;

            // Pick our SCID (random 8 bytes).
            let sys = &*s.syscalls;
            dev_csprng_fill(sys, conn.our_cid.as_mut_ptr(), 8);
            conn.our_cid_len = 8;

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
unsafe fn alloc_resumption_connection(
    s: &mut QuicState,
    ip: &[u8; 4],
    port: u16,
) -> Option<usize> {
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
            conn.driver.hs_state = HandshakeState::SendClientHello;
            conn.driver.suite = CipherSuite::ChaCha20Poly1305;
            // Pick fresh CIDs.
            let sys = &*s.syscalls;
            dev_csprng_fill(sys, conn.our_cid.as_mut_ptr(), 8);
            conn.our_cid_len = 8;
            dev_csprng_fill(sys, conn.peer_cid.as_mut_ptr(), 8);
            conn.peer_cid_len = 8;
            conn.original_dcid[..8].copy_from_slice(&conn.peer_cid[..8]);
            conn.original_dcid_len = 8;
            // Install Initial keys from the original DCID.
            let mut dcid_copy = [0u8; MAX_CID_LEN];
            core::ptr::copy_nonoverlapping(
                conn.peer_cid.as_ptr(),
                dcid_copy.as_mut_ptr(),
                8,
            );
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

unsafe fn alloc_client_connection(
    s: &mut QuicState,
    ip: &[u8; 4],
    port: u16,
) -> Option<usize> {
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
            conn.driver.hs_state = HandshakeState::SendClientHello;
            conn.driver.suite = CipherSuite::ChaCha20Poly1305;

            // Client picks BOTH connection IDs initially:
            //   our_cid (SCID we send) — random
            //   peer_cid placeholder (DCID we send) — also random; this
            //     becomes the server-side "original DCID" used to derive
            //     Initial keys on both sides.
            let sys = &*s.syscalls;
            dev_csprng_fill(sys, conn.our_cid.as_mut_ptr(), 8);
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
            core::ptr::copy_nonoverlapping(
                conn.peer_cid.as_ptr(),
                dcid_copy.as_mut_ptr(),
                n,
            );
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

// ---------------------------------------------------------------------
// HTTP/3 dispatcher. Lives in mod.rs because it accesses QuicState
// directly; framing + QPACK helpers are in h3.rs / qpack.rs.
// ---------------------------------------------------------------------

/// On a fresh Established h3 connection, open the three required
/// HTTP/3 unidirectional streams (RFC 9114 §6.2.1 + RFC 9204 §4.2):
///   - control stream: type 0x00 + SETTINGS frame
///   - QPACK encoder stream: type 0x02 (no instructions)
///   - QPACK decoder stream: type 0x03 (no instructions)
/// Stream IDs follow the QUIC initiator-direction encoding (RFC 9000
/// §2.1): server uni = 3, 7, 11; client uni = 2, 6, 10.
unsafe fn h3_open_uni_streams(s: &mut QuicState, idx: usize) {
    if s.conns[idx].h3_uni_streams_opened {
        return;
    }
    let is_server = s.conns[idx].is_server;
    // Allocate three slots: control / qpack-enc / qpack-dec.
    let mut alloc_one =
        |conn: &mut QuicConnection, role: H3StreamRole, type_byte: u64| -> bool {
            let id = if is_server {
                next_server_uni_id(conn.h3_next_uni_idx)
            } else {
                next_client_uni_id(conn.h3_next_uni_idx)
            };
            conn.h3_next_uni_idx = conn.h3_next_uni_idx.wrapping_add(1);
            let slot_idx = match extra_alloc(conn, id, true) {
                Some(i) => i,
                None => return false,
            };
            conn.extra_streams[slot_idx].h3_role = role;
            // Prime the type byte.
            let mut tmp = [0u8; 4];
            let n = varint_encode(tmp.as_mut_ptr(), tmp.len(), type_byte);
            conn.extra_streams[slot_idx].send_buf[..n].copy_from_slice(&tmp[..n]);
            conn.extra_streams[slot_idx].send_buf_len = n;
            true
        };
    {
        let conn = &mut s.conns[idx];
        if !alloc_one(conn, H3StreamRole::Control, H3_UNI_TYPE_CONTROL) {
            return;
        }
        if !alloc_one(conn, H3StreamRole::QpackEncoder, H3_UNI_TYPE_QPACK_ENCODER) {
            return;
        }
        if !alloc_one(conn, H3StreamRole::QpackDecoder, H3_UNI_TYPE_QPACK_DECODER) {
            return;
        }
    }
    // Append SETTINGS frame to the control-stream send buffer.
    h3_emit_settings(s, idx);
    s.conns[idx].h3_uni_streams_opened = true;
}

/// Build SETTINGS frame + append to the control stream slot's
/// send_buf. Both sides emit SETTINGS as the first frame on their
/// control stream (RFC 9114 §7.2.4).
unsafe fn h3_emit_settings(s: &mut QuicState, idx: usize) {
    // Find the control stream slot.
    let mut control_slot = MAX_EXTRA_STREAMS;
    let mut k = 0;
    while k < MAX_EXTRA_STREAMS {
        if s.conns[idx].extra_streams[k].allocated
            && s.conns[idx].extra_streams[k].h3_role == H3StreamRole::Control
            && s.conns[idx].extra_streams[k].locally_initiated
        {
            control_slot = k;
            break;
        }
        k += 1;
    }
    if control_slot == MAX_EXTRA_STREAMS {
        return;
    }
    // SETTINGS payload: QPACK_MAX_TABLE_CAPACITY=0,
    // MAX_FIELD_SECTION_SIZE=16384, QPACK_BLOCKED_STREAMS=0,
    // ENABLE_CONNECT_PROTOCOL=1 (server only — clients SHOULD NOT
    // send this per RFC 9220 §3, but we send it as advisory; servers
    // use it to negotiate WS).
    let settings_pairs: &[(u64, u64)] = if s.conns[idx].is_server {
        &[
            (H3_SETTING_QPACK_MAX_TABLE_CAPACITY, 0),
            (H3_SETTING_MAX_FIELD_SECTION_SIZE, 16384),
            (H3_SETTING_QPACK_BLOCKED_STREAMS, 0),
            (H3_SETTING_ENABLE_CONNECT_PROTOCOL, 1),
        ]
    } else {
        &[
            (H3_SETTING_QPACK_MAX_TABLE_CAPACITY, 0),
            (H3_SETTING_MAX_FIELD_SECTION_SIZE, 16384),
            (H3_SETTING_QPACK_BLOCKED_STREAMS, 0),
        ]
    };
    let mut payload = [0u8; 64];
    let n = h3_build_settings_payload(settings_pairs, &mut payload);
    if n == 0 {
        return;
    }
    // Wrap as SETTINGS frame.
    let mut frame_hdr = [0u8; 4];
    let hdr_n = h3_build_frame_header(H3_FRAME_SETTINGS, n, &mut frame_hdr);
    if hdr_n == 0 {
        return;
    }
    let slot = &mut s.conns[idx].extra_streams[control_slot];
    let space = slot.send_buf.len() - slot.send_buf_len;
    if hdr_n + n > space {
        return;
    }
    slot.send_buf[slot.send_buf_len..slot.send_buf_len + hdr_n]
        .copy_from_slice(&frame_hdr[..hdr_n]);
    slot.send_buf_len += hdr_n;
    slot.send_buf[slot.send_buf_len..slot.send_buf_len + n].copy_from_slice(&payload[..n]);
    slot.send_buf_len += n;
}

/// Walk every recv'd extra_stream slot. Classify uni streams by type
/// byte (consume the leading varint on first observation), then
/// dispatch frames appropriately:
///   control stream → SETTINGS (mandatory first), GOAWAY, MAX_PUSH_ID
///   qpack-encoder  → table-update instructions (we drop them since
///                    QPACK_MAX_TABLE_CAPACITY=0; peer SHOULD NOT
///                    send any)
///   qpack-decoder  → ack/cancel instructions (likewise empty)
unsafe fn h3_pump_extra_streams(s: &mut QuicState, idx: usize) {
    let sys = &*s.syscalls;
    let mut k = 0;
    while k < MAX_EXTRA_STREAMS {
        if !s.conns[idx].extra_streams[k].allocated
            || s.conns[idx].extra_streams[k].locally_initiated
            || s.conns[idx].extra_streams[k].recv_buf_len == 0
        {
            k += 1;
            continue;
        }
        // Classify by type byte if not already.
        if !s.conns[idx].extra_streams[k].h3_type_consumed {
            let slot = &s.conns[idx].extra_streams[k];
            let (stype, n) = match varint_decode(
                slot.recv_buf.as_ptr(),
                slot.recv_buf_len,
            ) {
                Some(t) => t,
                None => {
                    k += 1;
                    continue;
                }
            };
            let role = match stype {
                x if x == H3_UNI_TYPE_CONTROL => H3StreamRole::Control,
                x if x == H3_UNI_TYPE_PUSH => H3StreamRole::Push,
                x if x == H3_UNI_TYPE_QPACK_ENCODER => H3StreamRole::QpackEncoder,
                x if x == H3_UNI_TYPE_QPACK_DECODER => H3StreamRole::QpackDecoder,
                _ => H3StreamRole::Unknown,
            };
            let slot = &mut s.conns[idx].extra_streams[k];
            slot.h3_role = role;
            slot.h3_type_consumed = true;
            // Drop the type byte.
            let remain = slot.recv_buf_len - n;
            if remain > 0 {
                core::ptr::copy(
                    slot.recv_buf.as_ptr().add(n),
                    slot.recv_buf.as_mut_ptr(),
                    remain,
                );
            }
            slot.recv_buf_len = remain;
        }
        let role = s.conns[idx].extra_streams[k].h3_role;
        match role {
            H3StreamRole::Control => h3_drain_control_stream(s, idx, k),
            H3StreamRole::QpackEncoder | H3StreamRole::QpackDecoder => {
                // We advertise QPACK_MAX_TABLE_CAPACITY=0, so peer
                // dynamic-table updates would be a protocol error.
                s.conns[idx].extra_streams[k].recv_buf_len = 0;
            }
            _ => {
                s.conns[idx].extra_streams[k].recv_buf_len = 0;
            }
        }
        let _ = sys;
        k += 1;
    }
}

/// Drain a peer control stream slot: parse SETTINGS / GOAWAY /
/// MAX_PUSH_ID frames. Bytes are consumed in-place (shifted out of
/// the recv_buf) once a complete frame is processed.
unsafe fn h3_drain_control_stream(s: &mut QuicState, idx: usize, slot_idx: usize) {
    let sys = &*s.syscalls;
    loop {
        let buf_len = s.conns[idx].extra_streams[slot_idx].recv_buf_len;
        if buf_len == 0 {
            return;
        }
        let mut local = [0u8; 256];
        let take = buf_len.min(local.len());
        core::ptr::copy_nonoverlapping(
            s.conns[idx].extra_streams[slot_idx].recv_buf.as_ptr(),
            local.as_mut_ptr(),
            take,
        );
        let (frame, consumed) = match h3_parse_frame(&local[..take]) {
            Some(f) => f,
            None => return,
        };
        match frame.frame_type {
            x if x == H3_FRAME_SETTINGS => {
                let mut enable_connect = false;
                {
                    // Inline-parse without the closure path (the dyn
                    // FnMut indirection seemed to inhibit the log).
                    let payload = frame.payload;
                    let mut pos = 0;
                    while pos < payload.len() {
                        let after = &payload[pos..];
                        let (id, n1) = match varint_decode(after.as_ptr(), after.len()) {
                            Some(t) => t,
                            None => break,
                        };
                        pos += n1;
                        let after = &payload[pos..];
                        let (val, n2) = match varint_decode(after.as_ptr(), after.len()) {
                            Some(t) => t,
                            None => break,
                        };
                        pos += n2;
                        if id == H3_SETTING_ENABLE_CONNECT_PROTOCOL && val == 1 {
                            enable_connect = true;
                        }
                    }
                }
                s.conns[idx].h3_peer_settings_seen = true;
                if enable_connect {
                    s.conns[idx].h3_peer_enable_connect = true;
                }
            }
            x if x == H3_FRAME_GOAWAY => {
                if let Some(id) = h3_parse_goaway(frame.payload) {
                    let mut log_buf = [0u8; 64];
                    let prefix = b"[quic] h3 GOAWAY id=";
                    let mut p = 0;
                    while p < prefix.len() { log_buf[p] = prefix[p]; p += 1; }
                    // Truncate to u32 for log formatting — avoids
                    // pulling in __aeabi_uldivmod on thumbv8m for
                    // u64 division.
                    let mut v = id.min(u32::MAX as u64) as u32;
                    let mut tmp = [0u8; 12];
                    let mut t = 0;
                    if v == 0 { tmp[0] = b'0'; t = 1; }
                    while v > 0 {
                        tmp[t] = b'0' + ((v % 10) as u8);
                        v /= 10;
                        t += 1;
                    }
                    let mut k = 0;
                    while k < t && p < log_buf.len() {
                        log_buf[p] = tmp[t - 1 - k];
                        p += 1;
                        k += 1;
                    }
                    dev_log(sys, 3, log_buf.as_ptr(), p);
                }
            }
            x if x == H3_FRAME_MAX_PUSH_ID => {
                // Push not supported; accept the cap but no scheduling.
            }
            x if x == H3_FRAME_PRIORITY_UPDATE_REQUEST
                || x == H3_FRAME_PRIORITY_UPDATE_PUSH =>
            {
                // RFC 9218 §7.2: parse + accept. We don't yet honor
                // the urgency field for stream scheduling — the
                // dispatcher emits in arrival order — but the frame
                // is recognised + logged so peers don't see an
                // H3_FRAME_UNEXPECTED protocol error.
                if let Some(p) = h3_parse_priority_update(frame.payload) {
                    let mut log_buf = [0u8; 96];
                    let prefix = b"[quic] h3 PRIORITY_UPDATE id=";
                    let mut pos = 0;
                    while pos < prefix.len() { log_buf[pos] = prefix[pos]; pos += 1; }
                    let mut v = p.prioritized_id.min(u32::MAX as u64) as u32;
                    let mut tmp = [0u8; 12];
                    let mut t = 0;
                    if v == 0 { tmp[0] = b'0'; t = 1; }
                    while v > 0 {
                        tmp[t] = b'0' + ((v % 10) as u8);
                        v /= 10;
                        t += 1;
                    }
                    let mut k = 0;
                    while k < t && pos < log_buf.len() {
                        log_buf[pos] = tmp[t - 1 - k];
                        pos += 1;
                        k += 1;
                    }
                    if pos < log_buf.len() {
                        log_buf[pos] = b' ';
                        pos += 1;
                    }
                    let copy_n = p.field_value.len().min(log_buf.len() - pos);
                    core::ptr::copy_nonoverlapping(
                        p.field_value.as_ptr(),
                        log_buf.as_mut_ptr().add(pos),
                        copy_n,
                    );
                    pos += copy_n;
                    dev_log(sys, 3, log_buf.as_ptr(), pos);
                }
            }
            _ => {
                // RFC 9114 §7.2 forbids DATA/HEADERS and unknown
                // frames on the control stream; we tolerate by
                // skipping rather than aborting the connection.
            }
        }
        // Shift consumed bytes out of recv_buf.
        let slot = &mut s.conns[idx].extra_streams[slot_idx];
        let remain = slot.recv_buf_len - consumed;
        if remain > 0 {
            core::ptr::copy(
                slot.recv_buf.as_ptr().add(consumed),
                slot.recv_buf.as_mut_ptr(),
                remain,
            );
        }
        slot.recv_buf_len = remain;
    }
}

unsafe fn h3_handle_stream_recv(s: &mut QuicState, idx: usize) {
    let sys = &*s.syscalls;
    // Walk inbound buffer for complete H3 frames.
    let n = s.conns[idx].stream_recv_buf_len;
    if n == 0 {
        return;
    }
    // Snapshot the buffer onto the stack so we can mutate the conn
    // (re-borrow as &mut) without overlapping references.
    let mut local = [0u8; 1500];
    let take = n.min(local.len());
    core::ptr::copy_nonoverlapping(
        s.conns[idx].stream_recv_buf.as_ptr(),
        local.as_mut_ptr(),
        take,
    );
    let mut cursor = 0;
    while cursor < take {
        let (frame, consumed) = match h3_parse_frame(&local[cursor..take]) {
            Some(p) => p,
            None => break, // Truncated — wait for more.
        };
        match frame.frame_type {
            x if x == H3_FRAME_HEADERS => {
                if s.conns[idx].is_server {
                    h3_dispatch_request(s, idx, frame.payload);
                } else {
                    if let Some(status) = h3_decode_status(frame.payload) {
                        let mut log_buf = [0u8; 64];
                        let prefix = b"[quic] h3 status=";
                        let mut p = 0;
                        for &c in prefix { log_buf[p] = c; p += 1; }
                        let mut k = 0;
                        while k < status.len() && status[k] != 0 && p < log_buf.len() {
                            log_buf[p] = status[k];
                            p += 1;
                            k += 1;
                        }
                        dev_log(sys, 3, log_buf.as_ptr(), p);
                        // RFC 9220: client transitions into WS mode
                        // when its CONNECT request was accepted with
                        // 200. We requested extended CONNECT iff the
                        // module is in enable_ws mode.
                        if s.enable_ws != 0
                            && status[0] == b'2'
                            && status[1] == b'0'
                            && status[2] == b'0'
                        {
                            s.conns[idx].ws_mode = true;
                        }
                    }
                }
            }
            x if x == H3_FRAME_DATA => {
                if s.conns[idx].ws_mode {
                    // RFC 9220 §3 — the bidi stream's DATA payloads
                    // carry WS frames once the upgrade completes.
                    h3_ws_recv(s, idx, frame.payload);
                } else if s.conns[idx].is_server && s.conns[idx].h3_post_in_progress {
                    // Accumulate POST body bytes. Dispatch on stream FIN
                    // (handled below this match block).
                    let conn = &mut s.conns[idx];
                    let space = conn.h3_post_body.len() - conn.h3_post_body_len;
                    let n = frame.payload.len().min(space);
                    if n > 0 {
                        core::ptr::copy_nonoverlapping(
                            frame.payload.as_ptr(),
                            conn.h3_post_body.as_mut_ptr().add(conn.h3_post_body_len),
                            n,
                        );
                        conn.h3_post_body_len += n;
                    }
                } else {
                    let mut log_buf = [0u8; 96];
                    let prefix: &[u8] = if s.conns[idx].is_server {
                        b"[quic] h3 req body="
                    } else {
                        b"[quic] h3 resp body="
                    };
                    let mut p = 0;
                    for &c in prefix { log_buf[p] = c; p += 1; }
                    let copy_n = frame.payload.len().min(log_buf.len() - p);
                    core::ptr::copy_nonoverlapping(
                        frame.payload.as_ptr(),
                        log_buf.as_mut_ptr().add(p),
                        copy_n,
                    );
                    p += copy_n;
                    dev_log(sys, 3, log_buf.as_ptr(), p);
                }
            }
            _ => {
                // Skip unknown frames (RFC 9114 §9.).
            }
        }
        cursor += consumed;
    }
    // Shift any unconsumed tail to the front of the recv buffer.
    let remain = take - cursor;
    if remain > 0 {
        core::ptr::copy(
            s.conns[idx].stream_recv_buf.as_ptr().add(cursor),
            s.conns[idx].stream_recv_buf.as_mut_ptr(),
            remain,
        );
    }
    s.conns[idx].stream_recv_buf_len = remain;

    // Server-side POST: dispatch once the request stream is
    // FIN-closed (response is 200 + uppercase echo of the body).
    if s.conns[idx].is_server
        && s.conns[idx].h3_post_in_progress
        && !s.conns[idx].h3_post_dispatched
        && s.conns[idx].stream_recv_fin
    {
        h3_dispatch_post_complete(s, idx);
        s.conns[idx].h3_post_dispatched = true;
        s.conns[idx].h3_post_in_progress = false;
    }
}

/// Server: POST request body has fully arrived. Build a 200 response
/// with the body uppercased + echoed.
unsafe fn h3_dispatch_post_complete(s: &mut QuicState, idx: usize) {
    let sys = &*s.syscalls;
    let body_len = s.conns[idx].h3_post_body_len;
    let mut log_buf = [0u8; 96];
    let prefix = b"[quic] h3 POST body=";
    let mut p = 0;
    while p < prefix.len() { log_buf[p] = prefix[p]; p += 1; }
    let copy_n = body_len.min(log_buf.len() - p);
    core::ptr::copy_nonoverlapping(
        s.conns[idx].h3_post_body.as_ptr(),
        log_buf.as_mut_ptr().add(p),
        copy_n,
    );
    p += copy_n;
    dev_log(sys, 3, log_buf.as_ptr(), p);

    // Echo body uppercased.
    let mut up = [0u8; 1024];
    let mut k = 0;
    while k < body_len {
        let b = s.conns[idx].h3_post_body[k];
        up[k] = if b >= b'a' && b <= b'z' { b - 32 } else { b };
        k += 1;
    }
    let mut hdr_block = [0u8; 256];
    let hdr_len = h3_encode_response_headers(b"200", b"text/plain", body_len, &mut hdr_block);
    if hdr_len == 0 {
        return;
    }
    let mut h3_buf = [0u8; 1500];
    let mut q = 0;
    let n = h3_build_frame_header(H3_FRAME_HEADERS, hdr_len, &mut h3_buf[q..]);
    if n == 0 { return; }
    q += n;
    if q + hdr_len > h3_buf.len() { return; }
    h3_buf[q..q + hdr_len].copy_from_slice(&hdr_block[..hdr_len]);
    q += hdr_len;
    let n = h3_build_frame_header(H3_FRAME_DATA, body_len, &mut h3_buf[q..]);
    if n == 0 { return; }
    q += n;
    if q + body_len > h3_buf.len() { return; }
    h3_buf[q..q + body_len].copy_from_slice(&up[..body_len]);
    q += body_len;
    let conn = &mut s.conns[idx];
    let space = conn.stream_send_buf.len() - conn.stream_send_buf_len;
    let to_copy = q.min(space);
    core::ptr::copy_nonoverlapping(
        h3_buf.as_ptr(),
        conn.stream_send_buf.as_mut_ptr().add(conn.stream_send_buf_len),
        to_copy,
    );
    conn.stream_send_buf_len += to_copy;
    conn.stream_send_fin = true;
}

/// Server-side counterpart to `h3_dispatch_request` for a bidi extra
/// slot: routes `path_bytes` to a hardcoded body, encodes the
/// response into the slot's send_buf, and arms FIN so the stream
/// closes after emission.
unsafe fn h3_dispatch_request_bidi(
    s: &mut QuicState,
    idx: usize,
    slot_idx: usize,
    path_bytes: &[u8],
) {
    let sys = &*s.syscalls;
    let (status, body) = if eq_bytes(path_bytes, b"/") {
        (&b"200"[..], &b"hello h3\n"[..])
    } else if eq_bytes(path_bytes, b"/two") {
        (&b"200"[..], &b"hello two\n"[..])
    } else {
        (&b"404"[..], &b"not found\n"[..])
    };

    let mut log_buf = [0u8; 96];
    let prefix = b"[quic] h3 dispatch ";
    let mut p = 0;
    for &c in prefix { log_buf[p] = c; p += 1; }
    let n = path_bytes.len().min(log_buf.len() - p);
    core::ptr::copy_nonoverlapping(path_bytes.as_ptr(), log_buf.as_mut_ptr().add(p), n);
    p += n;
    if p + 4 <= log_buf.len() {
        log_buf[p] = b' '; p += 1;
        let mut k = 0;
        while k < status.len() && p < log_buf.len() {
            log_buf[p] = status[k];
            p += 1;
            k += 1;
        }
    }
    dev_log(sys, 3, log_buf.as_ptr(), p);

    let mut hdr_block = [0u8; 256];
    let hdr_len = h3_encode_response_headers(status, b"text/plain", body.len(), &mut hdr_block);
    if hdr_len == 0 {
        return;
    }
    let mut h3_buf = [0u8; 1024];
    let mut p = 0;
    let n = h3_build_frame_header(H3_FRAME_HEADERS, hdr_len, &mut h3_buf[p..]);
    if n == 0 { return; }
    p += n;
    if p + hdr_len > h3_buf.len() { return; }
    h3_buf[p..p + hdr_len].copy_from_slice(&hdr_block[..hdr_len]);
    p += hdr_len;
    let n = h3_build_frame_header(H3_FRAME_DATA, body.len(), &mut h3_buf[p..]);
    if n == 0 { return; }
    p += n;
    if p + body.len() > h3_buf.len() { return; }
    h3_buf[p..p + body.len()].copy_from_slice(body);
    p += body.len();

    let slot = &mut s.conns[idx].bidi_extra_streams[slot_idx];
    let space = slot.send_buf.len() - slot.send_buf_len;
    let to_copy = p.min(space);
    core::ptr::copy_nonoverlapping(
        h3_buf.as_ptr(),
        slot.send_buf.as_mut_ptr().add(slot.send_buf_len),
        to_copy,
    );
    slot.send_buf_len += to_copy;
    slot.send_fin_pending = true;
}

/// Bidi-slot counterpart to `h3_dispatch_post_complete`: a POST has
/// accumulated its body and the peer FIN'd the stream; build a 200
/// + uppercase echo response into the slot's send_buf.
unsafe fn h3_dispatch_post_complete_bidi(s: &mut QuicState, idx: usize, slot_idx: usize) {
    let sys = &*s.syscalls;
    let body_len = s.conns[idx].bidi_extra_streams[slot_idx].h3_post_body_len;
    let mut log_buf = [0u8; 96];
    let prefix = b"[quic] h3 POST body=";
    let mut p = 0;
    while p < prefix.len() { log_buf[p] = prefix[p]; p += 1; }
    let copy_n = body_len.min(log_buf.len() - p);
    core::ptr::copy_nonoverlapping(
        s.conns[idx].bidi_extra_streams[slot_idx].h3_post_body.as_ptr(),
        log_buf.as_mut_ptr().add(p),
        copy_n,
    );
    p += copy_n;
    dev_log(sys, 3, log_buf.as_ptr(), p);

    let mut up = [0u8; 1024];
    let mut k = 0;
    while k < body_len {
        let b = s.conns[idx].bidi_extra_streams[slot_idx].h3_post_body[k];
        up[k] = if b >= b'a' && b <= b'z' { b - 32 } else { b };
        k += 1;
    }
    let mut hdr_block = [0u8; 256];
    let hdr_len = h3_encode_response_headers(b"200", b"text/plain", body_len, &mut hdr_block);
    if hdr_len == 0 { return; }
    let mut h3_buf = [0u8; 1500];
    let mut q = 0;
    let n = h3_build_frame_header(H3_FRAME_HEADERS, hdr_len, &mut h3_buf[q..]);
    if n == 0 { return; }
    q += n;
    if q + hdr_len > h3_buf.len() { return; }
    h3_buf[q..q + hdr_len].copy_from_slice(&hdr_block[..hdr_len]);
    q += hdr_len;
    let n = h3_build_frame_header(H3_FRAME_DATA, body_len, &mut h3_buf[q..]);
    if n == 0 { return; }
    q += n;
    if q + body_len > h3_buf.len() { return; }
    h3_buf[q..q + body_len].copy_from_slice(&up[..body_len]);
    q += body_len;
    let slot = &mut s.conns[idx].bidi_extra_streams[slot_idx];
    let space = slot.send_buf.len() - slot.send_buf_len;
    let to_copy = q.min(space);
    core::ptr::copy_nonoverlapping(
        h3_buf.as_ptr(),
        slot.send_buf.as_mut_ptr().add(slot.send_buf_len),
        to_copy,
    );
    slot.send_buf_len += to_copy;
    slot.send_fin_pending = true;
}

/// Per-bidi-slot version of `h3_handle_stream_recv`: walks each
/// allocated slot's recv_buf for complete h3 frames, dispatching
/// using the slot's own send_buf and POST state.
unsafe fn h3_handle_bidi_extra_recv(s: &mut QuicState, idx: usize) {
    let sys = &*s.syscalls;
    let mut k = 0;
    while k < MAX_BIDI_EXTRA_STREAMS {
        let allocated = s.conns[idx].bidi_extra_streams[k].allocated;
        let buf_len = s.conns[idx].bidi_extra_streams[k].recv_buf_len;
        if !allocated || buf_len == 0 {
            // FIN may have arrived while the recv buffer is empty;
            // dispatch any in-progress POST regardless.
            if allocated
                && s.conns[idx].is_server
                && s.conns[idx].bidi_extra_streams[k].h3_post_in_progress
                && !s.conns[idx].bidi_extra_streams[k].h3_post_dispatched
                && s.conns[idx].bidi_extra_streams[k].recv_fin
            {
                h3_dispatch_post_complete_bidi(s, idx, k);
                s.conns[idx].bidi_extra_streams[k].h3_post_dispatched = true;
                s.conns[idx].bidi_extra_streams[k].h3_post_in_progress = false;
            }
            k += 1;
            continue;
        }
        let mut local = [0u8; 1500];
        let take = buf_len.min(local.len());
        core::ptr::copy_nonoverlapping(
            s.conns[idx].bidi_extra_streams[k].recv_buf.as_ptr(),
            local.as_mut_ptr(),
            take,
        );
        let mut cursor = 0;
        while cursor < take {
            let (frame, consumed) = match h3_parse_frame(&local[cursor..take]) {
                Some(p) => p,
                None => break,
            };
            match frame.frame_type {
                x if x == H3_FRAME_HEADERS => {
                    if s.conns[idx].is_server {
                        // Mirror h3_dispatch_request server logic but
                        // target this bidi slot. Decode method+path,
                        // route GET / POST.
                        if let Some(req) = h3_decode_request(frame.payload) {
                            let method_bytes: &[u8] = match (req.method_static, req.method) {
                                (Some(s), _) => s,
                                (None, Some(b)) => b,
                                _ => &[],
                            };
                            let path_bytes: &[u8] = match (req.path_static, req.path) {
                                (Some(s), _) => s,
                                (None, Some(b)) => b,
                                _ => &[],
                            };
                            if eq_bytes(method_bytes, b"POST") {
                                let slot = &mut s.conns[idx].bidi_extra_streams[k];
                                slot.h3_post_in_progress = true;
                                slot.h3_post_dispatched = false;
                                let n = path_bytes.len().min(slot.h3_post_path.len());
                                slot.h3_post_path[..n].copy_from_slice(&path_bytes[..n]);
                                slot.h3_post_path_len = n;
                                slot.h3_post_body_len = 0;
                                let msg = b"[quic] h3 POST headers (bidi)";
                                dev_log(sys, 3, msg.as_ptr(), msg.len());
                            } else {
                                h3_dispatch_request_bidi(s, idx, k, path_bytes);
                            }
                        }
                    } else {
                        // Client side: log :status from this stream.
                        if let Some(status) = h3_decode_status(frame.payload) {
                            let mut log_buf = [0u8; 64];
                            let prefix = b"[quic] h3 status=";
                            let mut p = 0;
                            for &c in prefix { log_buf[p] = c; p += 1; }
                            let mut j = 0;
                            while j < status.len() && status[j] != 0 && p < log_buf.len() {
                                log_buf[p] = status[j];
                                p += 1;
                                j += 1;
                            }
                            dev_log(sys, 3, log_buf.as_ptr(), p);
                        }
                    }
                }
                x if x == H3_FRAME_DATA => {
                    if s.conns[idx].is_server
                        && s.conns[idx].bidi_extra_streams[k].h3_post_in_progress
                    {
                        let slot = &mut s.conns[idx].bidi_extra_streams[k];
                        let space = slot.h3_post_body.len() - slot.h3_post_body_len;
                        let n = frame.payload.len().min(space);
                        if n > 0 {
                            core::ptr::copy_nonoverlapping(
                                frame.payload.as_ptr(),
                                slot.h3_post_body.as_mut_ptr().add(slot.h3_post_body_len),
                                n,
                            );
                            slot.h3_post_body_len += n;
                        }
                    } else {
                        let mut log_buf = [0u8; 96];
                        let prefix: &[u8] = if s.conns[idx].is_server {
                            b"[quic] h3 req body="
                        } else {
                            b"[quic] h3 resp body="
                        };
                        let mut p = 0;
                        for &c in prefix { log_buf[p] = c; p += 1; }
                        let copy_n = frame.payload.len().min(log_buf.len() - p);
                        core::ptr::copy_nonoverlapping(
                            frame.payload.as_ptr(),
                            log_buf.as_mut_ptr().add(p),
                            copy_n,
                        );
                        p += copy_n;
                        dev_log(sys, 3, log_buf.as_ptr(), p);
                    }
                }
                _ => {}
            }
            cursor += consumed;
        }
        // Shift unconsumed tail.
        let remain = take - cursor;
        if remain > 0 {
            core::ptr::copy(
                s.conns[idx].bidi_extra_streams[k].recv_buf.as_ptr().add(cursor),
                s.conns[idx].bidi_extra_streams[k].recv_buf.as_mut_ptr(),
                remain,
            );
        }
        s.conns[idx].bidi_extra_streams[k].recv_buf_len = remain;

        // POST: dispatch on FIN.
        if s.conns[idx].is_server
            && s.conns[idx].bidi_extra_streams[k].h3_post_in_progress
            && !s.conns[idx].bidi_extra_streams[k].h3_post_dispatched
            && s.conns[idx].bidi_extra_streams[k].recv_fin
        {
            h3_dispatch_post_complete_bidi(s, idx, k);
            s.conns[idx].bidi_extra_streams[k].h3_post_dispatched = true;
            s.conns[idx].bidi_extra_streams[k].h3_post_in_progress = false;
        }
        k += 1;
    }
}

/// Accumulate WS frame bytes from an h3 DATA payload + decode any
/// complete frames. Server: echo TEXT frames back uppercase.
/// Client: log each TEXT frame.
unsafe fn h3_ws_recv(s: &mut QuicState, idx: usize, data: &[u8]) {
    let sys = &*s.syscalls;
    {
        let conn = &mut s.conns[idx];
        let space = conn.ws_recv_accum.len() - conn.ws_recv_accum_len;
        let n = data.len().min(space);
        if n > 0 {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                conn.ws_recv_accum.as_mut_ptr().add(conn.ws_recv_accum_len),
                n,
            );
            conn.ws_recv_accum_len += n;
        }
    }
    loop {
        let buf_len = s.conns[idx].ws_recv_accum_len;
        if buf_len == 0 {
            return;
        }
        let mut local = [0u8; 256];
        let take = buf_len.min(local.len());
        core::ptr::copy_nonoverlapping(
            s.conns[idx].ws_recv_accum.as_ptr(),
            local.as_mut_ptr(),
            take,
        );
        let parsed = ws_parse_frame_with_mask(&local[..take]);
        let (frame, mask, masked, consumed) = match parsed {
            Some(p) => p,
            None => return, // truncated
        };
        // Snapshot payload into a mutable buffer so we can unmask if
        // needed.
        let mut payload_buf = [0u8; 240];
        let plen = frame.payload.len().min(payload_buf.len());
        payload_buf[..plen].copy_from_slice(&frame.payload[..plen]);
        if masked {
            ws_unmask(&mut payload_buf[..plen], &mask);
        }
        let opcode = frame.opcode;
        let fin = frame.fin;
        let _ = fin;
        // Shift the consumed bytes out of the accumulator.
        {
            let conn = &mut s.conns[idx];
            let remain = conn.ws_recv_accum_len - consumed;
            if remain > 0 {
                core::ptr::copy(
                    conn.ws_recv_accum.as_ptr().add(consumed),
                    conn.ws_recv_accum.as_mut_ptr(),
                    remain,
                );
            }
            conn.ws_recv_accum_len = remain;
        }
        match opcode {
            x if x == WS_OPCODE_TEXT || x == WS_OPCODE_BINARY || x == WS_OPCODE_CONT => {
                // RFC 6455 §5.4 — fragmented messages: first frame
                // carries TEXT/BINARY, intermediate carry CONT,
                // last carries CONT+FIN. A non-CONT frame mid-message
                // is a protocol error. CONT without an in-progress
                // message likewise.
                let conn = &mut s.conns[idx];
                let is_server = conn.is_server;
                if x == WS_OPCODE_CONT {
                    if conn.ws_msg_opcode == 0 {
                        let msg = b"[quic] h3-ws CONT without start";
                        dev_log(sys, 2, msg.as_ptr(), msg.len());
                        // Production: emit close with 1002 protocol error.
                        return;
                    }
                } else {
                    if conn.ws_msg_opcode != 0 {
                        // New TEXT/BINARY before previous FIN.
                        let msg = b"[quic] h3-ws frame interleave";
                        dev_log(sys, 2, msg.as_ptr(), msg.len());
                        return;
                    }
                    conn.ws_msg_opcode = x;
                    conn.ws_msg_len = 0;
                    if x == WS_OPCODE_TEXT {
                        conn.ws_utf8_state = UTF8_ACCEPT;
                    }
                }
                // Append payload bytes.
                let space = conn.ws_msg_buf.len() - conn.ws_msg_len;
                let n = plen.min(space);
                core::ptr::copy_nonoverlapping(
                    payload_buf.as_ptr(),
                    conn.ws_msg_buf.as_mut_ptr().add(conn.ws_msg_len),
                    n,
                );
                // RFC 6455 §8.1 — TEXT bytes must form valid UTF-8.
                // Stream-validate as bytes arrive. On FIN we'll also
                // require the validator to be at a codepoint boundary.
                if conn.ws_msg_opcode == WS_OPCODE_TEXT {
                    let mut st = Utf8State { state: conn.ws_utf8_state };
                    let ok = st.feed(&conn.ws_msg_buf[conn.ws_msg_len..conn.ws_msg_len + n]);
                    conn.ws_utf8_state = st.state;
                    if !ok {
                        let msgb = b"[quic] h3-ws UTF-8 invalid (close 1007)";
                        dev_log(sys, 2, msgb.as_ptr(), msgb.len());
                        // Send close with 1007 (Invalid frame payload data).
                        let close_payload = [0x03, 0xEFu8]; // 1007 BE
                        h3_ws_send(s, idx, WS_OPCODE_CLOSE, &close_payload);
                        let conn = &mut s.conns[idx];
                        conn.ws_msg_opcode = 0;
                        conn.ws_msg_len = 0;
                        conn.ws_utf8_state = UTF8_ACCEPT;
                        return;
                    }
                }
                conn.ws_msg_len += n;
                if !fin {
                    return; // Wait for next continuation.
                }
                // FIN — full message ready. For TEXT, require the
                // UTF-8 state machine at an accept boundary.
                if conn.ws_msg_opcode == WS_OPCODE_TEXT
                    && conn.ws_utf8_state != UTF8_ACCEPT
                {
                    let msgb = b"[quic] h3-ws UTF-8 truncated (close 1007)";
                    dev_log(sys, 2, msgb.as_ptr(), msgb.len());
                    let close_payload = [0x03, 0xEFu8];
                    h3_ws_send(s, idx, WS_OPCODE_CLOSE, &close_payload);
                    let conn = &mut s.conns[idx];
                    conn.ws_msg_opcode = 0;
                    conn.ws_msg_len = 0;
                    conn.ws_utf8_state = UTF8_ACCEPT;
                    return;
                }
                let msg_op = conn.ws_msg_opcode;
                let msg_len = conn.ws_msg_len;
                // Snapshot message into a local for emission.
                let mut snapshot = [0u8; 512];
                snapshot[..msg_len].copy_from_slice(&conn.ws_msg_buf[..msg_len]);
                conn.ws_msg_opcode = 0;
                conn.ws_msg_len = 0;
                conn.ws_utf8_state = UTF8_ACCEPT;
                // Log + (server) echo back uppercase.
                let mut log_buf = [0u8; 96];
                let prefix: &[u8] = if is_server {
                    b"[quic] h3-ws server rx="
                } else {
                    b"[quic] h3-ws client rx="
                };
                let mut p = 0;
                for &c in prefix { log_buf[p] = c; p += 1; }
                let copy_n = msg_len.min(log_buf.len() - p);
                core::ptr::copy_nonoverlapping(
                    snapshot.as_ptr(),
                    log_buf.as_mut_ptr().add(p),
                    copy_n,
                );
                p += copy_n;
                dev_log(sys, 3, log_buf.as_ptr(), p);
                if is_server {
                    let mut up = [0u8; 512];
                    let mut k = 0;
                    while k < msg_len {
                        let b = snapshot[k];
                        up[k] = if b >= b'a' && b <= b'z' {
                            b - 32
                        } else {
                            b
                        };
                        k += 1;
                    }
                    h3_ws_send(s, idx, msg_op, &up[..msg_len]);
                }
            }
            x if x == WS_OPCODE_CLOSE => {
                if s.conns[idx].is_server {
                    h3_ws_send(s, idx, WS_OPCODE_CLOSE, &payload_buf[..plen]);
                }
                let msg = b"[quic] h3-ws close";
                dev_log(sys, 3, msg.as_ptr(), msg.len());
            }
            x if x == WS_OPCODE_PING => {
                h3_ws_send(s, idx, WS_OPCODE_PONG, &payload_buf[..plen]);
            }
            _ => {}
        }
    }
}

/// Wrap a WS frame in an HTTP/3 DATA frame and append to the bidi
/// stream's send buffer.
unsafe fn h3_ws_send(s: &mut QuicState, idx: usize, opcode: u8, payload: &[u8]) {
    let mut ws_buf = [0u8; 256];
    let n = if s.conns[idx].is_server {
        ws_build_unmasked(opcode, true, payload, &mut ws_buf)
    } else {
        // Mask key from CSPRNG (RFC 6455 §5.3 — clients MUST mask).
        let mut mk = [0u8; 4];
        let sys = &*s.syscalls;
        dev_csprng_fill(sys, mk.as_mut_ptr(), 4);
        ws_build_masked(opcode, true, payload, mk, &mut ws_buf)
    };
    if n == 0 {
        return;
    }
    let mut h3_buf = [0u8; 384];
    let mut p = 0;
    let hn = h3_build_frame_header(H3_FRAME_DATA, n, &mut h3_buf[p..]);
    if hn == 0 {
        return;
    }
    p += hn;
    if p + n > h3_buf.len() {
        return;
    }
    h3_buf[p..p + n].copy_from_slice(&ws_buf[..n]);
    p += n;
    let conn = &mut s.conns[idx];
    let space = conn.stream_send_buf.len() - conn.stream_send_buf_len;
    let to_copy = p.min(space);
    core::ptr::copy_nonoverlapping(
        h3_buf.as_ptr(),
        conn.stream_send_buf.as_mut_ptr().add(conn.stream_send_buf_len),
        to_copy,
    );
    conn.stream_send_buf_len += to_copy;
}

/// Server-side: hardcoded route table. `GET /` returns "hello h3";
/// anything else returns 404. Extended-CONNECT for WebSocket
/// (`:method=CONNECT`, `:protocol=websocket`, `:path=/ws`) gets a
/// 200 response with no body and flips the connection into WS mode.
unsafe fn h3_dispatch_request(s: &mut QuicState, idx: usize, headers_block: &[u8]) {
    let sys = &*s.syscalls;
    let req = match h3_decode_request(headers_block) {
        Some(r) => r,
        None => return,
    };
    let method_bytes: &[u8] = match (req.method_static, req.method) {
        (Some(s), _) => s,
        (None, Some(b)) => b,
        _ => &[],
    };
    let path_bytes: &[u8] = match (req.path_static, req.path) {
        (Some(s), _) => s,
        (None, Some(b)) => b,
        _ => &[],
    };
    let protocol_bytes: &[u8] = match (req.protocol_static, req.protocol) {
        (Some(s), _) => s,
        (None, Some(b)) => b,
        _ => &[],
    };

    // Extended CONNECT for WebSocket (RFC 9220).
    if s.enable_ws != 0
        && eq_bytes(method_bytes, b"CONNECT")
        && eq_bytes(protocol_bytes, b"websocket")
        && eq_bytes(path_bytes, b"/ws")
    {
        let mut hdr_block = [0u8; 64];
        let hdr_len = h3_encode_connect_accept(&mut hdr_block);
        if hdr_len == 0 {
            return;
        }
        let mut h3_buf = [0u8; 256];
        let mut p = 0;
        let n = h3_build_frame_header(H3_FRAME_HEADERS, hdr_len, &mut h3_buf[p..]);
        if n == 0 { return; }
        p += n;
        h3_buf[p..p + hdr_len].copy_from_slice(&hdr_block[..hdr_len]);
        p += hdr_len;
        let conn = &mut s.conns[idx];
        let space = conn.stream_send_buf.len() - conn.stream_send_buf_len;
        let to_copy = p.min(space);
        core::ptr::copy_nonoverlapping(
            h3_buf.as_ptr(),
            conn.stream_send_buf.as_mut_ptr().add(conn.stream_send_buf_len),
            to_copy,
        );
        conn.stream_send_buf_len += to_copy;
        // Do NOT FIN — stream stays open for tunnelled WS frames.
        conn.ws_mode = true;
        let msg = b"[quic] h3 ws upgrade accepted";
        dev_log(sys, 3, msg.as_ptr(), msg.len());
        return;
    }

    // POST: accumulate body across DATA frames, then emit response
    // on stream FIN. Defers dispatch.
    if eq_bytes(method_bytes, b"POST") {
        let conn = &mut s.conns[idx];
        conn.h3_post_in_progress = true;
        conn.h3_post_dispatched = false;
        let n = path_bytes.len().min(conn.h3_post_path.len());
        conn.h3_post_path[..n].copy_from_slice(&path_bytes[..n]);
        conn.h3_post_path_len = n;
        conn.h3_post_body_len = 0;
        let msg = b"[quic] h3 POST headers";
        dev_log(sys, 3, msg.as_ptr(), msg.len());
        return;
    }

    let (status, body) = if eq_bytes(path_bytes, b"/") {
        (&b"200"[..], &b"hello h3\n"[..])
    } else {
        (&b"404"[..], &b"not found\n"[..])
    };
    let mut log_buf = [0u8; 96];
    let prefix = b"[quic] h3 dispatch ";
    let mut p = 0;
    for &c in prefix { log_buf[p] = c; p += 1; }
    let n = path_bytes.len().min(log_buf.len() - p);
    core::ptr::copy_nonoverlapping(path_bytes.as_ptr(), log_buf.as_mut_ptr().add(p), n);
    p += n;
    if p + 4 <= log_buf.len() {
        log_buf[p] = b' '; p += 1;
        let mut k = 0;
        while k < status.len() && p < log_buf.len() {
            log_buf[p] = status[k];
            p += 1;
            k += 1;
        }
    }
    dev_log(sys, 3, log_buf.as_ptr(), p);

    // Build response: HEADERS + DATA frames into stream_send_buf.
    let conn = &mut s.conns[idx];
    let mut hdr_block = [0u8; 256];
    let hdr_len = h3_encode_response_headers(status, b"text/plain", body.len(), &mut hdr_block);
    if hdr_len == 0 {
        return;
    }
    let mut h3_buf = [0u8; 1024];
    let mut p = 0;
    let n = h3_build_frame_header(H3_FRAME_HEADERS, hdr_len, &mut h3_buf[p..]);
    if n == 0 { return; }
    p += n;
    if p + hdr_len > h3_buf.len() { return; }
    h3_buf[p..p + hdr_len].copy_from_slice(&hdr_block[..hdr_len]);
    p += hdr_len;
    let n = h3_build_frame_header(H3_FRAME_DATA, body.len(), &mut h3_buf[p..]);
    if n == 0 { return; }
    p += n;
    if p + body.len() > h3_buf.len() { return; }
    h3_buf[p..p + body.len()].copy_from_slice(body);
    p += body.len();
    let space = conn.stream_send_buf.len() - conn.stream_send_buf_len;
    let to_copy = p.min(space);
    core::ptr::copy_nonoverlapping(
        h3_buf.as_ptr(),
        conn.stream_send_buf.as_mut_ptr().add(conn.stream_send_buf_len),
        to_copy,
    );
    conn.stream_send_buf_len += to_copy;
    conn.stream_send_fin = true;
}

/// Client-side: emit a `GET /` HTTP/3 HEADERS frame on stream 0.
/// In WS-on-h3 mode (RFC 9220) emits an extended CONNECT instead.
unsafe fn h3_emit_client_request(s: &mut QuicState, idx: usize) {
    let mut hdr_block = [0u8; 256];
    let hdr_len = if s.enable_ws != 0 {
        h3_encode_extended_connect(b"/ws", b"localhost", &mut hdr_block)
    } else {
        h3_encode_request_headers(b"GET", b"/", b"localhost", &mut hdr_block)
    };
    if hdr_len == 0 {
        return;
    }
    let mut h3_buf = [0u8; 512];
    let mut p = 0;
    let n = h3_build_frame_header(H3_FRAME_HEADERS, hdr_len, &mut h3_buf[p..]);
    if n == 0 { return; }
    p += n;
    if p + hdr_len > h3_buf.len() { return; }
    h3_buf[p..p + hdr_len].copy_from_slice(&hdr_block[..hdr_len]);
    p += hdr_len;
    let conn = &mut s.conns[idx];
    let space = conn.stream_send_buf.len() - conn.stream_send_buf_len;
    let to_copy = p.min(space);
    core::ptr::copy_nonoverlapping(
        h3_buf.as_ptr(),
        conn.stream_send_buf.as_mut_ptr().add(conn.stream_send_buf_len),
        to_copy,
    );
    conn.stream_send_buf_len += to_copy;
}

/// Queue a `GET /two` request on bidi stream id 4 (the second
/// client-initiated bidi stream, RFC 9000 §2.1) so it runs in
/// parallel with the `GET /` on stream id 0.
unsafe fn h3_emit_concurrent_bidi_request(s: &mut QuicState, idx: usize) {
    let stream_id: u64 = 4;
    let slot_idx = match bidi_alloc(&mut s.conns[idx], stream_id, true) {
        Some(i) => i,
        None => return,
    };
    let mut hdr_block = [0u8; 256];
    let hdr_len = h3_encode_request_headers(b"GET", b"/two", b"localhost", &mut hdr_block);
    if hdr_len == 0 {
        return;
    }
    let mut h3_buf = [0u8; 512];
    let mut p = 0;
    let n = h3_build_frame_header(H3_FRAME_HEADERS, hdr_len, &mut h3_buf[p..]);
    if n == 0 { return; }
    p += n;
    if p + hdr_len > h3_buf.len() { return; }
    h3_buf[p..p + hdr_len].copy_from_slice(&hdr_block[..hdr_len]);
    p += hdr_len;

    let slot = &mut s.conns[idx].bidi_extra_streams[slot_idx];
    let space = slot.send_buf.len() - slot.send_buf_len;
    let to_copy = p.min(space);
    core::ptr::copy_nonoverlapping(
        h3_buf.as_ptr(),
        slot.send_buf.as_mut_ptr().add(slot.send_buf_len),
        to_copy,
    );
    slot.send_buf_len += to_copy;
    slot.send_fin_pending = true;
}

fn eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] { return false; }
        i += 1;
    }
    true
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
