//! TLS 1.3 PIC Module for Fluxor
//!
//! Pure Rust implementation — no C, no GOT, no data relocations.
//! Channel-based graph node sitting between IP and HTTP:
//!   IP <--cipher_in/cipher_out--> TLS <--clear_in/clear_out--> HTTP
//!
//! Cipher suites: TLS_CHACHA20_POLY1305_SHA256 (preferred),
//!                TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384

#![no_std]
#![no_main]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

// PIC runtime (syscalls, helpers, intrinsics)
include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

// Crypto primitives
include!("../../sdk/sha256.rs");
include!("sha384.rs");
include!("hmac.rs");
include!("chacha20.rs");
include!("aes_gcm.rs");
include!("p256.rs");
include!("x509.rs");

// TLS protocol
include!("alert.rs");
include!("record.rs");
include!("key_schedule.rs");
include!("handshake.rs");

// ============================================================================
// Module constants
// ============================================================================

const MAX_SESSIONS: usize = 4;
const MAX_CERT_LEN: usize = 1024;
const MAX_KEY_LEN: usize = 160;
const RECV_BUF_SIZE: usize = 4096;
const SEND_BUF_SIZE: usize = 2048;
const SCRATCH_SIZE: usize = 1536;
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
    conn_id: u8,              // net_proto connection ID
    held_msg_type: u8,        // held ACCEPTED/CONNECTED msg type to forward after handshake
    is_server: bool,
    hrr_sent: bool,           // HelloRetryRequest was sent, expecting 2nd ClientHello
    hs_state: HandshakeState,
    suite: CipherSuite,

    // Key schedule
    key_schedule: Option<KeySchedule>,

    // Traffic keys
    read_keys: TrafficKeys,
    write_keys: TrafficKeys,

    // Transcript
    transcript: Option<Transcript>,

    // ECDH ephemeral key pair
    ecdh_private: [u8; 32],
    ecdh_public: [u8; 65],

    // Resumable ECDH shared-secret computation, advanced in bounded chunks
    // so concurrent handshakes interleave instead of blocking each other.
    ecdh_state: ScalarMulState,

    // Peer key share (from ClientHello/ServerHello)
    peer_key_share: [u8; 65],
    peer_key_share_len: u8,

    // Peer certificate public key (extracted during handshake for CertificateVerify)
    peer_cert_pubkey: [u8; 65],
    peer_cert_pubkey_len: u8,

    // Peer session_id (for echo)
    peer_session_id: [u8; 32],
    peer_session_id_len: u8,

    // Server random (for server mode)
    server_random: [u8; 32],

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

    // Transcript hash at server Finished (used for app key derivation)
    server_finished_hash: [u8; 48],

    // Handshake reassembly: accumulated decrypted bytes for fragmented messages
    hs_accum_len: usize,

    // Handshake scratch (for building messages)
    scratch: [u8; SCRATCH_SIZE],
}

impl TlsSession {
    const fn empty() -> Self {
        Self {
            state: SessionState::Idle,
            conn_id: 0,
            held_msg_type: 0,
            is_server: false,
            hrr_sent: false,
            hs_state: HandshakeState::RecvClientHello,
            suite: CipherSuite::ChaCha20Poly1305,
            key_schedule: None,
            read_keys: TrafficKeys::empty(),
            write_keys: TrafficKeys::empty(),
            transcript: None,
            ecdh_private: [0; 32],
            ecdh_public: [0; 65],
            ecdh_state: ScalarMulState::empty(),
            peer_key_share: [0; 65],
            peer_key_share_len: 0,
            peer_cert_pubkey: [0; 65],
            peer_cert_pubkey_len: 0,
            peer_session_id: [0; 32],
            peer_session_id_len: 0,
            server_random: [0; 32],
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
            server_finished_hash: [0; 48],
            hs_accum_len: 0,
            scratch: [0; SCRATCH_SIZE],
        }
    }

    fn reset(&mut self) {
        // Zeroize all sensitive material
        unsafe {
            let mut i = 0;
            while i < 32 {
                core::ptr::write_volatile(&mut self.ecdh_private[i], 0);
                core::ptr::write_volatile(&mut self.server_random[i], 0);
                i += 1;
            }
            // Zero traffic key material
            i = 0;
            while i < 32 {
                core::ptr::write_volatile(&mut self.read_keys.key[i], 0);
                core::ptr::write_volatile(&mut self.write_keys.key[i], 0);
                i += 1;
            }
        }
        self.state = SessionState::Idle;
        self.conn_id = 0;
        self.held_msg_type = 0;
        self.hrr_sent = false;
        self.recv_len = 0;
        self.recv_expected = 0;
        self.send_len = 0;
        self.retx_len = 0;
        self.retx_base_seq = 0;
        self.retx_seq_anchored = false;
        self.send_offset = 0;
        self.hs_accum_len = 0;
        self.peer_key_share_len = 0;
        self.peer_cert_pubkey_len = 0;
        self.ecdh_state.zeroise_scalar();
        self.ecdh_state = ScalarMulState::empty();
        self.key_schedule = None;
        self.transcript = None;
        self.read_keys = TrafficKeys::empty();
        self.write_keys = TrafficKeys::empty();
    }
}

// ============================================================================
// Module state
// ============================================================================

#[repr(C)]
struct TlsState {
    syscalls: *const SyscallTable,
    mode: u8,           // 0=client, 1=server
    verify_peer: u8,
    /// Bits of the P-256 ladder to process per pump tick. 256 runs the full
    /// ladder in one call; smaller values yield between chunks so a second
    /// concurrent handshake doesn't wait for the first to finish.
    ecdh_bits_per_step: u16,

    // Channel ports (4-port node: cipher side facing IP, clear side facing HTTP)
    cipher_in: i32,     // from IP: ciphertext net_proto frames
    cipher_out: i32,    // to IP: ciphertext net_proto frames
    clear_in: i32,      // from HTTP: cleartext net_proto frames (commands)
    clear_out: i32,     // to HTTP: cleartext net_proto frames (events)

    // Pre-computed ephemeral ECDH key pairs (one per session, computed in module_new)
    eph_private: [[u8; 32]; MAX_SESSIONS],
    eph_public: [[u8; 65]; MAX_SESSIONS],
    eph_used: [bool; MAX_SESSIONS], // true if key has been consumed

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

    // Scratch buffer for net_proto frame assembly
    net_scratch: [u8; NET_SCRATCH_SIZE],
}

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

    let sys = &*s.syscalls;

    // Discover 4 channel ports
    // in[0] = cipher_in (from IP), in[1] = clear_in (from HTTP)
    // out[0] = cipher_out (to IP), out[1] = clear_out (to HTTP)
    s.cipher_in = dev_channel_port(sys, 0, 0);
    s.clear_in = dev_channel_port(sys, 0, 1);
    s.cipher_out = dev_channel_port(sys, 1, 0);
    s.clear_out = dev_channel_port(sys, 1, 1);

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
            if rc < 0 { return -1; } // CSPRNG failure is fatal
            let (priv_key, pub_key) = ecdh_keygen(&random);
            s.eph_private[i] = priv_key;
            s.eph_public[i] = pub_key;
            s.eph_used[i] = false;
            let mut j = 0;
            while j < 32 { core::ptr::write_volatile(&mut random[j], 0); j += 1; }
            i += 1;
        }
    }

    // Deposit the private scalar into the kernel KEY_VAULT so that
    // CertificateVerify signs via `KV_SIGN` and the in-module `s.key`
    // bytes can be wiped immediately after.
    const KV_PROBE: u32 = 0x1000;
    const KV_STORE: u32 = 0x1001;
    if s.key_len >= 32 {
        let present = (sys.provider_call)(-1, KV_PROBE, core::ptr::null_mut(), 0);
        if present == 1 {
            let mut raw = [0u8; 32];
            if s.key_len == 32 {
                core::ptr::copy_nonoverlapping(s.key.as_ptr(), raw.as_mut_ptr(), 32);
            } else {
                extract_ec_private_key(&s.key[..s.key_len], &mut raw);
            }
            let mut store_arg = [0u8; 4 + 32];
            store_arg[0] = 1;  // key_type = P-256 scalar
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
    if params.is_null() || params_len < 4 { return; }
    let data = core::slice::from_raw_parts(params, params_len);

    // Scan for extended TLV entries anywhere in the blob
    let mut pos = 0;
    let end = params_len;

    // Search for extended TLV pattern: tag + 0x00 + len_hi + len_lo
    while pos + 4 <= end {
        let tag = data[pos];
        let ext_tags = tag == 3 || tag == 10 || tag == 11 || tag == 12;
        if ext_tags && pos + 1 < end && data[pos + 1] == 0x00 && pos + 4 <= end {
            let len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
            let data_start = pos + 4;
            if data_start + len > end { break; }

            match tag {
                3 => {
                    let n = if len < 64 { len } else { 64 };
                    core::ptr::copy_nonoverlapping(data.as_ptr().add(data_start), s.trust_domain.as_mut_ptr(), n);
                    s.trust_domain_len = n;
                }
                10 => {
                    let n = if len < MAX_CERT_LEN { len } else { MAX_CERT_LEN };
                    core::ptr::copy_nonoverlapping(data.as_ptr().add(data_start), s.cert.as_mut_ptr(), n);
                    s.cert_len = n;
                }
                11 => {
                    let n = if len < MAX_KEY_LEN { len } else { MAX_KEY_LEN };
                    core::ptr::copy_nonoverlapping(data.as_ptr().add(data_start), s.key.as_mut_ptr(), n);
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

#[no_mangle]
pub unsafe extern "C" fn module_step(state: *mut u8) -> i32 {
    let s = &mut *(state as *mut TlsState);
    let sys = &*s.syscalls;
    let mut did_work = false;

    // ── Phase 1: Drive active handshake sessions ──
    let mut i = 0;
    while i < MAX_SESSIONS {
        if s.sessions[i].state == SessionState::Handshaking {
            if pump_session(s, i) {
                did_work = true;
            }
        } else if s.sessions[i].state == SessionState::Closed {
            s.sessions[i].reset();
        } else if s.sessions[i].state == SessionState::Error {
            // Send CMD_CLOSE upstream for this conn_id, then forward MSG_CLOSED downstream
            let cid = s.sessions[i].conn_id;
            tls_write_frame(sys, s.cipher_out, NET_CMD_CLOSE, cid, core::ptr::null(), 0, &mut s.net_scratch);
            tls_write_frame(sys, s.clear_out, NET_MSG_CLOSED, cid, core::ptr::null(), 0, &mut s.net_scratch);
            s.sessions[i].reset();
        }
        i += 1;
    }

    // ── Phase 2: Read from cipher_in (downstream: IP → TLS) ──
    let poll_ci = (sys.channel_poll)(s.cipher_in, POLL_IN);
    if poll_ci > 0 && (poll_ci as u32 & POLL_IN) != 0 {
        let (msg_type, payload_len) = tls_read_header(sys, s.cipher_in);
        if msg_type != 0 {
            did_work = true;
            match msg_type {
                t if t == NET_MSG_ACCEPTED as u8 || t == NET_MSG_CONNECTED as u8 => {
                    // Read conn_id from payload
                    let mut payload = [0u8; 256];
                    let pl = payload_len as usize;
                    if pl > 0 {
                        let rd = if pl < 256 { pl } else { 256 };
                        (sys.channel_read)(s.cipher_in, payload.as_mut_ptr(), rd);
                        // Discard excess
                        if pl > 256 { tls_discard(sys, s.cipher_in, pl - 256); }
                    }
                    let conn_id = if pl > 0 { unsafe { *payload.as_ptr() } } else { 0 };
                    // Allocate session for this connection
                    match alloc_session_for_conn(s, conn_id) {
                        Some(idx) => {
                            s.sessions[idx].is_server = (t == NET_MSG_ACCEPTED as u8);
                            s.sessions[idx].held_msg_type = t;
                            s.sessions[idx].state = SessionState::Handshaking;
                            if s.sessions[idx].is_server {
                                s.sessions[idx].hs_state = HandshakeState::RecvClientHello;
                            } else {
                                s.sessions[idx].hs_state = HandshakeState::SendClientHello;
                            }
                            init_session_crypto(s, idx);
                        }
                        None => {
                            // No session slots — forward close
                            tls_write_frame(sys, s.cipher_out, NET_CMD_CLOSE, conn_id, core::ptr::null(), 0, &mut s.net_scratch);
                        }
                    }
                }
                t if t == NET_MSG_DATA as u8 => {
                    // Read conn_id + ciphertext payload
                    let pl = payload_len as usize;
                    if pl < 1 {
                        // Malformed — skip
                    } else {
                        let mut conn_id_buf = [0u8; 1];
                        (sys.channel_read)(s.cipher_in, conn_id_buf.as_mut_ptr(), 1);
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
                                    (sys.channel_read)(s.cipher_in,
                                        s.sessions[idx].recv_buf.as_mut_ptr().add(s.sessions[idx].recv_len),
                                        to_read);
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
                                    (sys.channel_read)(s.cipher_in,
                                        s.sessions[idx].recv_buf.as_mut_ptr().add(s.sessions[idx].recv_len),
                                        to_read);
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
                t if t == NET_MSG_CLOSED as u8 => {
                    // Read conn_id and forward to clear_out
                    let pl = payload_len as usize;
                    let mut payload = [0u8; 16];
                    let rd = if pl < 16 { pl } else { 16 };
                    if rd > 0 { (sys.channel_read)(s.cipher_in, payload.as_mut_ptr(), rd); }
                    if pl > 16 { tls_discard(sys, s.cipher_in, pl - 16); }
                    let conn_id = if pl > 0 { payload[0] } else { 0 };
                    // Clean up session
                    let si = find_session_by_conn_id(s, conn_id);
                    if si >= 0 { s.sessions[si as usize].reset(); }
                    // Forward to HTTP
                    tls_write_frame(sys, s.clear_out, NET_MSG_CLOSED, conn_id, core::ptr::null(), 0, &mut s.net_scratch);
                }
                t if t == NET_MSG_BOUND as u8 || t == NET_MSG_ERROR as u8 => {
                    // Pass through unchanged to clear_out
                    let pl = payload_len as usize;
                    let rd = if pl < NET_SCRATCH_SIZE { pl } else { NET_SCRATCH_SIZE };
                    if rd > 0 { (sys.channel_read)(s.cipher_in, s.net_scratch.as_mut_ptr(), rd); }
                    if pl > rd { tls_discard(sys, s.cipher_in, pl - rd); }
                    tls_write_raw_frame(sys, s.clear_out, t, s.net_scratch.as_ptr(), rd as u16);
                }
                t if t == NET_MSG_ACK as u8 => {
                    // Payload: [conn_id:1][acked_seq:4 LE].
                    let pl = payload_len as usize;
                    let mut payload = [0u8; 5];
                    let rd = if pl < 5 { pl } else { 5 };
                    if rd > 0 { (sys.channel_read)(s.cipher_in, payload.as_mut_ptr(), rd); }
                    if pl > rd { tls_discard(sys, s.cipher_in, pl - rd); }
                    if rd == 5 {
                        let conn_id = payload[0];
                        let acked_seq = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                        let si = find_session_by_conn_id(s, conn_id);
                        if si >= 0 {
                            retx_ack(&mut s.sessions[si as usize], acked_seq);
                        }
                    }
                }
                t if t == NET_MSG_RETRANSMIT as u8 => {
                    // Payload: [conn_id:1][from_seq:4 LE].
                    let pl = payload_len as usize;
                    let mut payload = [0u8; 5];
                    let rd = if pl < 5 { pl } else { 5 };
                    if rd > 0 { (sys.channel_read)(s.cipher_in, payload.as_mut_ptr(), rd); }
                    if pl > rd { tls_discard(sys, s.cipher_in, pl - rd); }
                    if rd == 5 {
                        let conn_id = payload[0];
                        let from_seq = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                        let si = find_session_by_conn_id(s, conn_id);
                        if si >= 0 {
                            retx_replay(s, si as usize, from_seq);
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

    // ── Phase 3: Read from clear_in (upstream: HTTP → TLS) ──
    let poll_cl = (sys.channel_poll)(s.clear_in, POLL_IN);
    if poll_cl > 0 && (poll_cl as u32 & POLL_IN) != 0 {
        let (msg_type, payload_len) = tls_read_header(sys, s.clear_in);
        if msg_type != 0 {
            did_work = true;
            match msg_type {
                t if t == NET_CMD_SEND as u8 => {
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
                                // Read plaintext
                                let rd = if data_len < SEND_BUF_SIZE { data_len } else { SEND_BUF_SIZE };
                                let sess = &mut s.sessions[idx];
                                (sys.channel_read)(s.clear_in, sess.send_buf.as_mut_ptr(), rd);
                                if data_len > rd { tls_discard(sys, s.clear_in, data_len - rd); }

                                // Encrypt as TLS application_data record
                                let mut enc_buf = [0u8; SEND_BUF_SIZE];
                                let enc_len = encrypt_record(
                                    sess.suite,
                                    &mut sess.write_keys,
                                    CT_APPLICATION_DATA,
                                    &sess.send_buf[..rd],
                                    &mut enc_buf,
                                );

                                // Build TLS record: 5-byte header + ciphertext
                                let mut rec = [0u8; SEND_BUF_SIZE + 5];
                                *rec.as_mut_ptr() = CT_APPLICATION_DATA;
                                *rec.as_mut_ptr().add(1) = 0x03;
                                *rec.as_mut_ptr().add(2) = 0x03;
                                *rec.as_mut_ptr().add(3) = (enc_len >> 8) as u8;
                                *rec.as_mut_ptr().add(4) = enc_len as u8;
                                core::ptr::copy_nonoverlapping(enc_buf.as_ptr(), rec.as_mut_ptr().add(5), enc_len);
                                let total = 5 + enc_len;

                                // Write CMD_SEND(conn_id, tls_record) to cipher_out
                                tls_write_frame(sys, s.cipher_out, NET_CMD_SEND, conn_id, rec.as_ptr(), total as u16, &mut s.net_scratch);
                                retx_push(&mut s.sessions[idx], rec.as_ptr(), total as u16);
                            } else {
                                tls_discard(sys, s.clear_in, data_len);
                            }
                        } else {
                            tls_discard(sys, s.clear_in, data_len);
                        }
                    }
                }
                t if t == NET_CMD_CLOSE as u8 => {
                    let pl = payload_len as usize;
                    let mut payload = [0u8; 16];
                    let rd = if pl < 16 { pl } else { 16 };
                    if rd > 0 { (sys.channel_read)(s.clear_in, payload.as_mut_ptr(), rd); }
                    if pl > 16 { tls_discard(sys, s.clear_in, pl - 16); }
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
                    // Forward CMD_CLOSE to cipher_out
                    tls_write_frame(sys, s.cipher_out, NET_CMD_CLOSE, conn_id, core::ptr::null(), 0, &mut s.net_scratch);
                }
                t if t == NET_CMD_BIND as u8 || t == NET_CMD_CONNECT as u8 => {
                    // Pass through unchanged to cipher_out
                    let pl = payload_len as usize;
                    let rd = if pl < NET_SCRATCH_SIZE { pl } else { NET_SCRATCH_SIZE };
                    if rd > 0 { (sys.channel_read)(s.clear_in, s.net_scratch.as_mut_ptr(), rd); }
                    if pl > rd { tls_discard(sys, s.clear_in, pl - rd); }
                    tls_write_raw_frame(sys, s.cipher_out, t, s.net_scratch.as_ptr(), rd as u16);
                }
                _ => {
                    tls_discard(sys, s.clear_in, payload_len as usize);
                }
            }
        }
    }

    // ── Phase 4: For Ready sessions, try to decrypt any buffered data ──
    i = 0;
    while i < MAX_SESSIONS {
        if s.sessions[i].state == SessionState::Ready && s.sessions[i].recv_len >= 5 {
            try_decrypt_forward(s, i);
        }
        i += 1;
    }

    if did_work { 2 } else { 0 } // Burst or Continue
}

// ============================================================================
// Session management
// ============================================================================

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
    if sess.peer_cert_pubkey_len == 0 { return true; }
    let hl = sess.suite.hash_len();
    let transcript_hash = match &sess.transcript {
        Some(t) => t.current_hash(),
        None => return false,
    };
    let context: &[u8] = if sess.is_server {
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
            let pk = &sess.peer_cert_pubkey[..sess.peer_cert_pubkey_len as usize];
            return ecdsa_verify(pk, &vc_hash, &raw_sig);
        }
    }
    false
}

/// Extract peer certificate public key and validate SPIFFE SAN.
unsafe fn extract_peer_cert_key(s: &mut TlsState, idx: usize, hs_body: &[u8]) -> bool {
    if let Some(cert_der) = parse_certificate_msg(hs_body) {
        if let Some(cert) = parse_certificate(cert_der) {
            // Trust anchor check: if a CA public key is configured, verify
            // the peer certificate's TBS signature against it. Chain-of-one
            // path validation — leaf must be signed directly by the CA.
            if s.require_ca && s.ca_pubkey_len > 0 {
                let ca_pk = &s.ca_pubkey[..s.ca_pubkey_len as usize];
                let tbs_hash = sha256(cert.tbs_raw);
                let raw_sig = match parse_der_signature(cert.signature) {
                    Some(r) => r,
                    None => return false,
                };
                if !ecdsa_verify(ca_pk, &tbs_hash, &raw_sig) {
                    return false;
                }
            }

            let pk = cert.public_key;
            let pk_len = if pk.len() <= 65 { pk.len() } else { 65 };
            core::ptr::copy_nonoverlapping(pk.as_ptr(), s.sessions[idx].peer_cert_pubkey.as_mut_ptr(), pk_len);
            s.sessions[idx].peer_cert_pubkey_len = pk_len as u8;
            if s.trust_domain_len > 0 {
                let td = &s.trust_domain[..s.trust_domain_len];
                let mut spiffe_ok = false;
                extract_san_uris(cert_der, |uri| {
                    if is_spiffe_match(uri, td) { spiffe_ok = true; }
                    spiffe_ok
                });
                if !spiffe_ok { return false; }
            }
        }
    }
    true
}

/// Skip any CCS records at the front of a session's recv_buf.
unsafe fn skip_ccs(sess: &mut TlsSession) {
    while sess.recv_len >= 5 && *sess.recv_buf.as_ptr() == CT_CHANGE_CIPHER_SPEC {
        let p = sess.recv_buf.as_ptr();
        let ccs_len = ((*p.add(3) as usize) << 8) | (*p.add(4) as usize);
        let consumed = 5 + ccs_len;
        if sess.recv_len < consumed || consumed > RECV_BUF_SIZE { break; }
        let remain = sess.recv_len - consumed;
        if remain > 0 {
            core::ptr::copy(sess.recv_buf.as_ptr().add(consumed), sess.recv_buf.as_mut_ptr(), remain);
        }
        sess.recv_len = remain;
    }
}

unsafe fn init_session_crypto(s: &mut TlsState, idx: usize) {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    // Generate a fresh ephemeral ECDH key pair per session (RFC §2.4).
    // Pre-computing keys at module_new and reusing them across sessions
    // weakens forward secrecy: a memory disclosure after session N reveals
    // the private key of every subsequent session that reuses it.
    let mut random = [0u8; 32];
    if dev_csprng_fill(sys, random.as_mut_ptr(), 32) < 0 {
        // Fall back to the pre-computed pool slot if CSPRNG is unavailable.
        let key_idx = if idx < MAX_SESSIONS && !s.eph_used[idx] { idx } else { 0 };
        sess.ecdh_private = s.eph_private[key_idx];
        sess.ecdh_public = s.eph_public[key_idx];
        s.eph_used[key_idx] = true;
    } else {
        let (priv_key, pub_key) = ecdh_keygen(&random);
        sess.ecdh_private = priv_key;
        sess.ecdh_public = pub_key;
        // Volatile wipe of the stack buffer — the private scalar has been
        // consumed by ecdh_keygen but the random seed also leaks it.
        let mut i = 0;
        while i < 32 {
            core::ptr::write_volatile(random.as_mut_ptr().add(i), 0);
            i += 1;
        }
    }

    // Default suite (will be set during handshake)
    sess.suite = CipherSuite::ChaCha20Poly1305;
}

// ============================================================================
// Handshake state machine pump
// ============================================================================

unsafe fn pump_session(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;

    match s.sessions[idx].hs_state {
        // ── Server flow ──
        HandshakeState::RecvClientHello | HandshakeState::RecvSecondClientHello => pump_recv_client_hello(s, idx),
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
        HandshakeState::RecvEncryptedExtensions => pump_recv_encrypted(s, idx, HT_ENCRYPTED_EXTENSIONS, HandshakeState::RecvCertificate),
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
    }
}

// ============================================================================
// Server handshake steps
// ============================================================================

unsafe fn pump_recv_client_hello(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    // Data arrives via cipher_in -> recv_buf in module_step; no socket read here.
    skip_ccs(sess);

    // Need at least record header (5) + handshake header (4)
    if sess.recv_len < 9 { return false; }

    // Parse record header with length validation (raw pointer access for PIC safety)
    let rbp = sess.recv_buf.as_ptr();
    let rec_type = *rbp;
    let rec_len = ((*rbp.add(3) as usize) << 8) | (*rbp.add(4) as usize);
    if rec_len > MAX_CIPHERTEXT || rec_len > RECV_BUF_SIZE { return false; }
    if sess.recv_len < 5 + rec_len { return false; }

    if rec_type != CT_HANDSHAKE { return false; }

    // Parse handshake message (raw pointer slicing for PIC safety)
    let hs_ptr = rbp.add(5);
    let hs_data = core::slice::from_raw_parts(hs_ptr, rec_len);
    if *hs_ptr != 1 { return false; } // ClientHello type
    let hs_len = ((*hs_ptr.add(1) as usize) << 16) | ((*hs_ptr.add(2) as usize) << 8) | (*hs_ptr.add(3) as usize);
    if hs_len + 4 > rec_len { return false; }

    let ch_body = core::slice::from_raw_parts(hs_ptr.add(4), hs_len);
    let ch = match parse_client_hello(ch_body) {
        Some(c) => c,
        None => {
            sess.state = SessionState::Error;
            return true;
        }
    };

    // Validate TLS 1.3
    if ch.supported_versions != Some(0x0304) {
        dev_log(sys, 2, b"[tls] client not TLS 1.3".as_ptr(), b"[tls] client not TLS 1.3".len());
        sess.state = SessionState::Error;
        return true;
    }

    // Select cipher suite
    sess.suite = match select_cipher_suite(ch.cipher_suites) {
        Some(cs) => cs,
        None => {
            dev_log(sys, 2, b"[tls] no common cipher suite".as_ptr(), b"[tls] no common cipher suite".len());
            sess.state = SessionState::Error;
            return true;
        }
    };

    // Extract peer key share
    // Save session_id for echo
    if ch.session_id.len() <= 32 {
        core::ptr::copy_nonoverlapping(ch.session_id.as_ptr(), sess.peer_session_id.as_mut_ptr(), ch.session_id.len());
        sess.peer_session_id_len = ch.session_id.len() as u8;
    }

    // Initialize or update transcript
    if sess.transcript.is_none() {
        sess.transcript = Some(Transcript::new(sess.suite.hash_alg()));
    }

    match ch.key_share {
        Some((_, key_data)) if key_data.len() <= 65 => {
            core::ptr::copy_nonoverlapping(key_data.as_ptr(), sess.peer_key_share.as_mut_ptr(), key_data.len());
            sess.peer_key_share_len = key_data.len() as u8;
        }
        _ => {
            if sess.hrr_sent {
                // Second ClientHello still has no P-256 → fatal
                sess.state = SessionState::Error;
                return true;
            }
            // No P-256 key share → send HelloRetryRequest
            // Update transcript with this ClientHello first
            if let Some(ref mut t) = sess.transcript {
                t.update(hs_data);
            }
            // Consume record
            let consumed = 5 + rec_len;
            let remain = sess.recv_len - consumed;
            if remain > 0 {
                core::ptr::copy(sess.recv_buf.as_ptr().add(consumed), sess.recv_buf.as_mut_ptr(), remain);
            }
            sess.recv_len = remain;
            sess.hs_state = HandshakeState::SendHelloRetryRequest;
            return true;
        }
    }

    // Update transcript with ClientHello (for normal flow or 2nd CH after HRR)
    if let Some(ref mut t) = sess.transcript {
        // For HRR: RFC 8446 Section 4.4.1 — replace first CH hash with
        // message_hash construct: handshake_type=254 + length + Hash(CH1)
        if sess.hrr_sent {
            // The transcript already has the synthetic message_hash from HRR.
            // Just add this second ClientHello.
        }
        t.update(hs_data);
    }

    // Generate server random (entropy failure is fatal)
    if dev_csprng_fill(sys, sess.server_random.as_mut_ptr(), 32) < 0 {
        sess.state = SessionState::Error;
        return true;
    }

    // Consume record from recv_buf
    let consumed = 5 + rec_len;
    let remain = sess.recv_len - consumed;
    if remain > 0 {
        core::ptr::copy(sess.recv_buf.as_ptr().add(consumed), sess.recv_buf.as_mut_ptr(), remain);
    }
    sess.recv_len = remain;

    sess.hs_state = HandshakeState::SendServerHello;
    true
}

unsafe fn pump_send_server_hello(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;

    {
        let sess = &mut s.sessions[idx];

        let msg_len = build_server_hello(
            &sess.server_random,
            &sess.peer_session_id,
            sess.suite,
            &sess.ecdh_public,
            &mut sess.scratch,
        );

        // Update transcript
        if let Some(ref mut t) = sess.transcript {
            t.update(&sess.scratch[..msg_len]);
        }

        // Wrap ServerHello in a TLS record, appending the middlebox-compat
        // CCS record into the same send when one has not already followed
        // an HRR (RFC 8446 §5: server sends at most one CCS).
        let mut rec = [0u8; 256];
        let mut hdr = [0u8; 5];
        build_record_header(CT_HANDSHAKE, msg_len, &mut hdr);
        core::ptr::copy_nonoverlapping(hdr.as_ptr(), rec.as_mut_ptr(), 5);
        core::ptr::copy_nonoverlapping(sess.scratch.as_ptr(), rec.as_mut_ptr().add(5), msg_len);

        let sh_total = 5 + msg_len;
        let conn_id = sess.conn_id;

        let total = if !sess.hrr_sent {
            *rec.as_mut_ptr().add(sh_total) = CT_CHANGE_CIPHER_SPEC;
            *rec.as_mut_ptr().add(sh_total + 1) = 0x03;
            *rec.as_mut_ptr().add(sh_total + 2) = 0x03;
            *rec.as_mut_ptr().add(sh_total + 3) = 0x00;
            *rec.as_mut_ptr().add(sh_total + 4) = 0x01;
            *rec.as_mut_ptr().add(sh_total + 5) = 0x01;
            sh_total + 6
        } else {
            sh_total
        };
        tls_write_frame(sys, s.cipher_out, NET_CMD_SEND, conn_id, rec.as_ptr(), total as u16, &mut s.net_scratch);
    }

    s.sessions[idx].hs_state = HandshakeState::DeriveHandshakeKeys;
    true
}

unsafe fn pump_send_hello_retry(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    let msg_len = build_hello_retry_request(
        &sess.peer_session_id,
        sess.suite,
        &mut sess.scratch,
    );

    // Update transcript with HRR
    // RFC 8446 Section 4.4.1: replace transcript with message_hash construct
    // transcript = Hash(message_hash(254) || length || Hash(CH1))
    // Then add HRR to it.
    if let Some(ref mut t) = sess.transcript {
        // Get Hash(CH1) from current transcript
        let ch1_hash = t.current_hash();
        let hl = sess.suite.hash_len();
        // Reset transcript and inject synthetic message_hash
        *t = Transcript::new(sess.suite.hash_alg());
        // message_hash: type=254, length=hash_len, data=Hash(CH1)
        let mut synthetic = [0u8; 4 + 48];
        synthetic[0] = 254; // message_hash type
        synthetic[3] = hl as u8;
        unsafe { core::ptr::copy_nonoverlapping(ch1_hash.as_ptr(), synthetic.as_mut_ptr().add(4), hl); }
        t.update(&synthetic[..4 + hl]);
        // Add HRR to transcript
        t.update(&sess.scratch[..msg_len]);
    }

    // Ship HRR and the middlebox-compat CCS record as a single send so they
    // land in the same TCP segment (RFC 8446 §4.1.4).
    let mut rec = [0u8; SEND_BUF_SIZE];
    let mut hdr = [0u8; 5];
    build_record_header(CT_HANDSHAKE, msg_len, &mut hdr);
    core::ptr::copy_nonoverlapping(hdr.as_ptr(), rec.as_mut_ptr(), 5);
    core::ptr::copy_nonoverlapping(sess.scratch.as_ptr(), rec.as_mut_ptr().add(5), msg_len);
    let hrr_total = 5 + msg_len;
    use core::ptr::write_volatile as wv;
    wv(rec.as_mut_ptr().add(hrr_total),     CT_CHANGE_CIPHER_SPEC);
    wv(rec.as_mut_ptr().add(hrr_total + 1), 0x03u8);
    wv(rec.as_mut_ptr().add(hrr_total + 2), 0x03u8);
    wv(rec.as_mut_ptr().add(hrr_total + 3), 0x00u8);
    wv(rec.as_mut_ptr().add(hrr_total + 4), 0x01u8);
    wv(rec.as_mut_ptr().add(hrr_total + 5), 0x01u8);
    let total = hrr_total + 6;
    let conn_id = sess.conn_id;
    tls_write_frame(sys, s.cipher_out, NET_CMD_SEND, conn_id, rec.as_ptr(), total as u16, &mut s.net_scratch);

    sess.hrr_sent = true;
    sess.hs_state = HandshakeState::RecvSecondClientHello;
    true
}

unsafe fn pump_send_certificate_request(s: &mut TlsState, idx: usize) -> bool {
    let mut buf = [0u8; SCRATCH_SIZE];
    let msg_len;
    {
        let sess = &mut s.sessions[idx];
        msg_len = build_certificate_request(&mut sess.scratch);
        if let Some(ref mut t) = sess.transcript {
            t.update(&sess.scratch[..msg_len]);
        }
        core::ptr::copy_nonoverlapping(sess.scratch.as_ptr(), buf.as_mut_ptr(), msg_len);
    }
    send_encrypted_handshake(s, idx, &buf, msg_len);
    s.sessions[idx].hs_state = HandshakeState::SendCertificate;
    true
}

unsafe fn pump_recv_client_cert(s: &mut TlsState, idx: usize) -> bool {
    match recv_encrypted_handshake(s, idx) {
        Some((data, len, msg_type)) => {
            if msg_type != 11 {
                if let Some(ref mut t) = s.sessions[idx].transcript {
                    t.update(&data[..len]);
                }
                s.sessions[idx].hs_state = HandshakeState::RecvClientFinished;
                return true;
            }
            if let Some(ref mut t) = s.sessions[idx].transcript {
                t.update(&data[..len]);
            }
            if !extract_peer_cert_key(s, idx, &data[4..len]) {
                s.sessions[idx].state = SessionState::Error;
                return true;
            }
            s.sessions[idx].hs_state = HandshakeState::RecvClientCertVerify;
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
            if let Some(ref mut t) = s.sessions[idx].transcript {
                t.update(&data[..len]);
            }
            s.sessions[idx].hs_state = HandshakeState::RecvClientFinished;
            true
        }
        None => false,
    }
}

unsafe fn pump_derive_handshake_keys(s: &mut TlsState, idx: usize) -> bool {
    // A `bits_per_step` of 0 runs the whole ladder in one step() call, used
    // when the caller-configured value is >= 256.
    let bits_per_step_u8 = if s.ecdh_bits_per_step >= 256 { 0u8 } else { s.ecdh_bits_per_step as u8 };
    {
        let sess = &mut s.sessions[idx];
        if !sess.ecdh_state.is_initialised() {
            let new = match ecdh_shared_secret_init(
                &sess.ecdh_private,
                &sess.peer_key_share[..sess.peer_key_share_len as usize],
                bits_per_step_u8,
            ) {
                Some(v) => v,
                None => {
                    sess.state = SessionState::Error;
                    return true;
                }
            };
            sess.ecdh_state = new;
            // Yield after init so a second handshake can start its own ECDH
            // before we advance ladder bits for this one.
            return true;
        }

        if !sess.ecdh_state.complete() {
            sess.ecdh_state.step();
            return true;
        }
    }

    let shared = {
        let sess = &mut s.sessions[idx];
        let out = match ecdh_shared_secret_finalise(&sess.ecdh_state) {
            Some(v) => v,
            None => {
                sess.state = SessionState::Error;
                return true;
            }
        };
        sess.ecdh_state.zeroise_scalar();
        out
    };
    let sess = &mut s.sessions[idx];

    // Get transcript hash (ClientHello..ServerHello)
    let transcript_hash = match &sess.transcript {
        Some(t) => t.current_hash(),
        None => { sess.state = SessionState::Error; return true; }
    };
    let hl = sess.suite.hash_len();

    // Derive handshake secrets
    let mut ks = KeySchedule::new(sess.suite);
    ks.derive_handshake_secrets(&shared, &transcript_hash[..hl]);

    // Set traffic keys
    if sess.is_server {
        sess.write_keys = TrafficKeys::from_secret(sess.suite, &ks.server_hs_secret[..hl]);
        sess.read_keys = TrafficKeys::from_secret(sess.suite, &ks.client_hs_secret[..hl]);
    } else {
        sess.read_keys = TrafficKeys::from_secret(sess.suite, &ks.server_hs_secret[..hl]);
        sess.write_keys = TrafficKeys::from_secret(sess.suite, &ks.client_hs_secret[..hl]);
    }

    sess.key_schedule = Some(ks);

    if sess.is_server {
        s.sessions[idx].hs_state = HandshakeState::SendEncryptedExtensions;
    } else {
        s.sessions[idx].hs_state = HandshakeState::RecvEncryptedExtensions;
    }
    true
}

unsafe fn pump_send_encrypted_extensions(s: &mut TlsState, idx: usize) -> bool {
    let mut buf = [0u8; SCRATCH_SIZE];
    let msg_len;
    {
        let sess = &mut s.sessions[idx];
        msg_len = build_encrypted_extensions(&mut sess.scratch);
        if let Some(ref mut t) = sess.transcript {
            t.update(&sess.scratch[..msg_len]);
        }
        core::ptr::copy_nonoverlapping(sess.scratch.as_ptr(), buf.as_mut_ptr(), msg_len);
    }
    send_encrypted_handshake(s, idx, &buf, msg_len);
    // If mTLS (verify_peer), send CertificateRequest before Certificate
    if s.verify_peer != 0 {
        s.sessions[idx].hs_state = HandshakeState::SendCertificateRequest;
    } else {
        s.sessions[idx].hs_state = HandshakeState::SendCertificate;
    }
    true
}

unsafe fn pump_send_certificate(s: &mut TlsState, idx: usize) -> bool {
    // Bounds-checked slice indexing can pull the panic handler (and its
    // .rodata strings) into a PIC module; raw pointer + length is safe.
    let cert_len = if s.cert_len <= MAX_CERT_LEN { s.cert_len } else { 0 };
    let cert = core::slice::from_raw_parts(s.cert.as_ptr(), cert_len);
    let msg_len = build_certificate(cert, &mut s.sessions[idx].scratch);

    if let Some(ref mut t) = s.sessions[idx].transcript {
        t.update(&s.sessions[idx].scratch[..msg_len]);
    }

    let mut buf = [0u8; SCRATCH_SIZE];
    unsafe { core::ptr::copy_nonoverlapping(s.sessions[idx].scratch.as_ptr(), buf.as_mut_ptr(), msg_len); }
    send_encrypted_handshake(s, idx, &buf, msg_len);

    s.sessions[idx].hs_state = HandshakeState::SendCertificateVerify;
    true
}

unsafe fn pump_send_certificate_verify(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    let hl = sess.suite.hash_len();
    let transcript_hash = match &sess.transcript {
        Some(t) => t.current_hash(),
        None => { sess.state = SessionState::Error; return true; }
    };

    // Build signing content
    let context = b"TLS 1.3, server CertificateVerify";
    let mut verify_content = [0u8; 200];
    let vc_len = build_verify_content(context, &transcript_hash[..hl], hl, &mut verify_content);

    // Hash the verify content
    let vc_hash = sha256(&verify_content[..vc_len]);

    // Sign with private key
    let mut k_random = [0u8; 32];
    dev_csprng_fill(sys, k_random.as_mut_ptr(), 32);

    // Sign via kernel KEY_VAULT when the identity key is held there; fall
    // back to the in-module signer on ENOSYS.
    const KV_SIGN: u32 = 0x1003;
    let mut raw_sig = [0u8; 64];
    let mut signed_via_vault = false;
    if s.key_vault_handle >= 0 {
        // arg layout: [hash_len: u16 LE][pad: u16][hash[32]][sig_out[64]]
        let mut sign_arg = [0u8; 4 + 32 + 64];
        sign_arg[0] = 32;
        core::ptr::copy_nonoverlapping(vc_hash.as_ptr(), sign_arg.as_mut_ptr().add(4), 32);
        let rc = (sys.provider_call)(s.key_vault_handle, KV_SIGN, sign_arg.as_mut_ptr(), sign_arg.len());
        if rc == 0 {
            core::ptr::copy_nonoverlapping(sign_arg.as_ptr().add(4 + 32), raw_sig.as_mut_ptr(), 64);
            signed_via_vault = true;
        }
    }
    if !signed_via_vault {
        let mut priv_key = [0u8; 32];
        if s.key_len == 32 {
            core::ptr::copy_nonoverlapping(s.key.as_ptr(), priv_key.as_mut_ptr(), 32);
        } else if s.key_len > 32 {
            extract_ec_private_key(&s.key[..s.key_len], &mut priv_key);
        }
        raw_sig = ecdsa_sign(&priv_key, &vc_hash, &k_random);
        let mut j = 0;
        while j < 32 { core::ptr::write_volatile(&mut priv_key[j], 0); j += 1; }
    }
    let (der_sig, der_len) = encode_der_signature(&raw_sig);

    let msg_len = build_certificate_verify(&der_sig, der_len, &mut sess.scratch);

    if let Some(ref mut t) = sess.transcript {
        t.update(&sess.scratch[..msg_len]);
    }

    let mut buf = [0u8; SCRATCH_SIZE];
    core::ptr::copy_nonoverlapping(sess.scratch.as_ptr(), buf.as_mut_ptr(), msg_len);
    send_encrypted_handshake(s, idx, &buf, msg_len);

    s.sessions[idx].hs_state = HandshakeState::SendFinished;
    true
}

unsafe fn pump_send_finished(s: &mut TlsState, idx: usize) -> bool {
    let mut buf = [0u8; SCRATCH_SIZE];
    let msg_len;
    let is_server;
    {
        let sess = &mut s.sessions[idx];
        let hl = sess.suite.hash_len();
        is_server = sess.is_server;

        let transcript_hash = match &sess.transcript {
            Some(t) => t.current_hash(),
            None => { sess.state = SessionState::Error; return true; }
        };

        let ks = match &sess.key_schedule {
            Some(k) => k,
            None => { sess.state = SessionState::Error; return true; }
        };

        let base_key = if sess.is_server {
            &ks.server_hs_secret
        } else {
            &ks.client_hs_secret
        };
        let finished_key = ks.compute_finished(base_key);
        let verify_data = ks.finished_verify_data(&finished_key[..hl], &transcript_hash[..hl]);

        msg_len = build_finished(&verify_data[..hl], hl, &mut sess.scratch);

        if let Some(ref mut t) = sess.transcript {
            t.update(&sess.scratch[..msg_len]);
        }

        core::ptr::copy_nonoverlapping(sess.scratch.as_ptr(), buf.as_mut_ptr(), msg_len);
    }
    send_encrypted_handshake(s, idx, &buf, msg_len);

    // Save transcript hash at this point (through server Finished) for app key derivation
    if let Some(ref t) = s.sessions[idx].transcript {
        s.sessions[idx].server_finished_hash = t.current_hash();
    }

    if is_server {
        if s.verify_peer != 0 {
            // mTLS: expect client Certificate + CertificateVerify + Finished
            s.sessions[idx].hs_state = HandshakeState::RecvClientCert;
        } else {
            s.sessions[idx].hs_state = HandshakeState::RecvClientFinished;
        }
    } else {
        s.sessions[idx].hs_state = HandshakeState::ClientDeriveAppKeys;
    }
    true
}

unsafe fn pump_recv_client_finished(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    // Read encrypted record
    let msg = match recv_encrypted_handshake(s, idx) {
        Some((data, len, msg_type)) => {
            if msg_type != 20 { // HT_FINISHED
                s.sessions[idx].state = SessionState::Error;
                return true;
            }
            (data, len)
        }
        None => return false,
    };

    let sess = &mut s.sessions[idx];
    let hl = sess.suite.hash_len();

    // Get expected verify_data
    let transcript_hash = match &sess.transcript {
        Some(t) => t.current_hash(),
        None => { sess.state = SessionState::Error; return true; }
    };

    let ks = match &sess.key_schedule {
        Some(k) => k,
        None => { sess.state = SessionState::Error; return true; }
    };

    let finished_key = ks.compute_finished(&ks.client_hs_secret);
    let expected = ks.finished_verify_data(&finished_key[..hl], &transcript_hash[..hl]);

    // Verify (constant-time)
    let (data, len) = msg;
    let fin_data = &data[4..4 + hl]; // skip handshake header
    let mut diff = 0u8;
    let mut i = 0;
    while i < hl {
        diff |= fin_data[i] ^ expected[i];
        i += 1;
    }
    if diff != 0 {
        dev_log(sys, 2, b"[tls] client Finished verify failed".as_ptr(), b"[tls] client Finished verify failed".len());
        sess.state = SessionState::Error;
        return true;
    }

    // Update transcript with client Finished
    if let Some(ref mut t) = sess.transcript {
        t.update(&data[..len]);
    }

    sess.hs_state = HandshakeState::DeriveAppKeys;
    true
}

unsafe fn pump_derive_app_keys(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];
    let hl = sess.suite.hash_len();

    // Use the transcript hash saved at server Finished (per RFC 8446 Section 7.1)
    let transcript_hash = sess.server_finished_hash;

    if let Some(ref mut ks) = sess.key_schedule {
        ks.derive_app_secrets(&transcript_hash[..hl]);

        // Switch to application traffic keys
        if sess.is_server {
            sess.write_keys = TrafficKeys::from_secret(sess.suite, &ks.server_app_secret[..hl]);
            sess.read_keys = TrafficKeys::from_secret(sess.suite, &ks.client_app_secret[..hl]);
        } else {
            sess.read_keys = TrafficKeys::from_secret(sess.suite, &ks.server_app_secret[..hl]);
            sess.write_keys = TrafficKeys::from_secret(sess.suite, &ks.client_app_secret[..hl]);
        }
    }

    // Zeroize handshake secrets — they're no longer needed
    if let Some(ref mut ks) = sess.key_schedule {
        let mut i = 0;
        while i < 48 {
            unsafe {
                core::ptr::write_volatile(&mut ks.client_hs_secret[i], 0);
                core::ptr::write_volatile(&mut ks.server_hs_secret[i], 0);
            }
            i += 1;
        }
    }
    // Zeroize ephemeral private key
    {
        let mut i = 0;
        while i < 32 {
            unsafe { core::ptr::write_volatile(&mut sess.ecdh_private[i], 0); }
            i += 1;
        }
    }

    // Don't reset recv_buf — may contain app data that arrived with handshake
    sess.state = SessionState::Ready;
    sess.hs_state = HandshakeState::Complete;
    dev_log(sys, 3, b"[tls] handshake complete".as_ptr(), b"[tls] handshake complete".len());

    // Forward held MSG_ACCEPTED/MSG_CONNECTED to clear_out so HTTP knows connection is ready
    let held = sess.held_msg_type;
    let conn_id = sess.conn_id;
    if held != 0 {
        sess.held_msg_type = 0;
        tls_write_frame(sys, s.clear_out, held, conn_id, core::ptr::null(), 0, &mut s.net_scratch);
    }
    true
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
    sess.peer_session_id = session_id;
    sess.peer_session_id_len = 32;

    let msg_len = build_client_hello(&random, &session_id, &sess.ecdh_public, &mut sess.scratch);

    // Init transcript
    sess.transcript = Some(Transcript::new(HashAlg::Sha256)); // Will switch if AES-256-GCM selected
    if let Some(ref mut t) = sess.transcript {
        t.update(&sess.scratch[..msg_len]);
    }

    // Wrap in TLS record and send via channel
    let mut rec = [0u8; SEND_BUF_SIZE];
    let mut hdr = [0u8; 5];
    build_record_header(CT_HANDSHAKE, msg_len, &mut hdr);
    core::ptr::copy_nonoverlapping(hdr.as_ptr(), rec.as_mut_ptr(), 5);
    core::ptr::copy_nonoverlapping(sess.scratch.as_ptr(), rec.as_mut_ptr().add(5), msg_len);

    let conn_id = sess.conn_id;
    tls_write_frame(sys, s.cipher_out, NET_CMD_SEND, conn_id, rec.as_ptr(), (5 + msg_len) as u16, &mut s.net_scratch);

    sess.hs_state = HandshakeState::RecvServerHello;
    true
}

unsafe fn pump_recv_server_hello(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;

    {
        let sess = &mut s.sessions[idx];

        // Data arrives via cipher_in -> recv_buf in module_step; no socket read here.
        if sess.recv_len < 9 { return false; }

        skip_ccs(sess);
        if sess.recv_len < 9 { return false; }

        let rec_type = sess.recv_buf[0];
        let rec_len = ((sess.recv_buf[3] as usize) << 8) | (sess.recv_buf[4] as usize);
        if sess.recv_len < 5 + rec_len { return false; }
        if rec_type != CT_HANDSHAKE { return false; }

        let hs_data = &sess.recv_buf[5..5 + rec_len];
        if hs_data[0] != 2 { return false; } // ServerHello
        let hs_len = ((hs_data[1] as usize) << 16) | ((hs_data[2] as usize) << 8) | (hs_data[3] as usize);

        let sh = match parse_server_hello(&hs_data[4..4 + hs_len]) {
            Some(h) => h,
            None => { sess.state = SessionState::Error; return true; }
        };

        // Validate TLS 1.3
        if sh.supported_version != Some(0x0304) {
            sess.state = SessionState::Error;
            return true;
        }

        // Check for HelloRetryRequest (magic random value)
        if sh.random.len() == 32 && sh.random == HRR_RANDOM {
            // Server requests retry with different key share
            // Update transcript: add this HRR to it
            if let Some(ref mut t) = sess.transcript {
                t.update(hs_data);
            }
            // Consume record
            let consumed = 5 + rec_len;
            let remain = sess.recv_len - consumed;
            if remain > 0 {
                core::ptr::copy(sess.recv_buf.as_ptr().add(consumed), sess.recv_buf.as_mut_ptr(), remain);
            }
            sess.recv_len = remain;
            // Client needs to send a new ClientHello (with P-256 key share)
            // For now, since we already offer P-256, this shouldn't happen.
            // If it does, error — we can't change our key share.
            sess.state = SessionState::Error;
            return true;
        }

        // Set cipher suite
        sess.suite = match CipherSuite::from_id(sh.cipher_suite) {
            Some(cs) => cs,
            None => { sess.state = SessionState::Error; return true; }
        };

        // Switch transcript to correct hash algorithm for negotiated suite.
        if let Some(ref mut t) = sess.transcript {
            t.set_alg(sess.suite.hash_alg());
        }

        // Extract server key share
        match sh.key_share {
            Some((_, key_data)) if key_data.len() <= 65 => {
                core::ptr::copy_nonoverlapping(key_data.as_ptr(), sess.peer_key_share.as_mut_ptr(), key_data.len());
                sess.peer_key_share_len = key_data.len() as u8;
            }
            _ => { sess.state = SessionState::Error; return true; }
        }

        // Update transcript with ServerHello
        if let Some(ref mut t) = sess.transcript {
            t.update(hs_data);
        }

        // Consume record
        let consumed = 5 + rec_len;
        let remain = sess.recv_len - consumed;
        if remain > 0 {
            core::ptr::copy(sess.recv_buf.as_ptr().add(consumed), sess.recv_buf.as_mut_ptr(), remain);
        }
        sess.recv_len = remain;
    } // drop `sess` borrow

    s.sessions[idx].hs_state = HandshakeState::ClientDeriveHandshakeKeys;
    true
}

unsafe fn pump_recv_encrypted(s: &mut TlsState, idx: usize, expected_type: u8, next_state: HandshakeState) -> bool {
    match recv_encrypted_handshake(s, idx) {
        Some((data, len, msg_type)) => {
            if msg_type != expected_type {
                s.sessions[idx].state = SessionState::Error;
                return true;
            }
            // Update transcript
            if let Some(ref mut t) = s.sessions[idx].transcript {
                t.update(&data[..len]);
            }
            s.sessions[idx].hs_state = next_state;
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
            if let Some(ref mut t) = s.sessions[idx].transcript {
                t.update(&data[..len]);
            }
            if !extract_peer_cert_key(s, idx, &data[4..len]) {
                s.sessions[idx].state = SessionState::Error;
                return true;
            }
            s.sessions[idx].hs_state = HandshakeState::RecvCertificateVerify;
            true
        }
        None => false,
    }
}

unsafe fn pump_recv_certificate_verify(s: &mut TlsState, idx: usize) -> bool {
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
            if let Some(ref mut t) = s.sessions[idx].transcript {
                t.update(&data[..len]);
            }
            s.sessions[idx].hs_state = HandshakeState::RecvFinished;
            true
        }
        None => false,
    }
}

unsafe fn pump_recv_server_finished(s: &mut TlsState, idx: usize) -> bool {
    match recv_encrypted_handshake(s, idx) {
        Some((data, len, msg_type)) => {
            if msg_type != 20 {
                s.sessions[idx].state = SessionState::Error;
                return true;
            }
            let sess = &mut s.sessions[idx];
            let hl = sess.suite.hash_len();

            // Verify server Finished
            let transcript_hash = match &sess.transcript {
                Some(t) => t.current_hash(),
                None => { sess.state = SessionState::Error; return true; }
            };
            if let Some(ref ks) = sess.key_schedule {
                let finished_key = ks.compute_finished(&ks.server_hs_secret);
                let expected = ks.finished_verify_data(&finished_key[..hl], &transcript_hash[..hl]);
                let fin_data = &data[4..4 + hl];
                let mut diff = 0u8;
                let mut i = 0;
                while i < hl { diff |= fin_data[i] ^ expected[i]; i += 1; }
                if diff != 0 {
                    sess.state = SessionState::Error;
                    return true;
                }
            }

            if let Some(ref mut t) = sess.transcript {
                t.update(&data[..len]);
            }
            // Save transcript hash for app key derivation (through server Finished)
            if let Some(ref t) = sess.transcript {
                sess.server_finished_hash = t.current_hash();
            }
            sess.hs_state = HandshakeState::SendClientFinished;
            true
        }
        None => false,
    }
}

unsafe fn pump_send_client_finished(s: &mut TlsState, idx: usize) -> bool {
    let mut buf = [0u8; SCRATCH_SIZE];
    let msg_len;
    {
        let sess = &mut s.sessions[idx];
        let hl = sess.suite.hash_len();

        let transcript_hash = match &sess.transcript {
            Some(t) => t.current_hash(),
            None => { sess.state = SessionState::Error; return true; }
        };

        let ks = match &sess.key_schedule {
            Some(k) => k,
            None => { sess.state = SessionState::Error; return true; }
        };

        let finished_key = ks.compute_finished(&ks.client_hs_secret);
        let verify_data = ks.finished_verify_data(&finished_key[..hl], &transcript_hash[..hl]);

        msg_len = build_finished(&verify_data[..hl], hl, &mut sess.scratch);

        if let Some(ref mut t) = sess.transcript {
            t.update(&sess.scratch[..msg_len]);
        }

        core::ptr::copy_nonoverlapping(sess.scratch.as_ptr(), buf.as_mut_ptr(), msg_len);
    }
    send_encrypted_handshake(s, idx, &buf, msg_len);

    s.sessions[idx].hs_state = HandshakeState::ClientDeriveAppKeys;
    true
}

// ============================================================================
// Encrypted record helpers
// ============================================================================

/// Send an encrypted handshake record via cipher_out channel
unsafe fn send_encrypted_handshake(s: &mut TlsState, idx: usize, msg: &[u8], msg_len: usize) {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    let mut enc_buf = [0u8; SEND_BUF_SIZE];
    let enc_len = encrypt_record(sess.suite, &mut sess.write_keys, CT_HANDSHAKE, &msg[..msg_len], &mut enc_buf);

    let mut rec = [0u8; SEND_BUF_SIZE + 5];
    *rec.as_mut_ptr() = CT_APPLICATION_DATA;
    *rec.as_mut_ptr().add(1) = 0x03;
    *rec.as_mut_ptr().add(2) = 0x03;
    *rec.as_mut_ptr().add(3) = (enc_len >> 8) as u8;
    *rec.as_mut_ptr().add(4) = enc_len as u8;
    core::ptr::copy_nonoverlapping(enc_buf.as_ptr(), rec.as_mut_ptr().add(5), enc_len);

    let total = 5 + enc_len;
    let conn_id = sess.conn_id;
    tls_write_frame(sys, s.cipher_out, NET_CMD_SEND, conn_id, rec.as_ptr(), total as u16, &mut s.net_scratch);
}

/// Try to receive and decrypt an encrypted handshake record.
/// Returns (decrypted_data_in_scratch, length, handshake_msg_type) or None if not enough data.
/// Data arrives via cipher_in -> recv_buf in module_step; no socket read here.
unsafe fn recv_encrypted_handshake(s: &mut TlsState, idx: usize) -> Option<([u8; SCRATCH_SIZE], usize, u8)> {
    let sess = &mut s.sessions[idx];

    skip_ccs(sess);

    if sess.recv_len < 5 { return None; }

    let rec_type = sess.recv_buf[0];
    let rec_len = ((sess.recv_buf[3] as usize) << 8) | (sess.recv_buf[4] as usize);
    if sess.recv_len < 5 + rec_len { return None; }

    if rec_type != CT_APPLICATION_DATA {
        // Unexpected record type during handshake
        return None;
    }

    // Decrypt
    let mut hdr = [0u8; 5];
    core::ptr::copy_nonoverlapping(sess.recv_buf.as_ptr(), hdr.as_mut_ptr(), 5);
    let mut ct = [0u8; RECV_BUF_SIZE];
    core::ptr::copy_nonoverlapping(sess.recv_buf.as_ptr().add(5), ct.as_mut_ptr(), rec_len);

    let consumed = 5 + rec_len;
    let remain = sess.recv_len - consumed;
    if remain > 0 {
        core::ptr::copy(sess.recv_buf.as_ptr().add(consumed), sess.recv_buf.as_mut_ptr(), remain);
    }
    sess.recv_len = remain;

    match decrypt_record(sess.suite, &mut sess.read_keys, &hdr, &mut ct[..rec_len]) {
        Some((pt_len, inner_type)) => {
            if inner_type != CT_HANDSHAKE {
                return None;
            }
            // Accumulate into scratch for reassembly
            if sess.hs_accum_len >= SCRATCH_SIZE {
                s.sessions[idx].state = SessionState::Error;
                return None;
            }
            let space = SCRATCH_SIZE - sess.hs_accum_len;
            let copy_len = if pt_len < space { pt_len } else { space };
            if copy_len == 0 && pt_len > 0 {
                s.sessions[idx].state = SessionState::Error;
                return None; // Scratch overflow
            }
            core::ptr::copy_nonoverlapping(
                ct.as_ptr(),
                sess.scratch.as_mut_ptr().add(sess.hs_accum_len),
                copy_len,
            );
            sess.hs_accum_len += copy_len;

            // Check if handshake message is complete
            if sess.hs_accum_len < 4 {
                // Don't have handshake header yet — need more records
                return None;
            }
            let hs_msg_len = ((sess.scratch[1] as usize) << 16)
                | ((sess.scratch[2] as usize) << 8)
                | (sess.scratch[3] as usize);
            let total_needed = 4 + hs_msg_len;
            if total_needed > SCRATCH_SIZE {
                // Message too large for scratch buffer
                s.sessions[idx].state = SessionState::Error;
                return None;
            }
            if sess.hs_accum_len < total_needed {
                // Fragmented — need more records
                return None;
            }

            let total = sess.hs_accum_len;
            sess.hs_accum_len = 0; // Reset for next message
            let mut out = [0u8; SCRATCH_SIZE];
            core::ptr::copy_nonoverlapping(sess.scratch.as_ptr(), out.as_mut_ptr(), total);
            let hs_type = if total > 0 { out[0] } else { 0 };
            Some((out, total, hs_type))
        }
        None => {
            s.sessions[idx].state = SessionState::Error;
            None
        }
    }
}

/// Send an encrypted alert via cipher_out channel
unsafe fn send_alert(s: &mut TlsState, idx: usize, description: u8) {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    let alert_body = build_alert(description);
    let mut enc_buf = [0u8; 64];
    let enc_len = encrypt_record(sess.suite, &mut sess.write_keys, CT_ALERT, &alert_body, &mut enc_buf);

    let mut rec = [0u8; 69];
    *rec.as_mut_ptr() = CT_APPLICATION_DATA;
    *rec.as_mut_ptr().add(1) = 0x03;
    *rec.as_mut_ptr().add(2) = 0x03;
    *rec.as_mut_ptr().add(3) = (enc_len >> 8) as u8;
    *rec.as_mut_ptr().add(4) = enc_len as u8;
    core::ptr::copy_nonoverlapping(enc_buf.as_ptr(), rec.as_mut_ptr().add(5), enc_len);

    let total = 5 + enc_len;
    let conn_id = sess.conn_id;
    tls_write_frame(sys, s.cipher_out, NET_CMD_SEND, conn_id, rec.as_ptr(), total as u16, &mut s.net_scratch);
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
    if n < 3 { return (0, 0); }
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
unsafe fn tls_write_frame(
    sys: &SyscallTable,
    chan: i32,
    msg_type: u8,
    conn_id: u8,
    data: *const u8,
    data_len: u16,
    scratch: &mut [u8; NET_SCRATCH_SIZE],
) {
    let total_payload = 1u16 + data_len; // conn_id + data
    let frame_len = 3 + total_payload as usize;
    if frame_len > NET_SCRATCH_SIZE { return; }
    // Assemble complete frame in scratch
    *scratch.as_mut_ptr() = msg_type;
    *scratch.as_mut_ptr().add(1) = total_payload as u8;
    *scratch.as_mut_ptr().add(2) = (total_payload >> 8) as u8;
    *scratch.as_mut_ptr().add(3) = conn_id;
    if data_len > 0 && !data.is_null() {
        core::ptr::copy_nonoverlapping(data, scratch.as_mut_ptr().add(4), data_len as usize);
    }
    (sys.channel_write)(chan, scratch.as_ptr(), frame_len);
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
    if delta == 0 || delta > sess.retx_len as u32 { return; }
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
        if !sess.retx_seq_anchored { return; }
        let off = from_seq.wrapping_sub(sess.retx_base_seq);
        if off >= sess.retx_len as u32 { return; }
        (off as usize, sess.retx_len as usize)
    };
    let bytes = len - offset;
    let mut local = [0u8; RETX_BUF_SIZE];
    core::ptr::copy_nonoverlapping(
        s.sessions[idx].retx_buf.as_ptr().add(offset),
        local.as_mut_ptr(),
        bytes,
    );
    let sys = &*s.syscalls;
    let conn_id = s.sessions[idx].conn_id;
    tls_write_frame(sys, s.cipher_out, NET_CMD_SEND, conn_id,
                    local.as_ptr(), bytes as u16, &mut s.net_scratch);
}

/// Write a raw net_proto frame (no conn_id prefix — used for pass-through).
/// Payload must already be in a buffer that can be prepended with a 3-byte
/// header. Uses a stack buffer to assemble atomically.
unsafe fn tls_write_raw_frame(
    sys: &SyscallTable,
    chan: i32,
    msg_type: u8,
    payload: *const u8,
    payload_len: u16,
) {
    let frame_len = 3 + payload_len as usize;
    let mut frame = [0u8; 256];
    if frame_len > 256 { return; }
    frame[0] = msg_type;
    frame[1] = payload_len as u8;
    frame[2] = (payload_len >> 8) as u8;
    if payload_len > 0 && !payload.is_null() {
        core::ptr::copy_nonoverlapping(payload, frame.as_mut_ptr().add(3), payload_len as usize);
    }
    (sys.channel_write)(chan, frame.as_ptr(), frame_len);
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

    if sess.recv_len < 5 { return; }

    let rec_type = *sess.recv_buf.as_ptr();
    let rec_len = ((*sess.recv_buf.as_ptr().add(3) as usize) << 8) | (*sess.recv_buf.as_ptr().add(4) as usize);
    if sess.recv_len < 5 + rec_len { return; }

    if rec_type == CT_CHANGE_CIPHER_SPEC {
        // Skip CCS
        let consumed = 5 + rec_len;
        let remain = sess.recv_len - consumed;
        if remain > 0 {
            core::ptr::copy(sess.recv_buf.as_ptr().add(consumed), sess.recv_buf.as_mut_ptr(), remain);
        }
        sess.recv_len = remain;
        return;
    }

    if rec_type != CT_APPLICATION_DATA { return; }

    // Copy header + ciphertext for decryption
    let mut hdr = [0u8; 5];
    core::ptr::copy_nonoverlapping(sess.recv_buf.as_ptr(), hdr.as_mut_ptr(), 5);
    let mut ct = [0u8; RECV_BUF_SIZE];
    core::ptr::copy_nonoverlapping(sess.recv_buf.as_ptr().add(5), ct.as_mut_ptr(), rec_len);

    // Consume record from recv_buf
    let consumed = 5 + rec_len;
    let remain = sess.recv_len - consumed;
    if remain > 0 {
        core::ptr::copy(sess.recv_buf.as_ptr().add(consumed), sess.recv_buf.as_mut_ptr(), remain);
    }
    sess.recv_len = remain;

    match decrypt_record(sess.suite, &mut sess.read_keys, &hdr, &mut ct[..rec_len]) {
        Some((pt_len, inner_type)) => {
            if inner_type == CT_ALERT {
                if pt_len >= 2 && *ct.as_ptr().add(1) == ALERT_CLOSE_NOTIFY {
                    sess.state = SessionState::Closed;
                    let conn_id = sess.conn_id;
                    tls_write_frame(sys, s.clear_out, NET_MSG_CLOSED, conn_id, core::ptr::null(), 0, &mut s.net_scratch);
                    return;
                }
                sess.state = SessionState::Error;
                return;
            }
            if inner_type == CT_APPLICATION_DATA && pt_len > 0 {
                // Forward decrypted data as MSG_DATA(conn_id, plaintext) to clear_out
                let conn_id = sess.conn_id;
                tls_write_frame(sys, s.clear_out, NET_MSG_DATA, conn_id, ct.as_ptr(), pt_len as u16, &mut s.net_scratch);
            }
        }
        None => {
            sess.state = SessionState::Error;
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Extract raw EC private key from SEC1 or PKCS#8 DER encoding
/// Extract EC private key (32 bytes) from SEC1 or PKCS#8 DER encoding.
/// SEC1: SEQUENCE { INTEGER(1), OCTET STRING(32), ... }
/// PKCS#8: SEQUENCE { INTEGER(0), SEQUENCE{OIDs}, OCTET STRING { SEC1 } }
unsafe fn extract_ec_private_key(der: &[u8], out: &mut [u8; 32]) {
    if der.len() < 4 { return; }
    // Must start with SEQUENCE
    if der[0] != 0x30 { return; }
    let (seq_start, seq_len, _) = match der_tlv(der, 0) { Some(v) => v, None => return };

    // Check first element: INTEGER with version
    let mut pos = seq_start;
    if pos >= der.len() || der[pos] != 0x02 { return; }
    let (int_start, int_len, int_total) = match der_tlv(der, pos) { Some(v) => v, None => return };
    let version = if int_len == 1 { der[int_start] } else { 0xFF };
    pos += int_total;

    if version == 1 {
        // SEC1 ECPrivateKey: next is OCTET STRING with the private key
        if pos < der.len() && der[pos] == 0x04 {
            let (os_start, os_len, _) = match der_tlv(der, pos) { Some(v) => v, None => return };
            if os_len == 32 && os_start + 32 <= der.len() {
                core::ptr::copy_nonoverlapping(der.as_ptr().add(os_start), out.as_mut_ptr(), 32);
            }
        }
    } else if version == 0 {
        // PKCS#8: skip AlgorithmIdentifier SEQUENCE, then OCTET STRING wrapping SEC1
        if pos < der.len() && der[pos] == 0x30 {
            let (_, _, alg_total) = match der_tlv(der, pos) { Some(v) => v, None => return };
            pos += alg_total;
        }
        // OCTET STRING containing the SEC1 ECPrivateKey
        if pos < der.len() && der[pos] == 0x04 {
            let (inner_start, inner_len, _) = match der_tlv(der, pos) { Some(v) => v, None => return };
            // Recurse into the inner SEC1 structure
            let inner = &der[inner_start..inner_start + inner_len];
            extract_ec_private_key(inner, out);
        }
    }
}


// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
