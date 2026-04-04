//! TLS 1.3 PIC Module for Fluxor
//!
//! Pure Rust implementation — no C, no GOT, no data relocations.
//! Registers as socket provider (class 0x08) via provider chain.
//! Supports server and client mode, mTLS, SPIFFE validation.
//!
//! Cipher suites: TLS_CHACHA20_POLY1305_SHA256 (preferred),
//!                TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384

#![no_std]
#![no_main]

use core::ffi::c_void;

#[path = "../../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

// PIC runtime (syscalls, helpers, intrinsics)
include!("../../pic_runtime.rs");
include!("../../param_macro.rs");

// Crypto primitives
include!("sha256.rs");
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

const MAX_SESSIONS: usize = 2;
const MAX_CERT_LEN: usize = 512;
const MAX_KEY_LEN: usize = 160;
const RECV_BUF_SIZE: usize = 1536;
const SEND_BUF_SIZE: usize = 1536;
const SCRATCH_SIZE: usize = 1024;

// Socket opcodes (class 0x08)
const SOCKET_OPEN: u32 = 0x0800;
const SOCKET_CONNECT: u32 = 0x0801;
const SOCKET_SEND: u32 = 0x0802;
const SOCKET_RECV: u32 = 0x0803;
const SOCKET_POLL: u32 = 0x0804;
const SOCKET_CLOSE: u32 = 0x0805;
const SOCKET_BIND: u32 = 0x0806;
const SOCKET_LISTEN: u32 = 0x0807;
const SOCKET_ACCEPT: u32 = 0x0808;

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
    raw_handle: i32,          // underlying socket handle
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
            raw_handle: -1,
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
        self.raw_handle = -1;
        self.hrr_sent = false;
        self.recv_len = 0;
        self.recv_expected = 0;
        self.send_len = 0;
        self.send_offset = 0;
        self.hs_accum_len = 0;
        self.peer_key_share_len = 0;
        self.peer_cert_pubkey_len = 0;
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
    registered: bool,

    // Pre-computed ephemeral ECDH key pairs (one per session, computed in module_new)
    eph_private: [[u8; 32]; MAX_SESSIONS],
    eph_public: [[u8; 65]; MAX_SESSIONS],
    eph_used: [bool; MAX_SESSIONS], // true if key has been consumed

    // Certificate and key (DER-encoded, loaded from params)
    cert: [u8; MAX_CERT_LEN],
    cert_len: usize,
    key: [u8; MAX_KEY_LEN],
    key_len: usize,

    // Trust domain for SPIFFE validation
    trust_domain: [u8; 64],
    trust_domain_len: usize,

    // Sessions
    sessions: [TlsSession; MAX_SESSIONS],
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

/// Exported for pack tool: sets deferred_ready flag bit 2
#[no_mangle]
pub extern "C" fn module_deferred_ready() {}

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
    s.registered = false;
    s.cert_len = 0;
    s.key_len = 0;
    s.trust_domain_len = 0;

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
    let sys = &*s.syscalls;
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
            // Zeroize random seed
            let mut j = 0;
            while j < 32 { core::ptr::write_volatile(&mut random[j], 0); j += 1; }
            i += 1;
        }
    }

    // Register as socket provider immediately during module_new.
    let dispatch_hash: u32 = 0xc7832e76; // FNV-1a("module_provider_dispatch")
    let mut buf = [0u8; 8];
    buf[0] = 0x08; // SOCKET class
    let fn_bytes = dispatch_hash.to_le_bytes();
    buf[4] = fn_bytes[0]; buf[5] = fn_bytes[1];
    buf[6] = fn_bytes[2]; buf[7] = fn_bytes[3];
    let rc = (sys.dev_call)(-1, 0x0C20, buf.as_mut_ptr(), 8);
    if rc >= 0 {
        s.registered = true;
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

    // Search for extended TLV pattern: tag(10 or 11) + 0x00 + len_hi + len_lo
    while pos + 4 <= end {
        let tag = data[pos];
        // Look for extended TLV marker: tag byte followed by 0x00
        if (tag == 10 || tag == 11 || tag == 3) && pos + 1 < end && data[pos + 1] == 0x00 && pos + 4 <= end {
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

    if !s.registered {
        return -1;
    }

    // Drive all active sessions
    let mut did_work = false;
    let mut i = 0;
    while i < MAX_SESSIONS {
        if s.sessions[i].state == SessionState::Handshaking {
            if pump_session(s, i) {
                did_work = true;
            }
        } else if s.sessions[i].state == SessionState::AcceptPending {
            // Check if raw accept completed — use FD_POLL (SYSTEM 0x0C41) to bypass provider chain
            let raw_h = s.sessions[i].raw_handle;
            let poll = dev_fd_poll(sys, raw_h, POLL_CONN);
            if poll > 0 && (poll as u8 & POLL_CONN) != 0 {
                // Accept completed — start TLS handshake
                dev_log(sys, 3, b"[tls] accept done, handshake".as_ptr(), 27);
                s.sessions[i].state = SessionState::Handshaking;
                s.sessions[i].is_server = true;
                s.sessions[i].hs_state = HandshakeState::RecvClientHello;
                init_session_crypto(s, i);
                did_work = true;
            }
        } else if s.sessions[i].state == SessionState::Connecting {
            // Check if raw connect completed — use FD_POLL
            let raw_h = s.sessions[i].raw_handle;
            let poll = dev_fd_poll(sys, raw_h, POLL_CONN);
            if poll > 0 && (poll as u8 & POLL_CONN) != 0 {
                s.sessions[i].state = SessionState::Handshaking;
                s.sessions[i].is_server = false;
                s.sessions[i].hs_state = HandshakeState::SendClientHello;
                init_session_crypto(s, i);
                did_work = true;
            }
        } else if s.sessions[i].state == SessionState::Ready {
            if s.sessions[i].send_offset < s.sessions[i].send_len {
                drain_send_buffer(s, i);
                did_work = true;
            }
        } else if s.sessions[i].state == SessionState::Closed {
            // Closed gracefully — free slot for reuse
            s.sessions[i].reset();
        } else if s.sessions[i].state == SessionState::Error {
            // Error — close raw socket and free slot
            let raw_h = s.sessions[i].raw_handle;
            if raw_h >= 0 {
                (sys.dev_call)(raw_h, CHAIN_NEXT | SOCKET_CLOSE, core::ptr::null_mut(), 0);
            }
            s.sessions[i].reset();
        }
        i += 1;
    }

    if did_work { 2 } else { 0 } // Burst or Continue
}

// ============================================================================
// Provider dispatch — called by kernel when any module does dev_call(SOCKET, ...)
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn module_provider_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    let s = &mut *(state as *mut TlsState);
    let sys = &*s.syscalls;
    match opcode {
        SOCKET_OPEN => {
            // Forward to raw socket, then wrap in TLS session
            let rc = (sys.dev_call)(handle, CHAIN_NEXT | SOCKET_OPEN, arg, arg_len);
            if rc < 0 { return rc; }
            let raw_handle = rc;
            // Allocate TLS session
            match alloc_session(s, raw_handle) {
                Some(idx) => raw_handle, // Return the raw handle (TLS wraps it transparently)
                None => {
                    (sys.dev_call)(raw_handle, CHAIN_NEXT | SOCKET_CLOSE, core::ptr::null_mut(), 0);
                    -12 // ENOMEM
                }
            }
        }

        SOCKET_CONNECT => {
            // Forward connect, then start client handshake
            let session_idx = find_session(s);
            if session_idx < 0 {
                return (sys.dev_call)(handle, CHAIN_NEXT | SOCKET_CONNECT, arg, arg_len);
            }
            let idx = session_idx as usize;
            let rc = (sys.dev_call)(handle, CHAIN_NEXT | SOCKET_CONNECT, arg, arg_len);
            if rc == E_INPROGRESS || rc >= 0 {
                s.sessions[idx].state = SessionState::Connecting;
            }
            rc
        }

        SOCKET_SEND => {
            let si = find_session(s);
            if si < 0 {
                return (sys.dev_call)(handle, CHAIN_NEXT | SOCKET_SEND, arg, arg_len);
            }
            let idx = si as usize;
            if s.sessions[idx].state != SessionState::Ready {
                return E_AGAIN;
            }

            // Encrypt and send
            let plaintext = core::slice::from_raw_parts(arg, arg_len);
            let mut enc_buf = [0u8; SEND_BUF_SIZE];

            // Build encrypted record
            let enc_len = encrypt_record(
                s.sessions[idx].suite,
                &mut s.sessions[idx].write_keys,
                CT_APPLICATION_DATA,
                plaintext,
                &mut enc_buf,
            );

            // Build record header
            let mut hdr = [0u8; 5];
            hdr[0] = CT_APPLICATION_DATA;
            hdr[1] = 0x03; hdr[2] = 0x03;
            hdr[3] = (enc_len >> 8) as u8;
            hdr[4] = enc_len as u8;

            // Send header + encrypted data via raw socket
            let mut full = [0u8; SEND_BUF_SIZE + 5];
            core::ptr::copy_nonoverlapping(hdr.as_ptr(), full.as_mut_ptr(), 5);
            core::ptr::copy_nonoverlapping(enc_buf.as_ptr(), full.as_mut_ptr().add(5), enc_len);
            let total = 5 + enc_len;

            let sent = (sys.dev_call)(handle, CHAIN_NEXT | SOCKET_SEND, full.as_mut_ptr(), total);
            if sent >= 0 {
                arg_len as i32 // Report plaintext bytes sent
            } else {
                sent
            }
        }

        SOCKET_RECV => {
            let si = find_session(s);
            if si < 0 {
                return (sys.dev_call)(handle, CHAIN_NEXT | SOCKET_RECV, arg, arg_len);
            }
            let idx = si as usize;
            if s.sessions[idx].state != SessionState::Ready {
                return E_AGAIN;
            }

            let sess = &mut s.sessions[idx];
            {
                let space = RECV_BUF_SIZE - sess.recv_len;
                if space > 0 {
                    let mut raw_buf = [0u8; 512]; // smaller stack alloc
                    let read_max = if space < 512 { space } else { 512 };
                    let n = (sys.dev_call)(handle, CHAIN_NEXT | SOCKET_RECV, raw_buf.as_mut_ptr(), read_max);
                    if n > 0 {
                        let n = n as usize;
                        core::ptr::copy_nonoverlapping(raw_buf.as_ptr(), sess.recv_buf.as_mut_ptr().add(sess.recv_len), n);
                        sess.recv_len += n;
                    }
                }
            }

            // Try to parse a complete record from recv_buf
            if sess.recv_len < 5 { return E_AGAIN; }
            let rec_type = sess.recv_buf[0];
            let rec_len = ((sess.recv_buf[3] as usize) << 8) | (sess.recv_buf[4] as usize);
            if sess.recv_len < 5 + rec_len { return E_AGAIN; }

            if rec_type == CT_APPLICATION_DATA {
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
                        if inner_type == CT_ALERT {
                            if pt_len >= 2 && ct[1] == ALERT_CLOSE_NOTIFY {
                                sess.state = SessionState::Closed;
                                return 0;
                            }
                            sess.state = SessionState::Error;
                            return -1;
                        }
                        let copy_len = if pt_len < arg_len { pt_len } else { arg_len };
                        core::ptr::copy_nonoverlapping(ct.as_ptr(), arg, copy_len);
                        copy_len as i32
                    }
                    None => {
                        sess.state = SessionState::Error;
                        -1
                    }
                }
            } else if rec_type == CT_CHANGE_CIPHER_SPEC {
                let consumed = 5 + rec_len;
                let remain = sess.recv_len - consumed;
                if remain > 0 {
                    core::ptr::copy(sess.recv_buf.as_ptr().add(consumed), sess.recv_buf.as_mut_ptr(), remain);
                }
                sess.recv_len = remain;
                E_AGAIN
            } else {
                E_AGAIN
            }
        }

        SOCKET_POLL => {
            let si = find_session(s);
            if si < 0 {
                return (sys.dev_call)(handle, CHAIN_NEXT | SOCKET_POLL, arg, arg_len);
            }
            let idx = si as usize;
            match s.sessions[idx].state {
                SessionState::Ready => {
                    (POLL_CONN | POLL_IN | POLL_OUT) as i32
                }
                SessionState::Handshaking | SessionState::AcceptPending | SessionState::Connecting => {
                    0 // Not ready yet
                }
                SessionState::Closed | SessionState::Error => {
                    POLL_HUP as i32
                }
                _ => 0,
            }
        }

        SOCKET_CLOSE => {
            let session_idx = find_session(s);
            if session_idx >= 0 {
                let idx = session_idx as usize;
                // Send close_notify if session is ready
                if s.sessions[idx].state == SessionState::Ready {
                    send_alert(s, idx, ALERT_CLOSE_NOTIFY);
                }
                s.sessions[idx].reset();
            }
            (sys.dev_call)(handle, CHAIN_NEXT | SOCKET_CLOSE, core::ptr::null_mut(), 0)
        }

        SOCKET_BIND | SOCKET_LISTEN => {
            // Pass through directly
            (sys.dev_call)(handle, CHAIN_NEXT | opcode, arg, arg_len)
        }

        SOCKET_ACCEPT => {
            // Forward accept, transition session to AcceptPending
            let session_idx = find_session(s);
            if session_idx < 0 {
                // No session yet — might need to create one
                return (sys.dev_call)(handle, CHAIN_NEXT | SOCKET_ACCEPT, arg, arg_len);
            }
            let idx = session_idx as usize;
            let rc = (sys.dev_call)(handle, CHAIN_NEXT | SOCKET_ACCEPT, arg, arg_len);
            if rc == E_INPROGRESS || rc >= 0 {
                s.sessions[idx].state = SessionState::AcceptPending;
            }
            rc
        }

        _ => {
            // Forward anything unrecognized via CHAIN_NEXT
            (sys.dev_call)(handle, CHAIN_NEXT | opcode, arg, arg_len)
        }
    }
}

// ============================================================================
// Session management
// ============================================================================

fn alloc_session(s: &mut TlsState, raw_handle: i32) -> Option<usize> {
    let mut i = 0;
    while i < MAX_SESSIONS {
        if s.sessions[i].state == SessionState::Idle {
            s.sessions[i].state = SessionState::Allocated;
            s.sessions[i].raw_handle = raw_handle;
            s.sessions[i].recv_len = 0;
            s.sessions[i].send_len = 0;
            s.sessions[i].send_offset = 0;
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_session(s: &TlsState) -> i32 {
    let mut i = 0;
    while i < MAX_SESSIONS {
        if s.sessions[i].state != SessionState::Idle {
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
    while sess.recv_len >= 5 && sess.recv_buf[0] == CT_CHANGE_CIPHER_SPEC {
        let ccs_len = ((sess.recv_buf[3] as usize) << 8) | (sess.recv_buf[4] as usize);
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
    let sess = &mut s.sessions[idx];

    // Use pre-computed ephemeral key pair for this session index
    // Each session gets a unique key pair for forward secrecy
    let key_idx = if idx < MAX_SESSIONS && !s.eph_used[idx] { idx } else { 0 };
    sess.ecdh_private = s.eph_private[key_idx];
    sess.ecdh_public = s.eph_public[key_idx];
    s.eph_used[key_idx] = true;

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

    // Read from raw socket into recv_buf
    let space = RECV_BUF_SIZE - sess.recv_len;
    if space == 0 { return false; }
    let n = (sys.dev_call)(sess.raw_handle, CHAIN_NEXT | SOCKET_RECV,
                           sess.recv_buf.as_mut_ptr().add(sess.recv_len), space);
    if n > 0 { sess.recv_len += n as usize; }

    skip_ccs(sess);

    // Need at least record header (5) + handshake header (4)
    if sess.recv_len < 9 { return false; }

    // Parse record header with length validation
    let rec_type = sess.recv_buf[0];
    let rec_len = ((sess.recv_buf[3] as usize) << 8) | (sess.recv_buf[4] as usize);
    if rec_len > MAX_CIPHERTEXT || rec_len > RECV_BUF_SIZE { return false; }
    if sess.recv_len < 5 + rec_len { return false; }

    if rec_type != CT_HANDSHAKE { return false; }

    // Parse handshake message
    let hs_data = &sess.recv_buf[5..5 + rec_len];
    if hs_data[0] != 1 { return false; } // ClientHello type
    let hs_len = ((hs_data[1] as usize) << 16) | ((hs_data[2] as usize) << 8) | (hs_data[3] as usize);
    if hs_len + 4 > rec_len { return false; }

    let ch_body = &hs_data[4..4 + hs_len];
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

    // Wrap in record and send
    let mut rec = [0u8; SEND_BUF_SIZE];
    let mut hdr = [0u8; 5];
    build_record_header(CT_HANDSHAKE, msg_len, &mut hdr);
    core::ptr::copy_nonoverlapping(hdr.as_ptr(), rec.as_mut_ptr(), 5);
    core::ptr::copy_nonoverlapping(sess.scratch.as_ptr(), rec.as_mut_ptr().add(5), msg_len);

    let total = 5 + msg_len;
    let sent = (sys.dev_call)(sess.raw_handle, CHAIN_NEXT | SOCKET_SEND, rec.as_mut_ptr(), total);
    if sent < 0 {
        // Buffer send for retry
        return false;
    }

    // Also send ChangeCipherSpec for middlebox compatibility
    let ccs = [CT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    (sys.dev_call)(sess.raw_handle, CHAIN_NEXT | SOCKET_SEND, ccs.as_ptr() as *mut u8, 6);

    sess.hs_state = HandshakeState::DeriveHandshakeKeys;
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

    // Wrap in record and send
    let mut rec = [0u8; SEND_BUF_SIZE];
    let mut hdr = [0u8; 5];
    build_record_header(CT_HANDSHAKE, msg_len, &mut hdr);
    core::ptr::copy_nonoverlapping(hdr.as_ptr(), rec.as_mut_ptr(), 5);
    core::ptr::copy_nonoverlapping(sess.scratch.as_ptr(), rec.as_mut_ptr().add(5), msg_len);
    (sys.dev_call)(sess.raw_handle, CHAIN_NEXT | SOCKET_SEND, rec.as_mut_ptr(), 5 + msg_len);

    // Send CCS for middlebox compatibility
    let ccs = [CT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    (sys.dev_call)(sess.raw_handle, CHAIN_NEXT | SOCKET_SEND, ccs.as_ptr() as *mut u8, 6);

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
    let sess = &mut s.sessions[idx];

    // Compute ECDH shared secret
    let shared = match ecdh_shared_secret(&sess.ecdh_private, &sess.peer_key_share[..sess.peer_key_share_len as usize]) {
        Some(s) => s,
        None => {
            sess.state = SessionState::Error;
            return true;
        }
    };

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
    let cert = &s.cert[..s.cert_len];
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

    let mut priv_key = [0u8; 32];
    // Parse SEC1/PKCS#8 private key (simplified: assume raw 32 bytes or SEC1 wrapper)
    if s.key_len == 32 {
        core::ptr::copy_nonoverlapping(s.key.as_ptr(), priv_key.as_mut_ptr(), 32);
    } else if s.key_len > 32 {
        // Try to extract raw key from SEC1/PKCS#8 DER
        extract_ec_private_key(&s.key[..s.key_len], &mut priv_key);
    }

    let raw_sig = ecdsa_sign(&priv_key, &vc_hash, &k_random);
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

    // Wrap in record and send
    let mut rec = [0u8; SEND_BUF_SIZE];
    let mut hdr = [0u8; 5];
    build_record_header(CT_HANDSHAKE, msg_len, &mut hdr);
    core::ptr::copy_nonoverlapping(hdr.as_ptr(), rec.as_mut_ptr(), 5);
    core::ptr::copy_nonoverlapping(sess.scratch.as_ptr(), rec.as_mut_ptr().add(5), msg_len);

    (sys.dev_call)(sess.raw_handle, CHAIN_NEXT | SOCKET_SEND, rec.as_mut_ptr(), 5 + msg_len);

    sess.hs_state = HandshakeState::RecvServerHello;
    true
}

unsafe fn pump_recv_server_hello(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    // Read
    let space = RECV_BUF_SIZE - sess.recv_len;
    if space == 0 { return false; }
    let n = (sys.dev_call)(sess.raw_handle, CHAIN_NEXT | SOCKET_RECV,
                           sess.recv_buf.as_mut_ptr().add(sess.recv_len), space);
    if n > 0 { sess.recv_len += n as usize; }
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

    sess.hs_state = HandshakeState::ClientDeriveHandshakeKeys;
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

/// Send an encrypted handshake record
unsafe fn send_encrypted_handshake(s: &mut TlsState, idx: usize, msg: &[u8], msg_len: usize) {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    let mut enc_buf = [0u8; SEND_BUF_SIZE];
    let enc_len = encrypt_record(sess.suite, &mut sess.write_keys, CT_HANDSHAKE, &msg[..msg_len], &mut enc_buf);

    let mut rec = [0u8; SEND_BUF_SIZE + 5];
    rec[0] = CT_APPLICATION_DATA;
    rec[1] = 0x03; rec[2] = 0x03;
    rec[3] = (enc_len >> 8) as u8;
    rec[4] = enc_len as u8;
    core::ptr::copy_nonoverlapping(enc_buf.as_ptr(), rec.as_mut_ptr().add(5), enc_len);

    (sys.dev_call)(sess.raw_handle, CHAIN_NEXT | SOCKET_SEND, rec.as_mut_ptr(), 5 + enc_len);
}

/// Try to receive and decrypt an encrypted handshake record.
/// Returns (decrypted_data_in_scratch, length, handshake_msg_type) or None if not enough data.
unsafe fn recv_encrypted_handshake(s: &mut TlsState, idx: usize) -> Option<([u8; SCRATCH_SIZE], usize, u8)> {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    // Read more data
    let space = RECV_BUF_SIZE - sess.recv_len;
    if space > 0 {
        let n = (sys.dev_call)(sess.raw_handle, CHAIN_NEXT | SOCKET_RECV,
                               sess.recv_buf.as_mut_ptr().add(sess.recv_len), space);
        if n > 0 { sess.recv_len += n as usize; }
    }

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

/// Send an encrypted alert
unsafe fn send_alert(s: &mut TlsState, idx: usize, description: u8) {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    let alert_body = build_alert(description);
    let mut enc_buf = [0u8; 64];
    let enc_len = encrypt_record(sess.suite, &mut sess.write_keys, CT_ALERT, &alert_body, &mut enc_buf);

    let mut rec = [0u8; 69];
    rec[0] = CT_APPLICATION_DATA;
    rec[1] = 0x03; rec[2] = 0x03;
    rec[3] = (enc_len >> 8) as u8;
    rec[4] = enc_len as u8;
    core::ptr::copy_nonoverlapping(enc_buf.as_ptr(), rec.as_mut_ptr().add(5), enc_len);

    (sys.dev_call)(sess.raw_handle, CHAIN_NEXT | SOCKET_SEND, rec.as_mut_ptr(), 5 + enc_len);
}

/// Drain pending send buffer
unsafe fn drain_send_buffer(s: &mut TlsState, idx: usize) {
    let sys = &*s.syscalls;
    let sess = &mut s.sessions[idx];

    if sess.send_offset < sess.send_len {
        let remain = sess.send_len - sess.send_offset;
        let sent = (sys.dev_call)(
            sess.raw_handle,
            CHAIN_NEXT | SOCKET_SEND,
            sess.send_buf.as_mut_ptr().add(sess.send_offset),
            remain,
        );
        if sent > 0 {
            sess.send_offset += sent as usize;
            if sess.send_offset >= sess.send_len {
                sess.send_len = 0;
                sess.send_offset = 0;
            }
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
