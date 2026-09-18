// Record-agnostic handshake driver.
//
// Owns every piece of TLS 1.3 handshake state that does NOT depend on
// the record layer: the state machine cursor, key schedule, transcript,
// ECDH key material, peer key share, peer cert pubkey, server random,
// ALPN selection, and the handshake-message reassembly scratch.
//
// Excluded — and left in `TlsSession` — is everything record-coupled:
// the inbound/outbound record buffers, the AEAD traffic keys (`read_keys`
// / `write_keys`), the retx buffer, and the net_proto session state.
// TLS-over-TCP, DTLS-over-UDP and QUIC all drive this one driver and
// supply their own record / packet protection layers.

/// Encryption levels exposed by TLS 1.3 (RFC 8446 §7.1) and consumed by
/// QUIC (RFC 9001 §4). For TLS-over-TCP and DTLS-over-UDP only one
/// level is active at any moment; QUIC may have multiple levels in
/// flight simultaneously.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EncLevel {
    Initial,
    Handshake,
    OneRtt,
}

/// Per-handshake-message stack buffer used both for building outbound
/// messages and returning inbound messages. Sized to fit a 1561-byte
/// curl-style ClientHello with extensions plus the longest server
/// flight component (a Certificate message carrying a chain).
pub const SCRATCH_SIZE: usize = 4096;

/// Most handshake plaintext one inbound record may carry. A record
/// beyond this cannot be taken whole, and taking it in pieces would mean
/// consuming a record partially — so it is refused rather than stalled
/// on. A peer coalescing more than a full message's worth into one
/// record is outside what this queue can assemble.
pub const HS_RECORD_PLAINTEXT_MAX: usize = SCRATCH_SIZE;

/// Inbound plaintext-handshake-byte queue. A handshake message is a byte
/// stream over records, so this is where a message is assembled: it must
/// hold any message `read_handshake_message` is prepared to return, plus
/// one further record, or an incomplete message and the record that
/// would complete it could not be held at the same time and the session
/// would stall rather than progress.
pub const HS_IN_BUF_SIZE: usize = SCRATCH_SIZE + HS_RECORD_PLAINTEXT_MAX;

/// Outbound queue. Holds whole messages this endpoint has built; the
/// record writer fragments them across records on the way out, so the
/// queue only has to hold one message at a time.
pub const HS_OUT_BUF_SIZE: usize = SCRATCH_SIZE;

/// The widest peer subject key an implemented suite carries: an RSA-4096
/// RSAPublicKey. Sized by the suite registry so a new suite cannot be
/// admitted without room for its key.
pub const PEER_KEY_MAX: usize = suite::max_public_key_len(suite::RSA_4096);

const _: () = assert!(HS_IN_BUF_SIZE >= SCRATCH_SIZE + HS_RECORD_PLAINTEXT_MAX);
const _: () = assert!(HS_OUT_BUF_SIZE >= SCRATCH_SIZE);

/// All record-agnostic TLS 1.3 handshake state.
pub struct HandshakeDriver {
    pub hs_state: HandshakeState,
    pub suite: CipherSuite,
    pub is_server: bool,
    pub hrr_sent: bool,
    /// Client side: set when the server sent a CertificateRequest, so after the
    /// server's Finished we present our own Certificate + CertificateVerify
    /// (mTLS client auth) before our Finished.
    pub client_cert_requested: bool,

    pub key_schedule: Option<KeySchedule>,
    pub transcript: Option<Transcript>,

    pub ecdh_private: [u8; 32],
    pub ecdh_public: [u8; 65],
    pub ecdh_state: ScalarMulState,
    pub peer_key_share: [u8; 65],
    pub peer_key_share_len: u8,

    /// X25519 agreement material (RFC 7748). The private value is the
    /// raw 32 random bytes: `x25519_public_key` and
    /// `x25519_shared_secret` clamp internally, so storing a
    /// pre-clamped copy would only give the same scalar two encodings.
    pub x25519_private: [u8; 32],
    pub x25519_public: [u8; 32],
    /// The X25519 ladder in flight: the key pair before the hello that
    /// carries the share, the agreement after the peer's. Stepped at the
    /// same bit budget as the P-256 ladder.
    pub x25519_state: X25519State,
    /// Whether `x25519_public` holds the key pair this handshake offers.
    pub x25519_pub_ready: u8,

    /// Negotiated named group — `GROUP_X25519` or `GROUP_SECP256R1`.
    /// Chosen by the server from what the client offered, echoed to the
    /// client in the ServerHello key_share, and read back here to pick
    /// which private value completes the agreement.
    pub group: u16,

    /// Resumable ECDSA signing for the server CertificateVerify;
    /// driven across ticks by `ecdh_bits_per_step` so concurrent
    /// handshakes don't stall on the P-256 ladder.
    pub ecdsa_sign_state: EcdsaSignState,
    /// Hash retained across the multi-tick signer; cleared once
    /// the signature is finalised.
    pub cert_verify_hash: [u8; 32],
    pub cert_verify_hash_ready: u8,

    pub peer_cert_pubkey: [u8; PEER_KEY_MAX],
    pub peer_cert_pubkey_len: u16,
    /// The suite the peer's leaf key belongs to, which decides which
    /// CertificateVerify schemes it may sign with and how its bytes are read.
    pub peer_cert_key_suite: u16,

    /// RSA signatures the chain walk deferred to the instance's stepped
    /// job, and the CertificateVerify awaiting the same job. While either
    /// is pending the received message is held in `scratch` (its length in
    /// `held_len`), because the job reads the signature and the signed
    /// bytes from there across ticks.
    pub deferred_links: DeferredLinks,
    /// The ECDSA half of the same job: per driver, since it is two ladder
    /// states rather than kilobytes.
    pub ecdsa_verify: EcdsaVerifyJob,
    pub held_len: u16,
    /// Whether the instance job currently holds this driver's work.
    pub rsa_job_active: u8,
    /// Pump calls the deferred verification has taken so far, for the
    /// line that reports it.
    pub verify_steps: u16,
    /// The CertificateVerify scheme, signature span and content hash the
    /// job verifies.
    pub cv_scheme: u16,
    pub cv_sig_off: u16,
    pub cv_sig_len: u16,
    pub cv_hash: [u8; 48],
    /// Where the driver goes once the job is done.
    pub after_verify: HandshakeState,
    pub peer_session_id: [u8; 32],
    pub peer_session_id_len: u8,

    pub server_random: [u8; 32],

    pub alpn_selected: [u8; 16],
    pub alpn_selected_len: u8,

    pub server_finished_hash: [u8; 48],

    /// Transcript hash captured at the moment the client's Finished
    /// has been processed (server view). RFC 8446 §4.6.1: the
    /// resumption_master_secret is derived from this hash. We snapshot
    /// it because subsequent post-handshake messages (NewSessionTicket,
    /// KeyUpdate) extend the transcript and would change the value.
    pub client_finished_hash: [u8; 48],

    pub hs_accum_len: usize,
    pub scratch: [u8; SCRATCH_SIZE],

    /// Plaintext input queue — the record/transport layer fills this with
    /// post-decrypt handshake bytes (or pre-encryption plaintext for
    /// Initial-level records), and the driver consumes it via
    /// `read_handshake_message`. This queue and `out_buf` are the only
    /// handshake-driver entry points any transport sees: the TLS record
    /// bridge, the DTLS record bridge and QUIC's CRYPTO frames all meet
    /// the state machine here.
    pub in_buf: [u8; HS_IN_BUF_SIZE],
    pub in_len: usize,

    /// Plaintext output queue — the driver writes ready-to-emit handshake
    /// bytes here via `write_handshake_message`, and the record/transport
    /// layer drains whole messages from the head, fragmenting them to fit
    /// its own records or packets.
    pub out_buf: [u8; HS_OUT_BUF_SIZE],
    pub out_len: usize,
}

impl HandshakeDriver {
    pub const fn empty() -> Self {
        Self {
            hs_state: HandshakeState::RecvClientHello,
            suite: CipherSuite::ChaCha20Poly1305,
            is_server: false,
            hrr_sent: false,
            client_cert_requested: false,
            key_schedule: None,
            transcript: None,
            ecdh_private: [0; 32],
            ecdh_public: [0; 65],
            ecdh_state: ScalarMulState::empty(),
            peer_key_share: [0; 65],
            peer_key_share_len: 0,
            x25519_private: [0; 32],
            x25519_public: [0; 32],
            x25519_state: X25519State::empty(),
            x25519_pub_ready: 0,
            group: GROUP_SECP256R1,
            ecdsa_sign_state: EcdsaSignState::empty(),
            cert_verify_hash: [0; 32],
            cert_verify_hash_ready: 0,
            peer_cert_pubkey: [0; PEER_KEY_MAX],
            peer_cert_pubkey_len: 0,
            peer_cert_key_suite: suite::UNKNOWN,
            deferred_links: DeferredLinks::empty(),
            ecdsa_verify: EcdsaVerifyJob::empty(),
            held_len: 0,
            rsa_job_active: 0,
            verify_steps: 0,
            cv_scheme: 0,
            cv_sig_off: 0,
            cv_sig_len: 0,
            cv_hash: [0; 48],
            after_verify: HandshakeState::Error,
            peer_session_id: [0; 32],
            peer_session_id_len: 0,
            server_random: [0; 32],
            alpn_selected: [0; 16],
            alpn_selected_len: 0,
            server_finished_hash: [0; 48],
            client_finished_hash: [0; 48],
            hs_accum_len: 0,
            scratch: [0; SCRATCH_SIZE],
            in_buf: [0; HS_IN_BUF_SIZE],
            in_len: 0,
            out_buf: [0; HS_OUT_BUF_SIZE],
            out_len: 0,
        }
    }

    pub fn reset(&mut self) {
        // SAFETY: pointer arithmetic over the handshake-state buffer; bounds
        // checked against the driver-message length.
        unsafe {
            let mut i = 0;
            while i < 32 {
                core::ptr::write_volatile(&mut self.ecdh_private[i], 0);
                core::ptr::write_volatile(&mut self.x25519_private[i], 0);
                core::ptr::write_volatile(&mut self.server_random[i], 0);
                i += 1;
            }
        }
        self.hrr_sent = false;
        self.client_cert_requested = false;
        self.hs_accum_len = 0;
        self.peer_key_share_len = 0;
        self.group = GROUP_SECP256R1;
        self.peer_cert_pubkey_len = 0;
        self.peer_cert_key_suite = suite::UNKNOWN;
        self.deferred_links.clear();
        self.ecdsa_verify = EcdsaVerifyJob::empty();
        self.held_len = 0;
        self.rsa_job_active = 0;
        self.cv_scheme = 0;
        self.cv_sig_off = 0;
        self.cv_sig_len = 0;
        self.after_verify = HandshakeState::Error;
        self.alpn_selected_len = 0;
        self.peer_session_id_len = 0;
        self.in_len = 0;
        self.out_len = 0;
        self.ecdh_state.zeroise_scalar();
        self.ecdh_state = ScalarMulState::empty();
        self.x25519_state.zeroise();
        self.x25519_state = X25519State::empty();
        self.x25519_pub_ready = 0;
        self.ecdsa_sign_state.zeroise_secrets();
        self.ecdsa_sign_state = EcdsaSignState::empty();
        for byte in &mut self.cert_verify_hash {
            // SAFETY: volatile write to a bounded array slot.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        self.cert_verify_hash_ready = 0;
        self.key_schedule = None;
        self.transcript = None;
    }

    /// Append `bytes` (post-decrypt plaintext handshake bytes) to the
    /// driver's input queue. The level parameter is informational; the
    /// driver tracks the active level via `hs_state` for TLS / DTLS,
    /// while QUIC supplies it explicitly via CRYPTO frames.
    ///
    /// Returns the number of bytes accepted; on overflow returns less
    /// than `bytes.len()` and the caller is responsible for retrying.
    /// The DTLS record bridge and QUIC's CRYPTO reassembler enter here;
    /// the TLS-over-TCP bridge appends to `in_buf` directly, having
    /// already settled capacity before it moved any AEAD sequence.
    pub fn feed_handshake(&mut self, _level: EncLevel, bytes: &[u8]) -> usize {
        let space = HS_IN_BUF_SIZE - self.in_len;
        let n = if bytes.len() < space {
            bytes.len()
        } else {
            space
        };
        if n == 0 {
            return 0;
        }
        // SAFETY: pointer arithmetic over the handshake-state buffer; bounds
        // checked against the driver-message length.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.in_buf.as_mut_ptr().add(self.in_len),
                n,
            );
        }
        self.in_len += n;
        n
    }

    /// Drain up to `out.len()` ready-to-emit handshake bytes into `out`.
    /// Returns the number of bytes written. The level parameter is
    /// informational; the driver knows internally what level it is at.
    /// A copying drain for a transport that wants the bytes in its own
    /// buffer; the TLS, DTLS and QUIC bridges instead frame messages in
    /// place from the head of `out_buf`.
    pub fn poll_handshake(&mut self, _level: EncLevel, out: &mut [u8]) -> usize {
        if self.out_len == 0 {
            return 0;
        }
        let n = if out.len() < self.out_len {
            out.len()
        } else {
            self.out_len
        };
        // SAFETY: pointer arithmetic over the handshake-state buffer; bounds
        // checked against the driver-message length.
        unsafe {
            core::ptr::copy_nonoverlapping(self.out_buf.as_ptr(), out.as_mut_ptr(), n);
            let remain = self.out_len - n;
            if remain > 0 {
                core::ptr::copy(
                    self.out_buf.as_ptr().add(n),
                    self.out_buf.as_mut_ptr(),
                    remain,
                );
            }
        }
        self.out_len -= n;
        n
    }

    /// Returns the current traffic secret for the requested level and
    /// direction. `send = true` returns the secret used to derive keys
    /// for the local peer's outbound traffic; `send = false` returns
    /// the inbound secret.
    ///
    /// `Initial` returns `None` because TLS 1.3 / DTLS 1.3 / QUIC v1
    /// derive the Initial keys from a known salt + connection id, not
    /// from a handshake-derived secret.
    pub fn read_secret(&self, level: EncLevel, send: bool) -> Option<&[u8]> {
        let ks = self.key_schedule.as_ref()?;
        let hl = ks.hash_len;
        match (level, send, self.is_server) {
            (EncLevel::Initial, _, _) => None,
            // send=true asks for the local outbound secret.
            (EncLevel::Handshake, true, true) => Some(&ks.server_hs_secret[..hl]),
            (EncLevel::Handshake, true, false) => Some(&ks.client_hs_secret[..hl]),
            (EncLevel::Handshake, false, true) => Some(&ks.client_hs_secret[..hl]),
            (EncLevel::Handshake, false, false) => Some(&ks.server_hs_secret[..hl]),
            (EncLevel::OneRtt, true, true) => Some(&ks.server_app_secret[..hl]),
            (EncLevel::OneRtt, true, false) => Some(&ks.client_app_secret[..hl]),
            (EncLevel::OneRtt, false, true) => Some(&ks.client_app_secret[..hl]),
            (EncLevel::OneRtt, false, false) => Some(&ks.server_app_secret[..hl]),
        }
    }

    pub fn is_handshake_complete(&self) -> bool {
        matches!(self.hs_state, HandshakeState::Complete)
    }

    pub fn is_handshake_error(&self) -> bool {
        matches!(self.hs_state, HandshakeState::Error)
    }

    /// Drain one complete handshake message (4-byte header + body) from
    /// `in_buf` into a fresh stack buffer. Returns
    /// `(msg_buf, total_len, hs_msg_type)` or None if a complete
    /// message isn't available yet. On size overflow (message larger
    /// than SCRATCH_SIZE), the driver moves to `HandshakeState::Error`
    /// and returns None.
    ///
    /// Used by both the TLS-over-TCP record bridge and the DTLS bridge
    /// (`dtls_recv_into_driver` ultimately appends bytes via
    /// `feed_handshake`; the pump_* logic then calls this method to
    /// pull complete messages out).
    /// # Safety
    /// `in_buf` is owned by `self` and sized `HS_IN_BUF_SIZE`; the
    /// bounds-checks above ensure the message length fits in scratch.
    /// True when `in_buf` already holds a COMPLETE handshake message that
    /// `read_handshake_message` would return.
    ///
    /// The record layer uses this as back-pressure: it must not take another
    /// record off the wire while a buffered message is still unprocessed,
    /// because processing that message can change the read keys. RFC 8446
    /// §5.1 lets a peer put several handshake messages in one record, so the
    /// client's Certificate, CertificateVerify and Finished routinely arrive
    /// together — and a server that consumed only the Certificate and then
    /// reached for the next record would be reaching for a record the client
    /// had already encrypted under its APPLICATION key, with the server's
    /// handshake key still installed. That decrypts to nothing, with a valid
    /// key, at a valid sequence number.
    #[must_use]
    pub fn has_complete_message(&self) -> bool {
        if self.in_len < 4 {
            return false;
        }
        let msg_body_len = ((self.in_buf[1] as usize) << 16)
            | ((self.in_buf[2] as usize) << 8)
            | (self.in_buf[3] as usize);
        let total = 4 + msg_body_len;
        // A message too large to ever read is not "complete" — it is a
        // failure `read_handshake_message` reports, and deferring on it
        // forever would wedge the session instead.
        total <= SCRATCH_SIZE && self.in_len >= total
    }

    pub unsafe fn read_handshake_message(&mut self) -> Option<([u8; SCRATCH_SIZE], usize, u8)> {
        if self.in_len < 4 {
            return None;
        }
        let msg_type = self.in_buf[0];
        let msg_body_len = ((self.in_buf[1] as usize) << 16)
            | ((self.in_buf[2] as usize) << 8)
            | (self.in_buf[3] as usize);
        let total = 4 + msg_body_len;
        if total > SCRATCH_SIZE {
            self.hs_state = HandshakeState::Error;
            return None;
        }
        if self.in_len < total {
            return None;
        }
        let mut out = [0u8; SCRATCH_SIZE];
        core::ptr::copy_nonoverlapping(self.in_buf.as_ptr(), out.as_mut_ptr(), total);
        let remain = self.in_len - total;
        if remain > 0 {
            core::ptr::copy(
                self.in_buf.as_ptr().add(total),
                self.in_buf.as_mut_ptr(),
                remain,
            );
        }
        self.in_len = remain;
        Some((out, total, msg_type))
    }

    /// Append `msg` (4-byte handshake header + body) to `out_buf`.
    /// Returns false on overflow — caller retries on the next pump
    /// tick. The TLS / DTLS / QUIC record (or packet) bridge drains
    /// these messages and frames them appropriately.
    ///
    /// # Safety
    /// `out_buf` is owned by `self`; the `msg.len() > space` guard
    /// keeps the `copy_nonoverlapping` write in-bounds.
    pub unsafe fn write_handshake_message(&mut self, msg: &[u8]) -> bool {
        let space = HS_OUT_BUF_SIZE - self.out_len;
        if msg.len() > space {
            return false;
        }
        core::ptr::copy_nonoverlapping(
            msg.as_ptr(),
            self.out_buf.as_mut_ptr().add(self.out_len),
            msg.len(),
        );
        self.out_len += msg.len();
        true
    }
}

// ── Peer verification shared by every transport ──────────────────────
//
// tls, dtls and quic mount this file; the CertificateVerify check, the
// peer-key binding and the stepped RSA pump live here so the three cannot
// drift apart on what a peer has to prove.

/// Verify a peer's CertificateVerify message against the captured
/// peer cert public key, update the transcript, and advance to the
/// next state. Server-side (mTLS, verifying the client) goes to
/// RecvClientFinished; client-side (verifying the server) goes to
/// RecvFinished. Caller picks the next state via `driver.is_server`
/// implicitly.
pub unsafe fn pump_recv_certificate_verify_core(driver: &mut HandshakeDriver) -> bool {
    let (data, len, msg_type) = match driver.read_handshake_message() {
        Some(t) => t,
        None => return false,
    };
    if msg_type != HT_CERTIFICATE_VERIFY {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    if driver.peer_cert_pubkey_len == 0 {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    let hl = driver.suite.hash_len();
    let transcript_hash = match &driver.transcript {
        Some(t) => t.current_hash(),
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    // We're verifying the OTHER side's CV. As server we're checking
    // a client cert (mTLS); as client we're checking the server.
    let context: &[u8] = if driver.is_server {
        b"TLS 1.3, client CertificateVerify"
    } else {
        b"TLS 1.3, server CertificateVerify"
    };
    let mut vc = [0u8; 200];
    let vc_len = build_verify_content(context, &transcript_hash[..hl], hl, &mut vc);
    let cv_body = &data[4..len];
    // The announced scheme must be one the peer's key may sign with; the
    // content is hashed under that scheme's digest.
    let Some((announced, sig)) = parse_certificate_verify(cv_body) else {
        driver.hs_state = HandshakeState::Error;
        return true;
    };
    let Some(scheme) = scheme_for_peer_key(driver.peer_cert_key_suite, announced) else {
        driver.hs_state = HandshakeState::Error;
        return true;
    };
    let next = if driver.is_server {
        HandshakeState::RecvClientFinished
    } else {
        HandshakeState::RecvFinished
    };
    // The signature check is a stepped job — RSA-PSS on the instance's
    // exponentiation, ECDSA on the driver's ladders — so the message is
    // held in `scratch`: the job reads the signature from it and the
    // transcript takes the message once it verifies.
    if scheme_hash_len(scheme) == 48 {
        driver.cv_hash[..48].copy_from_slice(&sha384(&vc[..vc_len]));
    } else {
        driver.cv_hash[..32].copy_from_slice(&sha256(&vc[..vc_len]));
    }
    let sig_off = 4 + (sig.as_ptr() as usize - cv_body.as_ptr() as usize);
    driver.scratch[..len].copy_from_slice(&data[..len]);
    driver.held_len = len as u16;
    driver.cv_scheme = scheme;
    driver.cv_sig_off = sig_off as u16;
    driver.cv_sig_len = sig.len() as u16;
    driver.rsa_job_active = 0;
    driver.after_verify = next;
    driver.verify_steps = 0;
    driver.hs_state = HandshakeState::VerifyPeerSignature;
    true
}

/// Bind the accepted leaf's subject public key and its suite to `driver`.
/// Called only after the chain was accepted, so downstream code's use of
/// `peer_cert_pubkey_len > 0` as the marker that a real identity was bound
/// stays true.
pub unsafe fn bind_peer_cert_key_core(driver: &mut HandshakeDriver, cert_der: &[u8]) -> u32 {
    let cert = match parse_certificate(cert_der) {
        Some(c) => c,
        None => return CERT_ERR_MALFORMED,
    };
    let pk = cert.public_key;
    if !key_is_valid(cert.key_suite, pk) || pk.len() > PEER_KEY_MAX {
        return CERT_ERR_BAD_KEY;
    }
    driver.peer_cert_pubkey[..pk.len()].copy_from_slice(pk);
    driver.peer_cert_pubkey_len = pk.len() as u16;
    driver.peer_cert_key_suite = cert.key_suite;
    CERT_OK
}

/// What one step of the instance job did for a driver.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RsaPump {
    /// Still going, or waiting for the job.
    Progress,
    /// Every deferred signature verified; the driver has moved to
    /// `after_verify`.
    Done,
    /// A signature did not verify.
    Failed,
}

/// Drive the verify jobs for `driver`, which is in `VerifyChain`
/// (deferred chain links, read from the held message and `anchor`) or
/// `VerifyPeerSignature` (the held CertificateVerify). An RSA signature
/// spends up to `rows` units of the instance job `job`; an ECDSA one spends
/// one `ec_bits`-bit step of the driver's own ladders. The caller has
/// already decided this driver may use the instance job.
pub unsafe fn rsa_verify_pump_core(
    driver: &mut HandshakeDriver,
    job: &mut RsaVerifyJob,
    anchor: &[u8],
    rows: usize,
    ec_bits: u8,
) -> RsaPump {
    let held = driver.held_len as usize;
    if !(4..=SCRATCH_SIZE).contains(&held) {
        return RsaPump::Failed;
    }
    driver.verify_steps = driver.verify_steps.wrapping_add(1);
    match driver.hs_state {
        HandshakeState::VerifyChain => {
            if !driver.deferred_links.pending() {
                driver.hs_state = driver.after_verify;
                driver.held_len = 0;
                return RsaPump::Done;
            }
            let link = driver.deferred_links.links[driver.deferred_links.next as usize];
            let ecdsa = link.sig_suite == suite::ECDSA_P256_SHA256;
            if driver.rsa_job_active == 0 {
                let message = &driver.scratch[4..held];
                let Some((tbs, sig, key_bytes)) = deferred_link_bytes(&link, message, anchor)
                else {
                    return RsaPump::Failed;
                };
                if ecdsa {
                    let Some(raw) = parse_der_signature(sig) else {
                        return RsaPump::Failed;
                    };
                    let Some(started) = ecdsa_verify_init(key_bytes, &sha256(tbs), &raw, ec_bits)
                    else {
                        return RsaPump::Failed;
                    };
                    driver.ecdsa_verify = started;
                } else {
                    let Some(key) = rsa_public_key_parse(key_bytes) else {
                        return RsaPump::Failed;
                    };
                    if !job.start(key.n, key.e, sig) {
                        return RsaPump::Failed;
                    }
                }
                driver.rsa_job_active = 1;
            }
            let ok = if ecdsa {
                if !driver.ecdsa_verify.step() {
                    return RsaPump::Progress;
                }
                ecdsa_verify_finalise(&driver.ecdsa_verify)
            } else {
                if job.step(rows) == RsaStep::Pending {
                    return RsaPump::Progress;
                }
                let message = &driver.scratch[4..held];
                deferred_link_rsa_check(&link, message, job.encoded_message())
            };
            driver.rsa_job_active = 0;
            if !ok {
                return RsaPump::Failed;
            }
            driver.deferred_links.next += 1;
            if driver.deferred_links.pending() {
                return RsaPump::Progress;
            }
            driver.hs_state = driver.after_verify;
            driver.held_len = 0;
            RsaPump::Done
        }
        HandshakeState::VerifyPeerSignature => {
            let ecdsa = driver.cv_scheme == SIG_ECDSA_SECP256R1_SHA256;
            if driver.rsa_job_active == 0 {
                let Some(sig) = driver.scratch.get(
                    driver.cv_sig_off as usize..(driver.cv_sig_off + driver.cv_sig_len) as usize,
                ) else {
                    return RsaPump::Failed;
                };
                let pk = &driver.peer_cert_pubkey[..driver.peer_cert_pubkey_len as usize];
                if ecdsa {
                    let Some(raw) = parse_der_signature(sig) else {
                        return RsaPump::Failed;
                    };
                    let Some(started) = ecdsa_verify_init(pk, &driver.cv_hash[..32], &raw, ec_bits)
                    else {
                        return RsaPump::Failed;
                    };
                    driver.ecdsa_verify = started;
                } else {
                    let Some(key) = rsa_public_key_parse(pk) else {
                        return RsaPump::Failed;
                    };
                    if !job.start(key.n, key.e, sig) {
                        return RsaPump::Failed;
                    }
                }
                driver.rsa_job_active = 1;
            }
            let ok = if ecdsa {
                if !driver.ecdsa_verify.step() {
                    return RsaPump::Progress;
                }
                ecdsa_verify_finalise(&driver.ecdsa_verify)
            } else {
                if job.step(rows) == RsaStep::Pending {
                    return RsaPump::Progress;
                }
                let pk = &driver.peer_cert_pubkey[..driver.peer_cert_pubkey_len as usize];
                let Some(key) = rsa_public_key_parse(pk) else {
                    return RsaPump::Failed;
                };
                let hl = scheme_hash_len(driver.cv_scheme);
                let hash = if hl == 48 {
                    RsaHash::Sha384
                } else {
                    RsaHash::Sha256
                };
                rsa_pss_verify(
                    hash,
                    &driver.cv_hash[..hl],
                    job.encoded_message(),
                    rsa_public_key_bits(&key),
                )
            };
            driver.rsa_job_active = 0;
            if !ok {
                return RsaPump::Failed;
            }
            // The message the transcript takes is the one that verified.
            let mut held_msg = [0u8; SCRATCH_SIZE];
            held_msg[..held].copy_from_slice(&driver.scratch[..held]);
            if let Some(ref mut t) = driver.transcript {
                t.update(&held_msg[..held]);
            }
            driver.hs_state = driver.after_verify;
            driver.held_len = 0;
            RsaPump::Done
        }
        _ => RsaPump::Failed,
    }
}
