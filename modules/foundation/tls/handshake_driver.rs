// Record-agnostic handshake driver (Phase A of
// docs/architecture/datagram_secure_transports.md).
//
// Owns every piece of TLS 1.3 handshake state that does NOT depend on
// the record layer: the state machine cursor, key schedule, transcript,
// ECDH key material, peer key share, peer cert pubkey, server random,
// ALPN selection, and the handshake-message reassembly scratch.
//
// Excluded — and left in `TlsSession` — is everything record-coupled:
// the inbound/outbound record buffers, the AEAD traffic keys (`read_keys`
// / `write_keys`), the retx buffer, and the net_proto session state.
// DTLS (Phase B) and QUIC (Phase C) reuse this driver verbatim and
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

    pub peer_cert_pubkey: [u8; 65],
    pub peer_cert_pubkey_len: u8,
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

    /// Plaintext input queue — record/transport layer fills this with
    /// post-decrypt handshake bytes (or pre-encryption plaintext for
    /// Initial-level records). Driver consumes via `feed_handshake` /
    /// `recv_handshake_message`. Reserved for Phase B (DTLS) / C (QUIC).
    pub in_buf: [u8; HS_IN_BUF_SIZE],
    pub in_len: usize,

    /// Plaintext output queue — driver writes ready-to-emit handshake
    /// bytes here; record/transport layer drains via `poll_handshake`.
    /// Reserved for Phase B / C.
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
            group: GROUP_SECP256R1,
            ecdsa_sign_state: EcdsaSignState::empty(),
            cert_verify_hash: [0; 32],
            cert_verify_hash_ready: 0,
            peer_cert_pubkey: [0; 65],
            peer_cert_pubkey_len: 0,
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
        self.alpn_selected_len = 0;
        self.peer_session_id_len = 0;
        self.in_len = 0;
        self.out_len = 0;
        self.ecdh_state.zeroise_scalar();
        self.ecdh_state = ScalarMulState::empty();
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
    /// Phase B (DTLS) is the first consumer; TLS-over-TCP currently
    /// drives the handshake via the legacy `recv_buf` path inside
    /// `recv_encrypted_handshake`.
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
    /// Phase B / C consumer; the legacy TLS path emits records via
    /// `send_encrypted_handshake` directly.
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
