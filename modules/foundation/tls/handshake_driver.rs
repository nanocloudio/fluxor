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

/// Plaintext-handshake-byte queue size. Sized for a typical
/// EE+Cert+CertificateVerify+Finished flight (cert chains up to ~1.2KB);
/// `SCRATCH_SIZE` is the per-message limit on the return-by-value
/// buffer of `read_handshake_message`.
pub const HS_IO_BUF_SIZE: usize = 2048;

/// Per-handshake-message stack buffer used both for building outbound
/// messages and returning inbound messages. Sized to fit a 1561-byte
/// curl-style ClientHello with extensions plus the longest server
/// flight component (Certificate at 400-1200 bytes).
pub const SCRATCH_SIZE: usize = 4096;

/// All record-agnostic TLS 1.3 handshake state.
pub struct HandshakeDriver {
    pub hs_state: HandshakeState,
    pub suite: CipherSuite,
    pub is_server: bool,
    pub hrr_sent: bool,

    pub key_schedule: Option<KeySchedule>,
    pub transcript: Option<Transcript>,

    pub ecdh_private: [u8; 32],
    pub ecdh_public: [u8; 65],
    pub ecdh_state: ScalarMulState,
    pub peer_key_share: [u8; 65],
    pub peer_key_share_len: u8,

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
    pub in_buf: [u8; HS_IO_BUF_SIZE],
    pub in_len: usize,

    /// Plaintext output queue — driver writes ready-to-emit handshake
    /// bytes here; record/transport layer drains via `poll_handshake`.
    /// Reserved for Phase B / C.
    pub out_buf: [u8; HS_IO_BUF_SIZE],
    pub out_len: usize,
}

impl HandshakeDriver {
    pub const fn empty() -> Self {
        Self {
            hs_state: HandshakeState::RecvClientHello,
            suite: CipherSuite::ChaCha20Poly1305,
            is_server: false,
            hrr_sent: false,
            key_schedule: None,
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
            alpn_selected: [0; 16],
            alpn_selected_len: 0,
            server_finished_hash: [0; 48],
            client_finished_hash: [0; 48],
            hs_accum_len: 0,
            scratch: [0; SCRATCH_SIZE],
            in_buf: [0; HS_IO_BUF_SIZE],
            in_len: 0,
            out_buf: [0; HS_IO_BUF_SIZE],
            out_len: 0,
        }
    }

    pub fn reset(&mut self) {
        unsafe {
            let mut i = 0;
            while i < 32 {
                core::ptr::write_volatile(&mut self.ecdh_private[i], 0);
                core::ptr::write_volatile(&mut self.server_random[i], 0);
                i += 1;
            }
        }
        self.hrr_sent = false;
        self.hs_accum_len = 0;
        self.peer_key_share_len = 0;
        self.peer_cert_pubkey_len = 0;
        self.alpn_selected_len = 0;
        self.peer_session_id_len = 0;
        self.in_len = 0;
        self.out_len = 0;
        self.ecdh_state.zeroise_scalar();
        self.ecdh_state = ScalarMulState::empty();
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
        let space = HS_IO_BUF_SIZE - self.in_len;
        let n = if bytes.len() < space { bytes.len() } else { space };
        if n == 0 {
            return 0;
        }
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
    pub unsafe fn read_handshake_message(
        &mut self,
    ) -> Option<([u8; SCRATCH_SIZE], usize, u8)> {
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
    pub unsafe fn write_handshake_message(&mut self, msg: &[u8]) -> bool {
        let space = HS_IO_BUF_SIZE - self.out_len;
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
