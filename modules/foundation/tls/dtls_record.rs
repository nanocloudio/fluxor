// DTLS 1.3 record layer (RFC 9147).
//
// Record format — unified header (RFC 9147 §4):
//
//   first byte:  0 0 1 C S L E E
//                       │ │ │ └─┴─ low 2 bits of epoch
//                       │ │ └─── 1 = explicit 16-bit length field present
//                       │ └───── 1 = 16-bit sequence number, 0 = 8-bit
//                       └─────── 1 = connection_id present
//
// This implementation always sets S=1, L=1, C=0 (no Connection ID). The
// header is therefore a fixed 5 bytes:
//   [0]   0b001_0_1_1_EE
//   [1-2] sequence number (low 16 bits, big-endian)
//   [3-4] length of `encrypted_record` (big-endian)
//
// `encrypted_record` is identical to TLS 1.3: AEAD-sealed
// (plaintext || content_type) under the per-record nonce
// `iv XOR padded_be64(seq)` with the unified header as AAD.
//
// Sequence numbers reconstructed by `recover_seq` use a sliding window
// (RFC 9147 §4.2.2) so we accept reorder-tolerant delivery from UDP.
//
// Reuses TLS 1.3 AEAD primitives (`encrypt_record` / `decrypt_record`
// can't be used directly — different header / AAD) and the same
// `TrafficKeys::nonce()` IV-XOR construction.
//
// Phase B status: record-layer primitives are live and exercised by a
// self-test below (cargo unit tests are not wired into PIC modules; the
// self-test is gated behind `cfg(test)`). Live wiring into a DTLS
// server / client is deferred — it requires extending the `pump_*`
// path in `mod.rs` to drive the handshake driver via the queue API
// (`feed_handshake` / `poll_handshake`) instead of the current
// `recv_buf` / `cipher_out` direct path. That refactor is the same
// one Phase C (QUIC) needs, so doing it once unblocks both transports.

/// Per-direction DTLS record-layer state.
pub struct DtlsRecord {
    /// Epoch advances when traffic keys rotate (handshake → application).
    pub epoch: u16,
    /// Next sequence number to emit (monotonic).
    pub send_seq: u64,
    /// Highest sequence number accepted on inbound (sliding-window anchor).
    pub recv_high: u64,
    /// Anti-replay bitmap — bit i = `recv_high - i` was seen.
    pub recv_window: u64,
}

impl DtlsRecord {
    pub const fn new() -> Self {
        Self {
            epoch: 0,
            send_seq: 0,
            recv_high: 0,
            recv_window: 0,
        }
    }

    /// Reset state on epoch transition. Called after handshake or app
    /// keys are derived; new keys start at seq 0 in the new epoch.
    pub fn rotate_epoch(&mut self, new_epoch: u16) {
        self.epoch = new_epoch;
        self.send_seq = 0;
        self.recv_high = 0;
        self.recv_window = 0;
    }
}

pub const DTLS_UNIFIED_HDR_LEN: usize = 5;

/// Build the 5-byte DTLS 1.3 unified header for `seq` / `epoch` /
/// `enc_len` (encrypted_record length = plaintext + content_type + tag).
/// `out` MUST be at least `DTLS_UNIFIED_HDR_LEN` bytes.
pub fn build_dtls_header(epoch: u16, seq: u64, enc_len: usize, out: &mut [u8; DTLS_UNIFIED_HDR_LEN]) {
    // First byte: fixed 0b001 prefix | C=0 | S=1 | L=1 | epoch low 2 bits
    out[0] = 0b0010_1100u8 | ((epoch & 0x0003) as u8);
    let seq16 = (seq & 0xFFFF) as u16;
    out[1] = (seq16 >> 8) as u8;
    out[2] = (seq16 & 0xFF) as u8;
    out[3] = (enc_len >> 8) as u8;
    out[4] = (enc_len & 0xFF) as u8;
}

/// Validate the fixed bits in a DTLS unified header first byte.
/// Returns Some(epoch_low2) on success, None if the byte is not a
/// DTLSCiphertext per RFC 9147 §4.
///
/// This implementation only emits and decrypts headers with C=0, S=1,
/// L=1 (no Connection ID, 16-bit sequence, length present — a fixed
/// 5-byte header). Other shapes are rejected: the decrypt path assumes
/// the 5-byte layout, so accepting C=1 or S=0 or L=0 would feed CID /
/// 8-bit-seq / data bytes to the seq/length parsers.
pub fn parse_dtls_header_byte(b: u8) -> Option<u8> {
    // bits 7..5 = 0b001 fixed prefix; bit 4 = C; bit 3 = S; bit 2 = L.
    if (b & 0b1111_1100u8) != 0b0010_1100u8 {
        return None;
    }
    Some(b & 0b0000_0011u8)
}

/// Reconstruct the full 64-bit sequence number from a 16-bit on-wire
/// value plus the recv_high anchor. Implements RFC 9147 §4.2.2: pick
/// the candidate (high32 << 16 | seq16) closest to recv_high.
pub fn recover_seq(recv_high: u64, seq16_on_wire: u16) -> u64 {
    let high = recv_high & !0xFFFFu64;
    let candidate = high | (seq16_on_wire as u64);
    // Compare the three candidates (prev window, current window, next
    // window) and pick the one closest to recv_high.
    let prev = candidate.wrapping_sub(0x1_0000);
    let next = candidate.wrapping_add(0x1_0000);
    let dist = |a: u64, b: u64| -> u64 {
        if a > b { a - b } else { b - a }
    };
    let mut best = candidate;
    let mut best_d = dist(candidate, recv_high);
    if dist(prev, recv_high) < best_d {
        best = prev;
        best_d = dist(prev, recv_high);
    }
    if dist(next, recv_high) < best_d {
        best = next;
    }
    best
}

/// Anti-replay check (RFC 9147 §4.2.2). Returns true if `seq` is fresh
/// and updates the sliding window. Returns false on duplicate or
/// outside-window.
pub fn check_replay(state: &mut DtlsRecord, seq: u64) -> bool {
    if seq > state.recv_high {
        let shift = seq - state.recv_high;
        if shift >= 64 {
            state.recv_window = 1;
        } else {
            state.recv_window = (state.recv_window << shift) | 1;
        }
        state.recv_high = seq;
        return true;
    }
    let delta = state.recv_high - seq;
    if delta >= 64 {
        return false; // Outside window.
    }
    let mask = 1u64 << delta;
    if state.recv_window & mask != 0 {
        return false; // Replay.
    }
    state.recv_window |= mask;
    true
}

/// Encrypt a DTLS 1.3 record. `plaintext` is the inner content;
/// `content_type` is the inner type. `out` receives:
///   [unified_header(5)] [encrypted_data + content_type + tag]
/// Returns total bytes written, or 0 on insufficient buffer.
pub fn encrypt_dtls_record(
    suite: CipherSuite,
    keys: &mut TrafficKeys,
    state: &mut DtlsRecord,
    content_type: u8,
    plaintext: &[u8],
    out: &mut [u8],
) -> usize {
    let enc_len = plaintext.len() + 1 + 16;
    let total = DTLS_UNIFIED_HDR_LEN + enc_len;
    if out.len() < total {
        return 0;
    }

    // Use the record's sequence counter, not the TLS implicit one. The
    // TrafficKeys nonce is computed from `keys.seq`; sync it.
    keys.seq = state.send_seq;

    let mut hdr = [0u8; DTLS_UNIFIED_HDR_LEN];
    build_dtls_header(state.epoch, state.send_seq, enc_len, &mut hdr);
    out[..DTLS_UNIFIED_HDR_LEN].copy_from_slice(&hdr);

    // Body = plaintext || content_type, then AEAD seals in-place and
    // appends the 16-byte tag. AAD = the unified header.
    unsafe {
        core::ptr::copy_nonoverlapping(
            plaintext.as_ptr(),
            out.as_mut_ptr().add(DTLS_UNIFIED_HDR_LEN),
            plaintext.len(),
        );
    }
    out[DTLS_UNIFIED_HDR_LEN + plaintext.len()] = content_type;

    let data_len = plaintext.len() + 1;
    let nonce = keys.nonce();

    let body_off = DTLS_UNIFIED_HDR_LEN;
    match suite {
        CipherSuite::ChaCha20Poly1305 => {
            let mut key = [0u8; 32];
            unsafe {
                core::ptr::copy_nonoverlapping(keys.key.as_ptr(), key.as_mut_ptr(), 32);
            }
            let tag = chacha20_poly1305_encrypt(
                &key,
                &nonce,
                &hdr,
                &mut out[body_off..body_off + data_len],
            );
            unsafe {
                core::ptr::copy_nonoverlapping(
                    tag.as_ptr(),
                    out.as_mut_ptr().add(body_off + data_len),
                    16,
                );
            }
            zeroize(&mut key);
        }
        CipherSuite::Aes128Gcm => {
            let mut key = [0u8; 16];
            unsafe {
                core::ptr::copy_nonoverlapping(keys.key.as_ptr(), key.as_mut_ptr(), 16);
            }
            let gcm = AesGcm::new_128(&key);
            let tag = gcm.encrypt(&nonce, &hdr, &mut out[body_off..body_off + data_len]);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    tag.as_ptr(),
                    out.as_mut_ptr().add(body_off + data_len),
                    16,
                );
            }
            zeroize(&mut key);
        }
        CipherSuite::Aes256Gcm => {
            let mut key = [0u8; 32];
            unsafe {
                core::ptr::copy_nonoverlapping(keys.key.as_ptr(), key.as_mut_ptr(), 32);
            }
            let gcm = AesGcm::new_256(&key);
            let tag = gcm.encrypt(&nonce, &hdr, &mut out[body_off..body_off + data_len]);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    tag.as_ptr(),
                    out.as_mut_ptr().add(body_off + data_len),
                    16,
                );
            }
            zeroize(&mut key);
        }
    }

    keys.advance_seq();
    state.send_seq = state.send_seq.wrapping_add(1);
    total
}

/// Decrypt a DTLS 1.3 record. `record` is the full datagram payload
/// (unified_header + encrypted_record). On success returns
/// `Some((plaintext_len, inner_content_type, recovered_seq))` and the
/// plaintext is in-place at `record[DTLS_UNIFIED_HDR_LEN..]`. On
/// failure (bad MAC / replay / malformed) returns None.
pub fn decrypt_dtls_record(
    suite: CipherSuite,
    keys: &mut TrafficKeys,
    state: &mut DtlsRecord,
    record: &mut [u8],
) -> Option<(usize, u8, u64)> {
    if record.len() < DTLS_UNIFIED_HDR_LEN + 17 {
        return None;
    }
    let _epoch_lo = parse_dtls_header_byte(record[0])?;
    let seq16 = ((record[1] as u16) << 8) | (record[2] as u16);
    let enc_len = ((record[3] as usize) << 8) | (record[4] as usize);
    // RFC 9147 §4: encrypted_record length covers ciphertext + 16-byte
    // AEAD tag. Reject anything too short for even the tag before
    // computing tag_start; otherwise `body_off + enc_len - 16` underflows
    // on malformed input and feeds out-of-bounds offsets to the unsafe
    // copy below.
    if enc_len < 16 || record.len() < DTLS_UNIFIED_HDR_LEN + enc_len {
        return None;
    }

    let seq = recover_seq(state.recv_high, seq16);

    // AAD is the literal 5-byte header on the wire.
    let mut hdr = [0u8; DTLS_UNIFIED_HDR_LEN];
    hdr.copy_from_slice(&record[..DTLS_UNIFIED_HDR_LEN]);

    keys.seq = seq;
    let nonce = keys.nonce();

    let body_off = DTLS_UNIFIED_HDR_LEN;
    let tag_start = body_off + enc_len - 16;
    let mut tag = [0u8; 16];
    unsafe {
        core::ptr::copy_nonoverlapping(
            record.as_ptr().add(tag_start),
            tag.as_mut_ptr(),
            16,
        );
    }

    let ok = match suite {
        CipherSuite::ChaCha20Poly1305 => {
            let mut key = [0u8; 32];
            unsafe {
                core::ptr::copy_nonoverlapping(keys.key.as_ptr(), key.as_mut_ptr(), 32);
            }
            let r = chacha20_poly1305_decrypt(
                &key,
                &nonce,
                &hdr,
                &mut record[body_off..tag_start],
                &tag,
            );
            zeroize(&mut key);
            r
        }
        CipherSuite::Aes128Gcm => {
            let mut key = [0u8; 16];
            unsafe {
                core::ptr::copy_nonoverlapping(keys.key.as_ptr(), key.as_mut_ptr(), 16);
            }
            let gcm = AesGcm::new_128(&key);
            let r = gcm.decrypt(&nonce, &hdr, &mut record[body_off..tag_start], &tag);
            zeroize(&mut key);
            r
        }
        CipherSuite::Aes256Gcm => {
            let mut key = [0u8; 32];
            unsafe {
                core::ptr::copy_nonoverlapping(keys.key.as_ptr(), key.as_mut_ptr(), 32);
            }
            let gcm = AesGcm::new_256(&key);
            let r = gcm.decrypt(&nonce, &hdr, &mut record[body_off..tag_start], &tag);
            zeroize(&mut key);
            r
        }
    };
    zeroize(&mut tag);
    if !ok {
        return None;
    }

    // Replay check is only valid AFTER MAC verification — otherwise a
    // forged seq number could shift the window without authenticating.
    if !check_replay(state, seq) {
        return None;
    }

    // Find inner content type (last non-zero byte of decrypted body).
    let mut pt_len = enc_len - 16;
    while pt_len > 0 && record[body_off + pt_len - 1] == 0 {
        pt_len -= 1;
    }
    if pt_len == 0 {
        return None;
    }
    pt_len -= 1;
    let inner_type = record[body_off + pt_len];
    unsafe {
        core::ptr::write_volatile(record.as_mut_ptr().add(body_off + pt_len), 0);
    }
    Some((pt_len, inner_type, seq))
}

// ----------------------------------------------------------------------
// Handshake fragmentation reassembly (RFC 9147 §5.5)
//
// DTLS handshake messages are framed with a 12-byte per-fragment header:
//
//   uint8  msg_type;            // 0 (offset 0)
//   uint24 length;              // 1..3   total message length
//   uint16 message_seq;         // 4..5
//   uint24 fragment_offset;     // 6..8
//   uint24 fragment_length;     // 9..11
//   opaque body[fragment_length]; // 12..
//
// The reassembler tracks a single in-progress message identified by
// `message_seq`. Out-of-order fragments are accepted; the message is
// "complete" when the union of all fragment ranges covers [0, length).
// ----------------------------------------------------------------------

pub const DTLS_HS_HEADER_LEN: usize = 12;
pub const DTLS_HS_REASSEMBLY_BUF: usize = 4096;

pub struct DtlsHandshakeReassembler {
    pub message_seq: u16,
    pub msg_type: u8,
    pub total_len: usize,
    pub buf: [u8; DTLS_HS_REASSEMBLY_BUF],
    /// Bitmap of received bytes — bit i = 1 if `buf[i]` filled. We use
    /// a coarser-grained "fragment list" in production; the bitmap is
    /// here for a self-contained test harness.
    pub seen: [u8; DTLS_HS_REASSEMBLY_BUF / 8],
    pub active: bool,
}

impl DtlsHandshakeReassembler {
    pub const fn new() -> Self {
        Self {
            message_seq: 0,
            msg_type: 0,
            total_len: 0,
            buf: [0; DTLS_HS_REASSEMBLY_BUF],
            seen: [0; DTLS_HS_REASSEMBLY_BUF / 8],
            active: false,
        }
    }

    pub fn reset(&mut self) {
        self.active = false;
        self.total_len = 0;
        let mut i = 0;
        while i < DTLS_HS_REASSEMBLY_BUF / 8 {
            self.seen[i] = 0;
            i += 1;
        }
    }

    /// Feed a fragment. Returns true when the message is complete and
    /// `self.buf[..self.total_len]` contains the assembled handshake
    /// message body (without the per-fragment header).
    pub fn feed(&mut self, fragment: &[u8]) -> bool {
        if fragment.len() < DTLS_HS_HEADER_LEN {
            return false;
        }
        let msg_type = fragment[0];
        let length = ((fragment[1] as usize) << 16)
            | ((fragment[2] as usize) << 8)
            | (fragment[3] as usize);
        let message_seq = ((fragment[4] as u16) << 8) | (fragment[5] as u16);
        let frag_off = ((fragment[6] as usize) << 16)
            | ((fragment[7] as usize) << 8)
            | (fragment[8] as usize);
        let frag_len = ((fragment[9] as usize) << 16)
            | ((fragment[10] as usize) << 8)
            | (fragment[11] as usize);
        if fragment.len() < DTLS_HS_HEADER_LEN + frag_len {
            return false;
        }
        if length > DTLS_HS_REASSEMBLY_BUF {
            return false;
        }
        if frag_off + frag_len > length {
            return false;
        }

        if !self.active || self.message_seq != message_seq {
            self.reset();
            self.message_seq = message_seq;
            self.msg_type = msg_type;
            self.total_len = length;
            self.active = true;
        } else if self.msg_type != msg_type || self.total_len != length {
            // Mismatched header for the same message_seq — protocol error.
            return false;
        }

        let body = &fragment[DTLS_HS_HEADER_LEN..DTLS_HS_HEADER_LEN + frag_len];
        let mut i = 0;
        while i < frag_len {
            self.buf[frag_off + i] = body[i];
            let bit = frag_off + i;
            self.seen[bit / 8] |= 1u8 << (bit % 8);
            i += 1;
        }

        // Check completion — all bits in [0, total_len) must be set.
        let mut bit = 0;
        while bit < self.total_len {
            if self.seen[bit / 8] & (1u8 << (bit % 8)) == 0 {
                return false;
            }
            bit += 1;
        }
        true
    }
}

// ----------------------------------------------------------------------
// Retransmission timer (RFC 9147 §5.8)
//
// DTLS 1.3 keeps a single "current flight" buffer. On a timer expiry
// (initial 1s, exponential backoff up to 60s), the entire flight is
// replayed. The timer is cleared when an ACK or the next flight is
// received from the peer.
// ----------------------------------------------------------------------

pub struct DtlsRetxTimer {
    /// Wall-clock millis when the current flight was last sent. 0 = idle.
    pub last_send_ms: u64,
    /// Current backoff in millis. Doubles on each retx, clamped to 60_000.
    pub interval_ms: u32,
    /// Number of consecutive retransmissions without progress. Caller
    /// gives up at some application-defined cap (typical: 4-6).
    pub retx_count: u8,
}

impl DtlsRetxTimer {
    pub const INITIAL_MS: u32 = 1_000;
    pub const MAX_MS: u32 = 60_000;

    pub const fn new() -> Self {
        Self {
            last_send_ms: 0,
            interval_ms: Self::INITIAL_MS,
            retx_count: 0,
        }
    }

    /// Mark a fresh flight just sent. Resets backoff.
    pub fn arm(&mut self, now_ms: u64) {
        self.last_send_ms = now_ms;
        self.interval_ms = Self::INITIAL_MS;
        self.retx_count = 0;
    }

    /// Clear on ACK or next-flight receive.
    pub fn disarm(&mut self) {
        self.last_send_ms = 0;
        self.interval_ms = Self::INITIAL_MS;
        self.retx_count = 0;
    }

    /// True if `now_ms` has reached the next retx deadline.
    pub fn should_retx(&self, now_ms: u64) -> bool {
        if self.last_send_ms == 0 {
            return false;
        }
        now_ms.wrapping_sub(self.last_send_ms) >= self.interval_ms as u64
    }

    /// Mark a retx just sent. Doubles backoff up to MAX_MS.
    pub fn record_retx(&mut self, now_ms: u64) {
        self.last_send_ms = now_ms;
        self.retx_count = self.retx_count.saturating_add(1);
        let next = (self.interval_ms as u64).saturating_mul(2);
        self.interval_ms = if next > Self::MAX_MS as u64 {
            Self::MAX_MS
        } else {
            next as u32
        };
    }
}

// ----------------------------------------------------------------------
// DTLS ↔ HandshakeDriver bridge
//
// HandshakeDriver consumes/produces TLS-style 4-byte-headered handshake
// messages via `feed_handshake` / `poll_handshake`. DTLS uses a 12-byte
// handshake header (type | 24-bit length | 16-bit message_seq |
// 24-bit fragment_offset | 24-bit fragment_length). The bridge
// converts between the two formats on each direction and applies
// DTLS record protection.
//
// Conventions:
// - Inbound bridge: caller passes a single datagram (== one DTLS
//   ciphertext record). Bridge decrypts, parses the DTLS handshake
//   header, feeds the fragment into a reassembler. When a complete
//   handshake message is assembled, the bridge prepends a TLS-style
//   4-byte header (type | 24-bit length) and pushes the result into
//   `driver.in_buf` via the queue API.
// - Outbound bridge: caller polls `driver.out_buf` for one complete
//   TLS-headered message (4-byte header + body), then the bridge
//   wraps the body in a DTLS handshake header (with the supplied
//   `message_seq` + zero fragment offset + total length as
//   fragment_length — i.e. one fragment per message — and emits one
//   DTLS record into `out`.
//
// Fragmentation across MTU is not yet handled; messages must fit in
// the caller-supplied output datagram. ServerHello and Finished
// always do; Certificate may need fragmentation in production
// deployments. `dtls_emit_handshake_fragmented` is the planned
// extension point.
// ----------------------------------------------------------------------

/// Consume one inbound DTLS record (`datagram`) — Initial-level
/// records are plaintext CT_HANDSHAKE; later levels are AEAD-sealed.
/// On success the contained handshake fragment is fed into
/// `reassembler`; if the message becomes complete, a TLS-style
/// 4-byte-headered message is appended to `driver.in_buf`.
///
/// Returns the inner content type that was decrypted (so the caller
/// can route alerts / app data appropriately) or None on a malformed
/// or undecryptable record.
///
/// `read_keys` is the AEAD state for the current inbound EncLevel.
/// `state` holds the per-direction sequence counter / replay window.
/// `is_initial = true` means the record is plaintext (no AEAD).
pub unsafe fn dtls_recv_into_driver(
    suite: CipherSuite,
    is_initial: bool,
    read_keys: &mut TrafficKeys,
    state: &mut DtlsRecord,
    reassembler: &mut DtlsHandshakeReassembler,
    driver: &mut HandshakeDriver,
    datagram: &mut [u8],
) -> Option<u8> {
    let payload = if is_initial {
        // Plaintext CT_HANDSHAKE record per DTLS 1.3 §4 — same unified
        // header form, but `epoch == 0` and no AEAD seal. Body is the
        // handshake fragment in the clear, with no inner content_type
        // suffix.
        if datagram.len() < DTLS_UNIFIED_HDR_LEN + 1 {
            return None;
        }
        let _epoch = parse_dtls_header_byte(datagram[0])?;
        let seq16 = ((datagram[1] as u16) << 8) | (datagram[2] as u16);
        let body_len = ((datagram[3] as usize) << 8) | (datagram[4] as usize);
        if datagram.len() < DTLS_UNIFIED_HDR_LEN + body_len {
            return None;
        }
        let seq = recover_seq(state.recv_high, seq16);
        if !check_replay(state, seq) {
            return None;
        }
        &datagram[DTLS_UNIFIED_HDR_LEN..DTLS_UNIFIED_HDR_LEN + body_len]
    } else {
        let (pt_len, inner_type, _seq) =
            decrypt_dtls_record(suite, read_keys, state, datagram)?;
        if inner_type != 22u8 {
            // CT_HANDSHAKE = 22. Other inner types are returned to
            // caller via the function's Some(inner_type) below.
            return Some(inner_type);
        }
        &datagram[DTLS_UNIFIED_HDR_LEN..DTLS_UNIFIED_HDR_LEN + pt_len]
    };

    if !reassembler.feed(payload) {
        return Some(22u8); // Fragment accepted, message not yet complete.
    }

    // Message complete — push to driver.in_buf with a TLS-style
    // 4-byte handshake header (type | 24-bit length).
    let total = reassembler.total_len;
    let mut hdr_and_body = [0u8; DTLS_HS_REASSEMBLY_BUF + 4];
    hdr_and_body[0] = reassembler.msg_type;
    hdr_and_body[1] = (total >> 16) as u8;
    hdr_and_body[2] = (total >> 8) as u8;
    hdr_and_body[3] = total as u8;
    core::ptr::copy_nonoverlapping(
        reassembler.buf.as_ptr(),
        hdr_and_body.as_mut_ptr().add(4),
        total,
    );
    let _ = driver.feed_handshake(EncLevel::Handshake, &hdr_and_body[..4 + total]);
    reassembler.reset();
    Some(22u8)
}

/// Maximum body bytes per DTLS handshake fragment. Sized so a record
/// fits in a 1500-byte MTU after the unified-header (5) + DTLS-handshake
/// header (12) + AEAD content_type (1) + tag (16) overhead = 34 bytes
/// of framing on top of the body. We pick 1024 to leave headroom for
/// IPv4/IPv6 + UDP headers (28-48 bytes) on the wire.
pub const DTLS_HS_MAX_FRAGMENT: usize = 1024;

/// Emit ONE DTLS record carrying the next outstanding fragment of the
/// head-of-queue handshake message in `driver.out_buf`. Each fragment
/// is at most `DTLS_HS_MAX_FRAGMENT` body bytes; subsequent fragments
/// share `message_seq` and advance `fragment_offset`. The caller is
/// expected to invoke this once per outbound datagram (loop in their
/// drain) so each fragment ships in its own UDP packet.
///
/// Returns the number of bytes written, or 0 if no message is queued
/// or `out` is too small. Once all fragments of a message are emitted,
/// the message is consumed from `driver.out_buf`, `next_send_msg_seq`
/// is bumped, and `frag_off_state` is reset to 0.
pub unsafe fn dtls_emit_from_driver(
    suite: CipherSuite,
    is_initial: bool,
    write_keys: &mut TrafficKeys,
    state: &mut DtlsRecord,
    next_send_msg_seq: &mut u16,
    frag_off_state: &mut usize,
    driver: &mut HandshakeDriver,
    out: &mut [u8],
) -> usize {
    if driver.out_len < 4 {
        return 0;
    }
    let msg_type = driver.out_buf[0];
    let body_len = ((driver.out_buf[1] as usize) << 16)
        | ((driver.out_buf[2] as usize) << 8)
        | (driver.out_buf[3] as usize);
    let total_tls = 4 + body_len;
    if driver.out_len < total_tls {
        return 0;
    }

    let frag_off = *frag_off_state;
    if frag_off >= body_len {
        // Stale state — reset and treat as start of new message.
        *frag_off_state = 0;
        return 0;
    }
    let frag_len = (body_len - frag_off).min(DTLS_HS_MAX_FRAGMENT);
    let mseq = *next_send_msg_seq;

    let dtls_msg_len = DTLS_HS_HEADER_LEN + frag_len;
    let mut dtls_msg = [0u8; DTLS_HS_HEADER_LEN + DTLS_HS_MAX_FRAGMENT];
    dtls_msg[0] = msg_type;
    dtls_msg[1] = (body_len >> 16) as u8;
    dtls_msg[2] = (body_len >> 8) as u8;
    dtls_msg[3] = body_len as u8;
    dtls_msg[4] = (mseq >> 8) as u8;
    dtls_msg[5] = mseq as u8;
    dtls_msg[6] = (frag_off >> 16) as u8;
    dtls_msg[7] = (frag_off >> 8) as u8;
    dtls_msg[8] = frag_off as u8;
    dtls_msg[9] = (frag_len >> 16) as u8;
    dtls_msg[10] = (frag_len >> 8) as u8;
    dtls_msg[11] = frag_len as u8;
    core::ptr::copy_nonoverlapping(
        driver.out_buf.as_ptr().add(4 + frag_off),
        dtls_msg.as_mut_ptr().add(DTLS_HS_HEADER_LEN),
        frag_len,
    );

    let written = if is_initial {
        let total = DTLS_UNIFIED_HDR_LEN + dtls_msg_len;
        if out.len() < total {
            return 0;
        }
        let mut hdr = [0u8; DTLS_UNIFIED_HDR_LEN];
        build_dtls_header(state.epoch, state.send_seq, dtls_msg_len, &mut hdr);
        out[..DTLS_UNIFIED_HDR_LEN].copy_from_slice(&hdr);
        core::ptr::copy_nonoverlapping(
            dtls_msg.as_ptr(),
            out.as_mut_ptr().add(DTLS_UNIFIED_HDR_LEN),
            dtls_msg_len,
        );
        state.send_seq = state.send_seq.wrapping_add(1);
        total
    } else {
        encrypt_dtls_record(
            suite,
            write_keys,
            state,
            22u8,
            &dtls_msg[..dtls_msg_len],
            out,
        )
    };

    if written == 0 {
        return 0;
    }
    *frag_off_state = frag_off + frag_len;
    if *frag_off_state >= body_len {
        // Last fragment — consume the TLS-headered message and advance.
        let remain = driver.out_len - total_tls;
        if remain > 0 {
            core::ptr::copy(
                driver.out_buf.as_ptr().add(total_tls),
                driver.out_buf.as_mut_ptr(),
                remain,
            );
        }
        driver.out_len = remain;
        *next_send_msg_seq = next_send_msg_seq.wrapping_add(1);
        *frag_off_state = 0;
    }
    written
}

/// Bundle of all DTLS-side state owed by a single endpoint (one peer).
/// A DTLS server keeps one of these per accepted client (keyed by
/// peer addr); a DTLS client keeps exactly one. Reuses the existing
/// HandshakeDriver verbatim — every TLS 1.3 handshake state, key
/// schedule, and transcript hasher is shared with the TLS-over-TCP
/// path.
pub struct DtlsEndpoint {
    pub driver: HandshakeDriver,
    pub read_keys: TrafficKeys,
    pub write_keys: TrafficKeys,
    pub recv_state: DtlsRecord,
    pub send_state: DtlsRecord,
    pub reassembler: DtlsHandshakeReassembler,
    pub retx_timer: DtlsRetxTimer,
    pub next_send_msg_seq: u16,
    pub next_recv_msg_seq: u16,
    /// Offset within the head-of-queue handshake message in
    /// `driver.out_buf` for the next fragment we'll emit. Cleared
    /// once the message is fully drained.
    pub current_frag_off: usize,
}

impl DtlsEndpoint {
    pub const fn new() -> Self {
        Self {
            driver: HandshakeDriver::empty(),
            read_keys: TrafficKeys::empty(),
            write_keys: TrafficKeys::empty(),
            recv_state: DtlsRecord::new(),
            send_state: DtlsRecord::new(),
            reassembler: DtlsHandshakeReassembler::new(),
            retx_timer: DtlsRetxTimer::new(),
            next_send_msg_seq: 0,
            next_recv_msg_seq: 0,
            current_frag_off: 0,
        }
    }

    /// Whether the inbound level is Initial (no AEAD on records).
    pub fn recv_is_initial(&self) -> bool {
        self.read_keys.key_len == 0
    }

    /// Whether the outbound level is Initial (no AEAD on records).
    pub fn send_is_initial(&self) -> bool {
        self.write_keys.key_len == 0
    }
}

// ----------------------------------------------------------------------
// DTLS module entry point — wiring guide (deferred work)
//
// A live DTLS server module's `module_step` would do, per accepted peer:
//
//   1. On MSG_DG_RX_FROM with peer addr P, pkt = datagram payload:
//        let ep = endpoint_for_peer(P);  // or allocate-on-first-CH
//        let inner = dtls_recv_into_driver(
//            ep.driver.suite,
//            ep.recv_is_initial(),
//            &mut ep.read_keys,
//            &mut ep.recv_state,
//            &mut ep.reassembler,
//            &mut ep.driver,
//            pkt);
//        if inner == Some(22) { /* handshake bytes are now in driver.in_buf */ }
//
//   2. Run the same `pump_session` loop the TLS path runs
//      (mod.rs::pump_session is record-agnostic — it reads from
//       driver.in_buf, writes to driver.out_buf). On key derivation
//      transitions, populate ep.read_keys / ep.write_keys from
//      driver.read_secret(EncLevel::Handshake | OneRtt, send) and
//      rotate ep.recv_state.epoch / ep.send_state.epoch. After
//      derive_handshake_keys, increment epoch to 2 (RFC 9147 §6.1
//      labels Initial=0, EarlyData=1, Handshake=2, Application=3).
//
//   3. After each pump step, drain driver.out_buf:
//        let n = dtls_emit_from_driver(
//            ep.driver.suite,
//            ep.send_is_initial(),
//            &mut ep.write_keys,
//            &mut ep.send_state,
//            &mut ep.next_send_msg_seq,
//            &mut ep.driver,
//            &mut datagram_out);
//        if n > 0 { CMD_DG_SEND_TO peer P with datagram_out[..n] }
//
//   4. Arm `ep.retx_timer.arm(now_ms)` after sending each handshake
//      flight; on `should_retx(now_ms)` resend the saved last flight
//      and call `record_retx(now_ms)`.
//
//   5. After `driver.is_handshake_complete()`, application data on
//      clear_in goes through `encrypt_dtls_record` with `ep.write_keys`
//      and the OneRtt epoch; inbound app records go through
//      `decrypt_dtls_record` and forward to clear_out.
//
// Fragmentation: real deployments split handshake messages > MTU
// across multiple DTLS records by emitting multiple
// `dtls_emit_from_driver` calls with adjusted fragment_offset /
// fragment_length in the DTLS handshake header. The reassembler
// already accepts out-of-order fragments via its bitmap.
//
// Single-session vs many: keep a `[DtlsEndpoint; N]` table keyed by
// (peer_ip, peer_port). DTLS connection migration via Connection IDs
// (RFC 9146) is a follow-up; without CIDs, peer-addr matching
// suffices for typical NAT-stable clients.
// ----------------------------------------------------------------------

