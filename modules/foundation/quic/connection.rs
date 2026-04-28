// QUIC v1 connection state (RFC 9000 + RFC 9001).
//
// Each connection holds three packet number spaces (Initial,
// Handshake, 1-RTT) with per-direction packet protection keys, an
// AckTracker, packet-number counters, and CRYPTO frame offsets
// (per RFC 9001 §4.1 — each EncLevel has its own crypto stream).
//
// The TLS 1.3 handshake bytes flow through `HandshakeDriver`'s queue
// API (`feed_handshake` / `poll_handshake`), so the state machine
// inside the driver is byte-identical with TLS-over-TCP and DTLS.
// QUIC just frames those bytes as CRYPTO frames inside Initial /
// Handshake / 1-RTT packets and applies QUIC-specific packet
// protection.

pub const QUIC_DGRAM_MAX: usize = 1500;
pub const INITIAL_MIN_DATAGRAM_LEN: usize = 1200;
pub const QUIC_CRYPTO_BUF: usize = 4096;

/// Maximum Retry token length we'll ever emit / accept. Our token
/// format (see `mod.rs::build_retry_token`) packs an 8-byte expiry,
/// 4-byte peer IPv4, 2-byte port, ODCID-len + ODCID (≤20), and a
/// 16-byte HMAC tag — 51 bytes worst case. Round to 64.
pub const MAX_RETRY_TOKEN_LEN: usize = 64;

/// NewReno tunables (RFC 9002 §B.1).
/// Congestion window measured in bytes; max_datagram_size = 1500 since
/// our wire layer caps datagrams at QUIC_DGRAM_MAX.
pub const MAX_DATAGRAM_SIZE: u64 = 1500;
/// Initial window: min(10 * MAX_DATAGRAM, max(2*MAX_DATAGRAM, 14720)).
/// = min(15000, max(3000, 14720)) = 14720.
pub const INITIAL_WINDOW: u64 = 14720;
/// Minimum congestion window after persistent congestion (RFC 9002
/// §B.2). 2 * MAX_DATAGRAM_SIZE.
pub const MINIMUM_WINDOW: u64 = 2 * MAX_DATAGRAM_SIZE;
/// Loss reduction factor (NewReno halves cwnd on loss).
pub const LOSS_REDUCTION_NUMERATOR: u64 = 1;
pub const LOSS_REDUCTION_DENOMINATOR: u64 = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConnPhase {
    Idle,
    Handshaking,
    Established,
    Closed,
    Errored,
}

// ----------------------------------------------------------------------
// CRYPTO frame reassembler (RFC 9000 §19.6).
//
// Each EncLevel has its own crypto stream with offset-addressed bytes.
// Frames may arrive out of order, overlap, or duplicate prior bytes.
// We keep a 4KB hold buffer + a bitmap covering its bytes and feed
// contiguous prefixes into the HandshakeDriver via `feed_handshake`.
// ----------------------------------------------------------------------

pub const CRYPTO_HOLD_LEN: usize = 4096;

pub struct CryptoReassembler {
    /// Bytes received but not yet delivered, indexed relative to the
    /// current `delivered_offset` (which lives in PnSpace as
    /// `crypto_recv_offset`).
    pub buf: [u8; CRYPTO_HOLD_LEN],
    /// `seen[i]` bit i = 1 if byte at relative offset i is in `buf`.
    pub seen: [u8; CRYPTO_HOLD_LEN / 8],
    /// Highest contiguous-from-base byte index buffered (one past the
    /// last contiguous byte). Used to short-circuit the bitmap scan.
    pub contiguous_high: usize,
}

impl CryptoReassembler {
    pub const fn new() -> Self {
        Self {
            buf: [0; CRYPTO_HOLD_LEN],
            seen: [0; CRYPTO_HOLD_LEN / 8],
            contiguous_high: 0,
        }
    }

    pub fn reset(&mut self) {
        let mut i = 0;
        while i < CRYPTO_HOLD_LEN / 8 {
            self.seen[i] = 0;
            i += 1;
        }
        self.contiguous_high = 0;
    }

    /// Insert a fragment whose first byte is at relative offset
    /// `rel_off` (= absolute_offset - delivered_offset). Returns the
    /// number of bytes that newly become contiguous-from-zero (the
    /// caller feeds those bytes to the driver and shifts the buffer).
    pub fn insert(&mut self, rel_off: usize, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        if rel_off + data.len() > CRYPTO_HOLD_LEN {
            // Overrun — peer sent more than our hold can carry. Drop
            // the excess; if the lost bytes never get retransmitted
            // the handshake will time out (which is fine — production
            // deployments would size the hold larger).
            let n = if rel_off >= CRYPTO_HOLD_LEN {
                0
            } else {
                CRYPTO_HOLD_LEN - rel_off
            };
            self.write_range(rel_off, &data[..n]);
        } else {
            self.write_range(rel_off, data);
        }

        // Recompute the contiguous-from-zero high water mark.
        while self.contiguous_high < CRYPTO_HOLD_LEN {
            let bit = self.contiguous_high;
            let byte = self.seen[bit / 8];
            if byte & (1u8 << (bit % 8)) == 0 {
                break;
            }
            self.contiguous_high += 1;
        }
        self.contiguous_high
    }

    fn write_range(&mut self, rel_off: usize, data: &[u8]) {
        let mut i = 0;
        while i < data.len() && rel_off + i < CRYPTO_HOLD_LEN {
            self.buf[rel_off + i] = data[i];
            let bit = rel_off + i;
            self.seen[bit / 8] |= 1u8 << (bit % 8);
            i += 1;
        }
    }

    /// Drain `n` bytes from the front of the hold, shifting buffered
    /// data + bitmap down by `n` bytes. Caller has already fed the
    /// drained bytes into the driver.
    pub fn shift(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        let n = if n > CRYPTO_HOLD_LEN { CRYPTO_HOLD_LEN } else { n };
        unsafe {
            core::ptr::copy(
                self.buf.as_ptr().add(n),
                self.buf.as_mut_ptr(),
                CRYPTO_HOLD_LEN - n,
            );
        }
        // Shift the bitmap.
        let mut i = 0;
        while i + n < CRYPTO_HOLD_LEN {
            let src_bit = i + n;
            let bit = (self.seen[src_bit / 8] >> (src_bit % 8)) & 1;
            let dst_byte = i / 8;
            let dst_bit = i % 8;
            self.seen[dst_byte] = (self.seen[dst_byte] & !(1u8 << dst_bit)) | (bit << dst_bit);
            i += 1;
        }
        // Clear the trailing bits.
        while i < CRYPTO_HOLD_LEN {
            let dst_byte = i / 8;
            let dst_bit = i % 8;
            self.seen[dst_byte] &= !(1u8 << dst_bit);
            i += 1;
        }
        self.contiguous_high = self.contiguous_high.saturating_sub(n);
    }
}

// ---------------------------------------------------------------------
// Per-connection stream pools beyond the legacy bidi stream id 0.
//
// `extra_streams` carries the small unidirectional streams HTTP/3
// uses for control + QPACK encoder/decoder traffic
// (RFC 9114 §6.2 + RFC 9204 §4.2); `bidi_extra_streams` carries
// concurrent bidirectional request streams (stream ids 4, 8, … on
// the client; 5, 9, … on the server).
// ---------------------------------------------------------------------

pub const MAX_EXTRA_STREAMS: usize = 6;
pub const MAX_BIDI_EXTRA_STREAMS: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum H3StreamRole {
    Unknown,
    Control,
    QpackEncoder,
    QpackDecoder,
    Push,
    /// Additional bidi (e.g. concurrent request) — carries h3 frames.
    BidiRequest,
}

#[derive(Clone, Copy)]
pub struct ExtraStream {
    pub stream_id: u64,
    pub allocated: bool,
    /// True when WE locally initiated this stream (we own its send
    /// half). For received unidirectional streams this is false and
    /// the send half is unused.
    pub locally_initiated: bool,
    pub h3_role: H3StreamRole,
    /// For received unidirectional streams: have we consumed the
    /// varint stream-type prefix yet (RFC 9114 §6.2)?
    pub h3_type_consumed: bool,

    pub send_off: u64,
    pub send_buf: [u8; 256],
    pub send_buf_len: usize,
    pub send_fin_pending: bool,
    pub send_fin_emitted: bool,

    pub recv_off: u64,
    pub recv_buf: [u8; 256],
    pub recv_buf_len: usize,
    pub recv_fin: bool,
}

impl ExtraStream {
    pub const fn empty() -> Self {
        Self {
            stream_id: 0,
            allocated: false,
            locally_initiated: false,
            h3_role: H3StreamRole::Unknown,
            h3_type_consumed: false,
            send_off: 0,
            send_buf: [0; 256],
            send_buf_len: 0,
            send_fin_pending: false,
            send_fin_emitted: false,
            recv_off: 0,
            recv_buf: [0; 256],
            recv_buf_len: 0,
            recv_fin: false,
        }
    }
}

/// One bidi h3 request stream beyond stream id 0. Sized to carry a
/// full HEADERS+DATA flight in each direction plus per-stream POST
/// body accumulation; distinct from [`ExtraStream`] so the uni-stream
/// pool can stay narrow.
#[derive(Clone, Copy)]
pub struct BidiExtraStream {
    pub stream_id: u64,
    pub allocated: bool,
    /// True when the local endpoint opened the stream (client GET /
    /// POST). False for server-side slots that hold a peer-initiated
    /// request.
    pub locally_initiated: bool,

    pub send_off: u64,
    pub send_buf: [u8; 1200],
    pub send_buf_len: usize,
    pub send_fin_pending: bool,
    pub send_fin_emitted: bool,

    pub recv_off: u64,
    pub recv_buf: [u8; 1500],
    pub recv_buf_len: usize,
    pub recv_fin: bool,

    /// Per-slot POST body accumulation; mirrors the legacy stream's
    /// `h3_post_*` fields on `QuicConnection`.
    pub h3_post_in_progress: bool,
    pub h3_post_dispatched: bool,
    pub h3_post_path: [u8; 64],
    pub h3_post_path_len: usize,
    pub h3_post_body: [u8; 1024],
    pub h3_post_body_len: usize,
}

impl BidiExtraStream {
    pub const fn empty() -> Self {
        Self {
            stream_id: 0,
            allocated: false,
            locally_initiated: false,
            send_off: 0,
            send_buf: [0; 1200],
            send_buf_len: 0,
            send_fin_pending: false,
            send_fin_emitted: false,
            recv_off: 0,
            recv_buf: [0; 1500],
            recv_buf_len: 0,
            recv_fin: false,
            h3_post_in_progress: false,
            h3_post_dispatched: false,
            h3_post_path: [0; 64],
            h3_post_path_len: 0,
            h3_post_body: [0; 1024],
            h3_post_body_len: 0,
        }
    }
}

/// In-flight packet record (RFC 9002 §A.1) — stored in a small ring
/// per `PnSpace`. Tracks the bytes the packet contributes to
/// `bytes_in_flight` so they can be backed out on ACK or loss.
#[derive(Clone, Copy)]
pub struct SentPacket {
    pub pn: u64,
    pub bytes: u32,
    pub sent_ms: u64,
    pub ack_eliciting: bool,
    pub in_flight: bool,
    /// True until acked or declared lost.
    pub live: bool,
}

impl SentPacket {
    pub const fn empty() -> Self {
        Self {
            pn: 0,
            bytes: 0,
            sent_ms: 0,
            ack_eliciting: false,
            in_flight: false,
            live: false,
        }
    }
}

pub const SENT_PACKET_RING: usize = 16;

/// Per-EncLevel packet number space + crypto state.
pub struct PnSpace {
    pub read_keys: QuicKeys,
    pub write_keys: QuicKeys,
    pub keys_set: bool,
    pub next_send_pn: u64,
    pub largest_recv_pn: u64,
    pub crypto_recv_offset: u64,
    pub crypto_send_offset: u64,
    pub ack_tracker: AckTracker,
    pub ack_pending: bool,
    pub reassembler: CryptoReassembler,

    /// Last emitted packet (post-AEAD ciphertext) retained for retx
    /// (RFC 9002 §6). On a retx-timer expiry the bytes are re-sent
    /// to the peer. On receipt of an ACK covering `last_emitted_pn`,
    /// the buffer is cleared. Sized to the largest packet we ever
    /// produce (~1500 bytes including padding).
    pub last_emitted: [u8; 1500],
    pub last_emitted_len: usize,
    pub last_emitted_pn: u64,
    /// Wall-clock millis when the last_emitted packet was sent.
    /// Zero = no outstanding packet.
    pub last_emitted_ms: u64,
    /// Largest packet number the peer has acknowledged in this space
    /// (from inbound ACK frames). Used to drop `last_emitted` once
    /// covered.
    pub peer_acked_largest: u64,
    pub peer_acked_seen: bool,

    /// Ring of recently-sent in-flight packets (RFC 9002 §A.1). On
    /// ACK we look up the matching pn here and credit `bytes_in_flight`
    /// + drive the NewReno controller. Older entries roll out as new
    /// packets are sent.
    pub sent_packets: [SentPacket; SENT_PACKET_RING],
    pub sent_head: usize,

    // ── Key update (RFC 9001 §6) — only meaningful at OneRtt ───────
    /// Current key phase (0 or 1). Set in the KEY_PHASE bit of the
    /// short-header first byte. Both sides start at 0.
    pub key_phase: u8,
    /// Active read/write traffic secrets — used to derive read_keys /
    /// write_keys above + to chain into the next-phase secret.
    pub read_secret: [u8; 48],
    pub write_secret: [u8; 48],
    pub secret_len: u8,
    /// Pre-derived next-phase keys, ready to switch to on a phase
    /// flip. Lazy-initialised after one_rtt secrets are installed.
    pub next_read_keys: QuicKeys,
    pub next_write_keys: QuicKeys,
    pub next_read_secret: [u8; 48],
    pub next_write_secret: [u8; 48],
    pub next_keys_ready: bool,
}

impl PnSpace {
    pub const fn new() -> Self {
        Self {
            read_keys: QuicKeys::empty(),
            write_keys: QuicKeys::empty(),
            keys_set: false,
            next_send_pn: 0,
            largest_recv_pn: 0,
            crypto_recv_offset: 0,
            crypto_send_offset: 0,
            ack_tracker: AckTracker::new(),
            ack_pending: false,
            reassembler: CryptoReassembler::new(),
            last_emitted: [0; 1500],
            last_emitted_len: 0,
            last_emitted_pn: 0,
            last_emitted_ms: 0,
            peer_acked_largest: 0,
            peer_acked_seen: false,
            sent_packets: [SentPacket::empty(); SENT_PACKET_RING],
            sent_head: 0,
            key_phase: 0,
            read_secret: [0; 48],
            write_secret: [0; 48],
            secret_len: 0,
            next_read_keys: QuicKeys::empty(),
            next_write_keys: QuicKeys::empty(),
            next_read_secret: [0; 48],
            next_write_secret: [0; 48],
            next_keys_ready: false,
        }
    }

    /// Place a freshly-sent packet into a free slot. Returns true on
    /// success. Returns false when every slot is still live (meaning
    /// every previously-tracked packet is unacked) — caller must
    /// treat this as a transient back-pressure signal and retry once
    /// ACKs free a slot. Never overwriting a live entry preserves
    /// `bytes_in_flight` accounting: an inbound ACK can always find
    /// the original entry to credit back.
    pub fn record_sent(&mut self, pkt: SentPacket) -> bool {
        // Prefer the slot at sent_head if it's free, otherwise sweep
        // the whole ring. Sweeping is O(SENT_PACKET_RING) which is
        // fine for a 16-slot ring.
        let mut idx = self.sent_head;
        if self.sent_packets[idx].live {
            let mut found = usize::MAX;
            let mut k = 0;
            while k < SENT_PACKET_RING {
                let probe = (self.sent_head + k) % SENT_PACKET_RING;
                if !self.sent_packets[probe].live {
                    found = probe;
                    break;
                }
                k += 1;
            }
            if found == usize::MAX {
                return false;
            }
            idx = found;
        }
        self.sent_packets[idx] = pkt;
        self.sent_head = (idx + 1) % SENT_PACKET_RING;
        true
    }

    /// Returns true iff the ring has at least one slot that's not
    /// currently holding a live (unacked / unlost) packet. Used as a
    /// pre-emit gate so we never have to overwrite a live entry — see
    /// `record_sent` for why losing the entry breaks bytes_in_flight
    /// accounting.
    pub fn has_free_sent_slot(&self) -> bool {
        let mut k = 0;
        while k < SENT_PACKET_RING {
            if !self.sent_packets[k].live {
                return true;
            }
            k += 1;
        }
        false
    }

    /// Walk the ring and find the entry matching `pn`. Returns its
    /// (bytes, ack_eliciting, in_flight, sent_ms, idx) or None.
    pub fn find_sent(&self, pn: u64) -> Option<(u32, bool, bool, u64, usize)> {
        let mut i = 0;
        while i < SENT_PACKET_RING {
            let p = &self.sent_packets[i];
            if p.live && p.pn == pn {
                return Some((p.bytes, p.ack_eliciting, p.in_flight, p.sent_ms, i));
            }
            i += 1;
        }
        None
    }

    /// Mark the entry at index `idx` as no longer live (acked or lost).
    pub fn clear_sent(&mut self, idx: usize) {
        self.sent_packets[idx].live = false;
    }
}

#[derive(Clone, Copy)]
pub struct PeerAddr {
    pub ip: [u8; 4],
    pub port: u16,
}

impl PeerAddr {
    pub const fn unset() -> Self {
        Self { ip: [0; 4], port: 0 }
    }
    pub fn matches(&self, ip: &[u8; 4], port: u16) -> bool {
        self.ip[0] == ip[0]
            && self.ip[1] == ip[1]
            && self.ip[2] == ip[2]
            && self.ip[3] == ip[3]
            && self.port == port
    }
    pub fn is_unset(&self) -> bool {
        self.port == 0
    }
}

/// RTT estimator state per connection (RFC 9002 §5).
/// Smoothed RTT + variance + min RTT, all in milliseconds. The PTO
/// computation in `quic_pto_check` reads these to size the timer.
pub struct RttSample {
    /// Most recent RTT sample (ms). 0 = uninitialised.
    pub latest_rtt: u32,
    /// Smoothed RTT (RFC 9002 §5.3). Initialised to first sample.
    pub smoothed_rtt: u32,
    /// RTT variance.
    pub rttvar: u32,
    /// Minimum observed RTT — never increased.
    pub min_rtt: u32,
    /// True once we have at least one sample.
    pub seeded: bool,
}

impl RttSample {
    pub const fn new() -> Self {
        Self {
            latest_rtt: 0,
            smoothed_rtt: 333, // RFC 9002 §6.2.2 default kInitialRtt = 333ms
            rttvar: 333 / 2,
            min_rtt: u32::MAX,
            seeded: false,
        }
    }

    /// Apply a fresh sample (RFC 9002 §5.3 update rule).
    /// Caller passes the wall-clock latency in milliseconds.
    pub fn update(&mut self, sample_ms: u32) {
        self.latest_rtt = sample_ms;
        if !self.seeded {
            self.min_rtt = sample_ms;
            self.smoothed_rtt = sample_ms;
            self.rttvar = sample_ms / 2;
            self.seeded = true;
            return;
        }
        if sample_ms < self.min_rtt {
            self.min_rtt = sample_ms;
        }
        // RFC 9002 §5.3: rttvar = 3/4 * rttvar + 1/4 * |smoothed - latest|
        // smoothed = 7/8 * smoothed + 1/8 * latest
        let abs_diff = if self.smoothed_rtt > sample_ms {
            self.smoothed_rtt - sample_ms
        } else {
            sample_ms - self.smoothed_rtt
        };
        self.rttvar = (3 * self.rttvar + abs_diff) / 4;
        self.smoothed_rtt = (7 * self.smoothed_rtt + sample_ms) / 8;
    }

    /// Probe Timeout (RFC 9002 §6.2.1) in milliseconds.
    /// PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay
    /// kGranularity defaults to 1ms; max_ack_delay defaults to 25ms
    /// (RFC 9002 §6.2 + §A.2).
    pub fn pto(&self) -> u32 {
        const K_GRANULARITY: u32 = 1;
        const MAX_ACK_DELAY: u32 = 25;
        let var_term = (4u32 * self.rttvar).max(K_GRANULARITY);
        self.smoothed_rtt.saturating_add(var_term).saturating_add(MAX_ACK_DELAY)
    }
}

pub struct QuicConnection {
    pub phase: ConnPhase,
    pub is_server: bool,
    pub peer: PeerAddr,
    /// RTT estimator state (RFC 9002 §5.3 + §6.2.1 PTO).
    pub rtt: RttSample,
    /// Connection IDs as picked by us / by the peer. RFC 9000 §5.1.
    /// Server's SCID becomes the client's DCID for subsequent packets;
    /// client's SCID becomes the server's DCID. Initial keys derive
    /// from the *original* DCID the client placed in its very first
    /// Initial packet.
    pub our_cid: [u8; MAX_CID_LEN],
    pub our_cid_len: u8,
    pub peer_cid: [u8; MAX_CID_LEN],
    pub peer_cid_len: u8,
    pub original_dcid: [u8; MAX_CID_LEN],
    pub original_dcid_len: u8,

    pub driver: HandshakeDriver,
    pub initial: PnSpace,
    pub handshake: PnSpace,
    pub one_rtt: PnSpace,

    /// Inbound datagram staging — module_step reads MSG_DG_RX_FROM
    /// bytes here, then a per-connection processor drains records.
    pub inbound: [u8; QUIC_DGRAM_MAX],
    pub inbound_len: usize,
    /// Offset into `inbound` for the next-packet boundary. Coalesced
    /// packets per RFC 9000 §12.2: we process one at a time so the
    /// pump can rotate keys (e.g., install handshake keys after
    /// processing the Initial packet) before the next one is
    /// decrypted. Reset to 0 alongside `inbound_len` once fully drained.
    pub inbound_off: usize,

    /// Server-only: HANDSHAKE_DONE frame queued for emission on the
    /// next 1-RTT packet (RFC 9001 §4.1.2). Cleared on emit.
    pub pending_handshake_done: bool,
    /// Whether the peer has confirmed handshake by sending us
    /// HANDSHAKE_DONE (client-side) or by sending an ack-eliciting
    /// 1-RTT packet (server-side, per RFC 9001 §4.1.2).
    pub handshake_confirmed: bool,

    // ── Bidirectional stream 0 — the only application stream this
    // revision supports. The client opens it with stream_id=0 (per
    // RFC 9000 §2.1: client-initiated bidi); the server replies on
    // the same id. STREAM frames carry app payload byte-for-byte.
    /// Highest offset the application has produced for outbound on this
    /// stream. Each outbound STREAM frame ships
    /// data[stream_send_off..stream_send_off+n] and advances the offset.
    pub stream_send_off: u64,
    /// Pending bytes from `clear_in` waiting to be wrapped in STREAM
    /// frames. Sized to fit one MTU's worth of unframed data.
    pub stream_send_buf: [u8; 1200],
    pub stream_send_buf_len: usize,
    /// Whether the local app has signalled end-of-stream (clear_in closed).
    pub stream_send_fin: bool,

    /// Highest contiguous offset received from the peer; bytes up to
    /// this point have either been forwarded to clear_out or are
    /// staged in `stream_recv_buf`.
    pub stream_recv_off: u64,
    /// Whether the peer signalled end-of-stream.
    pub stream_recv_fin: bool,
    /// Newly-arrived inbound stream bytes pending forward to
    /// clear_out. The module's pump_loop drains this each tick.
    pub stream_recv_buf: [u8; 1500],
    pub stream_recv_buf_len: usize,
    /// Set after the client queues its first auto-emitted stream
    /// message so the loop doesn't re-queue every step.
    pub test_sent: bool,

    // ── Retry (RFC 9000 §17.2.5 + §8.1.2) ──────────────────────────
    /// Whether this connection went through a Retry exchange. Used by
    /// (a) the server to decide whether to emit `retry_source_cid` in
    /// its EncryptedExtensions transport_parameters, and (b) the client
    /// to validate the server's `retry_source_cid` matches the SCID it
    /// observed in the Retry packet.
    pub used_retry: bool,
    /// The SCID the server placed in the Retry packet. On the server
    /// side this == `our_cid` post-retry; on the client side it's
    /// captured when the Retry is received.
    pub retry_source_cid: [u8; MAX_CID_LEN],
    pub retry_source_cid_len: u8,
    /// Retry token from the server. Client side: persisted across the
    /// re-emitted ClientHello so the second Initial header carries it.
    /// Sized to fit the longest token we'll emit (RFC 9000 places no
    /// formal limit; our token format below fits in 64 bytes).
    pub retry_token: [u8; MAX_RETRY_TOKEN_LEN],
    pub retry_token_len: usize,
    /// Tracks how many congestion-eligible bytes are currently in the
    /// network — incremented on emit, decremented on ACK. RFC 9002 §A.
    pub bytes_in_flight: u64,
    /// NewReno congestion window in bytes (RFC 9002 §A.4 + §A.6).
    pub congestion_window: u64,
    /// Slow-start threshold; transition to congestion avoidance once
    /// `congestion_window >= ssthresh`.
    pub ssthresh: u64,
    /// Wall-clock millis when the most recent congestion-recovery
    /// period started (RFC 9002 §A.7). New loss events that fall
    /// inside an existing recovery period don't re-collapse the window.
    pub recovery_start_time: u64,
    /// Largest acknowledged 1-RTT PN — used to age out the window.
    pub largest_acked_one_rtt: u64,
    pub largest_acked_one_rtt_seen: bool,

    // ── 0-RTT (RFC 8446 §4.2.10 + RFC 9001 §4.1.1) ──────────────────
    /// Negotiated PSK for this connection. When non-empty the
    /// handshake takes the resumption path.
    pub psk: [u8; 48],
    pub psk_len: u8,
    /// Identity bytes the client placed in / server selected from the
    /// PSK extension (used to look up the server's stored RMS for
    /// resumption + recompute the binder).
    pub psk_identity: [u8; 32],
    pub psk_identity_len: u8,
    /// Whether the client offered 0-RTT in its CH and the server has
    /// accepted (EE has early_data ext). False for both sides until
    /// confirmed.
    pub zero_rtt_accepted: bool,
    /// Whether the client offered 0-RTT (independent of acceptance).
    pub zero_rtt_offered: bool,
    /// Whether the server selected our (single) PSK identity.
    pub psk_selected: bool,
    /// 0-RTT (early-traffic) packet protection keys, derived from the
    /// `client_early_traffic_secret`. Both sides install symmetrically.
    pub zero_rtt_keys: QuicKeys,
    pub zero_rtt_keys_set: bool,
    /// Bytes the client wants to send as 0-RTT app data, forwarded
    /// to `stream_send_buf` once the handshake confirms.
    pub zero_rtt_payload: [u8; 256],
    pub zero_rtt_payload_len: usize,
    /// Whether NewSessionTicket has been emitted (server) or received
    /// (client). One-shot per connection.
    pub session_ticket_handled: bool,

    // ── Multi-stream support (HTTP/3 control + QPACK uni streams) ──
    pub extra_streams: [ExtraStream; MAX_EXTRA_STREAMS],
    /// Pool for concurrent bidi h3 request streams beyond stream id 0
    /// (client ids 4, 8, 12, …; server ids 5, 9, 13, …).
    pub bidi_extra_streams: [BidiExtraStream; MAX_BIDI_EXTRA_STREAMS],
    /// Whether we have already opened our HTTP/3 unidirectional streams
    /// (control + qpack-enc + qpack-dec) on this connection.
    pub h3_uni_streams_opened: bool,
    /// Counter for self-allocated unidirectional stream ids. Server
    /// uni = 3, 7, 11, ...; client uni = 2, 6, 10, ... — both
    /// increment by 4. We track the next index to allocate.
    pub h3_next_uni_idx: u8,
    /// Whether the peer's SETTINGS has been observed on its control
    /// stream. Becomes true once we successfully parse one SETTINGS
    /// frame from the peer's recv'd control-stream payload.
    pub h3_peer_settings_seen: bool,
    /// Whether the peer offered SETTINGS_ENABLE_CONNECT_PROTOCOL=1
    /// (RFC 9220 §3) so we can use extended CONNECT for WebSocket.
    pub h3_peer_enable_connect: bool,
    /// Sequence counter for our own bidi stream allocations on the
    /// client side. First client bidi = id 0; subsequent = 4, 8, ...
    pub h3_next_bidi_idx: u8,
    /// WebSocket-over-HTTP/3 mode (RFC 9220). When true, the bidi
    /// request stream's DATA frame payloads are interpreted as WS
    /// frames rather than application body bytes. Set on both sides
    /// once the extended-CONNECT exchange completes (server: on
    /// receiving the CONNECT request and emitting 200; client: on
    /// receiving the 200 response).
    pub ws_mode: bool,
    /// Whether the client has already emitted its initial WS payload.
    /// One-shot per connection.
    pub ws_test_sent: bool,
    /// Whether the client has already emitted its second concurrent
    /// `GET /two` request on the bidi extra pool. One-shot per
    /// connection.
    pub concurrent_bidi_sent: bool,
    /// Reassembly buffer for incoming WS frames whose bytes might be
    /// split across multiple h3 DATA frames.
    pub ws_recv_accum: [u8; 256],
    pub ws_recv_accum_len: usize,
    /// Per-message reassembly buffer — accumulates payload bytes
    /// across continuation frames (RFC 6455 §5.4). Reset on FIN.
    pub ws_msg_buf: [u8; 512],
    pub ws_msg_len: usize,
    /// Opcode of the in-progress message (TEXT/BINARY). Set by the
    /// first frame; CONT (0x0) frames extend it. Zero = no message.
    pub ws_msg_opcode: u8,
    /// UTF-8 streaming validator state for in-progress TEXT messages.
    /// Reset to UTF8_ACCEPT on each new message; mid-message
    /// continuation frames feed into it; rejection triggers a
    /// connection-close with code 1007 (RFC 6455 §8.1).
    pub ws_utf8_state: u32,

    /// Wall-clock millis of the most recent activity on this conn —
    /// any inbound packet decrypt success, any outbound emit. Drives
    /// idle-timeout closure (RFC 9000 §10.1). Zero = uninitialised
    /// (set to first dev_millis() on connection open).
    pub last_activity_ms: u64,
    /// Negotiated idle timeout in ms (the smaller of our + peer
    /// `max_idle_timeout` TPs, RFC 9000 §10.1.2). 0 = disabled.
    pub idle_timeout_ms: u64,

    // ── HTTP/3 POST body accumulation ──────────────────────────────
    /// Server-side flag: a POST request's HEADERS arrived; awaiting
    /// DATA frames + FIN before dispatch.
    pub h3_post_in_progress: bool,
    /// Saved request path for the in-flight POST.
    pub h3_post_path: [u8; 64],
    pub h3_post_path_len: usize,
    /// Accumulated request body bytes.
    pub h3_post_body: [u8; 1024],
    pub h3_post_body_len: usize,
    /// Whether we've already dispatched (single-shot).
    pub h3_post_dispatched: bool,
}

impl QuicConnection {
    pub const fn new() -> Self {
        Self {
            phase: ConnPhase::Idle,
            is_server: false,
            peer: PeerAddr::unset(),
            rtt: RttSample::new(),
            our_cid: [0; MAX_CID_LEN],
            our_cid_len: 0,
            peer_cid: [0; MAX_CID_LEN],
            peer_cid_len: 0,
            original_dcid: [0; MAX_CID_LEN],
            original_dcid_len: 0,
            driver: HandshakeDriver::empty(),
            initial: PnSpace::new(),
            handshake: PnSpace::new(),
            one_rtt: PnSpace::new(),
            inbound: [0; QUIC_DGRAM_MAX],
            inbound_len: 0,
            inbound_off: 0,
            pending_handshake_done: false,
            handshake_confirmed: false,
            stream_send_off: 0,
            stream_send_buf: [0; 1200],
            stream_send_buf_len: 0,
            stream_send_fin: false,
            stream_recv_off: 0,
            stream_recv_fin: false,
            stream_recv_buf: [0; 1500],
            stream_recv_buf_len: 0,
            test_sent: false,
            used_retry: false,
            retry_source_cid: [0; MAX_CID_LEN],
            retry_source_cid_len: 0,
            retry_token: [0; MAX_RETRY_TOKEN_LEN],
            retry_token_len: 0,
            bytes_in_flight: 0,
            congestion_window: INITIAL_WINDOW,
            ssthresh: u64::MAX,
            recovery_start_time: 0,
            largest_acked_one_rtt: 0,
            largest_acked_one_rtt_seen: false,
            psk: [0; 48],
            psk_len: 0,
            psk_identity: [0; 32],
            psk_identity_len: 0,
            zero_rtt_accepted: false,
            zero_rtt_offered: false,
            psk_selected: false,
            zero_rtt_keys: QuicKeys::empty(),
            zero_rtt_keys_set: false,
            zero_rtt_payload: [0; 256],
            zero_rtt_payload_len: 0,
            session_ticket_handled: false,
            extra_streams: [ExtraStream::empty(); MAX_EXTRA_STREAMS],
            bidi_extra_streams: [BidiExtraStream::empty(); MAX_BIDI_EXTRA_STREAMS],
            h3_uni_streams_opened: false,
            h3_next_uni_idx: 0,
            h3_peer_settings_seen: false,
            h3_peer_enable_connect: false,
            h3_next_bidi_idx: 0,
            ws_mode: false,
            ws_test_sent: false,
            concurrent_bidi_sent: false,
            ws_recv_accum: [0; 256],
            ws_recv_accum_len: 0,
            ws_msg_buf: [0; 512],
            ws_msg_len: 0,
            ws_msg_opcode: 0,
            ws_utf8_state: 0,
            last_activity_ms: 0,
            // Default to our advertised TP value (30s); refined on
            // EncryptedExtensions parse for the smaller of the two TPs.
            idle_timeout_ms: 30_000,
            h3_post_in_progress: false,
            h3_post_path: [0; 64],
            h3_post_path_len: 0,
            h3_post_body: [0; 1024],
            h3_post_body_len: 0,
            h3_post_dispatched: false,
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// NewReno (RFC 9002 §B.5) — apply on every fresh ACK that covers
    /// previously-unacked, ack-eliciting bytes. `acked_bytes` is the
    /// number of bytes the ACK newly covers. `now_ms` is the current
    /// wall-clock time. Recovery aging is intentionally simple: we
    /// only re-enter recovery if the new loss event timestamp exceeds
    /// `recovery_start_time` (RFC 9002 §B.4).
    pub fn cc_on_ack(&mut self, acked_bytes: u64, _now_ms: u64) {
        if acked_bytes == 0 {
            return;
        }
        if self.bytes_in_flight >= acked_bytes {
            self.bytes_in_flight -= acked_bytes;
        } else {
            self.bytes_in_flight = 0;
        }
        if self.congestion_window < self.ssthresh {
            // Slow start (RFC 9002 §B.5): cwnd += acked_bytes.
            self.congestion_window = self.congestion_window.saturating_add(acked_bytes);
        } else {
            // Congestion avoidance: cwnd += MAX_DATAGRAM * acked / cwnd.
            // u32 division avoids `__aeabi_uldivmod`, which the PIC-only
            // crt on thumbv8m doesn't provide.
            let num = (MAX_DATAGRAM_SIZE as u32).saturating_mul(acked_bytes.min(u32::MAX as u64) as u32);
            let denom = self.congestion_window.min(u32::MAX as u64).max(1) as u32;
            let inc = (num / denom).max(1) as u64;
            self.congestion_window = self.congestion_window.saturating_add(inc);
        }
    }

    /// NewReno on loss (RFC 9002 §B.6) — halve cwnd, set ssthresh, but
    /// only if the loss occurred outside an existing recovery period.
    /// `loss_time_ms` is the time the lost packet was sent.
    pub fn cc_on_loss(&mut self, lost_bytes: u64, loss_time_ms: u64) {
        if self.bytes_in_flight >= lost_bytes {
            self.bytes_in_flight -= lost_bytes;
        } else {
            self.bytes_in_flight = 0;
        }
        // Only collapse if outside the existing recovery period.
        if loss_time_ms <= self.recovery_start_time {
            return;
        }
        self.recovery_start_time = loss_time_ms;
        // RFC 9002 §B.6 mandates cwnd / 2; expressed as a shift since
        // the thumbv8m PIC-only crt doesn't provide u64 division.
        let _ = (LOSS_REDUCTION_NUMERATOR, LOSS_REDUCTION_DENOMINATOR);
        self.ssthresh = self.congestion_window >> 1;
        if self.ssthresh < MINIMUM_WINDOW {
            self.ssthresh = MINIMUM_WINDOW;
        }
        self.congestion_window = self.ssthresh;
    }

    /// RFC 9002 §B.7 — persistent congestion: when no ACKs have arrived
    /// for a duration spanning more than three PTOs, collapse the
    /// window to MINIMUM_WINDOW.
    pub fn cc_on_persistent_congestion(&mut self) {
        self.congestion_window = MINIMUM_WINDOW;
    }

    /// RFC 9002 §7 — congestion-controlled send permitted iff
    /// `bytes_in_flight + size <= cwnd`. Always allow at least one
    /// datagram so we don't deadlock if cwnd is zero (handshake
    /// re-tx).
    pub fn cc_can_send(&self, size: u64) -> bool {
        if size == 0 {
            return true;
        }
        // Permit a send when nothing is in flight (PTO probes,
        // handshake retransmits) so an empty cwnd doesn't deadlock.
        if self.bytes_in_flight == 0 {
            return true;
        }
        self.bytes_in_flight.saturating_add(size) <= self.congestion_window
    }
}

/// Pull a per-connection scratch buffer used to assemble outbound
/// payloads before AEAD seal. Sized to fit a server's first flight
/// (ServerHello + EE + Cert + CV + Finished) into one or two
/// datagrams.
pub const QUIC_OUT_SCRATCH: usize = 2048;

// ---------------------------------------------------------------------
// Extra stream helpers.
// ---------------------------------------------------------------------

pub fn extra_find(conn: &QuicConnection, stream_id: u64) -> Option<usize> {
    let mut i = 0;
    while i < MAX_EXTRA_STREAMS {
        if conn.extra_streams[i].allocated && conn.extra_streams[i].stream_id == stream_id {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn extra_alloc(
    conn: &mut QuicConnection,
    stream_id: u64,
    locally_initiated: bool,
) -> Option<usize> {
    let mut i = 0;
    while i < MAX_EXTRA_STREAMS {
        if !conn.extra_streams[i].allocated {
            conn.extra_streams[i] = ExtraStream::empty();
            conn.extra_streams[i].stream_id = stream_id;
            conn.extra_streams[i].allocated = true;
            conn.extra_streams[i].locally_initiated = locally_initiated;
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn bidi_find(conn: &QuicConnection, stream_id: u64) -> Option<usize> {
    let mut i = 0;
    while i < MAX_BIDI_EXTRA_STREAMS {
        if conn.bidi_extra_streams[i].allocated
            && conn.bidi_extra_streams[i].stream_id == stream_id
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn bidi_alloc(
    conn: &mut QuicConnection,
    stream_id: u64,
    locally_initiated: bool,
) -> Option<usize> {
    let mut i = 0;
    while i < MAX_BIDI_EXTRA_STREAMS {
        if !conn.bidi_extra_streams[i].allocated {
            conn.bidi_extra_streams[i] = BidiExtraStream::empty();
            conn.bidi_extra_streams[i].stream_id = stream_id;
            conn.bidi_extra_streams[i].allocated = true;
            conn.bidi_extra_streams[i].locally_initiated = locally_initiated;
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Allocate the next server-initiated unidirectional stream id.
/// Server uni ids = 3, 7, 11, ...  (low 2 bits = 11).
pub fn next_server_uni_id(idx: u8) -> u64 {
    3 + (idx as u64) * 4
}

/// Allocate the next client-initiated unidirectional stream id.
/// Client uni ids = 2, 6, 10, ... (low 2 bits = 10).
pub fn next_client_uni_id(idx: u8) -> u64 {
    2 + (idx as u64) * 4
}

/// Allocate the next client-initiated bidirectional stream id.
/// Client bidi ids = 0, 4, 8, ...  (low 2 bits = 00).
pub fn next_client_bidi_id(idx: u8) -> u64 {
    (idx as u64) * 4
}

/// Set up Initial-level keys for a freshly-allocated connection
/// using the client's DCID. Server-side: dcid = the DCID in the
/// client's first Initial packet (== our_cid from server's perspective
/// since the client populated DCID with what it picked for "us"). The
/// keys derived this way are byte-identical on both sides.
pub unsafe fn install_initial_keys(conn: &mut QuicConnection, dcid: &[u8]) {
    let (client_keys, server_keys) = derive_initial_keys(dcid);
    if conn.is_server {
        conn.initial.read_keys = client_keys;
        conn.initial.write_keys = server_keys;
    } else {
        conn.initial.read_keys = server_keys;
        conn.initial.write_keys = client_keys;
    }
    conn.initial.keys_set = true;
}

/// After TLS DeriveHandshakeKeys, install QUIC Handshake-level keys
/// derived from the TLS handshake-traffic secrets.
pub unsafe fn install_handshake_keys(conn: &mut QuicConnection) {
    if let Some(read_secret) = conn.driver.read_secret(EncLevel::Handshake, false) {
        conn.handshake.read_keys = secret_to_keys(read_secret);
    }
    if let Some(write_secret) = conn.driver.read_secret(EncLevel::Handshake, true) {
        conn.handshake.write_keys = secret_to_keys(write_secret);
    }
    conn.handshake.keys_set = true;
}

/// After TLS DeriveAppKeys, install QUIC 1-RTT keys derived from
/// the TLS application-traffic secrets. Also captures the secrets
/// for key update (RFC 9001 §6) and pre-derives the next-phase keys.
pub unsafe fn install_one_rtt_keys(conn: &mut QuicConnection) {
    let mut hl = 32usize;
    if let Some(read_secret) = conn.driver.read_secret(EncLevel::OneRtt, false) {
        conn.one_rtt.read_keys = secret_to_keys(read_secret);
        hl = read_secret.len();
        conn.one_rtt.read_secret[..hl].copy_from_slice(read_secret);
    }
    if let Some(write_secret) = conn.driver.read_secret(EncLevel::OneRtt, true) {
        conn.one_rtt.write_keys = secret_to_keys(write_secret);
        let n = write_secret.len();
        conn.one_rtt.write_secret[..n].copy_from_slice(write_secret);
    }
    conn.one_rtt.secret_len = hl as u8;
    conn.one_rtt.keys_set = true;
    conn.one_rtt.key_phase = 0;
    // Pre-derive next-phase secrets + keys so a phase flip is a swap.
    let mut nr = [0u8; 48];
    next_traffic_secret(&conn.one_rtt.read_secret[..hl], &mut nr[..hl]);
    let mut nw = [0u8; 48];
    next_traffic_secret(&conn.one_rtt.write_secret[..hl], &mut nw[..hl]);
    conn.one_rtt.next_read_secret[..hl].copy_from_slice(&nr[..hl]);
    conn.one_rtt.next_write_secret[..hl].copy_from_slice(&nw[..hl]);
    let prev_read_hp = conn.one_rtt.read_keys.hp;
    let prev_write_hp = conn.one_rtt.write_keys.hp;
    conn.one_rtt.next_read_keys = next_keys(&nr[..hl], prev_read_hp);
    conn.one_rtt.next_write_keys = next_keys(&nw[..hl], prev_write_hp);
    conn.one_rtt.next_keys_ready = true;
}

// ----------------------------------------------------------------------
// Transport parameters (RFC 9000 §18, RFC 9001 §8.2)
//
// Encoded as a sequence of (id_varint, len_varint, value) tuples.
// The `value` for connection-ID parameters is the raw CID bytes; for
// integer parameters it's a varint; for boolean parameters (e.g.
// `disable_active_migration`) it's empty.
//
// We emit the minimum set RFC 9000 §18.2 mandates plus a couple of
// reasonable defaults so the peer doesn't immediately violate flow
// control. We don't yet enforce the parameters we receive — that's
// the loss-recovery / flow-control work.
// ----------------------------------------------------------------------

pub const TP_ORIGINAL_DESTINATION_CID: u64 = 0x00;
pub const TP_MAX_IDLE_TIMEOUT: u64 = 0x01;
pub const TP_MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
pub const TP_INITIAL_MAX_DATA: u64 = 0x04;
pub const TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
pub const TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
pub const TP_INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
pub const TP_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
pub const TP_INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
pub const TP_DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
pub const TP_ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
pub const TP_INITIAL_SOURCE_CID: u64 = 0x0f;
pub const TP_RETRY_SOURCE_CID: u64 = 0x10;

/// Maximum encoded transport parameters length we ever emit.
pub const TP_BUF_LEN: usize = 256;

/// Append a varint-id + varint-len + bytes-value tuple.
unsafe fn tp_put_bytes(out: &mut [u8], pos: &mut usize, id: u64, value: &[u8]) {
    let n = varint_encode(out.as_mut_ptr().add(*pos), out.len() - *pos, id);
    *pos += n;
    let n = varint_encode(
        out.as_mut_ptr().add(*pos),
        out.len() - *pos,
        value.len() as u64,
    );
    *pos += n;
    if !value.is_empty() {
        core::ptr::copy_nonoverlapping(
            value.as_ptr(),
            out.as_mut_ptr().add(*pos),
            value.len(),
        );
        *pos += value.len();
    }
}

/// Append a varint-id + varint-encoded integer value.
unsafe fn tp_put_int(out: &mut [u8], pos: &mut usize, id: u64, value: u64) {
    let n = varint_encode(out.as_mut_ptr().add(*pos), out.len() - *pos, id);
    *pos += n;
    let v_size = varint_size(value);
    let n = varint_encode(
        out.as_mut_ptr().add(*pos),
        out.len() - *pos,
        v_size as u64,
    );
    *pos += n;
    let n = varint_encode(out.as_mut_ptr().add(*pos), out.len() - *pos, value);
    *pos += n;
}

/// Build a minimal client-side transport_parameters payload. RFC 9000
/// §18.2 mandates `initial_source_connection_id`. We also advertise
/// flow-control / stream-limit ceilings so the peer can use them
/// before we add explicit MAX_DATA / MAX_STREAMS frames.
pub unsafe fn build_transport_params_client(scid: &[u8], out: &mut [u8]) -> usize {
    let mut pos = 0;
    tp_put_bytes(out, &mut pos, TP_INITIAL_SOURCE_CID, scid);
    tp_put_int(out, &mut pos, TP_MAX_IDLE_TIMEOUT, 30_000);
    tp_put_int(out, &mut pos, TP_MAX_UDP_PAYLOAD_SIZE, 1500);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_DATA, 1 << 20);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 1 << 18);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 1 << 18);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAM_DATA_UNI, 1 << 18);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAMS_BIDI, 4);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAMS_UNI, 4);
    tp_put_int(out, &mut pos, TP_ACTIVE_CONNECTION_ID_LIMIT, 2);
    // We don't support connection migration this revision; advertise
    // disable_active_migration so a peer doesn't try (RFC 9000 §18.2).
    tp_put_bytes(out, &mut pos, TP_DISABLE_ACTIVE_MIGRATION, &[]);
    pos
}

/// Build a minimal server-side transport_parameters payload. Adds
/// `original_destination_connection_id` (mandatory for server) on
/// top of the same set the client emits. If a Retry was issued for
/// this connection, also emits `retry_source_connection_id` (RFC 9000
/// §7.3 — required when the server has issued a Retry).
pub unsafe fn build_transport_params_server(
    scid: &[u8],
    original_dcid: &[u8],
    retry_source_cid: Option<&[u8]>,
    out: &mut [u8],
) -> usize {
    let mut pos = 0;
    tp_put_bytes(out, &mut pos, TP_ORIGINAL_DESTINATION_CID, original_dcid);
    tp_put_bytes(out, &mut pos, TP_INITIAL_SOURCE_CID, scid);
    if let Some(rsc) = retry_source_cid {
        tp_put_bytes(out, &mut pos, TP_RETRY_SOURCE_CID, rsc);
    }
    tp_put_int(out, &mut pos, TP_MAX_IDLE_TIMEOUT, 30_000);
    tp_put_int(out, &mut pos, TP_MAX_UDP_PAYLOAD_SIZE, 1500);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_DATA, 1 << 20);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 1 << 18);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 1 << 18);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAM_DATA_UNI, 1 << 18);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAMS_BIDI, 4);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAMS_UNI, 4);
    tp_put_int(out, &mut pos, TP_ACTIVE_CONNECTION_ID_LIMIT, 2);
    // We don't support connection migration this revision; advertise
    // disable_active_migration so a peer doesn't try (RFC 9000 §18.2).
    tp_put_bytes(out, &mut pos, TP_DISABLE_ACTIVE_MIGRATION, &[]);
    pos
}

/// Walk a transport_parameters payload and validate the mandatory
/// items. Returns true iff:
///   - `initial_source_connection_id` is present and equals
///     `expected_isc_cid`.
///   - For `server_view = true` (client checking server's TP):
///     `original_destination_connection_id` is present and equals
///     `expected_orig_dcid`.
///   - If `expected_retry_source_cid` is `Some(...)` (client used Retry):
///     `retry_source_connection_id` is present and equals it. RFC 9000
///     §7.3: the server MUST include this when a Retry was issued.
///
/// Other parameters are accepted as-is — this is enough to conform
/// to RFC 9000 §7.3 + RFC 9001 §8.2 minimum compliance.
pub unsafe fn validate_transport_params(
    payload: &[u8],
    expected_isc_cid: &[u8],
    expected_orig_dcid: Option<&[u8]>,
    expected_retry_source_cid: Option<&[u8]>,
) -> bool {
    let mut pos = 0;
    let mut saw_isc = false;
    let mut saw_orig = expected_orig_dcid.is_none();
    let mut saw_rsc = expected_retry_source_cid.is_none();
    while pos < payload.len() {
        let after = &payload[pos..];
        let (id, n) = match varint_decode(after.as_ptr(), after.len()) {
            Some(t) => t,
            None => return false,
        };
        pos += n;
        let after = &payload[pos..];
        let (vlen, n) = match varint_decode(after.as_ptr(), after.len()) {
            Some(t) => t,
            None => return false,
        };
        pos += n;
        let vlen = vlen as usize;
        if pos + vlen > payload.len() {
            return false;
        }
        let value = &payload[pos..pos + vlen];
        pos += vlen;

        match id {
            x if x == TP_INITIAL_SOURCE_CID => {
                if value != expected_isc_cid {
                    return false;
                }
                saw_isc = true;
            }
            x if x == TP_ORIGINAL_DESTINATION_CID => {
                if let Some(exp) = expected_orig_dcid {
                    if value != exp {
                        return false;
                    }
                    saw_orig = true;
                }
            }
            x if x == TP_RETRY_SOURCE_CID => {
                if let Some(exp) = expected_retry_source_cid {
                    if value != exp {
                        return false;
                    }
                    saw_rsc = true;
                }
            }
            _ => {
                // Unknown / non-mandatory — ignored per RFC 9000 §7.4.
            }
        }
    }
    saw_isc && saw_orig && saw_rsc
}
