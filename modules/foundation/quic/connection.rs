/// Longest resumption ticket the client echoes as a PSK identity: a
/// vault-sealed ticket is ~104 bytes (`pump::emit_new_session_ticket`).
pub const MAX_TICKET_LEN: usize = 160;

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

/// Maximum ALPN protocol-name length we store per connection (and per
/// configured entry). The IANA tokens we care about — `h3`, `mqtt` —
/// are short; 24 leaves headroom for future protocols without bloating
/// the fixed-size connection struct.
pub const MAX_ALPN: usize = 24;

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

impl Default for CryptoReassembler {
    fn default() -> Self {
        Self::new()
    }
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
            let n = CRYPTO_HOLD_LEN.saturating_sub(rel_off);
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
// Per-connection stream pools beyond the main bidirectional stream.
//
// Two fixed-size arrays, split by direction because the two shapes want
// very different buffers: a unidirectional stream is typically a small
// one-way control or metadata channel, a bidirectional one carries a
// request/response-sized flight in each direction. Splitting them keeps
// the uni pool numerous and narrow without paying bidi buffer sizes for
// every slot.
//
// Both are TRANSPORT structures. Nothing here knows what protocol runs
// on a stream: a slot carries opaque bytes, its offsets, its FIN and
// reset state, and the local handle the application addresses it by.
// ---------------------------------------------------------------------

pub const MAX_UNI_STREAMS: usize = 6;
/// Three concurrent bidirectional streams per connection. Identical
/// memory to the arrangement this replaced (a dedicated stream-0 buffer
/// plus a pool of two) — the difference is that all three are now the
/// same kind of thing, addressed the same way.
pub const MAX_BIDI_STREAMS: usize = 3;

/// Per-stream delivery bookkeeping for the mux app surface, shared by
/// both pool shapes and by the main stream.
///
/// Every field here answers "has this event actually been handed to the
/// application yet", and each latches only on a successful enqueue —
/// that is what makes a backpressured lifecycle event retryable instead
/// of lost, and what stops a retried terminal event from re-delivering
/// bytes that already landed.
#[derive(Clone, Copy)]
pub struct AppStreamView {
    /// Opaque local handle the application addresses this stream by.
    /// Allocated from the connection's monotonic counter, never derived
    /// from the QUIC stream id and never recycled while the application
    /// can still observe it.
    pub handle: u32,
    /// MSG_MUX_STREAM_OPENED (locally opened) or MSG_MUX_STREAM_ACCEPTED
    /// (peer opened) has been delivered.
    pub open_sent: bool,
    /// MSG_MUX_STREAM_CLOSED has been delivered.
    pub close_sent: bool,
    /// MSG_MUX_STREAM_RESET has been delivered for a peer RESET_STREAM.
    pub reset_sent: bool,
    /// MSG_MUX_STREAM_STOPPED has been delivered for a peer STOP_SENDING.
    pub stopped_sent: bool,
}

impl AppStreamView {
    pub const fn empty() -> Self {
        Self {
            handle: 0,
            open_sent: false,
            close_sent: false,
            reset_sent: false,
            stopped_sent: false,
        }
    }
}

/// Abrupt-termination state for one stream half-pair (RFC 9000 §19.4 /
/// §19.5). Held per slot; entirely opaque application error codes.
#[derive(Clone, Copy)]
pub struct StreamAbort {
    /// The application asked us to RESET_STREAM; not yet on the wire.
    pub reset_pending: bool,
    /// Error code to place in our RESET_STREAM.
    pub reset_error: u64,
    /// Our RESET_STREAM has been emitted.
    pub reset_emitted: bool,
    /// The application asked us to STOP_SENDING; not yet on the wire.
    pub stop_pending: bool,
    /// Error code to place in our STOP_SENDING.
    pub stop_error: u64,
    /// Our STOP_SENDING has been emitted.
    pub stop_emitted: bool,
    /// The peer RESET_STREAM'd us; receive half is terminal.
    pub recv_reset: bool,
    pub recv_reset_error: u64,
    /// The peer STOP_SENDING'd us; it wants our send half to stop.
    pub recv_stop: bool,
    pub recv_stop_error: u64,
}

impl StreamAbort {
    pub const fn empty() -> Self {
        Self {
            reset_pending: false,
            reset_error: 0,
            reset_emitted: false,
            stop_pending: false,
            stop_error: 0,
            stop_emitted: false,
            recv_reset: false,
            recv_reset_error: 0,
            recv_stop: false,
            recv_stop_error: 0,
        }
    }
}

/// Per-stream flow control (RFC 9000 §4.1). Both directions.
#[derive(Clone, Copy)]
pub struct StreamFlow {
    /// Highest offset the peer has allowed us to write (its
    /// MAX_STREAM_DATA for this stream).
    pub send_max_data: u64,
    /// We hit `send_max_data` and owe the peer a STREAM_DATA_BLOCKED.
    pub send_blocked_pending: bool,
    /// Highest offset we have allowed the peer to write.
    pub recv_max_data: u64,
    /// Bytes the application has acknowledged consuming on this stream
    /// (`CMD_MUX_STREAM_ACK`). Drives `recv_max_data` advancement.
    pub recv_consumed: u64,
    /// A MAX_STREAM_DATA frame is owed to the peer for this stream.
    pub recv_max_data_tx_pending: bool,
}

impl StreamFlow {
    pub const fn empty(initial_recv: u64) -> Self {
        Self {
            // Until the peer's transport parameters are parsed we assume
            // nothing: `apply_peer_stream_limits` raises this at
            // handshake completion. Starting at 0 would wedge 0-RTT
            // writes, so seed it with the RFC 9000 minimum every peer we
            // interoperate with advertises at least.
            send_max_data: DEFAULT_PEER_STREAM_WINDOW,
            send_blocked_pending: false,
            recv_max_data: initial_recv,
            recv_consumed: 0,
            recv_max_data_tx_pending: false,
        }
    }
}

/// Conservative assumed peer per-stream window before its transport
/// parameters arrive. Matches what we advertise ourselves, so a peer
/// running the same defaults is never under-served.
pub const DEFAULT_PEER_STREAM_WINDOW: u64 = 1 << 18;
/// Our advertised per-stream receive window (mirrors the
/// `initial_max_stream_data_*` transport parameters we emit).
pub const LOCAL_STREAM_WINDOW: u64 = 1 << 18;
/// Our advertised connection-level receive window (`initial_max_data`).
pub const LOCAL_CONN_WINDOW: u64 = 1 << 20;
/// Advance a receive window when the application has consumed at least
/// this fraction of it — one frame per window rather than one per read.
pub const FLOW_UPDATE_DIVISOR: u64 = 2;

#[derive(Clone, Copy)]
pub struct UniStream {
    pub stream_id: u64,
    pub allocated: bool,
    /// True when WE locally initiated this stream (we own its send
    /// half). For received unidirectional streams this is false and
    /// the send half is unused.
    pub locally_initiated: bool,

    pub send_off: u64,
    pub send_buf: [u8; 256],
    pub send_buf_len: usize,
    pub send_fin_pending: bool,
    pub send_fin_emitted: bool,

    pub recv_off: u64,
    pub recv_buf: [u8; 256],
    pub recv_buf_len: usize,
    pub recv_fin: bool,

    pub app: AppStreamView,
    pub abort: StreamAbort,
    pub flow: StreamFlow,
}

impl UniStream {
    pub const fn empty() -> Self {
        Self {
            stream_id: 0,
            allocated: false,
            locally_initiated: false,
            send_off: 0,
            send_buf: [0; 256],
            send_buf_len: 0,
            send_fin_pending: false,
            send_fin_emitted: false,
            recv_off: 0,
            recv_buf: [0; 256],
            recv_buf_len: 0,
            recv_fin: false,
            app: AppStreamView::empty(),
            abort: StreamAbort::empty(),
            flow: StreamFlow::empty(LOCAL_STREAM_WINDOW),
        }
    }
}

/// One bidirectional stream beyond the main one. Sized to carry a full
/// application flight in each direction; distinct from [`UniStream`] so
/// the uni pool can stay narrow.
#[derive(Clone, Copy)]
pub struct BidiStream {
    pub stream_id: u64,
    pub allocated: bool,
    /// True when the local endpoint opened the stream. False for slots
    /// holding a peer-initiated stream.
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

    pub app: AppStreamView,
    pub abort: StreamAbort,
    pub flow: StreamFlow,
}

impl BidiStream {
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
            app: AppStreamView::empty(),
            abort: StreamAbort::empty(),
            flow: StreamFlow::empty(LOCAL_STREAM_WINDOW),
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
    ///   packets are sent.
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

impl Default for PnSpace {
    fn default() -> Self {
        Self::new()
    }
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

impl Default for RttSample {
    fn default() -> Self {
        Self::new()
    }
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
        let abs_diff = self.smoothed_rtt.abs_diff(sample_ms);
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
    pub psk_identity: [u8; MAX_TICKET_LEN],
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

    // ── Stream pools ───────────────────────────────────────────────
    /// Unidirectional streams, local and peer-initiated alike.
    pub uni_streams: [UniStream; MAX_UNI_STREAMS],
    /// Bidirectional streams beyond the main one (client ids 4, 8, 12, …;
    /// server ids 5, 9, 13, …).
    pub bidi_streams: [BidiStream; MAX_BIDI_STREAMS],
    /// Counter for self-allocated unidirectional stream ids. Server
    /// uni = 3, 7, 11, ...; client uni = 2, 6, 10, ... — both
    /// increment by 4. We track the next index to allocate.
    pub next_uni_idx: u8,
    /// Sequence counter for our own bidi stream allocations. First local
    /// bidi = the main stream; subsequent = 4, 8, ... (client) or
    /// 5, 9, ... (server).
    pub next_bidi_idx: u8,
    /// Monotonic allocator for the opaque per-stream app handles the mux
    /// contract addresses streams by. Starts at 1 — 0 is never a live
    /// handle, so a zeroed field is unambiguously "unassigned".
    ///
    /// Deliberately NOT the QUIC stream id: the wire id is 62 bits and
    /// the handle is 32, and a truncating map would alias two distinct
    /// streams onto one handle on a long-lived connection. The wire id
    /// travels separately as metadata on the opened/accepted event.
    pub next_app_handle: u32,
    /// Round-robin starting points for outbound stream emission, one per
    /// pool. Without them the packer always starts at slot 0, so a slot
    /// that can fill a packet on its own is the only one ever served and
    /// every other stream on the connection starves.
    pub tx_cursor_bidi: u8,
    pub tx_cursor_uni: u8,
    /// Wall-clock millis of the most recent activity on this conn —
    /// any inbound packet decrypt success, any outbound emit. Drives
    /// idle-timeout closure (RFC 9000 §10.1). Zero = uninitialised
    /// (set to first dev_millis() on connection open).
    pub last_activity_ms: u64,
    /// Negotiated idle timeout in ms (the smaller of our + peer
    /// `max_idle_timeout` TPs, RFC 9000 §10.1.2). 0 = disabled.
    pub idle_timeout_ms: u64,

    // ── Observability: `quic.connection` span (server-accepted conns) ──
    /// 16-byte W3C trace id, minted at server-accept when telemetry is wired.
    pub trace_id: [u8; 16],
    /// 8-byte span id for the connection's root span.
    pub span_id: [u8; 8],
    /// W3C trace-flags latched at accept (head-sampling decision). Low bit =
    /// sampled; the span and any future child contexts share it.
    pub sampled_flags: u8,
    /// Span start micros. Non-zero marks a pending span that the close path
    /// must still emit; zeroed once emitted (idempotent) or for client conns.
    pub span_start_us: u64,

    // ── ALPN (RFC 7301) ────────────────────────────────────────────
    /// The negotiated application protocol for this connection, as an
    /// opaque raw token. Server: selected at ClientHello from the
    /// intersection of the module's configured list and the client's
    /// offered list. Client: the protocol we offered and the server
    /// echoed. Empty (`alpn_selected_len == 0`) means no ALPN was
    /// negotiated.
    ///
    /// Reported to the application on `MSG_MUX_SESSION_OPENED` and used
    /// for nothing else here — this module performs the negotiation and
    /// holds no opinion about what any token means.
    pub alpn_selected: [u8; MAX_ALPN],
    pub alpn_selected_len: u8,

    // ── DATAGRAM (RFC 9221) ────────────────────────────────────────
    /// Peer's advertised `max_datagram_frame_size` (RFC 9221 §3),
    /// captured from its transport parameters. 0 = peer won't accept
    /// DATAGRAMs → outbound datagrams are dropped at the encoder. An
    /// outbound payload larger than this value is also dropped (never
    /// truncated, never retransmitted).
    pub peer_max_datagram_frame_size: u64,
    /// Single-slot outbound DATAGRAM staging. The app writes one
    /// MSG_QUIC_DATAGRAM_TX per drain; the pump emits it in the next
    /// 1-RTT packet and clears the slot. Unreliable: if a second TX
    /// arrives before the first is flushed, the older one is dropped
    /// (RFC 9221 §5.2 — datagrams may be dropped freely).
    pub dgram_tx: [u8; QUIC_MAX_DATAGRAM_SIZE],
    pub dgram_tx_len: usize,
    pub dgram_tx_pending: bool,
    /// Single-slot inbound DATAGRAM staging. `process_frames` writes a
    /// received datagram here; the top-level loop forwards it to the app
    /// (MSG_QUIC_DATAGRAM_RX) and clears the slot. Unreliable: a second
    /// inbound datagram before the first is drained overwrites it.
    pub dgram_rx: [u8; QUIC_MAX_DATAGRAM_SIZE],
    pub dgram_rx_len: usize,
    pub dgram_rx_pending: bool,

    // ── Connection migration (RFC 9000 §9) ────────────────────────
    /// True while we are validating a candidate 4-tuple before
    /// switching the active path to it. Set when a confirmed-handshake
    /// packet arrives from an address other than `peer`; cleared when
    /// the matching PATH_RESPONSE confirms reachability.
    pub path_validating: bool,
    /// The 8 unpredictable bytes we sent in our PATH_CHALLENGE; a
    /// PATH_RESPONSE must echo these to confirm the candidate path.
    pub path_challenge_data: [u8; 8],
    /// Wall-clock millis when path validation began. Used to abandon a
    /// validation that never completes (RFC 9000 §8.2.4) so the flag
    /// doesn't latch forever and block a later genuine migration.
    pub path_validate_ms: u64,
    /// Candidate path under validation (the new 4-tuple). Becomes the
    /// active `peer` once validation succeeds.
    pub cand_ip: [u8; 4],
    pub cand_port: u16,
    /// A PATH_CHALLENGE is queued for emission to the candidate path.
    pub path_challenge_tx_pending: bool,
    /// Wall-clock millis when the last PATH_CHALLENGE probe was enqueued
    /// (0 = none outstanding). Drives PTO-style retransmission of the
    /// probe (RFC 9000 §8.1 / §9.3.3) so a wire-lost challenge is resent
    /// even if the migrating peer goes quiet, bounded by
    /// `path_validate_ms` + the overall validation timeout.
    pub path_challenge_tx_ms: u64,
    /// A PATH_RESPONSE is queued (echoing a PATH_CHALLENGE the peer sent
    /// us). `path_response_data` holds the bytes to echo. RFC 9000 §8.2.2
    /// requires the PATH_RESPONSE be sent on the network path the
    /// PATH_CHALLENGE arrived on, so `path_response_to_*` records that
    /// source 4-tuple (captured at frame-dispatch time) and the response
    /// is emitted as a dedicated destination-scoped packet — NOT folded
    /// into the validated-path data packet.
    pub path_response_tx_pending: bool,
    pub path_response_data: [u8; 8],
    pub path_response_to_ip: [u8; 4],
    pub path_response_to_port: u16,
    /// Source 4-tuple of the datagram currently being dispatched. Set in
    /// `mod.rs` when bytes are staged into `inbound`, before
    /// `process_frames` runs, so path-validation frames can associate
    /// PATH_CHALLENGE / PATH_RESPONSE with the path they arrived on
    /// (RFC 9000 §8.2.2 / §8.2.3). Without this a PATH_RESPONSE could be
    /// matched on token alone and promote a candidate that answered on
    /// the wrong path.
    pub recv_ip: [u8; 4],
    pub recv_port: u16,

    // ── Stream-count flow control (RFC 9000 §4.6) ──────────────────
    /// Cumulative bidi-stream allowance granted to the peer. Starts at the
    /// `initial_max_streams_bidi` transport parameter and rises as streams
    /// are reclaimed, so a connection is not limited to its initial
    /// allowance for life.
    pub max_streams_bidi_granted: u64,
    /// A MAX_STREAMS (bidi) frame is owed to the peer.
    pub max_streams_tx_pending: bool,
    /// Same, for unidirectional streams. Without this a peer that opens
    /// uni streams — any control/metadata channel an application runs
    /// alongside its data streams — stalls at the initial allowance.
    pub max_streams_uni_granted: u64,
    pub max_streams_uni_tx_pending: bool,
    /// Peer-imposed caps on how many streams WE may open, from its
    /// transport parameters (RFC 9000 §18.2). An open beyond these is
    /// refused with STATUS_NO_CAPACITY and a STREAMS_BLOCKED frame,
    /// never attempted on the wire.
    pub peer_max_streams_bidi: u64,
    pub peer_max_streams_uni: u64,
    /// Peer's `initial_max_stream_data_*` (RFC 9000 §18.2), i.e. how much
    /// WE may write on a stream before its MAX_STREAM_DATA moves.
    ///
    /// Three values because the peer advertises three: which one applies
    /// depends on the stream's direction and who opened it, and getting
    /// that wrong shows up as a stall only under load.
    ///   * `_bidi_remote` — a bidi stream WE opened (remote to the peer);
    ///   * `_bidi_local`  — a bidi stream the PEER opened;
    ///   * `_uni`         — any unidirectional stream we send on.
    pub peer_stream_window_bidi_local: u64,
    pub peer_stream_window_bidi_remote: u64,
    pub peer_stream_window_uni: u64,
    /// Count of streams we have opened in each direction, against the
    /// caps above.
    pub local_bidi_opened: u64,
    pub local_uni_opened: u64,
    /// A STREAMS_BLOCKED frame is owed to the peer (we wanted to open and
    /// had no credit).
    pub streams_blocked_bidi_pending: bool,
    pub streams_blocked_uni_pending: bool,

    // ── Connection-level flow control (RFC 9000 §4.1) ──────────────
    /// Highest aggregate offset the peer allows us to write.
    pub send_max_data: u64,
    /// Aggregate bytes we have written across all streams.
    pub send_data_used: u64,
    /// A DATA_BLOCKED frame is owed to the peer.
    pub data_blocked_pending: bool,
    /// Highest aggregate offset we allow the peer to write.
    pub recv_max_data: u64,
    /// Aggregate bytes the application has acknowledged consuming.
    pub recv_data_consumed: u64,
    /// A MAX_DATA frame is owed to the peer.
    pub max_data_tx_pending: bool,

    // ── Mux app surface ────────────────────────────────────────────
    /// Which application-channel encoding this connection uses: the
    /// framed `mux` contract (true) or the transparent raw byte stream
    /// (false). Latched at connection allocation from whether the module
    /// has an `alpn` list configured.
    ///
    /// It selects an ENCODING, not a protocol. On the framed surface
    /// EVERY stream — including client bidi stream 0 — is an ordinary
    /// pool slot with an app handle, so there is exactly one code path
    /// for streams. The transparent surface owns `stream_send_buf` /
    /// `stream_recv_buf` and never touches the pools; the two never mix.
    pub framed_app_surface: bool,
    /// Whether MSG_MUX_SESSION_OPENED has been delivered for this
    /// connection. One-shot and retryable: latched only on a successful
    /// enqueue, so a backpressured session-open is retried rather than
    /// leaving the application with streams belonging to a session it
    /// was never told about.
    pub session_opened_sent: bool,
    /// Whether MSG_MUX_SESSION_CLOSED has been delivered.
    pub session_closed_sent: bool,
    /// Whether the post-handshake `MSG_MUX_PEER_IDENTITY` (mux 0xC8) has
    /// been emitted to the app surface.
    pub peer_identity_sent: bool,

    // ── Alternate connection IDs (RFC 9000 §5.1.1 / §19.15) ────────
    /// One spare local CID issued to the peer post-handshake via
    /// NEW_CONNECTION_ID (sequence 1), so the peer can switch to a
    /// fresh DCID on a new path (RFC 9000 §9.5 linkability). Matched by
    /// `find_conn_by_dcid` alongside `our_cid`. We advertise
    /// active_connection_id_limit = 2, so one spare is the most the peer
    /// expects.
    pub alt_cid: [u8; MAX_CID_LEN],
    pub alt_cid_len: u8,
    pub alt_cid_seq: u64,
    /// Stateless-reset token paired with `alt_cid` (RFC 9000 §10.3),
    /// carried in the NEW_CONNECTION_ID frame. Random per issuance.
    pub alt_cid_reset_token: [u8; 16],
    /// True once `alt_cid` has been minted (one-shot).
    pub alt_cid_issued: bool,
    /// A NEW_CONNECTION_ID frame for `alt_cid` is queued for emission.
    pub new_cid_tx_pending: bool,
}

impl Default for QuicConnection {
    fn default() -> Self {
        Self::new()
    }
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
            psk_identity: [0; MAX_TICKET_LEN],
            psk_identity_len: 0,
            zero_rtt_accepted: false,
            zero_rtt_offered: false,
            psk_selected: false,
            zero_rtt_keys: QuicKeys::empty(),
            zero_rtt_keys_set: false,
            zero_rtt_payload: [0; 256],
            zero_rtt_payload_len: 0,
            session_ticket_handled: false,
            uni_streams: [UniStream::empty(); MAX_UNI_STREAMS],
            bidi_streams: [BidiStream::empty(); MAX_BIDI_STREAMS],
            next_uni_idx: 0,
            next_bidi_idx: 0,
            next_app_handle: 1,
            tx_cursor_bidi: 0,
            tx_cursor_uni: 0,
            last_activity_ms: 0,
            // Default to our advertised TP value (30s); refined on
            // EncryptedExtensions parse for the smaller of the two TPs.
            idle_timeout_ms: 30_000,
            trace_id: [0; 16],
            span_id: [0; 8],
            sampled_flags: 0,
            span_start_us: 0,
            alpn_selected: [0; MAX_ALPN],
            alpn_selected_len: 0,
            peer_max_datagram_frame_size: 0,
            dgram_tx: [0; QUIC_MAX_DATAGRAM_SIZE],
            dgram_tx_len: 0,
            dgram_tx_pending: false,
            dgram_rx: [0; QUIC_MAX_DATAGRAM_SIZE],
            dgram_rx_len: 0,
            dgram_rx_pending: false,
            path_validating: false,
            path_challenge_data: [0; 8],
            path_validate_ms: 0,
            cand_ip: [0; 4],
            cand_port: 0,
            path_challenge_tx_pending: false,
            path_challenge_tx_ms: 0,
            path_response_tx_pending: false,
            path_response_data: [0; 8],
            path_response_to_ip: [0; 4],
            path_response_to_port: 0,
            recv_ip: [0; 4],
            recv_port: 0,
            max_streams_bidi_granted: MAX_BIDI_STREAMS as u64,
            max_streams_tx_pending: false,
            max_streams_uni_granted: MAX_UNI_STREAMS as u64,
            max_streams_uni_tx_pending: false,
            // Until the peer's transport parameters are parsed, assume it
            // advertises what we do. A peer that advertises less is
            // honoured the moment `apply_peer_stream_limits` runs, which
            // is before any application stream can be opened.
            peer_max_streams_bidi: 4,
            peer_max_streams_uni: 4,
            peer_stream_window_bidi_local: DEFAULT_PEER_STREAM_WINDOW,
            peer_stream_window_bidi_remote: DEFAULT_PEER_STREAM_WINDOW,
            peer_stream_window_uni: DEFAULT_PEER_STREAM_WINDOW,
            local_bidi_opened: 0,
            local_uni_opened: 0,
            streams_blocked_bidi_pending: false,
            streams_blocked_uni_pending: false,
            send_max_data: LOCAL_CONN_WINDOW,
            send_data_used: 0,
            data_blocked_pending: false,
            recv_max_data: LOCAL_CONN_WINDOW,
            recv_data_consumed: 0,
            max_data_tx_pending: false,
            framed_app_surface: false,
            session_opened_sent: false,
            session_closed_sent: false,
            peer_identity_sent: false,
            alt_cid: [0; MAX_CID_LEN],
            alt_cid_len: 0,
            alt_cid_seq: 0,
            alt_cid_reset_token: [0; 16],
            alt_cid_issued: false,
            new_cid_tx_pending: false,
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

/// Take the next opaque app handle for this connection.
///
/// Wraps back to 1 rather than to 0 — 0 means "unassigned" everywhere
/// else, and a wrapped handle colliding with that sentinel would make an
/// unassigned slot look addressable.
pub fn next_handle(conn: &mut QuicConnection) -> u32 {
    let h = conn.next_app_handle;
    // Wrap to 1, never 0: 0 is the "no handle" sentinel.
    conn.next_app_handle = conn.next_app_handle.checked_add(1).unwrap_or(1);
    h
}

pub fn uni_find(conn: &QuicConnection, stream_id: u64) -> Option<usize> {
    let mut i = 0;
    while i < MAX_UNI_STREAMS {
        if conn.uni_streams[i].allocated && conn.uni_streams[i].stream_id == stream_id {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn uni_alloc(
    conn: &mut QuicConnection,
    stream_id: u64,
    locally_initiated: bool,
) -> Option<usize> {
    let mut i = 0;
    while i < MAX_UNI_STREAMS {
        if !conn.uni_streams[i].allocated {
            let handle = next_handle(conn);
            conn.uni_streams[i] = UniStream::empty();
            conn.uni_streams[i].stream_id = stream_id;
            conn.uni_streams[i].allocated = true;
            conn.uni_streams[i].locally_initiated = locally_initiated;
            conn.uni_streams[i].app.handle = handle;
            conn.uni_streams[i].flow.send_max_data = conn.peer_stream_window_uni;
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn bidi_find(conn: &QuicConnection, stream_id: u64) -> Option<usize> {
    let mut i = 0;
    while i < MAX_BIDI_STREAMS {
        if conn.bidi_streams[i].allocated && conn.bidi_streams[i].stream_id == stream_id {
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
    while i < MAX_BIDI_STREAMS {
        if !conn.bidi_streams[i].allocated {
            let handle = next_handle(conn);
            let window = if locally_initiated {
                conn.peer_stream_window_bidi_remote
            } else {
                conn.peer_stream_window_bidi_local
            };
            conn.bidi_streams[i] = BidiStream::empty();
            conn.bidi_streams[i].stream_id = stream_id;
            conn.bidi_streams[i].allocated = true;
            conn.bidi_streams[i].locally_initiated = locally_initiated;
            conn.bidi_streams[i].app.handle = handle;
            conn.bidi_streams[i].flow.send_max_data = window;
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Find a stream by the opaque app handle the mux surface addresses it
/// by. Two pools, split by direction; nothing else.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StreamLoc {
    Bidi(usize),
    Uni(usize),
}

pub fn locate_handle(conn: &QuicConnection, handle: u32) -> Option<StreamLoc> {
    if handle == 0 {
        return None;
    }
    let mut i = 0;
    while i < MAX_BIDI_STREAMS {
        if conn.bidi_streams[i].allocated && conn.bidi_streams[i].app.handle == handle {
            return Some(StreamLoc::Bidi(i));
        }
        i += 1;
    }
    let mut i = 0;
    while i < MAX_UNI_STREAMS {
        if conn.uni_streams[i].allocated && conn.uni_streams[i].app.handle == handle {
            return Some(StreamLoc::Uni(i));
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

/// Allocate the next server-initiated bidirectional stream id.
/// Server bidi ids = 1, 5, 9, ...  (low 2 bits = 01).
pub fn next_server_bidi_id(idx: u8) -> u64 {
    1 + (idx as u64) * 4
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
/// RFC 9221 §3 — `max_datagram_frame_size`. Advertising a non-zero
/// value signals the peer it MAY send DATAGRAM frames up to that size.
/// We advertise the largest datagram we can stage inbound.
pub const TP_MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;

/// The largest DATAGRAM frame we advertise we can receive (RFC 9221 §3).
/// Bounds the inbound staging copy; sized to a single QUIC packet's
/// worth of payload so a datagram fits one 1-RTT packet.
pub const QUIC_MAX_DATAGRAM_SIZE: usize = 1200;

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
pub unsafe fn build_transport_params_client(
    scid: &[u8],
    disable_migration: bool,
    out: &mut [u8],
) -> usize {
    let mut pos = 0;
    tp_put_bytes(out, &mut pos, TP_INITIAL_SOURCE_CID, scid);
    tp_put_int(out, &mut pos, TP_MAX_IDLE_TIMEOUT, 30_000);
    tp_put_int(out, &mut pos, TP_MAX_UDP_PAYLOAD_SIZE, 1500);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_DATA, LOCAL_CONN_WINDOW);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, LOCAL_STREAM_WINDOW);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, LOCAL_STREAM_WINDOW);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAM_DATA_UNI, LOCAL_STREAM_WINDOW);
    // Advertised from the fixed pools, not a round number. Advertising
    // more than we can hold means a peer opens a stream we then have
    // nowhere to put, and its bytes are dropped with no error on either
    // side — which is indistinguishable from a slow application.
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAMS_BIDI, MAX_BIDI_STREAMS as u64);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAMS_UNI, MAX_UNI_STREAMS as u64);
    tp_put_int(out, &mut pos, TP_ACTIVE_CONNECTION_ID_LIMIT, 2);
    // RFC 9221 §3: advertise our inbound DATAGRAM capacity so the peer
    // may send unreliable datagrams up to this size.
    tp_put_int(
        out,
        &mut pos,
        TP_MAX_DATAGRAM_FRAME_SIZE,
        QUIC_MAX_DATAGRAM_SIZE as u64,
    );
    // RFC 9000 §18.2: advertise disable_active_migration ONLY when the
    // module is configured to refuse migration. By default we support it
    // and so omit the TP, permitting the peer to migrate.
    if disable_migration {
        tp_put_bytes(out, &mut pos, TP_DISABLE_ACTIVE_MIGRATION, &[]);
    }
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
    disable_migration: bool,
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
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_DATA, LOCAL_CONN_WINDOW);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, LOCAL_STREAM_WINDOW);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, LOCAL_STREAM_WINDOW);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAM_DATA_UNI, LOCAL_STREAM_WINDOW);
    // Advertised from the fixed pools, not a round number. Advertising
    // more than we can hold means a peer opens a stream we then have
    // nowhere to put, and its bytes are dropped with no error on either
    // side — which is indistinguishable from a slow application.
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAMS_BIDI, MAX_BIDI_STREAMS as u64);
    tp_put_int(out, &mut pos, TP_INITIAL_MAX_STREAMS_UNI, MAX_UNI_STREAMS as u64);
    tp_put_int(out, &mut pos, TP_ACTIVE_CONNECTION_ID_LIMIT, 2);
    // RFC 9221 §3: advertise our inbound DATAGRAM capacity.
    tp_put_int(
        out,
        &mut pos,
        TP_MAX_DATAGRAM_FRAME_SIZE,
        QUIC_MAX_DATAGRAM_SIZE as u64,
    );
    // RFC 9000 §18.2: advertise disable_active_migration ONLY when
    // configured to refuse migration (default: support it, omit the TP).
    if disable_migration {
        tp_put_bytes(out, &mut pos, TP_DISABLE_ACTIVE_MIGRATION, &[]);
    }
    pos
}

/// The peer's flow-control and stream-count limits, as far as this
/// transport uses them (RFC 9000 §18.2).
///
/// **Fills a fixed struct; takes no callback.** A per-parameter
/// `&mut dyn FnMut(u64, u64)` is a trait object, and a trait object is a
/// vtable: these modules are position-independent with no relocation
/// processing for one, so calling through it jumps to an unrelocated
/// address. That failure is invisible to both the build and the host
/// harness — it faults the runtime the first time a handshake completes.
#[derive(Clone, Copy)]
pub struct PeerTransportLimits {
    pub max_data: u64,
    pub max_stream_data_bidi_local: u64,
    pub max_stream_data_bidi_remote: u64,
    pub max_stream_data_uni: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub max_datagram_frame_size: u64,
}

impl PeerTransportLimits {
    /// RFC 9000 §18.2 defaults: every one of these parameters is
    /// optional and defaults to zero, which means "no credit". We seed
    /// with zero rather than a guess so an absent parameter is honoured
    /// as the RFC states it, not silently widened.
    pub const fn defaults() -> Self {
        Self {
            max_data: 0,
            max_stream_data_bidi_local: 0,
            max_stream_data_bidi_remote: 0,
            max_stream_data_uni: 0,
            max_streams_bidi: 0,
            max_streams_uni: 0,
            max_datagram_frame_size: 0,
        }
    }
}

/// Walk a transport_parameters payload, capturing the limits above.
/// Lenient about unknown parameters (they are skipped, per §7.4.2);
/// returns the defaults on a decode error.
pub unsafe fn parse_peer_transport_limits(payload: &[u8]) -> PeerTransportLimits {
    let mut out = PeerTransportLimits::defaults();
    let mut pos = 0;
    while pos < payload.len() {
        let after = &payload[pos..];
        let (id, n) = match varint_decode(after.as_ptr(), after.len()) {
            Some(t) => t,
            None => return out,
        };
        pos += n;
        let after = &payload[pos..];
        let (vlen, n) = match varint_decode(after.as_ptr(), after.len()) {
            Some(t) => t,
            None => return out,
        };
        pos += n;
        let vlen = vlen as usize;
        if pos + vlen > payload.len() {
            return out;
        }
        let value = &payload[pos..pos + vlen];
        pos += vlen;
        let v = match varint_decode(value.as_ptr(), value.len()) {
            Some((v, _)) => v,
            None => continue,
        };
        if id == TP_INITIAL_MAX_DATA {
            out.max_data = v;
        } else if id == TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL {
            out.max_stream_data_bidi_local = v;
        } else if id == TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE {
            out.max_stream_data_bidi_remote = v;
        } else if id == TP_INITIAL_MAX_STREAM_DATA_UNI {
            out.max_stream_data_uni = v;
        } else if id == TP_INITIAL_MAX_STREAMS_BIDI {
            out.max_streams_bidi = v;
        } else if id == TP_INITIAL_MAX_STREAMS_UNI {
            out.max_streams_uni = v;
        } else if id == TP_MAX_DATAGRAM_FRAME_SIZE {
            out.max_datagram_frame_size = v;
        }
    }
    out
}

/// Latch the peer's limits onto the connection.
///
/// Applied once the peer's transport parameters are available, which is
/// before any application stream can be opened on the connection —
/// so no stream is ever allocated against a guessed window.
pub fn apply_peer_transport_limits(conn: &mut QuicConnection, lim: &PeerTransportLimits) {
    conn.peer_max_datagram_frame_size = lim.max_datagram_frame_size;
    conn.peer_max_streams_bidi = lim.max_streams_bidi;
    conn.peer_max_streams_uni = lim.max_streams_uni;
    conn.peer_stream_window_bidi_local = lim.max_stream_data_bidi_local;
    conn.peer_stream_window_bidi_remote = lim.max_stream_data_bidi_remote;
    conn.peer_stream_window_uni = lim.max_stream_data_uni;
    conn.send_max_data = lim.max_data;
    // Streams allocated before the peer's parameters arrived (a 0-RTT
    // write, a stream the peer opened inside its first flight) were
    // seeded with the assumed window. Rewrite them from the real values
    // now, or they keep writing against a number the peer never agreed
    // to. Each stream's window depends on its direction and initiator —
    // the peer names its two bidi windows from ITS OWN point of view, so
    // a stream WE opened is the peer's `_bidi_remote`.
    let mut i = 0;
    while i < MAX_BIDI_STREAMS {
        if conn.bidi_streams[i].allocated {
            conn.bidi_streams[i].flow.send_max_data = if conn.bidi_streams[i].locally_initiated {
                lim.max_stream_data_bidi_remote
            } else {
                lim.max_stream_data_bidi_local
            };
        }
        i += 1;
    }
    let mut i = 0;
    while i < MAX_UNI_STREAMS {
        if conn.uni_streams[i].allocated && conn.uni_streams[i].locally_initiated {
            conn.uni_streams[i].flow.send_max_data = lim.max_stream_data_uni;
        }
        i += 1;
    }
}

/// Extract the peer's `max_datagram_frame_size` (RFC 9221 §3) from a
/// transport_parameters payload. Returns 0 if absent (peer won't accept
/// DATAGRAMs) or on any decode error. Lenient: unknown params skipped.
pub unsafe fn parse_peer_max_datagram_frame_size(payload: &[u8]) -> u64 {
    let mut pos = 0;
    while pos < payload.len() {
        let after = &payload[pos..];
        let (id, n) = match varint_decode(after.as_ptr(), after.len()) {
            Some(t) => t,
            None => return 0,
        };
        pos += n;
        let after = &payload[pos..];
        let (vlen, n) = match varint_decode(after.as_ptr(), after.len()) {
            Some(t) => t,
            None => return 0,
        };
        pos += n;
        let vlen = vlen as usize;
        if pos + vlen > payload.len() {
            return 0;
        }
        let value = &payload[pos..pos + vlen];
        pos += vlen;
        if id == TP_MAX_DATAGRAM_FRAME_SIZE {
            if let Some((v, _)) = varint_decode(value.as_ptr(), value.len()) {
                return v;
            }
            return 0;
        }
    }
    0
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
