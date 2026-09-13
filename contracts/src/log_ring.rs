//! Owner-scoped log ring file format.
//!
//! Dependency-free framing for the per-owner log ring the Linux runtime writes
//! (`logs/<owner_uid>.<slot>.<owner_generation>.ring`) and the `fluxor agent
//! logs` reader consumes. This module owns only the **format** — nothing here
//! does I/O:
//!
//! - a fixed file [`RingHeader`] with its own CRC (magic, capacity, the
//!   oldest/next `seq` watermarks, head/tail byte offsets);
//! - per-record framing with a **per-record CRC** in the length prefix, so a
//!   follower or crash-recovery reader detects a torn / mid-overwrite record
//!   individually (the header CRC alone cannot protect concurrent readers of an
//!   in-place file);
//! - the cursor-based gap synthesis that turns the monotone `seq` stream into
//!   per-reader [`LogsTruncated`] markers — a gap is a property of a *cursor*,
//!   not of the ring, so two readers at different positions each see their own
//!   correct gap.
//!
//! The in-place `pwrite`, `--follow`, and crash-recovery scan live in the
//! platform (writer) and tools (reader); they share exactly these bytes.

use alloc::vec::Vec;

/// File magic: `FXLR` — FluXor Log Ring.
pub const RING_MAGIC: [u8; 4] = *b"FXLR";

/// Format version. Bumped only if the framing changes incompatibly; consistent
/// with the "latest is all there is" policy, readers reject other versions.
pub const RING_FORMAT_VERSION: u16 = 1;

/// Fixed header length in bytes. Layout (all integers little-endian):
///
/// ```text
/// magic[4] version:u16 _pad:u16 capacity:u64 oldest_seq:u64 next_seq:u64
/// head_off:u64 tail_off:u64 header_crc:u32
/// ```
pub const HEADER_LEN: usize = 4 + 2 + 2 + 8 + 8 + 8 + 8 + 8 + 4;

/// Per-record frame overhead: `len:u32` + `crc:u32` prefix.
pub const RECORD_FRAME_OVERHEAD: usize = 8;

/// Fixed prefix of a record payload before the variable module/message bytes:
/// `owner_uid[16] owner_generation:u32 plan_generation:u64
/// timestamp_unix_ms:u64 seq:u64 module_len:u8`.
const RECORD_PREFIX_LEN: usize = 16 + 4 + 8 + 8 + 8 + 1;

/// The fixed file header. `capacity` is the ring's byte capacity (excluding the
/// header); `oldest_seq`/`next_seq` are the retained-record watermarks;
/// `head_off`/`tail_off` are byte offsets into the ring region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingHeader {
    pub version: u16,
    pub capacity: u64,
    pub oldest_seq: u64,
    pub next_seq: u64,
    pub head_off: u64,
    pub tail_off: u64,
}

impl RingHeader {
    /// Serialize the header including its trailing CRC. Always `HEADER_LEN`.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&RING_MAGIC);
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        // out[6..8] pad stays zero
        out[8..16].copy_from_slice(&self.capacity.to_le_bytes());
        out[16..24].copy_from_slice(&self.oldest_seq.to_le_bytes());
        out[24..32].copy_from_slice(&self.next_seq.to_le_bytes());
        out[32..40].copy_from_slice(&self.head_off.to_le_bytes());
        out[40..48].copy_from_slice(&self.tail_off.to_le_bytes());
        let crc = crc32(&out[0..HEADER_LEN - 4]);
        out[HEADER_LEN - 4..HEADER_LEN].copy_from_slice(&crc.to_le_bytes());
        out
    }

    /// Parse and CRC-verify a header. Returns `None` on bad magic, wrong
    /// version, short input, or CRC mismatch (a torn header → the reader treats
    /// the ring as empty and scans from the first record, per §4.3).
    pub fn decode(bytes: &[u8]) -> Option<RingHeader> {
        if bytes.len() < HEADER_LEN || bytes[0..4] != RING_MAGIC {
            return None;
        }
        let stored_crc = u32::from_le_bytes(bytes[HEADER_LEN - 4..HEADER_LEN].try_into().ok()?);
        if crc32(&bytes[0..HEADER_LEN - 4]) != stored_crc {
            return None;
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().ok()?);
        if version != RING_FORMAT_VERSION {
            return None;
        }
        Some(RingHeader {
            version,
            capacity: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            oldest_seq: u64::from_le_bytes(bytes[16..24].try_into().ok()?),
            next_seq: u64::from_le_bytes(bytes[24..32].try_into().ok()?),
            head_off: u64::from_le_bytes(bytes[32..40].try_into().ok()?),
            tail_off: u64::from_le_bytes(bytes[40..48].try_into().ok()?),
        })
    }
}

/// One owner-attributed log record. The
/// captured identity is the `(owner_uid, owner_generation)` pair plus the
/// committed `plan_generation` at emit; `module` is present only for on-step
/// records (off-step emitters have none). `message` is the already-formatted
/// line bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRecord {
    pub owner_uid: [u8; 16],
    pub owner_generation: u32,
    pub plan_generation: u64,
    pub timestamp_unix_ms: u64,
    pub seq: u64,
    /// Graph module name where known; empty means off-step / unattributed.
    pub module: Vec<u8>,
    pub message: Vec<u8>,
}

impl LogRecord {
    /// Serialize as a framed record: `len:u32 | crc:u32 | payload`, where the
    /// CRC covers the payload and `len` is the payload length. `module` is
    /// truncated to 255 bytes (a name, not data).
    pub fn encode(&self) -> Vec<u8> {
        let module_len = self.module.len().min(255);
        let payload_len = RECORD_PREFIX_LEN + module_len + self.message.len();
        let mut payload = Vec::with_capacity(payload_len);
        payload.extend_from_slice(&self.owner_uid);
        payload.extend_from_slice(&self.owner_generation.to_le_bytes());
        payload.extend_from_slice(&self.plan_generation.to_le_bytes());
        payload.extend_from_slice(&self.timestamp_unix_ms.to_le_bytes());
        payload.extend_from_slice(&self.seq.to_le_bytes());
        payload.push(module_len as u8);
        payload.extend_from_slice(&self.module[..module_len]);
        payload.extend_from_slice(&self.message);

        let crc = crc32(&payload);
        let mut out = Vec::with_capacity(RECORD_FRAME_OVERHEAD + payload.len());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// The total on-disk size of this record's frame.
    pub fn framed_len(&self) -> usize {
        RECORD_FRAME_OVERHEAD + RECORD_PREFIX_LEN + self.module.len().min(255) + self.message.len()
    }
}

/// Result of attempting to decode one framed record at the start of `bytes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordDecode {
    /// A CRC-valid record and the number of bytes it consumed.
    Ok(LogRecord, usize),
    /// A well-framed but CRC-invalid (torn / mid-overwrite) record; the reader
    /// should skip `consumed` bytes and surface the loss as a `seq` gap.
    Torn { consumed: usize },
    /// Not enough bytes for a full frame — stop scanning (end of valid region).
    Incomplete,
}

/// Decode the framed record at the start of `bytes`. Never panics on malformed
/// input; a length that overruns the buffer is reported as `Incomplete` so a
/// crash-recovery scan halts at the last intact frame.
pub fn decode_record(bytes: &[u8]) -> RecordDecode {
    if bytes.len() < RECORD_FRAME_OVERHEAD {
        return RecordDecode::Incomplete;
    }
    let payload_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let stored_crc = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let end = match RECORD_FRAME_OVERHEAD.checked_add(payload_len) {
        Some(end) => end,
        None => return RecordDecode::Incomplete,
    };
    if bytes.len() < end {
        return RecordDecode::Incomplete;
    }
    let payload = &bytes[RECORD_FRAME_OVERHEAD..end];
    if crc32(payload) != stored_crc {
        return RecordDecode::Torn { consumed: end };
    }
    // CRC verified, so the fixed prefix is present and lengths are self-consistent.
    if payload.len() < RECORD_PREFIX_LEN {
        // A CRC-valid but structurally short payload should be impossible from a
        // correct writer; treat as torn rather than trusting it.
        return RecordDecode::Torn { consumed: end };
    }
    let mut owner_uid = [0u8; 16];
    owner_uid.copy_from_slice(&payload[0..16]);
    let owner_generation = u32::from_le_bytes(payload[16..20].try_into().unwrap());
    let plan_generation = u64::from_le_bytes(payload[20..28].try_into().unwrap());
    let timestamp_unix_ms = u64::from_le_bytes(payload[28..36].try_into().unwrap());
    let seq = u64::from_le_bytes(payload[36..44].try_into().unwrap());
    let module_len = payload[44] as usize;
    let module_start = RECORD_PREFIX_LEN;
    let module_end = module_start + module_len;
    if payload.len() < module_end {
        return RecordDecode::Torn { consumed: end };
    }
    let module = payload[module_start..module_end].to_vec();
    let message = payload[module_end..].to_vec();
    RecordDecode::Ok(
        LogRecord {
            owner_uid,
            owner_generation,
            plan_generation,
            timestamp_unix_ms,
            seq,
            module,
            message,
        },
        end,
    )
}

/// A synthesized gap in a reader's stream: `dropped` records were evicted (ring
/// wrap) or lost (torn frames) between the last delivered record and the next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogsTruncated {
    pub dropped: u64,
}

/// Per-reader cursor that turns a monotone `seq` stream into gap markers. A gap
/// is a property of the *cursor*, so independent readers each compute their own.
#[derive(Clone, Copy, Debug, Default)]
pub struct GapCursor {
    /// `seq` of the last record handed to the consumer, plus one; `None` before
    /// the first record.
    last_delivered: Option<u64>,
}

impl GapCursor {
    /// Start a fresh cursor (before any record).
    pub fn new() -> Self {
        GapCursor {
            last_delivered: None,
        }
    }

    /// Resume a cursor that has already consumed up to and including `seq`.
    pub fn resume_after(seq: u64) -> Self {
        GapCursor {
            last_delivered: Some(seq),
        }
    }

    /// Observe the next record's `seq`. Returns `Some(LogsTruncated)` when the
    /// gap to the previous delivery is greater than one (records were dropped).
    /// The record itself is always the caller's to deliver next; this only
    /// reports the preceding gap. Out-of-order or duplicate `seq` (never emitted
    /// by a correct writer) yields no gap and does not move the cursor
    /// backwards.
    pub fn observe(&mut self, seq: u64) -> Option<LogsTruncated> {
        let gap = match self.last_delivered {
            Some(last) if seq > last + 1 => Some(LogsTruncated {
                dropped: seq - last - 1,
            }),
            _ => None,
        };
        match self.last_delivered {
            Some(last) if seq <= last => {}
            _ => self.last_delivered = Some(seq),
        }
        gap
    }
}

/// In-memory circular record ring with **drop-oldest** eviction, operating over
/// a caller-owned byte buffer. The
/// algorithm lives here — dependency-free, `unsafe`-free, host-tested — so the
/// intricate wrap and eviction arithmetic is exercised without the kernel's
/// static `[MAX_OWNERS] × LOG_RING_CAPACITY` storage. The kernel owns only the
/// buffer bytes and the single-writer discipline; it calls [`RingState::push`]
/// (allocation-free) on the hot path and drains via [`RingState::frames`] /
/// [`RingState::header`] on the platform tick.
///
/// Records are framed by [`LogRecord::encode`] and may **straddle** the
/// physical wrap boundary; all access is wrap-aware. Full vs empty is
/// disambiguated by tracking `used` explicitly rather than by head/tail
/// equality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingState {
    capacity: usize,
    /// Byte offset of the oldest retained record's frame.
    head: usize,
    /// Byte offset where the next record frame will be written.
    tail: usize,
    /// Bytes currently occupied (0..=capacity).
    used: usize,
    /// `seq` of the oldest retained record.
    oldest_seq: u64,
    /// `seq` the next appended record will receive.
    next_seq: u64,
}

impl RingState {
    /// A fresh empty ring of `capacity` bytes. `capacity` should exceed the
    /// largest single framed record; a record larger than `capacity` can never
    /// be stored and [`push`](Self::push) drops it. `const` so a kernel can back
    /// a `static [RingState; MAX_OWNERS]` with it.
    pub const fn new(capacity: usize) -> Self {
        RingState {
            capacity,
            head: 0,
            tail: 0,
            used: 0,
            oldest_seq: 0,
            next_seq: 0,
        }
    }

    /// Reconstruct ring state from a persisted header (crash recovery / restart
    /// continuation). `used` is not stored in the header — the caller recomputes
    /// it from a record scan and passes it in; the seq watermarks and offsets
    /// come from the header.
    pub fn from_header(header: &RingHeader, used: usize) -> Self {
        RingState {
            capacity: header.capacity as usize,
            head: header.head_off as usize,
            tail: header.tail_off as usize,
            used,
            oldest_seq: header.oldest_seq,
            next_seq: header.next_seq,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn used(&self) -> usize {
        self.used
    }
    pub fn oldest_seq(&self) -> u64 {
        self.oldest_seq
    }
    /// `seq` the next appended record will receive.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// A header snapshot for persisting this ring to its file.
    pub fn header(&self) -> RingHeader {
        RingHeader {
            version: RING_FORMAT_VERSION,
            capacity: self.capacity as u64,
            oldest_seq: self.oldest_seq,
            next_seq: self.next_seq,
            head_off: self.head as u64,
            tail_off: self.tail as u64,
        }
    }

    /// Append one already-framed record (from [`LogRecord::encode`]), evicting
    /// oldest records until it fits. Returns the number of records dropped:
    /// retained records evicted to make room (which a reader observes as a
    /// `seq` gap at the front of the window), or the incoming record itself
    /// when it cannot be stored at all. Allocation-free.
    ///
    /// The caller is responsible for assigning `seq` in the record equal to
    /// [`next_seq`](Self::next_seq) before framing; this method advances the
    /// watermark to match.
    pub fn push(&mut self, buf: &mut [u8], frame: &[u8]) -> u64 {
        debug_assert_eq!(buf.len(), self.capacity);
        let frame_len = frame.len();
        // A record that cannot fit even in an empty ring is dropped whole — it
        // would otherwise evict everything and still not store. It must NOT
        // consume a seq: the header encodes the retained window as the
        // contiguous range [oldest_seq, next_seq), so a mid-window hole is
        // unrepresentable — a reader walking `next_seq - oldest_seq` frames
        // would run one frame past the tail into stale bytes from a previous
        // lap. The unstored record simply never existed at ring level; the
        // next push reuses its seq.
        if frame_len > self.capacity {
            return 1;
        }

        let mut dropped = 0u64;
        while self.used + frame_len > self.capacity {
            dropped += self.evict_oldest(buf);
        }

        write_wrapped(buf, self.tail, frame);
        self.tail = (self.tail + frame_len) % self.capacity;
        self.used += frame_len;
        self.next_seq += 1;
        dropped
    }

    /// Evict the oldest record, returning 1 (it always drops exactly one). The
    /// oldest frame's length is read wrap-aware from its length prefix.
    fn evict_oldest(&mut self, buf: &[u8]) -> u64 {
        let payload_len = read_u32_wrapped(buf, self.head) as usize;
        let frame_len = RECORD_FRAME_OVERHEAD + payload_len;
        // Defensive: a corrupt length can't advance past what is used.
        let frame_len = frame_len.min(self.used);
        self.head = (self.head + frame_len) % self.capacity;
        self.used -= frame_len;
        self.oldest_seq += 1;
        1
    }

    /// Linearize the retained records into decoded [`LogRecord`]s, oldest first.
    /// Allocation is fine here — this is the platform-flush / reader path, not
    /// the emit hot path. A frame that fails to decode (should be impossible
    /// from this writer) stops the scan, bounding damage to the tail.
    pub fn frames(&self, buf: &[u8]) -> Vec<LogRecord> {
        let mut out = Vec::new();
        let mut off = self.head;
        let mut remaining = self.used;
        while remaining >= RECORD_FRAME_OVERHEAD {
            let payload_len = read_u32_wrapped(buf, off) as usize;
            let frame_len = RECORD_FRAME_OVERHEAD + payload_len;
            if frame_len > remaining {
                break;
            }
            let frame = read_wrapped(buf, off, frame_len);
            match decode_record(&frame) {
                RecordDecode::Ok(record, _) => out.push(record),
                _ => break,
            }
            off = (off + frame_len) % self.capacity;
            remaining -= frame_len;
        }
        out
    }
}

/// Read the retained records from a ring's byte region given its persisted
/// header, oldest-first. Reader-side companion to [`RingState::frames`] for when
/// only the header (not the live `used` count) is available — e.g. `fluxor
/// agent logs` opening a ring file. Walks exactly `next_seq - oldest_seq`
/// records from `head_off`, wrap-aware, stopping early on the first torn frame
/// (bounding damage to the tail).
pub fn read_ring_records(ring_bytes: &[u8], header: &RingHeader) -> Vec<LogRecord> {
    let cap = header.capacity as usize;
    let mut out = Vec::new();
    if cap == 0 || ring_bytes.len() < cap {
        return out;
    }
    let count = header.next_seq.saturating_sub(header.oldest_seq);
    let mut off = (header.head_off as usize) % cap;
    for _ in 0..count {
        let payload_len = read_u32_wrapped(ring_bytes, off) as usize;
        let frame_len = RECORD_FRAME_OVERHEAD + payload_len;
        if frame_len > cap {
            break;
        }
        let frame = read_wrapped(ring_bytes, off, frame_len);
        match decode_record(&frame) {
            RecordDecode::Ok(rec, _) => out.push(rec),
            _ => break,
        }
        off = (off + frame_len) % cap;
    }
    out
}

/// Write `data` into `buf` starting at `off`, wrapping around the end.
fn write_wrapped(buf: &mut [u8], off: usize, data: &[u8]) {
    let cap = buf.len();
    let first = (cap - off).min(data.len());
    buf[off..off + first].copy_from_slice(&data[..first]);
    if first < data.len() {
        let rest = data.len() - first;
        buf[..rest].copy_from_slice(&data[first..]);
    }
}

/// Read `len` bytes from `buf` starting at `off`, wrapping around the end.
fn read_wrapped(buf: &[u8], off: usize, len: usize) -> Vec<u8> {
    let cap = buf.len();
    let mut out = Vec::with_capacity(len);
    let first = (cap - off).min(len);
    out.extend_from_slice(&buf[off..off + first]);
    if first < len {
        let rest = len - first;
        out.extend_from_slice(&buf[..rest]);
    }
    out
}

/// Read a little-endian `u32` from `buf` at `off`, wrapping around the end.
fn read_u32_wrapped(buf: &[u8], off: usize) -> u32 {
    let cap = buf.len();
    let mut bytes = [0u8; 4];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = buf[(off + i) % cap];
    }
    u32::from_le_bytes(bytes)
}

/// CRC-32/ISO-HDLC (a.k.a. IEEE 802.3), polynomial `0xEDB88320`, bitwise —
/// dependency-free and `unsafe`-free, which this crate forbids. Log records are
/// short, so the per-record bitwise cost is negligible.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn sample(seq: u64, module: &[u8], message: &[u8]) -> LogRecord {
        LogRecord {
            owner_uid: [0xAB; 16],
            owner_generation: 7,
            plan_generation: 42,
            timestamp_unix_ms: 1_700_000_000_000,
            seq,
            module: module.to_vec(),
            message: message.to_vec(),
        }
    }

    #[test]
    fn record_round_trips() {
        let rec = sample(3, b"ip", b"[ip] hello world");
        let framed = rec.encode();
        assert_eq!(framed.len(), rec.framed_len());
        match decode_record(&framed) {
            RecordDecode::Ok(got, consumed) => {
                assert_eq!(got, rec);
                assert_eq!(consumed, framed.len());
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn record_with_no_module_round_trips() {
        let rec = sample(1, b"", b"off-step line");
        let framed = rec.encode();
        match decode_record(&framed) {
            RecordDecode::Ok(got, _) => {
                assert!(got.module.is_empty());
                assert_eq!(got.message, b"off-step line");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn tampered_payload_is_detected_as_torn() {
        let mut framed = sample(5, b"tls", b"secret").encode();
        // Flip a byte in the payload; the per-record CRC must catch it.
        let last = framed.len() - 1;
        framed[last] ^= 0xFF;
        match decode_record(&framed) {
            RecordDecode::Torn { consumed } => assert_eq!(consumed, framed.len()),
            other => panic!("expected Torn, got {other:?}"),
        }
    }

    #[test]
    fn truncated_frame_is_incomplete() {
        let framed = sample(1, b"m", b"body").encode();
        // Drop the last byte — a crash-recovery scan must stop, not misread.
        assert_eq!(
            decode_record(&framed[..framed.len() - 1]),
            RecordDecode::Incomplete
        );
        assert_eq!(decode_record(&[]), RecordDecode::Incomplete);
        assert_eq!(decode_record(&[0, 0, 0]), RecordDecode::Incomplete);
    }

    #[test]
    fn oversized_length_prefix_is_incomplete_not_panic() {
        // A torn header claiming a huge payload must not index out of bounds.
        let mut framed = vec![0u8; RECORD_FRAME_OVERHEAD];
        framed[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode_record(&framed), RecordDecode::Incomplete);
    }

    #[test]
    fn header_round_trips_and_crc_guards() {
        let header = RingHeader {
            version: RING_FORMAT_VERSION,
            capacity: 65536,
            oldest_seq: 10,
            next_seq: 40,
            head_off: 128,
            tail_off: 900,
        };
        let bytes = header.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(RingHeader::decode(&bytes), Some(header));

        // Corrupt one header byte → rejected.
        let mut corrupt = bytes;
        corrupt[10] ^= 0x01;
        assert_eq!(RingHeader::decode(&corrupt), None);

        // Wrong magic → rejected.
        let mut bad_magic = header.encode();
        bad_magic[0] = b'X';
        assert_eq!(RingHeader::decode(&bad_magic), None);
    }

    #[test]
    fn cursor_reports_no_gap_for_contiguous_stream() {
        let mut cursor = GapCursor::new();
        assert_eq!(cursor.observe(0), None);
        assert_eq!(cursor.observe(1), None);
        assert_eq!(cursor.observe(2), None);
    }

    #[test]
    fn cursor_reports_dropped_count_on_wrap() {
        let mut cursor = GapCursor::new();
        assert_eq!(cursor.observe(0), None);
        // Records 1..=4 were evicted before this reader saw them.
        assert_eq!(cursor.observe(5), Some(LogsTruncated { dropped: 4 }));
        assert_eq!(cursor.observe(6), None);
    }

    #[test]
    fn two_cursors_at_different_positions_see_their_own_gaps() {
        // The same record stream, two readers: one caught up, one lagging.
        let caught_up = {
            let mut c = GapCursor::resume_after(9);
            c.observe(10)
        };
        let lagging = {
            let mut c = GapCursor::resume_after(2);
            c.observe(10)
        };
        assert_eq!(caught_up, None);
        assert_eq!(lagging, Some(LogsTruncated { dropped: 7 }));
    }

    #[test]
    fn cursor_ignores_out_of_order_or_duplicate_seq() {
        let mut cursor = GapCursor::new();
        assert_eq!(cursor.observe(5), None);
        // A stale/duplicate seq must not move the cursor backwards or invent a gap.
        assert_eq!(cursor.observe(5), None);
        assert_eq!(cursor.observe(3), None);
        assert_eq!(cursor.observe(6), None);
    }

    // ── Ring algorithm ──────────────────────────────────────────────────────

    /// Frame a record whose message is `msg` and whose seq is the ring's next.
    fn framed(seq: u64, msg: &[u8]) -> Vec<u8> {
        sample(seq, b"m", msg).encode()
    }

    #[test]
    fn ring_round_trips_records_in_order() {
        let cap = 4096;
        let mut buf = vec![0u8; cap];
        let mut ring = RingState::new(cap);

        for i in 0..5u64 {
            let frame = framed(i, &[b'a' + i as u8; 10]);
            assert_eq!(
                ring.push(&mut buf, &frame),
                0,
                "no eviction, plenty of room"
            );
        }
        assert_eq!(ring.next_seq(), 5);
        assert_eq!(ring.oldest_seq(), 0);

        let records = ring.frames(&buf);
        assert_eq!(records.len(), 5);
        for (i, rec) in records.iter().enumerate() {
            assert_eq!(rec.seq, i as u64);
            assert_eq!(rec.message, vec![b'a' + i as u8; 10]);
        }
    }

    #[test]
    fn ring_evicts_oldest_on_wrap_and_reports_drops() {
        // Size the ring so only ~3 records fit; pushing 6 must evict the first 3.
        let one = framed(0, &[b'x'; 20]).len();
        let cap = one * 3 + 4; // room for 3 frames, not 4
        let mut buf = vec![0u8; cap];
        let mut ring = RingState::new(cap);

        let mut total_dropped = 0u64;
        for i in 0..6u64 {
            total_dropped += ring.push(&mut buf, &framed(i, &[b'x'; 20]));
        }
        // 6 pushed, ~3 retained → ~3 dropped.
        assert!(total_dropped >= 1, "wrap must evict");
        assert_eq!(ring.next_seq(), 6);
        assert_eq!(ring.oldest_seq(), total_dropped);

        let records = ring.frames(&buf);
        // Retained records are the most recent, contiguous, in order.
        assert_eq!(records.len() as u64, 6 - total_dropped);
        assert_eq!(records.first().unwrap().seq, total_dropped);
        assert_eq!(records.last().unwrap().seq, 5);

        // A reader that saw seq 0 then resumes sees exactly the eviction gap.
        let mut cursor = GapCursor::resume_after(0);
        let first_retained = records.first().unwrap().seq;
        let gap = cursor.observe(first_retained);
        if first_retained > 1 {
            assert_eq!(
                gap,
                Some(LogsTruncated {
                    dropped: first_retained - 1
                })
            );
        }
    }

    #[test]
    fn ring_handles_records_straddling_the_wrap_boundary() {
        // Choose a capacity that is NOT a multiple of the frame size, so once
        // the ring wraps, subsequent frames span the physical boundary.
        let frame_len = framed(0, &[b'z'; 17]).len();
        let cap = frame_len * 4 + frame_len / 2; // deliberately off-aligned
        let mut buf = vec![0u8; cap];
        let mut ring = RingState::new(cap);

        // Push enough to force multiple wraps.
        for i in 0..40u64 {
            ring.push(&mut buf, &framed(i, &[b'z'; 17]));
        }

        // Every retained record must decode intact despite straddling the wrap.
        let records = ring.frames(&buf);
        assert!(!records.is_empty());
        for rec in &records {
            assert_eq!(rec.message, vec![b'z'; 17]);
            assert_eq!(rec.module, b"m");
        }
        // Seqs are contiguous and end at the last pushed.
        assert_eq!(records.last().unwrap().seq, 39);
        for pair in records.windows(2) {
            assert_eq!(pair[1].seq, pair[0].seq + 1);
        }
    }

    #[test]
    fn ring_header_snapshot_round_trips_through_the_format() {
        let cap = 2048;
        let mut buf = vec![0u8; cap];
        let mut ring = RingState::new(cap);
        for i in 0..7u64 {
            ring.push(&mut buf, &framed(i, b"payload"));
        }
        let header = ring.header();
        let encoded = header.encode();
        assert_eq!(RingHeader::decode(&encoded), Some(header));
        assert_eq!(header.next_seq, 7);
        assert_eq!(header.capacity, cap as u64);
    }

    #[test]
    fn reader_reconstructs_records_from_header_and_ring_bytes() {
        // Simulate the reader path: a ring is filled (with eviction), its header
        // snapshotted, and a fresh reader recovers the retained records from the
        // header + raw bytes alone — no live `used`.
        let frame_len = framed(0, &[b'k'; 12]).len();
        let cap = frame_len * 3 + 3;
        let mut buf = vec![0u8; cap];
        let mut ring = RingState::new(cap);
        for i in 0..8u64 {
            ring.push(&mut buf, &framed(i, &[b'k'; 12]));
        }
        let header = ring.header();

        let recovered = read_ring_records(&buf, &header);
        let live = ring.frames(&buf);
        assert_eq!(recovered.len(), live.len());
        for (a, b) in recovered.iter().zip(live.iter()) {
            assert_eq!(a.seq, b.seq);
            assert_eq!(a.message, b.message);
        }
        assert_eq!(recovered.last().unwrap().seq, 7);
    }

    #[test]
    fn reader_on_empty_ring_returns_nothing() {
        let cap = 512;
        let buf = vec![0u8; cap];
        let ring = RingState::new(cap);
        assert!(read_ring_records(&buf, &ring.header()).is_empty());
    }

    #[test]
    fn ring_drops_a_record_larger_than_capacity_without_corrupting_state() {
        let cap = 64;
        let mut buf = vec![0u8; cap];
        let mut ring = RingState::new(cap);
        ring.push(&mut buf, &framed(0, b"small"));
        // A frame bigger than the whole ring is dropped whole WITHOUT
        // consuming a seq: the header's retained window is the contiguous
        // range [oldest_seq, next_seq), so `next_seq - oldest_seq` must stay
        // equal to the retained record count or a header-driven reader walks
        // past the tail into stale bytes.
        let huge = framed(1, &vec![b'q'; cap * 2]);
        assert_eq!(
            ring.push(&mut buf, &huge),
            1,
            "the incoming record is the drop"
        );
        assert_eq!(ring.next_seq(), 1, "no seq consumed for an unstored record");
        assert_eq!(ring.oldest_seq(), 0);
        // The small record survives; the huge one never landed.
        let records = ring.frames(&buf);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message, b"small");
    }

    #[test]
    fn header_reader_stays_consistent_after_oversized_drop_mid_stream() {
        // An oversized push into a NON-EMPTY ring must leave the persisted
        // header view identical to the live view. Advancing next_seq without
        // storing a frame would make read_ring_records walk one frame too far
        // and return stale CRC-valid bytes from an earlier lap at the tail.
        let frame_len = framed(0, &[b'x'; 20]).len();
        let cap = frame_len * 3 + 4;
        let mut buf = vec![0u8; cap];
        let mut ring = RingState::new(cap);

        // Wrap a few times so the buffer is full of old lap bytes.
        let mut seq = 0u64;
        for _ in 0..7 {
            ring.push(&mut buf, &framed(seq, &[b'x'; 20]));
            seq += 1;
        }
        // Oversized record into the non-empty ring.
        ring.push(&mut buf, &framed(seq, &vec![b'q'; cap * 2]));
        // The seq was not consumed — reuse it for the next stored record.
        ring.push(&mut buf, &framed(seq, &[b'y'; 20]));

        let live = ring.frames(&buf);
        let persisted = read_ring_records(&buf, &ring.header());
        assert_eq!(
            live.len() as u64,
            ring.next_seq() - ring.oldest_seq(),
            "retained window must stay contiguous"
        );
        assert_eq!(persisted.len(), live.len());
        for (a, b) in persisted.iter().zip(live.iter()) {
            assert_eq!((a.seq, &a.message), (b.seq, &b.message));
        }
        assert_eq!(persisted.last().unwrap().message, vec![b'y'; 20]);
    }
}
