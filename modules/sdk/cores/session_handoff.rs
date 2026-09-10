// session_handoff_core — opaque state export/import chunking with
// CRC32 integrity (SessionCtrlV1 EXPORT_BEGIN/CHUNK/END →
// IMPORT_BEGIN/CHUNK/END, see `contracts/net/session_ctrl.rs`).
//
// The exporting worker walks its opaque state blob through
// `HandoffExport`; the importing worker validates ordering, bounds,
// and integrity through `HandoffImport`. Both sides are pure logic
// over caller-owned buffers — the kernel never interprets the blob
// and this core never allocates.
//
// Chunks travel in offset order. The importer rejects gaps, overlaps,
// and over-length deliveries with `HANDOFF_CORRUPT`-class statuses
// mapped straight onto the SessionCtrlV1 `STATUS_*` codes so a module
// can put the return value on the wire unchanged.
//
// `no_std`, zero-alloc.

// ── CRC32 (IEEE, incremental) ──────────────────────────────────────

/// Incremental CRC32 (IEEE 802.3, reflected 0xEDB88320) over the
/// concatenated export blob. Same polynomial as `genstore_wire::crc32`
/// but incremental so chunked import never needs the whole blob
/// resident before checking.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct HandoffCrc32 {
    state: u32,
}

impl Default for HandoffCrc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl HandoffCrc32 {
    pub const fn new() -> Self {
        HandoffCrc32 { state: 0xFFFF_FFFF }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut crc = self.state;
        for &b in data {
            crc ^= b as u32;
            let mut i = 0;
            while i < 8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
                i += 1;
            }
        }
        self.state = crc;
    }

    pub fn finish(&self) -> u32 {
        !self.state
    }
}

/// One-shot CRC32 of a full blob (exporter side, EXPORT_END).
pub fn handoff_crc32(data: &[u8]) -> u32 {
    let mut c = HandoffCrc32::new();
    c.update(data);
    c.finish()
}

// ── Status codes (mirror session_ctrl::STATUS_*) ───────────────────

pub const HANDOFF_OK: u8 = 0; // STATUS_OK
pub const HANDOFF_NO_CAPACITY: u8 = 3; // STATUS_NO_CAPACITY
pub const HANDOFF_CORRUPT: u8 = 4; // STATUS_CORRUPT
pub const HANDOFF_NOT_READY: u8 = 5; // STATUS_NOT_READY
pub const HANDOFF_CURSOR_MISMATCH: u8 = 7; // STATUS_CURSOR_MISMATCH

// ── Exporter ───────────────────────────────────────────────────────

/// Chunk iterator over an opaque state blob. The module owns the blob
/// buffer; this tracks the walk so each `module_step` can emit one
/// CMD_SC_EXPORT_CHUNK without re-deriving offsets.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct HandoffExport {
    total_len: u32,
    offset: u32,
}

impl HandoffExport {
    /// Start an export of `total_len` bytes (the EXPORT_BEGIN payload's
    /// `total_len` field).
    pub const fn new(total_len: u32) -> Self {
        HandoffExport {
            total_len,
            offset: 0,
        }
    }

    /// Total bytes being exported.
    #[inline]
    pub fn total_len(&self) -> u32 {
        self.total_len
    }

    /// The next chunk to send as `(offset, len)` into the caller's
    /// blob, capped at `max_chunk` bytes. `None` when the walk is
    /// complete and CMD_SC_EXPORT_END (with `handoff_crc32(blob)`)
    /// should be sent instead. Call `advance` after the chunk is
    /// actually written to the channel.
    pub fn next_chunk(&self, max_chunk: u32) -> Option<(u32, u32)> {
        if self.offset >= self.total_len || max_chunk == 0 {
            return None;
        }
        let remaining = self.total_len - self.offset;
        let len = if remaining < max_chunk {
            remaining
        } else {
            max_chunk
        };
        Some((self.offset, len))
    }

    /// Mark `len` bytes from the current offset as delivered.
    pub fn advance(&mut self, len: u32) {
        self.offset = self.offset.saturating_add(len).min(self.total_len);
    }

    /// True once every byte has been delivered (time for EXPORT_END).
    #[inline]
    pub fn done(&self) -> bool {
        self.offset >= self.total_len
    }
}

// ── Importer ───────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ImportPhase {
    Idle = 0,
    Receiving = 1,
    Complete = 2,
}

/// Reassembly state machine for the importing worker. Validates
/// EXPORT_BEGIN/CHUNK/END ordering, bounds, contiguity, and the final
/// CRC32; copies chunk bytes into the caller's destination buffer.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct HandoffImport {
    phase: ImportPhase,
    _pad: [u8; 3],
    total_len: u32,
    received: u32,
    crc: HandoffCrc32,
}

impl Default for HandoffImport {
    fn default() -> Self {
        Self::new()
    }
}

impl HandoffImport {
    pub const fn new() -> Self {
        HandoffImport {
            phase: ImportPhase::Idle,
            _pad: [0; 3],
            total_len: 0,
            received: 0,
            crc: HandoffCrc32::new(),
        }
    }

    /// Handle CMD_SC_EXPORT_BEGIN. `capacity` is the size of the
    /// destination buffer the importer owns. Returns the STATUS_* code
    /// for MSG_SC_IMPORT_BEGIN: `HANDOFF_OK` or `HANDOFF_NO_CAPACITY`.
    pub fn begin(&mut self, total_len: u32, capacity: u32) -> u8 {
        if total_len > capacity {
            self.phase = ImportPhase::Idle;
            return HANDOFF_NO_CAPACITY;
        }
        self.phase = ImportPhase::Receiving;
        self.total_len = total_len;
        self.received = 0;
        self.crc = HandoffCrc32::new();
        HANDOFF_OK
    }

    /// Handle one CMD_SC_EXPORT_CHUNK: copy `data` at `offset` into
    /// `dest`. Chunks must be contiguous and in order (offset ==
    /// bytes received so far); a gap, overlap, or overrun is
    /// `HANDOFF_CORRUPT` and aborts the import. A chunk before BEGIN
    /// is `HANDOFF_NOT_READY`.
    pub fn chunk(&mut self, offset: u32, data: &[u8], dest: &mut [u8]) -> u8 {
        if self.phase != ImportPhase::Receiving {
            return HANDOFF_NOT_READY;
        }
        let len = data.len() as u32;
        if offset != self.received
            || self.received.saturating_add(len) > self.total_len
            || (dest.len() as u32) < offset.saturating_add(len)
        {
            self.phase = ImportPhase::Idle;
            return HANDOFF_CORRUPT;
        }
        // Byte loop rather than `copy_from_slice`: the PIC module
        // build has no len-mismatch panic machinery to link against,
        // and the bounds were validated above.
        let base = offset as usize;
        let mut i = 0;
        while i < data.len() {
            dest[base + i] = data[i];
            i += 1;
        }
        self.crc.update(data);
        self.received += len;
        HANDOFF_OK
    }

    /// Handle CMD_SC_EXPORT_END with the exporter's CRC32. Returns the
    /// STATUS_* code for MSG_SC_IMPORT_END: `HANDOFF_OK` when every
    /// byte arrived and the CRC matches, else `HANDOFF_CORRUPT` (or
    /// `HANDOFF_NOT_READY` before BEGIN).
    pub fn end(&mut self, expected_crc: u32) -> u8 {
        if self.phase != ImportPhase::Receiving {
            return HANDOFF_NOT_READY;
        }
        if self.received != self.total_len || self.crc.finish() != expected_crc {
            self.phase = ImportPhase::Idle;
            return HANDOFF_CORRUPT;
        }
        self.phase = ImportPhase::Complete;
        HANDOFF_OK
    }

    /// True once `end` accepted the blob; the imported bytes in the
    /// destination buffer are committed and RESUME may be honored.
    #[inline]
    pub fn complete(&self) -> bool {
        self.phase == ImportPhase::Complete
    }

    /// Bytes accepted so far.
    #[inline]
    pub fn received(&self) -> u32 {
        self.received
    }

    /// Total expected (0 before BEGIN).
    #[inline]
    pub fn total_len(&self) -> u32 {
        self.total_len
    }

    /// Discard any partial import (detach, stale epoch, error).
    pub fn reset(&mut self) {
        self.phase = ImportPhase::Idle;
        self.total_len = 0;
        self.received = 0;
        self.crc = HandoffCrc32::new();
    }
}

// ── Delivery cursors ───────────────────────────────────────────────

/// Where an exported blob sits in the session's two byte streams, both
/// counted from the session's first byte (see `contracts/net/session_ctrl.rs`
/// §Delivery cursors). The exporting worker fills these in; the anchor
/// checks them against its own counters; the importing worker resumes
/// from them.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct SessionCursors {
    /// Inbound bytes the anchor forwarded that the blob accounts for.
    pub in_consumed: u64,
    /// Outbound bytes the blob has already emitted toward the client.
    pub out_produced: u64,
}

/// Bytes a cursor pair occupies on the wire.
pub const CURSOR_PAIR_LEN: usize = 16;

impl SessionCursors {
    pub const fn new(in_consumed: u64, out_produced: u64) -> Self {
        SessionCursors {
            in_consumed,
            out_produced,
        }
    }

    /// Little-endian pair, in EXPORT_BEGIN field order.
    pub fn encode(&self, out: &mut [u8; CURSOR_PAIR_LEN]) {
        out[0..8].copy_from_slice(&self.in_consumed.to_le_bytes());
        out[8..16].copy_from_slice(&self.out_produced.to_le_bytes());
    }

    /// Inverse of `encode`. `None` if the field is short.
    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() < CURSOR_PAIR_LEN {
            return None;
        }
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        a.copy_from_slice(&src[0..8]);
        b.copy_from_slice(&src[8..16]);
        Some(SessionCursors {
            in_consumed: u64::from_le_bytes(a),
            out_produced: u64::from_le_bytes(b),
        })
    }
}

/// Anchor-side check of an EXPORT_BEGIN's cursors against what this
/// anchor actually delivered to and relayed from the exporting worker.
///
/// `HANDOFF_OK` only when both agree exactly. Any disagreement means the
/// blob and the client have seen different prefixes of the session, so
/// the caller must refuse the handoff and leave the session where it is
/// — see the fault table in `contracts/net/session_ctrl.rs`.
pub fn cursors_admit(exported: &SessionCursors, forwarded: u64, relayed: u64) -> u8 {
    if exported.in_consumed == forwarded && exported.out_produced == relayed {
        HANDOFF_OK
    } else {
        HANDOFF_CURSOR_MISMATCH
    }
}
