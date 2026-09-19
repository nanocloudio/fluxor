//! Per-owner in-memory log rings.
//!
//! A static `[MAX_OWNERS] × CAP` reservation keyed by owner **slot**, driven by
//! the host-tested [`RingState`]/[`LogRecord`] primitives in `fluxor_contracts`
//! (the intricate wrap/eviction/CRC logic lives there, exercised under host
//! tests). This module is only the storage and the single-writer entry points;
//! *attribution* (which slot a record belongs to) and the *file flush* live in
//! the platform.
//!
//! **Single-writer discipline.** [`push_on_slot`] and [`install_slot`] run on
//! the scheduler thread only. Off-step emitters route their records through a
//! platform MPSC queue that the scheduler drains, so each ring sees exactly one
//! writer — which is what makes the drop-oldest overwrite safe (the concern
//! that made [`crate::kernel::sys::log_ring`] choose drop-new).
//!
//! On bare-metal the existing `log_ring` backend is unchanged; these rings are
//! written only by the Linux logger tee, so on non-Linux targets the storage is
//! reserved but never pushed to.

extern crate alloc;
use alloc::vec::Vec;

use crate::kernel::workload::owner::MAX_OWNERS;
use fluxor_contracts::log_ring::{LogRecord, RingHeader, RingState};

/// Per-owner ring byte capacity. Matches `log_ring`'s per-chip sizing; a
/// per-profile knob is deferred.
#[cfg(feature = "chip-rp2040")]
pub const CAP: usize = 4096;
#[cfg(not(feature = "chip-rp2040"))]
pub const CAP: usize = 65536;

// Ring state + backing bytes per slot, plus the installed (uid, generation) so a
// reinstall of the *same* triple keeps the ring (rebuild survival) while a new
// triple starts fresh. Slot 0 (system / owner-0) has a ring like any other.
static mut RINGS: [RingState; MAX_OWNERS] = [RingState::new(CAP); MAX_OWNERS];
static mut BUFS: [[u8; CAP]; MAX_OWNERS] = [[0u8; CAP]; MAX_OWNERS];
static mut INSTALLED: [([u8; 16], u32); MAX_OWNERS] = [([0u8; 16], 0u32); MAX_OWNERS];

/// Reset `slot`'s ring iff its `(uid, generation)` differs from what is
/// installed there. A reinstall of the same triple — which every routine
/// whole-graph rebuild performs — keeps the ring, its buffer, and its `seq`
/// counter, preserving seq monotonicity across commits (§4.3 rebuild survival).
/// A genuinely new tenant starts at `seq` 0. Scheduler thread only.
pub fn install_slot(slot: usize, uid: [u8; 16], generation: u32) {
    if slot >= MAX_OWNERS {
        return;
    }
    // SAFETY: scheduler-thread single-writer access to the static tables;
    // element access goes through raw pointers, never forming a `&mut STATIC`.
    unsafe {
        let installed = &raw mut INSTALLED;
        if (*installed)[slot] == (uid, generation) {
            return;
        }
        (*installed)[slot] = (uid, generation);
        let rings = &raw mut RINGS;
        (*rings)[slot] = RingState::new(CAP);
        // The backing bytes need no zeroing: a fresh RingState reports `used` 0,
        // so stale bytes are never read.
    }
}

/// Append one attributed record to `slot`'s ring, assigning it the ring's next
/// `seq`. Scheduler thread only.
///
/// Framing goes through an allocating [`LogRecord::encode`]. Linux is the
/// only caller, and allocates freely, so that is acceptable here; framing in
/// place would keep allocation off the log hot path and would not change
/// this signature.
#[allow(
    clippy::too_many_arguments,
    reason = "attributed log record fields are passed positionally across the ABI boundary"
)]
pub fn push_on_slot(
    slot: usize,
    uid: [u8; 16],
    generation: u32,
    plan_generation: u64,
    timestamp_unix_ms: u64,
    module: &[u8],
    message: &[u8],
) {
    if slot >= MAX_OWNERS {
        return;
    }
    // SAFETY: scheduler-thread single-writer access; RINGS[slot] and BUFS[slot]
    // are distinct statics, reached through raw pointers (never a `&mut STATIC`).
    unsafe {
        let rings = &raw mut RINGS;
        let bufs = &raw mut BUFS;
        let seq = (*rings)[slot].next_seq();
        let record = LogRecord {
            owner_uid: uid,
            owner_generation: generation,
            plan_generation,
            timestamp_unix_ms,
            seq,
            module: module.to_vec(),
            message: message.to_vec(),
        };
        let frame = record.encode();
        (*rings)[slot].push(&mut (*bufs)[slot], &frame);
    }
}

/// Snapshot `slot`'s persisted header and retained records for the platform to
/// flush to its ring file. Reader-side; allocation is fine here (not the emit
/// hot path). Scheduler thread only.
pub fn snapshot_slot(slot: usize) -> Option<(RingHeader, Vec<LogRecord>)> {
    if slot >= MAX_OWNERS {
        return None;
    }
    // SAFETY: scheduler-thread read of the static tables, through raw pointers.
    unsafe {
        let rings = &raw const RINGS;
        let bufs = &raw const BUFS;
        Some((
            (*rings)[slot].header(),
            (*rings)[slot].frames(&(*bufs)[slot]),
        ))
    }
}

/// Snapshot `slot`'s persisted header and a **copy of its raw ring buffer
/// bytes** for the platform to write to the ring file (`[header][ring bytes]`,
/// read back by the reader's wrap-aware walk from `head_off`). Scheduler thread
/// only; allocation is fine here (flush path).
pub fn snapshot_slot_bytes(slot: usize) -> Option<(RingHeader, Vec<u8>)> {
    if slot >= MAX_OWNERS {
        return None;
    }
    // SAFETY: scheduler-thread read of the static tables, through raw pointers.
    unsafe {
        let rings = &raw const RINGS;
        let bufs = &raw const BUFS;
        Some(((*rings)[slot].header(), (*bufs)[slot].to_vec()))
    }
}

/// The `(uid, generation)` installed on `slot`, for naming the slot's ring file
/// `<uid>.<slot>.<generation>.ring`. An uninstalled slot returns the all-zero
/// UID (owner 0 / system uses slot 0). Scheduler thread only.
pub fn installed_identity(slot: usize) -> ([u8; 16], u32) {
    if slot >= MAX_OWNERS {
        return ([0u8; 16], 0);
    }
    // SAFETY: scheduler-thread read, through a raw pointer.
    unsafe {
        let installed = &raw const INSTALLED;
        (*installed)[slot]
    }
}

/// The `seq` the next record on `slot` will receive — lets a flush decide
/// whether anything is new since its last write without cloning records.
pub fn next_seq(slot: usize) -> u64 {
    if slot >= MAX_OWNERS {
        return 0;
    }
    // SAFETY: scheduler-thread read, through a raw pointer.
    unsafe {
        let rings = &raw const RINGS;
        (*rings)[slot].next_seq()
    }
}
