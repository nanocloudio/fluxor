//! Per-owner in-memory log rings (`rfc_owner_drain_and_logs.md` §4.3, Phase 1).
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
//! that made [`crate::kernel::log_ring`] choose drop-new).
//!
//! On bare-metal the existing `log_ring` backend is unchanged; these rings are
//! written only by the Linux logger tee, so on non-Linux targets the storage is
//! reserved but never pushed to.

extern crate alloc;
use alloc::vec::Vec;

use crate::kernel::owner::MAX_OWNERS;
use fluxor_contracts::log_ring::{LogRecord, RingHeader, RingState};

/// Per-owner ring byte capacity. Matches `log_ring`'s per-chip sizing; a
/// per-profile knob is deferred (`rfc_owner_drain_and_logs.md` §6.3).
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
    // SAFETY: scheduler-thread single-writer access to the static tables.
    unsafe {
        let installed = &mut *(&raw mut INSTALLED);
        if installed[slot] == (uid, generation) {
            return;
        }
        installed[slot] = (uid, generation);
        let rings = &mut *(&raw mut RINGS);
        rings[slot] = RingState::new(CAP);
        // The backing bytes need no zeroing: a fresh RingState reports `used` 0,
        // so stale bytes are never read.
    }
}

/// Append one attributed record to `slot`'s ring, assigning it the ring's next
/// `seq`. Scheduler thread only.
///
/// NOTE: v1 frames through an allocating [`LogRecord::encode`]. On Linux (the
/// only caller in Phase 1) that is acceptable; an allocation-free
/// frame-in-place path is a documented follow-up (§4.3 "no allocation on the
/// log hot path") and does not change this signature.
#[allow(clippy::too_many_arguments)]
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
    // are distinct statics borrowed once each.
    unsafe {
        let rings = &mut *(&raw mut RINGS);
        let bufs = &mut *(&raw mut BUFS);
        let seq = rings[slot].next_seq();
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
        rings[slot].push(&mut bufs[slot], &frame);
    }
}

/// Snapshot `slot`'s persisted header and retained records for the platform to
/// flush to its ring file. Reader-side; allocation is fine here (not the emit
/// hot path). Scheduler thread only.
pub fn snapshot_slot(slot: usize) -> Option<(RingHeader, Vec<LogRecord>)> {
    if slot >= MAX_OWNERS {
        return None;
    }
    // SAFETY: scheduler-thread read of the static tables.
    unsafe {
        let rings = &*(&raw const RINGS);
        let bufs = &*(&raw const BUFS);
        Some((rings[slot].header(), rings[slot].frames(&bufs[slot])))
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
    // SAFETY: scheduler-thread read of the static tables.
    unsafe {
        let rings = &*(&raw const RINGS);
        let bufs = &*(&raw const BUFS);
        Some((rings[slot].header(), bufs[slot].to_vec()))
    }
}

/// The `(uid, generation)` installed on `slot`, for naming the slot's ring file
/// `<uid>.<slot>.<generation>.ring`. An uninstalled slot returns the all-zero
/// UID (owner 0 / system uses slot 0). Scheduler thread only.
pub fn installed_identity(slot: usize) -> ([u8; 16], u32) {
    if slot >= MAX_OWNERS {
        return ([0u8; 16], 0);
    }
    // SAFETY: scheduler-thread read.
    unsafe {
        let installed = &*(&raw const INSTALLED);
        installed[slot]
    }
}

/// The `seq` the next record on `slot` will receive — lets a flush decide
/// whether anything is new since its last write without cloning records.
pub fn next_seq(slot: usize) -> u64 {
    if slot >= MAX_OWNERS {
        return 0;
    }
    // SAFETY: scheduler-thread read.
    unsafe {
        let rings = &*(&raw const RINGS);
        rings[slot].next_seq()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxor_contracts::log_ring::read_ring_records;
    use std::sync::Mutex;

    // The rings are process-global `static mut`; serialize the tests that touch
    // them (each `&raw mut RINGS` is a whole-array borrow).
    static LOCK: Mutex<()> = Mutex::new(());

    fn push_line(slot: usize, uid: [u8; 16], gen: u32, msg: &[u8]) {
        push_on_slot(slot, uid, gen, 0, 0, b"", msg);
    }

    /// Reconstruct the on-disk file bytes and read them back with the reader —
    /// exercises the real kernel statics through the same path the platform
    /// flush + `agent logs` use.
    fn read_back(slot: usize) -> Vec<LogRecord> {
        let (header, buffer) = snapshot_slot_bytes(slot).expect("snapshot");
        read_ring_records(&buffer, &header)
    }

    #[test]
    fn install_push_snapshot_round_trips_through_real_statics() {
        let _g = LOCK.lock().unwrap();
        let slot = 5;
        let uid = [0x11; 16];
        install_slot(slot, uid, 1);
        push_line(slot, uid, 1, b"alpha");
        push_line(slot, uid, 1, b"beta");
        push_line(slot, uid, 1, b"gamma");

        let recs = read_back(slot);
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].seq, 0);
        assert_eq!(recs[0].message, b"alpha");
        assert_eq!(recs[2].message, b"gamma");
        assert_eq!(recs[2].owner_uid, uid);
        assert_eq!(recs[2].owner_generation, 1);
        assert_eq!(installed_identity(slot), (uid, 1));
    }

    #[test]
    fn same_triple_reinstall_keeps_ring_new_triple_resets_it() {
        let _g = LOCK.lock().unwrap();
        let slot = 6;
        let uid = [0x22; 16];
        install_slot(slot, uid, 1);
        push_line(slot, uid, 1, b"one");
        push_line(slot, uid, 1, b"two");
        assert_eq!(next_seq(slot), 2);

        // Rebuild survival: reinstalling the SAME (uid, generation) must NOT
        // reset the ring — seq keeps climbing (rfc §4.3).
        install_slot(slot, uid, 1);
        push_line(slot, uid, 1, b"three");
        assert_eq!(next_seq(slot), 3);
        assert_eq!(read_back(slot).len(), 3);

        // A genuinely new tenant (bumped generation) starts fresh at seq 0.
        install_slot(slot, uid, 2);
        assert_eq!(next_seq(slot), 0);
        push_line(slot, uid, 2, b"fresh");
        let recs = read_back(slot);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].seq, 0);
        assert_eq!(recs[0].owner_generation, 2);
    }

    #[test]
    fn eviction_shows_as_a_seq_jump_readable_by_the_reader() {
        let _g = LOCK.lock().unwrap();
        let slot = 7;
        let uid = [0x33; 16];
        install_slot(slot, uid, 1);
        // Push more than the ring can hold to force eviction. Each framed record
        // is well under CAP; push enough big lines to wrap.
        let big = vec![b'x'; 4096];
        let pushes = (CAP / big.len()) + 4;
        for _ in 0..pushes {
            push_line(slot, uid, 1, &big);
        }
        let recs = read_back(slot);
        // The ring dropped the oldest; the retained records' seqs are contiguous
        // and end at the last pushed, but do not start at 0.
        assert!(!recs.is_empty());
        assert_eq!(recs.last().unwrap().seq, (pushes as u64) - 1);
        assert!(recs.first().unwrap().seq > 0, "oldest records were evicted");
    }
}
