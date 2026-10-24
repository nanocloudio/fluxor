//! Per-owner in-memory log rings.
//!
//! One ring per live owner, keyed by owner **slot**, driven by the
//! host-tested [`RingState`]/[`LogRecord`] primitives in `fluxor_contracts`
//! (the intricate wrap/eviction/CRC logic lives there, exercised under host
//! tests). This module is only the storage and the single-writer entry points;
//! *attribution* (which slot a record belongs to) and the *file flush* live in
//! the platform.
//!
//! **Storage.** The slot table is a boot-sized [`Table`] of the owner table's
//! size (the plan's `owners` ceiling), each entry empty until its owner is
//! created: the kernel's owner table installs a ring when it hands out or
//! installs a slot ([`install_slot`]) and releases it when the owner is freed
//! ([`release_slot`]), so a node with a thousand owner slots and ten
//! workloads holds ten 64 KiB rings, not a thousand. Slot 0 (system) has a
//! ring from its first record.
//!
//! **Release.** When a flusher is registered ([`set_flusher`]), a released
//! ring is **detached** from its slot at once: it leaves the slot table for
//! a list of rings awaiting their last flush, keeping its records, its
//! `(uid, generation)` and the slot it served. The slot is empty from the
//! release on, so a new owner that takes it starts a ring of its own, and
//! the freed owner's pending records cannot be overwritten by it. The
//! platform's flush writes each detached ring to its file and frees it
//! ([`flush_detached`]). A reinstall of the same `(uid, generation)` on the
//! same slot before that flush — a rebuild that seats the owner again —
//! reattaches the ring, so its `seq` carries on. Without a flusher a released
//! ring is freed at once. The list is bounded by the owner table's size: a
//! release that finds it full drops its oldest ring, counted
//! ([`detached_dropped`]).
//!
//! **Single-writer discipline.** [`push_on_slot`] and [`install_slot`] run on
//! the scheduler thread only. Off-step emitters route their records through a
//! platform MPSC queue that the scheduler drains, so each ring sees exactly one
//! writer — which is what makes the drop-oldest overwrite safe (the concern
//! that made [`crate::kernel::sys::log_ring`] choose drop-new).
//!
//! Hosted only (`kernel/workload/mod.rs` gates it on `host-linux`): the rings
//! are written by the Linux logger tee.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::kernel::mem::table::{Table, TableError};
use crate::kernel::workload::owner::MAX_OWNERS;
use core::sync::atomic::{AtomicBool, Ordering};
use fluxor_contracts::log_ring::{LogRecord, RingHeader, RingState};

/// Per-owner ring byte capacity. Matches `log_ring`'s per-chip sizing; a
/// per-profile knob is deferred.
#[cfg(feature = "chip-rp2040")]
pub const CAP: usize = 4096;
#[cfg(not(feature = "chip-rp2040"))]
pub const CAP: usize = 65536;

/// One owner's ring: its state, its bytes, and the `(uid, generation)` it was
/// installed for, so a reinstall of the *same* triple keeps the ring (rebuild
/// survival) while a new triple starts fresh.
struct Ring {
    state: RingState,
    buf: Box<[u8]>,
    installed: ([u8; 16], u32),
}

impl Ring {
    fn new(uid: [u8; 16], generation: u32) -> Ring {
        Ring {
            state: RingState::new(CAP),
            buf: alloc::vec![0u8; CAP].into_boxed_slice(),
            installed: (uid, generation),
        }
    }
}

/// A released owner's ring awaiting its last flush, with the slot it served.
struct Detached {
    slot: usize,
    ring: Box<Ring>,
}

/// Released rings awaiting their last flush, oldest first. Scheduler thread
/// only, like the slot table.
static mut DETACHED: Vec<Detached> = Vec::new();

/// Detached rings dropped unflushed because the list was full.
static mut DETACHED_DROPPED: u64 = 0;

fn detached() -> &'static mut Vec<Detached> {
    // SAFETY: scheduler-thread single-writer state, reached through a raw
    // pointer, never a `&mut STATIC` formed twice at once.
    unsafe { &mut *core::ptr::addr_of_mut!(DETACHED) }
}

/// Move `ring`, released from `slot`, to the list awaiting its flush.
fn detach(slot: usize, ring: Box<Ring>) {
    let list = detached();
    // One pending ring per owner slot the table holds, the system's aside:
    // more is a flusher that has stopped writing.
    if !list.is_empty() && list.len() >= slots().max(1) {
        list.remove(0);
        // SAFETY: scheduler-thread state.
        unsafe { DETACHED_DROPPED += 1 };
    }
    list.push(Detached { slot, ring });
}

/// The released ring of `(slot, uid, generation)` awaiting its flush, taken
/// back off the list.
fn reattach(slot: usize, uid: [u8; 16], generation: u32) -> Option<Box<Ring>> {
    let list = detached();
    let i = list
        .iter()
        .position(|d| d.slot == slot && d.ring.installed == (uid, generation))?;
    Some(list.remove(i).ring)
}

/// The ring of every owner slot, `None` while the slot has no owner.
static mut RINGS: Table<Option<Box<Ring>>, MAX_OWNERS> = crate::boot_table!(
    MAX_OWNERS,
    None,
    crate::abi::contracts::resource::POOL_OWNERS
);

/// A platform flushes released rings to their files ([`set_flusher`]).
static FLUSHER: AtomicBool = AtomicBool::new(false);

fn rings() -> &'static mut Table<Option<Box<Ring>>, MAX_OWNERS> {
    // SAFETY: scheduler-thread single-writer state (see the module doc); the
    // table is reached through a raw pointer, never a `&mut STATIC` formed
    // twice at once.
    unsafe { &mut *core::ptr::addr_of_mut!(RINGS) }
}

fn ring(slot: usize) -> Option<&'static mut Ring> {
    rings().get_mut(slot).and_then(|r| r.as_deref_mut())
}

/// Size the slot table to the owner table's `n` slots.
///
/// # Safety
/// Graph-preparation context: no reference into the table is live.
pub unsafe fn size(n: usize) -> Result<(), TableError> {
    let t = &*core::ptr::addr_of!(RINGS);
    t.reserve(n)?;
    t.grow(n)
}

/// Slots the table holds: what a flush walks.
pub fn slots() -> usize {
    rings().len()
}

/// Rings held: one per live owner, plus detached ones awaiting their flush.
pub fn rings_held() -> usize {
    rings().iter().filter(|r| r.is_some()).count() + detached().len()
}

/// Released rings awaiting their last flush.
pub fn detached_count() -> usize {
    detached().len()
}

/// Released rings dropped unflushed because the list awaiting the flush was
/// full.
pub fn detached_dropped() -> u64 {
    // SAFETY: scheduler-thread state.
    unsafe { DETACHED_DROPPED }
}

/// A platform will write released rings to their files
/// ([`flush_detached`]). Without one a released ring is freed at once.
pub fn set_flusher(on: bool) {
    FLUSHER.store(on, Ordering::Relaxed);
}

/// Reset `slot`'s ring iff its `(uid, generation)` differs from what is
/// installed there. A reinstall of the same triple — which every routine
/// whole-graph rebuild performs — keeps the ring, its buffer, and its `seq`
/// counter, preserving seq monotonicity across commits.
/// A genuinely new tenant starts at `seq` 0. Scheduler thread only.
pub fn install_slot(slot: usize, uid: [u8; 16], generation: u32) {
    let Some(entry) = rings().get_mut(slot) else {
        return;
    };
    match entry {
        Some(r) if r.installed == (uid, generation) => {}
        Some(_) if FLUSHER.load(Ordering::Relaxed) => {
            // A new tenant over a ring its predecessor never released: the
            // predecessor's records wait for their flush, detached, and the
            // new tenant starts its own.
            if let Some(old) = entry.take() {
                detach(slot, old);
            }
            *entry = Some(Box::new(Ring::new(uid, generation)));
        }
        Some(r) => {
            // A new tenant, no flusher to keep the old records for: fresh
            // state over the same bytes. They need no zeroing: a fresh
            // RingState reports `used` 0, so stale bytes are never read.
            r.state = RingState::new(CAP);
            r.installed = (uid, generation);
        }
        None => {
            *entry = Some(
                reattach(slot, uid, generation)
                    .unwrap_or_else(|| Box::new(Ring::new(uid, generation))),
            )
        }
    }
}

/// `slot`'s owner was freed: its ring leaves the slot now. With a flusher
/// registered it is detached and waits for its last flush
/// ([`flush_detached`]); without one it is freed. Either way the slot is
/// empty when this returns, so a new owner seated there cannot touch the
/// freed owner's records. Scheduler thread only.
pub fn release_slot(slot: usize) {
    let Some(entry) = rings().get_mut(slot) else {
        return;
    };
    let Some(r) = entry.take() else {
        return;
    };
    if FLUSHER.load(Ordering::Relaxed) {
        detach(slot, r);
    }
}

/// One released ring as the platform's flush writes it: the slot it served,
/// its owner's identity, the `seq` its next record would have taken, and its
/// persisted header and raw bytes.
pub struct DetachedRing<'a> {
    pub slot: usize,
    pub uid: [u8; 16],
    pub generation: u32,
    pub next_seq: u64,
    pub header: RingHeader,
    pub bytes: &'a [u8],
}

/// Offer each released ring to `write`, oldest first; a ring `write` returns
/// `true` for has been written and is freed, one it returns `false` for stays
/// for the next flush. Scheduler thread only.
pub fn flush_detached(mut write: impl FnMut(&DetachedRing<'_>) -> bool) {
    detached().retain(|d| {
        let view = DetachedRing {
            slot: d.slot,
            uid: d.ring.installed.0,
            generation: d.ring.installed.1,
            next_seq: d.ring.state.next_seq(),
            header: d.ring.state.header(),
            bytes: &d.ring.buf,
        };
        !write(&view)
    });
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
    let Some(r) = ring_for_push(slot, uid, generation) else {
        return;
    };
    let seq = r.state.next_seq();
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
    r.state.push(&mut r.buf, &frame);
}

/// The ring a record for `slot` lands in. The system slot's starts with its
/// first record; a workload slot's exists while its owner does, and one
/// whose owner was installed without the kernel's table seeing it (an owner
/// a test drives directly) starts here if that owner is live.
fn ring_for_push(slot: usize, uid: [u8; 16], generation: u32) -> Option<&'static mut Ring> {
    if ring(slot).is_none() {
        let live = slot == 0
            || crate::kernel::exec::scheduler::owners()
                .lookup(crate::kernel::workload::owner::OwnerHandle {
                    slot: slot as u16,
                    generation,
                })
                .is_some();
        if !live {
            return None;
        }
        install_slot(slot, uid, generation);
    }
    ring(slot)
}

/// Snapshot `slot`'s persisted header and retained records for the platform to
/// flush to its ring file. Reader-side; allocation is fine here (not the emit
/// hot path). Scheduler thread only.
pub fn snapshot_slot(slot: usize) -> Option<(RingHeader, Vec<LogRecord>)> {
    let r = ring(slot)?;
    Some((r.state.header(), r.state.frames(&r.buf)))
}

/// Snapshot `slot`'s persisted header and a **copy of its raw ring buffer
/// bytes** for the platform to write to the ring file (`[header][ring bytes]`,
/// read back by the reader's wrap-aware walk from `head_off`). Scheduler thread
/// only; allocation is fine here (flush path).
pub fn snapshot_slot_bytes(slot: usize) -> Option<(RingHeader, Vec<u8>)> {
    let r = ring(slot)?;
    Some((r.state.header(), r.buf.to_vec()))
}

/// The `(uid, generation)` installed on `slot`, for naming the slot's ring file
/// `<uid>.<slot>.<generation>.ring`. A slot with no ring returns the all-zero
/// UID (owner 0 / system uses slot 0). Scheduler thread only.
pub fn installed_identity(slot: usize) -> ([u8; 16], u32) {
    ring(slot).map_or(([0u8; 16], 0), |r| r.installed)
}

/// The `seq` the next record on `slot` will receive — lets a flush decide
/// whether anything is new since its last write without cloning records.
/// 0 for a slot with no ring.
pub fn next_seq(slot: usize) -> u64 {
    ring(slot).map_or(0, |r| r.state.next_seq())
}
