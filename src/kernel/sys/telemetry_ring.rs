//! Kernel telemetry ring — record buffer for the observability surface, on the
//! same core as [`super::log_ring`] (`super::ring`): independent consumer
//! tails, record-atomic push from any context on any core, drop-new on
//! overflow, activation on subscribe.
//!
//! What differs from the log ring:
//!
//! - **Records, not bytes.** Any module emits via `TLM_EMIT` and the kernel
//!   itself produces PSTATUS records. Drains copy and skip whole records,
//!   sized from each header by `abi::contracts::telemetry::record_len`, and a
//!   dropped record counts once.
//! - **Nothing kept for nobody.** A record emitted while no consumer is
//!   subscribed is discarded: there is no replay.
//! - **Four owned, filtered slots.** `observe`, one `otel` per export
//!   destination, and a spare; each claimed by a module and filtered by
//!   signal type at drain time.

use super::ring::{DropUnit, Pushed, Ring, WhenIdle};
use crate::abi::contracts::telemetry as tlm;
use portable_atomic::{AtomicU32, Ordering};

/// Independent drain slots. Each carries a tail, dropped counter, active flag,
/// and filter word: `observe` + one `otel` per export destination + a spare.
pub const CONSUMERS: usize = 4;

/// Ring capacity, from the kernel's capacity profile
/// (`config::TELEMETRY_RING_CAPACITY`), which holds at least one whole
/// PSTATUS round.
const CAPACITY: usize = crate::kernel::config::TELEMETRY_RING_CAPACITY;

/// Header bytes every record starts with; a shorter emit is refused.
const MIN_RECORD: usize = 12;

static RING: Ring<CAPACITY, CONSUMERS> = Ring::new(WhenIdle::Discard, DropUnit::Records);

/// Each slot's filter word (`tlm::FILTER_*`).
static FILTERS: [AtomicU32; CONSUMERS] = [const { AtomicU32::new(0) }; CONSUMERS];
/// Module index that claimed each slot. `observe` is a permission, not an
/// identity — without this any holder could drain a peer's slot and silently
/// starve it, since a drain advances the tail. Checked on every drain.
static OWNERS: [AtomicU32; CONSUMERS] = [const { AtomicU32::new(NO_OWNER) }; CONSUMERS];
const NO_OWNER: u32 = u32::MAX;

/// Producer-side enabled gate: non-zero when at least one consumer is
/// subscribed, so the SDK can skip building a record when nothing would consume
/// it. Published to modules via the `SyscallTable.telemetry_enabled` pointer
/// (EL1/host). A benign racy single-word read on the producer side.
static ENABLED: AtomicU32 = AtomicU32::new(0);

fn refresh_enabled() {
    let any = (0..CONSUMERS).any(|s| RING.is_active(s));
    ENABLED.store(any as u32, Ordering::Release);
}

/// Pointer to the enabled word, for `SyscallTable.telemetry_enabled`. The SDK
/// reads it as a plain `u32` (0 = collection disabled).
pub fn enabled_ptr() -> *const u32 {
    (&ENABLED as *const AtomicU32).cast::<u32>()
}

/// True when at least one consumer is subscribed.
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Acquire) != 0
}

/// Emit one complete record. The kernel stamps identity: `module_idx` overwrites
/// the record's `module` field (bytes 2..4) so a module cannot forge another's.
///
/// Drop-new: if the record would overrun any active consumer it is dropped whole
/// and each overrun slot's dropped counter bumps. A record with no active
/// consumer is dropped silently — nothing would consume it.
pub fn emit(module_idx: u16, rec: &[u8]) {
    let len = rec.len();
    if !(MIN_RECORD..=tlm::MAX_RECORD_SIZE).contains(&len) {
        return;
    }
    let ident = module_idx.to_le_bytes();
    let _: Pushed = RING.push(len, |k| match k {
        2 => ident[0],
        3 => ident[1],
        _ => rec[k],
    });
}

/// Claim a drain slot for `owner` with `filter`, seeding its tail to HEAD (start
/// from "now"). Returns the slot id, or `-1` if all slots are in use.
pub fn subscribe(owner: u16, filter: u32) -> i32 {
    let held = RING.lock();
    for slot in 0..CONSUMERS {
        if !RING.is_active(slot) {
            FILTERS[slot].store(filter, Ordering::Release);
            OWNERS[slot].store(owner as u32, Ordering::Release);
            RING.activate(&held, slot, |head| head);
            refresh_enabled();
            return slot as i32;
        }
    }
    -1
}

/// Release a drain slot. Under the lock, so `ENABLED` cannot be recomputed
/// from a half-updated slot table while a concurrent subscribe holds it.
pub fn unsubscribe(slot: usize) {
    if slot < CONSUMERS {
        let held = RING.lock();
        RING.deactivate(&held, slot);
        OWNERS[slot].store(NO_OWNER, Ordering::Release);
        refresh_enabled();
    }
}

/// Does `caller` hold `slot`? A drain advances the tail, so draining someone
/// else's slot destroys their records — ownership is enforced, not assumed.
pub fn owns(slot: usize, caller: u16) -> bool {
    slot < CONSUMERS && OWNERS[slot].load(Ordering::Acquire) == caller as u32
}

/// Drain whole records for `slot` into `out`, advancing the tail. Filtered-out
/// records are skipped (tail advanced) without copying and without counting
/// against the drop counter. Stops at HEAD or when the next admitted record
/// would not fit in `out`. Returns bytes copied.
pub fn drain(slot: usize, out: &mut [u8]) -> usize {
    if slot >= CONSUMERS || !RING.is_active(slot) {
        return 0;
    }
    let head = RING.head();
    let filter = FILTERS[slot].load(Ordering::Relaxed);
    let mut tail = RING.tail(slot);
    let mut written = 0usize;
    loop {
        let avail = head.wrapping_sub(tail) as usize;
        if avail < MIN_RECORD {
            break;
        }
        let signal = RING.byte_at(tail);
        let kind = RING.byte_at(tail.wrapping_add(1));
        let rlen = tlm::record_len(signal, kind);
        // A record-atomic ring never publishes a partial or malformed record,
        // so this guards only against a corrupted tail — stop rather than spin.
        if rlen == 0 || avail < rlen {
            break;
        }
        if tlm::filter_admits(filter, signal, kind) {
            if written + rlen > out.len() {
                break;
            }
            for (k, o) in out[written..written + rlen].iter_mut().enumerate() {
                *o = RING.byte_at(tail.wrapping_add(k as u32));
            }
            written += rlen;
        }
        tail = tail.wrapping_add(rlen as u32);
    }
    RING.set_tail(slot, tail);
    written
}

/// Atomically read and clear a slot's dropped-record counter. A non-zero return
/// means the consumer missed records and should emit a gap marker.
pub fn take_dropped(slot: usize) -> u32 {
    if slot < CONSUMERS {
        RING.take_dropped(slot)
    } else {
        0
    }
}

/// Ring head and, per slot, `(active, lag_bytes, dropped)`. `TLM_STATS` projects
/// head + drop counts onto its wire layout; lag and active are for the kernel's
/// own self-observability line.
pub fn stats() -> (u32, [(bool, u32, u32); CONSUMERS]) {
    let head = RING.head();
    let mut slots = [(false, 0u32, 0u32); CONSUMERS];
    for (slot, out) in slots.iter_mut().enumerate() {
        let active = RING.is_active(slot);
        let lag = head.wrapping_sub(RING.tail(slot));
        *out = (active, if active { lag } else { 0 }, RING.dropped(slot));
    }
    (head, slots)
}

/// Ring capacity in bytes (power of two). Exposed for sizing checks and the
/// out-of-`src/` conformance tests (`tests/harness/tests/telemetry_ring.rs`).
pub fn capacity() -> usize {
    CAPACITY
}

/// Zero all ring state (head, per-slot tails/drops/active/filters, owners,
/// enabled). The ring is a process-global static, so the harness tests
/// (`tests/harness/tests/telemetry_ring.rs`) call this to isolate each case.
/// Never invoked by firmware.
#[doc(hidden)]
pub fn reset_for_test() {
    RING.reset();
    for slot in 0..CONSUMERS {
        FILTERS[slot].store(0, Ordering::Release);
        OWNERS[slot].store(NO_OWNER, Ordering::Release);
    }
    ENABLED.store(0, Ordering::Release);
}
