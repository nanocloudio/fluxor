//! Kernel telemetry ring — multi-producer, multi-consumer record buffer for
//! the observability surface. The record-stream sibling of
//! [`super::log_ring`]: independent consumer tails, drop-new on overflow,
//! activation on subscribe.
//!
//! Two things differ from the log ring, both deliberate:
//!
//! - **Multi-producer.** Any module emits via `TLM_EMIT`, and the kernel itself
//!   produces PSTATUS records, so a reserve+copy+publish serialises under a
//!   short spinlock. v1 emission is **step-context only** (ISR emission is a
//!   stated extension point), so the lock is never taken from an interrupt and
//!   cannot deadlock on the single-core targets — there it is simply
//!   uncontended.
//! - **Record-atomic.** A whole record is copied before `HEAD` is published
//!   (Release), so a drain reading up to `HEAD` (Acquire) never sees a torn
//!   record. Drains copy and skip in whole-record units, sized from the header
//!   via the scheduler's `telemetry_record_len` mirror.

use crate::kernel::exec::scheduler::module_types::telemetry_record_len;
use portable_atomic::{AtomicBool, AtomicU32, Ordering};

/// Independent drain slots. Each carries a tail, dropped counter, active flag,
/// and filter word: `observe` + one `otel` per export destination + a spare.
pub const CONSUMERS: usize = 4;

// Capacity per target family, power of two. Telemetry records are denser than
// log text, so smaller than the log ring's 4/64 KiB split (§5.1). The `rp` MCUs
// are RAM-constrained (embassy-usb/net + kernel share ~256/520 KiB), so they get
// a modest ring; only the bcm2712 application processor gets the full 32 KiB.
#[cfg(feature = "chip-rp2040")]
const CAPACITY: usize = 4096;
#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
const CAPACITY: usize = 8192; // rp2350
#[cfg(not(feature = "rp"))]
const CAPACITY: usize = 32768; // bcm2712 / host
const MASK: usize = CAPACITY - 1;

/// One PSTATUS round: a `STEP` (52 B) and a `RES` (28 B) for every module slot,
/// plus a `POOL` (32 B) for every kernel resource pool. The scheduler emits a
/// whole round in one uninterrupted burst with no drain interleaved, so a ring
/// smaller than this drops the tail of *every* round and the high-index
/// modules / pools never report. Pinned here so the per-target capacity above
/// cannot be sized below the round it has to hold.
const PSTATUS_ROUND: usize = crate::kernel::exec::scheduler::MAX_MODULES * (52 + 28)
    + crate::abi::contracts::resource::KERNEL_POOL_COUNT * 32;
const _: () = assert!(CAPACITY >= PSTATUS_ROUND);

/// Largest record accepted in one reservation — a histogram metric (80 B). A
/// larger record is rejected whole. Mirror of
/// `abi::contracts::telemetry::MAX_RECORD_SIZE`, pinned by the same test that
/// pins `telemetry_record_len`.
const MAX_RECORD: usize = 80;

// Signal-type filter bits — mirror of `abi::contracts::telemetry::FILTER_*`.
const FILTER_METRIC: u32 = 1 << 0;
const FILTER_SPAN: u32 = 1 << 1;
const FILTER_PSTATUS: u32 = 1 << 2;

static mut BUF: [u8; CAPACITY] = [0; CAPACITY];
static HEAD: AtomicU32 = AtomicU32::new(0);
static TAILS: [AtomicU32; CONSUMERS] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
static DROPPED: [AtomicU32; CONSUMERS] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
static ACTIVE: [AtomicBool; CONSUMERS] = [
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];
static FILTERS: [AtomicU32; CONSUMERS] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
/// Module index that claimed each slot. `observe` is a permission, not an
/// identity — without this any holder could drain a peer's slot and silently
/// starve it, since a drain advances the tail. Checked on every drain.
static OWNERS: [AtomicU32; CONSUMERS] = [
    AtomicU32::new(NO_OWNER),
    AtomicU32::new(NO_OWNER),
    AtomicU32::new(NO_OWNER),
    AtomicU32::new(NO_OWNER),
];
const NO_OWNER: u32 = u32::MAX;
static LOCK: AtomicBool = AtomicBool::new(false);

/// Producer-side enabled gate (10):
/// non-zero when at least one consumer is subscribed, so the SDK can skip
/// building a record when nothing would consume it. Published to modules via the
/// `SyscallTable.telemetry_enabled` pointer (EL1/host) and, in a later step, an
/// EL0 read-only page. A benign racy single-word read on the producer side.
static ENABLED: AtomicU32 = AtomicU32::new(0);

fn refresh_enabled() {
    let any = (0..CONSUMERS).any(|s| ACTIVE[s].load(Ordering::Acquire));
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

/// RAII spinlock guard for the multi-producer emit/subscribe path.
struct Guard;
impl Guard {
    #[inline]
    fn acquire() -> Self {
        while LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Guard
    }
}
impl Drop for Guard {
    #[inline]
    fn drop(&mut self) {
        LOCK.store(false, Ordering::Release);
    }
}

#[inline]
fn ring_byte(pos: u32) -> u8 {
    // SAFETY: `& MASK` is in-bounds for BUF; volatile read paired with the
    // producer's `HEAD.store(Release)`.
    unsafe { core::ptr::read_volatile((&raw const BUF[0]).add((pos as usize) & MASK)) }
}

#[inline]
fn admits(filter: u32, signal: u8) -> bool {
    let bit = match signal {
        2 => FILTER_METRIC,  // SIGNAL_METRIC
        3 => FILTER_SPAN,    // SIGNAL_SPAN
        4 => FILTER_PSTATUS, // SIGNAL_PSTATUS
        _ => 0,
    };
    filter & bit != 0
}

/// Emit one complete record. The kernel stamps identity: `module_idx` overwrites
/// the record's `module` field (bytes 2..4) so a module cannot forge another's.
///
/// Drop-new: if the record would overrun any active consumer it is dropped whole
/// and each overrun slot's dropped counter bumps. A record with no active
/// consumer is dropped silently — nothing would consume it.
pub fn emit(module_idx: u16, rec: &[u8]) {
    let len = rec.len();
    if len < 12 || len > MAX_RECORD {
        return;
    }
    let _g = Guard::acquire();
    let head = HEAD.load(Ordering::Relaxed);

    let mut any_active = false;
    let mut overflow = false;
    for slot in 0..CONSUMERS {
        if ACTIVE[slot].load(Ordering::Acquire) {
            any_active = true;
            let lag = head.wrapping_sub(TAILS[slot].load(Ordering::Acquire)) as usize;
            if lag + len > CAPACITY {
                overflow = true;
            }
        }
    }
    if !any_active {
        return;
    }
    if overflow {
        for slot in 0..CONSUMERS {
            if ACTIVE[slot].load(Ordering::Acquire) {
                let lag = head.wrapping_sub(TAILS[slot].load(Ordering::Acquire)) as usize;
                if lag + len > CAPACITY {
                    DROPPED[slot].fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        return;
    }

    let ident = module_idx.to_le_bytes();
    for (k, &b) in rec.iter().enumerate() {
        let stamped = match k {
            2 => ident[0],
            3 => ident[1],
            _ => b,
        };
        let idx = (head.wrapping_add(k as u32) as usize) & MASK;
        // SAFETY: `idx` in-bounds via MASK; single writer under LOCK.
        unsafe {
            core::ptr::write_volatile((&raw mut BUF[0]).add(idx), stamped);
        }
    }
    HEAD.store(head.wrapping_add(len as u32), Ordering::Release);
}

/// Claim a drain slot for `owner` with `filter`, seeding its tail to HEAD (start
/// from "now"). Returns the slot id, or `-1` if all slots are in use.
pub fn subscribe(owner: u16, filter: u32) -> i32 {
    let _g = Guard::acquire();
    for slot in 0..CONSUMERS {
        if !ACTIVE[slot].load(Ordering::Acquire) {
            TAILS[slot].store(HEAD.load(Ordering::Acquire), Ordering::Release);
            DROPPED[slot].store(0, Ordering::Release);
            FILTERS[slot].store(filter, Ordering::Release);
            OWNERS[slot].store(owner as u32, Ordering::Release);
            ACTIVE[slot].store(true, Ordering::Release);
            refresh_enabled();
            return slot as i32;
        }
    }
    -1
}

/// Release a drain slot. Takes the lock so `ENABLED` cannot be recomputed from a
/// half-updated slot table while a concurrent subscribe holds it.
pub fn unsubscribe(slot: usize) {
    if slot < CONSUMERS {
        let _g = Guard::acquire();
        ACTIVE[slot].store(false, Ordering::Release);
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
    if slot >= CONSUMERS || !ACTIVE[slot].load(Ordering::Acquire) {
        return 0;
    }
    let head = HEAD.load(Ordering::Acquire);
    let filter = FILTERS[slot].load(Ordering::Relaxed);
    let mut tail = TAILS[slot].load(Ordering::Relaxed);
    let mut written = 0usize;
    loop {
        let avail = head.wrapping_sub(tail) as usize;
        if avail < 12 {
            break;
        }
        let signal = ring_byte(tail);
        let kind = ring_byte(tail.wrapping_add(1));
        let rlen = telemetry_record_len(signal, kind);
        // A record-atomic ring never publishes a partial or malformed record,
        // so this guards only against a corrupted tail — stop rather than spin.
        if rlen == 0 || avail < rlen {
            break;
        }
        if admits(filter, signal) {
            if written + rlen > out.len() {
                break;
            }
            for k in 0..rlen {
                out[written + k] = ring_byte(tail.wrapping_add(k as u32));
            }
            written += rlen;
        }
        tail = tail.wrapping_add(rlen as u32);
    }
    TAILS[slot].store(tail, Ordering::Release);
    written
}

/// Atomically read and clear a slot's dropped-record counter. A non-zero return
/// means the consumer missed records and should emit a gap marker.
pub fn take_dropped(slot: usize) -> u32 {
    if slot < CONSUMERS {
        DROPPED[slot].swap(0, Ordering::Relaxed)
    } else {
        0
    }
}

/// Ring head and, per slot, `(active, lag_bytes, dropped)`. `TLM_STATS` projects
/// head + drop counts onto its wire layout; lag and active are for the kernel's
/// own self-observability line.
pub fn stats() -> (u32, [(bool, u32, u32); CONSUMERS]) {
    let head = HEAD.load(Ordering::Acquire);
    let mut slots = [(false, 0u32, 0u32); CONSUMERS];
    for slot in 0..CONSUMERS {
        let active = ACTIVE[slot].load(Ordering::Acquire);
        let lag = head.wrapping_sub(TAILS[slot].load(Ordering::Acquire));
        let dropped = DROPPED[slot].load(Ordering::Relaxed);
        slots[slot] = (active, if active { lag } else { 0 }, dropped);
    }
    (head, slots)
}

/// Ring capacity in bytes (power of two). Exposed for sizing checks and the
/// out-of-`src/` conformance tests (`tests/harness/tests/telemetry_ring.rs`).
pub fn capacity() -> usize {
    CAPACITY
}

/// Zero all ring state (head, per-slot tails/drops/active/filters, enabled,
/// lock). The ring is a process-global static, so the harness conformance tests
/// call this to isolate each case. `#[doc(hidden)]` + never invoked by firmware
/// (cf. `owner_plan::reset_staged_plan_for_test`); inline unit tests are barred
/// from production `src/` by the `src_shape_no_inline_tests` lint, so the ring's
/// tests live in `tests/harness/tests/telemetry_ring.rs`.
#[doc(hidden)]
pub fn reset_for_test() {
    HEAD.store(0, Ordering::Release);
    for slot in 0..CONSUMERS {
        TAILS[slot].store(0, Ordering::Release);
        DROPPED[slot].store(0, Ordering::Release);
        ACTIVE[slot].store(false, Ordering::Release);
        FILTERS[slot].store(0, Ordering::Release);
        OWNERS[slot].store(NO_OWNER, Ordering::Release);
    }
    ENABLED.store(0, Ordering::Release);
    LOCK.store(false, Ordering::Release);
}
