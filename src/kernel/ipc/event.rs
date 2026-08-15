//! Kernel event subsystem — signalable/pollable notification objects.
//!
//! Events are the universal wake mechanism for modules. An event is a
//! single-bit flag that can be signaled (from any context, including ISR)
//! and polled (non-blocking, clears on read).
//!
//! Device-specific bindings (e.g. GPIO edge -> event) are handled by the
//! respective device providers, not here. Providers call `event_signal()`
//! when their hardware condition fires.
//!
//! The scheduler checks `EVENT_WAKE_PENDING` and steps only the affected
//! modules via `step_woken_modules()`, providing intra-tick wake response.

use portable_atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use crate::kernel::sys::errno;
use crate::kernel::sys::hal;
use crate::kernel::workload::bitmask::{ModuleMask, MODULE_MASK_WORDS};

/// Maximum concurrent events across all modules.
pub const MAX_EVENTS: usize = 32;

// ============================================================================
// Event slot
// ============================================================================

struct EventSlot {
    /// Whether this slot is allocated.
    allocated: AtomicBool,
    /// The signaled flag — set by signal(), cleared by poll().
    signaled: AtomicBool,
    /// Owning module index (0..MAX_MODULES-1), or 0xFF if unowned.
    owner: AtomicU8,
}

impl EventSlot {
    const fn new() -> Self {
        Self {
            allocated: AtomicBool::new(false),
            signaled: AtomicBool::new(false),
            owner: AtomicU8::new(0xFF),
        }
    }
}

// ============================================================================
// Static state
// ============================================================================

static EVENT_SLOTS: [EventSlot; MAX_EVENTS] = [const { EventSlot::new() }; MAX_EVENTS];

/// One bit per module. Set when any owned event is signaled. Backed by
/// `MODULE_MASK_WORDS` atomics so it scales with `MAX_MODULES` beyond 64.
/// Scheduler reads + clears each word atomically.
static EVENT_WAKE_PENDING: [AtomicU64; MODULE_MASK_WORDS] =
    [const { AtomicU64::new(0) }; MODULE_MASK_WORDS];

// ── Owner pause wake masking (rfc_workload_lifecycle.md §3.2 / P4;
//    rfc_owner_drain_and_logs.md §3.6 per-owner wake masking) ─────────
//
// While an owner is paused its modules' wake sources are MASKED, not
// dropped: a wake that would latch `EVENT_WAKE_PENDING` (event signal,
// wake-on-write, budget re-latch) is diverted into `PAUSED_DEFERRED_WAKES`
// and the scheduler doorbell is NOT rung — so a paused owner neither steps
// nor keeps its domain out of idle sleep, and no cross-domain doorbell
// leaks for it. `owner_resume` drains the deferred bits back into
// `EVENT_WAKE_PENDING` (the re-latch path), so anything that
// arrived-while-paused produces a wake exactly once.
//
// Lost-wakeup discipline is mask-then-check: `owner_pause` sets the
// PAUSED_MODULES bits FIRST, then sweeps already-latched bits into the
// deferred store; a signaller that raced past the mask read latches
// `EVENT_WAKE_PENDING`, where the runner's per-pass sweep (or the
// woken-step guard) defers it. `owner_resume` clears the mask FIRST, then
// drains the deferred store — a concurrent signal lands in whichever
// store is live and is delivered either way.
//
// Default-off: `PAUSED_OWNER_COUNT == 0` short-circuits every check, and
// non-multitenant builds compile the checks out entirely (a single-tenant
// target has no pausable owner).

/// Modules whose wake delivery is masked (their owner is paused).
#[cfg(feature = "multitenant")]
static PAUSED_MODULES: [AtomicU64; MODULE_MASK_WORDS] =
    [const { AtomicU64::new(0) }; MODULE_MASK_WORDS];
/// Wakes that arrived for masked modules; re-latched on resume.
#[cfg(feature = "multitenant")]
static PAUSED_DEFERRED_WAKES: [AtomicU64; MODULE_MASK_WORDS] =
    [const { AtomicU64::new(0) }; MODULE_MASK_WORDS];
/// Number of currently paused owners — the default-off guard.
#[cfg(feature = "multitenant")]
static PAUSED_OWNER_COUNT: portable_atomic::AtomicUsize = portable_atomic::AtomicUsize::new(0);

/// Default-off guard: true iff at least one owner is paused. One relaxed
/// load; every pause-aware check short-circuits on it.
#[inline]
pub fn paused_owners_present() -> bool {
    #[cfg(feature = "multitenant")]
    {
        PAUSED_OWNER_COUNT.load(Ordering::Relaxed) != 0
    }
    #[cfg(not(feature = "multitenant"))]
    {
        false
    }
}

/// True iff `module_idx`'s wake delivery is masked (its owner is paused).
/// Callers MUST short-circuit behind [`paused_owners_present`].
#[inline]
pub fn module_wake_masked(module_idx: usize) -> bool {
    #[cfg(feature = "multitenant")]
    {
        module_idx < crate::kernel::boot::config::MAX_MODULES
            && (PAUSED_MODULES[module_idx / 64].load(Ordering::Acquire) >> (module_idx % 64)) & 1
                != 0
    }
    #[cfg(not(feature = "multitenant"))]
    {
        let _ = module_idx;
        false
    }
}

/// Divert a wake for a masked module into the deferred store.
#[inline]
pub fn defer_masked_wake(module_idx: usize) {
    #[cfg(feature = "multitenant")]
    if module_idx < crate::kernel::boot::config::MAX_MODULES {
        PAUSED_DEFERRED_WAKES[module_idx / 64]
            .fetch_or(1u64 << (module_idx % 64), Ordering::Release);
    }
    #[cfg(not(feature = "multitenant"))]
    {
        let _ = module_idx;
    }
}

/// Divert an already-taken wake set into the deferred store (the runner's
/// per-pass straggler sweep for a paused graph).
#[cfg(feature = "multitenant")]
pub fn defer_masked_wakes(mask: &ModuleMask) {
    for (atomic, w) in PAUSED_DEFERRED_WAKES.iter().zip(mask.as_words().iter()) {
        if *w != 0 {
            atomic.fetch_or(*w, Ordering::Release);
        }
    }
}

/// `owner_pause` half of §3.6 masking: mark `mask`'s modules wake-masked and
/// bump the paused-owner count. Mask-then-check: callers sweep
/// already-latched bits AFTER this returns.
#[cfg(feature = "multitenant")]
pub fn pause_mask_modules(mask: &ModuleMask) {
    PAUSED_OWNER_COUNT.fetch_add(1, Ordering::Release);
    for (atomic, w) in PAUSED_MODULES.iter().zip(mask.as_words().iter()) {
        if *w != 0 {
            atomic.fetch_or(*w, Ordering::Release);
        }
    }
}

/// `owner_resume` half: unmask `mask`'s modules and drop the paused-owner
/// count. Returns the deferred wakes accumulated while masked — the caller
/// re-latches them (or discards them on `free_owner` of a paused owner).
#[cfg(feature = "multitenant")]
pub fn unpause_mask_modules(mask: &ModuleMask) -> ModuleMask {
    let mw = mask.as_words();
    for (atomic, w) in PAUSED_MODULES.iter().zip(mw.iter()) {
        if *w != 0 {
            atomic.fetch_and(!*w, Ordering::Release);
        }
    }
    let mut out = [0u64; MODULE_MASK_WORDS];
    for ((atomic, w), o) in PAUSED_DEFERRED_WAKES
        .iter()
        .zip(mw.iter())
        .zip(out.iter_mut())
    {
        if *w != 0 {
            let prev = atomic.fetch_and(!*w, Ordering::AcqRel);
            *o = prev & *w;
        }
    }
    PAUSED_OWNER_COUNT.fetch_sub(1, Ordering::Release);
    ModuleMask::from_words(out)
}

// ============================================================================
// Ownership validation
// ============================================================================

/// Check that the event handle is valid, allocated, and owned by the calling module.
/// Returns Ok(&EventSlot) on success, Err(errno) on failure.
fn check_event_access(handle: i32) -> Result<&'static EventSlot, i32> {
    if handle < 0 || handle as usize >= MAX_EVENTS {
        return Err(errno::EINVAL);
    }
    let slot = &EVENT_SLOTS[handle as usize];
    if !slot.allocated.load(Ordering::Acquire) {
        return Err(errno::EINVAL);
    }
    let owner = slot.owner.load(Ordering::Acquire);
    let caller = crate::kernel::exec::scheduler::current_module_index() as u8;
    if owner != 0xFF && owner != caller {
        return Err(errno::EINVAL);
    }
    Ok(slot)
}

// ============================================================================
// Core event operations
// ============================================================================

/// Create a new event owned by the currently executing module.
/// Returns event handle (slot index, >=0) or negative errno.
pub fn event_create() -> i32 {
    use crate::abi::contracts::resource::POOL_EVENTS;
    use crate::kernel::sys::resource_ledger as ledger;
    if !ledger::enforced_allows(POOL_EVENTS, in_use_count() as u32 + 1) {
        ledger::deny(POOL_EVENTS);
        return errno::ENOSPC;
    }
    let owner = crate::kernel::exec::scheduler::current_module_index() as u8;
    for (i, slot) in EVENT_SLOTS.iter().enumerate() {
        if slot
            .allocated
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            slot.signaled.store(false, Ordering::Release);
            slot.owner.store(owner, Ordering::Release);
            return i as i32;
        }
    }
    crate::kernel::sys::resource_ledger::deny(crate::abi::contracts::resource::POOL_EVENTS);
    errno::ENOSPC
}

/// Allocated slots — resource-ledger sample for `POOL_EVENTS`.
pub fn in_use_count() -> usize {
    EVENT_SLOTS
        .iter()
        .filter(|s| s.allocated.load(Ordering::Relaxed))
        .count()
}

/// Signal an event. Safe to call from any context (module step, poll, ISR).
///
/// Sets the signaled flag, marks the owning module for wake, and pokes
/// the scheduler signal so it can break out of its timer sleep.
pub fn event_signal(handle: i32) -> i32 {
    if handle < 0 || handle as usize >= MAX_EVENTS {
        return errno::EINVAL;
    }
    let slot = &EVENT_SLOTS[handle as usize];
    if !slot.allocated.load(Ordering::Acquire) {
        return errno::EINVAL;
    }
    slot.signaled.store(true, Ordering::Release);
    let owner = slot.owner.load(Ordering::Relaxed);
    if (owner as usize) < crate::kernel::boot::config::MAX_MODULES
        && !latch_module_wake(owner as usize)
    {
        // Owner paused: wake deferred, doorbell suppressed (§3.6 masking).
        return 0;
    }
    hal::wake_scheduler();
    0
}

/// Minimal ISR-safe signal path. No validation beyond bounds check.
/// Called at most once per ISR entry (coalesced), not per-pin.
///
/// # Safety
/// Caller must ensure handle is a valid, allocated event slot.
pub fn event_signal_from_isr(handle: i32) {
    if handle < 0 || handle as usize >= MAX_EVENTS {
        return;
    }
    let slot = &EVENT_SLOTS[handle as usize];
    slot.signaled.store(true, Ordering::Release);
    let owner = slot.owner.load(Ordering::Relaxed);
    if (owner as usize) < crate::kernel::boot::config::MAX_MODULES
        && !latch_module_wake(owner as usize)
    {
        // Owner paused: wake deferred, doorbell suppressed (§3.6 masking).
        return;
    }
    hal::wake_scheduler();
}

/// Poll an event (non-blocking). Clears the signaled flag atomically.
/// Returns: 1 if was signaled (now cleared), 0 if not signaled, <0 on error.
/// Only the owning module may poll its events.
pub fn event_poll(handle: i32) -> i32 {
    let slot = match check_event_access(handle) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if slot.signaled.swap(false, Ordering::AcqRel) {
        1
    } else {
        0
    }
}

/// Non-destructive peek: check if an event is signaled without clearing it.
/// Used by `fd_poll` for unified readiness checks.
pub fn event_is_signaled(handle: i32) -> bool {
    if handle < 0 || handle as usize >= MAX_EVENTS {
        return false;
    }
    let slot = &EVENT_SLOTS[handle as usize];
    if !slot.allocated.load(Ordering::Acquire) {
        return false;
    }
    slot.signaled.load(Ordering::Acquire)
}

/// Destroy an event and free its slot.
/// Only the owning module may destroy its events.
/// Note: Device-specific cleanup (e.g. GPIO edge unbinding) is the
/// responsibility of the device provider, not the event subsystem.
pub fn event_destroy(handle: i32) -> i32 {
    let slot = match check_event_access(handle) {
        Ok(s) => s,
        Err(e) => return e,
    };
    slot.signaled.store(false, Ordering::Release);
    slot.owner.store(0xFF, Ordering::Release);
    slot.allocated.store(false, Ordering::Release);
    0
}

// ============================================================================
// Scheduler interface
// ============================================================================

/// Atomically read and clear the wake-pending bitmask.
/// Returns a `ModuleMask` where bit N is set if module N has pending events.
pub fn take_wake_pending() -> ModuleMask {
    let mut words = [0u64; MODULE_MASK_WORDS];
    for (w, atomic) in words.iter_mut().zip(EVENT_WAKE_PENDING.iter()) {
        *w = atomic.swap(0, Ordering::AcqRel);
    }
    ModuleMask::from_words(words)
}

/// Non-clearing peek at the wake-pending bitmask. Used by platforms
/// that pace with a spin loop (Linux `tick_us <= 200` path) to yield
/// the spin budget early when an event fires, without consuming the
/// bits — the next iteration's `take_wake_pending` still observes them
/// and runs the woken modules.
#[inline]
pub fn wake_pending_nonzero() -> bool {
    EVENT_WAKE_PENDING
        .iter()
        .any(|w| w.load(Ordering::Acquire) != 0)
}

/// Non-clearing peek at the wake-pending bitmask, restricted to a set of
/// modules (a domain's modules). True iff any module in `mask` has a pending
/// event. The adaptive-tick pacer uses this so one domain's idle decision is
/// not coupled to a sibling domain's wake (RFC adaptive_tick §5.1). Like
/// `wake_pending_nonzero`, it does NOT consume the bits — the next
/// `take_wake_pending` still observes them.
#[inline]
pub fn wake_pending_in_mask(mask: &ModuleMask) -> bool {
    let mut words = [0u64; MODULE_MASK_WORDS];
    for (w, atomic) in words.iter_mut().zip(EVENT_WAKE_PENDING.iter()) {
        *w = atomic.load(Ordering::Acquire);
    }
    ModuleMask::from_words(words).intersects(mask)
}

/// Latch a module's wake bit WITHOUT ringing the scheduler doorbell —
/// the bare latch half of `event_signal`. Two callers, with opposite
/// doorbell needs:
/// - wake-on-write (`channel::wake_consumer_if_flagged`) latches here and
///   rings `wake_scheduler()` itself, so a flagged write cuts an idle
///   sleep short;
/// - the woken-step budget bound (RFC idle_skip_wake §5) restores a
///   deferred module's bit — already consumed by the caller's
///   `take_wake_pending` — so the wake is not lost, and deliberately does
///   NOT ring the doorbell: the deferral exists because the domain is
///   over budget NOW, and the next pass drains the bit without an
///   immediate re-wake storm.
pub fn relatch_module_wake(module_idx: usize) {
    let _ = latch_module_wake(module_idx);
}

/// Latch `module_idx`'s wake bit, honouring owner-pause masking: a masked
/// module's wake is diverted to the deferred store instead. Returns `true`
/// when the bit latched into `EVENT_WAKE_PENDING` (the caller may ring the
/// doorbell), `false` when it was diverted (the caller MUST NOT ring — the
/// suppressed doorbell is the §3.6 "no cross-domain leak" guarantee).
/// When no owner is paused the masking adds one relaxed-load guard before
/// the same `fetch_or`.
#[inline]
pub fn latch_module_wake(module_idx: usize) -> bool {
    if module_idx >= crate::kernel::boot::config::MAX_MODULES {
        return false;
    }
    if paused_owners_present() && module_wake_masked(module_idx) {
        defer_masked_wake(module_idx);
        return false;
    }
    EVENT_WAKE_PENDING[module_idx / 64].fetch_or(1u64 << (module_idx % 64), Ordering::Release);
    true
}

/// Test-only: latch a module's wake bit directly, as if an event owned by it
/// fired. Lets the multi-graph runner tests exercise the §6.5 "woken idle graph"
/// resumption path (RFC adaptive_tick_extra §7.4) without registering a real
/// event. Mirrors the wake-latch `event_signal` performs; a later
/// `take_wake_pending` consumes it identically.
pub fn signal_module_wake_for_test(module_idx: usize) {
    relatch_module_wake(module_idx);
}

/// Atomically read-and-clear the wake-pending bits for the modules in `mask`,
/// returning the cleared bits as a `ModuleMask`. The domain/owner-scoped
/// counterpart to `take_wake_pending` (which clears everything): a per-`(graph,
/// domain)` cooperative runner consumes only its own owners' wakes, so a one-shot
/// event wake is acted on exactly once and does not stay "sticky" (which would
/// pin an idle graph busy forever — notably on bcm2712, whose domain loop has no
/// global `take_wake_pending` drain). The returned mask lets the runner pass
/// `event_wake = true` for the *specific* modules that were woken (so a woken
/// module steps even when its step-period is not due), preserving normal
/// event-wake semantics. Bits outside `mask` are untouched.
pub fn take_wake_in_mask(mask: &ModuleMask) -> ModuleMask {
    let mw = mask.as_words();
    let mut out = [0u64; MODULE_MASK_WORDS];
    for ((atomic, m), o) in EVENT_WAKE_PENDING.iter().zip(mw.iter()).zip(out.iter_mut()) {
        if *m == 0 {
            continue;
        }
        let prev = atomic.fetch_and(!*m, Ordering::AcqRel);
        *o = prev & *m;
    }
    ModuleMask::from_words(out)
}

/// Release all events owned by a specific module. Called on module finish.
/// Note: Device providers (GPIO etc.) clean up their own bindings via
/// their own release_owned_by — this only frees event slots.
pub fn release_owned_by(module_idx: u8) {
    for slot in EVENT_SLOTS.iter() {
        if !slot.allocated.load(Ordering::Acquire) {
            continue;
        }
        if slot.owner.load(Ordering::Acquire) != module_idx {
            continue;
        }
        slot.signaled.store(false, Ordering::Release);
        slot.owner.store(0xFF, Ordering::Release);
        slot.allocated.store(false, Ordering::Release);
    }
}

/// Clear the owner-pause wake-masking state (mask, deferred wakes, count).
/// Called on graph rebuild (`prepare_graph`) — the owner table is reset
/// there (`reset_workloads`), so stale masks would suppress wakes for
/// reused module slots — and folded into [`reset_all`].
pub fn reset_pause_masking() {
    #[cfg(feature = "multitenant")]
    {
        for w in PAUSED_MODULES.iter() {
            w.store(0, Ordering::Release);
        }
        for w in PAUSED_DEFERRED_WAKES.iter() {
            w.store(0, Ordering::Release);
        }
        PAUSED_OWNER_COUNT.store(0, Ordering::Release);
    }
}

/// Clear all event slots. Called on graph teardown / reload.
/// Device providers must clear their own bindings before calling this.
pub fn reset_all() {
    for slot in EVENT_SLOTS.iter() {
        if slot.allocated.load(Ordering::Acquire) {
            slot.signaled.store(false, Ordering::Release);
            slot.owner.store(0xFF, Ordering::Release);
            slot.allocated.store(false, Ordering::Release);
        }
    }
    for w in EVENT_WAKE_PENDING.iter() {
        w.store(0, Ordering::Release);
    }
    reset_pause_masking();
}
