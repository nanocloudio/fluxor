//! Kernel event subsystem — signalable/pollable notification objects.
//!
//! Events are the universal wake mechanism for modules. An event is a
//! single-bit flag that can be signaled (from any context, including ISR)
//! and polled (non-blocking, clears on read).
//!
//! An event handle names its slot (`abi::kernel_abi::handle`): the slot's
//! generation moves on every claim, so a handle kept past its destroy names
//! nothing. Every op checks the caller owns the event.
//!
//! A doorbell is an event slot the kernel claims for the minter of a
//! signalling handle (`kernel::BIND_DOORBELL`): the provider rings it, the
//! minter is woken and its handle polls ready once. The doorbell is the
//! slot's handle word; ringing one whose handle closed rings nothing.
//!
//! The scheduler checks `EVENT_WAKE_PENDING` and steps only the affected
//! modules via a wake pass (`pass::run`), providing intra-tick wake response.

use portable_atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};

use crate::kernel::exec::scheduler::{ModuleId, NO_MODULE};

use crate::kernel::sys::errno;
use crate::kernel::sys::hal;
use crate::kernel::workload::bitmask::{ModuleMask, MODULE_MASK_WORDS};

/// Events held at once across all modules: the profile's static table, or
/// where the plan sizes it (Linux, bcm2712, RP) the plan's `events` pool
/// (`size`), which has no structural source and is its envelope entry or
/// default.
pub const MAX_EVENTS: usize =
    crate::kernel::config::static_slots(crate::abi::contracts::resource::POOL_EVENTS);

// ============================================================================
// Event slot
// ============================================================================

struct EventSlot {
    /// Whether this slot is allocated.
    allocated: AtomicBool,
    /// The signaled flag — set by signal(), cleared by poll().
    signaled: AtomicBool,
    /// Owning module index (below `scheduler::module_slots()`), or
    /// `NO_MODULE` if unowned.
    owner: AtomicU16,
    /// The generation a handle to this slot carries; moved on every claim.
    generation: AtomicU16,
    /// For a doorbell, the module provider that may ring it (`NO_MODULE`:
    /// the platform, which rings it directly). Unused for an event.
    ringer: AtomicU16,
}

impl EventSlot {
    const fn new() -> Self {
        Self {
            allocated: AtomicBool::new(false),
            signaled: AtomicBool::new(false),
            owner: AtomicU16::new(NO_MODULE),
            generation: AtomicU16::new(0),
            ringer: AtomicU16::new(NO_MODULE),
        }
    }

    fn free(&self) {
        self.signaled.store(false, Ordering::Release);
        self.owner.store(NO_MODULE, Ordering::Release);
        self.ringer.store(NO_MODULE, Ordering::Release);
        self.allocated.store(false, Ordering::Release);
    }
}

impl crate::kernel::ipc::handle::Native for EventSlot {
    fn live(&self) -> bool {
        self.allocated.load(Ordering::Acquire)
    }
    fn generation(&self) -> u16 {
        self.generation.load(Ordering::Acquire)
    }
    fn owner(&self) -> ModuleId {
        self.owner.load(Ordering::Acquire)
    }
}

/// The event contract's id: the contract field of every event handle.
const EVENT: u16 = crate::abi::registry::event::ID;

// ============================================================================
// Static state
// ============================================================================

static EVENT_SLOTS: crate::kernel::mem::table::Table<EventSlot, MAX_EVENTS> = crate::boot_table!(
    MAX_EVENTS,
    EventSlot::new(),
    crate::abi::contracts::resource::POOL_EVENTS
);

/// Size the event table to `n` slots, all live: events have no structural
/// source, so the plan's ceiling is the table.
///
/// # Safety
/// Boot or graph-preparation context: no reference into the table is live.
pub unsafe fn size(n: usize) -> Result<(), crate::kernel::mem::table::TableError> {
    EVENT_SLOTS.reserve(n)?;
    EVENT_SLOTS.grow(n)
}

/// The event table, sized from the plan's defaults when no plan has sized it.
fn slots() -> &'static [EventSlot] {
    EVENT_SLOTS.size_unplanned(|| {
        crate::kernel::sys::resource_ledger::ceiling(crate::abi::contracts::resource::POOL_EVENTS)
            as usize
    });
    &EVENT_SLOTS
}

/// One bit per module. Set when any owned event is signaled. Backed by
/// `MODULE_MASK_WORDS` atomics so it scales with `MAX_MODULES` beyond 64.
/// Scheduler reads + clears each word atomically.
static EVENT_WAKE_PENDING: [AtomicU64; MODULE_MASK_WORDS] =
    [const { AtomicU64::new(0) }; MODULE_MASK_WORDS];

// ── Owner pause wake masking ─────────────────────────────────────────
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
// `EVENT_WAKE_PENDING`, where the domain loop's per-pass sweep (or the
// woken-step guard) defers it. `owner_resume` clears the mask FIRST, then
// drains the deferred store — a concurrent signal lands in whichever
// store is live and is delivered either way.
//
// Default-off: `PAUSED_OWNER_COUNT == 0` short-circuits every check.

/// Modules whose wake delivery is masked (their owner is paused).
static PAUSED_MODULES: [AtomicU64; MODULE_MASK_WORDS] =
    [const { AtomicU64::new(0) }; MODULE_MASK_WORDS];
/// Wakes that arrived for masked modules; re-latched on resume.
static PAUSED_DEFERRED_WAKES: [AtomicU64; MODULE_MASK_WORDS] =
    [const { AtomicU64::new(0) }; MODULE_MASK_WORDS];
/// Number of currently paused owners — the default-off guard.
static PAUSED_OWNER_COUNT: portable_atomic::AtomicUsize = portable_atomic::AtomicUsize::new(0);

/// Default-off guard: true iff at least one owner is paused. One relaxed
/// load; every pause-aware check short-circuits on it.
#[inline]
pub fn paused_owners_present() -> bool {
    PAUSED_OWNER_COUNT.load(Ordering::Relaxed) != 0
}

/// True iff `module_idx`'s wake delivery is masked (its owner is paused).
/// Callers MUST short-circuit behind [`paused_owners_present`].
#[inline]
pub fn module_wake_masked(module_idx: usize) -> bool {
    module_idx < crate::kernel::exec::scheduler::committed_module_slots()
        && (PAUSED_MODULES[module_idx / 64].load(Ordering::Acquire) >> (module_idx % 64)) & 1 != 0
}

/// Divert a wake for a masked module into the deferred store.
#[inline]
pub fn defer_masked_wake(module_idx: usize) {
    if module_idx < crate::kernel::exec::scheduler::committed_module_slots() {
        PAUSED_DEFERRED_WAKES[module_idx / 64]
            .fetch_or(1u64 << (module_idx % 64), Ordering::Release);
    }
}

/// Divert an already-taken wake set into the deferred store (the domain loop's
/// per-pass straggler sweep for a paused graph).
pub fn defer_masked_wakes(mask: &ModuleMask) {
    for (atomic, w) in PAUSED_DEFERRED_WAKES.iter().zip(mask.as_words().iter()) {
        if *w != 0 {
            atomic.fetch_or(*w, Ordering::Release);
        }
    }
}

/// `owner_pause` half of wake masking: mark `mask`'s modules wake-masked and
/// bump the paused-owner count. Mask-then-check: callers sweep
/// already-latched bits AFTER this returns.
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

/// The event `handle` names, when it is live and the calling module's.
fn check_event_access(handle: i32) -> Result<&'static EventSlot, i32> {
    crate::kernel::ipc::handle::resolve_owned(
        slots(),
        EVENT,
        handle,
        crate::kernel::exec::scheduler::current_module_id(),
    )
    .map(|(_, s)| s)
}

/// Whether `handle` names a live event the calling module owns.
pub fn owned_by_caller(handle: i32) -> bool {
    check_event_access(handle).is_ok()
}

/// The live slot `handle` names, whoever owns it, from the committed table
/// alone (never sizes it): the interrupt-safe lookup.
#[inline]
fn committed_slot(handle: i32) -> Option<&'static EventSlot> {
    let (c, generation, idx) = crate::abi::kernel_abi::handle::decode(handle)?;
    let slot = EVENT_SLOTS.committed().get(idx as usize)?;
    (c == EVENT
        && slot.allocated.load(Ordering::Acquire)
        && slot.generation.load(Ordering::Acquire) == generation)
        .then_some(slot)
}

/// Claim a free slot for `owner` (and, for a doorbell, `ringer`): its handle.
fn claim(owner: ModuleId, ringer: ModuleId) -> i32 {
    use crate::abi::contracts::resource::POOL_EVENTS;
    use crate::kernel::sys::resource_ledger as ledger;
    if !ledger::enforced_allows(POOL_EVENTS, in_use_count() as u32 + 1) {
        ledger::deny(POOL_EVENTS);
        return errno::ENOSPC;
    }
    for (i, slot) in slots().iter().enumerate() {
        if slot
            .allocated
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            slot.signaled.store(false, Ordering::Release);
            slot.owner.store(owner, Ordering::Release);
            slot.ringer.store(ringer, Ordering::Release);
            let generation = slot.generation.load(Ordering::Relaxed).wrapping_add(1)
                & crate::abi::kernel_abi::handle::GEN_MASK;
            slot.generation.store(generation, Ordering::Release);
            return crate::abi::kernel_abi::handle::encode(EVENT, generation, i as u32);
        }
    }
    ledger::deny(POOL_EVENTS);
    errno::ENOSPC
}

// ============================================================================
// Core event operations
// ============================================================================

/// Create a new event owned by the currently executing module: its handle,
/// or a negative errno.
pub fn event_create() -> i32 {
    claim(
        crate::kernel::exec::scheduler::current_module_id(),
        NO_MODULE,
    )
}

/// Allocated slots — resource-ledger sample for `POOL_EVENTS`.
pub fn in_use_count() -> usize {
    slots()
        .iter()
        .filter(|s| s.allocated.load(Ordering::Relaxed))
        .count()
}

/// Signal an event the calling module owns.
///
/// Sets the signaled flag, marks the owning module for wake, and pokes
/// the scheduler signal so it can break out of its timer sleep.
pub fn event_signal(handle: i32) -> i32 {
    match check_event_access(handle) {
        Ok(slot) => {
            raise(slot);
            0
        }
        Err(e) => e,
    }
}

/// Set `slot` signaled and wake its owner.
///
/// Never inlined: interrupt context reaches it (`event_signal_from_isr`, a
/// platform's doorbell ring), and the `irq-neon-free` gate names its HAL
/// call as the IRQ path's indirect branch.
#[inline(never)]
fn raise(slot: &EventSlot) {
    slot.signaled.store(true, Ordering::Release);
    let owner = slot.owner.load(Ordering::Relaxed);
    if (owner as usize) < crate::kernel::exec::scheduler::committed_module_slots()
        && !latch_module_wake(owner as usize)
    {
        // Owner paused: wake deferred, doorbell suppressed.
        return;
    }
    hal::wake_scheduler();
}

/// Signal the event `handle` names from interrupt context (an IRQ bound with
/// `BIND_IRQ`, the fault monitor): no owner check, and a handle whose event
/// was destroyed signals nothing. Reads only the committed table.
///
/// Never inlined: it is a root of the `irq-neon-free` gate's walk.
#[inline(never)]
pub fn event_signal_from_isr(handle: i32) {
    if let Some(slot) = committed_slot(handle) {
        raise(slot);
    }
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

/// Non-destructive readiness of an event the calling module owns: the
/// event contract's `HANDLE_POLL`.
pub fn event_poll_ready(handle: i32, events: u32) -> i32 {
    match check_event_access(handle) {
        Ok(slot) => {
            if events & crate::abi::kernel_abi::poll::IN != 0
                && slot.signaled.load(Ordering::Acquire)
            {
                crate::abi::kernel_abi::poll::IN as i32
            } else {
                0
            }
        }
        Err(e) => e,
    }
}

/// Destroy an event and free its slot.
/// Only the owning module may destroy its events.
pub fn event_destroy(handle: i32) -> i32 {
    let slot = match check_event_access(handle) {
        Ok(s) => s,
        Err(e) => return e,
    };
    slot.free();
    0
}

// ============================================================================
// Doorbells
// ============================================================================

/// Claim a doorbell for `minter`, rung by `ringer` (a module provider) or by
/// the platform (`NO_MODULE`). Its word, or `ENOSPC` when the event pool is
/// spent.
pub fn doorbell_claim(minter: ModuleId, ringer: ModuleId) -> i32 {
    claim(minter, ringer)
}

/// Ring `doorbell` from the platform, in any context including an
/// interrupt handler: its minter's handle polls ready and the minter is
/// woken. A doorbell whose handle closed rings nothing. `false` when it
/// named no live doorbell.
#[inline(never)]
pub fn doorbell_ring(doorbell: i32) -> bool {
    match committed_slot(doorbell) {
        Some(slot) => {
            raise(slot);
            true
        }
        None => false,
    }
}

/// `DOORBELL_RING` from module `ringer`: 0, also for a doorbell whose handle
/// closed; `EACCES` when the doorbell was handed to another provider.
pub fn doorbell_ring_by(doorbell: i32, ringer: ModuleId) -> i32 {
    match committed_slot(doorbell) {
        Some(slot) if slot.ringer.load(Ordering::Acquire) == ringer => {
            raise(slot);
            0
        }
        Some(_) => errno::EACCES,
        None => 0,
    }
}

/// Whether `doorbell` rang since the last take, clearing it: a signalling
/// handle's `HANDLE_POLL`.
pub fn doorbell_take(doorbell: i32) -> bool {
    committed_slot(doorbell).is_some_and(|s| s.signaled.swap(false, Ordering::AcqRel))
}

/// Free `doorbell`; one already freed is left alone.
pub fn doorbell_release(doorbell: i32) {
    if let Some(slot) = committed_slot(doorbell) {
        slot.free();
    }
}

// ============================================================================
// Scheduler interface
// ============================================================================

/// Non-clearing peek at the wake-pending bitmask. Used by platforms
/// that pace with a spin loop (Linux `tick_us <= 200` path) to yield
/// the spin budget early when an event fires, without consuming the
/// bits — the next iteration's wake pass still takes them and runs the
/// woken modules.
#[inline]
pub fn wake_pending_nonzero() -> bool {
    EVENT_WAKE_PENDING
        .iter()
        .any(|w| w.load(Ordering::Acquire) != 0)
}

/// Non-clearing peek at the wake-pending bitmask, restricted to a set of
/// modules (a domain's modules). True iff any module in `mask` has a pending
/// event. The adaptive-tick pacer uses this so one domain's idle decision is
/// not coupled to a sibling domain's wake. Like `wake_pending_nonzero`, it
/// does NOT consume the bits — the next `take_wake_in_mask` still takes
/// them.
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
/// - the woken-step budget bound restores a
///   deferred module's bit — already consumed by the caller's
///   `take_wake_in_mask` — so the wake is not lost, and deliberately does
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
/// suppressed doorbell is what keeps a paused owner's wakes from leaking
/// across domains).
/// When no owner is paused the masking adds one relaxed-load guard before
/// the same `fetch_or`.
#[inline]
pub fn latch_module_wake(module_idx: usize) -> bool {
    if module_idx >= crate::kernel::exec::scheduler::committed_module_slots() {
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
/// fired. Lets the multi-graph pass tests exercise the woken-idle-graph
/// resumption path without registering a real event. Mirrors the
/// wake-latch `event_signal` performs; a later `take_wake_in_mask` consumes it
/// identically.
pub fn signal_module_wake_for_test(module_idx: usize) {
    relatch_module_wake(module_idx);
}

/// Atomically read-and-clear the wake-pending bits for the modules in `mask`,
/// returning the cleared bits as a `ModuleMask`: the only way wakes are taken.
/// A pass consumes only its own graph's or domain's wakes, so a one-shot event
/// wake is acted on exactly once, never by another domain's core, and does not
/// stay "sticky" (which would pin an idle graph busy). The returned mask lets
/// the pass give `event_wake = true` to the specific modules woken (a woken
/// module steps even when its period is not due). Bits outside `mask` are untouched.
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
pub fn release_owned_by(module_idx: ModuleId) {
    for slot in slots().iter() {
        if !slot.allocated.load(Ordering::Acquire) {
            continue;
        }
        if slot.owner.load(Ordering::Acquire) != module_idx {
            continue;
        }
        slot.free();
    }
}

/// Clear the owner-pause wake-masking state (mask, deferred wakes, count).
/// Called on graph rebuild (`prepare_graph`) — the owner table is reset
/// there (`reset_workloads`), so stale masks would suppress wakes for
/// reused module slots — and folded into [`reset_all`].
pub fn reset_pause_masking() {
    for w in PAUSED_MODULES.iter() {
        w.store(0, Ordering::Release);
    }
    for w in PAUSED_DEFERRED_WAKES.iter() {
        w.store(0, Ordering::Release);
    }
    PAUSED_OWNER_COUNT.store(0, Ordering::Release);
}

/// Clear all event slots. Called on graph teardown / reload.
/// Device providers must clear their own bindings before calling this.
pub fn reset_all() {
    for slot in slots().iter() {
        if slot.allocated.load(Ordering::Acquire) {
            slot.free();
        }
    }
    for w in EVENT_WAKE_PENDING.iter() {
        w.store(0, Ordering::Release);
    }
    reset_pause_masking();
}
