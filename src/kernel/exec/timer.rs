//! The `timer` execution mode: a domain's modules stepped at its fixed
//! cadence under the interrupt contract ([`super::interrupt`]).
//!
//! The module's standard `module_step(state)` is called directly from the
//! handler. On RP a hardware alarm interrupt on the domain's core runs
//! [`handler_on`] for that core's slots, at that core's period; on bcm2712
//! the module timer is polled ([`poll`]) by the domain loop of the `timer`
//! domain, or by a `tick` domain's loop when the `timer` domain has no core
//! of its own, and [`handler`] steps every slot.

use portable_atomic::{AtomicBool, AtomicU32, Ordering};

use super::interrupt::{
    bridge_row, claim_slot, enter, leave, InterruptMetrics, SlotLatch, MAX_BRIDGES,
};
use crate::kernel::exec::scheduler::{ModuleId, MAX_DOMAINS, NO_MODULE};
use crate::kernel::module::loader::ModuleStepFn;
use crate::kernel::sys::hal;

/// Maximum number of `timer` modules.
pub const MAX_TIMER_MODULES: usize = 4;

/// A single `timer` module slot.
#[repr(C)]
struct TimerSlot {
    /// Module step function pointer (same signature as cooperative modules).
    step_fn: ModuleStepFn,
    /// Module state pointer (allocated from state arena).
    state_ptr: *mut u8,
    /// Bridge indices this module reads from (input bridges).
    /// -1 = unused slot.
    in_bridges: [i8; MAX_BRIDGES],
    /// Bridge indices this module writes to (output bridges).
    /// -1 = unused slot.
    out_bridges: [i8; MAX_BRIDGES],
    /// Metrics for this module.
    metrics: InterruptMetrics,
    /// Module index in the scheduler.
    module_index: ModuleId,
    /// The core the module's domain runs on.
    core: u8,
    /// Dispatch state and latched outcome.
    latch: SlotLatch,
}

impl TimerSlot {
    const fn empty() -> Self {
        Self {
            step_fn: empty_step,
            state_ptr: core::ptr::null_mut(),
            in_bridges: [-1; MAX_BRIDGES],
            out_bridges: [-1; MAX_BRIDGES],
            metrics: InterruptMetrics::new(),
            module_index: NO_MODULE,
            core: 0,
            latch: SlotLatch::new(),
        }
    }
}

/// Placeholder step function for empty slots.
unsafe extern "C" fn empty_step(_state: *mut u8) -> i32 {
    crate::abi::kernel_abi::step_return::CONTINUE
}

/// `timer` module slots — accessed from the handler.
static mut SLOTS: [TimerSlot; MAX_TIMER_MODULES] =
    [const { TimerSlot::empty() }; MAX_TIMER_MODULES];

/// Number of claimed `timer` slots.
static mut COUNT: u8 = 0;

/// The module timer's period in microseconds (set when it starts).
static mut PERIOD_US: u32 = 0;

/// Each core's own period in microseconds, one entry for each core a domain
/// can run on: the shortest among the `timer` domains that core runs, 0 for
/// a core that runs none. A platform whose
/// cores each have a module-timer alarm arms each from its own entry.
static CORE_PERIOD_US: [AtomicU32; MAX_DOMAINS] = [const { AtomicU32::new(0) }; MAX_DOMAINS];

/// Whether the module timer is running.
pub static TIMER_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Cumulative handler runs.
static TICK_COUNT: AtomicU32 = AtomicU32::new(0);

/// Register a module for `timer` execution, or register it again after a
/// fault stopped its dispatch. The module's fault policy is read here:
/// under `Tolerate` a budget overrun is telemetry only.
///
/// Returns the slot index on success, or -1 if full.
///
/// Called on the scheduler thread. A slot is written only while the handler
/// does not dispatch it (inactive), and dispatch starts with the release of
/// its active flag.
pub fn register_module(
    step_fn: ModuleStepFn,
    state_ptr: *mut u8,
    module_index: ModuleId,
    core: u8,
    budget_cycles: u32,
    in_bridges: &[i8],
    out_bridges: &[i8],
) -> i32 {
    // SAFETY: scheduler-thread registration; the handler reads only the
    // count and active slots, and the slot written here is inactive until
    // `arm` releases it.
    unsafe {
        let slots_ptr = &raw mut SLOTS;
        let slots = &mut *slots_ptr;
        let count_ptr = &raw mut COUNT;
        let count = &mut *count_ptr;
        let held_by = |s: &TimerSlot| (!s.latch.is_active()).then_some(s.module_index);
        let Some(idx) = claim_slot(slots, count, held_by, module_index) else {
            log::error!("[timer] full ({MAX_TIMER_MODULES} slots)");
            return -1;
        };
        let slot = &mut slots[idx];
        if slot.module_index != module_index {
            slot.metrics = InterruptMetrics::new();
        }
        slot.step_fn = step_fn;
        slot.state_ptr = state_ptr;
        slot.module_index = module_index;
        slot.core = core;
        slot.metrics.budget_cycles = budget_cycles;
        slot.in_bridges = bridge_row(in_bridges);
        slot.out_bridges = bridge_row(out_bridges);
        slot.latch.arm(module_index);

        log::info!(
            "[timer] registered slot={idx} mod={module_index} core={core} budget={budget_cycles}cy"
        );
        idx as i32
    }
}

/// Clear every slot and the period.
///
/// # Safety
/// No handler may be stepping a slot: the module timer is stopped and
/// dispatch is closed (`interrupt::reset_all`).
pub(super) unsafe fn clear_slots() {
    let slots = &raw mut SLOTS;
    for slot in (*slots).iter_mut() {
        *slot = TimerSlot::empty();
    }
    COUNT = 0;
    PERIOD_US = 0;
    for p in CORE_PERIOD_US.iter() {
        p.store(0, Ordering::Release);
    }
    TIMER_ACTIVE.store(false, Ordering::Release);
    TICK_COUNT.store(0, Ordering::Release);
}

/// The `timer` handler — steps every registered `timer` module.
///
/// Called from the platform's module-timer interrupt, or its poll. Reads the
/// cycle counter before/after each module step for timing metrics. A step's
/// answer and budget check go to the slot's latch.
///
/// Sets `scheduler::current_module_index` to the slot's module index for
/// the duration of each step so the runtime EACCES gate
/// (`scheduler::deny_interrupt_mode_syscall`) fires correctly if the step
/// body inadvertently calls `provider_call` / `channel_read` /
/// `channel_write`. The original current-module pointer is restored after
/// the step so cooperative-thread state is left untouched.
///
/// # Safety
/// Called from interrupt context. Must not call any blocking or allocating
/// functions.
#[inline(never)]
pub unsafe fn handler() {
    step_slots(None);
}

/// The `timer` handler of one core: steps the registered modules whose
/// domain runs on `core`, and no other core's. For a platform that fires
/// each core's module timer on that core.
///
/// # Safety
/// As [`handler`]; called on `core`.
#[inline(never)]
pub unsafe fn handler_on(core: u8) {
    step_slots(Some(core));
}

/// Step every dispatching slot, or only those of `only`'s core.
///
/// # Safety
/// As [`handler`].
#[inline(always)]
unsafe fn step_slots(only: Option<u8>) {
    TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    if !enter() {
        return;
    }

    let count = COUNT as usize;
    let slots = &raw mut SLOTS;
    let saved_module = crate::kernel::exec::scheduler::current_module_index();
    for slot in (*slots).iter_mut().take(count) {
        if !slot.latch.is_active() || only.is_some_and(|core| slot.core != core) {
            continue;
        }

        crate::kernel::exec::scheduler::set_current_module(slot.module_index as usize);
        let before = hal::read_cycle_count();
        let rc = (slot.step_fn)(slot.state_ptr);
        let after = hal::read_cycle_count();
        let overrun = slot.metrics.record(after.wrapping_sub(before));
        let _ = slot.latch.settle(rc, overrun);
    }
    crate::kernel::exec::scheduler::set_current_module(saved_module);
    leave();
}

/// The metrics of slot `idx`, while it dispatches.
pub(super) fn slot_metrics(idx: usize) -> Option<InterruptMetrics> {
    // SAFETY: `InterruptMetrics` is `Copy` plain data; reading the snapshot
    // races with handler increments but each field is an aligned `u32`, and
    // the metrics are best-effort introspection.
    unsafe {
        let slots_ptr = &raw const SLOTS;
        let slots = &*slots_ptr;
        (idx < COUNT as usize && slots[idx].latch.is_active()).then(|| slots[idx].metrics)
    }
}

/// The number of claimed `timer` slots.
pub(super) fn count() -> u8 {
    // SAFETY: a u8 static; aligned read.
    unsafe { COUNT }
}

/// The bridges of `module_index`'s dispatching slot.
pub(super) fn bridge_slots(
    module_index: ModuleId,
) -> Option<([i8; MAX_BRIDGES], [i8; MAX_BRIDGES])> {
    // SAFETY: the slot table is written only by scheduler-thread
    // registration; this is a shared read of plain-data fields.
    unsafe {
        let slots_ptr = &raw const SLOTS;
        let slots = &*slots_ptr;
        slots
            .iter()
            .take(COUNT as usize)
            .find(|s| s.latch.is_active() && s.module_index == module_index)
            .map(|s| (s.in_bridges, s.out_bridges))
    }
}

/// Call `f` with each claimed slot's latch and module.
pub(super) fn each_latch(mut f: impl FnMut(&SlotLatch, ModuleId)) {
    // SAFETY: scheduler-thread read; the latch fields are atomics, and the
    // `module_index` of a latched slot is written only by registration,
    // which a latched (inactive) slot awaits.
    unsafe {
        let slots_ptr = &raw const SLOTS;
        let slots = &*slots_ptr;
        for slot in slots.iter().take(COUNT as usize) {
            f(&slot.latch, slot.module_index);
        }
    }
}

/// Cumulative handler runs.
pub fn ticks() -> u32 {
    TICK_COUNT.load(Ordering::Relaxed)
}

/// The module timer's period in microseconds.
pub fn period_us() -> u32 {
    // SAFETY: a u32 static; aligned read.
    unsafe { PERIOD_US }
}

/// Core `core`'s own period in microseconds; 0 when it runs no `timer`
/// domain.
pub fn core_period_us(core: usize) -> u32 {
    CORE_PERIOD_US
        .get(core)
        .map_or(0, |p| p.load(Ordering::Acquire))
}

/// Set core `core`'s own period, before [`start`]: the shortest among the
/// `timer` domains it runs.
pub fn set_core_period_us(core: usize, period_us: u32) {
    if let Some(p) = CORE_PERIOD_US.get(core) {
        p.store(period_us, Ordering::Release);
    }
}

/// Set the module timer's period in microseconds (called by platform start).
pub fn set_period_us(period_us: u32) {
    // SAFETY: called during platform start before the timer becomes active;
    // the active flag is set after this write.
    unsafe {
        PERIOD_US = period_us;
    }
}

/// Start the module timer with the given period in microseconds.
pub fn start(period_us: u32) {
    if period_us == 0 {
        return;
    }
    hal::module_timer_init(); // Ensure cycle counter is enabled
    set_period_us(period_us);
    hal::module_timer_start(period_us);
    log::info!("[timer] started period={period_us}us");
}

/// Stop the module timer.
pub fn stop() {
    hal::module_timer_stop();
}

/// Fire the module timer if its period has elapsed, on a platform without a
/// usable alarm (no-op on Cortex-M, whose alarm interrupt fires it).
#[inline]
pub fn poll() {
    hal::module_timer_poll();
}
