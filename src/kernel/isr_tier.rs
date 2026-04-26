//! ISR Execution Tiers — Tier 1b (shared-core timer ISR) and Tier 2 (IRQ-owned).
//!
//! # Architecture
//!
//! Fluxor modules execute in one of four tiers:
//!
//! - **Tier 0** (default): Cooperative 1ms tick in the main scheduler loop.
//! - **Tier 1a**: Fast cooperative tick (configurable sub-ms, same context as Tier 0).
//! - **Tier 1b**: Timer ISR — modules stepped from a periodic hardware interrupt.
//!   Low-latency, deterministic timing. Modules can ONLY use bridge channels.
//! - **Tier 2**: IRQ-owned — each module bound to a specific hardware IRQ.
//!   Module's `isr_entry` called directly from the IRQ handler.
//!
//! ## Constraints
//!
//! ISR-tier modules (1b and 2) communicate exclusively via bridge channels.
//! No `provider_call`, no `channel_read` / `channel_write`, no heap
//! operations. The ISR handler calls the module's step/entry function
//! directly — no syscall dispatch overhead.
//!
//! ## Platform backends
//!
//! Platform-specific timer setup and ISR vectors are in the HAL layer.
//! The HAL calls `isr_tier1b_handler()` from the timer ISR.
//!
//! ## Cycle budgeting
//!
//! Each ISR module declares a cycle budget. The handler measures actual cycles
//! and tracks overruns. The ISR_METRICS syscall (0x0CE8) exposes per-module stats.

use portable_atomic::{AtomicBool, AtomicU32, Ordering};

use crate::kernel::hal;
use crate::kernel::loader::ModuleStepFn;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of Tier 1b modules (timer ISR).
pub const MAX_ISR_MODULES: usize = 4;

/// Maximum number of Tier 2 modules (IRQ-owned).
pub const MAX_ISR_T2_MODULES: usize = 4;

/// Maximum number of bridge connections per ISR module.
const MAX_ISR_BRIDGES: usize = 4;

// ============================================================================
// Tier 1b — Timer ISR modules
// ============================================================================

/// Per-module metrics collected in ISR context.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IsrMetrics {
    /// Total cycles consumed across all invocations (low 32 bits).
    pub total_cycles_lo: u32,
    /// Total cycles consumed across all invocations (high 32 bits).
    pub total_cycles_hi: u32,
    /// Maximum cycles in a single invocation.
    pub max_cycles: u32,
    /// Total number of invocations.
    pub invocations: u32,
    /// Number of invocations that exceeded the declared cycle budget.
    pub overruns: u32,
    /// Declared cycle budget per invocation.
    pub budget_cycles: u32,
}

impl IsrMetrics {
    const fn new() -> Self {
        Self {
            total_cycles_lo: 0,
            total_cycles_hi: 0,
            max_cycles: 0,
            invocations: 0,
            overruns: 0,
            budget_cycles: 0,
        }
    }

    /// Add a cycle measurement.
    #[inline]
    fn record(&mut self, cycles: u32) {
        // 64-bit add using two 32-bit halves (no 64-bit ops in ISR)
        let new_lo = self.total_cycles_lo.wrapping_add(cycles);
        if new_lo < self.total_cycles_lo {
            self.total_cycles_hi = self.total_cycles_hi.wrapping_add(1);
        }
        self.total_cycles_lo = new_lo;
        if cycles > self.max_cycles {
            self.max_cycles = cycles;
        }
        self.invocations = self.invocations.wrapping_add(1);
        if cycles > self.budget_cycles && self.budget_cycles > 0 {
            self.overruns = self.overruns.wrapping_add(1);
        }
    }
}

/// A single Tier 1b ISR module slot.
///
/// The module's standard `module_step(state)` is called directly from the
/// timer ISR. The module must only use bridge channels for I/O.
#[repr(C)]
struct IsrModule {
    /// Module step function pointer (same signature as cooperative modules).
    step_fn: ModuleStepFn,
    /// Module state pointer (allocated from state arena).
    state_ptr: *mut u8,
    /// Bridge indices this module reads from (input bridges).
    /// -1 = unused slot.
    in_bridges: [i8; MAX_ISR_BRIDGES],
    /// Bridge indices this module writes to (output bridges).
    /// -1 = unused slot.
    out_bridges: [i8; MAX_ISR_BRIDGES],
    /// Metrics for this module.
    metrics: IsrMetrics,
    /// Module index in the main scheduler (for diagnostics).
    module_index: u8,
    /// Whether this slot is active.
    active: bool,
}

impl IsrModule {
    const fn empty() -> Self {
        Self {
            step_fn: empty_step,
            state_ptr: core::ptr::null_mut(),
            in_bridges: [-1; MAX_ISR_BRIDGES],
            out_bridges: [-1; MAX_ISR_BRIDGES],
            metrics: IsrMetrics::new(),
            module_index: 0xFF,
            active: false,
        }
    }
}

/// Placeholder step function for empty slots.
unsafe extern "C" fn empty_step(_state: *mut u8) -> i32 {
    0 // StepOutcome::Continue
}

// ============================================================================
// Tier 2 — IRQ-owned modules
// ============================================================================

/// ISR-specific init function type.
/// Called once during setup (non-ISR context) to initialize ISR-tier state.
pub type ModuleIsrInitFn =
    unsafe extern "C" fn(state: *mut u8, syscalls: *const crate::abi::SyscallTable) -> i32;

/// ISR-specific entry function type.
/// Called from the IRQ handler. Returns i32 status (0 = ok, <0 = error).
pub type ModuleIsrEntryFn = unsafe extern "C" fn(state: *mut u8) -> i32;

/// A single Tier 2 ISR module slot.
#[repr(C)]
struct IsrModuleTier2 {
    /// ISR entry function pointer.
    isr_entry: ModuleIsrEntryFn,
    /// Module state pointer.
    state_ptr: *mut u8,
    /// Hardware IRQ number this module handles.
    irq_number: u16,
    /// Bridge indices for input.
    in_bridges: [i8; MAX_ISR_BRIDGES],
    /// Bridge indices for output.
    out_bridges: [i8; MAX_ISR_BRIDGES],
    /// Metrics for this module.
    metrics: IsrMetrics,
    /// Module index in the main scheduler (for diagnostics).
    module_index: u8,
    /// Whether this slot is active.
    active: bool,
    /// Whether this module uses FPU (affects stacking overhead on Cortex-M33).
    uses_fpu: bool,
}

impl IsrModuleTier2 {
    const fn empty() -> Self {
        Self {
            isr_entry: empty_isr_entry,
            state_ptr: core::ptr::null_mut(),
            irq_number: 0xFFFF,
            in_bridges: [-1; MAX_ISR_BRIDGES],
            out_bridges: [-1; MAX_ISR_BRIDGES],
            metrics: IsrMetrics::new(),
            module_index: 0xFF,
            active: false,
            uses_fpu: false,
        }
    }
}

/// Placeholder ISR entry for empty slots.
unsafe extern "C" fn empty_isr_entry(_state: *mut u8) -> i32 {
    0
}

// ============================================================================
// Global ISR State
// ============================================================================

/// Tier 1b module slots — accessed from timer ISR.
static mut ISR_SLOTS: [IsrModule; MAX_ISR_MODULES] =
    [const { IsrModule::empty() }; MAX_ISR_MODULES];

/// Number of active Tier 1b modules.
static mut ISR_COUNT: u8 = 0;

/// Tier 2 module slots — accessed from IRQ handlers.
static mut ISR_T2_SLOTS: [IsrModuleTier2; MAX_ISR_T2_MODULES] =
    [const { IsrModuleTier2::empty() }; MAX_ISR_T2_MODULES];

/// Number of active Tier 2 modules.
static mut ISR_T2_COUNT: u8 = 0;

/// Tier 1b period in microseconds (set during init).
static mut TIER1B_PERIOD_US: u32 = 0;

/// Whether the Tier 1b timer is running.
pub static TIER1B_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Global overrun flag — set if any ISR module exceeds total budget.
static TIER1B_OVERRUN: AtomicBool = AtomicBool::new(false);

/// Cumulative total ISR ticks processed.
static TIER1B_TICK_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// Registration API (called from scheduler during graph setup)
// ============================================================================

/// Register a module for Tier 1b (timer ISR) execution.
///
/// Returns the slot index on success, or -1 if full.
///
/// # Safety
/// - `step_fn` must be a valid function pointer for the module's lifetime
/// - `state_ptr` must be a valid state buffer for the module's lifetime
/// - Must be called before `start_tier1b()` or with ISR disabled
pub fn register_tier1b_module(
    step_fn: ModuleStepFn,
    state_ptr: *mut u8,
    module_index: u8,
    budget_cycles: u32,
    in_bridges: &[i8],
    out_bridges: &[i8],
) -> i32 {
    unsafe {
        let count = ISR_COUNT as usize;
        if count >= MAX_ISR_MODULES {
            log::error!("[isr] tier1b full ({} slots)", MAX_ISR_MODULES);
            return -1;
        }

        let slot = &mut ISR_SLOTS[count];
        slot.step_fn = step_fn;
        slot.state_ptr = state_ptr;
        slot.module_index = module_index;
        slot.metrics = IsrMetrics::new();
        slot.metrics.budget_cycles = budget_cycles;

        // Copy bridge indices
        for i in 0..MAX_ISR_BRIDGES {
            slot.in_bridges[i] = if i < in_bridges.len() {
                in_bridges[i]
            } else {
                -1
            };
            slot.out_bridges[i] = if i < out_bridges.len() {
                out_bridges[i]
            } else {
                -1
            };
        }

        slot.active = true;
        ISR_COUNT = count as u8 + 1;

        log::info!(
            "[isr] tier1b registered slot={} mod={} budget={}cy",
            count,
            module_index,
            budget_cycles
        );
        count as i32
    }
}

/// Register a module for Tier 2 (IRQ-owned) execution.
///
/// Tier-2 ISR module registration parameters.
pub struct Tier2Registration<'a> {
    pub isr_entry: ModuleIsrEntryFn,
    pub state_ptr: *mut u8,
    pub irq_number: u16,
    pub module_index: u8,
    pub budget_cycles: u32,
    pub uses_fpu: bool,
    pub in_bridges: &'a [i8],
    pub out_bridges: &'a [i8],
}

/// Returns the slot index on success, or -1 if full.
///
/// # Safety
/// - `reg.isr_entry` must be a valid function pointer for the module's lifetime
/// - `reg.state_ptr` must be a valid state buffer for the module's lifetime
/// - Must be called before enabling the IRQ
pub fn register_tier2_module(reg: Tier2Registration<'_>) -> i32 {
    unsafe {
        let count = ISR_T2_COUNT as usize;
        if count >= MAX_ISR_T2_MODULES {
            log::error!("[isr] tier2 full ({} slots)", MAX_ISR_T2_MODULES);
            return -1;
        }

        let slot = &mut ISR_T2_SLOTS[count];
        slot.isr_entry = reg.isr_entry;
        slot.state_ptr = reg.state_ptr;
        slot.irq_number = reg.irq_number;
        slot.module_index = reg.module_index;
        slot.uses_fpu = reg.uses_fpu;
        slot.metrics = IsrMetrics::new();
        slot.metrics.budget_cycles = reg.budget_cycles;

        for i in 0..MAX_ISR_BRIDGES {
            slot.in_bridges[i] = if i < reg.in_bridges.len() {
                reg.in_bridges[i]
            } else {
                -1
            };
            slot.out_bridges[i] = if i < reg.out_bridges.len() {
                reg.out_bridges[i]
            } else {
                -1
            };
        }

        slot.active = true;
        ISR_T2_COUNT = count as u8 + 1;

        log::info!(
            "[isr] tier2 registered slot={} mod={} irq={} budget={}cy fpu={}",
            count,
            reg.module_index,
            reg.irq_number,
            reg.budget_cycles,
            reg.uses_fpu
        );
        count as i32
    }
}

/// Reset all ISR state (called on graph reconfigure).
pub fn reset_all() {
    stop_tier1b();
    unsafe {
        let slots = &raw mut ISR_SLOTS;
        for slot in (*slots).iter_mut() {
            *slot = IsrModule::empty();
        }
        ISR_COUNT = 0;
        let t2_slots = &raw mut ISR_T2_SLOTS;
        for slot in (*t2_slots).iter_mut() {
            *slot = IsrModuleTier2::empty();
        }
        ISR_T2_COUNT = 0;
        TIER1B_PERIOD_US = 0;
    }
    TIER1B_ACTIVE.store(false, Ordering::Release);
    TIER1B_OVERRUN.store(false, Ordering::Release);
    TIER1B_TICK_COUNT.store(0, Ordering::Release);
}

// ============================================================================
// Tier 1b ISR Handler
// ============================================================================

/// Core Tier 1b handler — steps all registered ISR modules.
///
/// Called from the platform-specific timer ISR. Reads cycle counter before/after
/// each module step for timing metrics.
///
/// # Safety
/// Called from ISR context. Must not call any blocking or allocating functions.
#[inline(never)]
pub unsafe fn isr_tier1b_handler() {
    TIER1B_TICK_COUNT.fetch_add(1, Ordering::Relaxed);

    let count = ISR_COUNT as usize;
    let slots = &raw mut ISR_SLOTS;
    for slot in (*slots).iter_mut().take(count) {
        if !slot.active {
            continue;
        }

        let before = hal::read_cycle_count();
        let _rc = (slot.step_fn)(slot.state_ptr);
        let after = hal::read_cycle_count();
        let elapsed = after.wrapping_sub(before);

        slot.metrics.record(elapsed);
    }
}

// ============================================================================
// Tier 2 ISR Trampoline
// ============================================================================

/// Tier 2 trampoline — dispatches to the correct module based on IRQ number.
///
/// Called from a generic ISR handler. Looks up the Tier 2 module registered
/// for the given IRQ and calls its `isr_entry` function.
///
/// Returns 0 if handled, -1 if no module registered for this IRQ.
///
/// # Safety
/// Called from ISR context.
pub unsafe fn isr_tier2_trampoline(irq_number: u16) -> i32 {
    let count = ISR_T2_COUNT as usize;
    let slots = &raw mut ISR_T2_SLOTS;
    for slot in (*slots).iter_mut().take(count) {
        if !slot.active || slot.irq_number != irq_number {
            continue;
        }

        let before = hal::read_cycle_count();
        let rc = (slot.isr_entry)(slot.state_ptr);
        let after = hal::read_cycle_count();

        let mut elapsed = after.wrapping_sub(before);
        // Account for FPU lazy stacking overhead on Cortex-M33
        if slot.uses_fpu {
            // FPU context save: 33 extra cycles on Cortex-M33
            elapsed = elapsed.saturating_add(33);
        }

        slot.metrics.record(elapsed);
        return rc;
    }
    -1 // No module found for this IRQ
}

// ============================================================================
// Metrics Query (from Tier 0 context via syscall)
// ============================================================================

/// Query ISR metrics for a given tier and slot.
///
/// `tier`: 1 = Tier 1b, 2 = Tier 2
/// `slot`: slot index within the tier
///
/// Returns the metrics struct, or None if invalid tier/slot.
pub fn query_metrics(tier: u8, slot: u8) -> Option<IsrMetrics> {
    unsafe {
        match tier {
            1 => {
                let idx = slot as usize;
                if idx < ISR_COUNT as usize && ISR_SLOTS[idx].active {
                    Some(ISR_SLOTS[idx].metrics)
                } else {
                    None
                }
            }
            2 => {
                let idx = slot as usize;
                if idx < ISR_T2_COUNT as usize && ISR_T2_SLOTS[idx].active {
                    Some(ISR_T2_SLOTS[idx].metrics)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Query the number of registered ISR modules.
/// Returns (tier1b_count, tier2_count).
pub fn module_counts() -> (u8, u8) {
    unsafe { (ISR_COUNT, ISR_T2_COUNT) }
}

/// Return the cumulative Tier 1b tick count.
pub fn tier1b_ticks() -> u32 {
    TIER1B_TICK_COUNT.load(Ordering::Relaxed)
}

/// Check and clear the Tier 1b overrun flag.
pub fn check_and_clear_overrun() -> bool {
    TIER1B_OVERRUN.swap(false, Ordering::AcqRel)
}

/// Get the Tier 1b period in microseconds.
pub fn tier1b_period_us() -> u32 {
    unsafe { TIER1B_PERIOD_US }
}

/// Set the Tier 1b period in microseconds (called by platform start).
pub fn set_tier1b_period_us(period_us: u32) {
    unsafe {
        TIER1B_PERIOD_US = period_us;
    }
}

// ============================================================================
// Platform backend entry points (called by HAL implementations)
// ============================================================================

/// Platform start implementation — called by HAL after hardware timer setup.
pub fn platform_start(period_us: u32) {
    hal::isr_tier_start(period_us);
}

/// Platform stop implementation — called by HAL.
pub fn platform_stop() {
    hal::isr_tier_stop();
}

// ============================================================================
// Platform-agnostic API
// ============================================================================

/// Initialize ISR tier hardware (DWT cycle counter, etc).
pub fn init() {
    hal::isr_tier_init();
}

/// Start the Tier 1b periodic timer with the given period in microseconds.
pub fn start_tier1b(period_us: u32) {
    if period_us == 0 {
        return;
    }
    init(); // Ensure cycle counter is enabled
    set_tier1b_period_us(period_us);
    hal::isr_tier_start(period_us);
    log::info!("[isr] tier1b started period={}us", period_us);
}

/// Stop the Tier 1b periodic timer.
pub fn stop_tier1b() {
    hal::isr_tier_stop();
}

/// Poll Tier 1b from main loop (aarch64 only — no-op on Cortex-M).
#[inline]
pub fn poll_tier1b() {
    hal::isr_tier_poll();
}

// ============================================================================
// ISR_METRICS Syscall Handler (0x0CE8)
// ============================================================================

/// Handle the ISR_METRICS syscall.
///
/// arg layout:
///   [0]: tier (1 = Tier 1b, 2 = Tier 2)
///   [1]: slot index
///
/// On success, writes IsrMetrics (24 bytes) to arg buffer.
/// Returns bytes written on success, or negative errno.
pub fn isr_metrics_dispatch(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 2 {
        return -crate::kernel::errno::EINVAL;
    }

    let tier = unsafe { *arg };
    let slot = unsafe { *arg.add(1) };

    match query_metrics(tier, slot) {
        Some(metrics) => {
            let out_size = core::mem::size_of::<IsrMetrics>();
            if arg_len < out_size {
                return -crate::kernel::errno::EINVAL;
            }
            unsafe {
                let src = &metrics as *const IsrMetrics as *const u8;
                core::ptr::copy_nonoverlapping(src, arg, out_size);
            }
            out_size as i32
        }
        None => -crate::kernel::errno::EINVAL,
    }
}
