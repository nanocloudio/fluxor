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
//! No `dev_call`, no `channel_read`/`channel_write`, no heap operations.
//! The ISR handler calls the module's step/entry function directly — no syscall
//! dispatch overhead.
//!
//! ## Platform backends
//!
//! - **RP2350**: TIMER1 alarm 1 for Tier 1b (alarm 0 is step_guard).
//! - **RP2040**: TIMER alarm 2 for Tier 1b (alarm 3 is step_guard, 0-1 are Embassy).
//! - **BCM2712**: Generic timer compare value for Tier 1b periodic interrupt.
//!
//! ## Cycle budgeting
//!
//! Each ISR module declares a cycle budget. The handler measures actual cycles
//! and tracks overruns. The ISR_METRICS syscall (0x0CE8) exposes per-module stats.

use portable_atomic::{AtomicBool, AtomicU32, Ordering};

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
pub type ModuleIsrInitFn = unsafe extern "C" fn(state: *mut u8, syscalls: *const crate::abi::SyscallTable) -> i32;

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
static mut ISR_SLOTS: [IsrModule; MAX_ISR_MODULES] = [const { IsrModule::empty() }; MAX_ISR_MODULES];

/// Number of active Tier 1b modules.
static mut ISR_COUNT: u8 = 0;

/// Tier 2 module slots — accessed from IRQ handlers.
static mut ISR_T2_SLOTS: [IsrModuleTier2; MAX_ISR_T2_MODULES] = [const { IsrModuleTier2::empty() }; MAX_ISR_T2_MODULES];

/// Number of active Tier 2 modules.
static mut ISR_T2_COUNT: u8 = 0;

/// Tier 1b period in microseconds (set during init).
static mut TIER1B_PERIOD_US: u32 = 0;

/// Whether the Tier 1b timer is running.
static TIER1B_ACTIVE: AtomicBool = AtomicBool::new(false);

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
            slot.in_bridges[i] = if i < in_bridges.len() { in_bridges[i] } else { -1 };
            slot.out_bridges[i] = if i < out_bridges.len() { out_bridges[i] } else { -1 };
        }

        slot.active = true;
        ISR_COUNT = count as u8 + 1;

        log::info!("[isr] tier1b registered slot={} mod={} budget={}cy",
            count, module_index, budget_cycles);
        count as i32
    }
}

/// Register a module for Tier 2 (IRQ-owned) execution.
///
/// Returns the slot index on success, or -1 if full.
///
/// # Safety
/// - `isr_entry` must be a valid function pointer for the module's lifetime
/// - `state_ptr` must be a valid state buffer for the module's lifetime
/// - Must be called before enabling the IRQ
pub fn register_tier2_module(
    isr_entry: ModuleIsrEntryFn,
    state_ptr: *mut u8,
    irq_number: u16,
    module_index: u8,
    budget_cycles: u32,
    uses_fpu: bool,
    in_bridges: &[i8],
    out_bridges: &[i8],
) -> i32 {
    unsafe {
        let count = ISR_T2_COUNT as usize;
        if count >= MAX_ISR_T2_MODULES {
            log::error!("[isr] tier2 full ({} slots)", MAX_ISR_T2_MODULES);
            return -1;
        }

        let slot = &mut ISR_T2_SLOTS[count];
        slot.isr_entry = isr_entry;
        slot.state_ptr = state_ptr;
        slot.irq_number = irq_number;
        slot.module_index = module_index;
        slot.uses_fpu = uses_fpu;
        slot.metrics = IsrMetrics::new();
        slot.metrics.budget_cycles = budget_cycles;

        for i in 0..MAX_ISR_BRIDGES {
            slot.in_bridges[i] = if i < in_bridges.len() { in_bridges[i] } else { -1 };
            slot.out_bridges[i] = if i < out_bridges.len() { out_bridges[i] } else { -1 };
        }

        slot.active = true;
        ISR_T2_COUNT = count as u8 + 1;

        log::info!("[isr] tier2 registered slot={} mod={} irq={} budget={}cy fpu={}",
            count, module_index, irq_number, budget_cycles, uses_fpu);
        count as i32
    }
}

/// Reset all ISR state (called on graph reconfigure).
pub fn reset_all() {
    stop_tier1b();
    unsafe {
        for i in 0..MAX_ISR_MODULES {
            ISR_SLOTS[i] = IsrModule::empty();
        }
        ISR_COUNT = 0;
        for i in 0..MAX_ISR_T2_MODULES {
            ISR_T2_SLOTS[i] = IsrModuleTier2::empty();
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
unsafe fn isr_tier1b_handler() {
    TIER1B_TICK_COUNT.fetch_add(1, Ordering::Relaxed);

    let count = ISR_COUNT as usize;
    for i in 0..count {
        let slot = &mut ISR_SLOTS[i];
        if !slot.active {
            continue;
        }

        let before = read_cycle_count();
        let _rc = (slot.step_fn)(slot.state_ptr);
        let after = read_cycle_count();
        let elapsed = after.wrapping_sub(before);

        slot.metrics.record(elapsed);
    }
}

/// Read hardware cycle counter (platform-specific).
#[inline(always)]
fn read_cycle_count() -> u32 {
    #[cfg(feature = "rp")]
    {
        // Cortex-M DWT cycle counter (CYCCNT)
        // Must be enabled first — see init().
        unsafe { core::ptr::read_volatile(0xE000_1004 as *const u32) }
    }
    #[cfg(feature = "chip-bcm2712")]
    {
        // aarch64: use PMCCNTR_EL0 (performance monitor cycle counter)
        // Fallback to CNTPCT_EL0 if PMU not available.
        let val: u64;
        unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) val) };
        val as u32
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
    for i in 0..count {
        let slot = &mut ISR_T2_SLOTS[i];
        if !slot.active || slot.irq_number != irq_number {
            continue;
        }

        let before = read_cycle_count();
        let rc = (slot.isr_entry)(slot.state_ptr);
        let after = read_cycle_count();

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

// ============================================================================
// RP2350 backend: TIMER1 alarm 1 (periodic)
// ============================================================================

#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
mod rp2350_backend {
    use super::*;
    use embassy_rp::pac;

    fn timer1() -> pac::timer::Timer {
        pac::TIMER1
    }

    /// Start the Tier 1b periodic timer.
    pub fn start(period_us: u32) {
        unsafe { super::TIER1B_PERIOD_US = period_us; }

        let t = timer1();
        // Clear and configure alarm 1
        t.inte().modify(|w| w.set_alarm(1, false));
        t.intr().write(|w| w.set_alarm(1, true));

        // Set first alarm
        let now_lo = t.timelr().read();
        let target = now_lo.wrapping_add(period_us);
        t.alarm(1).write_value(target);
        t.inte().modify(|w| w.set_alarm(1, true));

        // Enable TIMER1_IRQ_1 in NVIC
        unsafe {
            let nvic = &*cortex_m::peripheral::NVIC::PTR;
            // TIMER1_IRQ_1 on RP2350 is interrupt 5
            // (TIMER1_IRQ_0=4, TIMER1_IRQ_1=5)
            const TIMER1_IRQ_1: u16 = 5;
            nvic.iser[0].write(1 << TIMER1_IRQ_1);
        }

        super::TIER1B_ACTIVE.store(true, Ordering::Release);
    }

    /// Stop the Tier 1b periodic timer.
    pub fn stop() {
        let t = timer1();
        t.inte().modify(|w| w.set_alarm(1, false));
        t.intr().write(|w| w.set_alarm(1, true));
        super::TIER1B_ACTIVE.store(false, Ordering::Release);
    }

    /// Timer1 alarm 1 ISR — periodic Tier 1b handler.
    pub fn on_timer_irq() {
        let t = timer1();
        // Acknowledge interrupt
        t.intr().write(|w| w.set_alarm(1, true));

        // Re-arm for next period (before stepping modules for minimal jitter)
        let period = unsafe { super::TIER1B_PERIOD_US };
        if period > 0 && super::TIER1B_ACTIVE.load(Ordering::Acquire) {
            let now_lo = t.timelr().read();
            let target = now_lo.wrapping_add(period);
            t.alarm(1).write_value(target);
        } else {
            // Disable if no longer active
            t.inte().modify(|w| w.set_alarm(1, false));
            return;
        }

        // Step all Tier 1b modules
        unsafe { isr_tier1b_handler(); }
    }
}

// ============================================================================
// RP2040 backend: TIMER alarm 2 (periodic)
// ============================================================================

#[cfg(feature = "chip-rp2040")]
mod rp2040_backend {
    use super::*;
    use embassy_rp::pac;

    fn timer() -> pac::timer::Timer {
        pac::TIMER
    }

    /// Start the Tier 1b periodic timer.
    pub fn start(period_us: u32) {
        unsafe { super::TIER1B_PERIOD_US = period_us; }

        let t = timer();
        t.inte().modify(|w| w.set_alarm(2, false));
        t.intr().write(|w| w.set_alarm(2, true));

        let now_lo = t.timelr().read();
        let target = now_lo.wrapping_add(period_us);
        t.alarm(2).write_value(target);
        t.inte().modify(|w| w.set_alarm(2, true));

        // Enable TIMER_IRQ_2 in NVIC (IRQ 2 on RP2040)
        unsafe {
            let nvic = &*cortex_m::peripheral::NVIC::PTR;
            const TIMER_IRQ_2: u16 = 2;
            nvic.iser[0].write(1 << TIMER_IRQ_2);
        }

        super::TIER1B_ACTIVE.store(true, Ordering::Release);
    }

    /// Stop the Tier 1b periodic timer.
    pub fn stop() {
        let t = timer();
        t.inte().modify(|w| w.set_alarm(2, false));
        t.intr().write(|w| w.set_alarm(2, true));
        super::TIER1B_ACTIVE.store(false, Ordering::Release);
    }

    /// Timer alarm 2 ISR.
    pub fn on_timer_irq() {
        let t = timer();
        t.intr().write(|w| w.set_alarm(2, true));

        // Re-arm for next period
        let period = unsafe { super::TIER1B_PERIOD_US };
        if period > 0 && super::TIER1B_ACTIVE.load(Ordering::Acquire) {
            let now_lo = t.timelr().read();
            let target = now_lo.wrapping_add(period);
            t.alarm(2).write_value(target);
        } else {
            t.inte().modify(|w| w.set_alarm(2, false));
            return;
        }

        unsafe { isr_tier1b_handler(); }
    }
}

// ============================================================================
// BCM2712/aarch64 backend: software timer emulation
// ============================================================================

#[cfg(feature = "chip-bcm2712")]
mod bcm2712_backend {
    use super::*;

    /// Last Tier 1b invocation timestamp (counter ticks).
    static mut LAST_TICK: u64 = 0;
    /// Period in counter ticks.
    static mut PERIOD_TICKS: u64 = 0;

    fn read_cntpct() -> u64 {
        let val: u64;
        unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) val) };
        val
    }

    fn counter_freq() -> u64 {
        let freq: u64;
        unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq) };
        freq
    }

    /// Start Tier 1b (record initial time, compute period in ticks).
    pub fn start(period_us: u32) {
        unsafe {
            super::TIER1B_PERIOD_US = period_us;
            let freq = counter_freq();
            PERIOD_TICKS = (period_us as u64 * freq) / 1_000_000;
            LAST_TICK = read_cntpct();
        }
        super::TIER1B_ACTIVE.store(true, Ordering::Release);
    }

    /// Stop Tier 1b.
    pub fn stop() {
        super::TIER1B_ACTIVE.store(false, Ordering::Release);
    }

    /// Poll-based Tier 1b tick. Called from the main loop on aarch64.
    /// Checks if enough time has elapsed and runs the ISR handler if so.
    pub fn poll_tick() {
        if !super::TIER1B_ACTIVE.load(Ordering::Acquire) {
            return;
        }
        let now = read_cntpct();
        let elapsed = now.wrapping_sub(unsafe { LAST_TICK });
        let period = unsafe { PERIOD_TICKS };
        if period > 0 && elapsed >= period {
            unsafe {
                LAST_TICK = now;
                isr_tier1b_handler();
            }
        }
    }
}

// ============================================================================
// Platform-agnostic API
// ============================================================================

/// Initialize ISR tier hardware (DWT cycle counter, etc).
pub fn init() {
    #[cfg(feature = "rp")]
    {
        // Enable DWT cycle counter for timing measurements
        unsafe {
            let demcr = 0xE000_EDFC as *mut u32;
            let val = core::ptr::read_volatile(demcr);
            core::ptr::write_volatile(demcr, val | (1 << 24)); // TRCENA

            let dwt_ctrl = 0xE000_1000 as *mut u32;
            let val = core::ptr::read_volatile(dwt_ctrl);
            core::ptr::write_volatile(dwt_ctrl, val | 1); // CYCCNTENA
        }
    }
}

/// Start the Tier 1b periodic timer with the given period in microseconds.
pub fn start_tier1b(period_us: u32) {
    if period_us == 0 {
        return;
    }
    init(); // Ensure cycle counter is enabled
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    rp2350_backend::start(period_us);
    #[cfg(feature = "chip-rp2040")]
    rp2040_backend::start(period_us);
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_backend::start(period_us);
    log::info!("[isr] tier1b started period={}us", period_us);
}

/// Stop the Tier 1b periodic timer.
pub fn stop_tier1b() {
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    rp2350_backend::stop();
    #[cfg(feature = "chip-rp2040")]
    rp2040_backend::stop();
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_backend::stop();
}

/// Poll Tier 1b from main loop (aarch64 only — no-op on Cortex-M).
#[inline]
pub fn poll_tier1b() {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_backend::poll_tick();
}

// ============================================================================
// ISR Vector Entry Points (RP platforms)
// ============================================================================

/// TIMER1 alarm 1 ISR — Tier 1b on RP2350.
#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
#[no_mangle]
pub unsafe extern "C" fn TIMER1_IRQ_1() {
    rp2350_backend::on_timer_irq();
}

/// TIMER alarm 2 ISR — Tier 1b on RP2040.
#[cfg(feature = "chip-rp2040")]
#[no_mangle]
pub unsafe extern "C" fn TIMER_IRQ_2() {
    rp2040_backend::on_timer_irq();
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
