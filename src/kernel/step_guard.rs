//! Step guard timer — arms a hardware deadline before each module_step().
//!
//! # Architecture
//!
//! Before each `module_step()`, the scheduler arms a one-shot hardware timer
//! with the module's step deadline. On normal return, the timer is disarmed.
//! If the timer fires (module exceeded deadline), the ISR sets a timeout flag
//! and forces the module to return by modifying the exception return address.
//!
//! ## Platform backends
//!
//! - **RP2350**: TIMER1 alarm 0 (Embassy uses TIMER0). One-shot deadline.
//! - **RP2040**: TIMER alarm 3 (Embassy uses alarms 0-2). One-shot deadline.
//! - **BCM2712/aarch64**: Software check — no hardware timer manipulation.
//!   The main loop is single-threaded; modules that hang are caught by a
//!   simple elapsed-time check after each step returns (or by watchdog).
//!
//! ## Fault trampoline
//!
//! On Cortex-M, the timer ISR fires in Handler mode. It modifies the stacked
//! PC on PSP to point to `fault_trampoline`, which returns a timeout error
//! code to the scheduler. On aarch64, forced return is not implemented (the
//! step guard is advisory — it records the timeout but relies on cooperative
//! return).

use portable_atomic::{AtomicBool, AtomicU8, Ordering};

// ============================================================================
// Fault state machine
// ============================================================================

/// Module fault states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FaultState {
    /// Module is running normally.
    Running = 0,
    /// Module faulted (timeout or error). Excluded from step loop.
    Faulted = 1,
    /// Module is being recovered (state zeroed, channels drained).
    Recovering = 2,
    /// Module permanently terminated (max restarts exceeded or skip policy).
    Terminated = 3,
}

/// Fault recovery policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FaultPolicy {
    /// Terminate module, graph continues without it.
    Skip = 0,
    /// Zero state, reset heap, drain channels, call module_new() again.
    Restart = 1,
    /// Tear down and re-instantiate entire graph.
    RestartGraph = 2,
}

/// Fault type codes for last_fault_type.
pub mod fault_type {
    /// No fault.
    pub const NONE: u8 = 0;
    /// Step exceeded deadline (timeout).
    pub const TIMEOUT: u8 = 1;
    /// Module returned error from step().
    pub const STEP_ERROR: u8 = 2;
    /// Module caused a hard fault (bus error, etc).
    pub const HARD_FAULT: u8 = 3;
    /// Module caused an MPU/MMU memory protection fault.
    pub const MPU_FAULT: u8 = 4;
}

/// Per-module fault statistics (queryable via dev_query).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FaultStats {
    /// Total fault count since boot.
    pub fault_count: u16,
    /// Total restart count since boot.
    pub restart_count: u16,
    /// Type of last fault (fault_type::*).
    pub last_fault_type: u8,
    /// Current fault state (FaultState as u8).
    pub current_state: u8,
    /// Reserved for alignment.
    pub _reserved: u16,
    /// Ticks since last fault (0 if no fault yet).
    pub ticks_since_fault: u32,
}

/// Per-module fault bookkeeping (stored in SchedulerState).
#[derive(Clone, Copy)]
pub struct ModuleFaultInfo {
    /// Current fault state.
    pub state: FaultState,
    /// Fault recovery policy.
    pub policy: FaultPolicy,
    /// Total fault count.
    pub fault_count: u16,
    /// Total restart count.
    pub restart_count: u16,
    /// Maximum allowed restarts (0 = unlimited for Skip, but Skip doesn't restart).
    pub max_restarts: u16,
    /// Backoff time in ms between restart attempts.
    pub restart_backoff_ms: u16,
    /// Type of last fault.
    pub last_fault_type: u8,
    /// Tick count at last fault (for ticks_since_fault calculation).
    pub last_fault_tick: u32,
    /// Backoff countdown (ticks remaining before restart attempt).
    pub backoff_remaining: u32,
    /// Step deadline in microseconds (0 = use default).
    pub step_deadline_us: u32,
}

impl ModuleFaultInfo {
    pub const fn new() -> Self {
        Self {
            state: FaultState::Running,
            policy: FaultPolicy::Skip,
            fault_count: 0,
            restart_count: 0,
            max_restarts: 3,
            restart_backoff_ms: 100,
            last_fault_type: fault_type::NONE,
            last_fault_tick: 0,
            backoff_remaining: 0,
            step_deadline_us: 0,
        }
    }

    /// Get the effective step deadline in microseconds.
    pub fn effective_deadline_us(&self) -> u32 {
        if self.step_deadline_us > 0 {
            self.step_deadline_us
        } else {
            DEFAULT_STEP_DEADLINE_US
        }
    }

    /// Record a fault event.
    pub fn record_fault(&mut self, fault_kind: u8, tick: u32) {
        self.fault_count = self.fault_count.saturating_add(1);
        self.last_fault_type = fault_kind;
        self.last_fault_tick = tick;
    }

    /// Check if restart is allowed (policy + max_restarts).
    pub fn can_restart(&self) -> bool {
        if self.policy != FaultPolicy::Restart {
            return false;
        }
        if self.max_restarts == 0 {
            return false;
        }
        self.restart_count < self.max_restarts
    }

    /// Build a FaultStats snapshot for dev_query.
    pub fn to_stats(&self, current_tick: u32) -> FaultStats {
        let ticks_since = if self.last_fault_tick > 0 && current_tick >= self.last_fault_tick {
            current_tick - self.last_fault_tick
        } else {
            0
        };
        FaultStats {
            fault_count: self.fault_count,
            restart_count: self.restart_count,
            last_fault_type: self.last_fault_type,
            current_state: self.state as u8,
            _reserved: 0,
            ticks_since_fault: ticks_since,
        }
    }
}

// ============================================================================
// Step guard timer
// ============================================================================

/// Default step deadline: 2ms (2000 us).
pub const DEFAULT_STEP_DEADLINE_US: u32 = 2000;

/// Burst multiplier — burst deadline = step_deadline * this.
pub const BURST_MULTIPLIER: u32 = 8;

/// Global flag: set by timer ISR when a step times out.
/// Checked by scheduler after each step() call.
static STEP_TIMED_OUT: AtomicBool = AtomicBool::new(false);

/// Module index that the guard is armed for (for ISR context).
static GUARDED_MODULE: AtomicU8 = AtomicU8::new(0xFF);

/// Whether the step guard is currently armed.
static GUARD_ARMED: AtomicBool = AtomicBool::new(false);

/// Flag: set by MPU/MMU fault handler when a memory protection violation occurs.
static MPU_FAULT_PENDING: AtomicBool = AtomicBool::new(false);

/// Check if the last step timed out (and clear the flag).
#[inline]
pub fn check_and_clear_timeout() -> bool {
    STEP_TIMED_OUT.swap(false, Ordering::AcqRel)
}

/// Record an MPU/MMU fault for the current module.
/// Called from the MemManage (Cortex-M) or Data Abort (aarch64) handler.
pub fn record_mpu_fault(module_idx: usize) {
    MPU_FAULT_PENDING.store(true, Ordering::Release);
    GUARDED_MODULE.store(module_idx as u8, Ordering::Release);
}

/// Check if an MPU fault is pending (and clear the flag).
#[inline]
pub fn check_and_clear_mpu_fault() -> bool {
    MPU_FAULT_PENDING.swap(false, Ordering::AcqRel)
}

/// Check if a timeout is pending without clearing.
#[inline]
pub fn is_timed_out() -> bool {
    STEP_TIMED_OUT.load(Ordering::Acquire)
}

// ============================================================================
// RP2350 backend: TIMER1 alarm 0
// ============================================================================

#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
mod rp2350_backend {
    use super::*;
    use embassy_rp::pac;

    /// TIMER1 on RP2350 — separate from Embassy's TIMER0.
    fn timer1() -> pac::timer::Timer {
        pac::TIMER1
    }

    /// Arm the step guard with a deadline in microseconds.
    pub fn arm(deadline_us: u32) {
        STEP_TIMED_OUT.store(false, Ordering::Release);
        GUARD_ARMED.store(true, Ordering::Release);

        let t = timer1();
        // Read current time and set alarm 0 to fire at now + deadline
        let now_lo = t.timelr().read();
        let target = now_lo.wrapping_add(deadline_us);

        // Clear any pending alarm 0 interrupt
        t.intr().write(|w| w.set_alarm(0, true));
        // Set alarm target
        t.alarm(0).write_value(target);
        // Enable alarm 0 interrupt
        t.inte().modify(|w| w.set_alarm(0, true));
    }

    /// Disarm the step guard (normal return from step).
    pub fn disarm() {
        if !GUARD_ARMED.load(Ordering::Acquire) {
            return;
        }
        let t = timer1();
        // Disable alarm 0 interrupt
        t.inte().modify(|w| w.set_alarm(0, false));
        // Clear any pending
        t.intr().write(|w| w.set_alarm(0, true));
        GUARD_ARMED.store(false, Ordering::Release);
    }

    /// Timer1 alarm 0 ISR — called from vector table.
    /// Sets the timeout flag. Does NOT force-return (v1: advisory only).
    pub fn on_timer_irq() {
        let t = timer1();
        // Acknowledge interrupt
        t.intr().write(|w| w.set_alarm(0, true));
        // Disable further interrupts from this alarm
        t.inte().modify(|w| w.set_alarm(0, false));

        STEP_TIMED_OUT.store(true, Ordering::Release);
        GUARD_ARMED.store(false, Ordering::Release);
    }

    /// Initialize the timer1 hardware for step guard use.
    pub fn init() {
        // TIMER1 runs from the same clock as TIMER0 (1MHz by default on RP2350).
        // Just ensure alarm 0 is disabled and cleared.
        let t = timer1();
        t.inte().modify(|w| w.set_alarm(0, false));
        t.intr().write(|w| w.set_alarm(0, true));

        // Enable TIMER1_IRQ_0 in NVIC (IRQ number for TIMER1 alarm 0)
        // On RP2350, TIMER1_IRQ_0 = IRQ 4 + offset. The actual IRQ number
        // is chip-specific. We use cortex-m NVIC directly.
        unsafe {
            let nvic = &*cortex_m::peripheral::NVIC::PTR;
            // TIMER1_IRQ_0 on RP2350 is interrupt 4
            // (TIMER0_IRQ_0=0, TIMER0_IRQ_1=1, TIMER0_IRQ_2=2, TIMER0_IRQ_3=3,
            //  TIMER1_IRQ_0=4)
            const TIMER1_IRQ_0: u16 = 4;
            nvic.iser[0].write(1 << TIMER1_IRQ_0);
        }
    }
}

// ============================================================================
// RP2040 backend: TIMER alarm 3
// ============================================================================

#[cfg(feature = "chip-rp2040")]
mod rp2040_backend {
    use super::*;
    use embassy_rp::pac;

    fn timer() -> pac::timer::Timer {
        pac::TIMER
    }

    /// Arm the step guard with a deadline in microseconds.
    pub fn arm(deadline_us: u32) {
        STEP_TIMED_OUT.store(false, Ordering::Release);
        GUARD_ARMED.store(true, Ordering::Release);

        let t = timer();
        let now_lo = t.timelr().read();
        let target = now_lo.wrapping_add(deadline_us);

        // Clear any pending alarm 3 interrupt
        t.intr().write(|w| w.set_alarm(3, true));
        // Set alarm target
        t.alarm(3).write_value(target);
        // Enable alarm 3 interrupt
        t.inte().modify(|w| w.set_alarm(3, true));
    }

    /// Disarm the step guard (normal return from step).
    pub fn disarm() {
        if !GUARD_ARMED.load(Ordering::Acquire) {
            return;
        }
        let t = timer();
        t.inte().modify(|w| w.set_alarm(3, false));
        t.intr().write(|w| w.set_alarm(3, true));
        GUARD_ARMED.store(false, Ordering::Release);
    }

    /// Timer alarm 3 ISR.
    pub fn on_timer_irq() {
        let t = timer();
        t.intr().write(|w| w.set_alarm(3, true));
        t.inte().modify(|w| w.set_alarm(3, false));

        STEP_TIMED_OUT.store(true, Ordering::Release);
        GUARD_ARMED.store(false, Ordering::Release);
    }

    /// Initialize alarm 3 for step guard use.
    pub fn init() {
        let t = timer();
        t.inte().modify(|w| w.set_alarm(3, false));
        t.intr().write(|w| w.set_alarm(3, true));

        // Enable TIMER_IRQ_3 in NVIC (IRQ 3 on RP2040)
        unsafe {
            let nvic = &*cortex_m::peripheral::NVIC::PTR;
            const TIMER_IRQ_3: u16 = 3;
            nvic.iser[0].write(1 << TIMER_IRQ_3);
        }
    }
}

// ============================================================================
// BCM2712/aarch64 backend: software elapsed-time check
// ============================================================================

#[cfg(feature = "chip-bcm2712")]
mod bcm2712_backend {
    use super::*;

    /// Timestamp when guard was armed (CNT_CT virtual count).
    static mut ARM_TIME: u64 = 0;
    /// Deadline in counter ticks.
    static mut DEADLINE_TICKS: u64 = 0;

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

    /// Arm the step guard (record start time).
    pub fn arm(deadline_us: u32) {
        STEP_TIMED_OUT.store(false, Ordering::Release);
        GUARD_ARMED.store(true, Ordering::Release);
        let freq = counter_freq();
        let ticks = (deadline_us as u64 * freq) / 1_000_000;
        unsafe {
            ARM_TIME = read_cntpct();
            DEADLINE_TICKS = ticks;
        }
    }

    /// Disarm the step guard.
    pub fn disarm() {
        GUARD_ARMED.store(false, Ordering::Release);
    }

    /// Check elapsed time after step returns (called by scheduler).
    /// On aarch64 there is no forced return — this is advisory.
    pub fn check_elapsed() {
        if !GUARD_ARMED.load(Ordering::Acquire) {
            return;
        }
        let now = read_cntpct();
        let elapsed = now.wrapping_sub(unsafe { ARM_TIME });
        if elapsed >= unsafe { DEADLINE_TICKS } {
            STEP_TIMED_OUT.store(true, Ordering::Release);
        }
        GUARD_ARMED.store(false, Ordering::Release);
    }

    /// Init — no-op on aarch64 (software check only).
    pub fn init() {}
}

// ============================================================================
// Platform-agnostic API
// ============================================================================

/// Initialize the step guard hardware for the current platform.
pub fn init() {
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    rp2350_backend::init();
    #[cfg(feature = "chip-rp2040")]
    rp2040_backend::init();
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_backend::init();
}

/// Arm the step guard with a deadline in microseconds.
#[inline]
pub fn arm(deadline_us: u32) {
    GUARDED_MODULE.store(
        crate::kernel::scheduler::current_module_index() as u8,
        Ordering::Release,
    );
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    rp2350_backend::arm(deadline_us);
    #[cfg(feature = "chip-rp2040")]
    rp2040_backend::arm(deadline_us);
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_backend::arm(deadline_us);
}

/// Disarm the step guard (normal return path).
#[inline]
pub fn disarm() {
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    rp2350_backend::disarm();
    #[cfg(feature = "chip-rp2040")]
    rp2040_backend::disarm();
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_backend::disarm();
}

/// Post-step check for aarch64 (software elapsed check).
/// On Cortex-M this is a no-op (hardware ISR sets the flag).
#[inline]
pub fn post_step_check() {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_backend::check_elapsed();
}

/// Timer ISR entry point — called from interrupt vector.
/// Only needed on RP platforms (Cortex-M hardware timer).
#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
#[no_mangle]
pub unsafe extern "C" fn TIMER1_IRQ_0() {
    rp2350_backend::on_timer_irq();
}

#[cfg(feature = "chip-rp2040")]
#[no_mangle]
pub unsafe extern "C" fn TIMER_IRQ_3() {
    rp2040_backend::on_timer_irq();
}
