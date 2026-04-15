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
//! Platform-specific timer setup (RP2350 TIMER1, RP2040 TIMER alarm3,
//! BCM2712 advisory elapsed-time check) is implemented in the HAL layer.
//! The `platform_init/arm/disarm` entry points are called by the HAL
//! implementations and by the ISR vectors in the platform files.
//!
//! ## Fault trampoline
//!
//! On Cortex-M, the timer ISR fires in Handler mode. It modifies the stacked
//! PC on PSP to point to `fault_trampoline`, which returns a timeout error
//! code to the scheduler. On aarch64, forced return is not implemented (the
//! step guard is advisory — it records the timeout but relies on cooperative
//! return).

use portable_atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicI32, Ordering};
use core::cell::UnsafeCell;
use crate::kernel::hal;

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
    /// Module failed to drain within its deadline.
    pub const DRAIN_TIMEOUT: u8 = 5;
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
// Platform backend entry points (called by HAL implementations)
// ============================================================================

/// Set the timeout flag. Called by platform timer ISR.
pub fn set_timed_out() {
    STEP_TIMED_OUT.store(true, Ordering::Release);
}

/// Clear the timeout flag. Called by platform arm.
pub fn clear_timed_out() {
    STEP_TIMED_OUT.store(false, Ordering::Release);
}

/// Set the armed flag. Called by platform arm.
pub fn set_armed(armed: bool) {
    GUARD_ARMED.store(armed, Ordering::Release);
}

/// Check if armed. Called by platform disarm/post-check.
pub fn is_armed() -> bool {
    GUARD_ARMED.load(Ordering::Acquire)
}

// ============================================================================
// Platform-agnostic API
// ============================================================================

/// Initialize the step guard hardware for the current platform.
pub fn init() {
    hal::step_guard_init();
}

/// Arm the step guard with a deadline in microseconds.
#[inline]
pub fn arm(deadline_us: u32) {
    GUARDED_MODULE.store(
        crate::kernel::scheduler::current_module_index() as u8,
        Ordering::Release,
    );
    hal::step_guard_arm(deadline_us);
}

/// Disarm the step guard (normal return path).
#[inline]
pub fn disarm() {
    hal::step_guard_disarm();
}

/// Post-step check for aarch64 (software elapsed check).
/// On Cortex-M this is a no-op (hardware ISR sets the flag).
#[inline]
pub fn post_step_check() {
    hal::step_guard_post_check();
}

// ============================================================================
// Fault monitor: broadcast fault records to a subscribing module
// ============================================================================

/// Externally-visible fault record. Kept compact; serialised LE for monitors.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FaultRecord {
    /// Module index (0..MAX_MODULES).
    pub module_idx: u8,
    /// Fault type (fault_type::*).
    pub fault_kind: u8,
    /// Reserved for alignment.
    pub _reserved: u16,
    /// Tick at which the fault was observed.
    pub tick: u32,
    /// Cumulative fault count for this module after this event.
    pub fault_count: u16,
    /// Cumulative restart count for this module after this event.
    pub restart_count: u16,
}

impl FaultRecord {
    pub const SIZE: usize = 12;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        b[0] = self.module_idx;
        b[1] = self.fault_kind;
        b[4..8].copy_from_slice(&self.tick.to_le_bytes());
        b[8..10].copy_from_slice(&self.fault_count.to_le_bytes());
        b[10..12].copy_from_slice(&self.restart_count.to_le_bytes());
        b
    }
}

/// Ring of recent fault records. Producer and consumer both run on the
/// kernel thread; atomics guard the indices so an ISR that flags a pending
/// fault and the thread-mode push cannot race.
const FAULT_RING_CAP: usize = 16;

struct FaultRing {
    records: UnsafeCell<[FaultRecord; FAULT_RING_CAP]>,
    head: AtomicU16,
    tail: AtomicU16,
    dropped: AtomicU16,
}

// SAFETY: The actual push always happens in thread mode from the scheduler
// (handle_step_timeout / handle_step_error / handle_mpu_fault). ISRs only set
// a pending flag; they never touch this ring directly.
unsafe impl Sync for FaultRing {}

static FAULT_RING: FaultRing = FaultRing {
    records: UnsafeCell::new([FaultRecord {
        module_idx: 0,
        fault_kind: 0,
        _reserved: 0,
        tick: 0,
        fault_count: 0,
        restart_count: 0,
    }; FAULT_RING_CAP]),
    head: AtomicU16::new(0),
    tail: AtomicU16::new(0),
    dropped: AtomicU16::new(0),
};

/// Event handle to signal on fault (set by FAULT_MONITOR_SUBSCRIBE syscall).
/// -1 means no subscriber.
static FAULT_EVENT_HANDLE: AtomicI32 = AtomicI32::new(-1);

/// Register an event handle to be signaled whenever a fault is recorded.
/// Pass -1 to unsubscribe. Returns 0.
pub fn subscribe(event_handle: i32) -> i32 {
    FAULT_EVENT_HANDLE.store(event_handle, Ordering::Release);
    0
}

/// Push a fault record into the ring and signal the subscribed event.
/// Safe to call from scheduler thread context. Drops oldest if full.
pub fn push_fault(rec: FaultRecord) {
    // Emit on the host-facing log transport so `fluxor monitor` can parse
    // faults without a second channel.
    log::info!(
        "MON_FAULT mod={} kind={} fault_count={} restart_count={} tick={}",
        rec.module_idx, rec.fault_kind, rec.fault_count, rec.restart_count, rec.tick,
    );
    let head = FAULT_RING.head.load(Ordering::Relaxed);
    let tail = FAULT_RING.tail.load(Ordering::Acquire);
    let next = head.wrapping_add(1);
    if (next as usize) % FAULT_RING_CAP == (tail as usize) % FAULT_RING_CAP {
        // Ring full: drop the oldest by advancing the tail.
        FAULT_RING.tail.store(tail.wrapping_add(1), Ordering::Release);
        FAULT_RING.dropped.fetch_add(1, Ordering::Relaxed);
    }
    unsafe {
        let slot = &mut (*FAULT_RING.records.get())[(head as usize) % FAULT_RING_CAP];
        *slot = rec;
    }
    FAULT_RING.head.store(next, Ordering::Release);

    let eh = FAULT_EVENT_HANDLE.load(Ordering::Acquire);
    if eh >= 0 {
        // Bypass event_signal's owner check: the kernel is the producer and
        // has no module identity for the caller.
        crate::kernel::event::event_signal_from_isr(eh);
    }
}

/// Pop the next fault record into `out`. Returns 1 if a record was copied,
/// 0 if the ring was empty.
pub fn pop_fault(out: &mut FaultRecord) -> i32 {
    let tail = FAULT_RING.tail.load(Ordering::Relaxed);
    let head = FAULT_RING.head.load(Ordering::Acquire);
    if (head as usize) % FAULT_RING_CAP == (tail as usize) % FAULT_RING_CAP {
        return 0;
    }
    unsafe {
        let slot = &(*FAULT_RING.records.get())[(tail as usize) % FAULT_RING_CAP];
        *out = *slot;
    }
    FAULT_RING.tail.store(tail.wrapping_add(1), Ordering::Release);
    1
}

/// Return the dropped-record count (records overwritten because ring was full).
pub fn dropped_count() -> u16 {
    FAULT_RING.dropped.load(Ordering::Relaxed)
}
