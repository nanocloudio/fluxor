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

use crate::kernel::hal;
use core::cell::UnsafeCell;
use portable_atomic::{AtomicBool, AtomicI32, AtomicU16, AtomicU8, Ordering};

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
    /// **v1 limitation — partial restart**: channels are flushed and the
    /// fault state machine moves back to `Running`, but state is *not*
    /// zeroed and `module_new()` is *not* re-called. See
    /// `scheduler::handle_module_restart` for the exact behaviour. Safe
    /// for stateless / idempotent modules; modules with stateful invariants
    /// should use `Skip` and rely on the graph operator to drain+reload.
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

/// Per-module fault statistics (queryable via `provider_query`).
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
    /// Optional override for the deadline applied during a `Burst`
    /// re-step loop. When set (`> 0`), the burst path uses this value
    /// directly instead of the multiplier-derived `step_deadline_us *
    /// BURST_MULTIPLIER`, so modules with asymmetric typical-vs-burst
    /// step times (TCP retransmit path, codec keyframe decode) can
    /// declare both numbers explicitly rather than sizing the typical
    /// deadline for the worst case. `0` selects the multiplier path.
    pub step_deadline_burst_us: u32,
    /// Index of a paired module. When this module faults and the
    /// partner has also faulted within `QUARANTINE_WINDOW_TICKS`,
    /// both are terminated regardless of individual `FaultPolicy`.
    /// `0xFF` means no partner declared. Used by tightly-coupled
    /// pairs (TLS handshake + transport, codec pair-stream) where
    /// one half's failure invalidates the other.
    pub quarantine_partner: u8,
}

impl Default for ModuleFaultInfo {
    fn default() -> Self {
        Self::new()
    }
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
            step_deadline_burst_us: 0,
            quarantine_partner: 0xFF,
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

    /// Effective burst deadline override in microseconds, or `None`
    /// to use the `step_deadline_us * BURST_MULTIPLIER` fallback.
    pub fn explicit_burst_deadline_us(&self) -> Option<u32> {
        if self.step_deadline_burst_us > 0 {
            Some(self.step_deadline_burst_us)
        } else {
            None
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

    /// Geometric backoff before the next restart attempt, in scheduler
    /// ticks. Scales the configured base by `2^restart_count` so a
    /// module faulting on every restart attempt doesn't monopolise the
    /// scheduler with a tight retry loop — successive failures pay
    /// exponentially longer waits, paired with the `max_restarts` cap.
    ///
    /// The configured base (`restart_backoff_ms`) is treated as
    /// **ticks** here, matching the kernel's per-tick decrement of
    /// `backoff_remaining`. The field name is a legacy misnomer kept
    /// for ABI stability.
    pub fn effective_backoff_ticks(&self) -> u32 {
        let base = self.restart_backoff_ms as u32;
        let shift = (self.restart_count as u32).min(8);
        base.saturating_mul(1u32 << shift)
    }

    /// Build a FaultStats snapshot for `provider_query`.
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

/// Maximum cores the step-guard state arrays size for. Matches
/// `scheduler::MAX_DOMAINS` (4); on single-core platforms (RP /
/// Linux / WASM) only index 0 is used. Every step-guard atomic is
/// indexed by `hal::core_id()` so two cores arming their own steps
/// in parallel cannot clobber each other's guarded-module / timeout
/// / MPU-fault state.
pub const MAX_STEP_GUARD_CORES: usize = 4;

/// Per-core flag: set by timer ISR when a step times out.
/// Checked by the scheduler running on that core after each step()
/// call.
static STEP_TIMED_OUT: [AtomicBool; MAX_STEP_GUARD_CORES] = [
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];

/// Per-core module index that the guard is armed for (for ISR
/// context). `0xFF` means no module is currently guarded on that core.
static GUARDED_MODULE: [AtomicU8; MAX_STEP_GUARD_CORES] = [
    AtomicU8::new(0xFF),
    AtomicU8::new(0xFF),
    AtomicU8::new(0xFF),
    AtomicU8::new(0xFF),
];

/// Per-core armed flag. The platform `step_guard_arm` sets this
/// before reading `GUARDED_MODULE`; `step_guard_disarm` clears it.
static GUARD_ARMED: [AtomicBool; MAX_STEP_GUARD_CORES] = [
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];

/// Per-core MPU/MMU fault flag, set by the protection-fault handler
/// on the offending core.
static MPU_FAULT_PENDING: [AtomicBool; MAX_STEP_GUARD_CORES] = [
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];

#[inline(always)]
fn cur_core() -> usize {
    let id = crate::kernel::hal::core_id();
    if id < MAX_STEP_GUARD_CORES {
        id
    } else {
        0
    }
}

/// Check if the last step timed out on the current core (and clear
/// the flag).
#[inline]
pub fn check_and_clear_timeout() -> bool {
    STEP_TIMED_OUT[cur_core()].swap(false, Ordering::AcqRel)
}

/// Record an MPU/MMU fault for the current module on the current core.
/// Called from the MemManage (Cortex-M) or Data Abort (aarch64) handler.
pub fn record_mpu_fault(module_idx: usize) {
    let c = cur_core();
    MPU_FAULT_PENDING[c].store(true, Ordering::Release);
    GUARDED_MODULE[c].store(module_idx as u8, Ordering::Release);
}

/// Check if an MPU fault is pending on the current core (and clear).
#[inline]
pub fn check_and_clear_mpu_fault() -> bool {
    MPU_FAULT_PENDING[cur_core()].swap(false, Ordering::AcqRel)
}

/// Check if a timeout is pending on the current core without clearing.
#[inline]
pub fn is_timed_out() -> bool {
    STEP_TIMED_OUT[cur_core()].load(Ordering::Acquire)
}

// ============================================================================
// Platform backend entry points (called by HAL implementations)
// ============================================================================

/// Set the timeout flag for the current core. Called by platform timer ISR.
pub fn set_timed_out() {
    STEP_TIMED_OUT[cur_core()].store(true, Ordering::Release);
}

/// Clear the timeout flag for the current core. Called by platform arm.
pub fn clear_timed_out() {
    STEP_TIMED_OUT[cur_core()].store(false, Ordering::Release);
}

/// Set the armed flag for the current core. Called by platform arm.
pub fn set_armed(armed: bool) {
    GUARD_ARMED[cur_core()].store(armed, Ordering::Release);
}

/// Check if armed on the current core. Called by platform disarm/post-check.
pub fn is_armed() -> bool {
    GUARD_ARMED[cur_core()].load(Ordering::Acquire)
}

// ============================================================================
// Platform-agnostic API
// ============================================================================

/// Initialize the step guard hardware for the current platform.
pub fn init() {
    hal::step_guard_init();
}

/// Arm the step guard with a deadline in microseconds. Records the
/// guarded module index on the current core's slot so the timer ISR
/// / MPU fault handler can identify which module timed out without
/// stepping on another core's guarded module.
#[inline]
pub fn arm(deadline_us: u32) {
    GUARDED_MODULE[cur_core()].store(
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
///
/// Wire layout (12 bytes):
///   byte 0:    module_idx
///   byte 1:    fault_kind
///   byte 2:    caused_by — module index of the upstream that faulted
///              within the cascade window, or `0xFF` if independent.
///   byte 3:    last_input_ct — content_type of the module's most
///              recent consumed input, or `0` for unknown.
///   bytes 4-7: tick (u32 LE)
///   bytes 8-9: fault_count (u16 LE)
///   bytes 10-11: restart_count (u16 LE)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FaultRecord {
    /// Module index (0..MAX_MODULES).
    pub module_idx: u8,
    /// Fault type (fault_type::*).
    pub fault_kind: u8,
    /// Cascade origin — upstream module index that faulted within
    /// `CASCADE_WINDOW_TICKS` of this fault, or `0xFF` for independent.
    pub caused_by: u8,
    /// Content_type of the last consumed input, or `0` if unknown.
    pub last_input_ct: u8,
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
        b[2] = self.caused_by;
        b[3] = self.last_input_ct;
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
    records: UnsafeCell::new(
        [FaultRecord {
            module_idx: 0,
            fault_kind: 0,
            caused_by: 0xFF,
            last_input_ct: 0,
            tick: 0,
            fault_count: 0,
            restart_count: 0,
        }; FAULT_RING_CAP],
    ),
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
    // Emit on the host-facing log transport so `fluxor monitor` can
    // parse faults without a second channel — operators see cascade
    // origin and consumed content_type alongside the regular counters
    // without decoding the binary FaultRecord stream separately.
    log::info!(
        "MON_FAULT mod={} kind={} fault_count={} restart_count={} \
         caused_by={} last_input_ct={} tick={}",
        rec.module_idx,
        rec.fault_kind,
        rec.fault_count,
        rec.restart_count,
        rec.caused_by,
        rec.last_input_ct,
        rec.tick,
    );
    let head = FAULT_RING.head.load(Ordering::Relaxed);
    let tail = FAULT_RING.tail.load(Ordering::Acquire);
    let next = head.wrapping_add(1);
    if (next as usize) % FAULT_RING_CAP == (tail as usize) % FAULT_RING_CAP {
        // Ring full: drop the oldest by advancing the tail.
        FAULT_RING
            .tail
            .store(tail.wrapping_add(1), Ordering::Release);
        FAULT_RING.dropped.fetch_add(1, Ordering::Relaxed);
    }
    // SAFETY: `head % FAULT_RING_CAP` is in-bounds for the records array.
    // The write happens-before the `head.store(Release)` below, which is
    // what readers Acquire-load to observe the entry.
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
    // SAFETY: `tail % FAULT_RING_CAP` is in-bounds; the corresponding
    // record was published by the `head.store(Release)` in `record_fault`
    // which this consumer observed via the matching Acquire above.
    unsafe {
        let slot = &(*FAULT_RING.records.get())[(tail as usize) % FAULT_RING_CAP];
        *out = *slot;
    }
    FAULT_RING
        .tail
        .store(tail.wrapping_add(1), Ordering::Release);
    1
}

/// Return the dropped-record count (records overwritten because ring was full).
pub fn dropped_count() -> u16 {
    FAULT_RING.dropped.load(Ordering::Relaxed)
}
