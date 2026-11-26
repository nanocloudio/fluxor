//! Step guard timer — arms a hardware deadline before each module_step().
//!
//! # Architecture
//!
//! Before each `module_step()`, the scheduler arms a one-shot hardware timer
//! with the module's step deadline. On normal return, the timer is disarmed.
//! If the timer fires, the ISR records the overrun and disarms the alarm.
//!
//! An overrun is detected, never prevented: the module is not forced to
//! return, and the scheduler acts on the recorded flag only after the step
//! returns of its own accord. A module that never returns is not bounded by
//! this mechanism on any target.
//!
//! ## Platform backends
//!
//! Platform-specific timer setup (RP2350 TIMER1, RP2040 TIMER alarm3,
//! BCM2712 advisory elapsed-time check) is implemented in the HAL layer.
//! The `platform_init/arm/disarm` entry points are called by the HAL
//! implementations and by the ISR vectors in the platform files.
//!
//! On the Linux and WASM hosts the guard hooks are inert, so an overrun is
//! not observed at all. The forced-return trampoline that rewrites a stacked
//! PC belongs to the memory-protection fault path, not to this timer.

use crate::kernel::exec::scheduler::{ModuleId, NO_MODULE};
use crate::kernel::sys::hal;
use core::cell::UnsafeCell;
use portable_atomic::{AtomicBool, AtomicI32, AtomicU16, AtomicU64, Ordering};

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
    /// Partial restart: channels are flushed and the fault state machine
    /// moves back to `Running`, but state is *not* zeroed and
    /// `module_new()` is *not* re-called. See
    /// `scheduler::fault::restart` for the exact behaviour. Safe for
    /// stateless / idempotent modules; modules with stateful invariants
    /// should use `Skip` and rely on the graph operator to drain and reload.
    Restart = 1,
    /// Step-deadline overruns are RECORDED (fault counter, [guard]
    /// log, fault ring) but never fault the module. The policy for a
    /// module whose synchronous device ops carry a legitimate heavy
    /// tail: a FAT32/NVMe cache flush stalls every op queued behind
    /// it for 35-150 ms (pi5 rig measurement), so a hard deadline
    /// would terminate a storage module for latency it does not
    /// control. Step ERRORS (non-zero rc) still fault normally — only
    /// the overrun path is tolerated, and the deadline keeps its
    /// meaning as a telemetry threshold.
    Tolerate = 2,
}

impl FaultPolicy {
    /// The policy a composed graph's module record names.
    pub const fn from_graph(p: fluxor_contracts::graph::FaultPolicy) -> Self {
        match p {
            fluxor_contracts::graph::FaultPolicy::Skip => FaultPolicy::Skip,
            fluxor_contracts::graph::FaultPolicy::Restart => FaultPolicy::Restart,
            fluxor_contracts::graph::FaultPolicy::Tolerate => FaultPolicy::Tolerate,
        }
    }

    /// Whether the policy's whole effect stays on the faulting module, so a
    /// workload may choose it. Only `Skip` is: it terminates the module.
    /// `Tolerate` records an overrun and lets the module run on, so the
    /// domain's other modules pay for every late step and the deadline it
    /// was admitted under never binds it. `Restart` releases the module's
    /// provider layers and flushes its channels, which other owners may
    /// hold.
    pub const fn confined_to_module(self) -> bool {
        matches!(self, FaultPolicy::Skip)
    }
}

/// Fault type codes for last_fault_type.
pub mod fault_type {
    use crate::abi::contracts::workload::owners;
    /// No fault.
    pub const NONE: u8 = owners::FAULT_NONE;
    /// Step exceeded deadline (timeout).
    pub const TIMEOUT: u8 = owners::FAULT_TIMEOUT;
    /// Module returned error from step().
    pub const STEP_ERROR: u8 = owners::FAULT_STEP_ERROR;
    /// Module caused an MPU/MMU memory protection fault.
    pub const MPU_FAULT: u8 = owners::FAULT_MPU;
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

impl FaultStats {
    /// Bytes of the `FAULT_STATS_QUERY` answer.
    pub const SIZE: usize = 12;

    /// The `FAULT_STATS_QUERY` answer: the fields in order, LE.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        b[0..2].copy_from_slice(&self.fault_count.to_le_bytes());
        b[2..4].copy_from_slice(&self.restart_count.to_le_bytes());
        b[4] = self.last_fault_type;
        b[5] = self.current_state;
        b[8..12].copy_from_slice(&self.ticks_since_fault.to_le_bytes());
        b
    }
}

/// What a module's own core has left for the primary to do to it. A core
/// other than the primary does not finalize, restart or terminate a module
/// itself: that work changes tables every domain reads and runs through
/// provider release hooks of any depth, so it is the primary's, taken with
/// the other cores parked. The module is not stepped while one is posted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PostedFault {
    /// Nothing is posted.
    None = 0,
    /// The step ran past its deadline.
    Timeout = 1,
    /// A protection fault.
    Protection = 2,
    /// The step returned the error in `posted_rc`.
    Error = 3,
    /// As `Error`, from a burst re-step.
    ErrorInBurst = 4,
    /// As `Error`, from the pipeline-refill hook.
    ErrorInRefill = 5,
    /// As `Error`, from the post-tick-flush hook.
    ErrorInFlush = 6,
    /// The module finished.
    Done = 7,
    /// As `Done`, from a burst re-step.
    DoneInBurst = 8,
    /// The module is `Faulted`: its policy is due a look (the quarantine,
    /// then the restart or the termination once its backoff has passed).
    Advance = 9,
    /// The step was forced out at its deadline (a gated entry stopped
    /// mid-run).
    ForcedOut = 10,
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
    /// The module's domain's pass count at the last fault: feeds the ABI
    /// `FaultStats.ticks_since_fault` (a diagnostic, counted in passes).
    pub last_fault_tick: u32,
    /// Wall clock (ms, `hal::now_millis()`) at the last fault: the
    /// quarantine and cascade windows measure from it.
    pub last_fault_ms: u64,
    /// Wall clock (ms, `hal::now_millis()`) before which a `Faulted`
    /// module is not restarted.
    pub restart_not_before_ms: u64,
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
    /// partner has also faulted within `QUARANTINE_WINDOW_MS`,
    /// both are terminated regardless of individual `FaultPolicy`.
    /// `NO_MODULE` means no partner declared. Used by tightly-coupled
    /// pairs (TLS handshake + transport, codec pair-stream) where
    /// one half's failure invalidates the other.
    pub quarantine_partner: ModuleId,
    /// What the module's core has left for the primary, and the error code
    /// that goes with it.
    pub posted: PostedFault,
    pub posted_rc: i32,
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
            last_fault_ms: 0,
            restart_not_before_ms: 0,
            step_deadline_us: 0,
            step_deadline_burst_us: 0,
            quarantine_partner: NO_MODULE,
            posted: PostedFault::None,
            posted_rc: 0,
        }
    }

    /// Leave `what` for the primary, unless something is already posted:
    /// the first outcome stands until the primary has taken it. Returns
    /// whether it was recorded.
    pub fn post(&mut self, what: PostedFault, rc: i32) -> bool {
        if self.posted != PostedFault::None {
            return false;
        }
        self.posted = what;
        self.posted_rc = rc;
        true
    }

    /// Take what is posted, leaving nothing.
    pub fn take_posted(&mut self) -> (PostedFault, i32) {
        let taken = (self.posted, self.posted_rc);
        self.posted = PostedFault::None;
        self.posted_rc = 0;
        taken
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
        self.last_fault_ms = hal::now_millis();
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

    /// Geometric backoff before the next restart attempt, in
    /// milliseconds: the configured base scaled by `2^restart_count` (capped
    /// at 2^8), so a module faulting on every restart pays exponentially
    /// longer waits up to its `max_restarts`.
    pub fn effective_backoff_ms(&self) -> u32 {
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

/// Default step deadline. A deadline is a fault threshold, not a budget,
/// so it is sized to the machine the code runs on: the chip says
/// (`platform::chip`), 2 ms on silicon.
pub const DEFAULT_STEP_DEADLINE_US: u32 = crate::platform::chip::DEFAULT_STEP_DEADLINE_US;

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

/// Per-core flag: the step that timed out was forced out by the protection
/// backend (a gated entry stopped at its deadline), not merely late. A
/// forced-out step did not finish, so no policy may treat it as late work.
static STEP_FORCED_OUT: [AtomicBool; MAX_STEP_GUARD_CORES] = [
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];

/// Per-core module index that the guard is armed for (for ISR
/// context). `NO_MODULE` means no module is currently guarded on that core.
static GUARDED_MODULE: [AtomicU16; MAX_STEP_GUARD_CORES] = [
    AtomicU16::new(NO_MODULE),
    AtomicU16::new(NO_MODULE),
    AtomicU16::new(NO_MODULE),
    AtomicU16::new(NO_MODULE),
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

/// Per-core time, in microseconds, the kernel held the core for inside the
/// step it is running: time that is not the module's (a masked flash
/// operation, a park for another core's). Cleared when a step starts; the
/// scheduler takes it out of the time it records for the step.
static EXCLUDED_US: [portable_atomic::AtomicU32; MAX_STEP_GUARD_CORES] =
    [const { portable_atomic::AtomicU32::new(0) }; MAX_STEP_GUARD_CORES];

/// A step starts on this core: nothing is excluded from it yet.
#[inline]
pub fn begin_step() {
    EXCLUDED_US[cur_core()].store(0, Ordering::Relaxed);
}

/// The kernel held this core for `us` microseconds inside the running step.
/// Called by the platform, on the core, where it moves the step's deadline
/// past the same time.
#[inline]
pub fn exclude(us: u32) {
    let slot = &EXCLUDED_US[cur_core()];
    slot.store(
        slot.load(Ordering::Relaxed).saturating_add(us),
        Ordering::Relaxed,
    );
}

/// The time excluded from the step running on this core, since
/// [`begin_step`].
#[inline]
pub fn excluded_us() -> u32 {
    EXCLUDED_US[cur_core()].load(Ordering::Relaxed)
}

/// `elapsed_us` of wall clock, less the part of `excluded_us` that fell
/// inside it: what a step that took `elapsed_us` is charged when the kernel
/// held its core for `excluded_us` of that.
#[inline]
pub const fn charged(elapsed_us: u64, excluded_us: u32) -> u64 {
    elapsed_us.saturating_sub(excluded_us as u64)
}

#[inline(always)]
fn cur_core() -> usize {
    let id = crate::kernel::sys::hal::core_id();
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
    GUARDED_MODULE[c].store(module_idx as ModuleId, Ordering::Release);
}

/// Record that a gated module was forced out of an entry for running past
/// its step deadline. The scheduler handles it exactly as a step the guard
/// alarm caught: the module's timeout policy applies.
pub fn record_forced_timeout(module_idx: usize) {
    let c = cur_core();
    STEP_FORCED_OUT[c].store(true, Ordering::Release);
    STEP_TIMED_OUT[c].store(true, Ordering::Release);
    GUARDED_MODULE[c].store(module_idx as ModuleId, Ordering::Release);
}

/// Whether the current core's last timeout was a forced-out entry (and
/// clear): the timeout policy reads it so `Tolerate` never lets a step that
/// was stopped mid-run count as one that ran late.
#[inline]
pub fn take_forced_out() -> bool {
    STEP_FORCED_OUT[cur_core()].swap(false, Ordering::AcqRel)
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

/// Per-core step window for a platform that checks the deadline after the
/// step against a free-running counter: where the counter stood when the step
/// was armed, and the deadline in counter ticks. Per core, because each core
/// arms and checks its own steps.
static WINDOW_START: [AtomicU64; MAX_STEP_GUARD_CORES] =
    [const { AtomicU64::new(0) }; MAX_STEP_GUARD_CORES];
static WINDOW_TICKS: [AtomicU64; MAX_STEP_GUARD_CORES] =
    [const { AtomicU64::new(0) }; MAX_STEP_GUARD_CORES];

/// Record this core's step window. Called by platform arm.
pub fn set_window(start: u64, deadline_ticks: u64) {
    let c = cur_core();
    WINDOW_START[c].store(start, Ordering::Relaxed);
    WINDOW_TICKS[c].store(deadline_ticks, Ordering::Relaxed);
}

/// This core's step window, `(start, deadline_ticks)`. Called by platform
/// post-check, on the core that armed it.
pub fn window() -> (u64, u64) {
    let c = cur_core();
    (
        WINDOW_START[c].load(Ordering::Relaxed),
        WINDOW_TICKS[c].load(Ordering::Relaxed),
    )
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
    STEP_FORCED_OUT[cur_core()].store(false, Ordering::Release);
    GUARDED_MODULE[cur_core()].store(
        crate::kernel::exec::scheduler::current_module_id(),
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
/// Wire layout (16 bytes):
///   bytes 0-1:   module_idx (u16 LE)
///   bytes 2-3:   caused_by (u16 LE) — module index of the upstream that
///                faulted within the cascade window, or `NO_MODULE` (0xFFFF)
///                if independent.
///   byte 4:      fault_kind
///   byte 5:      0
///   bytes 6-7:   fault_count (u16 LE)
///   bytes 8-11:  tick (u32 LE)
///   bytes 12-13: restart_count (u16 LE)
///   bytes 14-15: 0
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FaultRecord {
    /// Module index (0..MAX_MODULES).
    pub module_idx: ModuleId,
    /// Cascade origin — upstream module index that faulted within
    /// the cascade window (ms) of this fault, or `NO_MODULE` for independent.
    pub caused_by: ModuleId,
    /// Fault type (fault_type::*).
    pub fault_kind: u8,
    /// Cumulative fault count for this module after this event.
    pub fault_count: u16,
    /// Tick at which the fault was observed.
    pub tick: u32,
    /// Cumulative restart count for this module after this event.
    pub restart_count: u16,
}

impl FaultRecord {
    pub const SIZE: usize = 16;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        b[0..2].copy_from_slice(&self.module_idx.to_le_bytes());
        b[2..4].copy_from_slice(&self.caused_by.to_le_bytes());
        b[4] = self.fault_kind;
        b[6..8].copy_from_slice(&self.fault_count.to_le_bytes());
        b[8..12].copy_from_slice(&self.tick.to_le_bytes());
        b[12..14].copy_from_slice(&self.restart_count.to_le_bytes());
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
// (`scheduler::fault::fault`). ISRs only set
// a pending flag; they never touch this ring directly.
unsafe impl Sync for FaultRing {}

static FAULT_RING: FaultRing = FaultRing {
    records: UnsafeCell::new(
        [FaultRecord {
            module_idx: 0,
            caused_by: NO_MODULE,
            fault_kind: 0,
            fault_count: 0,
            tick: 0,
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
    // Emit on the host-facing log transport so `fluxor rig monitor` can
    // parse faults without a second channel — operators see the cascade
    // origin alongside the regular counters without decoding the binary
    // FaultRecord stream separately.
    log::info!(
        "MON_FAULT mod={} kind={} fault_count={} restart_count={} caused_by={} tick={}",
        rec.module_idx,
        rec.fault_kind,
        rec.fault_count,
        rec.restart_count,
        rec.caused_by,
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
        crate::kernel::ipc::event::event_signal_from_isr(eh);
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
