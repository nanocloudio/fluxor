//! The interrupt execution modes: what `timer` and `irq` domains share.
//!
//! A domain runs in one of four execution modes (`ExecMode`). `tick` and
//! `poll` are cooperative: their modules step on the scheduler thread with
//! the full syscall surface. `timer` and `irq` are the interrupt family:
//!
//! - **`timer`** ([`super::timer`]): the domain's modules are stepped at its
//!   fixed cadence under the interrupt contract. On RP a hardware alarm
//!   fires the handler; on bcm2712 the tick domain's loop polls it.
//! - **`irq`** ([`super::irq`]): each module is bound to a hardware IRQ and
//!   its `module_isr_entry` runs from that interrupt.
//!
//! ## Constraints
//!
//! Interrupt-mode modules communicate exclusively via bridge channels.
//! No `provider_call`, no `channel_read` / `channel_write`, no heap
//! operations. The handler calls the module's step/entry function
//! directly — no syscall dispatch overhead.
//!
//! ## Dispatch gate
//!
//! Both handlers step modules only while dispatch is open. Graph preparation
//! closes it ([`close_dispatch`]) before it resizes the kernel tables, and
//! waits out every handler already past the gate, on any core; dispatch
//! opens again when the new graph registers an interrupt-mode module. A
//! handler raises an in-flight count and then reads the gate, and the close
//! stores the gate and then reads the count, all four accesses sequentially
//! consistent: of a handler and a close that race, either the handler sees
//! the gate closed or the close sees the handler in flight.
//!
//! ## Cycle budgeting
//!
//! Each interrupt-mode module declares a cycle budget. The handler measures
//! actual cycles and tracks overruns. The `INTERRUPT_METRICS` syscall
//! (`monitor::INTERRUPT_METRICS`) exposes per-module stats.
//!
//! ## Faults
//!
//! A handler does no fault work in interrupt context. A step that answers
//! `Done` or an error, or (unless the module's policy is `Tolerate`) runs
//! past its cycle budget, latches the outcome in its slot, stops the slot's
//! dispatch at once and raises [`FAULT_PENDING`]; an `irq` slot's line is
//! masked at the controller (`hal::irq_mask`, one register write), so a
//! level-triggered line cannot refire while its binding stays. The module's
//! own domain pass takes the latch on the scheduler thread ([`take_faults`])
//! and applies the module's fault policy there. Nothing in interrupt context
//! logs or touches a scheduler table.

use fluxor_contracts::boot_config::ExecMode;
use portable_atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};

use super::{irq, timer};
use crate::kernel::exec::scheduler::ModuleId;

/// Maximum number of bridge connections per interrupt-mode module.
pub(super) const MAX_BRIDGES: usize = 4;

/// Maximum bridge endpoints per interrupt-mode module (exposed for the
/// module-facing `SELF_BRIDGES` ABI buffer sizing).
pub const MODULE_MAX_BRIDGES: usize = MAX_BRIDGES;

// ============================================================================
// Metrics
// ============================================================================

/// Per-module metrics collected in interrupt context.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InterruptMetrics {
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

impl InterruptMetrics {
    /// The `INTERRUPT_METRICS` answer: the six fields as `u32` LE, in order.
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        let fields = [
            self.total_cycles_lo,
            self.total_cycles_hi,
            self.max_cycles,
            self.invocations,
            self.overruns,
            self.budget_cycles,
        ];
        for (chunk, v) in out.chunks_exact_mut(4).zip(fields) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
        out
    }

    pub(super) const fn new() -> Self {
        Self {
            total_cycles_lo: 0,
            total_cycles_hi: 0,
            max_cycles: 0,
            invocations: 0,
            overruns: 0,
            budget_cycles: 0,
        }
    }

    /// Add a cycle measurement. Returns whether it overran the budget.
    #[inline]
    pub(super) fn record(&mut self, cycles: u32) -> bool {
        // 64-bit add using two 32-bit halves (no 64-bit ops in interrupt context)
        let new_lo = self.total_cycles_lo.wrapping_add(cycles);
        if new_lo < self.total_cycles_lo {
            self.total_cycles_hi = self.total_cycles_hi.wrapping_add(1);
        }
        self.total_cycles_lo = new_lo;
        if cycles > self.max_cycles {
            self.max_cycles = cycles;
        }
        self.invocations = self.invocations.wrapping_add(1);
        let overrun = cycles > self.budget_cycles && self.budget_cycles > 0;
        if overrun {
            self.overruns = self.overruns.wrapping_add(1);
        }
        overrun
    }
}

// ============================================================================
// Slot latch
// ============================================================================

/// No latched outcome.
const PENDING_NONE: u8 = 0;
/// The step returned an error; the code is in `pending_rc`.
const PENDING_ERROR: u8 = 1;
/// The step returned `Done`.
const PENDING_DONE: u8 = 2;
/// The step ran past its cycle budget.
const PENDING_OVERRUN: u8 = 3;

/// Raised by a handler that latched an outcome in any slot; lowered by
/// [`take_faults`] once no slot remains pending.
static FAULT_PENDING: AtomicBool = AtomicBool::new(false);

/// A slot's dispatch state, shared by both kinds of slot: whether the
/// handler dispatches it, and the outcome it latched for the scheduler
/// thread.
#[repr(C)]
pub(super) struct SlotLatch {
    /// The handler dispatches the slot. Lowered by the handler when it
    /// latches an outcome; raised only by registration.
    active: AtomicBool,
    /// `PENDING_*`: what the handler latched.
    pending: AtomicU8,
    /// The error code of a `PENDING_ERROR`.
    pending_rc: AtomicI32,
    /// The module's policy is `Tolerate`: a budget overrun is telemetry
    /// only. Written by registration while the slot is inactive.
    tolerate_overrun: bool,
}

impl SlotLatch {
    pub(super) const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            pending: AtomicU8::new(PENDING_NONE),
            pending_rc: AtomicI32::new(0),
            tolerate_overrun: false,
        }
    }

    #[inline(always)]
    pub(super) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Classify one dispatch's step answer and budget check; latch any
    /// outcome that ends the module's dispatch. Interrupt-safe: atomics only.
    /// `true` when an outcome latched.
    #[inline(always)]
    pub(super) fn settle(&self, rc: i32, overrun: bool) -> bool {
        use crate::abi::kernel_abi::step_return;
        let (kind, code) = match rc {
            step_return::CONTINUE | step_return::BURST | step_return::READY => {
                if !overrun || self.tolerate_overrun {
                    return false;
                }
                (PENDING_OVERRUN, 0)
            }
            step_return::DONE => (PENDING_DONE, 0),
            _ => (PENDING_ERROR, rc),
        };
        self.active.store(false, Ordering::Release);
        self.pending_rc.store(code, Ordering::Relaxed);
        self.pending.store(kind, Ordering::Release);
        FAULT_PENDING.store(true, Ordering::SeqCst);
        true
    }

    /// Ready the slot for dispatch: clear any latch, take the module's
    /// fault policy, and open dispatch.
    pub(super) fn arm(&mut self, module_index: ModuleId) {
        self.pending.store(PENDING_NONE, Ordering::Relaxed);
        self.pending_rc.store(0, Ordering::Relaxed);
        self.tolerate_overrun = tolerates_overrun(module_index);
        self.active.store(true, Ordering::Release);
        open_dispatch();
    }
}

/// Whether `module_index`'s fault policy tolerates a budget overrun.
fn tolerates_overrun(module_index: ModuleId) -> bool {
    crate::kernel::exec::scheduler::module_fault_info(module_index as usize)
        .is_some_and(|fi| fi.policy == crate::kernel::exec::step_guard::FaultPolicy::Tolerate)
}

// ============================================================================
// Dispatch gate
// ============================================================================

/// Whether the handlers may step their modules. Closed while a graph is
/// prepared ([`close_dispatch`]), so no interrupt-mode module runs — and
/// reaches a kernel table through a syscall's admission check — while the
/// tables are resized; opened again as the new graph registers its modules.
static DISPATCH_OPEN: AtomicBool = AtomicBool::new(true);

/// Handlers between their entry check and their return, on any core.
static IN_FLIGHT: AtomicU32 = AtomicU32::new(0);

/// A handler's entry: `false` when dispatch is closed, and then the handler
/// steps nothing. Paired with [`leave`] when it returns `true`.
///
/// The count is raised before the gate is read, and [`close_dispatch`]
/// closes the gate before it reads the count, both sequentially consistent:
/// either the handler sees the gate closed, or the closer sees the handler
/// in flight and waits for it.
#[inline(always)]
pub(super) fn enter() -> bool {
    IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
    if DISPATCH_OPEN.load(Ordering::SeqCst) {
        true
    } else {
        IN_FLIGHT.fetch_sub(1, Ordering::Release);
        false
    }
}

#[inline(always)]
pub(super) fn leave() {
    IN_FLIGHT.fetch_sub(1, Ordering::Release);
}

/// Stop the `timer` and `irq` handlers stepping modules, and wait until
/// every handler already stepping one, on any core, has returned. From the
/// return on, no interrupt-mode module code runs until a module is
/// registered again. Called from the scheduler (never from a handler), when
/// a graph is prepared: an `irq` module's interrupt is delivered to its
/// domain's core, which the reconfigure quiesce parks but does not mask.
pub fn close_dispatch() {
    DISPATCH_OPEN.store(false, Ordering::SeqCst);
    while IN_FLIGHT.load(Ordering::SeqCst) != 0 {
        core::hint::spin_loop();
    }
}

/// Let the handlers step their modules again.
fn open_dispatch() {
    DISPATCH_OPEN.store(true, Ordering::SeqCst);
}

// ============================================================================
// Registration helpers (scheduler thread)
// ============================================================================

/// Copy up to `MAX_BRIDGES` bridge indices, `-1` past the end.
pub(super) fn bridge_row(src: &[i8]) -> [i8; MAX_BRIDGES] {
    let mut row = [-1i8; MAX_BRIDGES];
    for (d, s) in row.iter_mut().zip(src) {
        *d = *s;
    }
    row
}

/// The slot `module_index` held before its dispatch stopped, else the next
/// free one; `None` when every slot is taken. A restarted module gets its
/// own slot back, so its metrics carry on.
pub(super) fn claim_slot<T>(
    slots: &mut [T],
    count: &mut u8,
    held_by: impl Fn(&T) -> Option<ModuleId>,
    module_index: ModuleId,
) -> Option<usize> {
    let n = *count as usize;
    if let Some(i) = slots[..n]
        .iter()
        .position(|s| held_by(s) == Some(module_index))
    {
        return Some(i);
    }
    if n >= slots.len() {
        return None;
    }
    *count += 1;
    Some(n)
}

/// Reset every interrupt-mode slot (called on graph reconfigure). Dispatch
/// stays closed until the next graph registers a module.
pub fn reset_all() {
    timer::stop();
    close_dispatch();
    // SAFETY: `timer::stop()` above drops the active flag and
    // `close_dispatch` waits out every handler in flight, on any core; no
    // handler steps a slot from here, so the slot tables are exclusively
    // accessible.
    unsafe {
        timer::clear_slots();
        irq::clear_slots();
    }
    FAULT_PENDING.store(false, Ordering::Release);
}

// ============================================================================
// Queries (scheduler thread)
// ============================================================================

/// The metrics of slot `slot` of the interrupt mode `mode`, or `None` for a
/// cooperative mode or a slot that is not dispatching.
pub fn query_metrics(mode: ExecMode, slot: u8) -> Option<InterruptMetrics> {
    match mode {
        ExecMode::Timer => timer::slot_metrics(slot as usize),
        ExecMode::Irq => irq::slot_metrics(slot as usize),
        ExecMode::Tick | ExecMode::Poll => None,
    }
}

/// The number of registered `(timer, irq)` modules.
pub fn module_counts() -> (u8, u8) {
    (timer::count(), irq::count())
}

/// Look up the bridge slot indices wired for `module_index`, in either
/// interrupt mode. Returns `(in_bridges, out_bridges)` — each a
/// `[i8; MAX_BRIDGES]` of global bridge-table slot indices (as allocated by
/// `wire_isr_bridges`), `-1` for unused entries — or `None` if the module is
/// not registered in either mode.
///
/// This is the kernel side of the module-facing bridge ABI: an
/// interrupt-mode module enumerates its own bridge endpoints via the
/// `SELF_BRIDGES` opcode, then reads/writes them with the bridge
/// `WRITE`/`READ`/`POLL`/`INFO` opcodes (which are exempt from the
/// interrupt-context syscall deny because the underlying `IsrRing` ops are
/// lock-free and allocation-free). This is how a PIC module reaches its
/// bridges from `module_step` / `module_isr_entry` without routing through
/// `provider_call`, which that gate denies for interrupt-mode callers.
pub fn module_bridge_slots(
    module_index: ModuleId,
) -> Option<([i8; MAX_BRIDGES], [i8; MAX_BRIDGES])> {
    irq::bridge_slots(module_index).or_else(|| timer::bridge_slots(module_index))
}

// ============================================================================
// Fault drain (scheduler thread)
// ============================================================================

/// An outcome a handler latched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsrOutcome {
    /// The step returned `Done`.
    Done,
    /// The step returned this error code.
    Error(i32),
    /// The step ran past its cycle budget.
    Overrun,
}

/// One latched outcome, taken from its slot.
#[derive(Clone, Copy, Debug)]
pub struct IsrFault {
    pub module_index: ModuleId,
    pub outcome: IsrOutcome,
    /// The IRQ an `irq` slot is bound to; `None` for a `timer` slot.
    pub irq: Option<u16>,
}

/// The faults [`take_faults`] took.
pub struct IsrFaults {
    items: [Option<IsrFault>; timer::MAX_TIMER_MODULES + irq::MAX_IRQ_MODULES],
}

impl IsrFaults {
    pub fn iter(&self) -> impl Iterator<Item = IsrFault> + '_ {
        self.items.iter().flatten().copied()
    }
}

/// Take from its slot every latched outcome whose module `mine` accepts,
/// clearing the latch; the slot stays inactive until registered again.
/// One relaxed load when nothing is latched. [`FAULT_PENDING`] is lowered
/// before the scan and raised again for a latch left to another caller, so
/// a latch set during the scan is never lost.
pub fn take_faults(mine: impl Fn(ModuleId) -> bool) -> IsrFaults {
    let mut out = IsrFaults {
        items: [None; timer::MAX_TIMER_MODULES + irq::MAX_IRQ_MODULES],
    };
    if !FAULT_PENDING.load(Ordering::Relaxed) {
        return out;
    }
    FAULT_PENDING.store(false, Ordering::SeqCst);
    let mut left = false;
    let mut n = 0;
    let mut take = |latch: &SlotLatch, module_index: ModuleId, irq: Option<u16>| {
        let kind = latch.pending.load(Ordering::Acquire);
        if kind == PENDING_NONE {
            return;
        }
        if !mine(module_index) {
            left = true;
            return;
        }
        let outcome = match kind {
            PENDING_DONE => IsrOutcome::Done,
            PENDING_ERROR => IsrOutcome::Error(latch.pending_rc.load(Ordering::Relaxed)),
            _ => IsrOutcome::Overrun,
        };
        latch.pending.store(PENDING_NONE, Ordering::Relaxed);
        out.items[n] = Some(IsrFault {
            module_index,
            outcome,
            irq,
        });
        n += 1;
    };
    timer::each_latch(|latch, module_index| take(latch, module_index, None));
    irq::each_latch(|latch, module_index, line| take(latch, module_index, Some(line)));
    if left {
        FAULT_PENDING.store(true, Ordering::SeqCst);
    }
    out
}

// ============================================================================
// INTERRUPT_METRICS syscall handler (`monitor::INTERRUPT_METRICS`)
// ============================================================================

/// Handle the `INTERRUPT_METRICS` syscall.
///
/// arg layout:
///   [0]: the `ExecMode` byte of an interrupt mode (`Timer` or `Irq`)
///   [1]: slot index
///
/// On success, writes `InterruptMetrics` (24 bytes) to the arg buffer.
/// Returns bytes written on success, or negative errno; a cooperative or
/// unknown mode byte is `EINVAL`.
pub fn interrupt_metrics_dispatch(arg: &mut [u8]) -> i32 {
    let (mode, slot) = match *arg {
        [mode, slot, ..] => (mode, slot),
        _ => return crate::kernel::sys::errno::EINVAL,
    };
    let Some(mode) = ExecMode::from_u8(mode).filter(|m| m.is_interrupt()) else {
        return crate::kernel::sys::errno::EINVAL;
    };
    match query_metrics(mode, slot) {
        Some(metrics) => {
            let bytes = metrics.to_bytes();
            match arg.get_mut(..bytes.len()) {
                Some(out) => {
                    out.copy_from_slice(&bytes);
                    bytes.len() as i32
                }
                None => crate::kernel::sys::errno::EINVAL,
            }
        }
        None => crate::kernel::sys::errno::EINVAL,
    }
}
