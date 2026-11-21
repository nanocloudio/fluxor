//! The `irq` execution mode: each module bound to a hardware IRQ, its
//! `module_isr_entry` run from that interrupt under the interrupt contract
//! ([`super::interrupt`]).

use portable_atomic::{AtomicU32, Ordering};

use super::interrupt::{
    bridge_row, claim_slot, enter, leave, InterruptMetrics, SlotLatch, MAX_BRIDGES,
};
use crate::kernel::exec::scheduler::{ModuleId, NO_MODULE};
use crate::kernel::sys::hal;

/// Maximum number of `irq` modules.
pub const MAX_IRQ_MODULES: usize = 4;

/// Sentinel `event_handle` passed to `hal::irq_bind` for an `irq` module's
/// hardware IRQ. The platform IRQ handler recognises it and dispatches the
/// IRQ into [`irq_trampoline`] (which looks the module up by IRQ number),
/// rather than treating the binding as a device→event signal. Distinct from
/// the negative event handles used elsewhere (e.g. the PCIe1-MSI mux
/// sentinel).
pub const IRQ_MODULE_EVENT: i32 = -3;

/// The interrupt entry an `irq` module exports.
/// Called from the IRQ handler. Returns i32 status (0 = ok, <0 = error).
pub type ModuleIsrEntryFn = unsafe extern "C" fn(state: *mut u8) -> i32;

/// A single `irq` module slot.
#[repr(C)]
struct IrqSlot {
    /// Interrupt entry function pointer.
    isr_entry: ModuleIsrEntryFn,
    /// Module state pointer.
    state_ptr: *mut u8,
    /// Hardware IRQ number this module handles.
    irq_number: u16,
    /// Bridge indices for input.
    in_bridges: [i8; MAX_BRIDGES],
    /// Bridge indices for output.
    out_bridges: [i8; MAX_BRIDGES],
    /// Metrics for this module.
    metrics: InterruptMetrics,
    /// Module index in the scheduler.
    module_index: ModuleId,
    /// Dispatch state and latched outcome.
    latch: SlotLatch,
}

impl IrqSlot {
    const fn empty() -> Self {
        Self {
            isr_entry: empty_isr_entry,
            state_ptr: core::ptr::null_mut(),
            irq_number: 0xFFFF,
            in_bridges: [-1; MAX_BRIDGES],
            out_bridges: [-1; MAX_BRIDGES],
            metrics: InterruptMetrics::new(),
            module_index: NO_MODULE,
            latch: SlotLatch::new(),
        }
    }
}

/// Placeholder interrupt entry for empty slots.
unsafe extern "C" fn empty_isr_entry(_state: *mut u8) -> i32 {
    0
}

/// `irq` module slots — accessed from IRQ handlers.
static mut SLOTS: [IrqSlot; MAX_IRQ_MODULES] = [const { IrqSlot::empty() }; MAX_IRQ_MODULES];

/// Number of claimed `irq` slots.
static mut COUNT: u8 = 0;

/// Cumulative count of IRQ dispatches that matched a registered module.
/// Incremented by [`irq_trampoline`]; read for the dedicated-core liveness
/// log so an `irq` domain's core that has stopped taking its IRQ is visible
/// (the count stalls while the loop's pass count keeps climbing).
static DISPATCH_COUNT: AtomicU32 = AtomicU32::new(0);

/// `irq` module registration parameters.
pub struct IrqRegistration<'a> {
    pub isr_entry: ModuleIsrEntryFn,
    pub state_ptr: *mut u8,
    pub irq_number: u16,
    pub module_index: ModuleId,
    pub budget_cycles: u32,
    pub in_bridges: &'a [i8],
    pub out_bridges: &'a [i8],
}

/// Register a module for `irq` execution, or register it again after a
/// fault stopped its dispatch. The caller binds the IRQ afterwards. The
/// module's fault policy is read here, as for `timer::register_module`.
///
/// Returns the slot index on success, or -1 if full.
///
/// Called on the scheduler thread; a slot is written only while inactive,
/// as for `timer::register_module`.
pub fn register_module(reg: IrqRegistration<'_>) -> i32 {
    // SAFETY: as in `timer::register_module`.
    unsafe {
        let slots_ptr = &raw mut SLOTS;
        let slots = &mut *slots_ptr;
        let count_ptr = &raw mut COUNT;
        let count = &mut *count_ptr;
        let held_by = |s: &IrqSlot| (!s.latch.is_active()).then_some(s.module_index);
        let Some(idx) = claim_slot(slots, count, held_by, reg.module_index) else {
            log::error!("[irq] full ({MAX_IRQ_MODULES} slots)");
            return -1;
        };
        let slot = &mut slots[idx];
        if slot.module_index != reg.module_index {
            slot.metrics = InterruptMetrics::new();
        }
        slot.isr_entry = reg.isr_entry;
        slot.state_ptr = reg.state_ptr;
        slot.irq_number = reg.irq_number;
        slot.module_index = reg.module_index;
        slot.metrics.budget_cycles = reg.budget_cycles;
        slot.in_bridges = bridge_row(reg.in_bridges);
        slot.out_bridges = bridge_row(reg.out_bridges);
        slot.latch.arm(reg.module_index);

        log::info!(
            "[irq] registered slot={} mod={} irq={} budget={}cy",
            idx,
            reg.module_index,
            reg.irq_number,
            reg.budget_cycles,
        );
        idx as i32
    }
}

/// Clear every slot.
///
/// # Safety
/// No handler may be stepping a slot: dispatch is closed
/// (`interrupt::reset_all`).
pub(super) unsafe fn clear_slots() {
    let slots = &raw mut SLOTS;
    for slot in (*slots).iter_mut() {
        *slot = IrqSlot::empty();
    }
    COUNT = 0;
}

/// The `irq` trampoline — dispatches to the module registered for
/// `irq_number` and calls its `isr_entry`.
///
/// Sets `scheduler::current_module_index` to the matching slot's module
/// index for the duration of the dispatch so the runtime EACCES gate
/// (`scheduler::deny_interrupt_mode_syscall`) fires correctly if the entry
/// inadvertently calls a forbidden syscall. The original current-module
/// pointer is restored after the step.
///
/// The entry's answer and budget check go to the slot's latch.
///
/// Returns 0 if handled, -1 if no module dispatches this IRQ.
///
/// # Safety
/// Called from interrupt context.
///
/// Never inlined: it is a root of the `irq-neon-free` gate's walk.
#[inline(never)]
pub unsafe fn irq_trampoline(irq_number: u16) -> i32 {
    if !enter() {
        return -1;
    }
    let count = COUNT as usize;
    let slots = &raw mut SLOTS;
    let saved_module = crate::kernel::exec::scheduler::current_module_index();
    for slot in (*slots).iter_mut().take(count) {
        if slot.irq_number != irq_number || !slot.latch.is_active() {
            continue;
        }

        crate::kernel::exec::scheduler::set_current_module(slot.module_index as usize);
        let before = hal::read_cycle_count();
        #[cfg(target_arch = "aarch64")]
        let rc = crate::arch::fp_frame::call_isr_entry(slot.isr_entry, slot.state_ptr);
        #[cfg(not(target_arch = "aarch64"))]
        let rc = (slot.isr_entry)(slot.state_ptr);
        let after = hal::read_cycle_count();
        let overrun = slot.metrics.record(after.wrapping_sub(before));
        if slot.latch.settle(rc, overrun) {
            // The module's dispatch has ended; a level-triggered line would
            // refire before thread context retires it, so it is masked here.
            hal::irq_mask(u32::from(irq_number), true);
        }
        DISPATCH_COUNT.fetch_add(1, Ordering::Relaxed);
        crate::kernel::exec::scheduler::set_current_module(saved_module);
        leave();
        return 0;
    }
    crate::kernel::exec::scheduler::set_current_module(saved_module);
    leave();
    -1 // No module found for this IRQ
}

/// The metrics of slot `idx`, while it dispatches.
pub(super) fn slot_metrics(idx: usize) -> Option<InterruptMetrics> {
    // SAFETY: as in `timer::slot_metrics`.
    unsafe {
        let slots_ptr = &raw const SLOTS;
        let slots = &*slots_ptr;
        (idx < COUNT as usize && slots[idx].latch.is_active()).then(|| slots[idx].metrics)
    }
}

/// The number of claimed `irq` slots.
pub(super) fn count() -> u8 {
    // SAFETY: a u8 static; aligned read.
    unsafe { COUNT }
}

/// The bridges of `module_index`'s dispatching slot.
pub(super) fn bridge_slots(
    module_index: ModuleId,
) -> Option<([i8; MAX_BRIDGES], [i8; MAX_BRIDGES])> {
    // SAFETY: as in `timer::bridge_slots`.
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

/// Call `f` with each claimed slot's latch, module and IRQ line.
pub(super) fn each_latch(mut f: impl FnMut(&SlotLatch, ModuleId, u16)) {
    // SAFETY: as in `timer::each_latch`; an `irq_number` is written only by
    // registration too.
    unsafe {
        let slots_ptr = &raw const SLOTS;
        let slots = &*slots_ptr;
        for slot in slots.iter().take(COUNT as usize) {
            f(&slot.latch, slot.module_index, slot.irq_number);
        }
    }
}

/// The cumulative count of IRQ dispatches that matched a registered module.
/// Used by the bcm2712 `irq` domain loop's liveness log.
pub fn dispatch_count() -> u32 {
    DISPATCH_COUNT.load(Ordering::Relaxed)
}
