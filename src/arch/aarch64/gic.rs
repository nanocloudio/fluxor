//! GICv2 distributor + CPU interface + IRQ binding state.
//!
//! The controller's addresses and the timer's PPI are facts of the machine,
//! not of the architecture: a Pi 5's GIC-400 sits at one address, a QEMU
//! `virt` machine's GICv2 at another. The platform tells this module
//! before anything else touches the controller ([`configure`]); every
//! register access reads the configured base, so the same code serves
//! every machine.
//!
//! Which CPU-interface bit reaches which core is learned, not assumed: each
//! core reads its own from the distributor at its GIC init.
//!
//! Up to [`MAX_IRQ_BINDINGS`] hardware IRQs can be bound to fluxor event
//! handles via [`irq_bind`]; the matching ISR fires `event_signal_from_isr`
//! when the IRQ asserts. A binding whose handle is [`EVENT_HANDLE_MUX`]
//! routes the IRQ into the platform's registered multiplexer instead
//! ([`set_irq_mux`]) — a PCIe MSI mux that services many vectors through one
//! SPI, for instance.

#![allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]

use core::sync::atomic::{AtomicU32, AtomicU8, AtomicUsize, Ordering};

use super::exception::MAX_CORES;

static GICD: AtomicUsize = AtomicUsize::new(0);
static GICC: AtomicUsize = AtomicUsize::new(0);
static TIMER_PPI: AtomicU32 = AtomicU32::new(0);

/// Each core's GIC CPU-interface bit, as the distributor reports it to that
/// core (`GICD_ITARGETSR0`, banked); `0` until the core has run [`init`]
/// or [`init_secondary`].
static CPU_INTERFACE: [AtomicU8; MAX_CORES] = [const { AtomicU8::new(0) }; MAX_CORES];

// Distributor registers (GICv2 architecture specification, 4.3).
const GICD_CTLR: usize = 0x000;
const GICD_ISENABLER: usize = 0x100;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ITARGETSR: usize = 0x800;
const GICD_SGIR: usize = 0xF00;
// CPU-interface registers (4.4).
const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_IAR: usize = 0x00C;
const GICC_EOIR: usize = 0x010;

/// The highest INTID the distributor can be programmed with; 1020–1023
/// are the special (spurious) IDs.
pub const MAX_INTID: u32 = 1019;

/// Name the controller: distributor base, CPU-interface base, and the PPI
/// the generic timer raises. Called once by the platform at boot, before
/// [`init`] and before the first interrupt can be taken.
pub fn configure(gicd_base: usize, gicc_base: usize, timer_ppi: u32) {
    GICD.store(gicd_base, Ordering::Relaxed);
    GICC.store(gicc_base, Ordering::Relaxed);
    TIMER_PPI.store(timer_ppi, Ordering::Relaxed);
}

#[inline(always)]
pub fn gicd_base() -> usize {
    GICD.load(Ordering::Relaxed)
}

#[inline(always)]
pub fn gicc_base() -> usize {
    GICC.load(Ordering::Relaxed)
}

/// The PPI the generic timer raises on this machine.
#[inline(always)]
pub fn timer_ppi() -> u32 {
    TIMER_PPI.load(Ordering::Relaxed)
}

/// GICC_IAR: acknowledge the highest-priority pending interrupt.
#[inline(always)]
pub fn gicc_iar() -> *mut u32 {
    (gicc_base() + GICC_IAR) as *mut u32
}

/// GICC_EOIR: end of interrupt.
#[inline(always)]
pub fn gicc_eoir() -> *mut u32 {
    (gicc_base() + GICC_EOIR) as *mut u32
}

/// The `CPUTargetList` / `ITARGETSR` bit that reaches core `core`: what the
/// distributor told that core at its GIC init. Before then, and on a
/// uniprocessor GIC (where `ITARGETSR0` reads as zero), `1 << core`.
pub fn cpu_interface_mask(core: usize) -> u8 {
    let learned = CPU_INTERFACE
        .get(core)
        .map_or(0, |m| m.load(Ordering::Relaxed));
    if learned != 0 {
        learned
    } else {
        1u8 << (core & 0x7)
    }
}

/// Record the calling core's CPU-interface bit: any of the first eight
/// `ITARGETSR` bytes reads back as the reading core's own interface.
unsafe fn learn_cpu_interface(gicd: usize) {
    let mask = core::ptr::read_volatile((gicd + GICD_ITARGETSR) as *const u8);
    if let Some(slot) = CPU_INTERFACE.get(super::cpu::current_core_id() as usize) {
        slot.store(mask, Ordering::Relaxed);
    }
}

/// SGI id used as the WFI wake doorbell. A core idles on **WFI**, which a
/// global `SEV` does not break (SEV wakes WFE), so an `event_signal` or a
/// cross-domain push aimed at an idle core would otherwise wait for its
/// next timer tick. An SGI is a real IRQ, so it breaks WFI; the IRQ handler
/// EOIs it (it matches no binding) and the idle loop re-evaluates.
pub const WAKE_SGI: u32 = 0;

/// Send Software-Generated Interrupt `sgi_id` to every core, the sender
/// included (`TargetListFilter = 0b00`, `CPUTargetList = 0xFF`; bits for
/// CPU interfaces that do not exist are ignored), so every WFI-parked core
/// wakes.
///
/// # Safety
/// A single MMIO write to the configured, mapped distributor.
#[inline(always)]
pub unsafe fn send_sgi_all(sgi_id: u32) {
    // [25:24] TargetListFilter, [23:16] CPUTargetList, [3:0] SGIINTID.
    let val = (0xFF << 16) | (sgi_id & 0xF);
    core::ptr::write_volatile((gicd_base() + GICD_SGIR) as *mut u32, val);
}

/// Send SGI `sgi_id` to core `core` alone — the core a Tier-2 IRQ-owned
/// domain runs on, for instance.
///
/// # Safety
/// A single MMIO write to the configured, mapped distributor.
#[inline(always)]
pub unsafe fn send_sgi(core: u32, sgi_id: u32) {
    let target = u32::from(cpu_interface_mask(core as usize));
    let val = (target << 16) | (sgi_id & 0xF);
    core::ptr::write_volatile((gicd_base() + GICD_SGIR) as *mut u32, val);
}

/// IRQ-to-event binding table. When a bound IRQ fires, the kernel signals the
/// associated event via `event_signal_from_isr` (ISR-safe, lock-free).
pub const MAX_IRQ_BINDINGS: usize = 4;
pub struct IrqBinding {
    /// GIC INTID (an SPI is 32 + its number: SPI 16 is INTID 48).
    pub irq: u32,
    /// The event to signal, or a sentinel ([`EVENT_HANDLE_MUX`], the
    /// Tier-2 dispatch handle).
    pub event_handle: i32,
    /// A virtio-mmio device to acknowledge (`InterruptStatus` read back
    /// into `InterruptACK`), or 0.
    pub mmio_base: usize,
}
pub static mut IRQ_BINDINGS: [IrqBinding; MAX_IRQ_BINDINGS] = [
    IrqBinding {
        irq: 0,
        event_handle: -1,
        mmio_base: 0,
    },
    IrqBinding {
        irq: 0,
        event_handle: -1,
        mmio_base: 0,
    },
    IrqBinding {
        irq: 0,
        event_handle: -1,
        mmio_base: 0,
    },
    IrqBinding {
        irq: 0,
        event_handle: -1,
        mmio_base: 0,
    },
];
pub static mut IRQ_BINDING_COUNT: usize = 0;

/// Sentinel event_handle that tells the IRQ handler to call the platform's
/// multiplexer ([`set_irq_mux`]) instead of signalling a single event: one
/// SPI behind which a device-side mux (a PCIe MSI controller) holds many
/// vectors.
pub const EVENT_HANDLE_MUX: i32 = -2;

static mut IRQ_MUX: Option<fn()> = None;

/// Register the multiplexer an [`EVENT_HANDLE_MUX`] binding fans out
/// through. Boot-time, scheduler-thread-only, like the bindings.
pub fn set_irq_mux(mux: fn()) {
    // SAFETY: set once at boot before the binding that uses it exists, by
    // the thread that owns the binding table.
    unsafe { IRQ_MUX = Some(mux) };
}

/// The registered multiplexer, for the IRQ handler.
#[inline(always)]
pub(crate) fn irq_mux() -> Option<fn()> {
    // SAFETY: read on the IRQ path after boot; the writer ran before the
    // first bound interrupt could fire.
    unsafe { IRQ_MUX }
}

/// Bind an event to a hardware IRQ and enable it in the distributor.
/// `mmio_base`: if nonzero, the ISR acknowledges a virtio-mmio device by
/// reading `InterruptStatus` (offset 0x60) and writing it to
/// `InterruptACK` (0x64).
/// `target_core`: the core the distributor delivers this SPI to
/// (`GICD_ITARGETSR`) — for a Tier-2 IRQ the core its owning domain runs
/// on, otherwise core 0. For an SGI or PPI (INTID < 32) the enable and
/// priority registers are banked per core, so this programs the calling
/// core's copy, and `ITARGETSR` is read-only.
///
/// Returns 0 on success, negative errno on failure.
pub fn irq_bind(irq: u32, event_handle: i32, mmio_base: usize, target_core: u8) -> i32 {
    // 1020..=1023 are special IDs and must never be programmed into the
    // distributor (the validator rejects them at build time; this is the
    // runtime backstop). A larger value would also index ISENABLER,
    // IPRIORITYR and ITARGETSR past their banks.
    if irq > MAX_INTID {
        return crate::kernel::sys::errno::EINVAL;
    }
    let gicd = gicd_base();
    // SAFETY: IRQ_BINDINGS / IRQ_BINDING_COUNT are scheduler-thread-only
    // and only grow at boot/configure time; `idx` is range-checked above.
    // The distributor is mapped by the boot page tables.
    unsafe {
        if IRQ_BINDING_COUNT >= MAX_IRQ_BINDINGS {
            return crate::kernel::sys::errno::ENOMEM;
        }
        let idx = IRQ_BINDING_COUNT;
        IRQ_BINDINGS[idx] = IrqBinding {
            irq,
            event_handle,
            mmio_base,
        };
        IRQ_BINDING_COUNT = idx + 1;

        // ISENABLER<n>: one bit per INTID, write-1-to-set (zeros are
        // ignored, so no read-modify-write).
        let reg = gicd + GICD_ISENABLER + (irq as usize / 32) * 4;
        core::ptr::write_volatile(reg as *mut u32, 1u32 << (irq % 32));
        // IPRIORITYR: a byte per INTID; 0 is the highest priority.
        core::ptr::write_volatile((gicd + GICD_IPRIORITYR + irq as usize) as *mut u8, 0);
        // ITARGETSR: a byte per INTID, one bit per CPU interface.
        let target = cpu_interface_mask(target_core as usize);
        core::ptr::write_volatile((gicd + GICD_ITARGETSR + irq as usize) as *mut u8, target);

        log::info!(
            "[irq] bind irq={irq} event={event_handle} mmio={mmio_base:#x} core={target_core}"
        );
    }
    0
}

/// Enable the distributor and this core's CPU interface, with the timer
/// PPI at the highest priority and the SGIs enabled.
///
/// # Safety
/// MMIO writes to the configured GIC; the bases must be mapped and
/// [`configure`] must have run.
pub unsafe fn init() {
    let gicd = gicd_base();
    core::ptr::write_volatile((gicd + GICD_CTLR) as *mut u32, 1);
    init_secondary();
}

/// Bring up the calling core's banked GIC state and CPU interface: its
/// interface bit, the timer PPI (enabled, priority 0) and the SGIs —
/// whether SGIs can be disabled at all is IMPLEMENTATION DEFINED, so they
/// are enabled rather than assumed — then the priority mask and the
/// interface itself. Each core runs this for itself; [`init`] runs it for
/// the boot core.
///
/// # Safety
/// As [`init`].
pub unsafe fn init_secondary() {
    let gicd = gicd_base();
    let gicc = gicc_base();
    let ppi = timer_ppi();
    learn_cpu_interface(gicd);
    core::ptr::write_volatile((gicd + GICD_ISENABLER) as *mut u32, 0xFFFF | (1u32 << ppi));
    core::ptr::write_volatile((gicd + GICD_IPRIORITYR + ppi as usize) as *mut u8, 0);
    core::ptr::write_volatile((gicc + GICC_PMR) as *mut u32, 0xFF); // unmask every priority
    core::ptr::write_volatile((gicc + GICC_CTLR) as *mut u32, 1);
}
