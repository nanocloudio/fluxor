//! GICv2 distributor + CPU interface + IRQ binding state.
//!
//! The controller's addresses and the timer's PPI are facts of the machine,
//! not of the architecture: a Pi 5's GIC-400 sits at one address, a QEMU
//! `virt` machine's GICv2 at another, and a UEFI machine says where in its
//! MADT. The platform tells this module before anything else touches the
//! controller ([`configure`]); every register access reads the configured
//! base, so the same code serves every machine.
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

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

static GICD: AtomicUsize = AtomicUsize::new(0);
static GICC: AtomicUsize = AtomicUsize::new(0);
static TIMER_PPI: AtomicU32 = AtomicU32::new(0);

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
    (gicc_base() + 0x00C) as *mut u32
}

/// GICC_EOIR: end of interrupt.
#[inline(always)]
pub fn gicc_eoir() -> *mut u32 {
    (gicc_base() + 0x010) as *mut u32
}

/// GICv2 Software-Generated-Interrupt register (GICD_SGIR).
#[inline(always)]
fn gicd_sgir() -> *mut u32 {
    (gicd_base() + 0xF00) as *mut u32
}

/// SGI id used as the WFI wake doorbell. Tier 0/1a idle on **WFI**, which a
/// global `SEV` does NOT break (SEV wakes WFE). Once mechanism (a) widens the
/// idle deadline to `tick_max_us`, an intra-core `event_signal` or a
/// cross-domain SPSC push can otherwise be delayed to the backstop. An SGI is
/// a real IRQ, so it breaks WFI; the IRQ handler simply EOIs it (it matches no
/// binding) and the loop re-evaluates. SGI ids 0-15 are always enabled in
/// GICv2, so no `ISENABLER` setup is needed.
pub const WAKE_SGI: u32 = 0;

/// Send Software-Generated-Interrupt `sgi_id` to ALL cores (CPUTargetList =
/// 0xF, TargetListFilter = 00 "use the target list"), so every WFI-parked core
/// wakes — matching the broadcast semantics of the existing global `SEV`.
///
/// # Safety
/// Performs a single MMIO write to the (boot-mapped) GIC distributor.
#[inline(always)]
pub unsafe fn send_sgi_all(sgi_id: u32) {
    // [25:24] filter=00, [23:16] CPUTargetList=0xF (cores 0-3), [3:0] SGIINTID.
    let val = (0xF << 16) | (sgi_id & 0xF);
    core::ptr::write_volatile(gicd_sgir(), val);
}

/// Send SGI `sgi_id` to a single target core (`CPUTargetList = 1<<core`,
/// TargetListFilter = 00). Drives a Tier-2 IRQ-owned module on a dedicated
/// secondary core from core 0 (the IRQ a Tier-2 domain owns).
///
/// # Safety
/// Single MMIO write to the (boot-mapped) GIC distributor.
#[inline(always)]
pub unsafe fn send_sgi(core: u32, sgi_id: u32) {
    let val = ((1u32 << (core & 0x7)) << 16) | (sgi_id & 0xF);
    core::ptr::write_volatile(gicd_sgir(), val);
}

/// IRQ-to-event binding table. When a bound IRQ fires, the kernel signals the
/// associated event via event_signal_from_isr (ISR-safe, lock-free).
/// Up to 4 bindings (virtio devices, GPIO, etc.).
pub const MAX_IRQ_BINDINGS: usize = 4;
pub struct IrqBinding {
    pub irq: u32,          // GIC interrupt ID (e.g. 48 for virtio SPI 16)
    pub event_handle: i32, // Fluxor event handle to signal
    pub mmio_base: usize, // If nonzero, ACK device by reading INTERRUPT_STATUS and writing INTERRUPT_ACK
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

/// Bind an event to a hardware IRQ. Enables the IRQ in the GIC distributor.
/// `mmio_base`: if nonzero, the ISR reads offset 0x60 (INTERRUPT_STATUS) and
/// writes offset 0x64 (INTERRUPT_ACK) to ACK virtio-mmio devices.
/// `target_core`: the CPU the GIC distributor should deliver this SPI to
/// (GICD_ITARGETSR). For a Tier-2 IRQ this is the core parked on the owning
/// domain's `exec_mode==4` run loop (domain id == core id on this platform);
/// otherwise core 0. Clamped to the 8 ITARGETSR target bits.
///
/// Returns 0 on success, negative errno on failure.
pub fn irq_bind(irq: u32, event_handle: i32, mmio_base: usize, target_core: u8) -> i32 {
    // GIC-400 INTIDs are 0..=1019; 1020..=1023 are reserved/special and must
    // never be programmed into the distributor (the validator rejects these at
    // build time — this is the runtime backstop). A larger value would also
    // index ISENABLER/IPRIORITYR/ITARGETSR past their banks.
    if irq > 1019 {
        return crate::kernel::sys::errno::EINVAL;
    }
    let gicd = gicd_base();
    // SAFETY: IRQ_BINDINGS / IRQ_BINDING_COUNT are scheduler-thread-only
    // and only grow at boot/configure time; `idx` is range-checked above.
    // GICD register addresses are fixed MMIO mapped by the boot page tables.
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

        // Enable the SPI in the GIC distributor
        // SPIs start at IRQ 32. ISENABLER register: base + 0x100 + (irq/32)*4, bit = irq%32
        let reg = gicd + 0x100 + (irq as usize / 32) * 4;
        let bit = 1u32 << (irq % 32);
        core::ptr::write_volatile(
            reg as *mut u32,
            core::ptr::read_volatile(reg as *const u32) | bit,
        );
        // Set priority to 0 (highest)
        core::ptr::write_volatile((gicd + 0x400 + irq as usize) as *mut u8, 0);
        // Target the owning core (ITARGETSR is a byte per SPI; bit N = core N).
        // GIC-400 routes SPIs to at most 8 cores; clamp the shift so a bogus
        // core never aliases to a different target bit.
        let target = 1u8 << (target_core & 0x7);
        core::ptr::write_volatile((gicd + 0x800 + irq as usize) as *mut u8, target);

        log::info!(
            "[irq] bind irq={irq} event={event_handle} mmio={mmio_base:#x} core={target_core}"
        );
    }
    0
}

/// Enable the distributor and this core's CPU interface, with the timer PPI
/// enabled at the highest priority.
///
/// # Safety
/// MMIO writes to the configured GIC; the bases must be mapped and
/// [`configure`] must have run.
pub unsafe fn init() {
    let gicd = gicd_base();
    let gicc = gicc_base();
    let ppi = timer_ppi();
    core::ptr::write_volatile(gicd as *mut u32, 1); // GICD_CTLR: enable
    core::ptr::write_volatile((gicd + 0x100) as *mut u32, 1u32 << ppi); // ISENABLER0
    core::ptr::write_volatile((gicd + 0x400 + ppi as usize) as *mut u8, 0); // priority 0 (highest)
    core::ptr::write_volatile((gicc + 0x004) as *mut u32, 0xFF); // PMR: allow all
    core::ptr::write_volatile(gicc as *mut u32, 1); // GICC_CTLR: enable
}

/// Initialize GIC CPU interface on a secondary core.
/// Each core needs its own GICC setup for PPIs (like the timer).
///
/// # Safety
/// As [`init`].
pub unsafe fn init_secondary() {
    let gicd = gicd_base();
    let gicc = gicc_base();
    core::ptr::write_volatile((gicc + 0x004) as *mut u32, 0xFF); // PMR
    core::ptr::write_volatile(gicc as *mut u32, 1); // GICC_CTLR
                                                    // Enable timer PPI for this core
    core::ptr::write_volatile((gicd + 0x100) as *mut u32, 1u32 << timer_ppi());
}
