//! GIC distributor + CPU interface + IRQ binding state, for GICv2 and GICv3.
//!
//! The version is the machine's too: a GICv2's CPU interface is a block of
//! registers, a GICv3's is system registers beside a redistributor per core,
//! so [`configure`] and [`configure_v3`] pick which one every access below
//! takes.
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
//! handles via [`irq_bind`] (an LPI an ITS raises, via [`bind_lpi`]); the
//! matching ISR fires `event_signal_from_isr` when the IRQ asserts. A binding
//! whose handle is [`EVENT_HANDLE_MUX`] routes the IRQ into the platform's
//! registered multiplexer instead ([`set_irq_mux`]) — a PCIe MSI mux that
//! services many vectors through one SPI, for instance.

#![allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]

use core::sync::atomic::{AtomicU32, AtomicU8, AtomicUsize, Ordering};

use super::exception::MAX_CORES;
use super::mmio;

static GICD: AtomicUsize = AtomicUsize::new(0);
static GICC: AtomicUsize = AtomicUsize::new(0);
static TIMER_PPI: AtomicU32 = AtomicU32::new(0);
/// The boot core's redistributor when the machine is a GICv3; 0 on a GICv2.
static GICR: AtomicUsize = AtomicUsize::new(0);
/// Each core's redistributor on a GICv3, recorded as the core runs
/// [`init_v3_cpu`]; 0 until then.
static CORE_GICR: [AtomicUsize; MAX_CORES] = [const { AtomicUsize::new(0) }; MAX_CORES];

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

// GICv3 distributor additions (GICv3 architecture specification, 12.9).
const GICD_CTLR_RWP: u32 = 1 << 31;
const GICD_CTLR_ARE_NS: u32 = 1 << 4;
const GICD_CTLR_ENABLE_G1A: u32 = 1 << 1;
const GICD_CTLR_ENABLE_G1: u32 = 1;
const GICD_IGROUPR: usize = 0x080;
const GICD_IROUTER: usize = 0x6000;
// GICv3 redistributor: the control frame, then the SGI frame 64 KiB above it
// (12.10, 12.11).
const GICR_WAKER: usize = 0x014;
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;
const GICR_SGI: usize = 0x1_0000;
const GICR_IGROUPR0: usize = GICR_SGI + 0x080;
const GICR_ISENABLER0: usize = GICR_SGI + 0x100;
const GICR_IPRIORITYR: usize = GICR_SGI + 0x400;
/// The priority every interrupt takes on a GICv3, and the mask, which admits
/// every priority but the lowest. Both are as a non-secure access sees them; a
/// GIC with two security states maps that view into the lower half of its
/// range, keeping the order.
const V3_PRIORITY: u8 = 0x80;
const V3_PRIORITY_MASK: u64 = 0xF0;

/// Name the controller: distributor base, CPU-interface base, and the PPI
/// the generic timer raises. Called once by the platform at boot, before
/// [`init`] and before the first interrupt can be taken.
pub fn configure(gicd_base: usize, gicc_base: usize, timer_ppi: u32) {
    GICD.store(gicd_base, Ordering::Relaxed);
    GICC.store(gicc_base, Ordering::Relaxed);
    TIMER_PPI.store(timer_ppi, Ordering::Relaxed);
}

/// Name a GICv3: distributor base, the calling core's redistributor, and the
/// PPI the generic timer raises. Called as [`configure`] is.
pub fn configure_v3(gicd_base: usize, gicr_base: usize, timer_ppi: u32) {
    GICD.store(gicd_base, Ordering::Relaxed);
    GICR.store(gicr_base, Ordering::Relaxed);
    TIMER_PPI.store(timer_ppi, Ordering::Relaxed);
}

#[inline(always)]
fn v3() -> bool {
    GICR.load(Ordering::Relaxed) != 0
}

/// Acknowledge the highest-priority pending interrupt; what comes back goes
/// to [`end_of_interrupt`] unchanged, and its INTID is [`intid`].
///
/// # Safety
/// A CPU-interface access on the configured, enabled GIC; the IRQ path only.
#[inline(always)]
pub unsafe fn acknowledge() -> u32 {
    if v3() {
        let iar: u64;
        core::arch::asm!("mrs {}, s3_0_c12_c12_0", out(reg) iar, options(nomem, nostack));
        iar as u32
    } else {
        mmio::read32(gicc_base() + GICC_IAR)
    }
}

/// The INTID in what [`acknowledge`] returned: on a GICv2 the source CPU of an
/// SGI travels with it.
#[inline(always)]
pub fn intid(iar: u32) -> u32 {
    if v3() {
        iar & 0x00FF_FFFF
    } else {
        iar & 0x3FF
    }
}

/// End the interrupt [`acknowledge`] returned.
///
/// # Safety
/// As [`acknowledge`].
#[inline(always)]
pub unsafe fn end_of_interrupt(iar: u32) {
    if v3() {
        core::arch::asm!("msr s3_0_c12_c12_1, {}", in(reg) u64::from(iar), options(nomem, nostack));
    } else {
        mmio::write32(gicc_base() + GICC_EOIR, iar);
    }
}

/// The calling core's MPIDR.
#[inline(always)]
fn own_mpidr() -> u64 {
    let mpidr: u64;
    // SAFETY: reads a system register.
    unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nomem, nostack)) };
    mpidr
}

/// The MPIDR of core `core`: the calling core's own, or the one PSCI names it by.
fn mpidr_of(core: u8) -> u64 {
    if core == super::cpu::current_core_id() {
        own_mpidr()
    } else {
        super::cpu::mpidr_for_core(core)
    }
}

/// `ICC_SGI1R_EL1`'s value for `sgi_id` to the core with `mpidr`: Aff3 [55:48],
/// RS [47:44], Aff2 [39:32], INTID [27:24], Aff1 [23:16], and the target list
/// [15:0], one bit per Aff0 within the sixteen RS selects.
fn sgi1r(mpidr: u64, sgi_id: u32) -> u64 {
    let (aff0, aff1, aff2, aff3) = (
        mpidr & 0xFF,
        (mpidr >> 8) & 0xFF,
        (mpidr >> 16) & 0xFF,
        (mpidr >> 32) & 0xFF,
    );
    (aff3 << 48)
        | ((aff0 >> 4) << 44)
        | (aff2 << 32)
        | (u64::from(sgi_id & 0xF) << 24)
        | (aff1 << 16)
        | (1 << (aff0 & 0xF))
}

/// Write `ICC_SGI1R_EL1`, after the stores the target is to see are complete.
#[inline(always)]
unsafe fn write_sgi1r(value: u64) {
    core::arch::asm!("dsb ishst", "msr s3_0_c12_c11_5, {}", "isb", in(reg) value, options(nostack));
}

/// Order the stores the target is to see before a GICv2 SGI write.
#[inline(always)]
unsafe fn before_v2_sgi() {
    core::arch::asm!("dmb ishst", options(nostack, preserves_flags));
}

/// Send SGI `sgi_id` to the calling core, as a boot self-test does.
///
/// # Safety
/// As [`send_sgi`].
pub unsafe fn send_sgi_self(sgi_id: u32) {
    if v3() {
        write_sgi1r(sgi1r(own_mpidr(), sgi_id));
    } else {
        before_v2_sgi();
        // TargetListFilter 0b10: the requesting CPU only.
        mmio::write32(gicd_base() + GICD_SGIR, (0b10 << 24) | (sgi_id & 0xF));
    }
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
    let mask = mmio::read8(gicd + GICD_ITARGETSR);
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
/// included, so every WFI-parked core wakes. A GICv2 takes one write
/// (`TargetListFilter = 0b00`, `CPUTargetList = 0xFF`; bits for CPU interfaces
/// that do not exist are ignored); a GICv3 one to every other core
/// (`ICC_SGI1R_EL1.IRM`) and one to the sender.
///
/// # Safety
/// The configured GIC, initialised on the calling core.
#[inline(always)]
pub unsafe fn send_sgi_all(sgi_id: u32) {
    if v3() {
        write_sgi1r((1u64 << 40) | (u64::from(sgi_id & 0xF) << 24));
        send_sgi_self(sgi_id);
        return;
    }
    before_v2_sgi();
    // [25:24] TargetListFilter, [23:16] CPUTargetList, [3:0] SGIINTID.
    let val = (0xFF << 16) | (sgi_id & 0xF);
    mmio::write32(gicd_base() + GICD_SGIR, val);
}

/// Send SGI `sgi_id` to core `core` alone — the core a Tier-2 IRQ-owned
/// domain runs on, for instance.
///
/// # Safety
/// As [`send_sgi_all`].
#[inline(always)]
pub unsafe fn send_sgi(core: u32, sgi_id: u32) {
    if v3() {
        write_sgi1r(sgi1r(mpidr_of(core as u8), sgi_id));
        return;
    }
    before_v2_sgi();
    let target = u32::from(cpu_interface_mask(core as usize));
    let val = (target << 16) | (sgi_id & 0xF);
    mmio::write32(gicd_base() + GICD_SGIR, val);
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
/// (`GICD_ITARGETSR` on a GICv2, `GICD_IROUTER` on a GICv3) — for a Tier-2
/// IRQ the core its owning domain runs on, otherwise core 0. For an SGI or
/// PPI (INTID < 32) the enable and priority registers are banked per core
/// (in each core's redistributor on a GICv3), so this programs the calling
/// core's copy. An event binding (`event_handle >= 0`) must name a shared
/// peripheral interrupt: it is serviced on core 0, which only an SPI can be
/// routed to.
///
/// Returns 0 on success, negative errno on failure: `EINVAL` for an INTID
/// past the GIC's, or an SGI or PPI bound to an event.
pub fn irq_bind(irq: u32, event_handle: i32, mmio_base: usize, target_core: u8) -> i32 {
    // 1020..=1023 are special IDs and must never be programmed into the
    // distributor (the validator rejects them at build time; this is the
    // runtime backstop). A larger value would also index ISENABLER,
    // IPRIORITYR and ITARGETSR past their banks.
    if irq > MAX_INTID {
        return crate::kernel::sys::errno::EINVAL;
    }
    // An event binding is serviced on core 0, where a table move masks it
    // (`kernel::mem::table`). Only a shared peripheral interrupt can be
    // routed there; an SGI or PPI is taken on whichever core it is raised
    // on, so one is never bound to an event.
    if irq < 32 && event_handle >= 0 {
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

        // An event binding goes to core 0 whatever the caller named.
        let core = if event_handle >= 0 { 0 } else { target_core };
        if v3() {
            program_v3(irq, gicd, core);
            log::info!("[irq] bind irq={irq} event={event_handle} mmio={mmio_base:#x} core={core}");
            return 0;
        }

        // ISENABLER<n>: one bit per INTID, write-1-to-set (zeros are
        // ignored, so no read-modify-write).
        let reg = gicd + GICD_ISENABLER + (irq as usize / 32) * 4;
        mmio::write32(reg, 1u32 << (irq % 32));
        // IPRIORITYR: a byte per INTID; 0 is the highest priority.
        mmio::write8(gicd + GICD_IPRIORITYR + irq as usize, 0);
        // ITARGETSR: a byte per INTID, one bit per CPU interface.
        let target = cpu_interface_mask(core as usize);
        mmio::write8(gicd + GICD_ITARGETSR + irq as usize, target);

        log::info!("[irq] bind irq={irq} event={event_handle} mmio={mmio_base:#x} core={core}");
    }
    0
}

/// Bind an LPI, which an ITS translated from a device's MSI, to an event. Its
/// configuration lives in the LPI property table the ITS's owner keeps, so
/// nothing is programmed here: the binding is what the IRQ path dispatches on.
pub fn bind_lpi(intid: u32, event_handle: i32) -> i32 {
    if intid < FIRST_LPI || event_handle < 0 {
        return crate::kernel::sys::errno::EINVAL;
    }
    // SAFETY: as in `irq_bind`: scheduler-thread-only, grows at configure time.
    unsafe {
        if IRQ_BINDING_COUNT >= MAX_IRQ_BINDINGS {
            return crate::kernel::sys::errno::ENOMEM;
        }
        IRQ_BINDINGS[IRQ_BINDING_COUNT] = IrqBinding {
            irq: intid,
            event_handle,
            mmio_base: 0,
        };
        IRQ_BINDING_COUNT += 1;
    }
    log::info!("[irq] bind lpi={intid} event={event_handle}");
    0
}

/// Make SPI `irq` edge-triggered, as an MSI that a frame turns into an SPI is: a
/// single write, which a level-sensitive input can miss.
///
/// # Safety
/// A distributor access on the configured GIC, at configure time.
pub unsafe fn set_edge(irq: u32) {
    const GICD_ICFGR: usize = 0xC00;
    if !(32..=MAX_INTID).contains(&irq) {
        return;
    }
    let reg = gicd_base() + GICD_ICFGR + (irq as usize / 16) * 4;
    let bit = 1u32 << ((irq % 16) * 2 + 1);
    mmio::write32(reg, mmio::read32(reg) | bit);
}

/// The first LPI INTID.
pub const FIRST_LPI: u32 = 8192;

/// Interrupts taken per binding, in [`IRQ_BINDINGS`] order: what proves a bound
/// device's interrupt arrives, not just that it was asked for.
pub static BINDING_FIRES: [AtomicU32; MAX_IRQ_BINDINGS] =
    [const { AtomicU32::new(0) }; MAX_IRQ_BINDINGS];

/// Program `irq` on a GICv3 as group 1 and enabled: an SGI or PPI in the
/// calling core's redistributor, an SPI in the distributor, routed to `core`.
unsafe fn program_v3(irq: u32, gicd: usize, core: u8) {
    if irq < 32 {
        let rd = CORE_GICR
            .get(super::cpu::current_core_id() as usize)
            .map(|r| r.load(Ordering::Relaxed))
            .filter(|&r| r != 0)
            .unwrap_or_else(|| GICR.load(Ordering::Relaxed));
        mmio::write8(rd + GICR_IPRIORITYR + irq as usize, V3_PRIORITY);
        mmio::write32(rd + GICR_ISENABLER0, 1u32 << irq);
        return;
    }
    let bank = (irq as usize / 32) * 4;
    let group = gicd + GICD_IGROUPR + bank;
    mmio::write32(group, mmio::read32(group) | (1u32 << (irq % 32)));
    mmio::write8(gicd + GICD_IPRIORITYR + irq as usize, V3_PRIORITY);
    // IROUTER: Aff3 [39:32], Aff2..Aff0 [23:0], IRM (bit 31) clear.
    let route = mpidr_of(core) & 0xFF_00FF_FFFF;
    mmio::write64(gicd + GICD_IROUTER + irq as usize * 8, route);
    mmio::write32(gicd + GICD_ISENABLER + bank, 1u32 << (irq % 32));
}

/// Bring up a GICv3 for the calling core: the distributor in affinity-routing
/// mode, this core's redistributor awake, the system-register interface on,
/// SGIs and the timer PPI in group 1 and enabled.
unsafe fn init_v3() {
    let gicd = gicd_base();
    let rd = GICR.load(Ordering::Relaxed);
    mmio::write32(
        gicd + GICD_CTLR,
        GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_G1A | GICD_CTLR_ENABLE_G1,
    );
    while mmio::read32(gicd + GICD_CTLR) & GICD_CTLR_RWP != 0 {
        core::hint::spin_loop();
    }
    init_v3_cpu(rd);
}

/// Bring up the calling core's half of a GICv3: its redistributor `rd` awake,
/// the system-register interface on, SGIs and the timer PPI in group 1 and
/// enabled. The boot core runs it from [`init`]; each other core for itself.
///
/// # Safety
/// The calling core's own redistributor, mapped; the distributor is up.
pub unsafe fn init_v3_cpu(rd: usize) {
    if let Some(slot) = CORE_GICR.get(super::cpu::current_core_id() as usize) {
        slot.store(rd, Ordering::Relaxed);
    }
    let waker = rd + GICR_WAKER;
    mmio::write32(waker, mmio::read32(waker) & !GICR_WAKER_PROCESSOR_SLEEP);
    while mmio::read32(waker) & GICR_WAKER_CHILDREN_ASLEEP != 0 {
        core::hint::spin_loop();
    }
    // ICC_SRE_EL1.SRE: the system-register interface, which a GICv3 in
    // affinity routing cannot run without.
    let sre: u64;
    core::arch::asm!("mrs {}, s3_0_c12_c12_5", out(reg) sre, options(nomem, nostack));
    core::arch::asm!("msr s3_0_c12_c12_5, {}", "isb", in(reg) sre | 1, options(nomem, nostack));
    mmio::write32(rd + GICR_IGROUPR0, 0xFFFF_FFFF);
    let ppi = timer_ppi();
    for sgi in 0..16usize {
        mmio::write8(rd + GICR_IPRIORITYR + sgi, V3_PRIORITY);
    }
    mmio::write8(rd + GICR_IPRIORITYR + ppi as usize, V3_PRIORITY);
    mmio::write32(rd + GICR_ISENABLER0, 0xFFFF | (1u32 << ppi));
    core::arch::asm!("msr s3_0_c4_c6_0, {}", in(reg) V3_PRIORITY_MASK, options(nomem, nostack));
    core::arch::asm!("msr s3_0_c12_c12_7, {}", "isb", in(reg) 1u64, options(nomem, nostack));
}

/// Enable the distributor and this core's CPU interface, with the timer
/// PPI at the highest priority and the SGIs enabled.
///
/// # Safety
/// MMIO writes to the configured GIC; the bases must be mapped and
/// [`configure`] must have run.
pub unsafe fn init() {
    if v3() {
        init_v3();
        return;
    }
    let gicd = gicd_base();
    mmio::write32(gicd + GICD_CTLR, 1);
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
    mmio::write32(gicd + GICD_ISENABLER, 0xFFFF | (1u32 << ppi));
    mmio::write8(gicd + GICD_IPRIORITYR + ppi as usize, 0);
    mmio::write32(gicc + GICC_PMR, 0xFF); // unmask every priority
    mmio::write32(gicc + GICC_CTLR, 1);
}
