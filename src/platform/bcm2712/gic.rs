//! GICv2 distributor + CPU interface + IRQ binding state.
//!
//! Boards covered:
//!   * `board-cm5`: Pi 5 GIC-400 at 0x10_7fff_9000 (distributor) /
//!     0x10_7fff_a000 (CPU interface). Timer is the physical counter
//!     PPI 30 (no hypervisor → direct hardware access).
//!   * QEMU virt (default): GICv2 distributor at 0x0800_0000 / CPU
//!     interface at 0x0801_0000. Timer is the virtual counter PPI 27
//!     to avoid KVM trap overhead.
//!
//! Up to [`MAX_IRQ_BINDINGS`] hardware IRQs can be bound to fluxor
//! event handles via [`irq_bind`]; the matching ISR fires
//! `event_signal_from_isr` when the IRQ asserts. A sentinel
//! `event_handle = EVENT_HANDLE_PCIE1_MSI` routes the IRQ into the
//! brcmstb PCIe1 MSI mux dispatch instead of a single event.

#![allow(dead_code)]

// GIC
#[cfg(not(feature = "board-cm5"))]
pub const GICD_BASE: usize = 0x0800_0000; // QEMU virt GICv2 distributor
#[cfg(not(feature = "board-cm5"))]
pub const GICC_BASE: usize = 0x0801_0000; // QEMU virt GICv2 CPU interface
#[cfg(feature = "board-cm5")]
pub const GICD_BASE: usize = 0x10_7fff_9000; // Pi 5 GIC-400 distributor
#[cfg(feature = "board-cm5")]
pub const GICC_BASE: usize = 0x10_7fff_a000; // Pi 5 GIC-400 CPU interface

pub const GICC_IAR: *mut u32 = (GICC_BASE + 0x00C) as *mut u32;
pub const GICC_EOIR: *mut u32 = (GICC_BASE + 0x010) as *mut u32;

// Pi 5 (board-cm5): physical timer PPI 30 — no hypervisor, direct access.
// QEMU: virtual timer PPI 27 — avoids KVM trap overhead on physical timer.
#[cfg(feature = "board-cm5")]
pub const TIMER_PPI: u32 = 30;
#[cfg(not(feature = "board-cm5"))]
pub const TIMER_PPI: u32 = 27;

/// IRQ-to-event binding table. When a bound IRQ fires, the kernel signals the
/// associated event via event_signal_from_isr (ISR-safe, lock-free).
/// Up to 4 bindings (virtio devices, GPIO, etc.).
pub const MAX_IRQ_BINDINGS: usize = 4;
pub struct IrqBinding {
    pub irq: u32,           // GIC interrupt ID (e.g. 48 for virtio SPI 16)
    pub event_handle: i32,  // Fluxor event handle to signal
    pub mmio_base: usize,   // If nonzero, ACK device by reading INTERRUPT_STATUS and writing INTERRUPT_ACK
}
pub static mut IRQ_BINDINGS: [IrqBinding; MAX_IRQ_BINDINGS] = [
    IrqBinding { irq: 0, event_handle: -1, mmio_base: 0 },
    IrqBinding { irq: 0, event_handle: -1, mmio_base: 0 },
    IrqBinding { irq: 0, event_handle: -1, mmio_base: 0 },
    IrqBinding { irq: 0, event_handle: -1, mmio_base: 0 },
];
pub static mut IRQ_BINDING_COUNT: usize = 0;

/// Sentinel event_handle that tells `irq_handler` to fan out via
/// `pcie::pcie1_msi_dispatch` instead of signalling a single event. Used
/// by `register_pcie1_msi_spi` so the brcmstb MSI mux can service all
/// 32 MSI vectors through one GIC SPI.
pub const EVENT_HANDLE_PCIE1_MSI: i32 = -2;

/// One-shot guard for `register_pcie1_msi_spi`. `irq_bind` appends a
/// row on every call; without this flag a driver that allocates N
/// MSI-X vectors would exhaust `IRQ_BINDINGS`.
pub static mut PCIE1_MSI_SPI_REGISTERED: bool = false;

/// Enable `spi_irq` in the GIC distributor and route its fires into
/// `pcie::pcie1_msi_dispatch` (via the `EVENT_HANDLE_PCIE1_MSI`
/// sentinel). Returns 0 on success, -ENOMEM if the binding table is
/// full.
#[cfg(feature = "board-cm5")]
pub fn register_pcie1_msi_spi(spi_irq: u32) -> i32 {
    irq_bind(spi_irq, EVENT_HANDLE_PCIE1_MSI, 0)
}

#[cfg(not(feature = "board-cm5"))]
pub fn register_pcie1_msi_spi(_spi_irq: u32) -> i32 {
    fluxor::kernel::errno::ENOSYS
}

/// Bind an event to a hardware IRQ. Enables the IRQ in the GIC distributor.
/// `mmio_base`: if nonzero, the ISR reads offset 0x60 (INTERRUPT_STATUS) and
/// writes offset 0x64 (INTERRUPT_ACK) to ACK virtio-mmio devices.
///
/// Returns 0 on success, negative errno on failure.
pub fn irq_bind(irq: u32, event_handle: i32, mmio_base: usize) -> i32 {
    unsafe {
        if IRQ_BINDING_COUNT >= MAX_IRQ_BINDINGS {
            return fluxor::kernel::errno::ENOMEM;
        }
        let idx = IRQ_BINDING_COUNT;
        IRQ_BINDINGS[idx] = IrqBinding { irq, event_handle, mmio_base };
        IRQ_BINDING_COUNT = idx + 1;

        // Enable the SPI in the GIC distributor
        // SPIs start at IRQ 32. ISENABLER register: base + 0x100 + (irq/32)*4, bit = irq%32
        let reg = GICD_BASE + 0x100 + (irq as usize / 32) * 4;
        let bit = 1u32 << (irq % 32);
        core::ptr::write_volatile(reg as *mut u32,
            core::ptr::read_volatile(reg as *const u32) | bit);
        // Set priority to 0 (highest)
        core::ptr::write_volatile((GICD_BASE + 0x400 + irq as usize) as *mut u8, 0);
        // Target CPU 0
        core::ptr::write_volatile((GICD_BASE + 0x800 + irq as usize) as *mut u8, 1);

        log::info!("[irq] bind irq={} event={} mmio={:#x}", irq, event_handle, mmio_base);
    }
    0
}

pub unsafe fn gic_init() {
    core::ptr::write_volatile(GICD_BASE as *mut u32, 1); // GICD_CTLR: enable
    core::ptr::write_volatile((GICD_BASE + 0x100) as *mut u32, 1u32 << TIMER_PPI); // ISENABLER0
    core::ptr::write_volatile((GICD_BASE + 0x400 + TIMER_PPI as usize) as *mut u8, 0); // priority 0 (highest)
    core::ptr::write_volatile((GICC_BASE + 0x004) as *mut u32, 0xFF); // PMR: allow all
    core::ptr::write_volatile(GICC_BASE as *mut u32, 1); // GICC_CTLR: enable
}

/// Initialize GIC CPU interface on a secondary core.
/// Each core needs its own GICC setup for PPIs (like the timer).
pub unsafe fn gic_init_secondary() {
    core::ptr::write_volatile((GICC_BASE + 0x004) as *mut u32, 0xFF); // PMR
    core::ptr::write_volatile(GICC_BASE as *mut u32, 1); // GICC_CTLR
    // Enable timer PPI for this core
    core::ptr::write_volatile((GICD_BASE + 0x100) as *mut u32, 1u32 << TIMER_PPI);
}
