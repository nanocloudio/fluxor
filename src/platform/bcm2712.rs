// Platform: BCM2712 (Raspberry Pi 5) — Cortex-A76, aarch64 bare-metal
//
// Two board configurations (selected at compile time):
//   - QEMU virt (default): PL011 at 0x0900_0000, GICv2 at 0x0800_0000,
//     kernel loaded at 0x4008_0000
//   - Pi 5 (feature "board-pi5"): RP1 PL011 (UART0) at 0x1c_0003_0000,
//     GIC-400 distributor at 0x10_7fff_9000, kernel loaded at 0x8_0000
//
// Features:
//   - Secondary cores brought up through PSCI CPU_ON
//   - Early MMU init with identity-mapped page tables (cacheable DRAM, device MMIO)
//   - RP1 peripheral access via PCIe BAR (GPIO, SPI, I2C register bridges)
//   - Multi-domain execution with config-driven domain assignment and core wakeup
//
// Fully config-driven: the boot image carries trailer, modules.bin, and config.bin
// after the fixed kernel binary, discovered at runtime via the layout trailer.

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use fluxor::arch::aarch64::isolation;
use fluxor::kernel::exec::domains::{self, cross};
use fluxor::kernel::exec::scheduler;
use fluxor::kernel::module::loader;
use fluxor::platform::multicore;

// ── Boot-time submodules (binary-private; not exposed via fluxor::kernel) ──
//
// Boot-only support code (UART driver, RP1 HAL, boot-time MMU page
// tables, kernel `log` backend) is factored into focused submodules under
// `src/platform/bcm2712/` and consumed by `main()`, the domain loops,
// and the BCM HAL ops table. The exception vectors, the GICv2 driver and
// the generic timer are the architecture's, in `fluxor::arch::aarch64`;
// this file tells them the board's facts (`configure_arch`) before the
// first interrupt.
//
// Submodules that hold shared kernel state (PCIe enumeration,
// runtime MMU isolation, cross-domain channels, NIC DMA arena, paged
// memory) are declared in `src/kernel/mod.rs` and reachable as
// `fluxor::kernel::{pcie, mmu, multicore, nic_ring, …}`. They are
// **not** redeclared here — a loaded module's kernel-facing surface
// is the `fluxor::kernel` namespace, never `src/platform/*`.
#[path = "bcm2712/boot_mmu.rs"]
mod boot_mmu;
#[path = "bcm2712/logger.rs"]
mod logger;
#[path = "bcm2712/rp1.rs"]
mod rp1;
#[path = "bcm2712/uart.rs"]
mod uart;

// Bring the UART, GIC and exception names into the binary's namespace so
// the callsites (`uart_puts(b"…")`, `irq_bind(…)`, `IRQ_BINDING_COUNT`,
// `NEXT_DEADLINE_TICKS`, `CORE_TICKS`, `current_core_id()`, …) read
// unqualified.
use exception::*;
use fluxor::arch::aarch64::cpu::current_core_id;
use fluxor::arch::aarch64::{cpu, exception, gic, psci, timer};
use gic::*;
use logger::RingLogger;
use uart::*;

// ── The board's facts for the architecture ──────────────────────────────────
//
// Where the interrupt controller is, which PPI the timer raises, which
// counter it runs on, how PSCI is reached and which MPIDR field numbers the
// cores differ between the Pi 5 (GIC-400, physical timer: no hypervisor;
// Trusted Firmware by `smc`; cores in Aff1) and the QEMU `virt` machine
// (GICv2 at its own address; the virtual timer, which avoids a KVM trap per
// access; PSCI by `hvc`; cores in Aff0).
#[cfg(feature = "board-pi5")]
const GICD_BASE: usize = 0x10_7fff_9000; // Pi 5 GIC-400 distributor
#[cfg(feature = "board-pi5")]
const GICC_BASE: usize = 0x10_7fff_a000; // Pi 5 GIC-400 CPU interface
#[cfg(feature = "board-pi5")]
const TIMER_PPI: u32 = 30; // physical timer
#[cfg(feature = "board-pi5")]
const TIMER_COUNTER: timer::Counter = timer::Counter::Physical;
#[cfg(feature = "board-pi5")]
const PSCI_CONDUIT: psci::Conduit = psci::Conduit::Smc; // Trusted Firmware at EL3
#[cfg(feature = "board-pi5")]
const MPIDR_CORE_SHIFT: u32 = 8; // Cortex-A76 MPIDR: core number in Aff1
#[cfg(not(feature = "board-pi5"))]
const GICD_BASE: usize = 0x0800_0000; // QEMU virt GICv2 distributor
#[cfg(not(feature = "board-pi5"))]
const GICC_BASE: usize = 0x0801_0000; // QEMU virt GICv2 CPU interface
#[cfg(not(feature = "board-pi5"))]
const TIMER_PPI: u32 = 27; // virtual timer
#[cfg(not(feature = "board-pi5"))]
const TIMER_COUNTER: timer::Counter = timer::Counter::Virtual;
#[cfg(not(feature = "board-pi5"))]
const PSCI_CONDUIT: psci::Conduit = psci::Conduit::Hvc; // QEMU virt: PSCI by HVC
#[cfg(not(feature = "board-pi5"))]
const MPIDR_CORE_SHIFT: u32 = 0; // QEMU virt: core number in Aff0

/// The 1 GB indices of MMIO the kernel reaches at EL1 while an isolated
/// module's table is installed: the PCIe controllers (gigabyte 64, from
/// 0x10_0000_0000: the PCIe1 MSI mux the IRQ path reads), the GIC-400
/// (gigabyte 65: IAR/EOIR at 0x10_7fff_a000 on every IRQ) and the RP1
/// PL011 (gigabyte 112: 0x1c_0003_0000, the fault dump and debug drain).
#[cfg(feature = "board-pi5")]
const KERNEL_MMIO_GB: &[usize] = &[64, 65, 112];
/// QEMU virt's GIC and UART sit in the first gigabyte, inside the kernel
/// base every module table already carries.
#[cfg(not(feature = "board-pi5"))]
const KERNEL_MMIO_GB: &[usize] = &[];

/// Where `exception_dump` stashes ELR/ESR/FAR for an emulator's monitor
/// (`(qemu) xp /4gx 0x40070000`): inside DRAM on both boards.
const FAULT_STASH: usize = 0x4007_0000;

/// Tell the architecture the board's facts. First thing in `main`, before
/// the MMU, the timer or the GIC are touched: it only writes RAM, and with
/// the MMU still off the writes land in memory, where a secondary core's
/// entry stub reads the core-number shift with its own MMU off.
fn configure_arch() {
    gic::configure(GICD_BASE, GICC_BASE, TIMER_PPI);
    timer::configure(TIMER_COUNTER);
    psci::configure(PSCI_CONDUIT);
    // `_start` parks on the same field, by the same constant.
    cpu::configure_core_id(MPIDR_CORE_SHIFT);
    exception::set_fault_stash(FAULT_STASH);
    exception::set_stack_guard_probe(fluxor::platform::multicore::stack_guard_core);
    // Every module table maps the low 3 GB of DRAM EL1-only (kernel image,
    // BSS, arenas, stacks, modules blob) plus the apertures the kernel
    // touches while a module's table is live.
    isolation::configure(3, KERNEL_MMIO_GB);
    isolation::set_kernel_stack_guards(fluxor::platform::multicore::kernel_stack_guards);
}

/// The exception dump's sink: the PL011, raw, once `uart_init` has run.
fn exception_dump_to_uart(bytes: &[u8]) {
    if UART_READY.load(Ordering::Relaxed) != 0 {
        uart_raw_puts(bytes);
    }
}

/// One-shot guard for `register_pcie1_msi_spi`. `irq_bind` appends a
/// row on every call; without this flag a driver that allocates N
/// MSI-X vectors would exhaust `IRQ_BINDINGS`.
static mut PCIE1_MSI_SPI_REGISTERED: bool = false;

/// Enable `spi_irq` in the GIC distributor and route its fires into the
/// brcmstb PCIe1 MSI mux (`pcie::pcie1_msi_dispatch`, the architecture's
/// registered IRQ multiplexer), so all 32 MSI vectors are serviced through
/// one GIC SPI. Returns 0 on success, -ENOMEM if the binding table is full.
#[cfg(feature = "board-pi5")]
fn register_pcie1_msi_spi(spi_irq: u32) -> i32 {
    gic::set_irq_mux(|| {
        // SAFETY: runs on the IRQ path after `pcie1_msi_init` succeeded (the
        // caller checks it before registering), with the MSI controller's
        // registers mapped by the boot page tables.
        let _ = unsafe { fluxor::platform::pcie::pcie1_msi_dispatch() };
    });
    irq_bind(spi_irq, gic::EVENT_HANDLE_MUX, 0, 0)
}

#[cfg(not(feature = "board-pi5"))]
fn register_pcie1_msi_spi(_spi_irq: u32) -> i32 {
    fluxor::kernel::sys::errno::ENOSYS
}

// ============================================================================
// Platform address constants (compile-time board selection)
// ============================================================================

// UART (PL011) — see `bcm2712/uart.rs` for the driver. The `use uart::*`
// in the submodule block above brings UART_BASE/UART_DR/UART_FR/etc.
// into this file's namespace alongside the read/write functions.

// The GIC and the timer are the architecture's (`fluxor::arch::aarch64`);
// their board facts are the constants above, handed over by
// `configure_arch`.
#[cfg(not(feature = "board-pi5"))]
const QEMU_CONFIG_BLOB_ADDR: usize = 0x6100_0000;
#[cfg(not(feature = "board-pi5"))]
const QEMU_MODULES_BLOB_ADDR: usize = 0x6200_0000;

global_asm!(
    ".section .layout_header,\"a\"",
    ".global __package_header_start",
    ".global __package_source_start",
    "__package_header_start:",
    "    .word 0x4B505846", // PACKAGE_HEADER_MAGIC
    "    .byte 1, 0, 0, 0", // version + reserved
    // runtime_end: end of file-backed sections (must NOT include BSS
    // or stack). The kernel resolves the trailer via this same symbol
    // through `config::get_trailer_addr()`. `_start`'s relocator copies
    // `package_size` bytes here only when package_size != 0; RAM-loaded
    // aarch64 images leave it at 0 and skip the copy.
    "    .word __end_data_addr",
    "    .word 0", // package_size (RP/XIP post-BSS relocation only)
    "__package_source_start:",
);

// PL011 UART registers + driver: `bcm2712/uart.rs`.

// ============================================================================
// BCM2712 PCIe Root Complex
// ============================================================================
//
// RP1 is connected via PCIe x4. VPU firmware (with enable_rp1_uart=1 and
// pciex4_reset=0 in config.txt) brings up the link and maps RP1 at
// 0x1c_0000_0000 before kernel handoff. We only need to disable ASPM
// for reliable infrequent-access patterns (per RP1 datasheet §3.3.1.3).
// PCIe root complex (onboard) MMIO base — used by rp1_pcie_disable_aspm.
#[cfg(feature = "board-pi5")]
const PCIE_RC_BASE: usize = 0x10_0012_0000;
#[cfg(feature = "board-pi5")]
const PCIE_MISC_HARD_PCIE_HARD_DEBUG: usize = 0x4304;
#[cfg(feature = "board-pi5")]
const PCIE_MISC_UBUS_CTRL: usize = 0x40a4;

#[cfg(feature = "board-pi5")]
#[inline(always)]
unsafe fn pcie_read(off: usize) -> u32 {
    core::ptr::read_volatile((PCIE_RC_BASE + off) as *const u32)
}

#[cfg(feature = "board-pi5")]
#[inline(always)]
unsafe fn pcie_write(off: usize, val: u32) {
    core::ptr::write_volatile((PCIE_RC_BASE + off) as *mut u32, val);
}

/// Disable ASPM on the PCIe RC so that
/// writes from infrequent access patterns (ours) don't get stalled or
/// dropped by L1 wake latency. Per RP1 datasheet §3.3.1.3.
///
/// Does NOT toggle PCIe resets or touch the outbound window — VPU firmware
/// already brought the link up at kernel handoff.
#[cfg(feature = "board-pi5")]
unsafe fn rp1_pcie_disable_aspm() {
    // HARD_PCIE_HARD_DEBUG (+0x4304 on Pi 5 RC).
    //  bit 1  = CLKREQ_DEBUG_ENABLE
    //  bit 16 = REFCLK_OVRD_ENABLE
    //  bit 20 = REFCLK_OVRD_OUT
    //  bit 21 = L1SS_ENABLE
    // Clearing these matches `brcm_pcie_start_link` phase 1 in pcie-brcmstb.c.
    let mut tmp = pcie_read(PCIE_MISC_HARD_PCIE_HARD_DEBUG);
    tmp &= !0x0032_0002;
    pcie_write(PCIE_MISC_HARD_PCIE_HARD_DEBUG, tmp);

    // UBUS error suppression — without REPLY_ERR_DIS, a read to an unmapped
    // PCIe address raises an AXI external abort. Set it so UART writes
    // (which target legitimate addresses) aren't ambient-affected by stray
    // reads elsewhere in the kernel.
    let mut tmp = pcie_read(PCIE_MISC_UBUS_CTRL);
    tmp |= (1 << 13) | (1 << 19);
    pcie_write(PCIE_MISC_UBUS_CTRL, tmp);
}

// ============================================================================
// RP1 Ethernet (Cadence GEM_GXL 1p09) — register map
// ============================================================================
//
// Two MMIO regions:
//   eth     @ 0x1c_0010_0000 (16 kB)   Cadence GEM core
//   eth_cfg @ 0x1c_0010_4000 (16 kB)   RP1 wrapper (clkgen, TSU, irq mux)
//   pads_eth@ 0x1c_000f_c000           RGMII pad config
//
// Core offsets from Linux drivers/net/ethernet/cadence/macb.h (MACB + GEM
// classic register indices) cross-referenced with RP1 datasheet §7.
//
// VPU firmware leaves the GEM powered, clocked, and out of reset at kernel
// handoff — ethernet works under Linux with no clock/reset setup in the
// macb driver path. We rely on that state for initial bring-up.

#[cfg(feature = "board-pi5")]
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
mod eth {
    pub const GEM_BASE: usize = 0x1c_0010_0000;
    pub const ETH_CFG_BASE: usize = 0x1c_0010_4000;

    // --- Cadence GEM core register offsets ---
    pub const NCR: usize = 0x000; // Network Control
    pub const NCFGR: usize = 0x004; // Network Config
    pub const NSR: usize = 0x008; // Network Status (MDIO idle etc)
    pub const TSR: usize = 0x014; // Transmit Status
    pub const RBQP: usize = 0x018; // classic MACB RX Queue Ptr
    pub const TBQP: usize = 0x01c; // classic MACB TX Queue Ptr
    pub const RSR: usize = 0x020; // Receive Status
    pub const ISR: usize = 0x024;
    pub const IER: usize = 0x028;
    pub const IDR: usize = 0x02c;
    pub const IMR: usize = 0x030;
    pub const MAN: usize = 0x034; // PHY Maintenance (MDIO)
    pub const HRB: usize = 0x090; // Hash Bottom
    pub const HRT: usize = 0x094; // Hash Top
    pub const SA1B: usize = 0x098; // Specific address 1 Bottom (MAC lo)
    pub const SA1T: usize = 0x09c; // Specific address 1 Top    (MAC hi)
    pub const USRIO: usize = 0x0c0; // User IO
    pub const WOL: usize = 0x0c4;
    pub const MID: usize = 0x0fc; // Module ID (RO) — Pi 5 = 0x00070109

    pub const DMACFG: usize = 0x010; // GEM DMA Config
    pub const GEM_TBQP_0: usize = 0x440; // GEM queue-0 TX BD ptr
    pub const GEM_RBQP_0: usize = 0x480; // GEM queue-0 RX BD ptr

    // --- NCR bits ---
    pub const NCR_LB: u32 = 1 << 0; // loopback
    pub const NCR_LLB: u32 = 1 << 1; // local loopback
    pub const NCR_RE: u32 = 1 << 2; // RX enable
    pub const NCR_TE: u32 = 1 << 3; // TX enable
    pub const NCR_MPE: u32 = 1 << 4; // Management port enable (MDIO)
    pub const NCR_CLRSTAT: u32 = 1 << 5;
    pub const NCR_INCSTAT: u32 = 1 << 6;
    pub const NCR_WESTAT: u32 = 1 << 7;
    pub const NCR_BP: u32 = 1 << 8;
    pub const NCR_TSTART: u32 = 1 << 9; // Start transmission
    pub const NCR_THALT: u32 = 1 << 10;

    // --- MID expected value (verified via Linux /dev/mem on DUT) ---
    pub const EXPECTED_MID: u32 = 0x0007_0109;

    // --- eth_cfg wrapper offsets (RP1 datasheet §7.1) ---
    pub const CFG_CONTROL: usize = 0x00;
    pub const CFG_STATUS: usize = 0x04; // RGMII_LINK/SPEED/DUPLEX
    pub const CFG_TSU_CNT0: usize = 0x08;
    pub const CFG_TSU_CNT1: usize = 0x0c;
    pub const CFG_TSU_CNT2: usize = 0x10;
    pub const CFG_CLKGEN: usize = 0x14; // TXCLKDELEN, ENABLE, SPEED_OVERRIDE
    pub const CFG_CLK2FC: usize = 0x18;
    pub const CFG_INTR: usize = 0x1c; // bit 0 = ETHERNET top-level irq
    pub const CFG_INTE: usize = 0x20;
    pub const CFG_INTF: usize = 0x24;
    pub const CFG_INTS: usize = 0x28;

    #[inline(always)]
    pub unsafe fn read(off: usize) -> u32 {
        core::ptr::read_volatile((GEM_BASE + off) as *const u32)
    }

    #[inline(always)]
    pub unsafe fn write(off: usize, val: u32) {
        core::ptr::write_volatile((GEM_BASE + off) as *mut u32, val);
    }

    #[inline(always)]
    pub unsafe fn cfg_read(off: usize) -> u32 {
        core::ptr::read_volatile((ETH_CFG_BASE + off) as *const u32)
    }

    #[inline(always)]
    pub unsafe fn cfg_write(off: usize, val: u32) {
        core::ptr::write_volatile((ETH_CFG_BASE + off) as *mut u32, val);
    }
}

// The generic timer driver is `fluxor::arch::aarch64::timer`:
// `timer::{timer_freq, read_timer_count, timer_set}`.

// ============================================================================
// Entry point with secondary core parking
// ============================================================================
//
// The firmware enters `_start` on the boot core; the others stay with the
// PSCI implementation until `wake_core` starts them at
// `secondary_core_trampoline`. `_start` still checks the MPIDR core field
// (`MPIDR_CORE_SHIFT`) and parks any core but core 0, for firmware that
// releases every core into the image.

// DTB pointer handed to us by the firmware. `main` records it once the
// MMU is up; `kernel::boot::dtb::read_ethernet_mac` consults it. Placed in
// `.data` with a non-zero sentinel to keep it out of `.bss` (which the
// boot code zeros).
#[no_mangle]
#[link_section = ".data"]
pub static mut _boot_dtb_ptr: u64 = 0xFFFF_FFFF_FFFF_FFFF;

global_asm!(
    ".section .text._start",
    ".global _start",
    ".type _start, @function",
    "_start:",
    // aarch64 Linux boot protocol: x0 = DTB physical address. Stash it in
    // x19 (callee-saved) so we can hand it to `main` after the MMU comes
    // up — storing to a symbol here would use the virtual link address,
    // which does not map anywhere real with the MMU off.
    "    mov x19, x0",
    // Core 0 proceeds; any other core parks.
    "    mrs x0, mpidr_el1",
    "    ubfx x0, x0, #{core_shift}, #8",
    "    cbnz x0, .Lpark_core",
    // ---- Primary core (core 0) continues ----
    // The Pi 5's firmware hands off at EL2; the kernel runs at EL1, so drop
    // (the architecture's drop; already at EL1, it branches straight on).
    fluxor::drop_to_el1!("x0", "x1", "2f"),
    "2:",
    // At EL1 (either originally or via eret).
    // Install exception vectors for EL1.
    "    adr x1, exception_vectors",
    "    msr vbar_el1, x1",
    "    isb",
    // Make sure EL1 MMU/caches are off. We enable them ourselves in
    // boot_mmu::enable() after setting up page tables; any residual VPU state
    // needs to be cleared so our setup actually takes effect.
    "    mrs x0, sctlr_el1",
    "    bic x0, x0, #(1 << 0)",  // M
    "    bic x0, x0, #(1 << 2)",  // C
    "    bic x0, x0, #(1 << 12)", // I
    "    msr sctlr_el1, x0",
    "    isb",
    "    ic iallu",
    "    tlbi vmalle1",
    "    dsb sy",
    "    isb",
    // Enable NEON/FP (CPACR_EL1.FPEN = 0b11)
    "    mov x0, #(3 << 20)",
    "    msr cpacr_el1, x0",
    "    isb",
    // Use SP_EL1 for kernel execution so IRQs take the EL1h/SP_ELx vector slot.
    "    msr SPSel, #1",
    "    isb",
    // Set up stack before relocating the packaged payload.
    "    ldr x30, =__stack_end",
    "    mov sp, x30",
    // If a packaged payload is appended after the image, relocate it above the
    // runtime-reserved RAM region before zeroing .bss.
    "    ldr x2, =__package_header_start",
    "    ldr w3, [x2]",
    "    movz w4, #0x5846",
    "    movk w4, #0x4B50, lsl #16",
    "    cmp w3, w4",
    "    b.ne 9f",
    "    ldr w5, [x2, #12]", // package_size
    "    cbz w5, 9f",
    "    add x6, x2, #16",  // source: bytes appended after the header
    "    ldr w7, [x2, #8]", // destination base (__end_block_addr, aligned by packer)
    // Fast 8-byte copy loop (both src and dst are 256-byte aligned by packer)
    "    bic x10, x5, #7", // x10 = size rounded down to 8-byte multiple
    "    mov x8, xzr",
    "8:  cmp x8, x10",
    "    b.ge 7f",
    "    ldr x9, [x6, x8]",
    "    str x9, [x7, x8]",
    "    add x8, x8, #8",
    "    b 8b",
    // Copy remaining 0-7 tail bytes
    "7:  cmp x8, x5",
    "    b.ge 9f",
    "    ldrb w9, [x6, x8]",
    "    strb w9, [x7, x8]",
    "    add x8, x8, #1",
    "    b 7b",
    "9:",
    // Zero BSS
    "    ldr x0, =__bss_start",
    "    ldr x1, =__bss_end",
    "0:  cmp x0, x1",
    "    b.ge 1f",
    "    str xzr, [x0], #8",
    "    b 0b",
    "1:",
    // Jump to Rust main — pass DTB pointer (firmware-provided) as first arg.
    "    mov x0, x19",
    "    bl main",
    // Should never return
    "2:  b 2b",
    // Secondary-core fallback park. On Pi 5, ATF holds cores 1-3 in
    // its own PSCI-managed state and never dispatches them into
    // `_start`; `wake_secondary_cores` brings them up through PSCI
    // CPU_ON, which jumps straight into `secondary_core_trampoline`.
    // This label only matters for firmware variants that hand cores
    // 1-3 to the kernel image at boot.
    ".Lpark_core:",
    "    wfi",
    "    b .Lpark_core",
    core_shift = const MPIDR_CORE_SHIFT,
);

// ============================================================================
// Main entry point
// ============================================================================

#[no_mangle]
pub extern "C" fn main(dtb_phys: u64) -> ! {
    configure_arch();
    // The memory map, from the device tree the firmware handed over (QEMU:
    // left at the base of RAM): what the boot page tables map as DRAM, and
    // the zone above the boot image that the kernel's tables are carved from
    // and the state arena takes the rest of. Before the page tables, which
    // are built from it; nothing is written to the zone here.
    // SAFETY: once, on the boot core, before anything allocates.
    unsafe { fluxor::platform::memmap::build(dtb_phys) };
    // Pi 5 bring-up sequence:
    //   1. MMU enable — DRAM cacheable, RP1 MMIO as Device-nGnRE at 0x1c.
    //   2. rp1_pcie_disable_aspm() — surgical ASPM disable on PCIe RC.
    //      VPU firmware (with enable_rp1_uart=1 + pciex4_reset=0) has
    //      already brought up the PCIe link, enabled RP1 endpoint
    //      PCI_COMMAND, and configured GPIO14/15 + PL011 for UART.
    //   3. uart_init() — reprogram PL011 to be sure (VPU may have left
    //      it configured, but we set our own baud/params).
    // SAFETY: Single boot-thread; MMU init runs once before any module
    // observes virtual addresses. RP1 ASPM disable touches MMIO mapped
    // by init_page_tables one line earlier.
    #[cfg(feature = "board-pi5")]
    unsafe {
        boot_mmu::init_page_tables();
        boot_mmu::enable();
        fluxor::platform::memmap::install();
        rp1_pcie_disable_aspm();
    }

    // SAFETY: uart_init configures the PL011 MMIO pre-driver; single-threaded boot.
    unsafe { uart_init() };
    UART_READY.store(1, Ordering::Release);
    exception::set_dump_sink(exception_dump_to_uart);
    // UART FIFO is always drained by hardware, so the local log-ring
    // consumer can activate immediately.
    fluxor::kernel::sys::log_ring::activate_local();

    // Record the DTB pointer now that the MMU is on; later DTB reads
    // dereference `_boot_dtb_ptr`.
    // SAFETY: `_boot_dtb_ptr` is a static usize; single boot-time writer.
    unsafe {
        core::ptr::write_volatile(&raw mut _boot_dtb_ptr, dtb_phys);
    }

    #[cfg(feature = "board-pi5")]
    uart_puts(b"[fluxor] bcm2712 boot (Pi 5)\r\n");
    #[cfg(not(feature = "board-pi5"))]
    uart_puts(b"[fluxor] bcm2712 boot (QEMU virt)\r\n");

    // QEMU virt: MMU init happens here (Pi 5 did it earlier, before PCIe).
    // SAFETY: MMU init runs once at boot before any module observes virt addrs.
    #[cfg(not(feature = "board-pi5"))]
    unsafe {
        boot_mmu::init_page_tables();
        boot_mmu::enable();
        fluxor::platform::memmap::install();
    }

    // Probe RP1 early on Pi 5 to confirm the PCIe BAR mapping is alive.
    rp1::report(uart_puts, uart_put_hex32);

    // Keep the GEM module-ID probe pre-logger because it only feeds
    // UART diagnostics. Full PCIe enumeration runs below so its
    // log::info! lines reach the ring (and therefore log_net -> UDP).
    #[cfg(feature = "board-pi5")]
    {
        // SAFETY: GEM_BASE + MID is the documented module-ID register at the
        // GEM MMIO base; aligned u32 read.
        let mid =
            unsafe { core::ptr::read_volatile(eth::GEM_BASE.wrapping_add(eth::MID) as *const u32) };
        uart_puts(b"[gem] MID=0x");
        uart_put_hex32(mid);
        if mid == eth::EXPECTED_MID {
            uart_puts(b" (OK)\r\n");
        } else {
            uart_puts(b" (UNEXPECTED - expected 0x00070109)\r\n");
        }
    }

    static LOGGER: RingLogger = RingLogger;
    // SAFETY: set_logger_racy is documented as "single-threaded only"; boot
    // is the only call site and runs before any module exists.
    unsafe { log::set_logger_racy(&LOGGER).ok() };
    log::set_max_level(log::LevelFilter::Info);
    fluxor::platform::memmap::report();

    // Force the active cooler to full so sustained-load rig runs aren't
    // confounded by thermal throttling. Drives the RP1 PWM channel the boot
    // firmware uses for the Pi 5 fan; the readback is logged so the rig can
    // confirm the writes took. No-op on QEMU. Placed after logger init so the
    // report reaches the UDP telemetry stream.
    rp1::cooling_full_on();

    // PCIe1 bring-up: bridge reset and RESCAL, the root complex's registers,
    // MDIO tuning, SerDes and PERST#. The link trains after this returns, so
    // bus 1 is scanned by a later `PCIE_RESCAN` (the nvme driver's retry,
    // `pcie_scan`).
    {
        let n = fluxor::platform::pcie::enumerate();
        log::info!("[pcie] bus1 devices={n}");
    }

    // Report timer frequency
    let freq = timer::timer_freq();
    uart_puts(b"[timer] freq=");
    uart_put_u32(freq as u32);
    uart_puts(b" Hz\r\n");

    // Exception vectors + GIC + timer
    // Timer tick period will be recalculated after config is parsed (tick_us).
    // Start with 1ms default so the system runs during init.
    let default_ticks = if freq > 0 {
        (freq / 1000) as u32
    } else {
        62500
    };
    // Seed every per-core deadline slot with the 1 ms default so any core
    // that takes a timer IRQ before its domain-specific re-seed reloads a
    // sane value. Cores 1-3 overwrite their own slot in `secondary_core_main`
    // and core 0 re-seeds from config.tick_us below.
    for slot in &NEXT_DEADLINE_TICKS {
        slot.store(default_ticks, Ordering::Relaxed);
    }
    // SAFETY: GIC + generic timer init touch system control regs that the
    // boot path is the sole writer of; DAIFCLR enables IRQs after vectors
    // and step_guard are wired.
    unsafe {
        gic::init();
        timer::timer_set(default_ticks);
        core::arch::asm!("msr daifclr, #2"); // enable IRQs
    }

    uart_puts(b"[gic] initialized, IRQs enabled\r\n");

    // HAL ops, syscall table, providers, then the BCM2712
    // generic-timer-backed step guard.
    fluxor::kernel::boot(&BCM2712_HAL_OPS);
    fluxor::kernel::exec::step_guard::init();

    // --- Config-driven module graph ---
    //
    // `scheduler::prepare_graph` compiles the graph (edge decode, fan
    // module insertion, channel allocation, port-table population). This
    // shared domain runtime (`kernel::exec::domains`) layers the multi-core
    // concerns on top: cross-domain edges are bridged, and each core's run
    // loop steps its domain through the shared `step_one_module` body.
    use fluxor::kernel::boot::config;

    // Parse config + loader into the kernel's static state. Pi 5 scans
    // flash via the trailer; QEMU side-loads a packed blob at a fixed
    // address. `prepare_graph` reads STATIC_CONFIG / STATIC_LOADER from
    // there.
    loader::reset_state_arena();
    let static_state_ok = {
        #[cfg(not(feature = "board-pi5"))]
        {
            // SAFETY: QEMU virt's fluxor.ld places the config blob and
            // modules blob at known phys addresses; mappings established
            // by `boot_mmu::init_page_tables()` above.
            let blob_magic =
                unsafe { core::ptr::read_volatile(QEMU_CONFIG_BLOB_ADDR as *const u32) };
            // SAFETY: as above.
            let modules_blob_magic =
                unsafe { core::ptr::read_volatile(QEMU_MODULES_BLOB_ADDR as *const u32) };
            if blob_magic == config::MAGIC_CONFIG
                && modules_blob_magic == loader::MODULE_TABLE_MAGIC
            {
                // SAFETY: caller upholds `# Safety` invariant — blobs at
                // the QEMU known addresses remain mapped for the whole boot.
                unsafe {
                    // The config's window is the gap QEMU leaves it
                    // before the module blob; the parser refuses any
                    // header that declares more than that.
                    scheduler::populate_static_state(
                        QEMU_CONFIG_BLOB_ADDR as *const u8,
                        QEMU_MODULES_BLOB_ADDR - QEMU_CONFIG_BLOB_ADDR,
                        QEMU_MODULES_BLOB_ADDR as *const u8,
                    )
                }
                .is_ok()
            } else {
                // SAFETY: boot-time single-thread init.
                let loader_ref = unsafe { scheduler::static_loader_mut() };
                // SAFETY: as above.
                let cfg_ref = unsafe { scheduler::static_config_mut() };
                let l_ok = loader_ref.init().is_ok();
                let c_ok = config::read_config_into(cfg_ref);
                l_ok && c_ok
            }
        }
        #[cfg(feature = "board-pi5")]
        {
            // Flash-trailer path: the loader scans the packed image for
            // the module table; the config sits in the same trailer.
            // SAFETY: boot-time single-thread init.
            let loader_ref = unsafe { scheduler::static_loader_mut() };
            // SAFETY: as above.
            let cfg_ref = unsafe { scheduler::static_config_mut() };
            let l_ok = loader_ref.init().is_ok();
            let c_ok = config::read_config_into(cfg_ref);
            l_ok && c_ok
        }
    };
    if !static_state_ok {
        uart_puts(b"[config] parse / loader failed\r\n");
        boot_fail_stop();
    }
    // SAFETY: scheduler-thread boot-time read.
    let cfg = unsafe { scheduler::static_config() };
    let n_modules = cfg.module_count as usize;
    let n_edges = cfg.edge_count as usize;

    // Reconfigure the timer tick from config.tick_us.
    let tick_us = if cfg.header.tick_us > 0 {
        cfg.header.tick_us as u32
    } else {
        1000
    };
    // freq is in Hz, so ticks_per_us = freq / 1_000_000
    // ticks = tick_us * (freq / 1_000_000) = tick_us * freq / 1_000_000
    let core0_ticks = if freq > 0 {
        ((tick_us as u64) * freq / 1_000_000) as u32
    } else {
        62500 * tick_us / 1000
    };
    // Core 0 runs the default domain (domain 0); its Tier-0 cadence is the
    // global tick. Seed core 0's per-core deadline slot and arm the timer.
    // Cores 1-3 re-seed their own slots from `domain_tick_us` in
    // `secondary_core_main`; the per-core slot is what survives the IRQ
    // handler's reload, so each domain keeps its own rate.
    let core0 = (current_core_id() as usize).min(NEXT_DEADLINE_TICKS.len() - 1);
    NEXT_DEADLINE_TICKS[core0].store(core0_ticks, Ordering::Relaxed);
    // SAFETY: generic-timer regs are per-CPU; the boot core is the sole writer.
    unsafe {
        timer::timer_set(core0_ticks);
    }
    uart_puts(b"[timer] tick_us=");
    uart_put_u32(tick_us);
    uart_puts(b"\r\n");

    // The SGI wake doorbell and the absolute `cval` re-arm are off by
    // default and in production; this build-time feature turns them on at
    // boot so the rig can validate them on silicon without disturbing the
    // default path.
    #[cfg(feature = "adaptive_deferred_rig")]
    {
        set_wake_doorbell(true);
        set_absolute_rearm(true);
        log::info!("[adaptive] deferred mechanisms ON (wake_doorbell + absolute_rearm) — rig validation build");
    }

    uart_puts(b"[config] ");
    uart_put_u32(n_modules as u32);
    uart_puts(b" modules, ");
    uart_put_u32(n_edges as u32);
    uart_puts(b" edges\r\n");

    // Test hook (feature `test-plan`): stage an embedded owner plan so the boot
    // `apply_staged()` exercises the live-ownership path on hardware. The blob
    // (one workload in slot 1 owning module 0) is generated by
    // `cargo run -p fluxor-tools --example emit_plan`. test-only, never shipped.
    #[cfg(feature = "test-plan")]
    {
        // One workload (slot 1, gen 2) owning module index 100 — deliberately beyond
        // any real graph module, so the stamp is observable yet harmless (it
        // does not re-own the live net-stack modules and break the netconsole).
        static TEST_PLAN: [u8; 90] = [
            0x46, 0x4c, 0x58, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x64, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x1b, 0x97, 0x01, 0x60, 0x9a, 0xb6, 0xd0, 0xd4, 0x07, 0x20, 0x5f, 0x44,
            0x14, 0x8b, 0xed, 0x5e, 0x42, 0xa9, 0x63, 0x47, 0x6b, 0x72, 0x4d, 0xc6, 0xc8, 0x58,
            0xf7, 0x14, 0x6e, 0x50, 0x2c, 0x35,
        ];
        // SAFETY: TEST_PLAN is 'static; the pointer stays valid for the run.
        unsafe {
            fluxor::kernel::workload::owner_plan::set_staged_plan(
                TEST_PLAN.as_ptr(),
                TEST_PLAN.len(),
            );
        }
        uart_puts(b"[test] staged embedded owner plan\r\n");
    }

    let (module_list, module_count) = match scheduler::prepare_graph() {
        Ok(v) => v,
        Err(_) => {
            uart_puts(b"[graph] prepare_graph failed\r\n");
            loop {
                // SAFETY: WFI is a hint; safe as a fault path.
                unsafe { core::arch::asm!("wfi") };
            }
        }
    };

    // Split every edge whose endpoints live in different domains into a
    // producer-side and a consumer-side channel joined by an SPSC ring.
    if let Err(msg) = cross::bridge_edges() {
        // Boot posture: a reservation shortfall halts — rebinding a consumer
        // to a handle no pump fills would strand every byte the producer
        // writes, and there is no earlier generation to fall back to.
        uart_puts(b"[graph] ");
        uart_puts(msg.as_bytes());
        uart_puts(b"\r\n");
        loop {
            // SAFETY: WFI is a hint; safe as a fault path.
            unsafe { core::arch::asm!("wfi") };
        }
    }

    // Instantiate + activate the compiled graph (shared with live rebuild).
    let total_mods = match domains::instantiate(&module_list, module_count) {
        Ok(n) => n,
        Err(why) => {
            // Fail closed at boot. Running a graph whose modules did not all
            // load converts a loud, local failure into a silent one that
            // surfaces later as missing data, far from the cause; running it
            // with an invalid owner plan runs it with isolation off.
            for _ in 0..8 {
                debug_drain_poll_core0();
            }
            match why {
                domains::InstantiateError::Modules(failed) => {
                    uart_puts(b"[inst] REFUSING GRAPH: ");
                    uart_put_u32(failed as u32);
                    uart_puts(b" module(s) failed to instantiate\r\n");
                }
                domains::InstantiateError::OwnerPlan(_) => {
                    uart_puts(b"[owner] REFUSING GRAPH: staged plan invalid\r\n");
                }
            }
            boot_fail_stop();
        }
    };

    uart_puts(b"[inst] ");
    uart_put_u32(total_mods as u32);
    uart_puts(b" modules loaded total\r\n");

    fluxor::kernel::exec::scheduler::finalize_instantiation_accounting();

    // Admit resident workloads declared in the config's `[FXPD]` section
    // (`workloads:` / `combine <two-graph.yaml>`) as workload owners via
    // `apply_add` + finalize. Boot-time, before the run loops start. No-op
    // without a workload section; the multi-graph runner multiplexes the
    // workloads with the base graph on the shared cooperative runner.
    fluxor::kernel::exec::scheduler::admit_resident_workloads_from_config();

    uart_puts(b"[cross] channels=");
    uart_put_u32(cross::cross_edge_count() as u32);
    uart_puts(b" dma_arena_used=");
    uart_put_u32(multicore::dma_arena_used() as u32);
    uart_puts(b"\r\n");

    // Wake a core for each domain with modules; each waits for the release.
    // A domain whose core did not come up would hold its modules unstepped,
    // so the graph is refused instead.
    wake_secondary_cores();
    if let Some(d) = domains::coreless_domain(&PLATFORM) {
        uart_puts(b"[wake] REFUSING GRAPH: no core came up for domain ");
        uart_put_u32(d as u32);
        uart_puts(b"\r\n");
        boot_fail_stop();
    }

    // The secondaries may enter their loops.
    domains::release();

    uart_puts(b"[sched] starting domain 0 on core 0\r\n");

    // Flush buffered early-boot log bytes to the UART before we enter
    // the tick loop. Each poll moves up to the staging size (1 KB),
    // so a short burst covers typical boot chatter; anything left
    // over flushes during the first few ticks.
    for _ in 0..8 {
        debug_drain_poll_core0();
    }

    domains::run(0, &PLATFORM)
}

// ============================================================================
// The shared domain loop's platform part
// ============================================================================

/// What this platform does around the shared domain loop.
static PLATFORM: domains::Platform = domains::Platform {
    has_core: bcm_has_core,
    after_pass: bcm_after_pass,
    after_step: bcm_after_step,
};

/// Domain `n` runs on core `n`, once that core has come up.
fn bcm_has_core(domain_id: usize) -> bool {
    u8::try_from(domain_id).is_ok_and(multicore::is_core_started)
}

/// After each pass: core 0 drains the log to the UART; the cooperative and
/// high-rate loops report the die temperature; a high-rate domain 0 reports
/// the cross-domain bridges.
fn bcm_after_pass(domain_id: usize, core_id: usize, tier: domains::Tier) {
    if core_id == 0 {
        debug_drain_poll_core0();
    }
    if matches!(tier, domains::Tier::Cooperative | domains::Tier::HighRate) {
        maybe_emit_soc_temp(core_id);
    }
    if tier == domains::Tier::HighRate && domain_id == 0 && xdom_due() {
        report_cross_domain();
    }
}

/// Owner roots' background jobs (making, charging, removing a workload's
/// root) ride the domain that steps the node's own `fs` provider, so they
/// never race its step.
fn bcm_after_step(domain_id: usize) {
    let fs_domain = fluxor::kernel::module::provider::node_default_module(
        fluxor::kernel::module::provider::contract::FS as usize,
    )
    .map(|m| scheduler::module_domain_id(m) as usize);
    if fs_domain == Some(domain_id) {
        // SAFETY: on the domain that steps the node's `fs` provider.
        unsafe { fluxor::platform::owner_root::step() };
    }
}

/// The cross-domain bridges' health, on the ~0.5 s `[xdom]` cadence: drops
/// (the ring refused a frame), backpressure (a pass that left frames queued),
/// frames pending toward each domain, each domain's pass count, and, for each
/// ordered pair of domains that has carried frames, those pushed into the ring
/// and those delivered. A latched panic on any core is reported with it.
fn report_cross_domain() {
    let (drops, bp, _sb) = cross::cross_domain_stats();
    let depth = cross::cross_domain_queue_depths();
    let passes: [u32; scheduler::MAX_DOMAINS] = core::array::from_fn(domains::domain_ticks);
    log::info!("[xdom] drops={drops} bp={bp} depth={depth:?} passes={passes:?}");
    for from in 0..scheduler::MAX_DOMAINS {
        for to in (0..scheduler::MAX_DOMAINS).filter(|&to| to != from) {
            let (pushed, delivered) = cross::flow(from, to);
            if pushed != 0 || delivered != 0 {
                log::info!("[xdom] {from}>{to} pushed={pushed} delivered={delivered}");
            }
        }
    }
    let pc = PANIC_CORE.load(Ordering::Relaxed);
    if pc != 0xFFFF_FFFF {
        let line = PANIC_LINE.load(Ordering::Relaxed);
        let fptr = PANIC_FILE_PTR.load(Ordering::Relaxed);
        let flen = PANIC_FILE_LEN.load(Ordering::Relaxed) as usize;
        let file = if fptr != 0 && flen > 0 && flen < 256 {
            // SAFETY: file ptr/len come from a `&'static str` in the shared
            // address space; bounded length (<256), read-only.
            let bytes = unsafe { core::slice::from_raw_parts(fptr as *const u8, flen) };
            core::str::from_utf8(bytes).unwrap_or("?")
        } else {
            "?"
        };
        log::info!("[PANIC] core={pc} at {file}:{line}");
    }
}

// ============================================================================
// Secondary core entry points
// ============================================================================

/// Entry point for secondary cores after wake: once the primary has
/// released the graph, set up this core's GIC half and its tick at the
/// domain's rate, then run the domain's loop. Only a domain with modules has
/// its core woken.
fn secondary_core_main_1() -> ! {
    secondary_core_main(1)
}

fn secondary_core_main_2() -> ! {
    secondary_core_main(2)
}

fn secondary_core_main_3() -> ! {
    secondary_core_main(3)
}

fn secondary_core_main(domain_id: usize) -> ! {
    while !domains::released() {
        // SAFETY: WFE is a hint to wait until the next event.
        unsafe { core::arch::asm!("wfe") };
    }

    let core_id = current_core_id();
    uart_puts(b"[core");
    uart_put_u32(core_id as u32);
    uart_puts(b"] started, domain=");
    uart_put_u32(domain_id as u32);
    uart_puts(b"\r\n");
    log::info!("[core{core_id}] started, domain={domain_id}");

    let ticks = domains::seed_core_tick(domain_id);
    // SAFETY: once, before the domain loop starts; the GIC CPU interface and
    // the generic timer are this core's own.
    unsafe {
        gic::init_secondary();
        timer::timer_set(ticks);
        core::arch::asm!("msr daifclr, #2");
    }
    domains::run(domain_id, &PLATFORM)
}

/// How long a woken core has to report that it came up.
const CORE_START_WAIT_US: u64 = 1_000_000;

/// Wake the secondary cores whose domains have modules, after the primary has
/// instantiated the graph, and wait for each to come up. Domain N runs on
/// core N.
pub fn wake_secondary_cores() {
    let entries: [fn() -> !; 3] = [
        secondary_core_main_1,
        secondary_core_main_2,
        secondary_core_main_3,
    ];

    for core_id in 1u8..=3 {
        let domain_id = core_id as usize;
        if !domains::is_active(domain_id) {
            continue;
        }
        uart_puts(b"[wake] core ");
        uart_put_u32(core_id as u32);
        uart_puts(b" for domain ");
        uart_put_u32(domain_id as u32);
        uart_puts(b"\r\n");
        if !multicore::wake_core(core_id, entries[(core_id - 1) as usize]) {
            uart_puts(b"[wake] FAILED core ");
            uart_put_u32(core_id as u32);
            uart_puts(b"\r\n");
            continue;
        }
        let until =
            timer::read_timer_count_64() + CORE_START_WAIT_US * timer::timer_freq() / 1_000_000;
        while !multicore::is_core_started(core_id) && timer::read_timer_count_64() < until {
            core::hint::spin_loop();
        }
    }
}

// ============================================================================
// BCM2712 HAL Ops
// ============================================================================

use fluxor::kernel::sys::hal::HalOps;

fn bcm_disable_interrupts() -> u32 {
    let daif: u32;
    // SAFETY: reads + writes the DAIF system register; preserves_flags +
    // nomem/nostack mean the asm has no side effects on memory.
    unsafe {
        core::arch::asm!(
            "mrs {0:x}, daif",
            "msr daifset, #2",
            out(reg) daif,
            options(nomem, nostack, preserves_flags),
        );
    }
    daif
}

fn bcm_restore_interrupts(saved: u32) {
    // SAFETY: writes DAIF (interrupt-mask system register); no memory effects.
    unsafe {
        core::arch::asm!(
            "msr daif, {0:x}",
            in(reg) saved,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// WFI wake-doorbell toggle. Default OFF: the wake path emits only `SEV`,
/// paired with the idle-deadline clamp. When ON, the wake path also
/// broadcasts a GIC SGI so a WFI-parked core wakes immediately rather than
/// at its next timer tick — at the cost of an MMIO write on the hot
/// `event_signal` / cross-domain SPSC-push paths. Enable it
/// only where the clamp's first-request-after-idle latency is measured to be
/// insufficient.
static WAKE_DOORBELL: AtomicBool = AtomicBool::new(false);

/// Enable/disable the SGI wake doorbell at runtime (default off).
pub fn set_wake_doorbell(on: bool) {
    WAKE_DOORBELL.store(on, Ordering::Relaxed);
}

/// Enable/disable the absolute (`cval`) timer re-arm at runtime (default
/// off: the relative `tval` re-arm). See `exception::ABSOLUTE_REARM`.
pub fn set_absolute_rearm(on: bool) {
    exception::ABSOLUTE_REARM.store(on, Ordering::Relaxed);
}

/// Broadcast the wake doorbell SGI to all cores, IFF the doorbell is
/// enabled. Called alongside `SEV` on every wake path so a WFI-parked core
/// (which `SEV` cannot break) also wakes. No-op (one relaxed load) when off.
#[inline(always)]
pub fn wake_doorbell() {
    if WAKE_DOORBELL.load(Ordering::Relaxed) {
        #[cfg(target_arch = "aarch64")]
        // SAFETY: single MMIO write to the boot-mapped GIC distributor.
        unsafe {
            gic::send_sgi_all(gic::WAKE_SGI);
        }
    }
}

fn bcm_wake_scheduler() {
    // SAFETY: SEV broadcasts an event to wake WFE-parked cores; hint-only.
    unsafe { core::arch::asm!("sev") };
    // SEV does NOT break WFI, which the domain loops idle on. When the
    // doorbell is enabled, also send an SGI so a WFI-parked core wakes
    // immediately.
    wake_doorbell();
}

/// Portable `sleep_until`. The per-core periodic timer (the idle backstop,
/// ≤ `tick_max_us`) is already armed, and any bound IRQ — plus the wake
/// doorbell SGI — breaks WFI. So a single WFI blocks until the next
/// wake without programming a separate one-shot (which would race the
/// IRQ-handler's per-core deadline reload). Returns UNKNOWN: WFI cannot
/// report its wake source, so the caller must re-check its work/deadline
/// state.
fn bcm_sleep_until(_deadline_us: u64) -> u32 {
    // SAFETY: WFI is a hint that parks the core until an unmasked IRQ.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("wfi")
    };
    fluxor::kernel::sys::hal::WOKEN_UNKNOWN
}

/// Monotonic milliseconds since boot. Reads the ARM generic timer
/// (`CNTPCT_EL0`) and scales by `cntfrq_el0 / 1000`. Backs
/// `dev_millis` / `syscall_millis` for module-side timing such as
/// NVMe arena probe perf measurement and TCP RTT estimation.
fn bcm_now_millis() -> u64 {
    let counter = bcm_read_counter();
    let freq = bcm_counter_freq();
    if freq == 0 {
        return 0;
    }
    counter.wrapping_mul(1000) / freq
}

/// Monotonic microseconds since boot. Same source as
/// `bcm_now_millis`, scaled to µs for sub-millisecond profiling.
fn bcm_now_micros() -> u64 {
    let counter = bcm_read_counter();
    let freq = bcm_counter_freq();
    if freq == 0 {
        return 0;
    }
    counter.wrapping_mul(1_000_000) / freq
}
fn bcm_tick_count() -> u32 {
    // The HAL `tick_count` is wall-clock milliseconds from the counter, not
    // the scheduler's logical tick (`DBG_TICK`): "1 tick == 1 ms" holds only
    // at the fixed 1 ms default, while an adaptive domain varies its period
    // and an idle one stops advancing the tick, so only the counter gives
    // "ms since boot" under any pacing — as `rp_tick_count` does from its
    // `Instant`.
    bcm_now_millis() as u32
}

// ============================================================================
// BCM2712 SoC thermal sensor (AVS monitor) — read-only
// ============================================================================
//
// The bcm2712 exposes its on-die temperature via the AVS monitor (device-tree
// compatible "brcm,bcm2711-thermal") at SoC peripheral 0x7d542000, which the SoC
// `ranges` map to CPU physical 0x10_7d542000 — inside the aperture boot_mmu
// already maps (table[64]/[65]). The status word at +0x200 is valid only when
// bits 16 and 10 are set; the low 10 bits are the raw code. Per the stock
// device-tree `coefficients = <-550, 450000>`:  T(milli°C) = 450000 − 550·raw.
// Verified on silicon (raw=714 → 57.3 °C, matching the Linux thermal zone).

#[cfg(feature = "board-pi5")]
const AVS_TEMP_STATUS: usize = 0x10_7d54_2200;
#[cfg(feature = "board-pi5")]
const AVS_TEMP_VALID: u32 = (1 << 16) | (1 << 10);

/// SoC die temperature in milli-Celsius, or `None` if the sensor reading is not
/// yet valid. Board-pi5 only (no AVS monitor on the QEMU virt model).
#[cfg(feature = "board-pi5")]
pub fn soc_temp_mc() -> Option<i32> {
    // SAFETY: AVS_TEMP_STATUS is a fixed, side-effect-free MMIO status register
    // in the SoC peripheral aperture mapped by boot_mmu.
    let v = unsafe { core::ptr::read_volatile(AVS_TEMP_STATUS as *const u32) };
    if v & AVS_TEMP_VALID != AVS_TEMP_VALID {
        return None;
    }
    let raw = (v & 0x3ff) as i32;
    Some(450_000 - 550 * raw)
}

#[cfg(not(feature = "board-pi5"))]
pub fn soc_temp_mc() -> Option<i32> {
    None
}

/// Emit the SoC die temperature to the log/telemetry stream on a ~5 s
/// wall-clock cadence (core 0 only). This is the direct signal that the active
/// cooler is working — the DUT should cool under a sustained load instead of
/// throttling — and it is what the thermal floor-decay measurement consumes.
fn maybe_emit_soc_temp(core_id: usize) {
    if core_id != 0 {
        return;
    }
    const TEMP_INTERVAL_MS: u64 = 5_000;
    static LAST_TEMP_MS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    static LAST_CT0: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let now = bcm_now_millis();
    let last = LAST_TEMP_MS.load(Ordering::Relaxed);
    if now.wrapping_sub(last) < TEMP_INTERVAL_MS {
        return;
    }
    LAST_TEMP_MS.store(now, Ordering::Relaxed);
    let ct0 = exception::CORE_TICKS[0].load(Ordering::Relaxed);
    // irq_hz = the actual timer-IRQ (wakeup) RATE over the last interval.
    // On an idle adaptive domain this falls far below the nominal
    // `1e6/tick_us`. This is the SAMPLING-ROBUST idle signal: unlike
    // the instantaneous dl0_us below, it averages over the whole interval, so it
    // isn't skewed by the fact that the emit pass itself is busy.
    let dt_ms = now.wrapping_sub(last).max(1);
    let last_ct0 = LAST_CT0.swap(ct0, Ordering::Relaxed);
    let irq_hz = (ct0.wrapping_sub(last_ct0) as u64 * 1000 / dt_ms) as u32;
    // dl0_us = core 0's deadline at THIS (busy) emit instant; dl0_max_us = the
    // most-relaxed deadline reached since the last emit (sampling-robust — shows
    // the pacer relaxed even though the emit pass reads busy). Reset the
    // interval-max after reading it.
    let freq = timer::timer_freq();
    let to_us = |ticks: u64| -> u32 {
        if freq > 0 {
            (ticks * 1_000_000 / freq) as u32
        } else {
            0
        }
    };
    let dl0_us = to_us(exception::NEXT_DEADLINE_TICKS[0].load(Ordering::Relaxed) as u64);
    let dl0_max_us = domains::take_domain0_max_deadline_us();
    // worst_us = the pacer floor's input (decaying peak-hold step time); ovr =
    // per-domain budget overruns. Together they show whether the domain stays
    // inside budget and whether the floor rises on load and decays on cool-down.
    let worst_us = scheduler::domain_worst_step_us(0);
    let ovr = scheduler::domain_budget_overruns(0);
    // Surface the Tier-2 IRQ-dispatch count on the reliable core-0 cadence so a
    // dedicated-core Tier-2 module's `module_isr_entry` firing is observable
    // over UDP (its own loop logs only every 1M wakes).
    let t2disp = fluxor::kernel::exec::isr_tier::tier2_dispatch_count();
    if let Some(mc) = soc_temp_mc() {
        log::info!(
            "[therm] soc_temp_mC={mc} t_ms={now} ct0={ct0} irq_hz={irq_hz} dl0_us={dl0_us} dl0_max_us={dl0_max_us} worst_us={worst_us} ovr={ovr} t2disp={t2disp}"
        );
    } else {
        log::info!(
            "[therm] soc_temp_mC=na t_ms={now} ct0={ct0} irq_hz={irq_hz} dl0_us={dl0_us} dl0_max_us={dl0_max_us} worst_us={worst_us} ovr={ovr} t2disp={t2disp}"
        );
    }
    // Re-emit the fan PWM register readback on the same cadence. The one-shot
    // boot report is pre-DHCP and never reaches the UDP stream; this recurring
    // copy does, so the rig can confirm the channel stays programmed (DUTY,
    // enable bit) for the whole run.
    rp1::fan_report();
}

/// Wall-clock gate for the `[xdom]` cross-domain freeze/telemetry dump. Gated on
/// a fixed ~0.5 s wall-clock cadence so the telemetry rate is decoupled from
/// domain 0's `tick_count` — which, once domain 0 paces variably (adaptive
/// idle), advances slowly and would otherwise stall the sibling-lane liveness
/// windows. Core 0 / the domain-0 pump is the sole caller.
fn xdom_due() -> bool {
    const XDOM_INTERVAL_MS: u64 = 500;
    static LAST_XDOM_MS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    let now = bcm_now_millis();
    if now.wrapping_sub(LAST_XDOM_MS.load(Ordering::Relaxed)) < XDOM_INTERVAL_MS {
        return false;
    }
    LAST_XDOM_MS.store(now, Ordering::Relaxed);
    true
}

fn bcm_flash_base() -> usize {
    0
}
fn bcm_flash_end() -> usize {
    0
}
fn bcm_apply_code_bit(addr: usize) -> usize {
    addr
}
// BCM address-validation hooks. aarch64 instructions are 4-byte
// aligned and module headers / code bases are also 4-byte aligned on
// bare-metal, so requiring `addr & 0x3 == 0` catches ABI corruption
// and the "manifest claims an offset that lands mid-instruction"
// failure mode before the kernel calls into a bad fn pointer.
fn bcm_validate_fn_addr(addr: usize) -> bool {
    addr != 0 && (addr & 0x3) == 0
}
fn bcm_validate_module_base(addr: usize) -> bool {
    addr != 0 && (addr & 0x3) == 0
}
fn bcm_validate_fn_in_code(addr: usize, code_base: usize, code_size: u32) -> bool {
    // Belt-and-braces check against `[code_base, code_base + code_size)`.
    // `get_export_addr` already rejects manifests claiming offsets past
    // `code_size`, but the platform-side check runs uniformly and
    // mirrors `linux_validate_fn_in_code`.
    if code_base == 0 || code_size == 0 {
        return false;
    }
    let end = code_base.saturating_add(code_size as usize);
    addr >= code_base && addr < end
}
fn bcm_verify_integrity(computed: &[u8], expected: &[u8]) -> bool {
    computed.len() == expected.len() && computed == expected
}

/// OTA staging cache maintenance. EL1 DRAM is mapped RWX by the boot
/// page tables, so no permission flip is needed; what IS needed before
/// executing freshly written module code is coherency between the data
/// cache the writes landed in and the instruction stream: clean D-cache
/// to PoU + invalidate I-cache over the region, then DSB/ISB
/// (ARM DDI 0487, self-modifying-code sequence).
fn bcm_ota_stage_protect(base: *mut u8, len: usize, executable: bool) -> bool {
    if !executable {
        // Region is plain RW DRAM; nothing to undo.
        return true;
    }
    const LINE: usize = 64;
    let start = (base as usize) & !(LINE - 1);
    let end = (base as usize).saturating_add(len);
    let mut p = start;
    while p < end {
        // SAFETY: dc/ic by VA over a valid mapped DRAM region; cache
        // maintenance has no memory effects beyond coherency.
        unsafe {
            core::arch::asm!("dc cvau, {a}", a = in(reg) p);
        }
        p += LINE;
    }
    // SAFETY: barriers + broadcast I-cache invalidate, per the
    // architectural code-modification sequence.
    unsafe {
        core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb");
    }
    true
}

fn bcm_pic_barrier() {
    // SAFETY: DSB SY + ISB are architectural barriers — no memory effects.
    unsafe { core::arch::asm!("dsb sy", "isb") };
}

// Step guard: a software elapsed-time check, each core against its own window.

/// The generic-timer counter the board runs on (`TIMER_COUNTER`).
#[inline(always)]
fn bcm_read_counter() -> u64 {
    timer::read_timer_count_64()
}

fn bcm_counter_freq() -> u64 {
    timer::timer_freq()
}

fn bcm_step_guard_init() {}

fn bcm_step_guard_arm(deadline_us: u32) {
    use fluxor::kernel::exec::step_guard;
    step_guard::clear_timed_out();
    step_guard::set_armed(true);
    let freq = bcm_counter_freq();
    let ticks = (deadline_us as u64 * freq) / 1_000_000;
    step_guard::set_window(bcm_read_counter(), ticks);
}

fn bcm_step_guard_disarm() {
    fluxor::kernel::exec::step_guard::set_armed(false);
}

fn bcm_step_guard_post_check() {
    use fluxor::kernel::exec::step_guard;
    if !step_guard::is_armed() {
        return;
    }
    let (start, deadline) = step_guard::window();
    if bcm_read_counter().wrapping_sub(start) >= deadline {
        step_guard::set_timed_out();
    }
    step_guard::set_armed(false);
}

fn bcm_read_cycle_count() -> u32 {
    bcm_read_counter() as u32
}

fn bcm_isr_tier_init() {}

// ISR tier 1b: software poll on aarch64
static mut BCM_ISR_LAST_TICK: u64 = 0;
static mut BCM_ISR_PERIOD_TICKS: u64 = 0;

fn bcm_isr_tier_start(period_us: u32) {
    use fluxor::kernel::exec::isr_tier;
    isr_tier::set_tier1b_period_us(period_us);
    let freq = bcm_counter_freq();
    // SAFETY: ISR-tier statics are set during init before any tier-1b
    // module runs; sole writer on the scheduler thread.
    unsafe {
        BCM_ISR_PERIOD_TICKS = (period_us as u64 * freq) / 1_000_000;
        BCM_ISR_LAST_TICK = bcm_read_counter();
    }
    isr_tier::TIER1B_ACTIVE.store(true, core::sync::atomic::Ordering::Release);
}

fn bcm_isr_tier_stop() {
    fluxor::kernel::exec::isr_tier::TIER1B_ACTIVE
        .store(false, core::sync::atomic::Ordering::Release);
}

fn bcm_isr_tier_poll() {
    use fluxor::kernel::exec::isr_tier;
    if !isr_tier::TIER1B_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    let now = bcm_read_counter();
    // SAFETY: ISR poll runs on the scheduler thread; sole reader.
    let elapsed = now.wrapping_sub(unsafe { BCM_ISR_LAST_TICK });
    // SAFETY: as above.
    let period = unsafe { BCM_ISR_PERIOD_TICKS };
    if period > 0 && elapsed >= period {
        // SAFETY: sole writer for the ISR poll counter.
        unsafe {
            BCM_ISR_LAST_TICK = now;
            isr_tier::isr_tier1b_handler();
        }
    }
}

unsafe fn bcm_net_policy_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use fluxor::abi::contracts::net::policy::caps;
    // `ip` judges filter rules and translates `scope = local` services for
    // the node's own traffic; inbound translation is not realized here.
    let mut c = caps::FILTER | caps::EGRESS | caps::DNAT_LOCAL;
    if fluxor::kernel::net_policy::enforcer_attached() {
        c |= caps::ENFORCED;
    }
    fluxor::kernel::net_policy::dispatch(c, None, handle, opcode, arg, arg_len)
}

unsafe fn bcm_net_route_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    fluxor::kernel::net_route::dispatch(None, handle, opcode, arg, arg_len)
}

fn bcm_init_providers() {
    // BCM2712 system extension for MMIO and NIC opcodes
    fluxor::kernel::module::syscalls::register_system_extension(bcm_system_extension_dispatch);
    // Metal fmod-graph `workload` (0x1A) backend: stages a workload as an
    // owned module subgraph via `apply_add`/owner/lease. Gated exactly like
    // the Linux install — `requires_contract = "workload"` + `platform_raw` in
    // the caller's manifest. The core logic is kernel-generic
    // (`kernel::workload::workload_graph`); this is the metal registration
    // that installs it.
    use fluxor::kernel::module::provider;
    use fluxor::kernel::module::provider::contract as dev_class;
    provider::register(dev_class::WORKLOAD, bcm_workload_dispatch);
    // net.policy (0x1E): the fluxor-native construct is the in-graph packet
    // filter, which READs the tables and ATTACHes; until one has, CAPS leaves
    // ENFORCED clear. Only `scope = local` DNAT is realized (`ip` translates
    // the node's own traffic) — REPLACE refuses a `scope = any` record
    // (ENOSYS) rather than dropping it.
    provider::register(dev_class::NET_POLICY, bcm_net_policy_dispatch);
    // net.route (0x20): the kernel holds the tables; the node's `ip` module
    // realizes them, reading them with TAKE and stating each entry with
    // REPORT (`kernel::net_route`, no platform realizer).
    provider::register(dev_class::NET_ROUTE, bcm_net_route_dispatch);
    // The versioned watchable key store: `storage.object` (0x14) +
    // `storage.namespace` (0x13) over a fixed-capacity RAM store. A
    // store-backed graph reaches its state through these two contracts, and a
    // provider that is absent answers ENOSYS: the graph runs and produces
    // nothing, which is the failure that looks like no failure.
    // SAFETY: single-threaded boot, before any provider dispatch.
    unsafe { fluxor::platform::store::init() };
    // `fs` (0x09) for workloads: the node's own `fat32` layer serves the node
    // alone, so a workload's call reaches this kernel provider, which serves
    // it beneath the workload's own root on that volume, charges it to the
    // workload's storage quota, and removes the root when the workload is
    // released. Without it every workload `fs` call answers ENOSYS.
    // SAFETY: single-threaded boot, before any provider dispatch.
    unsafe { fluxor::platform::owner_root::init(fluxor::platform::owner_root::node_fs) };
    // The board's owner-release hook: an owner's root, and the store handles
    // an owner acting with the node's authority opened.
    provider::register_owner_release_hook(bcm_owner_released);
}

/// Release what a released owner holds of the board's storage: its root
/// (`owner_root`), and the store handles it opened (`store`).
fn bcm_owner_released(owner: fluxor::kernel::workload::owner::OwnerHandle) {
    fluxor::platform::owner_root::release(owner);
    // SAFETY: owner release runs on the scheduler thread, as every dispatch.
    unsafe { fluxor::platform::store::release_opener(owner) };
}

/// Metal `workload` (0x1A) provider dispatch — the thin bcm registration hook.
/// Delegates to the kernel-generic backend
/// (`kernel::workload::workload_graph`), which runs on the primary domain /
/// core 0 (the system graph's domain) so the runtime `apply_add`/`free_owner`
/// it drives honor the primary-only quiesce invariant.
///
/// # Safety
/// Scheduler-thread dispatch only; see `workload_graph::workload_dispatch`.
unsafe fn bcm_workload_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    fluxor::kernel::workload::workload_graph::workload_dispatch(handle, opcode, arg, arg_len)
}

/// Platform-specific per-module cleanup for BCM2712.
///
/// **Intentional no-op.** BCM platform resources (NIC rings, PCIe
/// BARs, DMA arena allocations, MSI vectors) do **not** record their
/// owning module index — the `nic_ring`, `pcie`, and
/// `cross_domain_*` tables allocate by sequence, not by owner. A
/// single faulted module cannot release just its slice of these
/// resources because the kernel doesn't know which slice is its.
/// BCM-side resource reclaim relies on the kernel-wide reset that
/// `prepare_graph` performs on every reconfigure
/// (`channel::reset_all` + `provider::reset_handle_tracking` +
/// `buffer_pool::reset_all`). A meaningful per-module release would
/// require an owner field in each of those tables, which they do not
/// carry: the body is empty by design.
fn bcm_release_module_handles(_module_idx: fluxor::kernel::exec::scheduler::ModuleId) {}
fn bcm_boot_scan() {}
/// No runtime parameter store on bcm2712: every module gets its compiled
/// params in place.
fn bcm_runtime_params(
    _module_id: u16,
    _compiled: &[u8],
) -> fluxor::kernel::sys::hal::RuntimeParams {
    fluxor::kernel::sys::hal::RuntimeParams::Compiled
}

/// A raw register access (`MMIO_READ32`/`MMIO_WRITE32`) reaches device
/// registers and nothing else: a 4-byte-aligned word inside one of the
/// board's device apertures (`boot_mmu::is_device_aperture`). DRAM — the
/// kernel's tables, module state, firmware memory — and address space with
/// nothing behind it are refused, whatever `platform_raw` grants. The first
/// refusal is logged.
fn mmio_target_ok(addr: u64) -> bool {
    let ok = addr & 3 == 0 && boot_mmu::is_device_aperture(addr);
    if !ok {
        report_refused_access("MMIO", addr, 4);
    }
    ok
}

/// Cache maintenance by address (`CACHE_FLUSH_RANGE`, `DMA_FLUSH`,
/// `DMA_INVALIDATE`) acts on DMA buffers only: `[addr, addr + size)` must lie
/// inside one of the arenas the DMA allocators hand out. Anywhere else an
/// invalidate would discard the kernel's dirty lines, and an unmapped address
/// would fault the kernel. The first refusal is logged.
fn dma_range_ok(addr: u64, size: u32) -> bool {
    use fluxor::platform::nic_ring as ring;
    let arenas = [
        (ring::dma_arena_base(), ring::DMA_ARENA_SIZE),
        (ring::pcie1_dma_arena_base(), ring::pcie1_dma_arena_size()),
        (
            ring::pcie1_stream_arena_base(),
            ring::PCIE1_STREAM_ARENA_SIZE,
        ),
    ];
    let ok = addr.checked_add(u64::from(size)).is_some_and(|end| {
        arenas.iter().any(|&(base, len)| {
            let (base, len) = (base as u64, len as u64);
            base != 0 && addr >= base && end <= base + len
        })
    });
    if !ok {
        report_refused_access("DMA cache maintenance", addr, size);
    }
    ok
}

fn report_refused_access(what: &str, addr: u64, size: u32) {
    static REPORTED: AtomicBool = AtomicBool::new(false);
    if !REPORTED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "[platform] {what} at {addr:#x} (+{size}) refused: outside the device apertures \
             and DMA arenas (further refusals not logged)"
        );
    }
}

unsafe fn bcm_system_extension_dispatch(
    _handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    use fluxor::abi::contracts::hal::pcie_device;
    use fluxor::abi::contracts::storage::paged_arena;
    use fluxor::abi::platform::bcm2712::{mmio_dma, msi, nic_ring, pcie_config};
    match opcode {
        mmio_dma::MMIO_READ32 => {
            if arg.is_null() || arg_len < 12 {
                return -22;
            }
            let addr = u64::from_le_bytes([
                *arg,
                *arg.add(1),
                *arg.add(2),
                *arg.add(3),
                *arg.add(4),
                *arg.add(5),
                *arg.add(6),
                *arg.add(7),
            ]);
            if !mmio_target_ok(addr) {
                return fluxor::kernel::sys::errno::EFAULT;
            }
            let val = core::ptr::read_volatile(addr as *const u32);
            let vb = val.to_le_bytes();
            *arg.add(8) = vb[0];
            *arg.add(9) = vb[1];
            *arg.add(10) = vb[2];
            *arg.add(11) = vb[3];
            0
        }
        mmio_dma::MMIO_WRITE32 => {
            if arg.is_null() || arg_len < 12 {
                return -22;
            }
            let addr = u64::from_le_bytes([
                *arg,
                *arg.add(1),
                *arg.add(2),
                *arg.add(3),
                *arg.add(4),
                *arg.add(5),
                *arg.add(6),
                *arg.add(7),
            ]);
            let val = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            if !mmio_target_ok(addr) {
                return fluxor::kernel::sys::errno::EFAULT;
            }
            core::ptr::write_volatile(addr as *mut u32, val);
            0
        }
        mmio_dma::CACHE_FLUSH_RANGE => {
            if arg.is_null() || arg_len < 12 {
                return -22;
            }
            let addr = u64::from_le_bytes([
                *arg,
                *arg.add(1),
                *arg.add(2),
                *arg.add(3),
                *arg.add(4),
                *arg.add(5),
                *arg.add(6),
                *arg.add(7),
            ]);
            let size = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            if !dma_range_ok(addr, size) {
                return fluxor::kernel::sys::errno::EFAULT;
            }
            // Clean + invalidate data cache by VA range
            let mut ptr = (addr as usize) & !63;
            let end = ((addr as usize) + size as usize + 63) & !63;
            while ptr < end {
                core::arch::asm!("dc civac, {}", in(reg) ptr, options(nostack));
                ptr += 64;
            }
            core::arch::asm!("dsb sy");
            0
        }
        mmio_dma::DMA_ALLOC_CONTIG => {
            if arg.is_null() || arg_len < 16 {
                return -22;
            }
            let size = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let align = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            // From the PCIe1 DMA arena, a BSS static the boot tables map
            // Normal Non-cacheable; a device behind PCIe1 reaches it through
            // the inbound BAR1 window (`pcie::enumerate`). See
            // `platform::nic_ring::pcie1_dma_alloc_contig`.
            let phys =
                fluxor::platform::nic_ring::pcie1_dma_alloc_contig(size as usize, align as usize);
            if phys == 0 {
                return -38;
            }
            let pb = (phys as u64).to_le_bytes();
            core::ptr::copy_nonoverlapping(pb.as_ptr(), arg.add(8), 8);
            0
        }
        mmio_dma::DMA_ALLOC_STREAMING => {
            if arg.is_null() || arg_len < 16 {
                return -22;
            }
            let size = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let align = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            // Streaming arena stays WB-cacheable. Callers must pair writes
            // with DMA_FLUSH before device-reads and DMA_INVALIDATE before
            // CPU-reads of device-written regions.
            let phys = fluxor::platform::nic_ring::pcie1_dma_alloc_streaming(
                size as usize,
                align as usize,
            );
            if phys == 0 {
                return -38;
            }
            let pb = (phys as u64).to_le_bytes();
            core::ptr::copy_nonoverlapping(pb.as_ptr(), arg.add(8), 8);
            0
        }
        mmio_dma::DMA_FLUSH => {
            if arg.is_null() || arg_len < 12 {
                return -22;
            }
            let addr = u64::from_le_bytes([
                *arg,
                *arg.add(1),
                *arg.add(2),
                *arg.add(3),
                *arg.add(4),
                *arg.add(5),
                *arg.add(6),
                *arg.add(7),
            ]);
            let size = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            if !dma_range_ok(addr, size) {
                return fluxor::kernel::sys::errno::EFAULT;
            }
            // Clean (but do not invalidate) by VA range. Caller has just
            // written to a streaming DMA buffer and is about to hand it
            // to the device. `dc cvac` pushes dirty lines to PoC so the
            // device reads the up-to-date data; CPU's copy stays valid.
            let mut ptr = (addr as usize) & !63;
            let end = ((addr as usize) + size as usize + 63) & !63;
            while ptr < end {
                core::arch::asm!("dc cvac, {}", in(reg) ptr, options(nostack));
                ptr += 64;
            }
            core::arch::asm!("dsb sy");
            0
        }
        mmio_dma::DMA_INVALIDATE => {
            if arg.is_null() || arg_len < 12 {
                return -22;
            }
            let addr = u64::from_le_bytes([
                *arg,
                *arg.add(1),
                *arg.add(2),
                *arg.add(3),
                *arg.add(4),
                *arg.add(5),
                *arg.add(6),
                *arg.add(7),
            ]);
            let size = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            if !dma_range_ok(addr, size) {
                return fluxor::kernel::sys::errno::EFAULT;
            }
            // Invalidate by VA range. Device has just DMA'd into the
            // region; drop any speculatively-loaded stale CPU lines so
            // the next CPU load returns DMA data. `dc ivac` is the
            // inverse of cvac — it discards without writeback. Use
            // `dc civac` semantics if the caller can't guarantee the
            // buffer was clean (we pick invalidate-only deliberately:
            // streaming DMA buffers are either wholly CPU-owned or
            // wholly device-owned at handoff).
            let mut ptr = (addr as usize) & !63;
            let end = ((addr as usize) + size as usize + 63) & !63;
            while ptr < end {
                core::arch::asm!("dc ivac, {}", in(reg) ptr, options(nostack));
                ptr += 64;
            }
            core::arch::asm!("dsb sy");
            0
        }
        nic_ring::NIC_BAR_MAP => fluxor::platform::pcie::syscall_bar_map(arg, arg_len),
        nic_ring::NIC_BAR_UNMAP => fluxor::platform::pcie::syscall_bar_unmap(arg, arg_len),
        nic_ring::NIC_RING_CREATE => fluxor::platform::nic_ring::syscall_ring_create(arg, arg_len),
        nic_ring::NIC_RING_DESTROY => {
            fluxor::platform::nic_ring::syscall_ring_destroy(arg, arg_len)
        }
        nic_ring::NIC_RING_INFO => {
            fluxor::platform::nic_ring::syscall_ring_info(_handle, arg, arg_len)
        }
        pcie_config::PCIE_RESCAN => {
            let _ = arg;
            let _ = arg_len;
            fluxor::platform::pcie::enumerate() as i32
        }
        pcie_config::PCIE_CFG_READ32 => fluxor::platform::pcie::syscall_cfg_read32(arg, arg_len),
        pcie_config::PCIE_CFG_WRITE32 => fluxor::platform::pcie::syscall_cfg_write32(arg, arg_len),
        msi::PCIE1_MSI_INIT => {
            // arg = [spi_irq: u32 LE]
            if arg.is_null() || arg_len < 4 {
                return -22;
            }
            let spi_irq = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            if !fluxor::platform::pcie::pcie1_msi_init() {
                return fluxor::kernel::sys::errno::ENODEV;
            }
            register_pcie1_msi_spi(spi_irq)
        }
        msi::PCIE1_MSI_ALLOC_VECTOR => {
            if arg.is_null() || arg_len < 20 {
                return -22;
            }
            let event_handle = i32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            match fluxor::platform::pcie::pcie1_msi_alloc_vector(event_handle) {
                None => -12, // ENOMEM
                Some((vec, addr, data)) => {
                    *arg.add(4) = vec;
                    *arg.add(5) = 0;
                    *arg.add(6) = 0;
                    *arg.add(7) = 0;
                    let ab = addr.to_le_bytes();
                    for (i, byte) in ab.iter().enumerate() {
                        *arg.add(8 + i) = *byte;
                    }
                    let db = data.to_le_bytes();
                    for (i, byte) in db.iter().enumerate() {
                        *arg.add(16 + i) = *byte;
                    }
                    0
                }
            }
        }
        // ── PCIE_DEVICE contract ──────────────────────────────────
        pcie_device::BIND => {
            if arg.is_null() || arg_len == 0 {
                return -22;
            }
            let sel = core::slice::from_raw_parts(arg, arg_len);
            fluxor::platform::pcie::bind_selector(sel)
        }
        pcie_device::CLOSE => fluxor::platform::pcie::syscall_device_close(_handle),
        pcie_device::CFG_READ32 => {
            fluxor::platform::pcie::syscall_device_cfg_read32(_handle, arg, arg_len)
        }
        pcie_device::CFG_WRITE32 => {
            fluxor::platform::pcie::syscall_device_cfg_write32(_handle, arg, arg_len)
        }
        pcie_device::BAR_MAP => {
            fluxor::platform::pcie::syscall_device_bar_map(_handle, arg, arg_len)
        }
        pcie_device::MSI_ALLOC => {
            if arg.is_null() || arg_len < 20 || _handle < 0 {
                return -22;
            }
            // The bound handle tells us which root complex's MSI mux
            // to use. Only PCIe1 is wired.
            match fluxor::platform::pcie::bound_device_root(_handle) {
                None => fluxor::kernel::sys::errno::EINVAL,
                Some(root) => {
                    use fluxor::platform::pcie_aliases::PcieRoot;
                    match root {
                        PcieRoot::Pcie1 => {
                            if !fluxor::platform::pcie::pcie1_msi_init() {
                                return fluxor::kernel::sys::errno::ENODEV;
                            }
                            if !PCIE1_MSI_SPI_REGISTERED {
                                let _ = register_pcie1_msi_spi(
                                    fluxor::platform::pcie::BCM2712_PCIE1_MSI_SPI_IRQ,
                                );
                                PCIE1_MSI_SPI_REGISTERED = true;
                            }
                            let event_handle =
                                i32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
                            match fluxor::platform::pcie::pcie1_msi_alloc_vector(event_handle) {
                                None => fluxor::kernel::sys::errno::ENOMEM,
                                Some((vec, addr, data)) => {
                                    *arg.add(4) = vec;
                                    *arg.add(5) = 0;
                                    *arg.add(6) = 0;
                                    *arg.add(7) = 0;
                                    let ab = addr.to_le_bytes();
                                    for (i, byte) in ab.iter().enumerate() {
                                        *arg.add(8 + i) = *byte;
                                    }
                                    let db = data.to_le_bytes();
                                    for (i, byte) in db.iter().enumerate() {
                                        *arg.add(16 + i) = *byte;
                                    }
                                    0
                                }
                            }
                        }
                        PcieRoot::Pcie2 => fluxor::kernel::sys::errno::ENOSYS,
                    }
                }
            }
        }
        pcie_device::INFO => fluxor::platform::pcie::syscall_device_info(_handle, arg, arg_len),
        paged_arena::ARENA_REGISTER => {
            if arg.is_null() || arg_len < 10 {
                return -22;
            }
            let vpages = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let rmax = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            let bt = match *arg.add(8) {
                0 => fluxor::kernel::backing_store::BackingType::None,
                1 => fluxor::kernel::backing_store::BackingType::RamDisk,
                2 => fluxor::kernel::backing_store::BackingType::External,
                _ => return -22,
            };
            let wb = match *arg.add(9) {
                0 => fluxor::kernel::backing_store::WritebackPolicy::Deferred,
                1 => fluxor::kernel::backing_store::WritebackPolicy::WriteThrough,
                _ => return -22,
            };
            let idx = fluxor::kernel::exec::scheduler::current_module_id();
            fluxor::kernel::backing_store::backing_register(idx, vpages, rmax, bt, wb)
        }
        paged_arena::ARENA_READ => {
            if arg.is_null() || arg_len < 14 {
                return -22;
            }
            let arena_id = *arg as usize;
            let vpage = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            let buf = u64::from_le_bytes([
                *arg.add(6),
                *arg.add(7),
                *arg.add(8),
                *arg.add(9),
                *arg.add(10),
                *arg.add(11),
                *arg.add(12),
                *arg.add(13),
            ]) as *mut u8;
            fluxor::kernel::backing_store::backing_read(arena_id, vpage, buf)
        }
        paged_arena::ARENA_WRITE => {
            if arg.is_null() || arg_len < 14 {
                return -22;
            }
            let arena_id = *arg as usize;
            let vpage = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            let buf = u64::from_le_bytes([
                *arg.add(6),
                *arg.add(7),
                *arg.add(8),
                *arg.add(9),
                *arg.add(10),
                *arg.add(11),
                *arg.add(12),
                *arg.add(13),
            ]) as *const u8;
            fluxor::kernel::backing_store::backing_write(arena_id, vpage, buf)
        }
        paged_arena::ARENA_FLUSH => {
            if arg.is_null() || arg_len < 1 {
                return -22;
            }
            let arena_id = *arg as usize;
            fluxor::kernel::backing_store::backing_flush(arena_id)
        }
        paged_arena::ARENA_BULK => {
            if arg.is_null() || arg_len < 18 {
                return -22;
            }
            let arena_id = *arg as usize;
            let op = *arg.add(1);
            let vpage = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            let count = u32::from_le_bytes([*arg.add(6), *arg.add(7), *arg.add(8), *arg.add(9)]);
            let buf_u64 = u64::from_le_bytes([
                *arg.add(10),
                *arg.add(11),
                *arg.add(12),
                *arg.add(13),
                *arg.add(14),
                *arg.add(15),
                *arg.add(16),
                *arg.add(17),
            ]);
            match op {
                paged_arena::ARENA_BULK_OP_WRITE => {
                    fluxor::kernel::backing_store::backing_write_pages(
                        arena_id,
                        vpage,
                        count,
                        buf_u64 as *const u8,
                    )
                }
                paged_arena::ARENA_BULK_OP_READ => {
                    fluxor::kernel::backing_store::backing_read_pages(
                        arena_id,
                        vpage,
                        count,
                        buf_u64 as *mut u8,
                    )
                }
                _ => -22,
            }
        }
        _ => -38, // E_NOSYS
    }
}

/// Protection impls (HalOps seam). On BCM2712 module protection is the EL0
/// MMU.
fn bcm_protection_set_enabled(enabled: bool) {
    isolation::set_enabled(enabled);
}
fn bcm_protection_register_module(
    module_idx: usize,
    code_base: usize,
    code_size: usize,
    state_ptr: *mut u8,
    state_size: usize,
    heap_ptr: *mut u8,
    heap_size: usize,
) -> bool {
    isolation::register_module(
        module_idx,
        code_base as u64,
        code_size as u64,
        state_ptr,
        state_size,
        heap_ptr,
        heap_size,
    )
}
fn bcm_protection_map_page(module_idx: usize, vaddr: usize, phys: usize, writable: bool) {
    isolation::map_4k_page(module_idx, vaddr as u64, phys as u64, writable);
}
fn bcm_protection_unmap_page(module_idx: usize, vaddr: usize) {
    isolation::unmap_4k_page(module_idx, vaddr as u64);
}

// ── VideoCore property mailbox: the TRANSPORT half ──────────────────────
//
// The MESSAGE half — which tag, how the value region is sized, which
// response codes mean the firmware actually answered — is
// `src/kernel/sys/vc_mailbox.rs`, pure data, host-tested. What lives here
// is only what genuinely cannot run off a board: four register accesses,
// cache maintenance, and a bounded poll.

/// ARM↔VC mailbox block. Device tree `mailbox@7c013880` under
/// `soc@107c000000` (`ranges = <0x00 0x10 0x00 0x80000000>`), so physical
/// 0x10_7c01_3880 — the same identity-mapped Device aperture (GB 65,
/// 0x10_4000_0000..) that already carries RNG200 (0x10_7d20_8000) and the
/// GIC. Mapped Device-nGnRnE by `boot_mmu`, so a wrong OFFSET here is at
/// best a bounded timeout and may be an SError from the fabric (this SoC
/// reports errors on some unbacked reads — see the UBUS REPLY_ERR_DIS note
/// in `pcie.rs`); it is NOT a quiet guarantee, which is why the base is
/// pinned against the DT rather than probed.
#[cfg(feature = "board-pi5")]
const VC_MBOX_BASE: usize = 0x10_7c01_3880;
/// Mailbox 0 (VC→ARM): read register and status.
#[cfg(feature = "board-pi5")]
const VC_MBOX_READ: usize = VC_MBOX_BASE;
#[cfg(feature = "board-pi5")]
const VC_MBOX0_STATUS: usize = VC_MBOX_BASE + 0x18;
/// Mailbox 1 (ARM→VC): write register and status.
#[cfg(feature = "board-pi5")]
const VC_MBOX_WRITE: usize = VC_MBOX_BASE + 0x20;
#[cfg(feature = "board-pi5")]
const VC_MBOX1_STATUS: usize = VC_MBOX_BASE + 0x38;
#[cfg(feature = "board-pi5")]
const VC_MBOX_FULL: u32 = 1 << 31;
#[cfg(feature = "board-pi5")]
const VC_MBOX_EMPTY: u32 = 1 << 30;
/// The property-tags channel (ARM→VC).
#[cfg(feature = "board-pi5")]
const VC_CH_PROPERTY: u32 = 8;
/// Status reads per wait before giving up. Device-memory reads are on the
/// order of 100 ns, so this is roughly a tenth of a second — far past the
/// ~100 µs a property call takes, and it runs on a lazy provider call
/// (`TIER`/`DESCRIBE`), never on the boot path, so the worst case is one
/// slow syscall that answers `false`.
#[cfg(feature = "board-pi5")]
const VC_MBOX_POLL_BOUND: u32 = 1_000_000;

/// The property buffer, and the invariant that makes the cache maintenance
/// below LEGAL rather than merely fast.
///
/// `dc ivac` discards a line without writeback. If this buffer shared a
/// cache line with a neighbouring kernel static, invalidating "our" line
/// would throw away the neighbour's dirty data — silent corruption of an
/// unrelated static — and a neighbour dirtied between our pre-ring clean
/// and the VC's response would write back OVER the response. So the buffer
/// must own its cache lines exclusively: aligned to 128 (CWG-safe on A76;
/// lines are 64) and padded to a whole number of lines. 32 words = 128
/// bytes = exactly its own lines; also headroom for any future tag (the
/// OTP exchange needs 16).
#[cfg(feature = "board-pi5")]
#[repr(C, align(128))]
struct VcMboxBuf([u32; 32]);
#[cfg(feature = "board-pi5")]
static mut VC_MBOX_BUF: VcMboxBuf = VcMboxBuf([0; 32]);

/// One caller at a time; the loser answers `false` (fail-safe) rather than
/// sharing the buffer. Needed because provider syscalls execute on the
/// calling core and this platform runs module domains on secondaries —
/// two cores CAN be in `TIER` at once. `compare_exchange` with
/// Acquire/Release so the winner's buffer writes are ordered against the
/// flag; every exit path below releases it, because in a kernel with no
/// RAII a leaked flag would be a permanent SOFTWARE tier until reboot.
#[cfg(feature = "board-pi5")]
static VC_MBOX_BUSY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Clean+invalidate the buffer's lines to PoC. Same idiom as the
/// `DMA_FLUSH`/`DMA_INVALIDATE` handlers above (the PoC pair) — NOT the
/// OTA-staging sequence, which is the PoU/instruction-coherency idiom.
///
/// # Safety
/// `addr..addr+len` must be valid mapped memory owned by the caller.
#[cfg(feature = "board-pi5")]
unsafe fn vc_cache_civac(addr: usize, len: usize) {
    let mut ptr = addr & !63;
    let end = (addr + len + 63) & !63;
    while ptr < end {
        core::arch::asm!("dc civac, {}", in(reg) ptr, options(nostack));
        ptr += 64;
    }
    core::arch::asm!("dsb sy");
}

/// One property-mailbox exchange over `VC_MBOX_BUF[..words]`.
///
/// `true` means the firmware took our address and answered SOMETHING at it
/// — whether it answered *successfully* is the parser's question, asked on
/// the buffer afterwards. Every failure path answers `false`, which the
/// caller turns into `SealProvenance::None`, which is the tier this part
/// reported before any of this existed.
///
/// # Safety
/// Kernel context; MMIO to the mailbox block; exclusive buffer access is
/// guaranteed by `VC_MBOX_BUSY` (taken by the caller).
#[cfg(feature = "board-pi5")]
unsafe fn vc_property_exchange(words: usize) -> bool {
    // Identity map: VA == PA for kernel DRAM on this platform (boot_mmu maps
    // all of DRAM 1:1), so the buffer's address IS its physical address. The
    // mailbox word is 32-bit — `(phys & !0xF) | channel` — so a buffer that
    // ever ended up above 4 GB is refused rather than truncated into
    // somebody else's memory.
    let addr = core::ptr::addr_of_mut!(VC_MBOX_BUF) as usize;
    if addr > (u32::MAX as usize) - 128 {
        return false;
    }
    let len = words * 4;

    // Push the request to PoC so the VC reads what we wrote, and drop our
    // own lines so the response is read from RAM, not stale cache.
    vc_cache_civac(addr, len);

    // Ring: wait for space, write `[phys | channel]`.
    let mut waited = 0u32;
    while core::ptr::read_volatile(VC_MBOX1_STATUS as *const u32) & VC_MBOX_FULL != 0 {
        waited += 1;
        if waited > VC_MBOX_POLL_BOUND {
            return false;
        }
    }
    core::ptr::write_volatile(
        VC_MBOX_WRITE as *mut u32,
        (addr as u32 & !0xF) | VC_CH_PROPERTY,
    );

    // Await OUR response. Status EMPTY==0 only says "a message is waiting";
    // the read word carries the channel in its low nibble and the address
    // above — anything not ours (another channel, RAZ garbage on a quiet
    // bus) is discarded and the wait continues, inside the same bound.
    waited = 0;
    loop {
        while core::ptr::read_volatile(VC_MBOX0_STATUS as *const u32) & VC_MBOX_EMPTY != 0 {
            waited += 1;
            if waited > VC_MBOX_POLL_BOUND {
                return false;
            }
        }
        let word = core::ptr::read_volatile(VC_MBOX_READ as *const u32);
        if word & 0xF == VC_CH_PROPERTY && word & !0xF == addr as u32 & !0xF {
            break;
        }
        waited += 1;
        if waited > VC_MBOX_POLL_BOUND {
            return false;
        }
    }

    // Drop any line speculatively fetched while the VC owned the memory,
    // so the parse below reads the firmware's bytes and not our stale ones.
    vc_cache_civac(addr, len);
    true
}

/// Read this board's provisioned sealing key: the raw customer-OTP bytes,
/// `[SEAL_KEY_MAGIC][28 key bytes]` per the layout pinned in
/// `vc_mailbox.rs`.
///
/// Build (host-tested core) → exchange (the transport above) → parse
/// (host-tested core) → rows to LE bytes. `true` ONLY when a processed,
/// well-formed firmware reply yielded exactly the eight rows — and even
/// then the caller's rule still checks the magic and per-row degeneracy,
/// so a mis-addressed or partially-provisioned read answers `None`.
///
/// Provisioning is a separate act and is not this function's business:
/// blowing fuses is irreversible and belongs to a deliberate, audited step,
/// not to a boot path. This only ever READS.
#[cfg(feature = "board-pi5")]
fn bcm_read_device_seal_key(out: &mut [u8; 32]) -> bool {
    use fluxor::kernel::sys::hal as k;

    if VC_MBOX_BUSY
        .compare_exchange(
            false,
            true,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        // A concurrent caller holds the buffer. `false` here is transient
        // and fail-safe — and `bcm_seal_provenance` memoizes SUCCESS, so
        // after the first good read this path is effectively unreachable.
        return false;
    }
    // SAFETY: the CAS above grants exclusive access to `VC_MBOX_BUF`, the
    // exchange's MMIO targets the DT-pinned mailbox block in the mapped
    // Device aperture, and the flag is released on every path below.
    let ok = unsafe {
        let buf = &mut (*core::ptr::addr_of_mut!(VC_MBOX_BUF)).0;
        let result = (|| {
            let words =
                k::build_get_customer_otp(buf, k::CUSTOMER_OTP_FIRST_ROW, k::CUSTOMER_OTP_ROWS)?;
            if !vc_property_exchange(words) {
                return None;
            }
            let rows = k::parse_get_customer_otp(&buf[..words], k::CUSTOMER_OTP_ROWS)?;
            for (i, row) in rows.iter().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&row.to_le_bytes());
            }
            Some(())
        })();
        result.is_some()
    };
    VC_MBOX_BUSY.store(false, core::sync::atomic::Ordering::Release);
    ok
}

/// Halt at boot, saying why. The boot's own log lines (`[config] ...`,
/// `[inst] module N error ...`) are queued in the log ring, which nothing
/// drains until the scheduler runs, and a fail-stop never reaches it. The
/// ring's tail goes out over the raw UART first (the exception handler's
/// path), so a refused graph says what refused it; then the core parks.
fn boot_fail_stop() -> ! {
    // Static, not stack: wide enough that a graph's long `[domain]` order
    // line does not push the failing module's own line out of the tail.
    static mut TAIL: [u8; 16384] = [0; 16384];
    // SAFETY: single core, boot path, never re-entered (we halt below).
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(TAIL) };
    let n = fluxor::kernel::sys::log_ring::read_tail(buf);
    uart_raw_puts(b"\r\n--- boot halted; log tail (");
    uart_raw_put_u32(n as u32);
    uart_raw_puts(b" bytes) ---\r\n");
    uart_raw_puts(&buf[..n]);
    uart_raw_puts(b"\r\n--- end ---\r\n");
    loop {
        // SAFETY: WFI is a hint to halt the core.
        unsafe { core::arch::asm!("wfi") };
    }
}

/// This board's sealing provenance, memoized on SUCCESS only.
///
/// `key_vault` asks on every `TIER` and every `DESCRIBE`, and each ask is a
/// full cache-maintained mailbox round trip — plus, under concurrency, the
/// busy-flag loser would transiently answer `None`, and a provenance
/// check racing an unrelated `DESCRIBE` would refuse spuriously. A
/// validated `DeviceUnique` read of OTP cannot become truer or falser
/// later, so a confirmed answer is cached forever; a FAILURE is never
/// cached, because "the mailbox was busy" must not become "this board has
/// no device key" for the rest of the boot.
fn bcm_seal_provenance() -> fluxor::kernel::sys::hal::SealProvenance {
    // The customer OTP is read through the Pi 5's VideoCore mailbox; a
    // bcm2712 kernel on another board (QEMU virt) has no mailbox at that
    // address, and touching it is an external abort. No mailbox, no device
    // key: the honest answer is that there is none.
    #[cfg(not(feature = "board-pi5"))]
    {
        fluxor::kernel::sys::hal::SealProvenance::None
    }
    #[cfg(feature = "board-pi5")]
    {
        bcm_seal_provenance_pi5()
    }
}

#[cfg(feature = "board-pi5")]
fn bcm_seal_provenance_pi5() -> fluxor::kernel::sys::hal::SealProvenance {
    use core::sync::atomic::{AtomicU8, Ordering};
    static CONFIRMED: AtomicU8 = AtomicU8::new(0);
    if CONFIRMED.load(Ordering::Acquire) == 1 {
        return fluxor::kernel::sys::hal::SealProvenance::DeviceUnique;
    }
    static REPORTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    let mut blob = [0u8; 32];
    let ok = bcm_read_device_seal_key(&mut blob);
    let p = fluxor::kernel::sys::hal::provenance_from_hardware_key(ok, &blob);
    if matches!(p, fluxor::kernel::sys::hal::SealProvenance::DeviceUnique) {
        // The sealing key: the OTP's key bytes (rows 1..8, after the KSK1
        // magic) expanded under this platform's context, as the provenance
        // rule asks of a key shorter than 32 bytes.
        let mut h = fluxor::kernel::security::crypto::sha256::Sha256::new();
        h.update(b"fluxor/seal/bcm2712/v1");
        h.update(&blob[4..32]);
        let key = h.finalize();
        // SAFETY: written once, before CONFIRMED publishes it.
        unsafe {
            *core::ptr::addr_of_mut!(SEAL_KEY) = key;
        }
        CONFIRMED.store(1, Ordering::Release);
    }
    blob.fill(0);
    if !REPORTED.swap(true, Ordering::AcqRel) {
        // Said once: whether this board can seal at all is the first thing a
        // reader of its log needs to know about its keys.
        let what = if matches!(p, fluxor::kernel::sys::hal::SealProvenance::DeviceUnique) {
            "device key in OTP: keys sealed and kept on the node's store"
        } else {
            "no device key in OTP: keys are not sealed, and live only until reboot"
        };
        log::info!("[seal] {what}");
    }
    p
}

/// The sealing key derived from the OTP, once `bcm_seal_provenance_pi5` has
/// confirmed a device key (never written otherwise).
#[cfg(feature = "board-pi5")]
static mut SEAL_KEY: [u8; 32] = [0; 32];

/// The sealing key, when this board has a device key.
fn bcm_seal_key() -> Option<[u8; 32]> {
    #[cfg(feature = "board-pi5")]
    {
        if matches!(
            bcm_seal_provenance(),
            fluxor::kernel::sys::hal::SealProvenance::DeviceUnique
        ) {
            // SAFETY: published before CONFIRMED, never written again.
            return Some(unsafe { *core::ptr::addr_of!(SEAL_KEY) });
        }
    }
    None
}

/// `HalOps::seal`: ChaCha20-Poly1305 under the OTP-derived key, a fresh
/// nonce from the TRNG; `[nonce:12][ciphertext][tag:16]`. `None` on a board
/// without a device key: nothing is sealed with anything weaker.
fn bcm_seal(aad: &[u8], input: &[u8], out: &mut [u8]) -> Option<usize> {
    use fluxor::kernel::security::crypto::chacha20::chacha20_poly1305_encrypt;
    let key = bcm_seal_key()?;
    let n = input.len();
    if out.len() < 12 + n + 16 {
        return None;
    }
    let mut nonce = [0u8; 12];
    if bcm_csprng_fill(nonce.as_mut_ptr(), 12) != 0 {
        return None;
    }
    out[..12].copy_from_slice(&nonce);
    out[12..12 + n].copy_from_slice(input);
    let tag = chacha20_poly1305_encrypt(&key, &nonce, aad, &mut out[12..12 + n]);
    out[12 + n..12 + n + 16].copy_from_slice(&tag);
    Some(12 + n + 16)
}

/// `HalOps::unseal`: the inverse; `None` on any failure, a wrong `aad` among
/// them, with nothing of a failed open left in `out`.
fn bcm_unseal(aad: &[u8], input: &[u8], out: &mut [u8]) -> Option<usize> {
    use fluxor::kernel::security::crypto::chacha20::chacha20_poly1305_decrypt;
    let key = bcm_seal_key()?;
    if input.len() < 28 {
        return None;
    }
    let n = input.len() - 28;
    if out.len() < n {
        return None;
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&input[..12]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&input[12 + n..]);
    out[..n].copy_from_slice(&input[12..12 + n]);
    if chacha20_poly1305_decrypt(&key, &nonce, aad, &mut out[..n], &tag) {
        Some(n)
    } else {
        out[..n].fill(0);
        None
    }
}

static BCM2712_HAL_OPS: HalOps = HalOps {
    // No store of its own: the vault's records live wherever the graph's
    // `vault_store` module keeps them (`kernel::security::vault_store`), and
    // a graph without one persists no key.
    seal_blob_write: |_, _| false,
    seal_blob_store: || false,
    seal_blob_delete: |_| true,
    seal_blob_read: |_, _| None,
    seal_blob_ready: || true,
    disable_interrupts: bcm_disable_interrupts,
    restore_interrupts: bcm_restore_interrupts,
    wake_scheduler: bcm_wake_scheduler,
    now_millis: bcm_now_millis,
    // No RTC: the wall clock is the network-disciplined one (`time_sync`),
    // anchored by an in-graph time client through `timer::DISCIPLINE`. Until
    // the first anchor it reads 0 and the sync status is `None` — this board
    // cannot tell, which is a different fact from an unsynchronised clock.
    now_unix_millis: || fluxor::kernel::sys::time_sync::unix_millis(bcm_now_micros()),
    clock_sync_status: || fluxor::kernel::sys::time_sync::status(bcm_now_micros()),
    // Sealing derives from the OTP's device key and nothing else: a sealing
    // key stored beside the blob it seals protects nothing and would still
    // read as `HostReadable`, a stronger claim than the truth. A board whose
    // OTP holds no device key cannot seal (`None`), and its vault keeps keys
    // in RAM only: the honest outcome, not a weaker stand-in.
    seal_provenance: bcm_seal_provenance,
    seal: bcm_seal,
    unseal: bcm_unseal,
    now_micros: bcm_now_micros,
    tick_count: bcm_tick_count,
    flash_base: bcm_flash_base,
    flash_end: bcm_flash_end,
    apply_code_bit: bcm_apply_code_bit,
    validate_fn_addr: bcm_validate_fn_addr,
    validate_module_base: bcm_validate_module_base,
    validate_fn_in_code: bcm_validate_fn_in_code,
    verify_integrity: bcm_verify_integrity,
    ota_stage_protect: bcm_ota_stage_protect,
    pic_barrier: bcm_pic_barrier,
    step_guard_init: bcm_step_guard_init,
    step_guard_arm: bcm_step_guard_arm,
    step_guard_disarm: bcm_step_guard_disarm,
    step_guard_post_check: bcm_step_guard_post_check,
    read_cycle_count: bcm_read_cycle_count,
    isr_tier_init: bcm_isr_tier_init,
    isr_tier_start: bcm_isr_tier_start,
    isr_tier_stop: bcm_isr_tier_stop,
    isr_tier_poll: bcm_isr_tier_poll,
    init_providers: bcm_init_providers,
    release_module_handles: bcm_release_module_handles,
    boot_scan: bcm_boot_scan,
    runtime_params: bcm_runtime_params,
    init_gpio: |_| 0, // no GPIO init on aarch64 (handled by PIC modules)
    csprng_fill: bcm_csprng_fill,
    core_id: || current_core_id() as usize,
    irq_bind,
    sleep_until: bcm_sleep_until,
    smp_quiesce_peers: domains::quiesce_peers,
    smp_release_peers: domains::release_quiesce,
    smp_max_domains: || scheduler::MAX_DOMAINS,
    protection_set_enabled: bcm_protection_set_enabled,
    protection_reset: isolation::reset_isolation,
    protection_register_module: bcm_protection_register_module,
    protection_release_module: isolation::release_module,
    protection_gateway_table: isolation::gateway_table,
    protected_call: isolation::protected_call,
    protection_map_page: bcm_protection_map_page,
    protection_unmap_page: bcm_protection_unmap_page,
    // An isolated module's stack sits above an unmapped guard page; the
    // composer admits every other module against that same figure.
    stack_fence_arm: |_| {},
    stack_fence_intact: || true,
    // Binary-safe debug-UART write (PL011) — the telemetry `transport_buffer` sink.
    serial_write: |b| uart::uart_nonblocking_write(b),
};

// iproc-rng200 registers (BCM2712 / Pi 5). DT: soc@107c000000/rng@7d208000
// with ranges <0x0 0x10_0000_0000 0x8000_0000>. The block's map, as its
// Linux driver (`iproc-rng200`) programs it: control, the two soft resets,
// the interrupt status word, and the output FIFO with its count register.
#[cfg(feature = "board-pi5")]
const RNG200_BASE: usize = 0x10_7d20_8000;
#[cfg(feature = "board-pi5")]
const RNG200_CTRL: *mut u32 = RNG200_BASE as *mut u32;
#[cfg(feature = "board-pi5")]
const RNG200_RNG_SOFT_RESET: *mut u32 = (RNG200_BASE + 0x04) as *mut u32;
#[cfg(feature = "board-pi5")]
const RNG200_RBG_SOFT_RESET: *mut u32 = (RNG200_BASE + 0x08) as *mut u32;
#[cfg(feature = "board-pi5")]
const RNG200_INT_STATUS: *mut u32 = (RNG200_BASE + 0x18) as *mut u32;
#[cfg(feature = "board-pi5")]
const RNG200_FIFO_DATA: *const u32 = (RNG200_BASE + 0x20) as *const u32;
#[cfg(feature = "board-pi5")]
const RNG200_FIFO_COUNT: *const u32 = (RNG200_BASE + 0x24) as *const u32;
/// `RNG_CTRL` generator-enable field.
#[cfg(feature = "board-pi5")]
const RNG200_RBGEN_MASK: u32 = 0x1FFF;
#[cfg(feature = "board-pi5")]
const RNG200_RBGEN_ENABLE: u32 = 0x1;
/// `RNG_INT_STATUS`: the generator locked itself out after a health-test
/// failure and produces nothing until reset.
#[cfg(feature = "board-pi5")]
const RNG200_MASTER_FAIL_LOCKOUT: u32 = 1 << 31;
/// `RNG_FIFO_COUNT`: words waiting in the output FIFO.
#[cfg(feature = "board-pi5")]
const RNG200_FIFO_COUNT_MASK: u32 = 0xFF;

/// Bring the generator to a known-running state: generator off, both
/// soft resets pulsed, interrupt status cleared, generator on.
#[cfg(feature = "board-pi5")]
unsafe fn rng200_restart() {
    let ctrl = core::ptr::read_volatile(RNG200_CTRL) & !RNG200_RBGEN_MASK;
    core::ptr::write_volatile(RNG200_CTRL, ctrl);
    core::ptr::write_volatile(RNG200_RNG_SOFT_RESET, 1);
    core::ptr::write_volatile(RNG200_RNG_SOFT_RESET, 0);
    core::ptr::write_volatile(RNG200_RBG_SOFT_RESET, 1);
    core::ptr::write_volatile(RNG200_RBG_SOFT_RESET, 0);
    let pending = core::ptr::read_volatile(RNG200_INT_STATUS);
    core::ptr::write_volatile(RNG200_INT_STATUS, pending);
    core::ptr::write_volatile(RNG200_CTRL, ctrl | RNG200_RBGEN_ENABLE);
}

/// Fill buffer with hardware random bytes.
///
/// Pi 5 (board-pi5): the iproc-rng200 TRNG at 0x10_7d20_8000. A word is
/// taken only from a running generator's FIFO, and a zero word is never
/// entropy: the source presents zeros while unseeded or locked out, so
/// zeros are discarded, a run of them restarts the block, and a run that
/// outlasts the restart is a dead source, refused rather than handed out.
/// QEMU virt: CNTPCT_EL0 counter jitter with LCG mixing (weak).
///
/// Returns 0 on success, -1 if the hardware failed to produce entropy —
/// the [`HalOps::csprng_fill`] contract. A byte count is not a success
/// value here: callers test the result against 0, so returning `len`
/// reads as a failure for every non-empty fill.
///
/// [`HalOps::csprng_fill`]: crate::kernel::sys::hal::HalOps::csprng_fill
fn bcm_csprng_fill(buf: *mut u8, len: usize) -> i32 {
    // SAFETY: iproc-rng200 MMIO is the documented BCM2712 RNG block;
    // mapped by `boot_mmu::init_page_tables`. `buf`/`len` come from a
    // caller-owned slice via the syscall ABI.
    unsafe {
        #[cfg(feature = "board-pi5")]
        {
            // The waits are time-bounded: the FIFO refills in microseconds,
            // so a wait this long is a hardware fault, not a race.
            const WORD_WAIT_US: u64 = 1_000_000;
            const ZERO_RUN_RESTART: u32 = 64;
            const ZERO_RUN_FATAL: u32 = 4096;
            let status = core::ptr::read_volatile(RNG200_INT_STATUS);
            let ctrl = core::ptr::read_volatile(RNG200_CTRL);
            if status & RNG200_MASTER_FAIL_LOCKOUT != 0
                || ctrl & RNG200_RBGEN_MASK != RNG200_RBGEN_ENABLE
            {
                rng200_restart();
            }
            let mut zero_run = 0u32;
            let mut restarted = false;
            let mut i = 0usize;
            while i < len {
                let deadline = bcm_now_micros() + WORD_WAIT_US;
                while core::ptr::read_volatile(RNG200_FIFO_COUNT) & RNG200_FIFO_COUNT_MASK == 0
                    && bcm_now_micros() < deadline
                {
                    core::hint::spin_loop();
                }
                if core::ptr::read_volatile(RNG200_FIFO_COUNT) & RNG200_FIFO_COUNT_MASK == 0 {
                    uart_puts(b"[rng200] FATAL: entropy timeout\r\n");
                    return -1;
                }
                let word = core::ptr::read_volatile(RNG200_FIFO_DATA);
                if word == 0 {
                    zero_run += 1;
                    if zero_run == ZERO_RUN_RESTART && !restarted {
                        rng200_restart();
                        restarted = true;
                    }
                    if zero_run >= ZERO_RUN_FATAL {
                        uart_puts(b"[rng200] FATAL: only zero words\r\n");
                        return -1;
                    }
                    continue;
                }
                zero_run = 0;
                let bytes = word.to_le_bytes();
                let mut j = 0;
                while j < 4 && i < len {
                    core::ptr::write_volatile(buf.add(i), bytes[j]);
                    i += 1;
                    j += 1;
                }
            }
        }

        #[cfg(not(feature = "board-pi5"))]
        {
            // QEMU virt: no hardware RNG. Use counter jitter + LCG mixing.
            // Adequate for testing only.
            let mut state: u64 = 0;
            let mut i = 0usize;
            while i < len {
                let cnt: u64;
                core::arch::asm!("mrs {}, cntvct_el0", out(reg) cnt);
                state ^= cnt;
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                core::ptr::write_volatile(buf.add(i), (state >> 32) as u8);
                i += 1;
            }
        }
    }
    0
}

/// Panic latch — a panic on a secondary core prints to the (possibly unwired)
/// UART then halts. These atomics let core 0, which owns the live UDP debug
/// drain, surface the panic site over network telemetry. file ptr+len point
/// into 'static rodata (kernel or PIC module — shared address space), so core 0
/// can reconstruct the `&str`.
pub static PANIC_CORE: portable_atomic::AtomicU32 = portable_atomic::AtomicU32::new(0xFFFF_FFFF);
pub static PANIC_LINE: portable_atomic::AtomicU32 = portable_atomic::AtomicU32::new(0);
pub static PANIC_FILE_PTR: portable_atomic::AtomicU64 = portable_atomic::AtomicU64::new(0);
pub static PANIC_FILE_LEN: portable_atomic::AtomicU32 = portable_atomic::AtomicU32::new(0);

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    // Latch the panic site so core 0 can broadcast it over UDP (the UART
    // dump below is invisible on benches without a wired debug UART). Done
    // first, with plain atomic stores only — no formatting/alloc in here.
    if let Some(loc) = info.location() {
        PANIC_LINE.store(loc.line(), Ordering::Relaxed);
        PANIC_FILE_PTR.store(loc.file().as_ptr() as u64, Ordering::Relaxed);
        PANIC_FILE_LEN.store(loc.file().len() as u32, Ordering::Relaxed);
    }
    PANIC_CORE.store(current_core_id() as u32, Ordering::Relaxed);
    // Emergency sink: platform-owned, separate from the normal
    // DebugTx drain. Writes directly to the UART hardware because
    // the scheduler is dead and the debug drain won't run again.
    // Gated on UART_READY so we don't poke the peripheral before
    // `uart_init` has run.
    if UART_READY.load(Ordering::Relaxed) != 0 {
        uart_raw_puts(b"\r\n!!! PANIC on core ");
        uart_raw_put_u32(current_core_id() as u32);
        uart_raw_puts(b"\r\n");
        if let Some(loc) = info.location() {
            uart_raw_puts(b"  at ");
            uart_raw_puts(loc.file().as_bytes());
            uart_raw_putc(b':');
            uart_raw_put_u32(loc.line());
            uart_raw_puts(b"\r\n");
        }
        let mut buf = [0u8; 1024];
        let n = fluxor::kernel::sys::log_ring::read_tail(&mut buf);
        if n > 0 {
            uart_raw_puts(b"--- log tail (");
            uart_raw_put_u32(n as u32);
            uart_raw_puts(b" bytes) ---\r\n");
            uart_raw_puts(&buf[..n]);
            uart_raw_puts(b"\r\n--- end ---\r\n");
        }
    }
    loop {
        // SAFETY: WFI is a hint; halts the core until next interrupt.
        unsafe { core::arch::asm!("wfi") };
    }
}
