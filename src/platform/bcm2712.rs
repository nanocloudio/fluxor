// Platform: BCM2712 (Raspberry Pi 5 / CM5) — Cortex-A76, aarch64 bare-metal
//
// Two board configurations (selected at compile time):
//   - QEMU virt (default): PL011 at 0x0900_0000, GICv2 at 0x0800_0000, RAM at 0x4008_0000
//   - Pi 5 / CM5 (feature "board-cm5"): PL011 at 0xFE20_1000, GIC-400 at 0xFF84_1000, RAM at 0x8_0000
//
// Features:
//   - Secondary core parking (Pi 5 boots all 4 cores; cores 1-3 wait in WFE)
//   - Early MMU init with identity-mapped page tables (cacheable DRAM, device MMIO)
//   - RP1 peripheral access via PCIe BAR (GPIO, SPI, I2C register bridges)
//   - Multi-domain execution with config-driven domain assignment and core wakeup
//
// Fully config-driven: the boot image carries trailer, modules.bin, and config.bin
// after the fixed kernel binary, discovered at runtime via the layout trailer.

use core::panic::PanicInfo;
use core::arch::global_asm;
use core::sync::atomic::{AtomicU32, Ordering};

use fluxor::kernel::scheduler;
use fluxor::kernel::loader;
use fluxor::kernel::multicore;
use fluxor::kernel::config::EdgeClass;

// ── Boot-time submodules (binary-private; not exposed via fluxor::kernel) ──
//
// Boot-only support code (UART driver, GIC distributor, ARM Generic
// Timer, RP1 HAL, exception vectors, boot-time MMU page tables,
// kernel `log` backend) is factored into focused submodules under
// `src/platform/bcm2712/` and consumed by `main()`, the domain
// loops, and the BCM HAL ops table.
//
// Submodules that hold shared kernel state (PCIe enumeration,
// runtime MMU isolation, cross-domain channels, NIC DMA arena, paged
// memory) are declared in `src/kernel/mod.rs` and reachable as
// `fluxor::kernel::{pcie, mmu, multicore, nic_ring, …}`. They are
// **not** redeclared here — a loaded module's kernel-facing surface
// is the `fluxor::kernel` namespace, never `src/platform/*`.
#[path = "bcm2712/timer.rs"]
mod timer;
#[path = "bcm2712/boot_mmu.rs"]
mod boot_mmu;
#[path = "bcm2712/uart.rs"]
mod uart;
#[path = "bcm2712/logger.rs"]
mod logger;
#[path = "bcm2712/gic.rs"]
mod gic;
#[path = "bcm2712/rp1.rs"]
mod rp1;
#[path = "bcm2712/exception.rs"]
mod exception;

// Bring UART + GIC + exception names into the binary's namespace so
// existing callsites (`uart_puts(b"…")`, `irq_bind(…)`, `GICD_BASE`,
// `IRQ_BINDING_COUNT`, `TICKS_PER_TICK`, `CORE_TICKS`,
// `current_core_id()`, …) stay unchanged. The submodules own the MMIO
// registers, log-ring drain, debug-tx sink, GIC distributor + CPU
// interface init, IRQ binding state, exception vectors, and the IRQ
// dispatch path.
use uart::*;
use logger::RingLogger;
use gic::*;
use exception::*;

// ============================================================================
// Platform address constants (compile-time board selection)
// ============================================================================

// UART (PL011) — see `bcm2712/uart.rs` for the driver. The `use uart::*`
// in the submodule block above brings UART_BASE/UART_DR/UART_FR/etc.
// into this file's namespace alongside the read/write functions.

// GIC base addresses, IAR/EOIR pointers, and TIMER_PPI live in
// `bcm2712/gic.rs` (brought in via `use gic::*` near the top of this
// file). The constants stay name-identical so existing references in
// the boot path resolve through the glob import unchanged.
#[cfg(not(feature = "board-cm5"))]
const QEMU_CONFIG_BLOB_ADDR: usize = 0x4100_0000;
#[cfg(not(feature = "board-cm5"))]
const QEMU_MODULES_BLOB_ADDR: usize = 0x4200_0000;

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
    "    .word 0",          // package_size (RP/XIP post-BSS relocation only)
    "__package_source_start:",
);

// PL011 UART registers + driver moved to `bcm2712/uart.rs`.

// ============================================================================
// BCM2712 PCIe Root Complex
// ============================================================================
//
// RP1 is connected via PCIe x4. VPU firmware (with enable_rp1_uart=1 and
// pciex4_reset=0 in config.txt) brings up the link and maps RP1 at
// 0x1c_0000_0000 before kernel handoff. We only need to disable ASPM
// for reliable infrequent-access patterns (per RP1 datasheet §3.3.1.3).
// PCIe root complex (onboard) MMIO base — used by rp1_pcie_disable_aspm.
#[cfg(feature = "board-cm5")]
const PCIE_RC_BASE: usize = 0x10_0012_0000;
#[cfg(feature = "board-cm5")] const PCIE_MISC_HARD_PCIE_HARD_DEBUG: usize = 0x4304;
#[cfg(feature = "board-cm5")] const PCIE_MISC_UBUS_CTRL:            usize = 0x40a4;

#[cfg(feature = "board-cm5")]
#[inline(always)]
unsafe fn pcie_read(off: usize) -> u32 {
    core::ptr::read_volatile((PCIE_RC_BASE + off) as *const u32)
}

#[cfg(feature = "board-cm5")]
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
#[cfg(feature = "board-cm5")]
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

#[cfg(feature = "board-cm5")]
#[allow(dead_code)]
mod eth {
    pub const GEM_BASE:     usize = 0x1c_0010_0000;
    pub const ETH_CFG_BASE: usize = 0x1c_0010_4000;

    // --- Cadence GEM core register offsets ---
    pub const NCR:    usize = 0x000;  // Network Control
    pub const NCFGR:  usize = 0x004;  // Network Config
    pub const NSR:    usize = 0x008;  // Network Status (MDIO idle etc)
    pub const TSR:    usize = 0x014;  // Transmit Status
    pub const RBQP:   usize = 0x018;  // classic MACB RX Queue Ptr
    pub const TBQP:   usize = 0x01c;  // classic MACB TX Queue Ptr
    pub const RSR:    usize = 0x020;  // Receive Status
    pub const ISR:    usize = 0x024;
    pub const IER:    usize = 0x028;
    pub const IDR:    usize = 0x02c;
    pub const IMR:    usize = 0x030;
    pub const MAN:    usize = 0x034;  // PHY Maintenance (MDIO)
    pub const HRB:    usize = 0x090;  // Hash Bottom
    pub const HRT:    usize = 0x094;  // Hash Top
    pub const SA1B:   usize = 0x098;  // Specific address 1 Bottom (MAC lo)
    pub const SA1T:   usize = 0x09c;  // Specific address 1 Top    (MAC hi)
    pub const USRIO:  usize = 0x0c0;  // User IO
    pub const WOL:    usize = 0x0c4;
    pub const MID:    usize = 0x0fc;  // Module ID (RO) — Pi 5 = 0x00070109

    pub const DMACFG: usize = 0x010;  // GEM DMA Config
    pub const GEM_TBQP_0: usize = 0x440;  // GEM queue-0 TX BD ptr
    pub const GEM_RBQP_0: usize = 0x480;  // GEM queue-0 RX BD ptr

    // --- NCR bits ---
    pub const NCR_LB:      u32 = 1 << 0;   // loopback
    pub const NCR_LLB:     u32 = 1 << 1;   // local loopback
    pub const NCR_RE:      u32 = 1 << 2;   // RX enable
    pub const NCR_TE:      u32 = 1 << 3;   // TX enable
    pub const NCR_MPE:     u32 = 1 << 4;   // Management port enable (MDIO)
    pub const NCR_CLRSTAT: u32 = 1 << 5;
    pub const NCR_INCSTAT: u32 = 1 << 6;
    pub const NCR_WESTAT:  u32 = 1 << 7;
    pub const NCR_BP:      u32 = 1 << 8;
    pub const NCR_TSTART:  u32 = 1 << 9;   // Start transmission
    pub const NCR_THALT:   u32 = 1 << 10;

    // --- MID expected value (verified via Linux /dev/mem on DUT) ---
    pub const EXPECTED_MID: u32 = 0x0007_0109;

    // --- eth_cfg wrapper offsets (RP1 datasheet §7.1) ---
    pub const CFG_CONTROL:   usize = 0x00;
    pub const CFG_STATUS:    usize = 0x04;  // RGMII_LINK/SPEED/DUPLEX
    pub const CFG_TSU_CNT0:  usize = 0x08;
    pub const CFG_TSU_CNT1:  usize = 0x0c;
    pub const CFG_TSU_CNT2:  usize = 0x10;
    pub const CFG_CLKGEN:    usize = 0x14;  // TXCLKDELEN, ENABLE, SPEED_OVERRIDE
    pub const CFG_CLK2FC:    usize = 0x18;
    pub const CFG_INTR:      usize = 0x1c;  // bit 0 = ETHERNET top-level irq
    pub const CFG_INTE:      usize = 0x20;
    pub const CFG_INTF:      usize = 0x24;
    pub const CFG_INTS:      usize = 0x28;

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



// Timer driver lives in `src/platform/bcm2712/timer.rs` — see
// the `#[path = "bcm2712/timer.rs"] mod timer;` declaration at the
// top of this file. Public surface: `timer::{timer_freq,
// read_timer_count, timer_set}`.

// ============================================================================
// Multi-core init signaling
// ============================================================================

/// Set by core 0 once graph compilation and module instantiation have
/// finished. Cores 1..3 spin on this in `secondary_core_main` before
/// entering their domain pump.
static INIT_COMPLETE: AtomicU32 = AtomicU32::new(0);


// ============================================================================
// Entry point with secondary core parking
// ============================================================================
//
// Pi 5 GPU firmware boots all 4 Cortex-A76 cores. The _start code checks
// MPIDR_EL1.Aff0 to identify the core. Core 0 proceeds to main, cores 1-3
// park in a WFE loop.
//
// On QEMU virt with -smp 1 (default), MPIDR_EL1.Aff0 = 0, so the check
// is harmless. With -smp 4, secondary cores will park correctly.

// DTB pointer handed to us by the firmware. `main` records it once the
// MMU is up; `kernel::dtb::read_ethernet_mac` consults it. Placed in
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
    // Core 0 proceeds; 1-3 park. Pi 5 encodes core at Aff1[15:8].
    "    mrs x0, mpidr_el1",
    "    ubfx x0, x0, #8, #8",
    "    cbnz x0, .Lpark_core",

    // ---- Primary core (core 0) continues ----
    // Pi 5 firmware hands off at EL2. Our kernel runs as EL1, so we must
    // drop down. If we're already at EL1 this short-circuits.
    "    mrs x0, CurrentEL",
    "    cmp x0, #(2 << 2)",     // currently at EL2?
    "    b.ne 2f",                // no → skip EL drop

    // At EL2: disable EL2 MMU/caches and prepare an eret to EL1h.
    "    mrs x0, sctlr_el2",
    "    bic x0, x0, #(1 << 0)", // M
    "    bic x0, x0, #(1 << 2)", // C
    "    bic x0, x0, #(1 << 12)",// I
    "    msr sctlr_el2, x0",
    "    isb",

    // HCR_EL2.RW = 1 → EL1 is aarch64
    "    mrs x0, hcr_el2",
    "    mov x1, #(1 << 31)",
    "    orr x0, x0, x1",
    "    msr hcr_el2, x0",

    // CNTHCTL_EL2: allow EL1 physical timer / counter access
    "    mrs x0, cnthctl_el2",
    "    orr x0, x0, #(1 << 0)", // EL1PCTEN
    "    orr x0, x0, #(1 << 1)", // EL1PCEN
    "    msr cnthctl_el2, x0",
    "    msr cntvoff_el2, xzr",

    // Fake EL1h return state: DAIF all masked, SP_EL1 selected
    "    mov x0, #0x3c5",        // (D|A|I|F)<<6 | 0b0101 = EL1h
    "    msr spsr_el2, x0",
    "    adr x0, 2f",
    "    msr elr_el2, x0",
    "    eret",

    "2:",
    // Now at EL1 (either originally or via eret).
    // Install exception vectors for EL1.
    "    adr x1, exception_vectors",
    "    msr vbar_el1, x1",
    "    isb",

    // Make sure EL1 MMU/caches are off. We enable them ourselves in
    // boot_mmu::enable() after setting up page tables; any residual VPU state
    // needs to be cleared so our setup actually takes effect.
    "    mrs x0, sctlr_el1",
    "    bic x0, x0, #(1 << 0)", // M
    "    bic x0, x0, #(1 << 2)", // C
    "    bic x0, x0, #(1 << 12)",// I
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
    "    ldr w5, [x2, #12]",     // package_size
    "    cbz w5, 9f",
    "    add x6, x2, #16",       // source: bytes appended after the header
    "    ldr w7, [x2, #8]",      // destination base (__end_block_addr, aligned by packer)
    // Fast 8-byte copy loop (both src and dst are 256-byte aligned by packer)
    "    bic x10, x5, #7",       // x10 = size rounded down to 8-byte multiple
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
);

// ============================================================================
// Main entry point
// ============================================================================

#[no_mangle]
pub extern "C" fn main(dtb_phys: u64) -> ! {
    // Pi 5 bring-up sequence:
    //   1. MMU enable — DRAM cacheable, RP1 MMIO as Device-nGnRE at 0x1c.
    //   2. rp1_pcie_disable_aspm() — surgical ASPM disable on PCIe RC.
    //      VPU firmware (with enable_rp1_uart=1 + pciex4_reset=0) has
    //      already brought up the PCIe link, enabled RP1 endpoint
    //      PCI_COMMAND, and configured GPIO14/15 + PL011 for UART.
    //   3. uart_init() — reprogram PL011 to be sure (VPU may have left
    //      it configured, but we set our own baud/params).
    #[cfg(feature = "board-cm5")]
    unsafe {
        boot_mmu::init_page_tables();
        boot_mmu::enable();
        rp1_pcie_disable_aspm();
    }

    unsafe { uart_init() };
    UART_READY.store(1, Ordering::Release);
    // UART FIFO is always drained by hardware, so the local log-ring
    // consumer can activate immediately.
    fluxor::kernel::log_ring::activate_local();

    // Record the DTB pointer now that the MMU is on; later DTB reads
    // dereference `_boot_dtb_ptr`.
    unsafe {
        core::ptr::write_volatile(&raw mut _boot_dtb_ptr, dtb_phys);
    }

    #[cfg(feature = "board-cm5")]
    uart_puts(b"[fluxor] bcm2712 boot (Pi 5 / CM5)\r\n");
    #[cfg(not(feature = "board-cm5"))]
    uart_puts(b"[fluxor] bcm2712 boot (QEMU virt)\r\n");

    // QEMU virt: MMU init happens here (Pi 5 did it earlier, before PCIe).
    #[cfg(not(feature = "board-cm5"))]
    unsafe {
        boot_mmu::init_page_tables();
        boot_mmu::enable();
    }

    // Probe RP1 early on Pi 5 to confirm the PCIe BAR mapping is alive.
    rp1::report(uart_puts, uart_put_hex32);

    // Keep the GEM module-ID probe pre-logger because it only feeds
    // UART diagnostics. Full PCIe enumeration runs below so its
    // log::info! lines reach the ring (and therefore log_net -> UDP).
    #[cfg(feature = "board-cm5")]
    {
        let mid = unsafe { core::ptr::read_volatile(eth::GEM_BASE.wrapping_add(eth::MID) as *const u32) };
        uart_puts(b"[gem] MID=0x");
        uart_put_hex32(mid);
        if mid == eth::EXPECTED_MID {
            uart_puts(b" (OK)\r\n");
        } else {
            uart_puts(b" (UNEXPECTED - expected 0x00070109)\r\n");
        }
    }

    static LOGGER: RingLogger = RingLogger;
    unsafe { log::set_logger_racy(&LOGGER).ok() };
    log::set_max_level(log::LevelFilter::Info);

    // PCIe1 bring-up: stages 1 + 2a + 2b (reset/RESCAL + RC-wide regs
    // + MDIO tuning). Stage 2c onwards (SerDes/PERST#/link) is deferred
    // pending cold-boot stability work.
    {
        let n = fluxor::kernel::pcie::enumerate();
        log::info!("[pcie] bus1 devices={}", n);
    }

    // Report timer frequency
    let freq = timer::timer_freq();
    uart_puts(b"[timer] freq=");
    uart_put_u32(freq as u32);
    uart_puts(b" Hz\r\n");

    // Exception vectors + GIC + timer
    // Timer tick period will be recalculated after config is parsed (tick_us).
    // Start with 1ms default so the system runs during init.
    unsafe {
        gic_init();
        TICKS_PER_TICK = if freq > 0 { (freq / 1000) as u32 } else { 62500 };
        timer::timer_set(TICKS_PER_TICK);
        core::arch::asm!("msr daifclr, #2"); // enable IRQs
    }

    uart_puts(b"[gic] initialized, IRQs enabled\r\n");

    // HAL ops, syscall table, providers, then the BCM2712
    // generic-timer-backed step guard.
    fluxor::kernel::boot(&BCM2712_HAL_OPS);
    fluxor::kernel::step_guard::init();

    // --- Config-driven module graph ---
    //
    // `scheduler::prepare_graph` compiles the graph (edge decode, fan
    // module insertion, channel allocation, port-table population). This
    // platform layers the multi-core concerns on top: cross-domain
    // edges are bridged with `multicore::register_cross_edge`, and each
    // core's run loop drives `scheduler::step_domain_modules` (or
    // `step_domain_modules_poll` for Tier 3) through the shared
    // `step_one_module` body.
    use fluxor::kernel::channel;
    use fluxor::kernel::config;

    // Parse config + loader into the kernel's static state. CM5 scans
    // flash via the trailer; QEMU side-loads a packed blob at a fixed
    // address. `prepare_graph` reads STATIC_CONFIG / STATIC_LOADER from
    // there.
    loader::reset_state_arena();
    let static_state_ok = {
        #[cfg(not(feature = "board-cm5"))]
        {
            let blob_magic = unsafe { core::ptr::read_volatile(QEMU_CONFIG_BLOB_ADDR as *const u32) };
            let modules_blob_magic = unsafe {
                core::ptr::read_volatile(QEMU_MODULES_BLOB_ADDR as *const u32)
            };
            if blob_magic == config::MAGIC_CONFIG
                && modules_blob_magic == loader::MODULE_TABLE_MAGIC
            {
                unsafe {
                    // Cap the declared length to MAX_CONFIG_SIZE so the
                    // parser slice doesn't span the full 16 MB gap
                    // between QEMU_CONFIG_BLOB_ADDR and the modules
                    // blob; the parser will reject any header that
                    // declares more.
                    scheduler::populate_static_state(
                        QEMU_CONFIG_BLOB_ADDR as *const u8,
                        config::MAX_CONFIG_SIZE,
                        QEMU_MODULES_BLOB_ADDR as *const u8,
                    )
                }
                .is_ok()
            } else {
                let loader_ref = unsafe { scheduler::static_loader_mut() };
                let cfg_ref = unsafe { scheduler::static_config_mut() };
                let l_ok = loader_ref.init().is_ok();
                let c_ok = config::read_config_into(cfg_ref);
                l_ok && c_ok
            }
        }
        #[cfg(feature = "board-cm5")]
        {
            // Flash-trailer path: the loader scans the packed image for
            // the module table; the config sits in the same trailer.
            let loader_ref = unsafe { scheduler::static_loader_mut() };
            let cfg_ref = unsafe { scheduler::static_config_mut() };
            let l_ok = loader_ref.init().is_ok();
            let c_ok = config::read_config_into(cfg_ref);
            l_ok && c_ok
        }
    };
    if !static_state_ok {
        uart_puts(b"[config] parse / loader failed\r\n");
        loop { unsafe { core::arch::asm!("wfi") }; }
    }
    let cfg = unsafe { scheduler::static_config() };
    let n_modules = cfg.module_count as usize;
    let n_edges = cfg.edge_count as usize;

    // Reconfigure the timer tick from config.tick_us.
    let tick_us = if cfg.header.tick_us > 0 { cfg.header.tick_us as u32 } else { 1000 };
    unsafe {
        // freq is in Hz, so ticks_per_us = freq / 1_000_000
        // TICKS_PER_TICK = tick_us * (freq / 1_000_000) = tick_us * freq / 1_000_000
        TICKS_PER_TICK = if freq > 0 {
            ((tick_us as u64) * freq / 1_000_000) as u32
        } else {
            62500 * tick_us / 1000
        };
        timer::timer_set(TICKS_PER_TICK);
    }
    uart_puts(b"[timer] tick_us=");
    uart_put_u32(tick_us);
    uart_puts(b"\r\n");

    uart_puts(b"[config] ");
    uart_put_u32(n_modules as u32);
    uart_puts(b" modules, ");
    uart_put_u32(n_edges as u32);
    uart_puts(b" edges\r\n");

    let (module_list, module_count) = match scheduler::prepare_graph() {
        Ok(v) => v,
        Err(_) => {
            uart_puts(b"[graph] prepare_graph failed\r\n");
            loop { unsafe { core::arch::asm!("wfi") }; }
        }
    };

    // Cross-domain post-process: split every edge whose endpoints live
    // in different domains into producer-side / consumer-side channels
    // bridged by a `multicore::CrossDomainChannel` SPSC pump.
    //
    // The walk reads `sched.edges` (not `cfg.graph_edges`) so an edge
    // that is part of both a fan group and a cross-domain hop is seen
    // through its rewritten endpoints — the bridge lands on the actual
    // producer/consumer hop, not the original config one.
    //
    // For each cross edge, open a fresh consumer-side channel `W2`,
    // register the SPSC bridge `edge.channel → W2`, and set
    // `edge.consumer_channel = W2`. `collect_input_channels` honours
    // `consumer_channel`, so `populate_ports` lifts `W2` into the
    // consumer's in_chans.
    {
        let sched = unsafe { scheduler::sched_mut() };
        let n_compiled_edges = sched.edge_count;
        let mut e = 0usize;
        while e < n_compiled_edges {
            let edge_snapshot = sched.edges[e];
            if edge_snapshot.channel < 0 { e += 1; continue; }

            let from = edge_snapshot.from_module;
            let to = edge_snapshot.to_module;
            let from_domain = scheduler::module_domain_id(from);
            let to_domain = scheduler::module_domain_id(to);
            let is_cross = from_domain != to_domain
                || edge_snapshot.edge_class == EdgeClass::CrossCore;
            if !is_cross { e += 1; continue; }

            // Reserve the SPSC ring, the consumer-side channel, and the
            // edge-table slot before touching `consumer_channel`. If any
            // reservation fails, halt — rebinding the consumer to a
            // handle that no pump fills would strand every byte the
            // producer writes.
            let cross_ch_idx = match multicore::alloc_cross_channel() {
                Some(i) => i,
                None => {
                    uart_puts(b"[graph] cross-domain SPSC rings exhausted (");
                    uart_put_u32(multicore::MAX_CROSS_CHANNELS as u32);
                    uart_puts(b" max); cannot bridge edge ");
                    uart_put_u32(e as u32);
                    uart_puts(b"\r\n");
                    loop { unsafe { core::arch::asm!("wfi") }; }
                }
            };

            let in_ch = channel::channel_open(
                channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
            if in_ch < 0 {
                uart_puts(b"[graph] consumer-side channel alloc failed for cross-domain edge ");
                uart_put_u32(e as u32);
                uart_puts(b"\r\n");
                loop { unsafe { core::arch::asm!("wfi") }; }
            }

            // Mirror the producer-side channel's mailbox flag onto the
            // consumer-side bridge channel. Without this, typed-envelope
            // edges (WsFrame, FmpMessage, etc.) shred their framing at
            // this seam: the pump writes back-to-back atomic frames into
            // a FIFO ring, the consumer's next `channel_read` returns
            // multiple envelopes coalesced, and only the first parses
            // cleanly. POLL_IN also stays latched on the leftover bytes,
            // driving the consumer module to spin on phantom reads. See
            // `tests/ws.rs::cross_domain_pump_*` for the host-side
            // regression coverage.
            if channel::channel_is_mailbox(edge_snapshot.channel) {
                channel::channel_set_mailbox(in_ch);
            }

            let to_port_marker: u8 = if edge_snapshot.is_ctrl() { 1 } else { 0 };
            let registered = unsafe {
                multicore::register_cross_edge(multicore::CrossDomainEdge {
                    from_domain,
                    from_module: from as u8,
                    from_port: edge_snapshot.from_port_index,
                    to_domain,
                    to_module: to as u8,
                    to_port: to_port_marker,
                    channel_idx: cross_ch_idx as u8,
                    local_out_handle: edge_snapshot.channel,
                    local_in_handle: in_ch,
                    pending_aux: core::sync::atomic::AtomicU32::new(u32::MAX),
                })
            };
            if registered.is_none() {
                uart_puts(b"[graph] cross-domain edge table full (");
                uart_put_u32(multicore::MAX_CROSS_EDGES as u32);
                uart_puts(b" max); cannot bridge edge ");
                uart_put_u32(e as u32);
                uart_puts(b"\r\n");
                loop { unsafe { core::arch::asm!("wfi") }; }
            }

            sched.edges[e].consumer_channel = in_ch;
            e += 1;
        }
    }

    // Mask IRQs during module instantiation
    let _inst_guard = fluxor::kernel::guard::KernelGuard::acquire();

    let loader_ref = unsafe { scheduler::static_loader() };
    let sched = unsafe { scheduler::sched_mut() };
    let mut total_mods = 0usize;
    for (module_idx, slot) in module_list.iter().enumerate().take(module_count) {
        let entry = match slot {
            Some(e) => e,
            None => continue,
        };
        if entry.domain_id as usize >= multicore::MAX_DOMAINS {
            uart_puts(b"[inst] invalid domain_id for module ");
            uart_put_u32(module_idx as u32);
            uart_puts(b"\r\n");
            continue;
        }
        scheduler::set_current_module(module_idx);
        let result = scheduler::instantiate_one_module(
            loader_ref, entry,
            module_idx, module_idx,
            &mut sched.edges,
            &mut sched.modules,
            &mut sched.ports,
        );
        match result {
            scheduler::InstantiateResult::Done => {
                total_mods += 1;
            }
            scheduler::InstantiateResult::Pending(mut pending) => {
                let mut loaded = false;
                for _ in 0..100 {
                    for _ in 0..10000 { unsafe { core::arch::asm!("nop") }; }
                    match unsafe { pending.try_complete() } {
                        Ok(Some(dm)) => {
                            scheduler::store_dynamic_module(module_idx, dm);
                            total_mods += 1;
                            loaded = true;
                            break;
                        }
                        Ok(None) => {}
                        Err(e) => { e.log("module"); loaded = true; break; }
                    }
                }
                if !loaded {
                    uart_puts(b"[inst] module ");
                    uart_put_u32(module_idx as u32);
                    uart_puts(b" pending timeout\r\n");
                }
            }
            scheduler::InstantiateResult::Error(_) => {}
        }
    }

    // Activate the compiled graph and log per-domain composition.
    // BCM doesn't populate `sched.edges`, so DMA-owned edges are
    // logged by walking the config's edge slice directly via
    // `log_dma_owned_edges_from_config`.
    scheduler::set_active_module_count(module_count);
    fluxor::kernel::scheduler::log_dma_owned_edges_from_config(&cfg.graph_edges);

    let mut d = 0usize;
    while d < multicore::MAX_DOMAINS {
        let mod_count = scheduler::domain_module_count(d);
        if mod_count > 0 {
            unsafe {
                let ds = multicore::domain_state(d);
                ds.core_id = d as u8; // Domain N runs on core N
                ds.module_count = mod_count as u8;
                ds.active = true;
            }
            uart_puts(b"[domain] ");
            uart_put_u32(d as u32);
            uart_puts(b": ");
            uart_put_u32(mod_count as u32);
            uart_puts(b" modules (core ");
            uart_put_u32(d as u32);
            uart_puts(b") order: ");
            let mut k = 0usize;
            while k < mod_count {
                if k > 0 { uart_puts(b"->"); }
                if let Some(g) = scheduler::domain_exec_order_at(d, k) {
                    uart_put_u32(g as u32);
                }
                k += 1;
            }
            uart_puts(b"\r\n");
        }
        d += 1;
    }

    drop(_inst_guard);

    uart_puts(b"[inst] ");
    uart_put_u32(total_mods as u32);
    uart_puts(b" modules loaded total\r\n");

    fluxor::kernel::scheduler::log_arena_summary();

    // Signal init complete — secondary cores can start
    INIT_COMPLETE.store(1, Ordering::Release);

    // Log cross-domain channel status
    uart_puts(b"[cross] channels=");
    uart_put_u32(multicore::cross_edge_count() as u32);
    uart_puts(b" dma_arena_used=");
    uart_put_u32(multicore::dma_arena_used() as u32);
    uart_puts(b"\r\n");

    // Wake secondary cores that have non-empty domains assigned
    wake_secondary_cores();

    uart_puts(b"[sched] starting domain 0 on core 0\r\n");

    // Flush buffered early-boot log bytes to the UART before we enter
    // the tick loop. Each poll moves up to the staging size (1 KB),
    // so a short burst covers typical boot chatter; anything left
    // over flushes during the first few ticks.
    for _ in 0..8 {
        debug_drain_poll_core0();
    }

    // Main loop — domain 0 on core 0
    run_domain_loop(0)
}


// ============================================================================
// Domain execution loop
// ============================================================================

/// Run the main loop for a domain. Steps all modules assigned to that domain.
///
/// This function never returns. On core 0 it is called directly from main().
/// On secondary cores it is called from the secondary_core_main() entry point.
/// Per-domain execution metrics.
struct DomainMetrics {
    /// Total ticks processed.
    tick_count: u32,
    /// Ticks where step work exceeded 50% of tick budget.
    busy_ticks: u32,
    /// Tier 3 only: total step calls.
    poll_steps: u32,
    /// Tier 3 only: steps where all modules returned Continue (idle).
    poll_idle: u32,
    /// Tier 3 only: WFE count.
    wfe_count: u32,
    /// Worst-case step duration in timer ticks (for deadline margin).
    worst_step_ticks: u32,
}

impl DomainMetrics {
    const fn new() -> Self {
        Self { tick_count: 0, busy_ticks: 0, poll_steps: 0, poll_idle: 0, wfe_count: 0, worst_step_ticks: 0 }
    }
}

static mut DOMAIN_METRICS: [DomainMetrics; multicore::MAX_DOMAINS] =
    [const { DomainMetrics::new() }; multicore::MAX_DOMAINS];

fn run_domain_loop(domain_id: usize) -> ! {
    let exec_mode = scheduler::domain_exec_mode(domain_id);
    let core_id = current_core_id() as usize;

    match exec_mode {
        // ── Tier 1a: High-rate periodic (1-10 kHz) ──
        // Same as Tier 0 but with per-domain timer tick rate.
        // Timer IRQ fires at domain_tick_us; full module ABI retained.
        1 => {
            log::info!("[domain] {} core={} tier=1a tick_us={}", domain_id, core_id,
                scheduler::domain_tick_us(domain_id));
            loop {
                unsafe { core::arch::asm!("wfi") };
                multicore::park_if_requested(domain_id);
                let t0 = timer::read_timer_count();
                domain_step_all(domain_id);
                pump_cross_domain(domain_id);
                if core_id == 0 { debug_drain_poll_core0(); }
                let elapsed = timer::read_timer_count().wrapping_sub(t0);
                let metrics = unsafe { &mut DOMAIN_METRICS[domain_id] };
                metrics.tick_count += 1;
                if elapsed > metrics.worst_step_ticks { metrics.worst_step_ticks = elapsed; }
                // Track busy ticks (step work exceeded 50% of tick budget)
                let freq = timer::timer_freq() as u32;
                let budget_ticks = if freq > 0 { (scheduler::domain_tick_us(domain_id) as u64 * freq as u64 / 1_000_000) as u32 } else { 62500 };
                if elapsed > budget_ticks / 2 { metrics.busy_ticks += 1; }
                // Report every ~10s (at domain tick rate)
                let report_interval = 10_000_000 / scheduler::domain_tick_us(domain_id);
                if metrics.tick_count % report_interval == 0 && metrics.tick_count > 0 {
                    log::info!("[tier1a] d={} ticks={} worst={}cyc", domain_id, metrics.tick_count, metrics.worst_step_ticks);
                }
            }
        }
        // ── Tier 3: Poll-mode (continuous stepping) ──
        // Continuous stepping through the shared scheduler body. The
        // pass runs every module in the domain once via
        // `step_domain_modules_poll`, which is identical to
        // `step_domain_modules` except it also reports whether any
        // module returned `StepOutcome::Burst` during the pass. When
        // no module bursted (and there's no other pending work) the
        // core WFEs.
        3 => {
            log::info!("[domain] {} core={} tier=3 poll-mode", domain_id, core_id);
            loop {
                multicore::park_if_requested(domain_id);
                let sched = unsafe { scheduler::sched_mut() };
                let (_result, any_burst) =
                    scheduler::step_domain_modules_poll(&mut sched.modules, domain_id);
                pump_cross_domain(domain_id);
                if core_id == 0 { debug_drain_poll_core0(); }

                let metrics = unsafe { &mut DOMAIN_METRICS[domain_id] };
                metrics.poll_steps += 1;
                if !any_burst {
                    metrics.poll_idle += 1;
                    metrics.wfe_count += 1;
                    unsafe { core::arch::asm!("wfe") };
                }
                // Report every ~1M poll steps
                if metrics.poll_steps & 0xFFFFF == 0 && metrics.poll_steps > 0 {
                    let idle_pct = if metrics.poll_steps > 0 { metrics.poll_idle * 100 / metrics.poll_steps } else { 0 };
                    log::info!("[tier3] d={} polls={} idle={}% wfe={}",
                        domain_id, metrics.poll_steps, idle_pct, metrics.wfe_count);
                }
            }
        }
        // ── Tier 0: Cooperative (default, 1ms tick) ──
        _ => {
            loop {
                unsafe { core::arch::asm!("wfi") };
                multicore::park_if_requested(domain_id);
                let tick = CORE_TICKS[core_id].load(Ordering::Relaxed);
                domain_step_all(domain_id);
                pump_cross_domain(domain_id);
                if core_id == 0 { debug_drain_poll_core0(); }
                let metrics = unsafe { &mut DOMAIN_METRICS[domain_id] };
                metrics.tick_count += 1;
                scheduler::maybe_emit_alive(tick as u64, Some(domain_id));
                // Rebuild bridge. On the primary domain, a pending rebuild
                // request quiesces every non-primary domain (so mutation of
                // global scheduler state is race-free), then clears the
                // phase byte and releases. The rebuild body itself — full
                // arena reset, prepare_graph, module instantiation — is
                // not invoked here; on bcm2712 the request is consumed
                // without rebuilding, leaving the current graph running.
                if domain_id == 0 && scheduler::take_rebuild_request().is_some() {
                    let expected = multicore::non_primary_active_count();
                    multicore::request_quiesce();
                    multicore::wait_parked(expected);
                    log::warn!("[reconfigure] quiesced {} domains; phase reset", expected);
                    scheduler::set_reconfigure_phase(
                        scheduler::ReconfigurePhase::Running
                    );
                    multicore::release_quiesce();
                }
            }
        }
    }
}

/// Step every module in `domain_id` via the shared per-domain
/// scheduler path. Routes through `scheduler::step_domain_modules`
/// (same `step_one_module` body single-domain platforms use), so
/// every BCM-domain step honours period gating, upstream-ready
/// gating, `Done` finalisation, the fault state machine, and the
/// `Burst` loop identically to RP/Linux/WASM. See
/// `.context/scheduler_domain_api.md`.
fn domain_step_all(domain_id: usize) {
    let sched = unsafe { scheduler::sched_mut() };
    let _ = scheduler::step_domain_modules(&mut sched.modules, domain_id);
}

/// Move one slot per edge in each direction between local pipe channels
/// and their cross-domain SPSC ring. Called from `run_domain_loop` on
/// every tick; producer and consumer sides of each edge each fire on
/// the tick of their owning domain.
///
/// On the consumer side, the local pipe FIFO is peeked via `POLL_OUT`
/// before consuming from the SPSC ring — `channel_write` can return a
/// short write when the FIFO is near-full, and SPSC slots are consumed
/// in whole-message units, so pulling from the ring first and then
/// writing to a full FIFO would silently drop the tail.
///
/// `IOCTL_NOTIFY` sideband (seek requests and the like) is bridged via
/// `edge.pending_aux`: the consumer-side pump drains the consumer's
/// local input aux and stores it there; the producer-side pump drains
/// it and replays it onto the producer's local output aux.
fn pump_cross_domain(domain_id: usize) {
    let n_cross = multicore::cross_edge_count();
    let mut ei = 0;
    while ei < n_cross {
        let Some(edge) = multicore::get_cross_edge(ei) else { ei += 1; continue };
        let Some(ch) = multicore::get_cross_channel(edge.channel_idx as usize) else { ei += 1; continue };

        // Producer side. Check remote SPSC space first — `channel_read`
        // commits the local mailbox frame, so consuming the producer's
        // frame before knowing the SPSC ring has room would be a real
        // drop. If the ring is full we leave the frame in the producer
        // mailbox; the producer module sees back-pressure on its output
        // and the pump retries next tick.
        if edge.from_domain == domain_id as u8 && edge.local_out_handle >= 0 {
            if ch.is_full() {
                multicore::CROSS_DOMAIN_BACKPRESSURE.fetch_add(1, Ordering::Relaxed);
            } else {
                let mut buf = [0u8; multicore::SLOT_DATA_SIZE];
                let n = unsafe {
                    fluxor::kernel::channel::channel_read(
                        edge.local_out_handle, buf.as_mut_ptr(), buf.len(),
                    )
                };
                if n > 0 {
                    // The ring had space when we checked, but a parallel
                    // consumer-side close (or an oversized frame, which
                    // `ch.send` rejects) can still cause a refusal. Bump
                    // the cross-domain drop counter so operator-side
                    // telemetry sees it.
                    if !ch.send(&buf[..n as usize]) {
                        multicore::CROSS_DOMAIN_DROPS.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            let aux = edge.pending_aux.swap(u32::MAX, Ordering::AcqRel);
            if aux != u32::MAX {
                let mut val = aux;
                let _ = fluxor::kernel::channel::channel_ioctl(
                    edge.local_out_handle,
                    fluxor::kernel::channel::IOCTL_NOTIFY,
                    &mut val as *mut u32 as *mut u8,
                );
            }
        }

        // Consumer side.
        if edge.to_domain == domain_id as u8 && edge.local_in_handle >= 0 {
            let write_ready = fluxor::kernel::channel::channel_poll(
                edge.local_in_handle,
                fluxor::kernel::channel::POLL_OUT,
            );
            let can_write = write_ready > 0
                && (write_ready as u32 & fluxor::kernel::channel::POLL_OUT) != 0;
            if can_write {
                let mut buf = [0u8; multicore::SLOT_DATA_SIZE];
                if let Some(len) = ch.try_recv(&mut buf) {
                    unsafe {
                        fluxor::kernel::channel::channel_write(
                            edge.local_in_handle, buf.as_ptr(), len,
                        );
                    }
                }
            } else if ch.try_peek_len().is_some() {
                // Cross-domain ring has data but the local consumer
                // can't accept right now. No drop — the data stays
                // queued until the next pump — but a sustained nonzero
                // rate here means the consumer is under-served.
                multicore::CROSS_DOMAIN_BACKPRESSURE.fetch_add(1, Ordering::Relaxed);
            }
            let mut val: u32 = 0;
            let rc = fluxor::kernel::channel::channel_ioctl(
                edge.local_in_handle,
                fluxor::kernel::channel::IOCTL_POLL_NOTIFY,
                &mut val as *mut u32 as *mut u8,
            );
            if rc == fluxor::kernel::channel::CHAN_OK && val != u32::MAX {
                // `pending_aux` is single-slot — a fresh notification
                // overwrites any prior one that the producer pump
                // hadn't yet drained. The single-slot design is
                // intentionally coalescing (later writes win); the
                // overwrite counter below makes the rate of coalesced
                // events visible without changing the wire shape.
                let prev = edge.pending_aux.swap(val, Ordering::AcqRel);
                if prev != u32::MAX {
                    multicore::SIDEBAND_AUX_OVERWRITES.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        ei += 1;
    }
}

// ============================================================================
// Secondary core entry points
// ============================================================================

/// Entry point for secondary cores after wake.
///
/// Waits for init_complete, sets up its own timer and GIC, then runs its
/// assigned domain loop. If no domain is assigned, parks in WFE.
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
    // Wait for init to complete on core 0
    while INIT_COMPLETE.load(Ordering::Acquire) == 0 {
        unsafe { core::arch::asm!("wfe"); }
    }

    let core_id = current_core_id();
    uart_puts(b"[core");
    uart_put_u32(core_id as u32);
    uart_puts(b"] started, domain=");
    uart_put_u32(domain_id as u32);
    uart_puts(b"\r\n");
    log::info!("[core{}] started, domain={}", core_id, domain_id);

    // Set up GIC CPU interface for this core
    unsafe {
        gic_init_secondary();
        // Set per-domain timer rate (Tier 1a may run faster than global tick)
        let domain_tick = scheduler::domain_tick_us(domain_id);
        let freq = timer::timer_freq();
        let ticks_for_domain = if freq > 0 {
            ((domain_tick as u64) * freq / 1_000_000) as u32
        } else {
            TICKS_PER_TICK
        };
        timer::timer_set(ticks_for_domain);
        // Enable IRQs (not needed for Tier 3 poll-mode, but harmless)
        core::arch::asm!("msr daifclr, #2");
    }

    // Check if this domain is active
    let ds = multicore::domain_state_ref(domain_id);
    if !ds.active || ds.module_count == 0 {
        uart_puts(b"[core");
        uart_put_u32(core_id as u32);
        uart_puts(b"] no work, parking\r\n");
        loop { unsafe { core::arch::asm!("wfe"); } }
    }

    // Run the domain loop
    run_domain_loop(domain_id)
}

/// Wake all secondary cores that have domains assigned.
///
/// Called after module instantiation on core 0. Each secondary core
/// gets its own entry function that maps to its domain.
pub fn wake_secondary_cores() {
    let entries: [fn() -> !; 3] = [
        secondary_core_main_1,
        secondary_core_main_2,
        secondary_core_main_3,
    ];

    for core_id in 1u8..=3 {
        let domain_id = core_id as usize;
        let ds = multicore::domain_state_ref(domain_id);
        if ds.active && ds.module_count > 0 {
            uart_puts(b"[wake] core ");
            uart_put_u32(core_id as u32);
            uart_puts(b" for domain ");
            uart_put_u32(domain_id as u32);
            uart_puts(b"\r\n");

            let entry = entries[(core_id - 1) as usize];
            let ok = multicore::wake_core(core_id, entry);
            if !ok {
                uart_puts(b"[wake] FAILED core ");
                uart_put_u32(core_id as u32);
                uart_puts(b"\r\n");
            }
        }
    }
}


// ============================================================================
// BCM2712 HAL Ops
// ============================================================================

use fluxor::kernel::hal::HalOps;

fn bcm_disable_interrupts() -> u32 {
    let daif: u32;
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
    unsafe {
        core::arch::asm!(
            "msr daif, {0:x}",
            in(reg) saved,
            options(nomem, nostack, preserves_flags),
        );
    }
}

fn bcm_wake_scheduler() {
    unsafe { core::arch::asm!("sev") };
}

/// Monotonic milliseconds since boot. Reads the ARM generic timer
/// (`CNTPCT_EL0`) and scales by `cntfrq_el0 / 1000`. Backs
/// `dev_millis` / `syscall_millis` for module-side timing such as
/// NVMe arena probe perf measurement and TCP RTT estimation.
fn bcm_now_millis() -> u64 {
    let counter = bcm_read_cntpct();
    let freq = bcm_counter_freq();
    if freq == 0 { return 0; }
    counter.wrapping_mul(1000) / freq
}

/// Monotonic microseconds since boot. Same source as
/// `bcm_now_millis`, scaled to µs for sub-millisecond profiling.
fn bcm_now_micros() -> u64 {
    let counter = bcm_read_cntpct();
    let freq = bcm_counter_freq();
    if freq == 0 { return 0; }
    counter.wrapping_mul(1_000_000) / freq
}
fn bcm_tick_count() -> u32 {
    fluxor::kernel::scheduler::tick_count()
}

fn bcm_flash_base() -> usize { 0 }
fn bcm_flash_end() -> usize { 0 }
fn bcm_apply_code_bit(addr: usize) -> usize { addr }
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

fn bcm_pic_barrier() {
    unsafe { core::arch::asm!("dsb sy", "isb") };
}

// Step guard: software elapsed-time check
static mut BCM_ARM_TIME: u64 = 0;
static mut BCM_DEADLINE_TICKS: u64 = 0;

/// Read the timer counter (physical on Pi 5, virtual on QEMU for KVM compat).
fn bcm_read_cntpct() -> u64 {
    let val: u64;
    #[cfg(feature = "board-cm5")]
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) val) };
    #[cfg(not(feature = "board-cm5"))]
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) val) };
    val
}

fn bcm_counter_freq() -> u64 {
    let freq: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq) };
    freq
}

fn bcm_step_guard_init() {}

fn bcm_step_guard_arm(deadline_us: u32) {
    use fluxor::kernel::step_guard;
    step_guard::clear_timed_out();
    step_guard::set_armed(true);
    let freq = bcm_counter_freq();
    let ticks = (deadline_us as u64 * freq) / 1_000_000;
    unsafe {
        BCM_ARM_TIME = bcm_read_cntpct();
        BCM_DEADLINE_TICKS = ticks;
    }
}

fn bcm_step_guard_disarm() {
    fluxor::kernel::step_guard::set_armed(false);
}

fn bcm_step_guard_post_check() {
    use fluxor::kernel::step_guard;
    if !step_guard::is_armed() { return; }
    let now = bcm_read_cntpct();
    let elapsed = now.wrapping_sub(unsafe { BCM_ARM_TIME });
    if elapsed >= unsafe { BCM_DEADLINE_TICKS } {
        step_guard::set_timed_out();
    }
    step_guard::set_armed(false);
}

fn bcm_read_cycle_count() -> u32 {
    bcm_read_cntpct() as u32
}

fn bcm_isr_tier_init() {}

// ISR tier 1b: software poll on aarch64
static mut BCM_ISR_LAST_TICK: u64 = 0;
static mut BCM_ISR_PERIOD_TICKS: u64 = 0;

fn bcm_isr_tier_start(period_us: u32) {
    use fluxor::kernel::isr_tier;
    isr_tier::set_tier1b_period_us(period_us);
    let freq = bcm_counter_freq();
    unsafe {
        BCM_ISR_PERIOD_TICKS = (period_us as u64 * freq) / 1_000_000;
        BCM_ISR_LAST_TICK = bcm_read_cntpct();
    }
    isr_tier::TIER1B_ACTIVE.store(true, core::sync::atomic::Ordering::Release);
}

fn bcm_isr_tier_stop() {
    fluxor::kernel::isr_tier::TIER1B_ACTIVE.store(false, core::sync::atomic::Ordering::Release);
}

fn bcm_isr_tier_poll() {
    use fluxor::kernel::isr_tier;
    if !isr_tier::TIER1B_ACTIVE.load(core::sync::atomic::Ordering::Acquire) { return; }
    let now = bcm_read_cntpct();
    let elapsed = now.wrapping_sub(unsafe { BCM_ISR_LAST_TICK });
    let period = unsafe { BCM_ISR_PERIOD_TICKS };
    if period > 0 && elapsed >= period {
        unsafe {
            BCM_ISR_LAST_TICK = now;
            isr_tier::isr_tier1b_handler();
        }
    }
}

fn bcm_init_providers() {
    // BCM2712 system extension for MMIO and NIC opcodes
    fluxor::kernel::syscalls::register_system_extension(bcm_system_extension_dispatch);
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
/// require adding `owner_module: u8` to each of those tables; until
/// then the empty body is deliberate, not a TODO.
fn bcm_release_module_handles(_module_idx: u8) {
    // See docstring above — intentional no-op pending per-resource
    // ownership tracking in nic_ring / pcie / dma arenas.
}
fn bcm_boot_scan() {}
fn bcm_merge_runtime_overrides(_module_id: u16, _buf: *mut u8, len: usize, _max: usize) -> usize { len }

unsafe fn bcm_system_extension_dispatch(_handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use fluxor::abi::platform::bcm2712::{mmio_dma, pcie_device, pcie_nic};
    use fluxor::abi::contracts::storage::paged_arena;
    match opcode {
        mmio_dma::MMIO_READ32 => {
            if arg.is_null() || arg_len < 12 { return -22; }
            let addr = u64::from_le_bytes([
                *arg, *arg.add(1), *arg.add(2), *arg.add(3),
                *arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7),
            ]);
            let val = core::ptr::read_volatile(addr as *const u32);
            let vb = val.to_le_bytes();
            *arg.add(8) = vb[0]; *arg.add(9) = vb[1];
            *arg.add(10) = vb[2]; *arg.add(11) = vb[3];
            0
        }
        mmio_dma::MMIO_WRITE32 => {
            if arg.is_null() || arg_len < 12 { return -22; }
            let addr = u64::from_le_bytes([
                *arg, *arg.add(1), *arg.add(2), *arg.add(3),
                *arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7),
            ]);
            let val = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            core::ptr::write_volatile(addr as *mut u32, val);
            0
        }
        mmio_dma::CACHE_FLUSH_RANGE => {
            if arg.is_null() || arg_len < 12 { return -22; }
            let addr = u64::from_le_bytes([
                *arg, *arg.add(1), *arg.add(2), *arg.add(3),
                *arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7),
            ]);
            let size = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
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
            if arg.is_null() || arg_len < 16 { return -22; }
            let size = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let align = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            // Use the PCIe1-reachable arena at AXI 0x1_0000_0000 so
            // device DMA routed through the PCIe1 inbound window lands
            // in real DRAM. See `bcm2712_nic_ring::pcie1_dma_alloc_contig`.
            let phys = fluxor::kernel::nic_ring::pcie1_dma_alloc_contig(size as usize, align as usize);
            if phys == 0 { return -38; }
            let pb = (phys as u64).to_le_bytes();
            core::ptr::copy_nonoverlapping(pb.as_ptr(), arg.add(8), 8);
            0
        }
        mmio_dma::DMA_ALLOC_STREAMING => {
            if arg.is_null() || arg_len < 16 { return -22; }
            let size = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let align = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            // Streaming arena stays WB-cacheable. Callers must pair writes
            // with DMA_FLUSH before device-reads and DMA_INVALIDATE before
            // CPU-reads of device-written regions.
            let phys = fluxor::kernel::nic_ring::pcie1_dma_alloc_streaming(size as usize, align as usize);
            if phys == 0 { return -38; }
            let pb = (phys as u64).to_le_bytes();
            core::ptr::copy_nonoverlapping(pb.as_ptr(), arg.add(8), 8);
            0
        }
        mmio_dma::DMA_FLUSH => {
            if arg.is_null() || arg_len < 12 { return -22; }
            let addr = u64::from_le_bytes([
                *arg, *arg.add(1), *arg.add(2), *arg.add(3),
                *arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7),
            ]);
            let size = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
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
            if arg.is_null() || arg_len < 12 { return -22; }
            let addr = u64::from_le_bytes([
                *arg, *arg.add(1), *arg.add(2), *arg.add(3),
                *arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7),
            ]);
            let size = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
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
        pcie_nic::NIC_BAR_MAP => {
            fluxor::kernel::pcie::syscall_bar_map(arg, arg_len)
        }
        pcie_nic::NIC_BAR_UNMAP => {
            fluxor::kernel::pcie::syscall_bar_unmap(arg, arg_len)
        }
        pcie_nic::NIC_RING_CREATE => {
            fluxor::kernel::nic_ring::syscall_ring_create(arg, arg_len)
        }
        pcie_nic::NIC_RING_DESTROY => {
            fluxor::kernel::nic_ring::syscall_ring_destroy(arg, arg_len)
        }
        pcie_nic::NIC_RING_INFO => {
            fluxor::kernel::nic_ring::syscall_ring_info(_handle, arg, arg_len)
        }
        pcie_nic::PCIE_RESCAN => {
            let _ = arg;
            let _ = arg_len;
            fluxor::kernel::pcie::enumerate() as i32
        }
        pcie_nic::PCIE_CFG_READ32 => {
            fluxor::kernel::pcie::syscall_cfg_read32(arg, arg_len)
        }
        pcie_nic::PCIE_CFG_WRITE32 => {
            fluxor::kernel::pcie::syscall_cfg_write32(arg, arg_len)
        }
        pcie_nic::PCIE1_MSI_INIT => {
            // arg = [spi_irq: u32 LE]
            if arg.is_null() || arg_len < 4 { return -22; }
            let spi_irq = u32::from_le_bytes([
                *arg, *arg.add(1), *arg.add(2), *arg.add(3),
            ]);
            if !fluxor::kernel::pcie::pcie1_msi_init() {
                return fluxor::kernel::errno::ENODEV;
            }
            register_pcie1_msi_spi(spi_irq)
        }
        pcie_nic::PCIE1_MSI_ALLOC_VECTOR => {
            if arg.is_null() || arg_len < 20 { return -22; }
            let event_handle = i32::from_le_bytes([
                *arg, *arg.add(1), *arg.add(2), *arg.add(3),
            ]);
            match fluxor::kernel::pcie::pcie1_msi_alloc_vector(event_handle) {
                None => -12, // ENOMEM
                Some((vec, addr, data)) => {
                    *arg.add(4) = vec;
                    *arg.add(5) = 0;
                    *arg.add(6) = 0;
                    *arg.add(7) = 0;
                    let ab = addr.to_le_bytes();
                    for (i, byte) in ab.iter().enumerate() { *arg.add(8 + i) = *byte; }
                    let db = data.to_le_bytes();
                    for (i, byte) in db.iter().enumerate() { *arg.add(16 + i) = *byte; }
                    0
                }
            }
        }
        // ── PCIE_DEVICE contract ──────────────────────────────────
        pcie_device::BIND => {
            if arg.is_null() || arg_len == 0 { return -22; }
            let sel = core::slice::from_raw_parts(arg, arg_len);
            fluxor::kernel::pcie::bind_selector(sel)
        }
        pcie_device::CLOSE => {
            fluxor::kernel::pcie::syscall_device_close(_handle)
        }
        pcie_device::CFG_READ32 => {
            fluxor::kernel::pcie::syscall_device_cfg_read32(_handle, arg, arg_len)
        }
        pcie_device::CFG_WRITE32 => {
            fluxor::kernel::pcie::syscall_device_cfg_write32(_handle, arg, arg_len)
        }
        pcie_device::BAR_MAP => {
            fluxor::kernel::pcie::syscall_device_bar_map(_handle, arg, arg_len)
        }
        pcie_device::MSI_ALLOC => {
            if arg.is_null() || arg_len < 20 || _handle < 0 { return -22; }
            // The bound handle tells us which root complex's MSI mux
            // to use. Only PCIe1 is wired today.
            match fluxor::kernel::pcie::bound_device_root(_handle) {
                None => fluxor::kernel::errno::EINVAL,
                Some(root) => {
                    use fluxor::kernel::pcie_aliases::PcieRoot;
                    match root {
                        PcieRoot::Pcie1 => {
                            if !fluxor::kernel::pcie::pcie1_msi_init() {
                                return fluxor::kernel::errno::ENODEV;
                            }
                            if !PCIE1_MSI_SPI_REGISTERED {
                                let _ = register_pcie1_msi_spi(
                                    fluxor::kernel::pcie::BCM2712_PCIE1_MSI_SPI_IRQ,
                                );
                                PCIE1_MSI_SPI_REGISTERED = true;
                            }
                            let event_handle = i32::from_le_bytes([
                                *arg, *arg.add(1), *arg.add(2), *arg.add(3),
                            ]);
                            match fluxor::kernel::pcie::pcie1_msi_alloc_vector(event_handle) {
                                None => fluxor::kernel::errno::ENOMEM,
                                Some((vec, addr, data)) => {
                                    *arg.add(4) = vec;
                                    *arg.add(5) = 0;
                                    *arg.add(6) = 0;
                                    *arg.add(7) = 0;
                                    let ab = addr.to_le_bytes();
                                    for (i, byte) in ab.iter().enumerate() { *arg.add(8 + i) = *byte; }
                                    let db = data.to_le_bytes();
                                    for (i, byte) in db.iter().enumerate() { *arg.add(16 + i) = *byte; }
                                    0
                                }
                            }
                        }
                        PcieRoot::Pcie2 => fluxor::kernel::errno::ENOSYS,
                    }
                }
            }
        }
        pcie_device::INFO => {
            fluxor::kernel::pcie::syscall_device_info(_handle, arg, arg_len)
        }
        paged_arena::ARENA_REGISTER => {
            if arg.is_null() || arg_len < 10 { return -22; }
            let vpages = u32::from_le_bytes([
                *arg, *arg.add(1), *arg.add(2), *arg.add(3),
            ]);
            let rmax = u32::from_le_bytes([
                *arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7),
            ]);
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
            let idx = fluxor::kernel::scheduler::current_module_index() as u8;
            fluxor::kernel::backing_store::backing_register(idx, vpages, rmax, bt, wb)
        }
        paged_arena::ARENA_READ => {
            if arg.is_null() || arg_len < 14 { return -22; }
            let arena_id = *arg as usize;
            let vpage = u32::from_le_bytes([
                *arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5),
            ]);
            let buf = u64::from_le_bytes([
                *arg.add(6),  *arg.add(7),  *arg.add(8),  *arg.add(9),
                *arg.add(10), *arg.add(11), *arg.add(12), *arg.add(13),
            ]) as *mut u8;
            fluxor::kernel::backing_store::backing_read(arena_id, vpage, buf)
        }
        paged_arena::ARENA_WRITE => {
            if arg.is_null() || arg_len < 14 { return -22; }
            let arena_id = *arg as usize;
            let vpage = u32::from_le_bytes([
                *arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5),
            ]);
            let buf = u64::from_le_bytes([
                *arg.add(6),  *arg.add(7),  *arg.add(8),  *arg.add(9),
                *arg.add(10), *arg.add(11), *arg.add(12), *arg.add(13),
            ]) as *const u8;
            fluxor::kernel::backing_store::backing_write(arena_id, vpage, buf)
        }
        paged_arena::ARENA_FLUSH => {
            if arg.is_null() || arg_len < 1 { return -22; }
            let arena_id = *arg as usize;
            fluxor::kernel::backing_store::backing_flush(arena_id)
        }
        paged_arena::ARENA_BULK => {
            if arg.is_null() || arg_len < 18 { return -22; }
            let arena_id = *arg as usize;
            let op = *arg.add(1);
            let vpage = u32::from_le_bytes([
                *arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5),
            ]);
            let count = u32::from_le_bytes([
                *arg.add(6), *arg.add(7), *arg.add(8), *arg.add(9),
            ]);
            let buf_u64 = u64::from_le_bytes([
                *arg.add(10), *arg.add(11), *arg.add(12), *arg.add(13),
                *arg.add(14), *arg.add(15), *arg.add(16), *arg.add(17),
            ]);
            match op {
                paged_arena::ARENA_BULK_OP_WRITE => fluxor::kernel::backing_store::backing_write_pages(
                    arena_id, vpage, count, buf_u64 as *const u8,
                ),
                paged_arena::ARENA_BULK_OP_READ => fluxor::kernel::backing_store::backing_read_pages(
                    arena_id, vpage, count, buf_u64 as *mut u8,
                ),
                _ => -22,
            }
        }
        _ => -38, // E_NOSYS
    }
}

static BCM2712_HAL_OPS: HalOps = HalOps {
    disable_interrupts: bcm_disable_interrupts,
    restore_interrupts: bcm_restore_interrupts,
    wake_scheduler: bcm_wake_scheduler,
    now_millis: bcm_now_millis,
    now_micros: bcm_now_micros,
    tick_count: bcm_tick_count,
    flash_base: bcm_flash_base,
    flash_end: bcm_flash_end,
    apply_code_bit: bcm_apply_code_bit,
    validate_fn_addr: bcm_validate_fn_addr,
    validate_module_base: bcm_validate_module_base,
    validate_fn_in_code: bcm_validate_fn_in_code,
    verify_integrity: bcm_verify_integrity,
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
    merge_runtime_overrides: bcm_merge_runtime_overrides,
    init_gpio: |_| 0, // no GPIO init on aarch64 (handled by PIC modules)
    csprng_fill: bcm_csprng_fill,
    core_id: || current_core_id() as usize,
    irq_bind,
};

// iproc-rng200 registers (BCM2712 / Pi 5). DT: soc@107c000000/rng@7d208000
// with ranges <0x0 0x10_0000_0000 0x8000_0000>.
#[cfg(feature = "board-cm5")]
const RNG200_BASE: usize = 0x10_7d20_8000;
#[cfg(feature = "board-cm5")]
const RNG200_CTRL: *mut u32 = RNG200_BASE as *mut u32;
#[cfg(feature = "board-cm5")]
#[allow(dead_code)]
const RNG200_STATUS: *const u32 = (RNG200_BASE + 0x04) as *const u32;
#[cfg(feature = "board-cm5")]
const RNG200_DATA: *const u32 = (RNG200_BASE + 0x08) as *const u32;
#[cfg(feature = "board-cm5")]
const RNG200_COUNT: *const u32 = (RNG200_BASE + 0x0C) as *const u32;

/// Fill buffer with hardware random bytes.
///
/// Pi 5 (board-cm5): Uses iproc-rng200 hardware TRNG at 0x10_7d20_8000.
/// QEMU virt: Uses CNTPCT_EL0 counter jitter with LCG mixing (weak).
///
/// Returns len on success, -1 if the hardware failed to produce entropy.
fn bcm_csprng_fill(buf: *mut u8, len: usize) -> i32 {
    unsafe {
        #[cfg(feature = "board-cm5")]
        {
            // Enable RNG if not already running
            let ctrl = core::ptr::read_volatile(RNG200_CTRL);
            if ctrl & 1 == 0 {
                core::ptr::write_volatile(RNG200_CTRL, ctrl | 1);
                // Wait for initial seed
                let mut wait = 0u32;
                while core::ptr::read_volatile(RNG200_COUNT) == 0 && wait < 1_000_000 {
                    wait += 1;
                }
                if core::ptr::read_volatile(RNG200_COUNT) == 0 {
                    uart_puts(b"[rng200] FATAL: no entropy after enable\r\n");
                    return -1;
                }
            }

            let mut i = 0usize;
            while i < len {
                // Wait for data available
                let mut wait = 0u32;
                while core::ptr::read_volatile(RNG200_COUNT) == 0 && wait < 1_000_000 {
                    wait += 1;
                }
                if core::ptr::read_volatile(RNG200_COUNT) == 0 {
                    uart_puts(b"[rng200] FATAL: entropy timeout\r\n");
                    return -1;
                }
                let word = core::ptr::read_volatile(RNG200_DATA);
                let bytes = word.to_le_bytes();
                let mut j = 0;
                while j < 4 && i < len {
                    core::ptr::write_volatile(buf.add(i), bytes[j]);
                    i += 1;
                    j += 1;
                }
            }
        }

        #[cfg(not(feature = "board-cm5"))]
        {
            // QEMU virt: no hardware RNG. Use counter jitter + LCG mixing.
            // Adequate for testing only.
            let mut state: u64 = 0;
            let mut i = 0usize;
            while i < len {
                let cnt: u64;
                core::arch::asm!("mrs {}, cntvct_el0", out(reg) cnt);
                state ^= cnt;
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                core::ptr::write_volatile(buf.add(i), (state >> 32) as u8);
                i += 1;
            }
        }
    }
    len as i32
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
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
        let n = fluxor::kernel::log_ring::read_tail(&mut buf);
        if n > 0 {
            uart_raw_puts(b"--- log tail (");
            uart_raw_put_u32(n as u32);
            uart_raw_puts(b" bytes) ---\r\n");
            uart_raw_puts(&buf[..n]);
            uart_raw_puts(b"\r\n--- end ---\r\n");
        }
    }
    loop { unsafe { core::arch::asm!("wfi") }; }
}
