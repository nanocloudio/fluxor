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

// ============================================================================
// Platform address constants (compile-time board selection)
// ============================================================================

// UART (PL011)
#[cfg(not(feature = "board-cm5"))]
const UART_BASE: usize = 0x0900_0000; // QEMU virt PL011
#[cfg(feature = "board-cm5")]
const UART_BASE: usize = 0x1c_0003_0000; // Pi 5 RP1 UART0 on GPIO14/15
// RP1 is mapped at 0x1c_0000_0000 by VPU firmware (PCIe outbound window).
// Requires enable_uart=1, enable_rp1_uart=1, and pciex4_reset=0 in config.txt.

// GIC
#[cfg(not(feature = "board-cm5"))]
const GICD_BASE: usize = 0x0800_0000; // QEMU virt GICv2 distributor
#[cfg(not(feature = "board-cm5"))]
const GICC_BASE: usize = 0x0801_0000; // QEMU virt GICv2 CPU interface
#[cfg(feature = "board-cm5")]
const GICD_BASE: usize = 0x10_7fff_9000; // Pi 5 GIC-400 distributor
#[cfg(feature = "board-cm5")]
const GICC_BASE: usize = 0x10_7fff_a000; // Pi 5 GIC-400 CPU interface

const GICC_IAR: *mut u32 = (GICC_BASE + 0x00C) as *mut u32;
const GICC_EOIR: *mut u32 = (GICC_BASE + 0x010) as *mut u32;
// Pi 5 (board-cm5): physical timer PPI 30 — no hypervisor, direct access.
// QEMU: virtual timer PPI 27 — avoids KVM trap overhead on physical timer.
#[cfg(feature = "board-cm5")]
const TIMER_PPI: u32 = 30;
#[cfg(not(feature = "board-cm5"))]
const TIMER_PPI: u32 = 27;
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

// ============================================================================
// PL011 UART registers (full register set for Pi 5 init)
// ============================================================================

const UART_DR: *mut u32 = UART_BASE as *mut u32;
#[cfg(feature = "board-cm5")]
const UART_FR: *const u32 = (UART_BASE + 0x18) as *const u32;
#[cfg(feature = "board-cm5")]
const UART_FR_TXFF: u32 = 1 << 5;

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

// ============================================================================
// UART driver
// ============================================================================

/// Initialize PL011 UART for Pi 5 (RP1 UART0 at 0x1c_0003_0000).
///
/// Depends on `rp1_clocks_init()` having run first to ungate the PL011
/// reference clock. Values are the ones a running Linux kernel programs
/// (captured via devmem) for 115200 baud at RP1's 50 MHz UART ref clock.
///
///   +0x24 IBRD = 0x1B  (27)     -> 50 MHz ref / (16 * (27 + 8/64)) = 115200 baud
///   +0x28 FBRD = 0x08  (8)
///   +0x2c LCRH = 0x70           -> 8N1, FIFO enabled
///   +0x30 CR   = 0x301          -> UARTEN | TXE | RXE (no hardware flow control)
#[cfg(feature = "board-cm5")]
unsafe fn uart_init() {
    // VPU firmware (with enable_rp1_uart=1) fully configures PL011 at
    // 115200 8N1 before kernel handoff. We just reprogram to be sure.
    let fr   = (UART_BASE + 0x18) as *const u32;
    let ibrd = (UART_BASE + 0x24) as *mut u32;
    let fbrd = (UART_BASE + 0x28) as *mut u32;
    let lcrh = (UART_BASE + 0x2c) as *mut u32;
    let cr   = (UART_BASE + 0x30) as *mut u32;
    let imsc = (UART_BASE + 0x38) as *mut u32;
    let icr  = (UART_BASE + 0x44) as *mut u32;

    core::ptr::write_volatile(cr, 0);
    let mut retries = 0u32;
    while retries < 10_000 {
        if core::ptr::read_volatile(fr) & (1 << 3) == 0 { break; }
        retries += 1;
    }
    core::ptr::write_volatile(imsc, 0);
    core::ptr::write_volatile(icr, 0x7FF);
    core::ptr::write_volatile(ibrd, 27);
    core::ptr::write_volatile(fbrd, 8);
    core::ptr::write_volatile(lcrh, 0x70);
    core::ptr::write_volatile(cr, 0x301);
}

#[cfg(not(feature = "board-cm5"))]
unsafe fn uart_init() {
    // QEMU virt: UART is already configured, nothing to do
}

// Normal kernel log path: push to the log ring only. The wire is driven
// by the platform-runtime debug drain (`platform::debug::DebugDrain`)
// via the `Bcm2712UartSink` below. Keeps logs opt-in and orthogonal to
// the application.
fn uart_putc(c: u8) {
    fluxor::kernel::log_ring::push_byte(c);
}

fn uart_puts(s: &[u8]) {
    fluxor::kernel::log_ring::push_bytes(s);
}

// Direct synchronous MMIO path — used only by the exception / panic
// handler, which cannot rely on the scheduler (or therefore the debug
// drain) still being alive. Normal-runtime writes go through the non-
// blocking FIFO-fill path (`uart_nonblocking_write`).
fn uart_raw_putc(c: u8) {
    unsafe {
        #[cfg(feature = "board-cm5")]
        {
            while core::ptr::read_volatile(UART_FR) & UART_FR_TXFF != 0 {}
        }
        core::ptr::write_volatile(UART_DR, c as u32);
    }
}

fn uart_raw_puts(s: &[u8]) {
    let mut i = 0;
    while i < s.len() {
        uart_raw_putc(s[i]);
        i += 1;
    }
}

/// Non-blocking UART FIFO fill. Writes as many bytes as the TX FIFO
/// will accept right now, then returns the count. Used as the
/// `DebugTx` backend for the platform debug drain — the drain owns
/// retry/backpressure state so we never spin here. On QEMU virt
/// (non-board-cm5) the FR bit isn't meaningful; fall back to writing
/// all bytes.
fn uart_nonblocking_write(bytes: &[u8]) -> usize {
    if UART_READY.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    let mut i = 0;
    while i < bytes.len() {
        #[cfg(feature = "board-cm5")]
        unsafe {
            if core::ptr::read_volatile(UART_FR) & UART_FR_TXFF != 0 {
                break;
            }
        }
        unsafe { core::ptr::write_volatile(UART_DR, bytes[i] as u32) };
        i += 1;
    }
    i
}

/// Raw u32 decimal printer for panic / exception paths (mirrors
/// `uart_put_u32` but goes straight to the wire).
fn uart_raw_put_u32(mut n: u32) {
    let mut buf = [0u8; 10];
    let mut i = 0usize;
    if n == 0 { uart_raw_putc(b'0'); return; }
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; uart_raw_putc(buf[i]); }
}

// --- Platform debug drain (local UART) ---
//
// Normal-runtime path for kernel log output. Drains `log_ring` into
// the UART via `DebugTx`, called from the core-0 main loop once per
// scheduler tick (tier 0 / tier 1a). SPSC against the kernel log
// path — single consumer. Panic / exception handlers do not use this
// path; they hit the wire directly via `uart_raw_puts`.
struct Bcm2712UartSink;

impl fluxor::platform::debug::DebugTx for Bcm2712UartSink {
    fn write(&mut self, bytes: &[u8]) -> usize {
        uart_nonblocking_write(bytes)
    }
}

static mut DEBUG_DRAIN: fluxor::platform::debug::DebugDrain<1024> =
    fluxor::platform::debug::DebugDrain::new();
static mut DEBUG_SINK: Bcm2712UartSink = Bcm2712UartSink;

/// Drain queued log bytes to the UART. MUST only be called from core 0.
#[inline]
fn debug_drain_poll_core0() {
    // SAFETY: SPSC consumer on log_ring; only called from core 0 in
    // the main loop or during boot before secondary cores wake.
    unsafe {
        let drain = &mut *(&raw mut DEBUG_DRAIN);
        let sink = &mut *(&raw mut DEBUG_SINK);
        drain.poll(sink);
    }
}

fn uart_put_u32(mut n: u32) {
    let mut buf = [0u8; 10];
    let mut i = 0usize;
    if n == 0 { uart_putc(b'0'); return; }
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; uart_putc(buf[i]); }
}

fn uart_put_hex32(val: u32) {
    let hex = b"0123456789abcdef";
    uart_puts(b"0x");
    let mut i = 28i32;
    while i >= 0 {
        uart_putc(hex[((val >> i as u32) & 0xf) as usize]);
        i -= 4;
    }
}

// ============================================================================
// MMU — Identity-mapped page tables (Pi 5 only)
// ============================================================================
//
// 4KB granule, EL1, 2-level (L1 + L2) identity map.
// L1 covers 512 entries x 1GB each = 512 GB address space.
// L2 covers 512 entries x 2MB each = 1 GB per L1 entry.
//
// MAIR indices:
//   0 = Normal Cacheable (Write-Back, Write-Allocate, inner+outer)
//   1 = Device-nGnRnE (strongly ordered device memory)
//   2 = Normal Non-cacheable
//
// Memory map:
//   0x0000_0000 .. 0x3FFF_FFFF  (1 GB)  — DRAM, Normal Cacheable
//   0x4000_0000 .. 0x7FFF_FFFF  (1 GB)  — DRAM, Normal Cacheable
//   0x8000_0000 .. 0xBFFF_FFFF  (1 GB)  — DRAM, Normal Cacheable
//   0xC000_0000 .. 0xFFFF_FFFF  (1 GB)  — DRAM, Normal Cacheable
//   0x1_0000_0000 .. onwards    — Device (PCIe, RP1, GIC, BCM2712 peripherals)
//
// On QEMU virt, the memory map is different but we use 1GB blocks which is
// coarse enough to work. The key device regions (0x08000000 GIC, 0x09000000 UART)
// fall in the first 1GB which we map as device memory.

#[cfg(feature = "board-cm5")]
#[allow(dead_code)]
mod mmu {
    // Page table attributes for block descriptors (2MB or 1GB)
    const VALID: u64 = 1;        // bit 0: valid
    const TABLE: u64 = 1 << 1;   // bit 1: table descriptor (vs block for L1 1GB)
    const BLOCK: u64 = 0;        // bit 1=0: block descriptor

    // Lower attributes (bits [11:2])
    const ATTR_IDX_SHIFT: u64 = 2;
    const NS: u64 = 1 << 5;      // Non-secure
    const AP_RW: u64 = 0 << 6;   // AP[2:1] = 00: EL1 RW
    const SH_INNER: u64 = 3 << 8; // Inner shareable
    const AF: u64 = 1 << 10;     // Access flag (must set or we get fault)

    // Upper attributes
    const PXN: u64 = 1 << 53;    // Privileged execute-never
    const UXN: u64 = 1 << 54;    // Unprivileged execute-never

    // MAIR_EL1 encoding
    // Attr0: Normal, Write-Back Write-Allocate (inner+outer) = 0xFF
    // Attr1: Device-nGnRE = 0x04 (per RP1 datasheet §3.3.1.2: recommended
    //        AArch64 mapping for the RP1 PCIe peripheral region is nGnRE,
    //        not nGnRnE — nGnRnE forces the CPU to wait for writes to be
    //        "observable" before proceeding, which stalls on PCIe Posted
    //        writes that never return explicit completions)
    // Attr2: Normal Non-cacheable = 0x44
    pub const MAIR_VALUE: u64 =
        0xFF              // index 0: Normal WB-WA
        | (0x04 << 8)    // index 1: Device-nGnRE
        | (0x44 << 16);  // index 2: Normal Non-cacheable

    // TCR_EL1: 48-bit VA (T0SZ=16), 4KB granule, inner+outer WB-WA cacheable
    // TG0 = 0b00 (4KB), SH0 = 0b11 (inner shareable)
    // ORGN0 = 0b01 (WB-WA), IRGN0 = 0b01 (WB-WA)
    // T0SZ = 16 (48-bit)
    // T0SZ=25 → 39-bit VA (512 GB). Translation starts at L1 (no L0 needed).
    // Each L1 entry covers 1 GB. 512 entries covers the full 512 GB space.
    // RP1 BAR at 0x1f_xxxx_xxxx (~133 GB) fits within 512 GB.
    pub const TCR_VALUE: u64 =
        25                 // T0SZ = 25 → 39-bit VA (512 GB)
        | (0b01 << 8)     // IRGN0: WB-WA
        | (0b01 << 10)    // ORGN0: WB-WA
        | (0b11 << 12)    // SH0: inner shareable
        | (0b00 << 14)    // TG0: 4KB
        | (1 << 23)       // EPD1: disable TTBR1_EL1 walks (kernel-only, no upper VA)
        | (0b010u64 << 32); // IPS = 0b010 → 40-bit PA (1TB, covers RP1 BAR at 0x1f_xxxx_xxxx)

    // Block descriptor for DRAM: Normal Cacheable, RW, Inner Shareable
    const fn dram_block(addr: u64) -> u64 {
        addr | VALID | BLOCK | (0 << ATTR_IDX_SHIFT) | AP_RW | SH_INNER | AF
    }

    // Block descriptor for Device memory: Device-nGnRnE, RW, no exec
    const fn device_block(addr: u64) -> u64 {
        addr | VALID | BLOCK | (1 << ATTR_IDX_SHIFT) | AP_RW | AF | PXN | UXN
    }

    // Block descriptor for DMA memory: Normal Non-Cacheable, RW, Inner Shareable
    // Used for NIC DMA arena so hardware DMA and CPU see coherent data without
    // explicit cache maintenance. MAIR index 2 = 0x44 (Normal Non-cacheable).
    const fn dma_block(addr: u64) -> u64 {
        addr | VALID | BLOCK | (2 << ATTR_IDX_SHIFT) | AP_RW | SH_INNER | AF | UXN
    }

    // Table descriptor: points L1 entry to an L2 table (for 2MB granularity)
    const fn table_desc(l2_addr: u64) -> u64 {
        l2_addr | VALID | TABLE
    }

    /// Static L1 page table (512 entries, 4KB aligned, in BSS).
    /// Each entry covers 1 GB.
    #[repr(C, align(4096))]
    pub struct PageTable([u64; 512]);

    #[link_section = ".bss"]
    pub static mut L1_TABLE: PageTable = PageTable([0; 512]);

    /// L2 page table for the first 1GB of DRAM (0x0 - 0x3FFFFFFF).
    /// This allows the NIC DMA arena (2MB-aligned in BSS) to be mapped
    /// as non-cacheable while the rest of DRAM stays cacheable.
    /// Each entry covers 2MB.
    #[repr(C, align(4096))]
    struct L2Table([u64; 512]);

    #[link_section = ".bss"]
    static mut L2_TABLE_0: L2Table = L2Table([0; 512]);

    /// Fill the L1 page table with identity mappings.
    /// Must be called before enabling the MMU.
    pub unsafe fn init_page_tables() {
        let table = &mut *(&raw mut L1_TABLE.0);

        // 0x0_0000_0000 .. 0x0_3FFF_FFFF (1 GB): DRAM with L2 table so
        // the 2 MB blocks enclosing the BSS-backed DMA arenas (NIC ring
        // and PCIe1) can be flipped to Normal Non-Cacheable while the
        // rest stays cacheable. Both arenas must live below 4 GB because
        // the PCIe1 inbound ATU only covers PCI bus 0..0xFFFFFFFF on
        // Pi 5 (see nvme_trace/baseline/README.md).
        {
            let l2 = &mut *(&raw mut L2_TABLE_0.0);
            // Fill all 512 L2 entries as cacheable DRAM (each 2MB)
            let mut i = 0usize;
            while i < 512 {
                l2[i] = dram_block((i as u64) * 0x20_0000);
                i += 1;
            }
            // Flip each BSS DMA arena's enclosing 2 MB to Normal
            // Non-Cacheable (MAIR index 2). Hardware DMA and CPU see
            // coherent memory by construction — no DC CVAC / IVAC on
            // the fast path.
            let dma_addr = fluxor::kernel::nic_ring::dma_arena_base();
            if dma_addr != 0 && dma_addr < 0x4000_0000 {
                let l2_idx = dma_addr >> 21;
                l2[l2_idx] = dma_block((l2_idx as u64) * 0x20_0000);
            }
            let pcie1_dma = fluxor::kernel::nic_ring::pcie1_dma_arena_base();
            if pcie1_dma != 0 && pcie1_dma < 0x4000_0000 {
                let l2_idx = pcie1_dma >> 21;
                l2[l2_idx] = dma_block((l2_idx as u64) * 0x20_0000);
            }
            // Point L1[0] to our L2 table
            table[0] = table_desc(&raw const L2_TABLE_0 as u64);
        }
        // 0x0_4000_0000 .. 0x0_7FFF_FFFF (1 GB): DRAM
        table[1] = dram_block(0x0_4000_0000);
        // 0x0_8000_0000 .. 0x0_BFFF_FFFF (1 GB): DRAM
        table[2] = dram_block(0x0_8000_0000);
        // 0x0_C000_0000 .. 0x0_FFFF_FFFF (1 GB): DRAM
        table[3] = dram_block(0x0_C000_0000);

        // 0x1_0000_0000 .. 0x1_3FFF_FFFF: real DRAM on 8/16 GB Pi 5
        // boards. No longer used as DMA target (see PCIE1_DMA_ARENA
        // comment in bcm2712/net.rs) — mapped as regular cacheable
        // DRAM in case a future consumer wants it.
        table[4] = dram_block(0x1_0000_0000);
        // 0x1_4000_0000 .. 0x1_7FFF_FFFF: more PCIe space (device)
        table[5] = device_block(0x1_4000_0000);
        // 0x1_8000_0000 .. 0x1_BFFF_FFFF: PCIe range (device)
        table[6] = device_block(0x1_8000_0000);
        // 0x1_C000_0000 .. 0x1_FFFF_FFFF: PCIe range (device)
        table[7] = device_block(0x1_C000_0000);

        // BCM2712 peripheral space at 0xFE000000-0xFFFFFFFF (GIC, UART, etc.)
        // falls in the 4th GB (0xC000_0000..0xFFFF_FFFF). Map as device memory.
        // This loses 1GB of DRAM addressability (3GB usable), which is fine for
        // a bare-metal kernel that uses < 1MB.
        table[3] = device_block(0x0_C000_0000);

        // BCM2712 SoC peripheral aperture at 0x10_0000_0000..0x10_8000_0000 (2 GB).
        // This covers the legacy peripherals block that device tree exposes under
        // `soc@107c000000 { ranges = <0x00 0x10 0x00 0x80000000>; }`, including
        // GIC-400 at 0x10_7fff_9000/a000 and the BCM7271 UART, pinctrl, etc.
        // L1 index = 0x10_0000_0000 / 0x4000_0000 = 64. Two 1GB blocks = 64, 65.
        table[64] = device_block(0x10_0000_0000);
        table[65] = device_block(0x10_4000_0000);

        // RP1 PCIe BAR region at 0x1c_0000_0000 (VPU firmware window).
        // L1 index = 0x1c_0000_0000 / 0x4000_0000 = 112.
        // Map 4 GB of device space covering the full RP1 BAR range.
        table[112] = device_block(0x1c_0000_0000);
        table[113] = device_block(0x1c_4000_0000);
        table[114] = device_block(0x1c_8000_0000);
        table[115] = device_block(0x1c_C000_0000);

        // PCIe1 (external x1 slot, NVMe HAT+) outbound MMIO window at
        // 0x18_0000_0000..0x1b_ffff_ffff (16 GB total) — verified
        // against the Pi 5 base-board 6.12 rpt kernel `dmesg` ranges
        // for the 1000110000.pcie controller (two ranges: mem1 at
        // 0x1800_0000_00 prefetchable, mem0 at 0x1b80_0000_00).
        // L1 indices 96..111, one 1 GB block each.
        let mut pcie1_idx = 96usize;
        while pcie1_idx < 112 {
            let addr = (pcie1_idx as u64) * 0x4000_0000;
            table[pcie1_idx] = device_block(addr);
            pcie1_idx += 1;
        }
    }

    /// Enable the MMU with the identity-mapped page tables.
    ///
    /// # Safety
    /// Must be called once, early in boot, before accessing any memory that
    /// requires cacheability attributes.
    pub unsafe fn enable() {
        let ttbr = &raw const L1_TABLE as u64;

        core::arch::asm!(
            // Set MAIR_EL1
            "msr mair_el1, {mair}",
            // Set TCR_EL1
            "msr tcr_el1, {tcr}",
            // Set TTBR0_EL1
            "msr ttbr0_el1, {ttbr}",
            // Barrier: ensure all table writes are visible
            "dsb ish",
            "isb",
            // Enable MMU (SCTLR_EL1: M=1, C=1, I=1)
            "mrs {tmp}, sctlr_el1",
            "orr {tmp}, {tmp}, #(1 << 0)",  // M: MMU enable
            "orr {tmp}, {tmp}, #(1 << 2)",  // C: Data cache enable
            "orr {tmp}, {tmp}, #(1 << 12)", // I: Instruction cache enable
            "msr sctlr_el1, {tmp}",
            "isb",
            mair = in(reg) MAIR_VALUE,
            tcr = in(reg) TCR_VALUE,
            ttbr = in(reg) ttbr,
            tmp = out(reg) _,
        );

        // Publish MAIR/TCR/TTBR0 for the secondary-core trampoline in
        // `bcm2712/multicore.rs`, which reads them with MMU off and
        // needs the values to already be at PoC.
        let mair_p = core::ptr::addr_of_mut!(fluxor::kernel::SECONDARY_MMU_MAIR);
        let tcr_p  = core::ptr::addr_of_mut!(fluxor::kernel::SECONDARY_MMU_TCR);
        let ttbr_p = core::ptr::addr_of_mut!(fluxor::kernel::SECONDARY_MMU_TTBR0);
        core::ptr::write_volatile(mair_p, MAIR_VALUE);
        core::ptr::write_volatile(tcr_p, TCR_VALUE);
        core::ptr::write_volatile(ttbr_p, ttbr);
        core::arch::asm!(
            "dc cvac, {m}",
            "dc cvac, {t}",
            "dc cvac, {b}",
            "dsb sy",
            m = in(reg) mair_p,
            t = in(reg) tcr_p,
            b = in(reg) ttbr_p,
            options(nostack),
        );
    }
}

// On QEMU virt, no MMU setup needed (identity mapped by QEMU firmware).
#[cfg(not(feature = "board-cm5"))]
mod mmu {
    pub unsafe fn init_page_tables() {}
    pub unsafe fn enable() {}
}

// ============================================================================
// RP1 HAL — GPIO, SPI, I2C via PCIe BAR (Pi 5 only)
// ============================================================================
//
// The RP1 chip is a separate silicon die connected to BCM2712 via PCIe x4.
// GPU firmware configures PCIe and maps RP1 into the ARM's physical address space.
// With `pciex4_reset=0` in config.txt, these mappings survive kernel handoff.
//
// RP1 BAR base address (set by GPU firmware, confirmed via /proc/iomem on Linux):
//   0x1c_0000_0000 (typical, may vary)
//
// RP1 peripheral offsets from BAR base:
//   GPIO bank0: BAR + 0xd0000
//   SPI0:       BAR + 0x50000
//   I2C0:       BAR + 0x70000
//   I2C1:       BAR + 0x74000

#[cfg(feature = "board-cm5")]
#[allow(dead_code)]
mod rp1 {
    /// RP1 PCIe BAR base address as mapped by GPU firmware.
    /// This is the standard address on Pi 5 with stock firmware.
    const RP1_BAR_BASE: usize = 0x1c_0000_d000;

    // RP1 GPIO bank0 registers (offset 0xd0000 from RP1 BAR)
    // But RP1_BAR_BASE already includes the offset to the peripheral aperture.
    // The actual layout from rp1-peripherals.pdf:
    //   GPIO bank0 base = RP1 BAR + 0x0_d0000
    // The BAR itself is at 0x1c_0000_0000, so GPIO is at 0x1c_000d_0000.

    /// RP1 peripheral base (start of RP1 address space on PCIe BAR)
    const RP1_PERI_BASE: usize = 0x1c_0000_0000;

    /// GPIO bank0 base within RP1 peripheral space
    const RP1_GPIO_BASE: usize = RP1_PERI_BASE + 0xd_0000;

    /// SYS_RIO0 base — register I/O for GPIO bank0
    const RP1_SYS_RIO0_BASE: usize = RP1_PERI_BASE + 0xe_0000;

    /// GPIO register offsets (per-pin)
    const GPIO_STATUS: usize = 0x00; // 8 bytes per GPIO: status @ +0, ctrl @ +4
    const GPIO_CTRL: usize = 0x04;

    /// RIO register offsets
    const RIO_OUT: usize = 0x00;       // Output value
    const RIO_OE: usize = 0x04;        // Output enable
    const RIO_IN: usize = 0x08;        // Input value
    // Atomic set/clr/xor at +0x2000/+0x3000/+0x1000

    const RIO_SET_OFFSET: usize = 0x2000;
    const RIO_CLR_OFFSET: usize = 0x3000;
    const RIO_XOR_OFFSET: usize = 0x1000;

    // FUNCSEL values for GPIO_CTRL
    const FUNCSEL_SYS_RIO: u32 = 5;   // Connect GPIO to SYS_RIO (software-controlled)
    const FUNCSEL_NULL: u32 = 31;      // Disconnect (high-Z)

    /// Probe RP1: try reading the GPIO bank0 status register for pin 0.
    /// Returns true if the read succeeds (non-0xFFFFFFFF / non-fault).
    pub fn probe() -> bool {
        let val = unsafe { core::ptr::read_volatile(RP1_GPIO_BASE as *const u32) };
        // If PCIe is not mapped, reads return 0xFFFFFFFF (bus error → all-ones)
        val != 0xFFFF_FFFF
    }

    /// Read the raw value of RP1 SYS_RIO0 input register.
    /// Returns the GPIO pin states as a bitmask.
    pub fn gpio_read_all() -> u32 {
        unsafe { core::ptr::read_volatile((RP1_SYS_RIO0_BASE + RIO_IN) as *const u32) }
    }

    /// Set a GPIO pin as output via RP1 SYS_RIO.
    /// Sets FUNCSEL to SYS_RIO and enables output.
    pub fn gpio_set_output(pin: u8) {
        if pin > 27 { return; }
        unsafe {
            // Set FUNCSEL to SYS_RIO (5)
            let ctrl_addr = (RP1_GPIO_BASE + (pin as usize) * 8 + GPIO_CTRL) as *mut u32;
            core::ptr::write_volatile(ctrl_addr, FUNCSEL_SYS_RIO);

            // Enable output (set OE bit)
            let oe_set = (RP1_SYS_RIO0_BASE + RIO_OE + RIO_SET_OFFSET) as *mut u32;
            core::ptr::write_volatile(oe_set, 1u32 << pin);
        }
    }

    /// Set a GPIO pin as input via RP1 SYS_RIO.
    pub fn gpio_set_input(pin: u8) {
        if pin > 27 { return; }
        unsafe {
            // Set FUNCSEL to SYS_RIO (5)
            let ctrl_addr = (RP1_GPIO_BASE + (pin as usize) * 8 + GPIO_CTRL) as *mut u32;
            core::ptr::write_volatile(ctrl_addr, FUNCSEL_SYS_RIO);

            // Disable output (clear OE bit)
            let oe_clr = (RP1_SYS_RIO0_BASE + RIO_OE + RIO_CLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(oe_clr, 1u32 << pin);
        }
    }

    /// Set GPIO pin output high.
    pub fn gpio_set_high(pin: u8) {
        if pin > 27 { return; }
        unsafe {
            let out_set = (RP1_SYS_RIO0_BASE + RIO_OUT + RIO_SET_OFFSET) as *mut u32;
            core::ptr::write_volatile(out_set, 1u32 << pin);
        }
    }

    /// Set GPIO pin output low.
    pub fn gpio_set_low(pin: u8) {
        if pin > 27 { return; }
        unsafe {
            let out_clr = (RP1_SYS_RIO0_BASE + RIO_OUT + RIO_CLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(out_clr, 1u32 << pin);
        }
    }

    /// Toggle GPIO pin output.
    pub fn gpio_toggle(pin: u8) {
        if pin > 27 { return; }
        unsafe {
            let out_xor = (RP1_SYS_RIO0_BASE + RIO_OUT + RIO_XOR_OFFSET) as *mut u32;
            core::ptr::write_volatile(out_xor, 1u32 << pin);
        }
    }

    /// Read a single GPIO pin input state.
    pub fn gpio_read(pin: u8) -> bool {
        if pin > 27 { return false; }
        (gpio_read_all() >> pin) & 1 != 0
    }

    // ==========================================================================
    // RP1 SPI register bridge
    // ==========================================================================

    const RP1_SPI0_BASE: usize = RP1_PERI_BASE + 0x5_0000;
    const RP1_SPI1_BASE: usize = RP1_PERI_BASE + 0x5_4000;

    fn spi_base(idx: u8) -> usize {
        match idx {
            0 => RP1_SPI0_BASE,
            _ => RP1_SPI1_BASE,
        }
    }

    /// Write a 32-bit value to an RP1 SPI register.
    pub fn spi_reg_write(spi_idx: u8, offset: u16, value: u32) {
        let addr = spi_base(spi_idx) + offset as usize;
        unsafe { core::ptr::write_volatile(addr as *mut u32, value) };
    }

    /// Read a 32-bit value from an RP1 SPI register.
    pub fn spi_reg_read(spi_idx: u8, offset: u16) -> u32 {
        let addr = spi_base(spi_idx) + offset as usize;
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    // ==========================================================================
    // RP1 I2C register bridge
    // ==========================================================================

    const RP1_I2C0_BASE: usize = RP1_PERI_BASE + 0x7_0000;
    const RP1_I2C1_BASE: usize = RP1_PERI_BASE + 0x7_4000;

    fn i2c_base(idx: u8) -> usize {
        match idx {
            0 => RP1_I2C0_BASE,
            _ => RP1_I2C1_BASE,
        }
    }

    /// Write a 32-bit value to an RP1 I2C register.
    pub fn i2c_reg_write(i2c_idx: u8, offset: u16, value: u32) {
        let addr = i2c_base(i2c_idx) + offset as usize;
        unsafe { core::ptr::write_volatile(addr as *mut u32, value) };
    }

    /// Read a 32-bit value from an RP1 I2C register.
    pub fn i2c_reg_read(i2c_idx: u8, offset: u16) -> u32 {
        let addr = i2c_base(i2c_idx) + offset as usize;
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    /// Print RP1 probe results to UART.
    pub fn report(uart_puts_fn: fn(&[u8]), uart_put_hex32_fn: fn(u32)) {
        if probe() {
            uart_puts_fn(b"[rp1] detected, GPIO bank0 accessible\r\n");
            let rio_in = gpio_read_all();
            uart_puts_fn(b"[rp1] SYS_RIO0 IN=");
            uart_put_hex32_fn(rio_in);
            uart_puts_fn(b"\r\n");
        } else {
            uart_puts_fn(b"[rp1] NOT detected (PCIe BAR read failed)\r\n");
            uart_puts_fn(b"[rp1] ensure config.txt has: pciex4_reset=0\r\n");
        }
    }
}

// Stub RP1 module for QEMU (no PCIe)
#[cfg(not(feature = "board-cm5"))]
mod rp1 {
    #[allow(dead_code)]
    pub fn probe() -> bool { false }
    pub fn report(_uart_puts_fn: fn(&[u8]), _uart_put_hex32_fn: fn(u32)) {}
}

// ============================================================================
// GICv2
// ============================================================================

/// IRQ-to-event binding table. When a bound IRQ fires, the kernel signals the
/// associated event via event_signal_from_isr (ISR-safe, lock-free).
/// Up to 4 bindings (virtio devices, GPIO, etc.).
const MAX_IRQ_BINDINGS: usize = 4;
struct IrqBinding {
    irq: u32,           // GIC interrupt ID (e.g. 48 for virtio SPI 16)
    event_handle: i32,  // Fluxor event handle to signal
    mmio_base: usize,   // If nonzero, ACK device by reading INTERRUPT_STATUS and writing INTERRUPT_ACK
}
static mut IRQ_BINDINGS: [IrqBinding; MAX_IRQ_BINDINGS] = [
    IrqBinding { irq: 0, event_handle: -1, mmio_base: 0 },
    IrqBinding { irq: 0, event_handle: -1, mmio_base: 0 },
    IrqBinding { irq: 0, event_handle: -1, mmio_base: 0 },
    IrqBinding { irq: 0, event_handle: -1, mmio_base: 0 },
];
static mut IRQ_BINDING_COUNT: usize = 0;

/// Sentinel event_handle that tells `irq_handler` to fan out via
/// `pcie::pcie1_msi_dispatch` instead of signalling a single event. Used
/// by `register_pcie1_msi_spi` so the brcmstb MSI mux can service all
/// 32 MSI vectors through one GIC SPI.
const EVENT_HANDLE_PCIE1_MSI: i32 = -2;

/// One-shot guard for `register_pcie1_msi_spi`. `irq_bind` appends a
/// row on every call; without this flag a driver that allocates N
/// MSI-X vectors would exhaust `IRQ_BINDINGS`.
static mut PCIE1_MSI_SPI_REGISTERED: bool = false;

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

unsafe fn gic_init() {
    core::ptr::write_volatile(GICD_BASE as *mut u32, 1); // GICD_CTLR: enable
    core::ptr::write_volatile((GICD_BASE + 0x100) as *mut u32, 1u32 << TIMER_PPI); // ISENABLER0
    core::ptr::write_volatile((GICD_BASE + 0x400 + TIMER_PPI as usize) as *mut u8, 0); // priority 0 (highest)
    core::ptr::write_volatile((GICC_BASE + 0x004) as *mut u32, 0xFF); // PMR: allow all
    core::ptr::write_volatile(GICC_BASE as *mut u32, 1); // GICC_CTLR: enable
}

/// Initialize GIC CPU interface on a secondary core.
/// Each core needs its own GICC setup for PPIs (like the timer).
unsafe fn gic_init_secondary() {
    core::ptr::write_volatile((GICC_BASE + 0x004) as *mut u32, 0xFF); // PMR
    core::ptr::write_volatile(GICC_BASE as *mut u32, 1); // GICC_CTLR
    // Enable timer PPI for this core
    core::ptr::write_volatile((GICD_BASE + 0x100) as *mut u32, 1u32 << TIMER_PPI);
}

// ============================================================================
// ARM Generic Timer
// ============================================================================

fn timer_freq() -> u64 {
    let freq: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq) };
    freq
}

/// Read the timer counter for cycle-accurate timing.
/// Pi 5: physical counter (CNTPCT_EL0) — direct hardware access.
/// QEMU: virtual counter (CNTVCT_EL0) — no KVM trap overhead.
fn read_timer_count() -> u32 {
    let val: u64;
    #[cfg(feature = "board-cm5")]
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) val) };
    #[cfg(not(feature = "board-cm5"))]
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) val) };
    val as u32
}

unsafe fn timer_set(ticks: u32) {
    #[cfg(feature = "board-cm5")]
    core::arch::asm!(
        "msr cntp_tval_el0, {val}",
        "mov {ctl}, #1",
        "msr cntp_ctl_el0, {ctl}",
        val = in(reg) ticks as u64,
        ctl = out(reg) _,
    );
    #[cfg(not(feature = "board-cm5"))]
    core::arch::asm!(
        "msr cntv_tval_el0, {val}",
        "mov {ctl}, #1",
        "msr cntv_ctl_el0, {ctl}",
        val = in(reg) ticks as u64,
        ctl = out(reg) _,
    );
}

// ============================================================================
// Exception vectors
// ============================================================================

global_asm!(
    ".section .text",
    ".balign 2048",
    ".global exception_vectors",
    "exception_vectors:",
    // Current EL with SP_EL0 (4 entries)
    ".balign 128", "b unhandled_exception",  // Synchronous
    ".balign 128", "b unhandled_exception",  // IRQ
    ".balign 128", "b unhandled_exception",  // FIQ
    ".balign 128", "b unhandled_exception",  // SError
    // Current EL with SP_ELx (4 entries)
    ".balign 128", "b unhandled_exception",  // Synchronous
    // IRQ handler — save all caller-saved registers
    ".balign 128",
    "sub sp, sp, #256",
    "stp x0,  x1,  [sp, #0]",
    "stp x2,  x3,  [sp, #16]",
    "stp x4,  x5,  [sp, #32]",
    "stp x6,  x7,  [sp, #48]",
    "stp x8,  x9,  [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x29, x30, [sp, #160]",
    "bl irq_handler",
    "ldp x0,  x1,  [sp, #0]",
    "ldp x2,  x3,  [sp, #16]",
    "ldp x4,  x5,  [sp, #32]",
    "ldp x6,  x7,  [sp, #48]",
    "ldp x8,  x9,  [sp, #64]",
    "ldp x10, x11, [sp, #80]",
    "ldp x12, x13, [sp, #96]",
    "ldp x14, x15, [sp, #112]",
    "ldp x16, x17, [sp, #128]",
    "ldp x18, x19, [sp, #144]",
    "ldp x29, x30, [sp, #160]",
    "add sp, sp, #256",
    "eret",
    ".balign 128", "b unhandled_exception",  // FIQ
    ".balign 128", "b unhandled_exception",  // SError
    // Lower EL using AArch64 (4 entries)
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    // Lower EL using AArch32 (4 entries)
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    "unhandled_exception:",
    "stp x29, x30, [sp, #-16]!",
    "stp x0, x1, [sp, #-16]!",
    "mrs x0, elr_el1",
    "mrs x1, esr_el1",
    "mrs x2, far_el1",
    "bl exception_dump",
    "ldp x0, x1, [sp], #16",
    "ldp x29, x30, [sp], #16",
    // Spin on exception — no recovery, keep CPU in diagnosable state.
    "1: b 1b",
);

/// Guard against recursive exceptions in exception_dump.
static EXCEPTION_DEPTH: AtomicU32 = AtomicU32::new(0);
/// Set to 1 after UART is initialised — exception_dump won't touch UART before this.
static UART_READY: AtomicU32 = AtomicU32::new(0);

#[no_mangle]
unsafe extern "C" fn exception_dump(elr: u64, esr: u64, far: u64) {
    // Prevent recursive exception storms — if we fault inside the handler,
    // just spin silently rather than faulting again.
    if EXCEPTION_DEPTH.fetch_add(1, Ordering::Relaxed) > 0 {
        return;
    }
    // Always store exception state at a fixed address for QEMU monitor inspection.
    // Read with: (qemu) xp /4gx 0x40070000
    // Useful when UART is not yet initialized (early boot / KVM).
    core::ptr::write_volatile(0x4007_0000 as *mut u64, elr);
    core::ptr::write_volatile(0x4007_0008 as *mut u64, esr);
    core::ptr::write_volatile(0x4007_0010 as *mut u64, far);
    core::ptr::write_volatile(0x4007_0018 as *mut u64, 0xDEAD_BEEF_CAFE_BABE);

    // Don't touch UART if it hasn't been initialised yet (early boot / KVM)
    if UART_READY.load(Ordering::Relaxed) == 0 {
        return;
    }
    // Exception path writes directly to the UART hardware. The ring
    // is unusable here — the scheduler may be dead, the log_uart
    // overlay won't drain, and even the heap allocator might be
    // poisoned. Raw MMIO is the only thing we can trust.
    uart_raw_puts(b"\r\n!!! EXCEPTION\r\n");
    uart_raw_puts(b"  ELR=0x"); exception_dump_hex64(elr);
    uart_raw_puts(b"\r\n  ESR=0x"); exception_dump_hex64(esr);
    uart_raw_puts(b"\r\n  FAR=0x"); exception_dump_hex64(far);
    uart_raw_puts(b"\r\n");
    // Recent log tail — helps correlate the fault with whatever the
    // system logged right before it. `read_tail` does not advance
    // the SPSC tail pointer, so a concurrent drain (if any remains)
    // still sees the same bytes.
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

/// Hex dump for exception handler. Duplicates uart_put_hex64 but routes
/// through uart_raw_putc — see exception_dump rationale.
fn exception_dump_hex64(val: u64) {
    let hex = b"0123456789abcdef";
    let mut i = 60i32;
    while i >= 0 {
        uart_raw_putc(hex[((val >> i as u64) & 0xf) as usize]);
        i -= 4;
    }
}

/// Timer ticks per scheduler tick (set from tick_us config or default 1ms)
static mut TICKS_PER_TICK: u32 = 0;

/// Per-core tick counters. Core 0 uses DBG_TICK for backward compatibility.
/// Secondary cores use this array.
static CORE_TICKS: [AtomicU32; 4] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

/// Current core number (0-3). Pi 5 encodes it in MPIDR Aff1[15:8].
#[inline(always)]
fn current_core_id() -> u8 {
    let mpidr: u64;
    unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nomem, nostack)); }
    ((mpidr >> 8) & 0xFF) as u8
}

#[no_mangle]
unsafe extern "C" fn irq_handler() {
    let iar = core::ptr::read_volatile(GICC_IAR);
    let irq_id = iar & 0x3FF;
    core::ptr::write_volatile(GICC_EOIR, iar);

    if irq_id == TIMER_PPI {
        // Timer tick — reload and count
        timer_set(TICKS_PER_TICK);
        let core_id = {
            let mpidr: u64;
            core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nomem, nostack));
            ((mpidr >> 8) & 0xFF) as usize
        };
        CORE_TICKS[core_id].fetch_add(1, Ordering::Relaxed);
    } else {
        // Check IRQ bindings (virtio, etc.)
        let n = IRQ_BINDING_COUNT;
        let mut i = 0;
        while i < n {
            let binding = &IRQ_BINDINGS[i];
            if binding.irq == irq_id {
                if binding.event_handle == EVENT_HANDLE_PCIE1_MSI {
                    // brcmstb MSI mux: read + clear MSI_INT_STATUS,
                    // fan out per-vector events. Keeps total ISR
                    // cost proportional to the number of pending
                    // MSIs (typically 1).
                    let _ = fluxor::kernel::pcie::pcie1_msi_dispatch();
                } else if binding.event_handle >= 0 {
                    // ACK device if mmio_base is set (virtio-mmio)
                    if binding.mmio_base != 0 {
                        let isr = core::ptr::read_volatile((binding.mmio_base + 0x60) as *const u32);
                        if isr != 0 {
                            core::ptr::write_volatile((binding.mmio_base + 0x64) as *mut u32, isr);
                        }
                    }
                    fluxor::kernel::event::event_signal_from_isr(binding.event_handle);
                }
            }
            i += 1;
        }
    }
}

// ============================================================================
// Per-domain module storage
// ============================================================================

/// Maximum modules per domain on this platform.
const MAX_MODS_PER_DOMAIN: usize = 12;

/// Module storage for each domain. Domain 0 is on core 0, domain 1 on core 1, etc.
/// Each domain's modules array is only accessed by its owning core after init.
struct DomainModules {
    modules: [Option<loader::DynamicModule>; MAX_MODS_PER_DOMAIN],
    count: usize,
    /// Topological execution order (domain-local indices).
    exec_order: [u8; MAX_MODS_PER_DOMAIN],
    exec_order_count: usize,
    /// Map from domain-local index to global module index.
    global_idx: [u8; MAX_MODS_PER_DOMAIN],
}

impl DomainModules {
    const fn new() -> Self {
        Self {
            modules: [const { None }; MAX_MODS_PER_DOMAIN],
            count: 0,
            exec_order: [0; MAX_MODS_PER_DOMAIN],
            exec_order_count: 0,
            global_idx: [0; MAX_MODS_PER_DOMAIN],
        }
    }
}

/// Per-domain module storage. Indexed by domain_id.
/// SAFETY: After init, each domain's storage is only accessed by its owning core.
static mut DOMAIN_MODULES: [DomainModules; multicore::MAX_DOMAINS] =
    [const { DomainModules::new() }; multicore::MAX_DOMAINS];

/// Signal that domain module storage has been initialized and secondary cores can start.
static INIT_COMPLETE: AtomicU32 = AtomicU32::new(0);

// ── Fan-out pump table ─────────────────────────────────────────────────
//
// When a single (module, out_port) has more than one edge on bcm2712,
// `scheduler::set_module_port` would overwrite the previous channel
// (last-wiring-wins). Instead we insert an intermediate tee channel:
// the source module writes to `src_chan`, and the domain loop's
// `pump_fan_outs` reads from `src_chan` and broadcasts to every
// `dst_chans` entry each tick. Small fan-out degree + small frames
// (debug log lines, net_proto frames) keep the pump cheap.

const MAX_FAN_OUTS: usize = 8;
const MAX_FAN_OUT_DSTS: usize = 4;
const FAN_BUF_SIZE: usize = 1024;

#[derive(Clone, Copy)]
struct FanOutEntry {
    domain: u8,
    active: bool,
    /// Identifier of the aliased source port.
    from_mod: u8,
    from_port: u8,
    /// Channel the source module writes to (the tee's input).
    src_chan: i32,
    dst_chans: [i32; MAX_FAN_OUT_DSTS],
    dst_count: u8,
}

impl FanOutEntry {
    const fn empty() -> Self {
        Self {
            domain: 0,
            active: false,
            from_mod: 0,
            from_port: 0,
            src_chan: -1,
            dst_chans: [-1; MAX_FAN_OUT_DSTS],
            dst_count: 0,
        }
    }
}

static mut FAN_OUTS: [FanOutEntry; MAX_FAN_OUTS] = [const { FanOutEntry::empty() }; MAX_FAN_OUTS];
static mut FAN_BUF: [u8; FAN_BUF_SIZE] = [0; FAN_BUF_SIZE];

// Fan-in (merge) counterpart to the fan-out table. When a single
// (module, in_port) has more than one producer edge, we collect the
// producers into `src_chans` and merge-pump them into `dst_chan` — the
// channel the consumer module binds to its in port.
const MAX_FAN_INS: usize = 8;
const MAX_FAN_IN_SRCS: usize = 4;

#[derive(Clone, Copy)]
struct FanInEntry {
    domain: u8,
    active: bool,
    to_mod: u8,
    to_port_type: u8,  // 0 = in, 2 = ctrl
    to_port: u8,
    dst_chan: i32,
    src_chans: [i32; MAX_FAN_IN_SRCS],
    src_count: u8,
    next_read_idx: u8,
}

impl FanInEntry {
    const fn empty() -> Self {
        Self {
            domain: 0,
            active: false,
            to_mod: 0,
            to_port_type: 0,
            to_port: 0,
            dst_chan: -1,
            src_chans: [-1; MAX_FAN_IN_SRCS],
            src_count: 0,
            next_read_idx: 0,
        }
    }
}

static mut FAN_INS: [FanInEntry; MAX_FAN_INS] = [const { FanInEntry::empty() }; MAX_FAN_INS];

unsafe fn find_fan_in(to_mod: u8, to_port_type: u8, to_port: u8) -> Option<usize> {
    for (i, e) in (*(&raw const FAN_INS)).iter().enumerate() {
        if e.active && e.to_mod == to_mod && e.to_port_type == to_port_type && e.to_port == to_port {
            return Some(i);
        }
    }
    None
}

unsafe fn register_fan_in(domain: u8, to_mod: u8, to_port_type: u8, to_port: u8,
                          first_src: i32) -> i32 {
    use fluxor::kernel::channel;
    for e in (*(&raw mut FAN_INS)).iter_mut() {
        if !e.active {
            let dst = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
            if dst < 0 { return -1; }
            e.domain = domain;
            e.active = true;
            e.to_mod = to_mod;
            e.to_port_type = to_port_type;
            e.to_port = to_port;
            e.dst_chan = dst;
            e.src_chans = [-1; MAX_FAN_IN_SRCS];
            e.src_chans[0] = first_src;
            e.src_count = 1;
            e.next_read_idx = 0;
            FAN_DIAG.fi_active = FAN_DIAG.fi_active.saturating_add(1);
            if FAN_DIAG.fi_first_dst_chan < 0 {
                FAN_DIAG.fi_first_dst_chan = dst;
                FAN_DIAG.fi_first_src0 = first_src;
            }
            return dst;
        }
    }
    -1
}

unsafe fn add_fan_in_src(entry_idx: usize, src: i32) -> bool {
    let fi = &mut (*(&raw mut FAN_INS))[entry_idx];
    if (fi.src_count as usize) >= MAX_FAN_IN_SRCS { return false; }
    fi.src_chans[fi.src_count as usize] = src;
    if fi.src_count == 1 && FAN_DIAG.fi_first_src1 < 0 {
        FAN_DIAG.fi_first_src1 = src;
    }
    fi.src_count += 1;
    true
}

/// Merge round-robin from producer channels into the consumer channel.
/// One frame per source per tick keeps producers fair without requiring
/// a per-source buffer.
unsafe fn pump_fan_ins(domain_id: usize) {
    use fluxor::kernel::channel::{syscall_channel_poll, syscall_channel_read,
        syscall_channel_write, POLL_IN, POLL_OUT};
    let buf = &raw mut FAN_BUF;
    for e in (*(&raw mut FAN_INS)).iter_mut() {
        if !e.active || e.domain as usize != domain_id { continue; }
        // Short-circuit if the consumer channel has no room.
        if syscall_channel_poll(e.dst_chan, POLL_OUT) & (POLL_OUT as i32) == 0 {
            FAN_DIAG.fi_skip_consumer_full = FAN_DIAG.fi_skip_consumer_full.wrapping_add(1);
            continue;
        }
        let n = e.src_count as usize;
        let mut moved = false;
        let mut tries = 0;
        while tries < n {
            let idx = e.next_read_idx as usize;
            e.next_read_idx = ((idx + 1) % n) as u8;
            tries += 1;
            let src = e.src_chans[idx];
            if syscall_channel_poll(src, POLL_IN) & (POLL_IN as i32) == 0 { continue; }
            let read = syscall_channel_read(src, (*buf).as_mut_ptr(), FAN_BUF_SIZE);
            if read <= 0 { continue; }
            let _ = syscall_channel_write(e.dst_chan, (*buf).as_ptr(), read as usize);
            FAN_DIAG.fi_frames = FAN_DIAG.fi_frames.wrapping_add(1);
            FAN_DIAG.fi_bytes = FAN_DIAG.fi_bytes.wrapping_add(read as u32);
            moved = true;
            break;
        }
        if !moved { FAN_DIAG.fi_skip_no_src = FAN_DIAG.fi_skip_no_src.wrapping_add(1); }
    }
    FAN_DIAG.fi_calls = FAN_DIAG.fi_calls.wrapping_add(1);
}

/// Locate the fan-out entry for (from_mod, from_port), or None.
unsafe fn find_fan_out(from_mod: u8, from_port: u8) -> Option<usize> {
    for (i, e) in (*(&raw const FAN_OUTS)).iter().enumerate() {
        if e.active && e.from_mod == from_mod && e.from_port == from_port {
            return Some(i);
        }
    }
    None
}

/// Allocate and populate a fan-out entry. Returns the tee's source
/// channel (the one the writer module binds to its out port) or -1 on
/// capacity failure.
unsafe fn register_fan_out(domain: u8, from_mod: u8, from_port: u8, first_dst: i32) -> i32 {
    use fluxor::kernel::channel;
    for e in (*(&raw mut FAN_OUTS)).iter_mut() {
        if !e.active {
            let src = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
            if src < 0 { return -1; }
            e.domain = domain;
            e.active = true;
            e.from_mod = from_mod;
            e.from_port = from_port;
            e.src_chan = src;
            e.dst_chans = [-1; MAX_FAN_OUT_DSTS];
            e.dst_chans[0] = first_dst;
            e.dst_count = 1;
            FAN_DIAG.fo_active = FAN_DIAG.fo_active.saturating_add(1);
            if FAN_DIAG.fo_first_src_chan < 0 {
                FAN_DIAG.fo_first_src_chan = src;
                FAN_DIAG.fo_first_dst0 = first_dst;
            }
            return src;
        }
    }
    -1
}

unsafe fn add_fan_out_dst(entry_idx: usize, dst: i32) -> bool {
    let fo = &mut (*(&raw mut FAN_OUTS))[entry_idx];
    if (fo.dst_count as usize) >= MAX_FAN_OUT_DSTS { return false; }
    fo.dst_chans[fo.dst_count as usize] = dst;
    if fo.dst_count == 1 && FAN_DIAG.fo_first_dst1 < 0 {
        FAN_DIAG.fo_first_dst1 = dst;
    }
    fo.dst_count += 1;
    true
}

/// Drain all fan-out entries that belong to `domain_id`: read one
/// message from each source channel and write it to every destination.
/// Backpressures conservatively — if any destination is full the frame
/// stays in the source channel until the next tick.
unsafe fn pump_fan_outs(domain_id: usize) {
    use fluxor::kernel::channel::{syscall_channel_poll, syscall_channel_read,
        syscall_channel_write, POLL_IN, POLL_OUT};
    let buf = &raw mut FAN_BUF;
    for e in (*(&raw mut FAN_OUTS)).iter() {
        if !e.active || e.domain as usize != domain_id { continue; }
        if syscall_channel_poll(e.src_chan, POLL_IN) & (POLL_IN as i32) == 0 {
            FAN_DIAG.fo_skip_input = FAN_DIAG.fo_skip_input.wrapping_add(1);
            continue;
        }
        // Require space in every destination so we don't partial-deliver.
        let mut all_ready = true;
        for i in 0..e.dst_count as usize {
            if syscall_channel_poll(e.dst_chans[i], POLL_OUT) & (POLL_OUT as i32) == 0 {
                all_ready = false;
                break;
            }
        }
        if !all_ready {
            FAN_DIAG.fo_skip_dst_full = FAN_DIAG.fo_skip_dst_full.wrapping_add(1);
            continue;
        }
        let read = syscall_channel_read(e.src_chan, (*buf).as_mut_ptr(), FAN_BUF_SIZE);
        if read <= 0 { continue; }
        let len = read as usize;
        for i in 0..e.dst_count as usize {
            let _ = syscall_channel_write(e.dst_chans[i], (*buf).as_ptr(), len);
        }
        FAN_DIAG.fo_frames += 1;
        FAN_DIAG.fo_bytes += len as u32;
    }
    FAN_DIAG.fo_calls = FAN_DIAG.fo_calls.wrapping_add(1);
}

// ── Fan-out / fan-in diagnostic counters ──────────────────────────────
// Exposed via `FAN_DIAG_SNAPSHOT` for inspection through the http
// `/_fan` diagnostic endpoint. Single-core updates (domain 0), no sync.
#[repr(C)]
pub struct FanDiag {
    pub fo_active: u8,
    pub fi_active: u8,
    pub fo_calls: u32,
    pub fi_calls: u32,
    pub fo_frames: u32,
    pub fo_bytes: u32,
    pub fi_frames: u32,
    pub fi_bytes: u32,
    pub fo_skip_input: u32,
    pub fo_skip_dst_full: u32,
    pub fi_skip_consumer_full: u32,
    pub fi_skip_no_src: u32,
    pub fo_first_src_chan: i32,
    pub fo_first_dst0: i32,
    pub fo_first_dst1: i32,
    pub fi_first_dst_chan: i32,
    pub fi_first_src0: i32,
    pub fi_first_src1: i32,
}

pub static mut FAN_DIAG: FanDiag = FanDiag {
    fo_active: 0, fi_active: 0,
    fo_calls: 0, fi_calls: 0,
    fo_frames: 0, fo_bytes: 0,
    fi_frames: 0, fi_bytes: 0,
    fo_skip_input: 0, fo_skip_dst_full: 0,
    fi_skip_consumer_full: 0, fi_skip_no_src: 0,
    fo_first_src_chan: -1, fo_first_dst0: -1, fo_first_dst1: -1,
    fi_first_dst_chan: -1, fi_first_src0: -1, fi_first_src1: -1,
};

/// Copy FAN_DIAG into a caller-supplied buffer as ASCII text. Returns
/// number of bytes written.
pub unsafe fn fan_diag_snapshot(buf: *mut u8, cap: usize) -> i32 {
    if buf.is_null() || cap == 0 { return 0; }
    let d = &raw const FAN_DIAG;
    let d = &*d;
    // Simple text serializer — no_std, no alloc, no formatter crate.
    let mut pos = 0usize;
    macro_rules! emit {
        ($bytes:expr) => {{
            let bs: &[u8] = $bytes;
            let mut k = 0;
            while k < bs.len() && pos < cap {
                *buf.add(pos) = bs[k]; pos += 1; k += 1;
            }
        }};
    }
    let mut numbuf = [0u8; 16];
    fn u32_to_dec(v: u32, out: &mut [u8; 16]) -> usize {
        if v == 0 { out[0] = b'0'; return 1; }
        let mut tmp = [0u8; 16];
        let mut n = 0;
        let mut x = v;
        while x > 0 {
            tmp[n] = b'0' + (x % 10) as u8;
            x /= 10;
            n += 1;
        }
        for i in 0..n { out[i] = tmp[n - 1 - i]; }
        n
    }
    fn i32_to_dec(v: i32, out: &mut [u8; 16]) -> usize {
        if v < 0 {
            out[0] = b'-';
            let mut tmp2 = [0u8; 16];
            let nn = u32_to_dec((-v) as u32, &mut tmp2);
            for i in 0..nn { out[1 + i] = tmp2[i]; }
            1 + nn
        } else {
            u32_to_dec(v as u32, out)
        }
    }

    macro_rules! emit_u32 {
        ($name:expr, $v:expr) => {{
            emit!($name);
            emit!(b"=");
            let n = u32_to_dec($v, &mut numbuf);
            let mut i = 0;
            while i < n && pos < cap { *buf.add(pos) = numbuf[i]; pos += 1; i += 1; }
            emit!(b" ");
        }};
    }
    macro_rules! emit_i32 {
        ($name:expr, $v:expr) => {{
            emit!($name);
            emit!(b"=");
            let n = i32_to_dec($v, &mut numbuf);
            let mut i = 0;
            while i < n && pos < cap { *buf.add(pos) = numbuf[i]; pos += 1; i += 1; }
            emit!(b" ");
        }};
    }

    emit_u32!(b"fo_active", d.fo_active as u32);
    emit_u32!(b"fi_active", d.fi_active as u32);
    emit_u32!(b"fo_calls", d.fo_calls);
    emit_u32!(b"fi_calls", d.fi_calls);
    emit_u32!(b"fo_frames", d.fo_frames);
    emit_u32!(b"fo_bytes", d.fo_bytes);
    emit_u32!(b"fi_frames", d.fi_frames);
    emit_u32!(b"fi_bytes", d.fi_bytes);
    emit_u32!(b"fo_skip_in", d.fo_skip_input);
    emit_u32!(b"fo_skip_dst", d.fo_skip_dst_full);
    emit_u32!(b"fi_skip_cons", d.fi_skip_consumer_full);
    emit_u32!(b"fi_skip_src", d.fi_skip_no_src);
    emit_i32!(b"fo_src", d.fo_first_src_chan);
    emit_i32!(b"fo_dst0", d.fo_first_dst0);
    emit_i32!(b"fo_dst1", d.fo_first_dst1);
    emit_i32!(b"fi_dst", d.fi_first_dst_chan);
    emit_i32!(b"fi_src0", d.fi_first_src0);
    emit_i32!(b"fi_src1", d.fi_first_src1);
    let (drop_l, drop_n, local_act, net_act) = fluxor::kernel::log_ring::peek_stats();
    emit_u32!(b"ring_drop_local", drop_l);
    emit_u32!(b"ring_drop_net", drop_n);
    emit_u32!(b"ring_local_active", if local_act { 1 } else { 0 });
    emit_u32!(b"ring_net_active", if net_act { 1 } else { 0 });
    emit!(b"\n");

    pos as i32
}

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
    // mmu::enable() after setting up page tables; any residual VPU state
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
        mmu::init_page_tables();
        mmu::enable();
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
        mmu::init_page_tables();
        mmu::enable();
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
    let freq = timer_freq();
    uart_puts(b"[timer] freq=");
    uart_put_u32(freq as u32);
    uart_puts(b" Hz\r\n");

    // Exception vectors + GIC + timer
    // Timer tick period will be recalculated after config is parsed (tick_us).
    // Start with 1ms default so the system runs during init.
    unsafe {
        gic_init();
        TICKS_PER_TICK = if freq > 0 { (freq / 1000) as u32 } else { 62500 };
        timer_set(TICKS_PER_TICK);
        core::arch::asm!("msr daifclr, #2"); // enable IRQs
    }

    uart_puts(b"[gic] initialized, IRQs enabled\r\n");

    // Initialize HAL with BCM2712 platform ops
    fluxor::kernel::hal::init(&BCM2712_HAL_OPS);

    // Initialize syscall table and provider registry
    fluxor::kernel::syscalls::init_syscall_table();
    fluxor::kernel::syscalls::init_providers();
    fluxor::kernel::syscalls::register_fan_diag_handler(fan_diag_snapshot);
    fluxor::kernel::step_guard::init();

    // --- Config-driven module graph ---
    use fluxor::kernel::channel;
    use fluxor::kernel::config::{self, MAX_MODULES};

    // Parse config from the QEMU side-loaded blob when present; otherwise use
    // the packaged trailer path (Pi 5 / raw packed image).
    let mut cfg = config::Config::empty();
    let cfg_ok = {
        #[cfg(not(feature = "board-cm5"))]
        {
            let blob_magic = unsafe { core::ptr::read_volatile(QEMU_CONFIG_BLOB_ADDR as *const u32) };
            if blob_magic == config::MAGIC_CONFIG {
                config::read_config_from_ptr(QEMU_CONFIG_BLOB_ADDR as *const u8, &mut cfg)
            } else {
                config::read_config_into(&mut cfg)
            }
        }
        #[cfg(feature = "board-cm5")]
        {
            config::read_config_into(&mut cfg)
        }
    };
    if !cfg_ok {
        uart_puts(b"[config] parse failed\r\n");
        loop { unsafe { core::arch::asm!("wfi") }; }
    }
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
        timer_set(TICKS_PER_TICK);
    }
    uart_puts(b"[timer] tick_us=");
    uart_put_u32(tick_us);
    uart_puts(b"\r\n");

    uart_puts(b"[config] ");
    uart_put_u32(n_modules as u32);
    uart_puts(b" modules, ");
    uart_put_u32(n_edges as u32);
    uart_puts(b" edges\r\n");

    // Load module table from the QEMU side-loaded blob when present; otherwise
    // use the packaged trailer path.
    loader::reset_state_arena();
    let mut ldr = loader::ModuleLoader::new();
    let loader_ok = {
        #[cfg(not(feature = "board-cm5"))]
        {
            let blob_magic = unsafe { core::ptr::read_volatile(QEMU_MODULES_BLOB_ADDR as *const u32) };
            if blob_magic == loader::MODULE_TABLE_MAGIC {
                ldr.init_from_blob(QEMU_MODULES_BLOB_ADDR as *const u8)
            } else {
                ldr.init()
            }
        }
        #[cfg(feature = "board-cm5")]
        {
            ldr.init()
        }
    };
    if loader_ok.is_err() {
        uart_puts(b"[loader] no modules\r\n");
        loop { unsafe { core::arch::asm!("wfi") }; }
    }

    // Create channels from graph edges.
    // Track per-global-module-index: input, output, ctrl channel handles.
    let mut mod_in: [i32; MAX_MODULES] = [-1; MAX_MODULES];
    let mut mod_out: [i32; MAX_MODULES] = [-1; MAX_MODULES];
    let mut mod_ctrl: [i32; MAX_MODULES] = [-1; MAX_MODULES];

    // Remember the channel opened for each edge so the per-module port
    // registrations can be re-applied immediately before start_new. A later
    // provider registration or allocation can otherwise disturb the port
    // table before the module sees it.
    const MAX_EDGE_CHANNELS: usize = 16;
    let mut edge_channels: [i32; MAX_EDGE_CHANNELS] = [-1; MAX_EDGE_CHANNELS];

    // Track which edges are cross-domain so we can set up CrossDomainChannels.
    // For cross-domain edges, we still create local pipe channels on each side,
    // and the domain loop pumps data between the cross-domain ring buffer and
    // the local channel.
    let mut e = 0usize;
    while e < n_edges {
        if let Some(ref edge) = cfg.graph_edges[e] {
            let from = edge.from_id as usize;
            let to = edge.to_id as usize;

            // Determine if this edge crosses domains
            let from_domain = if from < n_modules {
                cfg.modules[from].as_ref().map(|m| m.domain_id).unwrap_or(0)
            } else { 0 };
            let to_domain = if to < n_modules {
                cfg.modules[to].as_ref().map(|m| m.domain_id).unwrap_or(0)
            } else { 0 };

            let is_cross = from_domain != to_domain || edge.edge_class == EdgeClass::CrossCore;

            if is_cross {
                // Cross-domain edge: create separate local channels on each side
                // and a CrossDomainChannel to bridge them. Each cross-domain edge
                // gets its own local channel pair (supports multi-port modules).
                let out_ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
                let in_ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);

                if out_ch >= 0 && in_ch >= 0 {
                    // Track in per-module arrays for module instantiation.
                    // Only port_index==0 sets the module's primary handle (passed to start_new).
                    // Secondary ports are accessible via dev_channel_port() syscall.
                    if from < MAX_MODULES && edge.from_port_index == 0 && mod_out[from] < 0 {
                        mod_out[from] = out_ch;
                    }
                    if to < MAX_MODULES {
                        if edge.to_port == 0 && edge.to_port_index == 0 && mod_in[to] < 0 {
                            mod_in[to] = in_ch;
                        } else if edge.to_port == 1 && edge.to_port_index == 0 && mod_ctrl[to] < 0 {
                            mod_ctrl[to] = in_ch;
                        }
                    }
                    // Populate scheduler port table for cross-domain channels too
                    scheduler::set_module_port(from, 1, edge.from_port_index, out_ch);
                    let to_port_type = if edge.to_port == 1 { 2u8 } else { 0u8 };
                    scheduler::set_module_port(to, to_port_type, edge.to_port_index, in_ch);

                    // Allocate a cross-domain channel and register the edge.
                    // The edge stores both local handles directly so pump_cross_domain
                    // can operate per-edge without module-index indirection.
                    if let Some(cross_ch_idx) = multicore::alloc_cross_channel() {
                        let from_mod_in_domain = domain_local_index(&cfg, from, from_domain, n_modules);
                        let to_mod_in_domain = domain_local_index(&cfg, to, to_domain, n_modules);

                        unsafe {
                            multicore::register_cross_edge(multicore::CrossDomainEdge {
                                from_domain,
                                from_module: from_mod_in_domain as u8,
                                from_port: edge.from_port_index,
                                to_domain,
                                to_module: to_mod_in_domain as u8,
                                to_port: edge.to_port,
                                channel_idx: cross_ch_idx as u8,
                                local_out_handle: out_ch,
                                local_in_handle: in_ch,
                                pending_aux: core::sync::atomic::AtomicU32::new(u32::MAX),
                            });
                        }
                    }
                }
            } else {
                // Same-domain edge: allocate channels with fan-out (tee)
                // on aliased source ports and fan-in (merge) on aliased
                // destination ports. The raw `ch` is the producer-side
                // wire in the non-aliased case; fan-in replaces it with
                // a per-producer tributary.
                let ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
                if ch >= 0 {
                    let to_port_type = if edge.to_port == 1 { 2u8 } else { 0u8 };

                    // ── Fan-IN: multiple producers → single consumer port.
                    // Aliasing is detected through the scheduler's per-port
                    // channel table, which covers every (port_type, index).
                    let existing_fi = unsafe { find_fan_in(to as u8, to_port_type, edge.to_port_index) };
                    let producer_ch = if let Some(idx) = existing_fi {
                        let tributary = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
                        if tributary >= 0 {
                            unsafe { let _ = add_fan_in_src(idx, tributary); }
                            tributary
                        } else { ch }
                    } else {
                        let prior_consumer_chan = scheduler::get_module_port(
                            to, to_port_type, edge.to_port_index);
                        if prior_consumer_chan >= 0 {
                            // Second producer for this (module, in_port):
                            // promote to merge. Tributary #1 is the channel
                            // the first producer already writes to.
                            let new_dst = unsafe {
                                register_fan_in(from_domain, to as u8, to_port_type,
                                                edge.to_port_index, prior_consumer_chan)
                            };
                            if new_dst >= 0 {
                                // Redirect consumer port to merge's dst.
                                // Keep mod_in/mod_ctrl in sync when port 0.
                                if to < MAX_MODULES {
                                    if edge.to_port == 0 && edge.to_port_index == 0 {
                                        mod_in[to] = new_dst;
                                    } else if edge.to_port == 1 && edge.to_port_index == 0 {
                                        mod_ctrl[to] = new_dst;
                                    }
                                }
                                scheduler::set_module_port(to, to_port_type, edge.to_port_index, new_dst);
                                let idx = unsafe {
                                    find_fan_in(to as u8, to_port_type, edge.to_port_index).unwrap()
                                };
                                unsafe { let _ = add_fan_in_src(idx, ch); }
                                ch
                            } else { ch }
                        } else {
                            // First (producer, consumer) pair for this port.
                            if to < MAX_MODULES {
                                if edge.to_port == 0 && edge.to_port_index == 0 && mod_in[to] < 0 {
                                    mod_in[to] = ch;
                                } else if edge.to_port == 1 && edge.to_port_index == 0 && mod_ctrl[to] < 0 {
                                    mod_ctrl[to] = ch;
                                }
                            }
                            scheduler::set_module_port(to, to_port_type, edge.to_port_index, ch);
                            ch
                        }
                    };

                    if e < MAX_EDGE_CHANNELS { edge_channels[e] = ch; }

                    // ── Fan-OUT: single producer → multiple consumers.
                    // Aliasing is detected the same way as fan-in above,
                    // via scheduler port lookup.
                    let src_port_key = (from as u8, edge.from_port_index);
                    let first_chan_here = scheduler::get_module_port(from, 1, edge.from_port_index);
                    let existing_fan = unsafe { find_fan_out(src_port_key.0, src_port_key.1) };
                    if let Some(idx) = existing_fan {
                        unsafe { let _ = add_fan_out_dst(idx, producer_ch); }
                    } else if from < MAX_MODULES && first_chan_here >= 0 {
                        let src = unsafe {
                            register_fan_out(from_domain, src_port_key.0, src_port_key.1, first_chan_here)
                        };
                        if src >= 0 {
                            unsafe { let _ = add_fan_out_dst(find_fan_out(src_port_key.0, src_port_key.1).unwrap(), producer_ch); }
                            if from < MAX_MODULES && edge.from_port_index == 0 {
                                mod_out[from] = src;
                            }
                            scheduler::set_module_port(from, 1, edge.from_port_index, src);
                        }
                    } else {
                        if from < MAX_MODULES && edge.from_port_index == 0 && mod_out[from] < 0 {
                            mod_out[from] = producer_ch;
                        }
                        scheduler::set_module_port(from, 1, edge.from_port_index, producer_ch);
                    }
                }
            }
        }
        e += 1;
    }

    // Mask IRQs during module instantiation
    let _inst_guard = fluxor::kernel::guard::KernelGuard::acquire();

    let syscalls = fluxor::kernel::syscalls::get_table_for_module_type(0);

    // Instantiate modules and assign to domains based on entry.domain_id.
    let mut i = 0usize;
    while i < n_modules {
        if let Some(ref entry) = cfg.modules[i] {
            let domain_id = entry.domain_id as usize;
            if domain_id >= multicore::MAX_DOMAINS {
                uart_puts(b"[inst] invalid domain_id for module ");
                uart_put_u32(i as u32);
                uart_puts(b"\r\n");
                i += 1;
                continue;
            }

            if let Ok(m) = ldr.find_by_name_hash(entry.name_hash) {
                let dm_ref = unsafe { &mut DOMAIN_MODULES[domain_id] };
                if dm_ref.count >= MAX_MODS_PER_DOMAIN {
                    uart_puts(b"[inst] domain ");
                    uart_put_u32(domain_id as u32);
                    uart_puts(b" full\r\n");
                    i += 1;
                    continue;
                }
                let mod_idx = dm_ref.count;

                // Set global module index so syscalls and loader-driven
                // provider registration can identify the calling module
                // during module_new.
                fluxor::kernel::scheduler::set_current_module(i);

                // Populate export table and caps in SCHED so
                // resolve_export_for_module works for provider registration.
                scheduler::set_module_exports(
                    i, m.code_base() as usize,
                    m.export_table_ptr(), m.header.export_count,
                );
                let cap_class = match m.header.module_type {
                    5 => 3, 3 => 1, 4 => 2, _ => 0,
                };
                scheduler::set_module_caps(
                    i,
                    cap_class,
                    m.header.required_caps() as u32,
                    m.manifest_permissions(),
                );

                // Re-apply port registrations for this module from the stored edge
                // channel table. This keeps SCHED.ports consistent if earlier
                // instantiation (or provider registration) has perturbed it.
                //
                // When a port is fan-out/in'd, the real channel the module
                // uses is the tee's src (for out) or the merge's dst (for
                // in), not the raw edge channel. Skip the re-apply for
                // those ports and fall back to mod_in/out/ctrl, which
                // track the authoritative post-fan values.
                {
                    let mut ee = 0usize;
                    while ee < n_edges && ee < MAX_EDGE_CHANNELS {
                        if edge_channels[ee] >= 0 {
                            if let Some(ref edge) = cfg.graph_edges[ee] {
                                let from = edge.from_id as usize;
                                let to = edge.to_id as usize;
                                if from == i {
                                    let has_fan = unsafe { find_fan_out(i as u8, edge.from_port_index).is_some() };
                                    if !has_fan {
                                        scheduler::set_module_port(i, 1, edge.from_port_index, edge_channels[ee]);
                                    }
                                }
                                if to == i {
                                    let tp = if edge.to_port == 1 { 2u8 } else { 0u8 };
                                    let has_fan = unsafe { find_fan_in(i as u8, tp, edge.to_port_index).is_some() };
                                    if !has_fan {
                                        scheduler::set_module_port(i, tp, edge.to_port_index, edge_channels[ee]);
                                    }
                                }
                            }
                        }
                        ee += 1;
                    }
                    // Fan-out/in sources of truth: mod_out/mod_in for port 0.
                    if mod_out[i] >= 0 {
                        scheduler::set_module_port(i, 1, 0, mod_out[i]);
                    }
                    if mod_in[i] >= 0 {
                        scheduler::set_module_port(i, 0, 0, mod_in[i]);
                    }
                    if mod_ctrl[i] >= 0 {
                        scheduler::set_module_port(i, 2, 0, mod_ctrl[i]);
                    }
                }

                let result = unsafe {
                    loader::DynamicModule::start_new(
                        &m, syscalls,
                        mod_in[i], mod_out[i], mod_ctrl[i],
                        entry.params_ptr, entry.params_len, "",
                    )
                };
                match result {
                    Ok(loader::StartNewResult::Ready(dm)) => {
                        dm_ref.global_idx[mod_idx] = i as u8;
                        // Publish state pointer into the scheduler's
                        // per-module shadow so resolve_register_target
                        // can find us from a step-time registration
                        // call (e.g. BACKING_PROVIDER_ENABLE). bcm2712
                        // keeps modules in DOMAIN_MODULES rather than
                        // SCHED.modules, so without this, get_module_state
                        // returns null and every registration fails.
                        fluxor::kernel::scheduler::set_module_state_ptr(i, dm.state_ptr());
                        dm_ref.modules[mod_idx] = Some(dm);
                        dm_ref.count += 1;
                    }
                    Ok(loader::StartNewResult::Pending(mut pending)) => {
                        for _ in 0..100 {
                            for _ in 0..10000 { unsafe { core::arch::asm!("nop") }; }
                            match unsafe { pending.try_complete() } {
                                Ok(Some(dm)) => {
                                    dm_ref.global_idx[mod_idx] = i as u8;
                                    fluxor::kernel::scheduler::set_module_state_ptr(i, dm.state_ptr());
                                    dm_ref.modules[mod_idx] = Some(dm);
                                    dm_ref.count += 1;
                                    break;
                                }
                                Ok(None) => {}
                                Err(e) => { e.log("module"); break; }
                            }
                        }
                    }
                    Err(e) => e.log("module"),
                }
            }
        }
        i += 1;
    }

    // Sum per-domain module counts into SCHED.active_module_count so
    // queries like RECONFIGURE_MODULE_COUNT (used by the monitor overlay)
    // see the right number on bcm2712. The domain path instantiates
    // directly into DOMAIN_MODULES and doesn't go through
    // `prepare_graph`, which is the RP path that normally sets this.
    unsafe {
        let mut total = 0usize;
        let mut d = 0usize;
        while d < multicore::MAX_DOMAINS {
            total += DOMAIN_MODULES[d].count;
            d += 1;
        }
        fluxor::kernel::scheduler::set_active_module_count(total);
    }

    // Observability for Layer 2 DmaOwned edges. Same intent as the RP
    // graph path but reads cfg.graph_edges directly because the bcm2712
    // platform doesn't mirror edges into scheduler::SCHED.edges.
    fluxor::kernel::scheduler::log_dma_owned_edges_from_config(&cfg.graph_edges);

    // Compute per-domain topological execution order (Kahn's algorithm).
    // Must be done after all modules are instantiated so global_idx is populated.
    {
        let mut d = 0usize;
        while d < multicore::MAX_DOMAINS {
            let mod_count = unsafe { DOMAIN_MODULES[d].count };
            if mod_count > 0 {
                compute_domain_topo_order(d, &cfg, n_edges);
                let dm = unsafe { &DOMAIN_MODULES[d] };
                uart_puts(b"[topo] domain ");
                uart_put_u32(d as u32);
                uart_puts(b" order: ");
                let mut k = 0;
                while k < dm.exec_order_count {
                    if k > 0 { uart_puts(b"->"); }
                    uart_put_u32(dm.exec_order[k] as u32);
                    k += 1;
                }
                uart_puts(b"\r\n");
            }
            d += 1;
        }
    }

    // Set up domain execution state for all domains that have modules.
    let mut d = 0usize;
    while d < multicore::MAX_DOMAINS {
        let mod_count = unsafe { DOMAIN_MODULES[d].count };
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
            uart_puts(b")\r\n");
        }
        d += 1;
    }

    // Re-enable IRQs
    drop(_inst_guard);

    let total_mods: usize = {
        let mut total = 0usize;
        let mut dd = 0;
        while dd < multicore::MAX_DOMAINS {
            total += unsafe { DOMAIN_MODULES[dd].count };
            dd += 1;
        }
        total
    };
    uart_puts(b"[inst] ");
    uart_put_u32(total_mods as u32);
    uart_puts(b" modules loaded total\r\n");

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

/// Compute domain-local module index for a given global module index.
/// Counts how many modules with global index < `global_idx` are in the same domain.
fn domain_local_index(
    cfg: &fluxor::kernel::config::Config,
    global_idx: usize,
    domain_id: u8,
    n_modules: usize,
) -> usize {
    let mut count = 0usize;
    let mut j = 0;
    while j < n_modules && j < global_idx {
        if let Some(ref entry) = cfg.modules[j] {
            if entry.domain_id == domain_id {
                count += 1;
            }
        }
        j += 1;
    }
    count
}

/// Compute topological execution order for modules within a single domain.
///
/// Uses Kahn's algorithm restricted to intra-domain edges. Edges are identified
/// by matching global module indices against the domain's global_idx map.
/// The result is stored in dm.exec_order[] as domain-local indices.
fn compute_domain_topo_order(
    domain_id: usize,
    cfg: &fluxor::kernel::config::Config,
    n_edges: usize,
) {
    let dm = unsafe { &mut DOMAIN_MODULES[domain_id] };
    let n = dm.count;
    if n == 0 { return; }

    // Build global→local index map for this domain
    let mut global_to_local = [0xFFu8; fluxor::kernel::config::MAX_MODULES];
    let mut j = 0;
    while j < n {
        let g = dm.global_idx[j] as usize;
        if g < global_to_local.len() {
            global_to_local[g] = j as u8;
        }
        j += 1;
    }

    // Compute in-degree for domain-local modules (only intra-domain edges)
    let mut in_degree = [0u8; MAX_MODS_PER_DOMAIN];
    let mut e = 0;
    while e < n_edges {
        if let Some(ref edge) = cfg.graph_edges[e] {
            let from_local = global_to_local.get(edge.from_id as usize).copied().unwrap_or(0xFF);
            let to_local = global_to_local.get(edge.to_id as usize).copied().unwrap_or(0xFF);
            if from_local != 0xFF && to_local != 0xFF && from_local != to_local {
                in_degree[to_local as usize] = in_degree[to_local as usize].saturating_add(1);
            }
        }
        e += 1;
    }

    // BFS: start with zero in-degree modules
    let mut queue = [0u8; MAX_MODS_PER_DOMAIN];
    let mut qhead = 0usize;
    let mut qtail = 0usize;
    j = 0;
    while j < n {
        if in_degree[j] == 0 {
            queue[qtail] = j as u8;
            qtail += 1;
        }
        j += 1;
    }

    let mut count = 0usize;
    while qhead < qtail {
        let m = queue[qhead] as usize;
        qhead += 1;
        dm.exec_order[count] = m as u8;
        count += 1;

        // Decrement in-degree of successors
        e = 0;
        while e < n_edges {
            if let Some(ref edge) = cfg.graph_edges[e] {
                let from_local = global_to_local.get(edge.from_id as usize).copied().unwrap_or(0xFF);
                let to_local = global_to_local.get(edge.to_id as usize).copied().unwrap_or(0xFF);
                if from_local != 0xFF && to_local != 0xFF
                    && from_local as usize == m
                    && (to_local as usize) < n
                {
                    in_degree[to_local as usize] -= 1;
                    if in_degree[to_local as usize] == 0 {
                        queue[qtail] = to_local;
                        qtail += 1;
                    }
                }
            }
            e += 1;
        }
    }

    // Append any remaining (isolated or cycle-broken) modules
    if count < n {
        j = 0;
        while j < n {
            let mut found = false;
            let mut k = 0;
            while k < count {
                if dm.exec_order[k] as usize == j { found = true; }
                k += 1;
            }
            if !found {
                dm.exec_order[count] = j as u8;
                count += 1;
            }
            j += 1;
        }
    }

    dm.exec_order_count = count;
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
    use fluxor::modules::Module;
    use fluxor::kernel::step_guard;

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
                let t0 = read_timer_count();
                domain_step_all(domain_id);
                pump_cross_domain(domain_id);
                unsafe { pump_fan_outs(domain_id); pump_fan_ins(domain_id); }
                if core_id == 0 { debug_drain_poll_core0(); }
                let elapsed = read_timer_count().wrapping_sub(t0);
                let metrics = unsafe { &mut DOMAIN_METRICS[domain_id] };
                metrics.tick_count += 1;
                if elapsed > metrics.worst_step_ticks { metrics.worst_step_ticks = elapsed; }
                // Track busy ticks (step work exceeded 50% of tick budget)
                let freq = timer_freq() as u32;
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
        // Module step returns Burst → re-step immediately. WFE when all idle.
        3 => {
            log::info!("[domain] {} core={} tier=3 poll-mode", domain_id, core_id);
            let freq = bcm_counter_freq();
            loop {
                multicore::park_if_requested(domain_id);
                let dm = unsafe { &mut DOMAIN_MODULES[domain_id] };
                let mut any_burst = false;
                // Step in topological order for correct producer-before-consumer
                let n = if dm.exec_order_count > 0 { dm.exec_order_count } else { dm.count };
                let mut pos = 0;
                while pos < n {
                    let j = if dm.exec_order_count > 0 { dm.exec_order[pos] as usize } else { pos };
                    if let Some(ref mut m) = dm.modules[j] {
                        let global_idx = dm.global_idx[j] as usize;
                        fluxor::kernel::scheduler::set_current_module(global_idx);
                        step_guard::arm(step_guard::DEFAULT_STEP_DEADLINE_US);
                        let t0 = bcm_read_cntpct();
                        let outcome = m.step();
                        let elapsed_ticks = bcm_read_cntpct().wrapping_sub(t0);
                        step_guard::disarm();
                        step_guard::post_step_check();
                        if step_guard::check_and_clear_timeout() {
                            log::warn!("[guard] domain {} module {} timeout", domain_id, j);
                        }
                        if freq > 0 {
                            let elapsed_us = (elapsed_ticks.saturating_mul(1_000_000) / freq) as u32;
                            fluxor::kernel::scheduler::record_step_time(global_idx, elapsed_us);
                        }
                        if matches!(outcome, Ok(fluxor::modules::StepOutcome::Burst)) {
                            any_burst = true;
                        }
                    }
                    pos += 1;
                }
                pump_cross_domain(domain_id);
                unsafe { pump_fan_outs(domain_id); pump_fan_ins(domain_id); }
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
                unsafe { pump_fan_outs(domain_id); pump_fan_ins(domain_id); }
                if core_id == 0 { debug_drain_poll_core0(); }
                let metrics = unsafe { &mut DOMAIN_METRICS[domain_id] };
                metrics.tick_count += 1;
                if tick % 10000 == 0 && tick > 0 {
                    log::info!("[sched] alive t={} core={} domain={}", tick, core_id, domain_id);
                }
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

/// Step all modules in a domain with step guard protection.
/// Uses topological order when available for correct producer-before-consumer.
fn domain_step_all(domain_id: usize) {
    use fluxor::modules::Module;
    use fluxor::kernel::step_guard;

    // Counter frequency is invariant at runtime — read once per call.
    let freq = bcm_counter_freq();
    let dm = unsafe { &mut DOMAIN_MODULES[domain_id] };
    let n = if dm.exec_order_count > 0 { dm.exec_order_count } else { dm.count };
    let mut pos = 0;
    while pos < n {
        let j = if dm.exec_order_count > 0 { dm.exec_order[pos] as usize } else { pos };
        if let Some(ref mut m) = dm.modules[j] {
            let global_idx = dm.global_idx[j] as usize;
            fluxor::kernel::scheduler::set_current_module(global_idx);
            step_guard::arm(step_guard::DEFAULT_STEP_DEADLINE_US);
            let t0 = bcm_read_cntpct();
            let _ = m.step();
            let elapsed_ticks = bcm_read_cntpct().wrapping_sub(t0);
            step_guard::disarm();
            step_guard::post_step_check();
            if step_guard::check_and_clear_timeout() {
                log::warn!("[guard] domain {} module {} timeout", domain_id, j);
            }
            // Feed the step-time histogram so MON_HIST / fluxor monitor
            // see non-zero buckets. freq != 0 after uart_init, but guard
            // anyway in case this path runs pre-timer.
            if freq > 0 {
                let elapsed_us = (elapsed_ticks.saturating_mul(1_000_000) / freq) as u32;
                fluxor::kernel::scheduler::record_step_time(global_idx, elapsed_us);
            }
        }
        pos += 1;
    }
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

        // Producer side.
        if edge.from_domain == domain_id as u8 && edge.local_out_handle >= 0 {
            let mut buf = [0u8; multicore::SLOT_DATA_SIZE];
            let n = unsafe {
                fluxor::kernel::channel::channel_read(
                    edge.local_out_handle, buf.as_mut_ptr(), buf.len(),
                )
            };
            if n > 0 {
                let _ = ch.send(&buf[..n as usize]);
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
            }
            let mut val: u32 = 0;
            let rc = fluxor::kernel::channel::channel_ioctl(
                edge.local_in_handle,
                fluxor::kernel::channel::IOCTL_POLL_NOTIFY,
                &mut val as *mut u32 as *mut u8,
            );
            if rc == fluxor::kernel::channel::CHAN_OK && val != u32::MAX {
                edge.pending_aux.store(val, Ordering::Release);
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
        let freq = timer_freq();
        let ticks_for_domain = if freq > 0 {
            ((domain_tick as u64) * freq / 1_000_000) as u32
        } else {
            TICKS_PER_TICK
        };
        timer_set(ticks_for_domain);
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
// log crate backend — formats records into the kernel log ring.
// ============================================================================
//
// Parallel to the RingLogger on RP platforms: both routes funnel every
// `log::info!` etc. into `kernel::log_ring::push_bytes`. Wire output is
// driven by an opt-in overlay module (log_uart / log_usb / log_net).

struct RingLogger;

impl log::Log for RingLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool { true }
    fn log(&self, record: &log::Record) {
        use core::fmt::Write;
        // Format into a stack buffer first, then push the whole record
        // (plus CRLF) into the ring in a single call. Incremental
        // write_str pushes let a preempting ISR or cross-core producer
        // interleave bytes with our message; per-record staging prevents
        // that on both single-core and multi-core boots.
        struct BufWriter<'a> {
            buf: &'a mut [u8],
            pos: usize,
        }
        impl<'a> Write for BufWriter<'a> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let remaining = self.buf.len().saturating_sub(self.pos);
                let take = bytes.len().min(remaining);
                self.buf[self.pos..self.pos + take].copy_from_slice(&bytes[..take]);
                self.pos += take;
                Ok(())
            }
        }

        let mut buf = [0u8; 256];
        let written = {
            let mut w = BufWriter { buf: &mut buf, pos: 0 };
            let _ = core::fmt::write(&mut w, *record.args());
            if w.pos + 2 <= w.buf.len() {
                w.buf[w.pos] = b'\r';
                w.buf[w.pos + 1] = b'\n';
                w.pos += 2;
            }
            w.pos
        };
        fluxor::kernel::log_ring::push_bytes(&buf[..written]);
    }
    fn flush(&self) {}
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

fn bcm_now_millis() -> u64 { 0 }
fn bcm_now_micros() -> u64 { 0 }
fn bcm_tick_count() -> u32 {
    fluxor::kernel::scheduler::tick_count()
}

fn bcm_flash_base() -> usize { 0 }
fn bcm_flash_end() -> usize { 0 }
fn bcm_apply_code_bit(addr: usize) -> usize { addr }
fn bcm_validate_fn_addr(addr: usize) -> bool { addr != 0 }
fn bcm_validate_module_base(addr: usize) -> bool { addr != 0 }
fn bcm_validate_fn_in_code(_addr: usize, _code_base: usize, _code_size: u32) -> bool { true }
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

fn bcm_release_module_handles(_module_idx: u8) {}
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
                    for i in 0..8 { *arg.add(8 + i) = ab[i]; }
                    let db = data.to_le_bytes();
                    for i in 0..4 { *arg.add(16 + i) = db[i]; }
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
                None => return fluxor::kernel::errno::EINVAL,
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
                                    for i in 0..8 { *arg.add(8 + i) = ab[i]; }
                                    let db = data.to_le_bytes();
                                    for i in 0..4 { *arg.add(16 + i) = db[i]; }
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
    irq_bind: irq_bind,
};

// iproc-rng200 registers (BCM2712 / Pi 5). DT: soc@107c000000/rng@7d208000
// with ranges <0x0 0x10_0000_0000 0x8000_0000>.
#[cfg(feature = "board-cm5")]
const RNG200_BASE: usize = 0x10_7d20_8000;
#[cfg(feature = "board-cm5")]
const RNG200_CTRL: *mut u32 = (RNG200_BASE + 0x00) as *mut u32;
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
