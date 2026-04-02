// Platform: BCM2712 (Raspberry Pi 5 / CM5) — Cortex-A76, aarch64 bare-metal
//
// Two board configurations (selected at compile time):
//   - QEMU virt (default): PL011 at 0x0900_0000, GICv2 at 0x0800_0000, RAM at 0x4008_0000
//   - Pi 5 / CM5 (feature "board-cm5"): PL011 at 0xFE20_1000, GIC-400 at 0xFF84_1000, RAM at 0x8_0000
//
// Features:
//   - E3-S7: Secondary core parking (Pi 5 boots all 4 cores; we park 1-3 in WFE)
//   - E3-S2: Early MMU init with identity-mapped page tables (cacheable DRAM, device MMIO)
//   - E3-S4/S5: RP1 peripheral access via PCIe BAR (GPIO, SPI, I2C register bridges)
//   - E6: Multi-domain execution — modules assigned to domains by config, secondary cores woken
//
// Fully config-driven: the boot image carries trailer, modules.bin, and config.bin
// after the fixed kernel binary, discovered at runtime via the layout trailer.

use core::panic::PanicInfo;
use core::arch::global_asm;
use core::sync::atomic::{AtomicU32, Ordering};

use fluxor::kernel::scheduler;
use fluxor::kernel::loader;
use fluxor::kernel::cross_domain;
use fluxor::kernel::config::EdgeClass;

// ============================================================================
// Platform address constants (compile-time board selection)
// ============================================================================

// UART (PL011)
#[cfg(not(feature = "board-cm5"))]
const UART_BASE: usize = 0x0900_0000; // QEMU virt PL011
#[cfg(feature = "board-cm5")]
const UART_BASE: usize = 0xFE20_1000; // Pi 5 PL011 (BCM2712 legacy peripheral space)

// GICv2
#[cfg(not(feature = "board-cm5"))]
const GICD_BASE: usize = 0x0800_0000; // QEMU virt GICv2 distributor
#[cfg(not(feature = "board-cm5"))]
const GICC_BASE: usize = 0x0801_0000; // QEMU virt GICv2 CPU interface
#[cfg(feature = "board-cm5")]
const GICD_BASE: usize = 0xFF84_1000; // Pi 5 GIC-400 distributor
#[cfg(feature = "board-cm5")]
const GICC_BASE: usize = 0xFF84_2000; // Pi 5 GIC-400 CPU interface

const GICC_IAR: *mut u32 = (GICC_BASE + 0x00C) as *mut u32;
const GICC_EOIR: *mut u32 = (GICC_BASE + 0x010) as *mut u32;
const TIMER_PPI: u32 = 30; // Non-secure physical timer PPI

global_asm!(
    ".section .layout_header,\"a\"",
    ".global __package_header_start",
    ".global __package_source_start",
    "__package_header_start:",
    "    .word 0x4B505846", // PACKAGE_HEADER_MAGIC
    "    .byte 1, 0, 0, 0", // version + reserved
    "    .word __end_block_addr",
    "    .word 0",          // package_size (patched by pack-image)
    "__package_source_start:",
);

// ============================================================================
// PL011 UART registers (full register set for Pi 5 init)
// ============================================================================

const UART_DR: *mut u32 = UART_BASE as *mut u32;

// Full PL011 register set (used on Pi 5 for UART init)
#[cfg(feature = "board-cm5")]
const UART_FR: *const u32 = (UART_BASE + 0x18) as *const u32;    // Flag register
#[cfg(feature = "board-cm5")]
const UART_IBRD: *mut u32 = (UART_BASE + 0x24) as *mut u32;     // Integer baud rate
#[cfg(feature = "board-cm5")]
const UART_FBRD: *mut u32 = (UART_BASE + 0x28) as *mut u32;     // Fractional baud rate
#[cfg(feature = "board-cm5")]
const UART_LCRH: *mut u32 = (UART_BASE + 0x2C) as *mut u32;     // Line control
#[cfg(feature = "board-cm5")]
const UART_CR: *mut u32 = (UART_BASE + 0x30) as *mut u32;       // Control register
#[cfg(feature = "board-cm5")]
const UART_FR_TXFF: u32 = 1 << 5; // Transmit FIFO full

// ============================================================================
// UART driver
// ============================================================================

/// Initialize PL011 UART. On QEMU virt the UART is already configured.
/// On Pi 5, GPU firmware typically sets up UART0 on GPIO 14/15, but we
/// reinitialize to be safe.
#[cfg(feature = "board-cm5")]
unsafe fn uart_init() {
    // Disable UART
    core::ptr::write_volatile(UART_CR, 0);

    // Wait for ongoing TX to complete
    while core::ptr::read_volatile(UART_FR) & UART_FR_TXFF != 0 {}

    // Set baud rate: 115200 @ 48MHz UART clock
    // Divider = 48000000 / (16 * 115200) = 26.0416...
    // Integer = 26, Fractional = (0.0416 * 64 + 0.5) = 3
    core::ptr::write_volatile(UART_IBRD, 26);
    core::ptr::write_volatile(UART_FBRD, 3);

    // 8N1, enable FIFOs
    core::ptr::write_volatile(UART_LCRH, (0b11 << 5) | (1 << 4));

    // Enable UART, TX, RX
    core::ptr::write_volatile(UART_CR, (1 << 0) | (1 << 8) | (1 << 9));
}

#[cfg(not(feature = "board-cm5"))]
unsafe fn uart_init() {
    // QEMU virt: UART is already configured, nothing to do
}

fn uart_putc(c: u8) {
    unsafe {
        #[cfg(feature = "board-cm5")]
        {
            // Wait for space in TX FIFO
            while core::ptr::read_volatile(UART_FR) & UART_FR_TXFF != 0 {}
        }
        core::ptr::write_volatile(UART_DR, c as u32);
    }
}

fn uart_puts(s: &[u8]) {
    let mut i = 0;
    while i < s.len() { uart_putc(s[i]); i += 1; }
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

fn uart_put_hex64(val: u64) {
    let hex = b"0123456789abcdef";
    let mut i = 60i32;
    while i >= 0 {
        uart_putc(hex[((val >> i as u64) & 0xf) as usize]);
        i -= 4;
    }
}

// ============================================================================
// E3-S2: MMU — Identity-mapped page tables (Pi 5 only)
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
    // Attr1: Device-nGnRnE = 0x00
    // Attr2: Normal Non-cacheable = 0x44
    pub const MAIR_VALUE: u64 =
        0xFF              // index 0: Normal WB-WA
        | (0x00 << 8)    // index 1: Device-nGnRnE
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

    /// Static L1 page table (512 entries, 4KB aligned, in BSS).
    /// Each entry covers 1 GB.
    #[repr(C, align(4096))]
    pub struct PageTable([u64; 512]);

    #[link_section = ".bss"]
    pub static mut L1_TABLE: PageTable = PageTable([0; 512]);

    /// Fill the L1 page table with identity mappings.
    /// Must be called before enabling the MMU.
    pub unsafe fn init_page_tables() {
        let table = &mut *(&raw mut L1_TABLE.0);

        // 0x0_0000_0000 .. 0x0_3FFF_FFFF (1 GB): DRAM
        table[0] = dram_block(0x0_0000_0000);
        // 0x0_4000_0000 .. 0x0_7FFF_FFFF (1 GB): DRAM
        table[1] = dram_block(0x0_4000_0000);
        // 0x0_8000_0000 .. 0x0_BFFF_FFFF (1 GB): DRAM
        table[2] = dram_block(0x0_8000_0000);
        // 0x0_C000_0000 .. 0x0_FFFF_FFFF (1 GB): DRAM
        table[3] = dram_block(0x0_C000_0000);

        // 0x1_0000_0000 .. 0x1_3FFF_FFFF: PCIe / RP1 BAR region (device)
        table[4] = device_block(0x1_0000_0000);
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

        // RP1 PCIe BAR region at 0x1f_0000_0000.
        // L1 index = 0x1f_0000_0000 / 0x4000_0000 = 124.
        // Map 4 GB of device space covering the full RP1 BAR range.
        table[124] = device_block(0x1f_0000_0000);
        table[125] = device_block(0x1f_4000_0000);
        table[126] = device_block(0x1f_8000_0000);
        table[127] = device_block(0x1f_C000_0000);
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
    }
}

// On QEMU virt, skip MMU setup (QEMU handles cacheability transparently)
#[cfg(not(feature = "board-cm5"))]
mod mmu {
    pub unsafe fn init_page_tables() {}
    pub unsafe fn enable() {}
}

// ============================================================================
// E3-S4/S5: RP1 HAL — GPIO, SPI, I2C via PCIe BAR (Pi 5 only)
// ============================================================================
//
// The RP1 chip is a separate silicon die connected to BCM2712 via PCIe x4.
// GPU firmware configures PCIe and maps RP1 into the ARM's physical address space.
// With `pciex4_reset=0` in config.txt, these mappings survive kernel handoff.
//
// RP1 BAR base address (set by GPU firmware, confirmed via /proc/iomem on Linux):
//   0x1f_0000_0000 (typical, may vary)
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
    const RP1_BAR_BASE: usize = 0x1f_0000_d000;

    // RP1 GPIO bank0 registers (offset 0xd0000 from RP1 BAR)
    // But RP1_BAR_BASE already includes the offset to the peripheral aperture.
    // The actual layout from rp1-peripherals.pdf:
    //   GPIO bank0 base = RP1 BAR + 0x0_d0000
    // The BAR itself is at 0x1f_0000_0000, so GPIO is at 0x1f_000d_0000.

    /// RP1 peripheral base (start of RP1 address space on PCIe BAR)
    const RP1_PERI_BASE: usize = 0x1f_0000_0000;

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

/// Read the physical counter (CNTPCT_EL0) for cycle-accurate timing.
fn read_timer_count() -> u32 {
    let val: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) val) };
    val as u32
}

unsafe fn timer_set(ticks: u32) {
    core::arch::asm!(
        "msr cntp_tval_el0, {val}",
        "mov {ctl}, #1",
        "msr cntp_ctl_el0, {ctl}",
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
    "1: wfe",
    "b 1b",
);

#[no_mangle]
unsafe extern "C" fn exception_dump(elr: u64, esr: u64, far: u64) {
    uart_puts(b"\r\n!!! EXCEPTION\r\n");
    uart_puts(b"  ELR=0x"); uart_put_hex64(elr);
    uart_puts(b"\r\n  ESR=0x"); uart_put_hex64(esr);
    uart_puts(b"\r\n  FAR=0x"); uart_put_hex64(far);
    uart_puts(b"\r\n");
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

/// Read the current core's MPIDR Aff0 field (core number 0-3).
#[inline(always)]
fn current_core_id() -> u8 {
    let mpidr: u64;
    unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nomem, nostack)); }
    (mpidr & 0xFF) as u8
}

#[no_mangle]
unsafe extern "C" fn irq_handler() {
    let iar = core::ptr::read_volatile(GICC_IAR);
    let int_id = iar & 0x3FF;
    if int_id == TIMER_PPI {
        timer_set(TICKS_PER_TICK);
        let core_id = current_core_id() as usize;
        if core_id == 0 {
            scheduler::DBG_TICK += 1;
        }
        if core_id < 4 {
            CORE_TICKS[core_id].fetch_add(1, Ordering::Relaxed);
        }
    }
    core::ptr::write_volatile(GICC_EOIR, iar);
}

// ============================================================================
// Multi-domain module storage (E6)
// ============================================================================

/// Maximum modules per domain on this platform.
const MAX_MODS_PER_DOMAIN: usize = 8;

/// Module storage for each domain. Domain 0 is on core 0, domain 1 on core 1, etc.
/// Each domain's modules array is only accessed by its owning core after init.
struct DomainModules {
    modules: [Option<loader::DynamicModule>; MAX_MODS_PER_DOMAIN],
    count: usize,
    /// Local channel handles per module: input, output, ctrl.
    /// Used for cross-domain channel pumping.
    mod_in: [i32; MAX_MODS_PER_DOMAIN],
    mod_out: [i32; MAX_MODS_PER_DOMAIN],
}

impl DomainModules {
    const fn new() -> Self {
        Self {
            modules: [const { None }; MAX_MODS_PER_DOMAIN],
            count: 0,
            mod_in: [-1; MAX_MODS_PER_DOMAIN],
            mod_out: [-1; MAX_MODS_PER_DOMAIN],
        }
    }
}

/// Per-domain module storage. Indexed by domain_id.
/// SAFETY: After init, each domain's storage is only accessed by its owning core.
static mut DOMAIN_MODULES: [DomainModules; cross_domain::MAX_DOMAINS] =
    [const { DomainModules::new() }; cross_domain::MAX_DOMAINS];

/// Signal that domain module storage has been initialized and secondary cores can start.
static INIT_COMPLETE: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// E3-S7: Entry point with secondary core parking
// ============================================================================
//
// Pi 5 GPU firmware boots all 4 Cortex-A76 cores. The _start code checks
// MPIDR_EL1.Aff0 to identify the core. Core 0 proceeds to main, cores 1-3
// park in a WFE loop.
//
// On QEMU virt with -smp 1 (default), MPIDR_EL1.Aff0 = 0, so the check
// is harmless. With -smp 4, secondary cores will park correctly.

global_asm!(
    ".section .text._start",
    ".global _start",
    ".type _start, @function",
    "_start:",
    // ---- E3-S7: Check core ID, park secondary cores ----
    "    mrs x0, mpidr_el1",
    "    and x0, x0, #0xFF",     // Aff0 = core ID
    "    cbnz x0, .Lpark_core",  // core != 0 → park

    // ---- Primary core (core 0) continues ----
    // Enable NEON/FP (CPACR_EL1.FPEN = 0b11)
    "    mov x0, #(3 << 20)",
    "    msr cpacr_el1, x0",
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
    "    ldr w7, [x2, #8]",      // destination base (__end_block_addr, aligned by pack-image)
    // Fast 8-byte copy loop (both src and dst are 256-byte aligned from pack-image)
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

    // Jump to Rust main
    "    bl main",

    // Should never return
    "2:  wfe",
    "    b 2b",

    // ---- Secondary core parking (E3-S7) ----
    ".Lpark_core:",
    "    wfe",
    "    b .Lpark_core",
);

// ============================================================================
// Main entry point
// ============================================================================

#[no_mangle]
pub extern "C" fn main() -> ! {
    // Initialize UART first (Pi 5 needs explicit PL011 setup)
    unsafe { uart_init() };

    #[cfg(feature = "board-cm5")]
    uart_puts(b"[fluxor] bcm2712 boot (Pi 5 / CM5)\r\n");
    #[cfg(not(feature = "board-cm5"))]
    uart_puts(b"[fluxor] bcm2712 boot (QEMU virt)\r\n");

    // E3-S2: MMU setup (identity-mapped page tables)
    unsafe {
        mmu::init_page_tables();
        mmu::enable();
    }

    #[cfg(feature = "board-cm5")]
    uart_puts(b"[mmu] enabled: DRAM cacheable, peripherals device\r\n");

    // E3-S4: Probe RP1 (Pi 5 only — checks PCIe BAR mapping)
    rp1::report(uart_puts, uart_put_hex32);

    static LOGGER: UartLogger = UartLogger;
    unsafe { log::set_logger_racy(&LOGGER).ok() };
    log::set_max_level(log::LevelFilter::Info);

    // Report timer frequency
    let freq = timer_freq();
    uart_puts(b"[timer] freq=");
    uart_put_u32(freq as u32);
    uart_puts(b" Hz\r\n");

    // Exception vectors + GIC + timer
    // Timer tick period will be recalculated after config is parsed (tick_us).
    // Start with 1ms default so the system runs during init.
    unsafe {
        core::arch::asm!("adr {tmp}, exception_vectors", "msr vbar_el1, {tmp}", tmp = out(reg) _);
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
    fluxor::kernel::step_guard::init();

    // --- Config-driven module graph ---
    use fluxor::kernel::channel;
    use fluxor::kernel::config::{self, MAX_MODULES};

    // Parse config from the layout trailer appended to kernel8.img
    let mut cfg = config::Config::empty();
    if !config::read_config_into(&mut cfg) {
        uart_puts(b"[config] parse failed\r\n");
        loop { unsafe { core::arch::asm!("wfi") }; }
    }
    let n_modules = cfg.module_count as usize;
    let n_edges = cfg.edge_count as usize;

    // Reconfigure timer tick from config tick_us (E4-S1)
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

    // Load module table from the layout trailer appended to kernel8.img
    loader::reset_state_arena();
    let mut ldr = loader::ModuleLoader::new();
    if ldr.init().is_err() {
        uart_puts(b"[loader] no modules\r\n");
        loop { unsafe { core::arch::asm!("wfi") }; }
    }

    // Create channels from graph edges.
    // Track per-global-module-index: input, output, ctrl channel handles.
    let mut mod_in: [i32; MAX_MODULES] = [-1; MAX_MODULES];
    let mut mod_out: [i32; MAX_MODULES] = [-1; MAX_MODULES];
    let mut mod_ctrl: [i32; MAX_MODULES] = [-1; MAX_MODULES];

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
                // and a CrossDomainChannel to bridge them.
                let out_ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
                let in_ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);

                if out_ch >= 0 && in_ch >= 0 {
                    if from < MAX_MODULES && mod_out[from] < 0 {
                        mod_out[from] = out_ch;
                    }
                    if to < MAX_MODULES {
                        if edge.to_port == 0 && mod_in[to] < 0 {
                            mod_in[to] = in_ch;
                        } else if edge.to_port == 1 && mod_ctrl[to] < 0 {
                            mod_ctrl[to] = in_ch;
                        }
                    }

                    // Allocate a cross-domain channel and register the edge
                    if let Some(cross_ch_idx) = cross_domain::alloc_cross_channel() {
                        // Compute per-domain module indices.
                        // We need to count how many modules with lower global index are
                        // in the same domain, to find the domain-local index.
                        let from_mod_in_domain = domain_local_index(&cfg, from, from_domain, n_modules);
                        let to_mod_in_domain = domain_local_index(&cfg, to, to_domain, n_modules);

                        unsafe {
                            cross_domain::register_cross_edge(cross_domain::CrossDomainEdge {
                                from_domain,
                                from_module: from_mod_in_domain as u8,
                                from_port: 0,
                                to_domain,
                                to_module: to_mod_in_domain as u8,
                                to_port: edge.to_port,
                                channel_idx: cross_ch_idx as u8,
                            });
                        }
                    }
                }
            } else {
                // Same-domain edge: single shared channel
                let ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
                if ch >= 0 {
                    if from < MAX_MODULES && mod_out[from] < 0 {
                        mod_out[from] = ch;
                    }
                    if to < MAX_MODULES {
                        if edge.to_port == 0 && mod_in[to] < 0 {
                            mod_in[to] = ch;
                        } else if edge.to_port == 1 && mod_ctrl[to] < 0 {
                            mod_ctrl[to] = ch;
                        }
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
            if domain_id >= cross_domain::MAX_DOMAINS {
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
                fluxor::kernel::scheduler::set_current_module(mod_idx);
                let result = unsafe {
                    loader::DynamicModule::start_new(
                        &m, syscalls,
                        mod_in[i], mod_out[i], mod_ctrl[i],
                        entry.params_ptr, entry.params_len, "",
                    )
                };
                match result {
                    Ok(loader::StartNewResult::Ready(dm)) => {
                        dm_ref.mod_in[mod_idx] = mod_in[i];
                        dm_ref.mod_out[mod_idx] = mod_out[i];
                        dm_ref.modules[mod_idx] = Some(dm);
                        dm_ref.count += 1;
                    }
                    Ok(loader::StartNewResult::Pending(mut pending)) => {
                        for _ in 0..100 {
                            for _ in 0..10000 { unsafe { core::arch::asm!("nop") }; }
                            match unsafe { pending.try_complete() } {
                                Ok(Some(dm)) => {
                                    dm_ref.mod_in[mod_idx] = mod_in[i];
                                    dm_ref.mod_out[mod_idx] = mod_out[i];
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

    // Set up domain execution state for all domains that have modules.
    let mut d = 0usize;
    while d < cross_domain::MAX_DOMAINS {
        let mod_count = unsafe { DOMAIN_MODULES[d].count };
        if mod_count > 0 {
            unsafe {
                let ds = cross_domain::domain_state(d);
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
        while dd < cross_domain::MAX_DOMAINS {
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
    uart_put_u32(cross_domain::cross_edge_count() as u32);
    uart_puts(b" dma_arena_used=");
    uart_put_u32(cross_domain::dma_arena_used() as u32);
    uart_puts(b"\r\n");

    // Wake secondary cores that have non-empty domains assigned
    wake_secondary_cores();

    uart_puts(b"[sched] starting domain 0 on core 0\r\n");

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

// ============================================================================
// Domain execution loop (E6)
// ============================================================================

/// Run the main loop for a domain. Steps all modules assigned to that domain.
///
/// This function never returns. On core 0 it is called directly from main().
/// On secondary cores it is called from the secondary_core_main() entry point.
/// Per-domain metrics (E7b-S3).
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

static mut DOMAIN_METRICS: [DomainMetrics; cross_domain::MAX_DOMAINS] =
    [const { DomainMetrics::new() }; cross_domain::MAX_DOMAINS];

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
                let t0 = read_timer_count();
                domain_step_all(domain_id);
                pump_cross_domain(domain_id);
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
            loop {
                let dm = unsafe { &mut DOMAIN_MODULES[domain_id] };
                let mut any_burst = false;
                let mut j = 0;
                while j < dm.count {
                    if let Some(ref mut m) = dm.modules[j] {
                        step_guard::arm(step_guard::DEFAULT_STEP_DEADLINE_US);
                        let outcome = m.step();
                        step_guard::disarm();
                        step_guard::post_step_check();
                        if step_guard::check_and_clear_timeout() {
                            log::warn!("[guard] domain {} module {} timeout", domain_id, j);
                        }
                        // StepOutcome::Burst
                        if matches!(outcome, Ok(fluxor::modules::StepOutcome::Burst)) {
                            any_burst = true;
                        }
                    }
                    j += 1;
                }
                pump_cross_domain(domain_id);

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
                let tick = CORE_TICKS[core_id].load(Ordering::Relaxed);
                domain_step_all(domain_id);
                pump_cross_domain(domain_id);
                let metrics = unsafe { &mut DOMAIN_METRICS[domain_id] };
                metrics.tick_count += 1;
                if domain_id == 0 && tick % 10000 == 0 && tick > 0 {
                    log::info!("[sched] alive t={} core={}", tick, core_id);
                }
            }
        }
    }
}

/// Step all modules in a domain with step guard protection.
fn domain_step_all(domain_id: usize) {
    use fluxor::modules::Module;
    use fluxor::kernel::step_guard;

    let dm = unsafe { &mut DOMAIN_MODULES[domain_id] };
    let mut j = 0;
    while j < dm.count {
        if let Some(ref mut m) = dm.modules[j] {
            step_guard::arm(step_guard::DEFAULT_STEP_DEADLINE_US);
            let _ = m.step();
            step_guard::disarm();
            step_guard::post_step_check();
            if step_guard::check_and_clear_timeout() {
                log::warn!("[guard] domain {} module {} timeout", domain_id, j);
            }
        }
        j += 1;
    }
}

/// Pump cross-domain channels for a domain.
fn pump_cross_domain(domain_id: usize) {
    let n_cross = cross_domain::cross_edge_count();
    let mut ei = 0;
    while ei < n_cross {
        if let Some(edge) = cross_domain::get_cross_edge(ei) {
            if let Some(ch) = cross_domain::get_cross_channel(edge.channel_idx as usize) {
                if edge.from_domain == domain_id as u8 {
                    let mod_local = edge.from_module as usize;
                    let dm_src = unsafe { &DOMAIN_MODULES[domain_id] };
                    if mod_local < dm_src.count {
                        let out_handle = dm_src.mod_out[mod_local];
                        if out_handle >= 0 {
                            let mut buf = [0u8; cross_domain::CHANNEL_DATA_SIZE];
                            let n = unsafe {
                                fluxor::kernel::channel::channel_read(
                                    out_handle, buf.as_mut_ptr(), buf.len(),
                                )
                            };
                            if n > 0 {
                                let _ = ch.send(&buf[..n as usize]);
                            }
                        }
                    }
                }
                if edge.to_domain == domain_id as u8 {
                    let mod_local = edge.to_module as usize;
                    let dm_dst = unsafe { &DOMAIN_MODULES[domain_id] };
                    if mod_local < dm_dst.count {
                        let in_handle = dm_dst.mod_in[mod_local];
                        if in_handle >= 0 {
                            let mut buf = [0u8; cross_domain::CHANNEL_DATA_SIZE];
                            if let Some(len) = ch.try_recv(&mut buf) {
                                unsafe {
                                    fluxor::kernel::channel::channel_write(
                                        in_handle, buf.as_ptr(), len,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        ei += 1;
    }
}

// ============================================================================
// Secondary core entry points (E6)
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
    let ds = cross_domain::domain_state_ref(domain_id);
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
        let ds = cross_domain::domain_state_ref(domain_id);
        if ds.active && ds.module_count > 0 {
            uart_puts(b"[wake] core ");
            uart_put_u32(core_id as u32);
            uart_puts(b" for domain ");
            uart_put_u32(domain_id as u32);
            uart_puts(b"\r\n");

            let entry = entries[(core_id - 1) as usize];
            if !cross_domain::wake_core(core_id, entry) {
                uart_puts(b"[wake] FAILED core ");
                uart_put_u32(core_id as u32);
                uart_puts(b"\r\n");
            }
        }
    }
}

// ============================================================================
// log crate backend
// ============================================================================

struct UartLogger;

impl log::Log for UartLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool { true }
    fn log(&self, record: &log::Record) {
        use core::fmt::Write;
        struct UartWriter;
        impl Write for UartWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                for b in s.bytes() { uart_putc(b); }
                Ok(())
            }
        }
        let _ = core::fmt::write(&mut UartWriter, *record.args());
        uart_puts(b"\r\n");
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
fn bcm_verify_integrity(_computed: &[u8], _expected: &[u8]) -> bool { true }

fn bcm_pic_barrier() {
    unsafe { core::arch::asm!("dsb sy", "isb") };
}

// Step guard: software elapsed-time check
static mut BCM_ARM_TIME: u64 = 0;
static mut BCM_DEADLINE_TICKS: u64 = 0;

fn bcm_read_cntpct() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) val) };
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
    use fluxor::abi::dev_system;
    match opcode {
        dev_system::MMIO_READ32 => {
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
        dev_system::MMIO_WRITE32 => {
            if arg.is_null() || arg_len < 12 { return -22; }
            let addr = u64::from_le_bytes([
                *arg, *arg.add(1), *arg.add(2), *arg.add(3),
                *arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7),
            ]);
            let val = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            core::ptr::write_volatile(addr as *mut u32, val);
            0
        }
        dev_system::DMA_ALLOC_CONTIG => {
            if arg.is_null() || arg_len < 16 { return -22; }
            let size = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let align = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            let phys = fluxor::kernel::nic_ring::dma_alloc_contig(size as usize, align as usize);
            if phys == 0 { return -38; }
            let pb = (phys as u64).to_le_bytes();
            core::ptr::copy_nonoverlapping(pb.as_ptr(), arg.add(8), 8);
            0
        }
        dev_system::NIC_BAR_MAP => {
            fluxor::kernel::pcie::syscall_bar_map(arg, arg_len)
        }
        dev_system::NIC_BAR_UNMAP => {
            fluxor::kernel::pcie::syscall_bar_unmap(arg, arg_len)
        }
        dev_system::NIC_RING_CREATE => {
            fluxor::kernel::nic_ring::syscall_ring_create(arg, arg_len)
        }
        dev_system::NIC_RING_DESTROY => {
            fluxor::kernel::nic_ring::syscall_ring_destroy(arg, arg_len)
        }
        dev_system::NIC_RING_INFO => {
            fluxor::kernel::nic_ring::syscall_ring_info(_handle, arg, arg_len)
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
};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    uart_puts(b"[fluxor] PANIC on core ");
    uart_put_u32(current_core_id() as u32);
    uart_puts(b"\r\n");
    loop { unsafe { core::arch::asm!("wfi") }; }
}
