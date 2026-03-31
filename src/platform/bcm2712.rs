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
//
// Fully config-driven: YAML -> config.bin + modules.bin embedded at compile time.

use core::panic::PanicInfo;
use core::arch::global_asm;

use fluxor::kernel::scheduler;
use fluxor::kernel::loader;

// Embedded module table + config — built by `make vm` or `make cm5`
#[repr(C, align(4096))]
struct PageAligned([u8; include_bytes!("../../target/bcm2712/modules.bin").len()]);
static MODULE_BLOB: PageAligned = PageAligned(*include_bytes!("../../target/bcm2712/modules.bin"));
static MODULE_TABLE: &[u8] = &MODULE_BLOB.0;

#[repr(C, align(4))]
struct ConfigAligned([u8; include_bytes!("../../target/bcm2712/config.bin").len()]);
static CONFIG_BLOB: ConfigAligned = ConfigAligned(*include_bytes!("../../target/bcm2712/config.bin"));
static CONFIG_DATA: &[u8] = &CONFIG_BLOB.0;

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

// ============================================================================
// ARM Generic Timer
// ============================================================================

fn timer_freq() -> u64 {
    let freq: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq) };
    freq
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

static mut TICKS_PER_MS: u32 = 0;

#[no_mangle]
unsafe extern "C" fn irq_handler() {
    let iar = core::ptr::read_volatile(GICC_IAR);
    let int_id = iar & 0x3FF;
    if int_id == TIMER_PPI {
        timer_set(TICKS_PER_MS);
        scheduler::DBG_TICK += 1;
    }
    core::ptr::write_volatile(GICC_EOIR, iar);
}

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

    // Zero BSS
    "    adr x0, __bss_start",
    "    adr x1, __bss_end",
    "0:  cmp x0, x1",
    "    b.ge 1f",
    "    str xzr, [x0], #8",
    "    b 0b",
    "1:",

    // Set up stack
    "    ldr x30, =__stack_end",
    "    mov sp, x30",

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
    unsafe {
        core::arch::asm!("adr {tmp}, exception_vectors", "msr vbar_el1, {tmp}", tmp = out(reg) _);
        gic_init();
        TICKS_PER_MS = if freq > 0 { (freq / 1000) as u32 } else { 62500 };
        timer_set(TICKS_PER_MS);
        core::arch::asm!("msr daifclr, #2"); // enable IRQs
    }

    uart_puts(b"[gic] initialized, IRQs enabled\r\n");

    // Initialize syscall table and provider registry
    fluxor::kernel::syscalls::init_syscall_table();
    fluxor::kernel::syscalls::init_providers();
    fluxor::kernel::step_guard::init();

    // --- Config-driven module graph ---
    use fluxor::kernel::channel;
    use fluxor::kernel::config::{self, MAX_MODULES};

    // Parse config
    let mut cfg = config::Config::empty();
    if !config::read_config_from_ptr(CONFIG_DATA.as_ptr(), &mut cfg) {
        uart_puts(b"[config] parse failed\r\n");
        loop { unsafe { core::arch::asm!("wfi") }; }
    }
    let n_modules = cfg.module_count as usize;
    let n_edges = cfg.edge_count as usize;
    uart_puts(b"[config] ");
    uart_put_u32(n_modules as u32);
    uart_puts(b" modules, ");
    uart_put_u32(n_edges as u32);
    uart_puts(b" edges\r\n");

    // Load module table
    loader::reset_state_arena();
    let mut ldr = loader::ModuleLoader::new();
    if ldr.init_from_blob(MODULE_TABLE.as_ptr()).is_err() {
        uart_puts(b"[loader] no modules\r\n");
        loop { unsafe { core::arch::asm!("wfi") }; }
    }

    // Create channels from graph edges
    let mut mod_in: [i32; MAX_MODULES] = [-1; MAX_MODULES];
    let mut mod_out: [i32; MAX_MODULES] = [-1; MAX_MODULES];
    let mut mod_ctrl: [i32; MAX_MODULES] = [-1; MAX_MODULES];

    let mut e = 0usize;
    while e < n_edges {
        if let Some(ref edge) = cfg.graph_edges[e] {
            let ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
            if ch >= 0 {
                let from = edge.from_id as usize;
                let to = edge.to_id as usize;
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
        e += 1;
    }

    // Mask IRQs during module instantiation
    let _inst_guard = fluxor::kernel::guard::KernelGuard::acquire();

    let syscalls = fluxor::kernel::syscalls::get_table_for_module_type(0);

    const MAX_MODS: usize = 8;
    let mut modules: [Option<loader::DynamicModule>; MAX_MODS] = [const { None }; MAX_MODS];
    let mut mod_count = 0usize;

    let mut i = 0usize;
    while i < n_modules && i < MAX_MODS {
        if let Some(ref entry) = cfg.modules[i] {
            if let Ok(m) = ldr.find_by_name_hash(entry.name_hash) {
                fluxor::kernel::scheduler::set_current_module(mod_count);
                let result = unsafe {
                    loader::DynamicModule::start_new(
                        &m, syscalls,
                        mod_in[i], mod_out[i], mod_ctrl[i],
                        entry.params_ptr, entry.params_len, "",
                    )
                };
                match result {
                    Ok(loader::StartNewResult::Ready(dm)) => {
                        modules[mod_count] = Some(dm);
                        mod_count += 1;
                    }
                    Ok(loader::StartNewResult::Pending(mut pending)) => {
                        for _ in 0..100 {
                            for _ in 0..10000 { unsafe { core::arch::asm!("nop") }; }
                            match unsafe { pending.try_complete() } {
                                Ok(Some(dm)) => {
                                    modules[mod_count] = Some(dm);
                                    mod_count += 1;
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

    // Re-enable IRQs
    drop(_inst_guard);

    uart_puts(b"[inst] ");
    uart_put_u32(mod_count as u32);
    uart_puts(b" modules loaded\r\n");

    uart_puts(b"[sched] starting\r\n");

    // Main loop — step all modules with step guard
    use fluxor::modules::Module;
    use fluxor::kernel::step_guard;
    loop {
        unsafe { core::arch::asm!("wfi") };
        unsafe { scheduler::DBG_TICK += 1; }
        let tick = unsafe { scheduler::DBG_TICK };

        let mut j = 0;
        while j < mod_count {
            if let Some(ref mut m) = modules[j] {
                step_guard::arm(step_guard::DEFAULT_STEP_DEADLINE_US);
                let _ = m.step();
                step_guard::disarm();
                step_guard::post_step_check();
                if step_guard::check_and_clear_timeout() {
                    log::warn!("[guard] module {} timeout", j);
                }
            }
            j += 1;
        }

        if tick % 10000 == 0 {
            log::info!("[sched] alive t={}", tick);
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    uart_puts(b"[fluxor] PANIC\r\n");
    loop { unsafe { core::arch::asm!("wfi") }; }
}
