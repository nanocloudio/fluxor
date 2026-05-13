//! RP1 HAL — GPIO, SPI, I2C via PCIe BAR (Pi 5 only).
//!
//! The RP1 chip is a separate silicon die connected to BCM2712 via PCIe x4.
//! GPU firmware configures PCIe and maps RP1 into the ARM's physical address
//! space. With `pciex4_reset=0` in config.txt, these mappings survive kernel
//! handoff.
//!
//! RP1 BAR base address (set by GPU firmware, confirmed via /proc/iomem on
//! Linux): 0x1c_0000_0000 (typical, may vary).
//!
//! RP1 peripheral offsets from BAR base:
//!   GPIO bank0: BAR + 0xd0000
//!   SPI0:       BAR + 0x50000
//!   I2C0:       BAR + 0x70000
//!   I2C1:       BAR + 0x74000
//!
//! On non-`board-cm5` configs (QEMU virt) every entry point degrades to a
//! no-op stub so the same code calls compile.

#![allow(dead_code)]

#[cfg(feature = "board-cm5")]
mod cm5_impl {
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
    const RIO_OUT: usize = 0x00; // Output value
    const RIO_OE: usize = 0x04; // Output enable
    const RIO_IN: usize = 0x08; // Input value
    // Atomic set/clr/xor at +0x2000/+0x3000/+0x1000

    const RIO_SET_OFFSET: usize = 0x2000;
    const RIO_CLR_OFFSET: usize = 0x3000;
    const RIO_XOR_OFFSET: usize = 0x1000;

    // FUNCSEL values for GPIO_CTRL
    const FUNCSEL_SYS_RIO: u32 = 5; // Connect GPIO to SYS_RIO (software-controlled)
    const FUNCSEL_NULL: u32 = 31; // Disconnect (high-Z)

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
        if pin > 27 {
            return;
        }
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
        if pin > 27 {
            return;
        }
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
        if pin > 27 {
            return;
        }
        unsafe {
            let out_set = (RP1_SYS_RIO0_BASE + RIO_OUT + RIO_SET_OFFSET) as *mut u32;
            core::ptr::write_volatile(out_set, 1u32 << pin);
        }
    }

    /// Set GPIO pin output low.
    pub fn gpio_set_low(pin: u8) {
        if pin > 27 {
            return;
        }
        unsafe {
            let out_clr = (RP1_SYS_RIO0_BASE + RIO_OUT + RIO_CLR_OFFSET) as *mut u32;
            core::ptr::write_volatile(out_clr, 1u32 << pin);
        }
    }

    /// Toggle GPIO pin output.
    pub fn gpio_toggle(pin: u8) {
        if pin > 27 {
            return;
        }
        unsafe {
            let out_xor = (RP1_SYS_RIO0_BASE + RIO_OUT + RIO_XOR_OFFSET) as *mut u32;
            core::ptr::write_volatile(out_xor, 1u32 << pin);
        }
    }

    /// Read a single GPIO pin input state.
    pub fn gpio_read(pin: u8) -> bool {
        if pin > 27 {
            return false;
        }
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

// Stub for non-board-cm5 (QEMU virt — no PCIe).
#[cfg(not(feature = "board-cm5"))]
mod cm5_impl {
    pub fn probe() -> bool {
        false
    }
    pub fn report(_uart_puts_fn: fn(&[u8]), _uart_put_hex32_fn: fn(u32)) {}
}

pub use cm5_impl::*;
