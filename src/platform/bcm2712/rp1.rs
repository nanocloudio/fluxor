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

#![allow(dead_code, reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it")]

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
        // SAFETY: RP1_GPIO_BASE is a fixed MMIO register mapped by
        // boot_mmu::init_page_tables; an unmapped PCIe BAR returns 0xFFFFFFFF.
        let val = unsafe { core::ptr::read_volatile(RP1_GPIO_BASE as *const u32) };
        // If PCIe is not mapped, reads return 0xFFFFFFFF (bus error → all-ones)
        val != 0xFFFF_FFFF
    }

    /// Read the raw value of RP1 SYS_RIO0 input register.
    /// Returns the GPIO pin states as a bitmask.
    pub fn gpio_read_all() -> u32 {
        // SAFETY: RIO_IN is a fixed MMIO register; read is side-effect free.
        unsafe { core::ptr::read_volatile((RP1_SYS_RIO0_BASE + RIO_IN) as *const u32) }
    }

    /// Set a GPIO pin as output via RP1 SYS_RIO.
    /// Sets FUNCSEL to SYS_RIO and enables output.
    pub fn gpio_set_output(pin: u8) {
        if pin > 27 {
            return;
        }
        // SAFETY: GPIO_CTRL and RIO_OE registers are fixed MMIO; `pin` is
        // range-checked against the 28-pin bank above.
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
        // SAFETY: GPIO_CTRL and RIO_OE registers are fixed MMIO; `pin` is
        // range-checked above.
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
        // SAFETY: RIO_OUT set register is fixed MMIO; `pin` is range-checked.
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
        // SAFETY: RIO_OUT clear register is fixed MMIO; `pin` is range-checked.
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
        // SAFETY: RIO_OUT XOR register is fixed MMIO; `pin` is range-checked.
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
        // SAFETY: SPI register block at known MMIO base mapped by boot_mmu.
        unsafe { core::ptr::write_volatile(addr as *mut u32, value) };
    }

    /// Read a 32-bit value from an RP1 SPI register.
    pub fn spi_reg_read(spi_idx: u8, offset: u16) -> u32 {
        let addr = spi_base(spi_idx) + offset as usize;
        // SAFETY: SPI register block at known MMIO base mapped by boot_mmu.
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
        // SAFETY: I2C register block at known MMIO base mapped by boot_mmu.
        unsafe { core::ptr::write_volatile(addr as *mut u32, value) };
    }

    /// Read a 32-bit value from an RP1 I2C register.
    pub fn i2c_reg_read(i2c_idx: u8, offset: u16) -> u32 {
        let addr = i2c_base(i2c_idx) + offset as usize;
        // SAFETY: I2C register block at known MMIO base mapped by boot_mmu.
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    // ==========================================================================
    // RP1 PWM — active-cooler ("pwm-fan") force-on
    // ==========================================================================
    //
    // The Pi 5 / CM5 active cooler is driven by the RP1 `raspberrypi,rp1-pwm`
    // block (offset 0x9c000 within the RP1 peripheral aperture) on channel 3,
    // routed to gpio45 (function "pwm1" = ALT0). The fan PWM runs from a 50 MHz
    // clock with a ~41.5 µs (24 kHz) period and INVERTED polarity (matching the
    // stock device-tree `pwm-fan` node), so a *higher* DUTY value yields *more*
    // low-time and therefore a *faster* fan.
    //
    // Register layout (verified against the rpi-6.12.y `pwm-rp1.c` driver and
    // read back from a running Pi 5):
    //   GLOBAL_CTRL @ 0x000 : per-channel enable = BIT(ch); SET_UPDATE = BIT(31)
    //   CHANNEL_CTRL(ch) @ 0x014 + ch*0x10 : mode/FIFO_POP + POLARITY = BIT(3)
    //   RANGE(ch)        @ 0x018 + ch*0x10 : period, in 20 ns clock cycles
    //   DUTY(ch)         @ 0x020 + ch*0x10 : compare point, in clock cycles
    //
    // Empirical max-speed point on a Pi 5 cooler: RANGE=0x81E(2078),
    // CHANNEL_CTRL=0x109, DUTY=0x7F6(2038) → ~8971 RPM. We program exactly that.
    // This assumes the boot firmware (which drives the fan before kernel handoff)
    // has left the PWM function clock running; `fan_report()` reads the registers
    // back so the rig can confirm the writes stuck.

    const RP1_PWM_BASE: usize = RP1_PERI_BASE + 0x9_c000;

    const PWM_GLOBAL_CTRL: usize = 0x000;
    const PWM_SET_UPDATE: u32 = 1 << 31;
    /// FIFO_POP_MASK (bit 8) + trailing-edge mark-space mode (bit 0) — the
    /// fixed-duty mode the Linux driver uses.
    const PWM_CHANNEL_DEFAULT: u32 = (1 << 8) | (1 << 0);
    const PWM_POLARITY: u32 = 1 << 3;

    /// Fan tachometer / RPM register within the RP1 PWM block. The stock
    /// device-tree `pwm-fan` node reads RPM from `rpm-offset = 0x3c`; verified
    /// on silicon (reads decimal RPM, matching the Linux `fan1_input` hwmon).
    /// Nonzero here is direct proof the fan is physically spinning.
    const PWM_FAN_RPM: usize = 0x03c;

    const fn pwm_chan_ctrl(ch: usize) -> usize {
        0x014 + ch * 0x10
    }
    const fn pwm_chan_range(ch: usize) -> usize {
        0x018 + ch * 0x10
    }
    const fn pwm_chan_duty(ch: usize) -> usize {
        0x020 + ch * 0x10
    }

    /// Fan PWM channel (Pi 5 / CM5 active cooler).
    const FAN_PWM_CHANNEL: usize = 3;
    /// Period in 20 ns clock cycles (≈41.5 µs / 24 kHz).
    const FAN_PWM_RANGE: u32 = 2078;
    /// ~98 % duty — the empirically-confirmed max-speed point. Higher DUTY =
    /// faster fan under inverted polarity; 2038 is proven (≈8971 RPM) and keeps
    /// a small margin off the DUTY==RANGE edge.
    const FAN_PWM_DUTY_FULL: u32 = 2038;

    // gpio45 routing — RP1 GPIO bank2 (gpio34..53). Bank stride is +0x4000:
    // bank0 IO @ 0xd0000 / pads @ 0xf0000, bank2 IO @ 0xd8000 / pads @ 0xf8000.
    const RP1_GPIO2_BASE: usize = RP1_PERI_BASE + 0xd_8000;
    const RP1_PADS2_BASE: usize = RP1_PERI_BASE + 0xf_8000;
    const FAN_GPIO_BANK2_LOCAL: usize = 45 - 34; // local index 11
    /// ALT0 selects function "pwm1" on gpio45.
    const FAN_FUNCSEL_PWM1: u32 = 0;
    const FUNCSEL_MASK_PWM: u32 = 0x1f;
    /// Pad: pull-down (bit2) + 8 mA drive (bits5:4=0b10) + input-enable (bit6);
    /// output-disable (bit7) left clear. Mirrors the stock pad config.
    const FAN_PAD_VALUE: u32 = (1 << 2) | (0b10 << 4) | (1 << 6);

    #[inline]
    unsafe fn pwm_write(off: usize, val: u32) {
        // SAFETY: caller guarantees `off` is a valid RP1 PWM register offset;
        // RP1_PWM_BASE is fixed MMIO mapped by boot_mmu.
        unsafe { core::ptr::write_volatile((RP1_PWM_BASE + off) as *mut u32, val) };
    }
    #[inline]
    unsafe fn pwm_read(off: usize) -> u32 {
        // SAFETY: side-effect-free MMIO read of a fixed RP1 PWM register.
        unsafe { core::ptr::read_volatile((RP1_PWM_BASE + off) as *const u32) }
    }

    /// Route gpio45 to the RP1 PWM1 function and configure its pad as a
    /// peripheral output. Defensive: the boot firmware that drives the fan
    /// usually already did this, so this re-asserts known-good values.
    unsafe fn fan_pin_configure() {
        // GPIO ctrl reg: 8 bytes per pin, ctrl word @ +4. Preserve the upper
        // ctrl bits, set only the FUNCSEL field.
        let ctrl_addr = (RP1_GPIO2_BASE + FAN_GPIO_BANK2_LOCAL * 8 + 0x04) as *mut u32;
        // SAFETY: bank2 GPIO ctrl register is fixed MMIO within the RP1 BAR.
        unsafe {
            let cur = core::ptr::read_volatile(ctrl_addr);
            core::ptr::write_volatile(ctrl_addr, (cur & !FUNCSEL_MASK_PWM) | FAN_FUNCSEL_PWM1);
        }
        // Pad block: a voltage-select word sits at +0x00, then one pad word per
        // pin starting at +0x04.
        let pad_addr = (RP1_PADS2_BASE + 0x04 + FAN_GPIO_BANK2_LOCAL * 4) as *mut u32;
        // SAFETY: bank2 pad register is fixed MMIO within the RP1 BAR.
        unsafe { core::ptr::write_volatile(pad_addr, FAN_PAD_VALUE) };
    }

    /// Force the active cooler to (near-)maximum speed. Reprograms the RP1 PWM
    /// channel the boot firmware uses for the fan so sustained-load rig runs are
    /// not confounded by thermal throttling.
    pub fn fan_full() {
        // SAFETY: RP1 PWM + GPIO bank2 + pads are fixed MMIO mapped by boot_mmu
        // (RP1 BAR @ 0x1c..). Runs once on the single boot thread.
        unsafe {
            fan_pin_configure();
            // Mode + inverted polarity (matches the stock pwm-fan node).
            pwm_write(pwm_chan_ctrl(FAN_PWM_CHANNEL), PWM_CHANNEL_DEFAULT | PWM_POLARITY);
            pwm_write(pwm_chan_range(FAN_PWM_CHANNEL), FAN_PWM_RANGE);
            pwm_write(pwm_chan_duty(FAN_PWM_CHANNEL), FAN_PWM_DUTY_FULL);
            // Enable channel 3 and latch the new configuration (SET_UPDATE
            // self-clears after the latch).
            let g = pwm_read(PWM_GLOBAL_CTRL);
            pwm_write(
                PWM_GLOBAL_CTRL,
                g | (1u32 << FAN_PWM_CHANNEL) | PWM_SET_UPDATE,
            );
        }
    }

    /// Read the fan PWM registers back for telemetry. If the writes stuck the
    /// block is clocked and accessible; logged via `log` so it reaches the UDP
    /// telemetry stream once networking is up (UART is dead on the bench).
    pub fn fan_report() {
        // SAFETY: side-effect-free MMIO reads of the RP1 PWM block.
        unsafe {
            let g = pwm_read(PWM_GLOBAL_CTRL);
            let c = pwm_read(pwm_chan_ctrl(FAN_PWM_CHANNEL));
            let r = pwm_read(pwm_chan_range(FAN_PWM_CHANNEL));
            let d = pwm_read(pwm_chan_duty(FAN_PWM_CHANNEL));
            let rpm = pwm_read(PWM_FAN_RPM);
            log::info!(
                "[fan] rp1 pwm ch{FAN_PWM_CHANNEL} GLOBAL={g:#010x} CTRL={c:#06x} RANGE={r} DUTY={d} rpm={rpm}"
            );
        }
    }

    /// Bring the active cooler to full and report the resulting register state.
    pub fn cooling_full_on() {
        fan_full();
        fan_report();
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
    pub fn cooling_full_on() {}
    pub fn fan_report() {}
}

pub use cm5_impl::*;
