// RP-family hardware providers for the syscall system.
//
// This file is `include!`d from `src/kernel/syscalls.rs` under `#[cfg(feature = "rp")]`.
// All symbols share the `syscalls` module namespace — they can reference E_NOSYS,
// channel::*, gpio::*, etc. directly.
//
// SPI, I2C, UART, and ADC providers live in PIC modules; the loader
// auto-registers them after module_new() via the
// `module_provides_contract` export. The raw register bridges they
// call into remain in `rp_system_extension_dispatch` below.

use crate::kernel::pio_util;

/// Check if a GPIO pin has been claimed
pub fn is_gpio_registered(pin_num: u8) -> bool {
    gpio::gpio_is_claimed(pin_num)
}

/// Convenience syscall: claim + configure as output
/// Returns handle on success, <0 on error
pub unsafe extern "C" fn syscall_gpio_request_output(pin_num: u8) -> i32 {
    let handle = gpio::gpio_claim(pin_num);
    if handle < 0 {
        log::error!("[gpio] request_output pin {} claim failed rc={}", pin_num, handle);
        return handle;
    }
    gpio::gpio_set_owner(pin_num, crate::kernel::scheduler::current_module_index() as u8);
    let result = gpio::gpio_set_mode(handle, gpio::PinMode::Output, true);
    if result < 0 {
        log::error!("[gpio] request_output pin {} set_mode failed rc={}", pin_num, result);
        gpio::gpio_release(handle);
        return result;
    }
    handle
}

/// Virtual handle for the board user button (BOOTSEL on Pico).
/// Outside the normal GPIO handle range (0..31).
const USER_BUTTON_HANDLE: i32 = 0xFF;

/// Convenience syscall: claim + configure as input with pull
/// pull: 0=none, 1=up, 2=down
/// Pin 0xFF = board user button (BOOTSEL on Pico)
/// Returns handle on success, <0 on error
pub unsafe extern "C" fn syscall_gpio_request_input(pin_num: u8, pull: u8) -> i32 {
    if pin_num == 0xFF {
        // Board user button — return virtual handle
        return USER_BUTTON_HANDLE;
    }
    let handle = gpio::gpio_claim(pin_num);
    if handle < 0 {
        return handle;
    }
    gpio::gpio_set_owner(pin_num, crate::kernel::scheduler::current_module_index() as u8);
    // Set pull configuration
    let pin_pull = match pull {
        1 => gpio::PinPull::Up,
        2 => gpio::PinPull::Down,
        _ => gpio::PinPull::None,
    };
    gpio::gpio_set_pull(handle, pin_pull);
    // Configure as input
    let result = gpio::gpio_set_mode(handle, gpio::PinMode::Input, false);
    if result < 0 {
        gpio::gpio_release(handle);
        return result;
    }
    handle
}

/// GPIO get level wrapper — handles virtual user button handle
unsafe extern "C" fn syscall_gpio_get_level(handle: i32) -> i32 {
    if handle == USER_BUTTON_HANDLE {
        return crate::kernel::resource::flash_sideband_read_cs();
    }
    if !gpio::gpio_check_owner(handle) {
        return E_INVAL;
    }
    gpio::gpio_get_level(handle)
}

// ============================================================================
// Per-class provider dispatchers (RP-specific)
// ============================================================================

unsafe fn gpio_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::contracts::hal::gpio as dev_gpio;
    match opcode {
        dev_gpio::CLAIM => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let result = gpio::syscall_gpio_claim(*arg);
            if result >= 0 {
                gpio::gpio_set_owner(*arg, crate::kernel::scheduler::current_module_index() as u8);
            }
            result
        }
        dev_gpio::SET_OUTPUT => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            syscall_gpio_request_output(*arg)
        }
        dev_gpio::SET_INPUT => {
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            syscall_gpio_request_input(*arg, *arg.add(1))
        }
        dev_gpio::RELEASE => {
            if !gpio::gpio_check_owner(handle) { return E_INVAL; }
            gpio::syscall_gpio_release(handle)
        }
        dev_gpio::SET_MODE => {
            if !gpio::gpio_check_owner(handle) { return E_INVAL; }
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            gpio::syscall_gpio_set_mode(handle, *arg, *arg.add(1))
        }
        dev_gpio::SET_PULL => {
            if !gpio::gpio_check_owner(handle) { return E_INVAL; }
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            gpio::syscall_gpio_set_pull(handle, *arg)
        }
        dev_gpio::SET_LEVEL => {
            if !gpio::gpio_check_owner(handle) { return E_INVAL; }
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            gpio::syscall_gpio_set_level(handle, *arg)
        }
        dev_gpio::GET_LEVEL => {
            syscall_gpio_get_level(handle)
        }
        dev_gpio::WATCH_EDGE => {
            if !gpio::gpio_check_owner(handle) { return E_INVAL; }
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let edge = *arg;
            let evt = i32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            gpio::gpio_watch_edge(handle as u8, edge, evt)
        }
        _ => E_NOSYS,
    }
}

// PIO provider dispatch removed — PIC pio_stream module handles PIO via register bridges.

// ============================================================================
// Raw PAC GPIO 9-bit SPI bit-bang (for display register init)
// ============================================================================

/// Set a pin as SIO output with initial level.
unsafe fn spi9_pac_gpio_init(pin: u8, high: bool) {
    use embassy_rp::pac;
    pac::IO_BANK0.gpio(pin as usize).ctrl().write(|w| w.set_funcsel(5));
    pac::PADS_BANK0.gpio(pin as usize).write(|w| {
        super::chip::pad_set_iso_false!(w);
        w.set_schmitt(false);
        w.set_slewfast(false);
        w.set_ie(true);
        w.set_od(false);
        w.set_pue(false);
        w.set_pde(false);
        w.set_drive(pac::pads::vals::Drive::_4M_A);
    });
    let bank = (pin >> 5) as usize;
    let bit = 1u32 << (pin & 31);
    if high {
        pac::SIO.gpio_out(bank).value_set().write_value(bit);
    } else {
        pac::SIO.gpio_out(bank).value_clr().write_value(bit);
    }
    pac::SIO.gpio_oe(bank).value_set().write_value(bit);
}

/// Set a SIO output pin level.
#[inline(always)]
unsafe fn spi9_pac_pin_set(pin: u8, high: bool) {
    use embassy_rp::pac;
    let bank = (pin >> 5) as usize;
    let bit = 1u32 << (pin & 31);
    if high {
        pac::SIO.gpio_out(bank).value_set().write_value(bit);
    } else {
        pac::SIO.gpio_out(bank).value_clr().write_value(bit);
    }
}

/// Busy-wait for `us` microseconds using the RP hardware TIMER.
#[inline(always)]
unsafe fn spi9_timer_us(us: u32) {
    let timer = super::chip::timer();
    let t0 = timer.timerawl().read();
    while timer.timerawl().read().wrapping_sub(t0) < us {}
}

/// Busy-wait ~100 us using hardware TIMER.
#[inline(always)]
unsafe fn spi9_pac_delay() {
    spi9_timer_us(100);
}

/// Busy-wait ~N ms using hardware TIMER.
#[inline(always)]
unsafe fn spi9_pac_delay_ms(ms: u32) {
    spi9_timer_us(ms * 1000);
}

/// Send one 9-bit SPI word. Clock idle low, data on rising edge, MSB first.
unsafe fn spi9_pac_write_word(sck: u8, sda: u8, word: u16) {
    for i in (0..=8i32).rev() {
        spi9_pac_pin_set(sda, (word & (1u16 << i as u32)) != 0);
        spi9_timer_us(10);   // Data setup time before rising edge
        spi9_pac_pin_set(sck, true);
        spi9_pac_delay();     // 100 us SCK high time
        spi9_pac_pin_set(sck, false);
        spi9_pac_delay();     // 100 us SCK low time
    }
}

/// Send 9-bit SPI command + data bytes, CS-framed.
unsafe fn spi9_pac_send(cs: u8, sck: u8, sda: u8, cmd: u8, data: *const u8, data_len: usize, hold_cs: bool) {
    spi9_pac_pin_set(cs, false);
    spi9_timer_us(5);  // CS setup time before first clock
    spi9_pac_write_word(sck, sda, cmd as u16); // DC=0 for command
    for i in 0..data_len {
        spi9_pac_write_word(sck, sda, 0x0100 | *data.add(i) as u16); // DC=1 for data
    }
    if !hold_cs {
        spi9_timer_us(5);  // CS hold time after last clock
        spi9_pac_pin_set(cs, true);
    }
}

/// Reset sequence + SIO pin init for 9-bit SPI.
unsafe fn spi9_pac_reset(rst: u8, cs: u8, sck: u8, sda: u8) {
    spi9_pac_gpio_init(cs, true);
    spi9_pac_gpio_init(sck, false);
    spi9_pac_gpio_init(sda, false);
    spi9_pac_gpio_init(rst, true);

    spi9_pac_pin_set(rst, true);
    spi9_pac_delay_ms(20);
    spi9_pac_pin_set(rst, false);
    spi9_pac_delay_ms(20);
    spi9_pac_pin_set(rst, true);
    spi9_pac_delay_ms(200);
}

// ============================================================================
// RP System Extension Dispatch
// ============================================================================
//
// Handles hardware-specific system opcodes (PWM, PIO registers, DMA, SPI9)
// delegated from system_provider_dispatch's catch-all arm.

/// Handle-family discriminators for `PLATFORM_DMA` (raw channel number,
/// from `channel::ALLOC`) and `PLATFORM_DMA_FD` (FD_TAG_DMA-tagged fd,
/// from `fd::CREATE`). The two families never share handles; each
/// handler rejects wrong-family handles with EINVAL.
#[inline]
fn is_dma_channel_handle(h: i32) -> bool {
    if h < 0 { return false; }
    let (tag, _slot) = crate::kernel::fd::untag_fd(h);
    tag == 0
}

#[inline]
fn is_dma_fd_handle(h: i32) -> bool {
    if h < 0 { return false; }
    let (tag, _slot) = crate::kernel::fd::untag_fd(h);
    tag == crate::kernel::fd::FD_TAG_DMA
}

unsafe fn rp_system_extension_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::kernel_abi::SYS_CLOCK_HZ;
    use crate::abi::internal::flash;
    use crate::abi::contracts::storage::runtime_params;
    use crate::abi::internal::provider_registry::FLASH_STORE_ENABLE;
    use crate::abi::platform::rp::{adc_raw, dma_raw, i2c_raw, pio_raw, pwm_raw, spi_raw, spi9_raw, uart_raw};
    match opcode {
        // ── Raw PWM register bridge ─────────────────────────────────
        pwm_raw::PIN_ENABLE => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let pin = *arg as usize;
            if pin >= gpio::runtime_max_gpio() as usize { return E_INVAL; }
            use embassy_rp::pac;
            pac::IO_BANK0.gpio(pin).ctrl().write(|w| w.set_funcsel(4));
            pac::PADS_BANK0.gpio(pin).modify(|w| {
                w.set_ie(false);
                w.set_od(false);
                super::chip::pad_set_iso_false!(w);
            });
            0
        }
        pwm_raw::PIN_DISABLE => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let pin = *arg as usize;
            if pin >= gpio::runtime_max_gpio() as usize { return E_INVAL; }
            use embassy_rp::pac;
            pac::IO_BANK0.gpio(pin).ctrl().write(|w| w.set_funcsel(31));
            0
        }
        pwm_raw::SLICE_WRITE => {
            if arg.is_null() || arg_len < 6 { return E_INVAL; }
            let slice = *arg as usize;
            let reg = *arg.add(1);
            let value = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            if slice >= 12 { return E_INVAL; }
            use embassy_rp::pac;
            let ch = pac::PWM.ch(slice);
            match reg {
                0 => ch.csr().write(|w| w.0 = value),
                1 => ch.div().write(|w| w.0 = value),
                2 => ch.ctr().write(|w| w.0 = value),
                3 => ch.cc().write(|w| w.0 = value),
                4 => ch.top().write(|w| w.0 = value),
                _ => return E_INVAL,
            }
            0
        }
        pwm_raw::SLICE_READ => {
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            let slice = *arg as usize;
            let reg = *arg.add(1);
            if slice >= 12 { return E_INVAL; }
            use embassy_rp::pac;
            let ch = pac::PWM.ch(slice);
            match reg {
                0 => ch.csr().read().0 as i32,
                1 => ch.div().read().0 as i32,
                2 => ch.ctr().read().0 as i32,
                3 => ch.cc().read().0 as i32,
                4 => ch.top().read().0 as i32,
                _ => E_INVAL,
            }
        }
        // ── Raw PIO register bridge ───────────────────────────────────
        pio_raw::SM_EXEC => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let pio_num = *arg;
            let sm = *arg.add(1);
            if pio_num > 2 || sm > 3 { return E_INVAL; }
            let instr = u16::from_le_bytes([*arg.add(2), *arg.add(3)]);
            pio_util::pio_pac(pio_num).sm(sm as usize).instr().write(|w| w.set_instr(instr));
            0
        }
        pio_raw::SM_WRITE_REG => {
            if arg.is_null() || arg_len < 7 { return E_INVAL; }
            let pio_num = *arg;
            let sm_idx = *arg.add(1);
            let reg = *arg.add(2);
            if pio_num > 2 || sm_idx > 3 { return E_INVAL; }
            let value = u32::from_le_bytes([*arg.add(3), *arg.add(4), *arg.add(5), *arg.add(6)]);
            let sm = pio_util::pio_pac(pio_num).sm(sm_idx as usize);
            match reg {
                0 => sm.clkdiv().write(|w| w.0 = value),
                1 => sm.execctrl().write(|w| w.0 = value),
                2 => sm.shiftctrl().write(|w| w.0 = value),
                3 => sm.pinctrl().write(|w| w.0 = value),
                _ => return E_INVAL,
            }
            0
        }
        pio_raw::SM_READ_REG => {
            if arg.is_null() || arg_len < 3 { return E_INVAL; }
            let pio_num = *arg;
            let sm_idx = *arg.add(1);
            let reg = *arg.add(2);
            if pio_num > 2 || sm_idx > 3 { return E_INVAL; }
            let sm = pio_util::pio_pac(pio_num).sm(sm_idx as usize);
            match reg {
                0 => sm.clkdiv().read().0 as i32,
                1 => sm.execctrl().read().0 as i32,
                2 => sm.shiftctrl().read().0 as i32,
                3 => sm.pinctrl().read().0 as i32,
                4 => sm.addr().read().addr() as i32,
                _ => E_INVAL,
            }
        }
        pio_raw::SM_ENABLE => {
            if arg.is_null() || arg_len < 3 { return E_INVAL; }
            let pio_num = *arg;
            let mask = *arg.add(1) & 0x0F;
            let enable = *arg.add(2);
            if pio_num > 2 { return E_INVAL; }
            let p = pio_util::pio_pac(pio_num);
            p.ctrl().modify(|w| {
                if enable != 0 {
                    w.set_sm_enable(w.sm_enable() | mask);
                } else {
                    w.set_sm_enable(w.sm_enable() & !mask);
                }
            });
            0
        }
        pio_raw::INSTR_ALLOC => {
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            let pio_num = *arg;
            let count = *arg.add(1);
            if pio_num > 2 || count == 0 || count > 32 { return E_INVAL; }
            match pio_util::alloc_instruction_slots(pio_num, count as usize) {
                Some((origin, mask)) => {
                    // Write mask back to arg[2..6] so caller can free later
                    if arg_len >= 6 {
                        let mask_bytes = mask.to_le_bytes();
                        *arg.add(2) = mask_bytes[0];
                        *arg.add(3) = mask_bytes[1];
                        *arg.add(4) = mask_bytes[2];
                        *arg.add(5) = mask_bytes[3];
                    }
                    origin as i32
                }
                None => E_NOMEM,
            }
        }
        pio_raw::INSTR_WRITE => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let pio_num = *arg;
            let addr = *arg.add(1);
            if pio_num > 2 || addr > 31 { return E_INVAL; }
            let instr = u16::from_le_bytes([*arg.add(2), *arg.add(3)]);
            pio_util::pio_pac(pio_num).instr_mem(addr as usize).write(|w| w.0 = instr as u32);
            0
        }
        pio_raw::INSTR_FREE => {
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let pio_num = *arg;
            if pio_num > 2 { return E_INVAL; }
            let mask = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            pio_util::free_instruction_slots(pio_num, mask);
            0
        }
        pio_raw::PIN_SETUP => {
            if arg.is_null() || arg_len < 3 { return E_INVAL; }
            let pin = *arg;
            let pio_num = *arg.add(1);
            let pull = *arg.add(2);
            if pio_num > 2 || pin as usize >= gpio::runtime_max_gpio() as usize { return E_INVAL; }
            let pio_pull = match pull {
                0 => pio_util::PioPull::None,
                1 => pio_util::PioPull::PullDown,
                2 => pio_util::PioPull::PullUp,
                _ => return E_INVAL,
            };
            pio_util::setup_pio_pin(pin, pio_num, pio_pull);
            0
        }
        pio_raw::GPIOBASE => {
            // PIO GPIOBASE: RP2350 only (register absent on RP2040 PAC)
            #[cfg(not(feature = "chip-rp2040"))]
            {
                if arg.is_null() || arg_len < 2 { return E_INVAL; }
                let pio_num = *arg;
                let base16 = *arg.add(1);
                if pio_num > 2 { return E_INVAL; }
                pio_util::pio_pac(pio_num).gpiobase().write(|w| w.set_gpiobase(base16 != 0));
                0
            }
            #[cfg(feature = "chip-rp2040")]
            { E_NOSYS }
        }
        pio_raw::TXF_WRITE => {
            if arg.is_null() || arg_len < 6 { return E_INVAL; }
            let pio_num = *arg;
            let sm = *arg.add(1);
            if pio_num > 2 || sm > 3 { return E_INVAL; }
            let value = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            pio_util::pio_pac(pio_num).txf(sm as usize).write_value(value);
            0
        }
        pio_raw::FSTAT_READ => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let pio_num = *arg;
            if pio_num > 2 { return E_INVAL; }
            pio_util::pio_pac(pio_num).fstat().read().0 as i32
        }
        pio_raw::SM_RESTART => {
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            let pio_num = *arg;
            let mask = *arg.add(1) & 0x0F;
            if pio_num > 2 { return E_INVAL; }
            let p = pio_util::pio_pac(pio_num);
            p.ctrl().modify(|w| {
                w.set_sm_restart(mask);
                w.set_clkdiv_restart(mask);
            });
            0
        }
        pio_raw::INPUT_SYNC_BYPASS => {
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let pio_num = *arg;
            if pio_num > 2 { return E_INVAL; }
            let mask = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            let p = pio_util::pio_pac(pio_num);
            p.input_sync_bypass().modify(|w| *w |= mask);
            0
        }
        pio_raw::CMD_TRANSFER => {
            // Atomic PIO cmd transfer: setup SM + DMA in one call (no syscall latency between steps)
            // arg layout (28 bytes):
            //   [0] pio_num, [1] sm_num, [2] origin, [3] reserved
            //   [4..8] write_bits (u32 LE), [8..12] read_bits (u32 LE)
            //   [12..16] tx_addr (u32 LE), [16..20] tx_words (u32 LE)
            //   [20..24] rx_addr (u32 LE), [24] dma_ch_tx, [25] dma_ch_rx, [26..28] reserved
            if arg.is_null() || arg_len < 28 { return E_INVAL; }
            let pio_num = *arg;
            let sm_num = *arg.add(1) as usize;
            let origin = *arg.add(2);
            if pio_num > 2 || sm_num > 3 { return E_INVAL; }

            let write_bits = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            let read_bits = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            let tx_addr = u32::from_le_bytes([*arg.add(12), *arg.add(13), *arg.add(14), *arg.add(15)]);
            let tx_words = u32::from_le_bytes([*arg.add(16), *arg.add(17), *arg.add(18), *arg.add(19)]);
            let rx_addr = u32::from_le_bytes([*arg.add(20), *arg.add(21), *arg.add(22), *arg.add(23)]);
            let ch_tx = *arg.add(24);
            let _ch_rx = *arg.add(25);

            let pio = pio_util::pio_pac(pio_num);
            let sm = pio.sm(sm_num);
            let sm_mask = 1u8 << sm_num;

            // Disable SM
            pio.ctrl().modify(|w| w.set_sm_enable(w.sm_enable() & !sm_mask));

            // Set X = write_bits via TXF + forced OUT X,32
            pio.txf(sm_num).write_value(write_bits);
            sm.instr().write(|w| w.set_instr(0x6020)); // OUT X, 32
            cortex_m::asm::delay(10);

            // Set Y = read_bits via TXF + forced OUT Y,32
            pio.txf(sm_num).write_value(read_bits);
            sm.instr().write(|w| w.set_instr(0x6040)); // OUT Y, 32
            cortex_m::asm::delay(10);

            // SET PINDIRS, 1 (output for TX phase)
            sm.instr().write(|w| w.set_instr(0xE081));
            cortex_m::asm::delay(10);

            // JMP origin
            sm.instr().write(|w| w.set_instr(origin as u16));
            cortex_m::asm::delay(10);

            compiler_fence(Ordering::SeqCst);

            let tx_dreq = (pio_num << 3) + sm_num as u8;
            let rx_dreq = tx_dreq + 4;
            let txf_addr = pio.txf(sm_num).as_ptr() as u32;
            let rxf_addr = pio.rxf(sm_num).as_ptr() as u32;

            // Enable the state machine before DMA so the PIO FIFOs drain
            // as transfers land.
            pio.ctrl().modify(|w| w.set_sm_enable(w.sm_enable() | sm_mask));

            compiler_fence(Ordering::SeqCst);

            // Sequential TX then RX on a single DMA channel. RX must run
            // even for write-only transactions — the PIO program expects
            // the full TX→RX cycle to complete.
            let rx_words = if read_bits > 0 { (read_bits + 1 + 31) / 32 } else { 1 };

            // TX DMA blocking
            if tx_words > 0 {
                crate::kernel::rp_ext::dma_start_raw(ch_tx, tx_addr, txf_addr, tx_words, tx_dreq, 0x05);
                compiler_fence(Ordering::SeqCst);
                while crate::kernel::rp_ext::dma_busy(ch_tx) != 0 {}
                compiler_fence(Ordering::SeqCst);
            }

            // RX DMA blocking (always — PIO needs full TX→RX cycle)
            crate::kernel::rp_ext::dma_start_raw(ch_tx, rxf_addr, rx_addr, rx_words, rx_dreq, 0x06);
            compiler_fence(Ordering::SeqCst);
            while crate::kernel::rp_ext::dma_busy(ch_tx) != 0 {}
            compiler_fence(Ordering::SeqCst);

            let total = (tx_words * 4 + rx_words * 4) as i32;
            total
        }
        // ── PLATFORM_DMA: channel family ──────────────────────────────
        //
        // Handle-type rule: `channel::ALLOC` is the only opener in this
        // family; its returned handle is a raw DMA channel number
        // (0..15). Every follow-up op requires that handle and rejects
        // tagged fds from the `fd::*` family.
        //
        // Cross-family rejection: a tagged DMA fd has bits >= 15 set
        // (FD_TAG_DMA=7 shifted by TAG_SHIFT=27). `is_dma_channel_handle`
        // refuses any such handle outright — so passing `fd::CREATE`'s
        // return value to `channel::FREE` fails fast with EINVAL.
        dma_raw::channel::ALLOC => {
            dma_alloc_channel()
        }
        dma_raw::channel::FREE => {
            if !is_dma_channel_handle(handle) { return E_INVAL; }
            dma_free_channel(handle as u8)
        }
        dma_raw::channel::START => {
            if !is_dma_channel_handle(handle) { return E_INVAL; }
            if arg.is_null() || arg_len < 14 { return E_INVAL; }
            let read_addr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let write_addr = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            let count = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            let dreq = *arg.add(12);
            let flags = *arg.add(13);
            dma_start_raw(handle as u8, read_addr, write_addr, count, dreq, flags)
        }
        dma_raw::channel::BUSY => {
            if !is_dma_channel_handle(handle) { return E_INVAL; }
            dma_busy(handle as u8)
        }
        dma_raw::channel::ABORT => {
            if !is_dma_channel_handle(handle) { return E_INVAL; }
            dma_abort(handle as u8)
        }
        spi9_raw::SEND => {
            // 9-bit SPI bit-bang: send command + data using raw PAC GPIO.
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let cs = *arg;
            let sck = *arg.add(1);
            let sda = *arg.add(2);
            let cmd = *arg.add(3);
            let data_len = *arg.add(4) as usize;
            if arg_len < 5 + data_len { return E_INVAL; }
            let hold_cs = if arg_len > 5 + data_len { *arg.add(5 + data_len) != 0 } else { false };
            spi9_pac_send(cs, sck, sda, cmd, arg.add(5), data_len, hold_cs);
            0
        }
        spi9_raw::RESET => {
            // 9-bit SPI reset: RST high->low->high + init SIO pins
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let rst = *arg;
            let cs = *arg.add(1);
            let sck = *arg.add(2);
            let sda = *arg.add(3);
            spi9_pac_reset(rst, cs, sck, sda);
            0
        }
        spi9_raw::CS_SET => {
            // Set CS pin level: arg=[cs_pin:u8, level:u8]
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            let cs = *arg;
            let level = *arg.add(1) != 0;
            spi9_pac_pin_set(cs, level);
            0
        }
        // ── Raw SPI peripheral bridge ─────────────────────────────────
        spi_raw::REG_WRITE => {
            // handle=bus_id, arg=[offset:u8, value:u32 LE]
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let bus = handle as u8;
            if bus > 1 { return E_INVAL; }
            let base = if bus == 0 { 0x4008_0000usize } else { 0x4009_0000usize };
            let offset = (*arg as usize) & 0xFC; // 4-byte aligned
            let val = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            core::ptr::write_volatile((base + offset) as *mut u32, val);
            0
        }
        spi_raw::REG_READ => {
            // handle=bus_id, arg=[offset:u8], returns value in arg[1..5]
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let bus = handle as u8;
            if bus > 1 { return E_INVAL; }
            let base = if bus == 0 { 0x4008_0000usize } else { 0x4009_0000usize };
            let offset = (*arg as usize) & 0xFC;
            let val = core::ptr::read_volatile((base + offset) as *const u32);
            let bytes = val.to_le_bytes();
            *arg.add(1) = bytes[0]; *arg.add(2) = bytes[1];
            *arg.add(3) = bytes[2]; *arg.add(4) = bytes[3];
            0
        }
        spi_raw::BUS_INFO => {
            // handle=bus_id, returns [dr_addr:u32, tx_dreq:u8, rx_dreq:u8, max_freq:u32, pad:u16]
            if arg.is_null() || arg_len < 12 { return E_INVAL; }
            let bus = handle as u8;
            if bus > 1 { return E_INVAL; }
            let dr_addr: u32 = if bus == 0 { 0x4008_0008 } else { 0x4009_0008 };
            let tx_dreq: u8 = if bus == 0 { 16 } else { 18 };
            let rx_dreq: u8 = if bus == 0 { 17 } else { 19 };
            let max_freq: u32 = 150_000_000 / 2; // SPI max = Fsys/2 (default 150MHz)
            let dr = dr_addr.to_le_bytes();
            *arg = dr[0]; *arg.add(1) = dr[1]; *arg.add(2) = dr[2]; *arg.add(3) = dr[3];
            *arg.add(4) = tx_dreq;
            *arg.add(5) = rx_dreq;
            let mf = max_freq.to_le_bytes();
            *arg.add(6) = mf[0]; *arg.add(7) = mf[1]; *arg.add(8) = mf[2]; *arg.add(9) = mf[3];
            *arg.add(10) = 0; *arg.add(11) = 0;
            0
        }
        spi_raw::PIN_INIT => {
            // handle=bus_id, arg=[clk:u8, mosi:u8, miso:u8]
            if arg.is_null() || arg_len < 3 { return E_INVAL; }
            let bus = handle as u8;
            if bus > 1 { return E_INVAL; }
            let funcsel: u32 = 1; // SPI function on RP2350
            let pins = [*arg, *arg.add(1), *arg.add(2)];
            let mut i = 0usize;
            while i < 3 {
                let pin = pins[i];
                if pin != 0xFF && pin < 30 {
                    let pad_base = 0x4003_8004usize + (pin as usize) * 4;
                    let io_base = 0x4002_8004usize + (pin as usize) * 8;
                    // Enable pad (IE + drive)
                    core::ptr::write_volatile(pad_base as *mut u32, 0x56);
                    // Set funcsel
                    core::ptr::write_volatile(io_base as *mut u32, funcsel);
                }
                i += 1;
            }
            0
        }
        // ── Raw I2C peripheral bridge ──────────────────────────────────
        i2c_raw::REG_WRITE => {
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let bus = handle as u8;
            if bus > 1 { return E_INVAL; }
            let base = if bus == 0 { 0x4009_0000usize } else { 0x4009_8000usize };
            let offset = (*arg as usize) & 0xFC;
            let val = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            core::ptr::write_volatile((base + offset) as *mut u32, val);
            0
        }
        i2c_raw::REG_READ => {
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let bus = handle as u8;
            if bus > 1 { return E_INVAL; }
            let base = if bus == 0 { 0x4009_0000usize } else { 0x4009_8000usize };
            let offset = (*arg as usize) & 0xFC;
            let val = core::ptr::read_volatile((base + offset) as *const u32);
            let bytes = val.to_le_bytes();
            *arg.add(1) = bytes[0]; *arg.add(2) = bytes[1];
            *arg.add(3) = bytes[2]; *arg.add(4) = bytes[3];
            0
        }
        i2c_raw::BUS_INFO => {
            if arg.is_null() || arg_len < 8 { return E_INVAL; }
            let bus = handle as u8;
            if bus > 1 { return E_INVAL; }
            let data_cmd: u32 = if bus == 0 { 0x4009_0010 } else { 0x4009_8010 }; // IC_DATA_CMD
            let tx_dreq: u8 = if bus == 0 { 20 } else { 22 }; // I2C0_TX=20, I2C1_TX=22
            let rx_dreq: u8 = if bus == 0 { 21 } else { 23 };
            let dc = data_cmd.to_le_bytes();
            *arg = dc[0]; *arg.add(1) = dc[1]; *arg.add(2) = dc[2]; *arg.add(3) = dc[3];
            *arg.add(4) = tx_dreq; *arg.add(5) = rx_dreq;
            *arg.add(6) = 0; *arg.add(7) = 0;
            0
        }
        i2c_raw::PIN_INIT => {
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            let funcsel: u32 = 3; // I2C function on RP2350
            let pins = [*arg, *arg.add(1)];
            let mut i = 0usize;
            while i < 2 {
                let pin = pins[i];
                if pin != 0xFF && pin < 30 {
                    let pad_base = 0x4003_8004usize + (pin as usize) * 4;
                    let io_base = 0x4002_8004usize + (pin as usize) * 8;
                    // I2C needs pullup + input enable
                    core::ptr::write_volatile(pad_base as *mut u32, 0x4E); // IE + PUE + drive=4mA
                    core::ptr::write_volatile(io_base as *mut u32, funcsel);
                }
                i += 1;
            }
            0
        }
        i2c_raw::SET_ENABLE => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let bus = handle as u8;
            if bus > 1 { return E_INVAL; }
            let base = if bus == 0 { 0x4009_0000usize } else { 0x4009_8000usize };
            // IC_ENABLE at offset 0x6C
            core::ptr::write_volatile((base + 0x6C) as *mut u32, if *arg != 0 { 1 } else { 0 });
            0
        }
        // ── Raw UART peripheral bridge ─────────────────────────────────
        uart_raw::REG_WRITE => {
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let bus = handle as u8;
            if bus > 1 { return E_INVAL; }
            let base = if bus == 0 { 0x4007_0000usize } else { 0x4007_8000usize };
            let offset = (*arg as usize) & 0xFC;
            let val = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            core::ptr::write_volatile((base + offset) as *mut u32, val);
            0
        }
        uart_raw::REG_READ => {
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let bus = handle as u8;
            if bus > 1 { return E_INVAL; }
            let base = if bus == 0 { 0x4007_0000usize } else { 0x4007_8000usize };
            let offset = (*arg as usize) & 0xFC;
            let val = core::ptr::read_volatile((base + offset) as *const u32);
            let bytes = val.to_le_bytes();
            *arg.add(1) = bytes[0]; *arg.add(2) = bytes[1];
            *arg.add(3) = bytes[2]; *arg.add(4) = bytes[3];
            0
        }
        uart_raw::PIN_INIT => {
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            let funcsel: u32 = 2; // UART function on RP2350
            let pins = [*arg, *arg.add(1)];
            let mut i = 0usize;
            while i < 2 {
                let pin = pins[i];
                if pin != 0xFF && pin < 30 {
                    let pad_base = 0x4003_8004usize + (pin as usize) * 4;
                    let io_base = 0x4002_8004usize + (pin as usize) * 8;
                    core::ptr::write_volatile(pad_base as *mut u32, 0x56);
                    core::ptr::write_volatile(io_base as *mut u32, funcsel);
                }
                i += 1;
            }
            0
        }
        uart_raw::SET_ENABLE => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let bus = handle as u8;
            if bus > 1 { return E_INVAL; }
            let base = if bus == 0 { 0x4007_0000usize } else { 0x4007_8000usize };
            // UARTCR at offset 0x30
            let cr = core::ptr::read_volatile((base + 0x30) as *const u32);
            if *arg != 0 {
                core::ptr::write_volatile((base + 0x30) as *mut u32, cr | 0x301); // UARTEN + TXE + RXE
            } else {
                core::ptr::write_volatile((base + 0x30) as *mut u32, cr & !1); // clear UARTEN
            }
            0
        }
        // ── Raw ADC peripheral bridge ──────────────────────────────────
        adc_raw::REG_WRITE => {
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let base = 0x400A_0000usize;
            let offset = (*arg as usize) & 0xFC;
            let val = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            core::ptr::write_volatile((base + offset) as *mut u32, val);
            0
        }
        adc_raw::REG_READ => {
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let base = 0x400A_0000usize;
            let offset = (*arg as usize) & 0xFC;
            let val = core::ptr::read_volatile((base + offset) as *const u32);
            let bytes = val.to_le_bytes();
            *arg.add(1) = bytes[0]; *arg.add(2) = bytes[1];
            *arg.add(3) = bytes[2]; *arg.add(4) = bytes[3];
            0
        }
        adc_raw::PIN_INIT => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let pin = *arg;
            if pin < 26 || pin > 29 { return E_INVAL; }
            let pad_base = 0x4003_8004usize + (pin as usize) * 4;
            // ADC: disable digital input (IE=0), no pulls
            core::ptr::write_volatile(pad_base as *mut u32, 0x80); // ISO=1 (analog mode)
            0
        }
        // ── SPI bridge (continued) ─────────────────────────────────────
        spi_raw::SET_ENABLE => {
            // handle=bus_id, arg=[enable:u8]
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let bus = handle as u8;
            if bus > 1 { return E_INVAL; }
            let base = if bus == 0 { 0x4008_0000usize } else { 0x4009_0000usize };
            let cr1 = core::ptr::read_volatile((base + 0x04) as *const u32);
            if *arg != 0 {
                core::ptr::write_volatile((base + 0x04) as *mut u32, cr1 | (1 << 1)); // SSE=1
            } else {
                core::ptr::write_volatile((base + 0x04) as *mut u32, cr1 & !(1 << 1)); // SSE=0
            }
            0
        }
        flash::SIDEBAND => {
            use crate::abi::internal::flash::sideband_op as flash_sideband_op;
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            match *arg {
                flash_sideband_op::READ_CS => crate::kernel::resource::flash_sideband_read_cs(),
                flash_sideband_op::XIP_READ => {
                    if arg_len < 6 { return E_INVAL; }
                    let offset = u32::from_le_bytes([
                        *arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4),
                    ]);
                    const FLASH_SIZE: u32 = 0x0040_0000;
                    let data_len = arg_len - 5;
                    if offset >= FLASH_SIZE { return E_INVAL; }
                    let avail = (FLASH_SIZE - offset) as usize;
                    let copy_len = if data_len < avail { data_len } else { avail };
                    let xip_src = (0x1000_0000u32 + offset) as *const u8;
                    core::ptr::copy_nonoverlapping(xip_src, arg.add(5), copy_len);
                    copy_len as i32
                }
                _ => E_NOSYS,
            }
        }
        // ── Runtime parameter store ──
        runtime_params::STORE => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let module_id = crate::kernel::scheduler::current_module_index() as u8;
            let mut fwd = [0u8; 252];
            fwd[0] = module_id;
            let n = if arg_len > 251 { 251 } else { arg_len };
            core::ptr::copy_nonoverlapping(arg, fwd.as_mut_ptr().add(1), n);
            crate::kernel::flash_store::dispatch_param_op(
                runtime_params::STORE, fwd.as_mut_ptr(), 1 + n)
        }
        runtime_params::DELETE => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let module_id = crate::kernel::scheduler::current_module_index() as u8;
            let mut fwd = [module_id, *arg];
            crate::kernel::flash_store::dispatch_param_op(
                runtime_params::DELETE, fwd.as_mut_ptr(), 2)
        }
        runtime_params::CLEAR_ALL => {
            if arg_len >= 1 && !arg.is_null() && *arg == 0xFF {
                let mut fwd = [0xFFu8];
                crate::kernel::flash_store::dispatch_param_op(
                    runtime_params::CLEAR_ALL, fwd.as_mut_ptr(), 1)
            } else {
                let module_id = crate::kernel::scheduler::current_module_index() as u8;
                let mut fwd = [module_id];
                crate::kernel::flash_store::dispatch_param_op(
                    runtime_params::CLEAR_ALL, fwd.as_mut_ptr(), 1)
            }
        }
        // ── Flash store bridge ──
        FLASH_STORE_ENABLE => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let fn_addr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let module_idx = crate::kernel::scheduler::current_module_index();
            // Resolve export hash to absolute address (PIC-safe)
            let resolved_addr = crate::kernel::loader::resolve_export_for_module(
                module_idx, fn_addr
            ).unwrap_or(fn_addr as usize);
            let dispatch: crate::kernel::flash_store::FlashStoreDispatchFn =
                core::mem::transmute(resolved_addr);
            let state = crate::kernel::scheduler::get_module_state(module_idx);
            crate::kernel::flash_store::register_dispatch(dispatch, state)
        }
        flash::RAW_ERASE => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let offset = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            crate::kernel::flash_store::raw_erase(offset)
        }
        flash::RAW_PROGRAM => {
            if arg.is_null() || arg_len < 4 + 256 { return E_INVAL; }
            let offset = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            crate::kernel::flash_store::raw_program(offset, arg.add(4))
        }
        // ── PLATFORM_DMA: fd family ──────────────────────────────────
        //
        // Handle-type rule: `fd::CREATE` is the only opener in this
        // family; its returned handle is a tagged DMA fd (FD_TAG_DMA).
        // Every follow-up op rejects raw channel numbers via
        // `is_dma_fd_handle` so passing `channel::ALLOC`'s return value
        // to `fd::START` fails fast with EINVAL.
        dma_raw::fd::CREATE => {
            dma_fd_create()
        }
        dma_raw::fd::START => {
            if !is_dma_fd_handle(handle) { return E_INVAL; }
            if arg.is_null() || arg_len < 14 { return E_INVAL; }
            let read_addr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let write_addr = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            let count = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            let dreq = *arg.add(12);
            let flags = *arg.add(13);
            dma_fd_start(handle, read_addr, write_addr, count, dreq, flags)
        }
        dma_raw::fd::RESTART => {
            if !is_dma_fd_handle(handle) { return E_INVAL; }
            if arg.is_null() || arg_len < 8 { return E_INVAL; }
            let read_addr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let count = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            dma_fd_restart(handle, read_addr, count)
        }
        dma_raw::fd::FREE => {
            if !is_dma_fd_handle(handle) { return E_INVAL; }
            dma_fd_free(handle)
        }
        dma_raw::fd::QUEUE => {
            if !is_dma_fd_handle(handle) { return E_INVAL; }
            if arg.is_null() || arg_len < 8 { return E_INVAL; }
            let read_addr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let count = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            dma_fd_queue(handle, read_addr, count)
        }
        // ── SYS_CLOCK_HZ ──
        SYS_CLOCK_HZ => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            *(arg as *mut u32) = embassy_rp::clocks::clk_sys_freq();
            0
        }
        _ => E_NOSYS,
    }
}

// ============================================================================
// RP provider_query extension (GPIO + SYS_CLOCK_HZ)
// ============================================================================

unsafe fn rp_dev_query_extension(handle: i32, key: u32, out: *mut u8, out_len: usize) -> i32 {
    use crate::abi::contracts::hal::gpio as dev_gpio;
    use crate::abi::kernel_abi::SYS_CLOCK_HZ;
    use crate::kernel::provider::contract as dev_class;
    let class = ((key >> 8) & 0xFF) as u16;
    match class {
        dev_class::GPIO => {
            match key {
                dev_gpio::GET_LEVEL => {
                    if !gpio::gpio_check_owner(handle) { return E_INVAL; }
                    gpio::gpio_get_level(handle)
                }
                _ => E_NOSYS,
            }
        }
        dev_class::INTERNAL_DISPATCH_BUCKET => {
            match key {
                SYS_CLOCK_HZ => {
                    if out.is_null() || out_len < 4 { return E_INVAL; }
                    *(out as *mut u32) = embassy_rp::clocks::clk_sys_freq();
                    0
                }
                _ => E_NOSYS,
            }
        }
        _ => E_NOSYS,
    }
}

// ============================================================================
// RP Provider Registration + Cleanup
// ============================================================================

/// Register RP-specific contract providers. Called from init_providers().
fn init_rp_providers() {
    use crate::kernel::provider::{self, contract as dev_class};
    provider::register(dev_class::HAL_GPIO, gpio_provider_dispatch);
    // Handle-scoped vtable routes tracked GPIO handles by contract id;
    // the class-byte registration above is the fallback for handle=-1
    // global ops.
    provider::register_vtable(&GPIO_VTABLE);
    // PIO, SPI, I2C, UART, ADC, PWM providers are registered by the
    // loader when their PIC module exports `module_provides_contract`.
    // Register system extension for hardware opcodes (raw register bridges)
    register_system_extension(rp_system_extension_dispatch);
}

// Handle-scoped vtable for HAL GPIO. `call` delegates to
// `gpio_provider_dispatch`; open-style opcodes (CLAIM, SET_INPUT,
// SET_OUTPUT) return a pin handle that `provider_open` tracks. Close
// invokes RELEASE.
static GPIO_VTABLE: crate::kernel::provider::ProviderVTable =
    crate::kernel::provider::ProviderVTable {
        contract: crate::kernel::provider::contract::HAL_GPIO,
        call:  gpio_provider_dispatch,
        query: None,
        default_close_op: crate::abi::contracts::hal::gpio::RELEASE,
    };

/// Release all RP-specific hardware handles owned by a module.
fn release_rp_handles(module_idx: u8) {
    // PIO handles released by PIC pio_stream module provider
    // Release GPIO pins
    gpio::release_owned_by(module_idx);
}
