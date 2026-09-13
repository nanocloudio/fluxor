//! A minimal UART console that does not depend on USB.
//!
//! This exists for one situation: the USB device stack does not enumerate,
//! and the only channel that could explain why is the one that is broken.
//!
//! The USB console cannot report its own failure. A silent board
//! says nothing about which of the layers below it failed. A serial console
//! on two header pins costs almost nothing and turns that from a guess into
//! a reading.
//!
//! It is deliberately blocking and deliberately tiny. It is not a driver for
//! general use: there is no receive path, no interrupt, no buffering. It
//! writes bytes out of a pin so a person with a USB-serial adapter can watch
//! a boot that has no other voice.

/// PL011 register offsets. Identical on both chips; the *base* is not.
mod reg {
    /// Data. Writing sends a byte.
    pub const DR: usize = 0x00;
    /// Flags. `TXFF` is bit 5, `BUSY` bit 3.
    pub const FR: usize = 0x18;
    // Configuration registers, written only by `init` — and `init` only has
    // something to write where the board declared a console header.
    /// Integer baud divisor.
    #[cfg(console_uart)]
    pub const IBRD: usize = 0x24;
    /// Fractional baud divisor.
    #[cfg(console_uart)]
    pub const FBRD: usize = 0x28;
    /// Line control: word length, FIFO enable.
    #[cfg(console_uart)]
    pub const LCR_H: usize = 0x2c;
    /// Control: UART, TX and RX enable.
    #[cfg(console_uart)]
    pub const CR: usize = 0x30;
}

/// `FR` bits.
mod fr {
    /// Transmit FIFO full.
    pub const TXFF: u32 = 1 << 5;
    /// Transmitting.
    pub const BUSY: u32 = 1 << 3;
}

/// IO_BANK0 `FUNCSEL` for UART0 on the Pico family's console pins.
#[cfg(console_uart)]
const FUNCSEL_UART: u32 = 2;

/// Spin budget for the FIFO to accept a byte.
///
/// Bounded, like every other wait in this platform. A UART whose clock never
/// started never drains, and a console that hangs the boot it exists to
/// diagnose is worse than no console at all.
const TX_LIMIT: u32 = 100_000;

/// Bring up the console UART.
///
/// Which pins carry the console, and at what baud, is board wiring — so this
/// does nothing unless the board declared a console header. A silicon-level
/// build has no board, and must not drive two arbitrary pins on the strength
/// of a guess; the `console_uart` cfg is emitted by `build.rs` only when
/// `targets/boards/<board>.toml` names the header.
#[cfg(feature = "rp")]
pub fn init(peri_hz: u32) {
    #[cfg(not(console_uart))]
    {
        let _ = peri_hz;
    }

    #[cfg(console_uart)]
    {
        use crate::platform::chip::{
            CONSOLE_UART_BAUD, CONSOLE_UART_RX_PIN, CONSOLE_UART_TX_PIN, RESETS_BASE,
            RESETS_IO_BANK0_BIT, RESETS_PADS_BANK0_BIT, RESETS_UART0_BIT, UART0_BASE,
        };
        use crate::platform::rp_gpio_regs as gpio_regs;
        use crate::platform::rp_regs::{clear_bits, read32, wait_until, write32};

        let base = UART0_BASE as usize;
        let resets = RESETS_BASE as usize;
        let bit = 1u32 << RESETS_UART0_BIT;
        // The console owns its own bring-up, banks included. This is the
        // first thing the boot brings up — before the general reset
        // release, because it exists to report what happens during it — and
        // the function select and pad config below are ordinary
        // configuration writes, which a bank still in reset swallows. The
        // pins would keep their default function and the console would be
        // silent for exactly the window it is there to cover. Clearing a
        // reset that is already clear is a no-op, so releasing them here
        // costs the later release nothing.
        let banks = (1u32 << RESETS_IO_BANK0_BIT) | (1u32 << RESETS_PADS_BANK0_BIT);

        // SAFETY: generated bases for this silicon; single boot-thread writer.
        unsafe {
            let needed = banks | bit;
            clear_bits(resets, needed);
            if !wait_until(TX_LIMIT, || read32(resets + 0x08) & needed == needed) {
                // The UART or a bank it needs never left reset. Nothing to
                // say and nowhere to say it — returning quietly is the only
                // option that does not hang the boot this exists to observe.
                return;
            }

            // Baud divisors: the PL011 divides the peripheral clock by
            // `16 * (IBRD + FBRD/64)`. The caller passes what `clk_peri` is
            // actually running at, which is not always the declared system
            // clock — the early console runs from the crystal, before the
            // PLLs exist. Assuming the final rate there gets the line rate
            // wrong by the PLL's whole multiplier, which reads as silence.
            let clk = peri_hz as u64;
            let div = (8 * clk) / CONSOLE_UART_BAUD as u64;
            let ibrd = (div >> 7) as u32;
            let fbrd = (div & 0x7f).div_ceil(2) as u32;
            write32(base + reg::IBRD, ibrd);
            write32(base + reg::FBRD, fbrd);

            // 8N1 with the FIFO enabled. LCR_H must be written after the
            // divisors: the PL011 latches IBRD/FBRD on an LCR_H write, so
            // setting them afterwards leaves the previous baud in force.
            const WLEN_8BIT: u32 = 0b11 << 5;
            const FIFO_EN: u32 = 1 << 4;
            write32(base + reg::LCR_H, WLEN_8BIT | FIFO_EN);

            const UARTEN: u32 = 1 << 0;
            const TXE: u32 = 1 << 8;
            const RXE: u32 = 1 << 9;
            write32(base + reg::CR, UARTEN | TXE | RXE);

            gpio_regs::set_function(CONSOLE_UART_TX_PIN, FUNCSEL_UART);
            gpio_regs::set_function(CONSOLE_UART_RX_PIN, FUNCSEL_UART);
        }
    }
}

/// Write one byte, blocking until the FIFO has room or the budget expires.
#[cfg(feature = "rp")]
pub fn write_byte(b: u8) {
    use crate::platform::chip::UART0_BASE;
    use crate::platform::rp_regs::{read32, wait_until, write32};

    let base = UART0_BASE as usize;
    // SAFETY: the generated UART base for this silicon.
    unsafe {
        if !wait_until(TX_LIMIT, || read32(base + reg::FR) & fr::TXFF == 0) {
            // Dropping the byte is correct: a console that stalls the system
            // it is reporting on has replaced the problem with a worse one.
            return;
        }
        write32(base + reg::DR, b as u32);
    }
}

/// Write a byte only if the transmit FIFO has room, reporting whether it did.
///
/// For callers that share their loop with something that cannot wait. The
/// blocking [`write_byte`] spins until the FIFO drains, which at 115200 baud
/// is around 87 µs a byte once it is full — a console burst then holds the
/// caller for tens of milliseconds. Where that caller is also servicing the
/// USB device stack, which the host expects to answer within a frame, the
/// console silently takes the board off the bus during boot: the port never
/// appears, and the reason is a log line.
#[cfg(feature = "rp")]
#[must_use]
pub fn try_write_byte(b: u8) -> bool {
    use crate::platform::chip::UART0_BASE;
    use crate::platform::rp_regs::{read32, write32};

    let base = UART0_BASE as usize;
    // SAFETY: the generated UART base for this silicon.
    unsafe {
        if read32(base + reg::FR) & fr::TXFF != 0 {
            return false;
        }
        write32(base + reg::DR, b as u32);
    }
    true
}

/// Write a string, expanding newlines so a terminal shows lines where they
/// are meant to be.
#[cfg(feature = "rp")]
pub fn write_str(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            write_byte(b'\r');
        }
        write_byte(b);
    }
}

/// Wait for the transmitter to drain.
///
/// Called before a reset, so a final message is not cut off mid-word by the
/// reset that follows it.
#[cfg(feature = "rp")]
pub fn flush() {
    use crate::platform::chip::UART0_BASE;
    use crate::platform::rp_regs::{read32, wait_until};
    // SAFETY: the generated UART base for this silicon.
    unsafe {
        let _ = wait_until(TX_LIMIT, || {
            read32(UART0_BASE as usize + reg::FR) & fr::BUSY == 0
        });
    }
}
