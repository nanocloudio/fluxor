//! RP GPIO registers — IO_BANK0 function select, PADS_BANK0 pad control and
//! SIO's output/enable banks.
//!
//! # Why the addressing is parameterised
//!
//! SIO's two GPIO banks are laid out differently on the two chips, not merely
//! relocated. RP2040 keeps each bank contiguous — `OUT`, `OUT_SET`,
//! `OUT_CLR`, `OUT_XOR`, then the high bank 0x20 further on. RP2350
//! interleaves them — `OUT`, `HI_OUT`, `OUT_SET`, `HI_OUT_SET`, and so on. So
//! the stride between banks is 0x20 on one part and 0x04 on the other, while
//! the stride between registers is 0x04 against 0x08.
//!
//! Assuming either layout on the other chip still lands on a real register.
//! It drives the pin in the wrong bank, or writes an output-enable where an
//! output value was meant — a pin that stays dark, or one that floats.

/// Address arithmetic, separated from register access so it is host-testable.
pub mod addr {
    /// IO_BANK0 gives each pin a `{STATUS, CTRL}` pair.
    pub const IO_BANK0_STRIDE: usize = 0x08;
    /// `CTRL` is the second word of the pair.
    pub const IO_BANK0_CTRL: usize = 0x04;
    /// PADS_BANK0 is one word per pin, after a `VOLTAGE_SELECT` word.
    pub const PADS_BANK0_STRIDE: usize = 0x04;
    /// The `VOLTAGE_SELECT` word PADS_BANK0 begins with; pin 0 follows it.
    pub const PADS_BANK0_FIRST_PIN: usize = 0x04;

    /// Index of a SIO GPIO register within its block.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(usize)]
    pub enum SioReg {
        /// The register itself — read the driven value, or write it wholesale.
        Value = 0,
        /// Atomic set: write-one-to-set, no read-modify-write.
        Set = 1,
        /// Atomic clear: write-one-to-clear.
        Clr = 2,
        /// Atomic toggle.
        Xor = 3,
    }

    /// Address of pin `pin`'s `CTRL` in IO_BANK0.
    #[inline]
    pub const fn io_ctrl(base: usize, pin: usize) -> usize {
        base + pin * IO_BANK0_STRIDE + IO_BANK0_CTRL
    }

    /// Address of pin `pin`'s pad control in PADS_BANK0.
    #[inline]
    pub const fn pad(base: usize, pin: usize) -> usize {
        base + PADS_BANK0_FIRST_PIN + pin * PADS_BANK0_STRIDE
    }

    /// `GPIO_IN` within SIO: the pin's actual electrical level.
    pub const SIO_GPIO_IN: usize = 0x04;
    /// `GPIO_HI_IN`, for pins 32 and above.
    pub const SIO_GPIO_HI_IN: usize = 0x08;

    /// Address of a SIO GPIO register.
    ///
    /// `block_base` selects `OUT` or `OE`; `reg` selects the plain register or
    /// one of its atomic aliases; `bank` is 0 for pins 0-31 and 1 above.
    /// Both strides are silicon facts — see the module docs.
    #[inline]
    pub const fn sio(
        sio_base: usize,
        block_base: usize,
        reg: SioReg,
        bank: usize,
        reg_stride: usize,
        bank_stride: usize,
    ) -> usize {
        sio_base + block_base + (reg as usize) * reg_stride + bank * bank_stride
    }

    /// The bank a pin lives in, and its bit within that bank.
    #[inline]
    pub const fn bank_and_bit(pin: u8) -> (usize, u32) {
        ((pin >> 5) as usize, 1u32 << (pin & 31))
    }
}

/// PWM register-block arithmetic.
///
/// Each slice has five consecutive words. The block *base* and the number of
/// slices are silicon facts — RP2040 has 8 slices, RP2350 has 12.
pub mod pwm {
    /// Bytes per slice: CSR, DIV, CTR, CC, TOP.
    pub const SLICE_STRIDE: usize = 0x14;
    /// Registers within a slice, in the order the syscall bridge indexes them.
    pub const REGS: usize = 5;

    /// Address of slice `slice`'s register `reg`, or `None` if `reg` is not
    /// one of the five. The caller checks `slice` against `PWM_SLICES`.
    #[inline]
    pub const fn reg(base: usize, slice: usize, reg: u8) -> Option<usize> {
        if (reg as usize) < REGS {
            Some(base + slice * SLICE_STRIDE + (reg as usize) * 4)
        } else {
            None
        }
    }
}

/// SIO's base address. The one GPIO address that *is* the same on both chips.
pub const SIO_BASE: usize = 0xd000_0000;

#[cfg(feature = "rp")]
pub use rp::*;

#[cfg(feature = "rp")]
mod rp {
    use super::addr::{self, SioReg};
    use crate::platform::chip::{
        IO_BANK0_BASE, PADS_BANK0_BASE, SIO_BANK_STRIDE, SIO_GPIO_OE_BASE, SIO_GPIO_OUT_BASE,
        SIO_REG_STRIDE,
    };
    use crate::platform::rp_regs::{read32, set_field, write32};

    /// PADS_BANK0 field positions. Shared by both chips except `ISO`, which
    /// only RP2350 has — so it is named where it exists and nowhere else.
    pub mod pad_field {
        /// Slew rate.
        pub const SLEWFAST: u32 = 0;
        /// Schmitt trigger on the input.
        pub const SCHMITT: u32 = 1;
        /// Pull-down enable.
        pub const PDE: u32 = 2;
        /// Pull-up enable.
        pub const PUE: u32 = 3;
        /// Drive strength, two bits.
        pub const DRIVE: u32 = 4;
        /// Input enable.
        pub const IE: u32 = 6;
        /// Output disable.
        pub const OD: u32 = 7;
        /// Pad isolation — RP2350 only, and it latches on after reset, so a
        /// pad left isolated is a pin that does nothing at all.
        #[cfg(not(feature = "chip-rp2040"))]
        pub const ISO: u32 = 8;
    }

    /// Drive strength, as the hardware's two-bit encoding.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u32)]
    pub enum Drive {
        /// 2 mA.
        Ma2 = 0,
        /// 4 mA.
        Ma4 = 1,
        /// 8 mA.
        Ma8 = 2,
        /// 12 mA.
        Ma12 = 3,
    }

    /// Select a pin's peripheral function in IO_BANK0.
    ///
    /// # Safety
    /// The caller must own `pin` — two owners driving one pin is a hardware
    /// conflict this layer cannot detect.
    #[inline]
    pub unsafe fn set_function(pin: u8, funcsel: u32) {
        // FUNCSEL is the low five bits of CTRL on both chips.
        // SAFETY: the generated IO_BANK0 base for this silicon, indexed by a
        // pin the caller owns.
        unsafe { write32(addr::io_ctrl(IO_BANK0_BASE as usize, pin as usize), funcsel) };
    }

    /// A pad configuration, built field by field.
    ///
    /// Every setter writes through a named field position, so the RP2350-only
    /// `ISO` bit cannot be set by accident on RP2040 and cannot be *left* set
    /// on RP2350 — pads come out of reset isolated there, and an isolated pad
    /// is a pin that never moves however correct everything upstream is.
    /// Building from zero clears it without needing a cfg at each call site.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct PadConfig(u32);

    impl PadConfig {
        /// Input enable.
        #[must_use]
        pub const fn input_enable(self, on: bool) -> Self {
            Self(set_field(self.0, pad_field::IE, 1, on as u32))
        }

        /// Schmitt trigger on the input.
        #[must_use]
        pub const fn schmitt(self, on: bool) -> Self {
            Self(set_field(self.0, pad_field::SCHMITT, 1, on as u32))
        }

        /// Fast slew rate.
        #[must_use]
        pub const fn slew_fast(self, on: bool) -> Self {
            Self(set_field(self.0, pad_field::SLEWFAST, 1, on as u32))
        }

        /// Pull-up enable.
        #[must_use]
        pub const fn pull_up(self, on: bool) -> Self {
            Self(set_field(self.0, pad_field::PUE, 1, on as u32))
        }

        /// Pull-down enable.
        #[must_use]
        pub const fn pull_down(self, on: bool) -> Self {
            Self(set_field(self.0, pad_field::PDE, 1, on as u32))
        }

        /// Drive strength.
        #[must_use]
        pub const fn drive(self, drive: Drive) -> Self {
            Self(set_field(self.0, pad_field::DRIVE, 2, drive as u32))
        }

        /// The raw register value.
        #[must_use]
        pub const fn bits(self) -> u32 {
            self.0
        }
    }

    /// Write a pad configuration.
    ///
    /// # Safety
    /// As [`set_function`].
    #[inline]
    pub unsafe fn write_pad(pin: u8, cfg: PadConfig) {
        // SAFETY: the generated PADS_BANK0 base, indexed by an owned pin.
        unsafe {
            write32(
                addr::pad(PADS_BANK0_BASE as usize, pin as usize),
                cfg.bits(),
            )
        };
    }

    /// Configure a pin's pad as a push-pull output driver.
    ///
    /// Clears `ISO` on RP2350, which is not optional: pads come out of reset
    /// isolated there, and a pad left isolated is a pin that never moves.
    ///
    /// # Safety
    /// As [`set_function`].
    #[inline]
    pub unsafe fn set_pad_output(pin: u8, drive: Drive) {
        let mut v = 0u32;
        v = set_field(v, pad_field::IE, 1, 1);
        v = set_field(v, pad_field::DRIVE, 2, drive as u32);
        // ISO defaults to 0 in this freshly built value, which is the cleared
        // state RP2350 needs; RP2040 has no such field to write.
        // SAFETY: the generated PADS_BANK0 base, indexed by an owned pin.
        unsafe { write32(addr::pad(PADS_BANK0_BASE as usize, pin as usize), v) };
    }

    /// Address of a SIO `OUT`-block register for `bank`.
    #[inline]
    fn out_reg(reg: SioReg, bank: usize) -> usize {
        addr::sio(
            super::SIO_BASE,
            SIO_GPIO_OUT_BASE as usize,
            reg,
            bank,
            SIO_REG_STRIDE as usize,
            SIO_BANK_STRIDE as usize,
        )
    }

    /// Address of a SIO `OE`-block register for `bank`.
    #[inline]
    fn oe_reg(reg: SioReg, bank: usize) -> usize {
        addr::sio(
            super::SIO_BASE,
            SIO_GPIO_OE_BASE as usize,
            reg,
            bank,
            SIO_REG_STRIDE as usize,
            SIO_BANK_STRIDE as usize,
        )
    }

    /// Drive a pin high or low through SIO's atomic set/clear aliases.
    ///
    /// # Safety
    /// As [`set_function`].
    #[inline]
    pub unsafe fn set_level(pin: u8, high: bool) {
        let (bank, bit) = addr::bank_and_bit(pin);
        let reg = if high { SioReg::Set } else { SioReg::Clr };
        // SAFETY: SIO's OUT block for this silicon's strides; a write-one
        // alias, so only this pin's bit is affected.
        unsafe { write32(out_reg(reg, bank), bit) };
    }

    /// Read a pin's actual electrical level.
    ///
    /// `GPIO_IN`, not the output register: for an input this is the only
    /// answer, and for an output it reports what the pin is really doing
    /// rather than what was requested — which differ when something else is
    /// driving the line.
    ///
    /// # Safety
    /// As [`set_function`].
    #[inline]
    pub unsafe fn read_level(pin: u8) -> bool {
        let (bank, bit) = addr::bank_and_bit(pin);
        let off = if bank == 0 {
            addr::SIO_GPIO_IN
        } else {
            addr::SIO_GPIO_HI_IN
        };
        // SAFETY: SIO's input register; read-only, no side effect.
        unsafe { read32(super::SIO_BASE + off) & bit != 0 }
    }

    /// Read the level a pin is being *driven* to.
    ///
    /// Distinct from [`read_level`]: this is the value written to `GPIO_OUT`,
    /// which is what the driver asked for. Reporting it as the pin's state
    /// would hide a shorted or contended line.
    ///
    /// # Safety
    /// As [`set_function`].
    #[inline]
    pub unsafe fn read_driven_level(pin: u8) -> bool {
        let (bank, bit) = addr::bank_and_bit(pin);
        // SAFETY: SIO's output register, read back.
        unsafe { read32(out_reg(SioReg::Value, bank)) & bit != 0 }
    }

    /// Enable a pin's output driver.
    ///
    /// # Safety
    /// As [`set_function`].
    #[inline]
    pub unsafe fn set_output_enable(pin: u8, on: bool) {
        let (bank, bit) = addr::bank_and_bit(pin);
        let reg = if on { SioReg::Set } else { SioReg::Clr };
        // SAFETY: as `set_level`, on the OE block.
        unsafe { write32(oe_reg(reg, bank), bit) };
    }
}
