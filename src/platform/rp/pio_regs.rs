//! RP PIO registers.
//!
//! Unusually for this peripheral family, the two chips agree on the register
//! layout: same offsets, same field positions, same strides. What differs is
//! how many PIO instances exist — RP2040 has two, RP2350 has three — and that
//! RP2350 adds a `GPIOBASE` register RP2040 has no equivalent for.
//!
//! The instance count is the part that had gone wrong. Every syscall in the
//! PIO bridge tested `pio_num > 2`, which admits PIO2, and the RP2040 index
//! mapping sent that to **PIO0** rather than refusing: asking for a PIO the
//! die does not have silently drove a different one.

/// Address arithmetic, host-testable.
pub mod addr {
    /// PIO instances are 1 MiB apart.
    pub const INSTANCE_STRIDE: usize = 0x0010_0000;
    /// Bytes per state machine: CLKDIV, EXECCTRL, SHIFTCTRL, ADDR, INSTR,
    /// PINCTRL.
    pub const SM_STRIDE: usize = 0x18;
    /// First state machine's register block.
    pub const SM0: usize = 0xc8;

    /// `CTRL`.
    pub const CTRL: usize = 0x00;
    /// `FSTAT`.
    pub const FSTAT: usize = 0x04;
    /// First TX FIFO; one word per state machine.
    pub const TXF0: usize = 0x10;
    /// First RX FIFO; one word per state machine.
    pub const RXF0: usize = 0x20;
    /// Instruction memory; 32 words.
    pub const INSTR_MEM0: usize = 0x48;
    /// `INPUT_SYNC_BYPASS` — one bit per GPIO.
    pub const INPUT_SYNC_BYPASS: usize = 0x38;
    /// `GPIOBASE` — RP2350 only.
    pub const GPIOBASE: usize = 0x168;

    /// Registers within a state machine's block, in the order the syscall
    /// bridge indexes them.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(usize)]
    pub enum SmReg {
        /// Clock divider.
        ClkDiv = 0,
        /// Execution control.
        ExecCtrl = 1,
        /// Shift control.
        ShiftCtrl = 2,
        /// Pin mapping.
        PinCtrl = 3,
        /// Current instruction address (read-only).
        Addr = 4,
        /// Instruction to execute immediately.
        Instr = 5,
    }

    impl SmReg {
        /// Byte offset within the state machine's block.
        ///
        /// The hardware order is CLKDIV, EXECCTRL, SHIFTCTRL, ADDR, INSTR,
        /// PINCTRL — which is *not* the order the syscall bridge numbers
        /// them, so this mapping is deliberate rather than `idx * 4`.
        #[inline]
        pub const fn byte_offset(self) -> usize {
            match self {
                SmReg::ClkDiv => 0x00,
                SmReg::ExecCtrl => 0x04,
                SmReg::ShiftCtrl => 0x08,
                SmReg::Addr => 0x0c,
                SmReg::Instr => 0x10,
                SmReg::PinCtrl => 0x14,
            }
        }

        /// The register the syscall bridge's `reg` byte names, if any.
        #[inline]
        pub const fn from_syscall(reg: u8) -> Option<Self> {
            match reg {
                0 => Some(SmReg::ClkDiv),
                1 => Some(SmReg::ExecCtrl),
                2 => Some(SmReg::ShiftCtrl),
                3 => Some(SmReg::PinCtrl),
                4 => Some(SmReg::Addr),
                _ => None,
            }
        }
    }

    /// Base address of PIO instance `idx`.
    #[inline]
    pub const fn instance(pio0_base: usize, idx: usize) -> usize {
        pio0_base + idx * INSTANCE_STRIDE
    }

    /// Address of state machine `sm`'s register `reg` in instance `base`.
    #[inline]
    pub const fn sm_reg(base: usize, sm: usize, reg: SmReg) -> usize {
        base + SM0 + sm * SM_STRIDE + reg.byte_offset()
    }

    /// Address of state machine `sm`'s TX FIFO.
    #[inline]
    pub const fn txf(base: usize, sm: usize) -> usize {
        base + TXF0 + sm * 4
    }

    /// Address of state machine `sm`'s RX FIFO.
    #[inline]
    pub const fn rxf(base: usize, sm: usize) -> usize {
        base + RXF0 + sm * 4
    }

    /// Address of instruction-memory word `slot`.
    #[inline]
    pub const fn instr_mem(base: usize, slot: usize) -> usize {
        base + INSTR_MEM0 + slot * 4
    }
}

/// `CTRL` field positions. Shared by both chips.
pub mod ctrl {
    /// `SM_ENABLE`, one bit per state machine.
    pub const SM_ENABLE_LSB: u32 = 0;
    /// `SM_RESTART`, write-one-to-restart.
    pub const SM_RESTART_LSB: u32 = 4;
    /// `CLKDIV_RESTART`, write-one-to-restart.
    pub const CLKDIV_RESTART_LSB: u32 = 8;
    /// Every field here is four bits: one per state machine.
    pub const WIDTH: u32 = 4;
}

/// State machines per PIO instance. Four on both chips.
pub const STATE_MACHINES: usize = 4;

/// Instruction-memory words per PIO instance. Thirty-two on both chips.
pub const INSTR_SLOTS: usize = 32;

#[cfg(feature = "rp")]
pub use rp::*;

#[cfg(feature = "rp")]
mod rp {
    use super::addr::{self, SmReg};
    use super::{ctrl, INSTR_SLOTS, STATE_MACHINES};
    use crate::platform::chip::{PIO0_BASE, PIO_COUNT};
    use crate::platform::rp_regs::{modify32, read32, set_field, write32};

    /// Base address of PIO instance `idx`, or `None` if this silicon does not
    /// have it.
    ///
    /// **The refusal is the point.** RP2040 has two PIO instances and RP2350
    /// has three; accepting index 2 on both would leave the RP2040
    /// mapping sent it to PIO0, so a graph asking for a PIO that is not there
    /// quietly reconfigured the one driving something else.
    #[inline]
    pub fn instance(idx: u8) -> Option<usize> {
        if (idx as usize) < PIO_COUNT as usize {
            Some(addr::instance(PIO0_BASE as usize, idx as usize))
        } else {
            None
        }
    }

    /// Whether `sm` names a state machine.
    #[inline]
    pub const fn is_state_machine(sm: u8) -> bool {
        (sm as usize) < STATE_MACHINES
    }

    /// Whether `slot` names an instruction-memory word.
    #[inline]
    pub const fn is_instr_slot(slot: u8) -> bool {
        (slot as usize) < INSTR_SLOTS
    }

    /// Write a state machine's configuration register.
    ///
    /// # Safety
    /// `base` must come from [`instance`] and `sm` must satisfy
    /// [`is_state_machine`].
    #[inline]
    pub unsafe fn write_sm_reg(base: usize, sm: u8, reg: SmReg, value: u32) {
        // SAFETY: the caller's contract — `base` from `instance`, `sm` a
        // real state machine on this silicon.
        unsafe { write32(addr::sm_reg(base, sm as usize, reg), value) };
    }

    /// Read a state machine's configuration register.
    ///
    /// # Safety
    /// As [`write_sm_reg`].
    #[inline]
    pub unsafe fn read_sm_reg(base: usize, sm: u8, reg: SmReg) -> u32 {
        // SAFETY: the caller's contract — `base` from `instance`, `sm` a
        // real state machine on this silicon.
        unsafe { read32(addr::sm_reg(base, sm as usize, reg)) }
    }

    /// Enable or disable the state machines named by `mask`, leaving the rest
    /// as they are.
    ///
    /// # Safety
    /// `base` must come from [`instance`].
    #[inline]
    pub unsafe fn set_enabled(base: usize, mask: u8, enable: bool) {
        let bits = (mask as u32 & 0x0f) << ctrl::SM_ENABLE_LSB;
        // CTRL is a plain read/write register, and the other fields in it are
        // write-one-to-restart pulses that read back as zero — so a
        // read-modify-write here does not re-trigger them.
        //
        // SAFETY: `base` comes from `instance`, so CTRL is this instance's.
        unsafe {
            modify32(
                base + addr::CTRL,
                |v| {
                    if enable {
                        v | bits
                    } else {
                        v & !bits
                    }
                },
            )
        };
    }

    /// Restart the state machines named by `mask`, and their clock dividers.
    ///
    /// # Safety
    /// `base` must come from [`instance`].
    #[inline]
    pub unsafe fn restart(base: usize, mask: u8) {
        let m = mask as u32 & 0x0f;
        // SAFETY: `base` comes from `instance`, so CTRL is this instance's.
        unsafe {
            modify32(base + addr::CTRL, |v| {
                let v = set_field(v, ctrl::SM_RESTART_LSB, ctrl::WIDTH, m);
                set_field(v, ctrl::CLKDIV_RESTART_LSB, ctrl::WIDTH, m)
            })
        };
    }
}
