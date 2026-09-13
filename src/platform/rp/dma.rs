//! RP DMA channel registers — the parts the kernel touches directly.
//!
//! The allocator in `rp_providers` hands out channel *numbers*; this module
//! is the register view of a channel, and exists mainly for one operation:
//! proving that no channel is reading out of flash before flash is erased.
//!
//! # Why this is its own module
//!
//! Flash erase and the BOOTSEL read both need the same guarantee, and both
//! had their own copy of the loop that establishes it. The copies had drifted
//! — one iterated a hardcoded sixteen channels, which on RP2040 reads four
//! channels the die does not implement — and a divergence in a safety
//! precondition is worth more than the duplication it saves.

/// Address arithmetic for the DMA block, separated from register access so
/// it can be checked on a host.
///
/// Channels are a flat array of four-word control blocks. Getting the stride
/// wrong does not fault: it reads a neighbouring channel's registers and
/// reports *that* channel's business, which is the wrong answer delivered
/// confidently.
pub mod addr {
    /// Bytes per channel control block: READ_ADDR, WRITE_ADDR, TRANS_COUNT,
    /// CTRL_TRIG.
    pub const CHANNEL_STRIDE: usize = 0x40;
    /// `READ_ADDR` within a channel block.
    pub const READ_ADDR: usize = 0x00;
    /// `WRITE_ADDR` within a channel block.
    pub const WRITE_ADDR: usize = 0x04;
    /// `TRANS_COUNT` within a channel block.
    pub const TRANS_COUNT: usize = 0x08;
    /// `CTRL_TRIG` within a channel block. Writing it starts the transfer,
    /// which is why every other field must already be set.
    pub const CTRL_TRIG: usize = 0x0c;
    /// `AL1_CTRL` — the same control register without the trigger side
    /// effect, for reading or editing a live channel's configuration.
    pub const AL1_CTRL: usize = 0x10;
    /// `AL3_TRANS_COUNT`, paired with [`AL3_READ_ADDR_TRIG`].
    pub const AL3_TRANS_COUNT: usize = 0x38;
    /// `AL3_READ_ADDR_TRIG` — writing it re-triggers the channel, so it must
    /// be written last.
    pub const AL3_READ_ADDR_TRIG: usize = 0x3c;

    /// Address of a channel register at `reg` within the block.
    #[inline]
    pub const fn channel_reg(base: usize, ch: usize, reg: usize) -> usize {
        base + ch * CHANNEL_STRIDE + reg
    }

    /// Address of channel `ch`'s `READ_ADDR`.
    #[inline]
    pub const fn read_addr(base: usize, ch: usize) -> usize {
        channel_reg(base, ch, READ_ADDR)
    }

    /// Address of channel `ch`'s `CTRL_TRIG`.
    #[inline]
    pub const fn ctrl_trig(base: usize, ch: usize) -> usize {
        channel_reg(base, ch, CTRL_TRIG)
    }
}

/// `STREAM_CTR` within the XIP control block — the count of words the XIP
/// stream engine has still to deliver. Same offset on both chips; the *base*
/// is not, which is why it is generated.
pub const XIP_STREAM_CTR: usize = 0x18;

/// The first SRAM address. A channel whose read pointer is below this is
/// sourcing from flash (XIP) and must finish before flash is disturbed.
pub const SRAM_LOWER: u32 = 0x2000_0000;

/// Whether a channel's read pointer means it is sourcing from flash.
///
/// Split out from the polling loop so the comparison is host-testable: the
/// boundary case (`read_addr == SRAM_LOWER` is *not* a flash reader) is the
/// kind of off-by-one that would otherwise only show up as a rare corruption
/// during an erase.
#[inline]
pub const fn reads_from_flash(read_addr: u32) -> bool {
    read_addr < SRAM_LOWER
}

/// Spin budget for [`quiesce_flash_readers`], in poll iterations.
///
/// Generous: a legitimate in-flight transfer is thousands of cycles, and the
/// cost of expiring early is a spurious write failure. What matters is that a
/// bound exists at all — the previous code had none.
pub const QUIESCE_LIMIT: u32 = 1_000_000;

/// Wait until nothing is reading out of flash.
///
/// Every DMA channel whose read pointer is in the XIP window is allowed to
/// finish, then the XIP stream engine is drained. **The caller must already
/// have interrupts disabled** — otherwise a channel can be re-armed between
/// this returning and the erase starting, and the guarantee is worthless.
///
/// Bounded: a channel wired to a peripheral that has stopped
/// producing never clears `BUSY`, and an unbounded wait here is a hang inside
/// a critical section with no watchdog left to notice it. On expiry this
/// returns `false` and the caller must refuse the erase — proceeding would
/// erase flash underneath a live read.
#[cfg(feature = "rp")]
#[must_use]
pub fn quiesce_flash_readers(limit: u32) -> bool {
    use crate::platform::chip::{DMA_BASE, DMA_CHANNELS, DMA_CTRL_BUSY_LSB, XIP_CTRL_BASE};
    use crate::platform::rp_regs::{read32, wait_until};

    let base = DMA_BASE as usize;
    let busy = 1u32 << DMA_CTRL_BUSY_LSB;

    for ch in 0..DMA_CHANNELS as usize {
        // SAFETY: `ch` is bounded by the generated channel count, so both
        // addresses are inside this silicon's implemented DMA block.
        let still_reading = || unsafe {
            reads_from_flash(read32(addr::read_addr(base, ch)))
                && (read32(addr::ctrl_trig(base, ch)) & busy) != 0
        };
        if !wait_until(limit, || !still_reading()) {
            return false;
        }
    }

    // SAFETY: generated base for this silicon's XIP control block.
    wait_until(limit, || unsafe {
        read32(XIP_CTRL_BASE as usize + XIP_STREAM_CTR) == 0
    })
}

// ============================================================================
// Channel configuration
// ============================================================================

/// Transfer width, as the hardware's `DATA_SIZE` encoding.
///
/// The encoding is shared by both chips even though the field's *position*
/// is not, which is the general shape of the RP variant story: the meanings
/// are stable, the layout moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DataSize {
    /// One byte per transfer.
    Byte = 0,
    /// Two bytes per transfer.
    HalfWord = 1,
    /// Four bytes per transfer.
    Word = 2,
}

/// A channel's `CTRL_TRIG` value, built field by field.
///
/// Every setter goes through [`set_field`](crate::platform::rp_regs::set_field)
/// with a generated position, so a field can only ever be written where this
/// silicon actually has it. Values wider than their field are masked rather
/// than allowed to spill into a neighbour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CtrlTrig(pub u32);

#[cfg(feature = "rp")]
impl CtrlTrig {
    /// Set the channel enable bit.
    #[must_use]
    pub const fn enable(self, on: bool) -> Self {
        use crate::platform::chip::{DMA_CTRL_EN_LSB, DMA_CTRL_EN_WIDTH};
        Self(crate::platform::rp_regs::set_field(
            self.0,
            DMA_CTRL_EN_LSB,
            DMA_CTRL_EN_WIDTH,
            on as u32,
        ))
    }

    /// Set the transfer width.
    #[must_use]
    pub const fn data_size(self, size: DataSize) -> Self {
        use crate::platform::chip::{DMA_CTRL_DATA_SIZE_LSB, DMA_CTRL_DATA_SIZE_WIDTH};
        Self(crate::platform::rp_regs::set_field(
            self.0,
            DMA_CTRL_DATA_SIZE_LSB,
            DMA_CTRL_DATA_SIZE_WIDTH,
            size as u32,
        ))
    }

    /// Whether the read pointer advances.
    #[must_use]
    pub const fn incr_read(self, on: bool) -> Self {
        use crate::platform::chip::{DMA_CTRL_INCR_READ_LSB, DMA_CTRL_INCR_READ_WIDTH};
        Self(crate::platform::rp_regs::set_field(
            self.0,
            DMA_CTRL_INCR_READ_LSB,
            DMA_CTRL_INCR_READ_WIDTH,
            on as u32,
        ))
    }

    /// Whether the write pointer advances.
    #[must_use]
    pub const fn incr_write(self, on: bool) -> Self {
        use crate::platform::chip::{DMA_CTRL_INCR_WRITE_LSB, DMA_CTRL_INCR_WRITE_WIDTH};
        Self(crate::platform::rp_regs::set_field(
            self.0,
            DMA_CTRL_INCR_WRITE_LSB,
            DMA_CTRL_INCR_WRITE_WIDTH,
            on as u32,
        ))
    }

    /// The transfer-request source that paces this channel.
    #[must_use]
    pub const fn treq_sel(self, dreq: u8) -> Self {
        use crate::platform::chip::{DMA_CTRL_TREQ_SEL_LSB, DMA_CTRL_TREQ_SEL_WIDTH};
        Self(crate::platform::rp_regs::set_field(
            self.0,
            DMA_CTRL_TREQ_SEL_LSB,
            DMA_CTRL_TREQ_SEL_WIDTH,
            dreq as u32,
        ))
    }

    /// The channel to trigger on completion. Pointing a channel at itself is
    /// the idiom for "chain to nothing".
    #[must_use]
    pub const fn chain_to(self, ch: u8) -> Self {
        use crate::platform::chip::{DMA_CTRL_CHAIN_TO_LSB, DMA_CTRL_CHAIN_TO_WIDTH};
        Self(crate::platform::rp_regs::set_field(
            self.0,
            DMA_CTRL_CHAIN_TO_LSB,
            DMA_CTRL_CHAIN_TO_WIDTH,
            ch as u32,
        ))
    }

    /// Whether the channel is mid-transfer.
    #[must_use]
    pub const fn busy(self) -> bool {
        use crate::platform::chip::DMA_CTRL_BUSY_LSB;
        (self.0 >> DMA_CTRL_BUSY_LSB) & 1 != 0
    }
}

/// Whether `ch` is a channel this silicon implements.
///
/// The bound is the generated channel count, not a literal. Four call sites
/// tested `ch > 15`, which on RP2040 admits four channels the die does not
/// have — writes that go nowhere and reads that return nothing.
#[cfg(feature = "rp")]
#[inline]
pub fn is_implemented(ch: u8) -> bool {
    (ch as usize) < crate::platform::chip::DMA_CHANNELS as usize
}

/// Encode a `TRANS_COUNT` value for this silicon.
///
/// RP2350 splits the register into a MODE field and a count; RP2040 is a
/// plain 32-bit count. Mode 0 is NORMAL on RP2350, so the encodings agree
/// numerically — but only because the mode we want happens to be zero, which
/// is not a property worth relying on silently.
#[cfg(feature = "rp")]
#[inline]
pub const fn trans_count(count: u32) -> u32 {
    #[cfg(not(feature = "chip-rp2040"))]
    {
        use crate::platform::chip::{DMA_TRANS_COUNT_MODE_LSB, DMA_TRANS_COUNT_MODE_WIDTH};
        crate::platform::rp_regs::set_field(
            count,
            DMA_TRANS_COUNT_MODE_LSB,
            DMA_TRANS_COUNT_MODE_WIDTH,
            0, // NORMAL
        )
    }
    #[cfg(feature = "chip-rp2040")]
    {
        count
    }
}

/// Abort a channel and wait for it to stop.
///
/// Bounded, as [`quiesce_flash_readers`]: the previous implementation spun
/// forever on `BUSY`, so a channel that never acknowledged the abort hung the
/// caller. Returns whether the channel actually stopped.
#[cfg(feature = "rp")]
#[must_use]
pub fn abort(ch: u8, limit: u32) -> bool {
    use crate::platform::chip::{DMA_BASE, DMA_CHAN_ABORT_OFFSET};
    use crate::platform::rp_regs::{read32, wait_until, write32};

    let base = DMA_BASE as usize;
    // SAFETY: caller has checked `ch` against `is_implemented`; the abort
    // register offset is generated for this silicon.
    unsafe { write32(base + DMA_CHAN_ABORT_OFFSET as usize, 1u32 << ch) };
    wait_until(limit, || {
        // SAFETY: as above.
        !CtrlTrig(unsafe { read32(addr::ctrl_trig(base, ch as usize)) }).busy()
    })
}
