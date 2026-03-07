//! Chip abstraction layer.
//!
//! Constants are generated from silicon TOML `[kernel]` sections by build.rs.
//! Helper functions centralize the remaining PAC API differences between
//! RP2040 and RP2350.

use embassy_rp::pac;

// Generated constants from silicon TOML.
include!(concat!(env!("OUT_DIR"), "/chip_generated.rs"));

// ============================================================================
// DMA trans_count
// ============================================================================

/// Write DMA transfer count. RP2350 has MODE+COUNT fields; RP2040 is plain u32.
#[inline(always)]
pub fn dma_write_trans_count(ch: &pac::dma::Channel, count: u32) {
    #[cfg(not(feature = "chip-rp2040"))]
    ch.trans_count().write(|w| {
        w.set_mode(0.into());
        w.set_count(count);
    });
    #[cfg(feature = "chip-rp2040")]
    ch.trans_count().write_value(count);
}

// ============================================================================
// PAD ISO field
// ============================================================================

/// Clear pad ISO on RP2350. No-op on RP2040 (field doesn't exist).
/// Use inside `pac::PADS_BANK0.gpio(n).write(|w| { chip::pad_set_iso_false!(w); ... })`.
#[cfg(not(feature = "chip-rp2040"))]
macro_rules! pad_set_iso_false {
    ($w:expr) => { $w.set_iso(false) };
}

#[cfg(feature = "chip-rp2040")]
macro_rules! pad_set_iso_false {
    ($w:expr) => { };
}

pub(crate) use pad_set_iso_false;

// ============================================================================
// Timer peripheral
// ============================================================================

/// Get hardware timer. RP2350: TIMER0, RP2040: TIMER.
#[inline(always)]
pub fn timer() -> pac::timer::Timer {
    #[cfg(not(feature = "chip-rp2040"))]
    { pac::TIMER0 }
    #[cfg(feature = "chip-rp2040")]
    { pac::TIMER }
}

// ============================================================================
// PIO PAC
// ============================================================================

/// Get PAC PIO instance by index. RP2350 has PIO2; RP2040 does not.
#[inline(always)]
pub fn pio_pac(idx: u8) -> pac::pio::Pio {
    match idx {
        0 => pac::PIO0,
        1 => pac::PIO1,
        #[cfg(not(feature = "chip-rp2040"))]
        _ => pac::PIO2,
        #[cfg(feature = "chip-rp2040")]
        _ => pac::PIO0,
    }
}

/// Whether PIO GPIOBASE register is available.
#[inline(always)]
pub const fn has_pio_gpiobase() -> bool {
    !IS_RP2040
}
