//! Chip abstraction layer — RP targets.
//!
//! Constants are generated from silicon TOML `[kernel]` sections by build.rs.
//! Helper functions centralize the remaining PAC API differences.

// Generated constants from silicon TOML (RP targets only).
include!(concat!(env!("OUT_DIR"), "/chip_generated.rs"));

use embassy_rp::pac;

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

/// Clear pad ISO on RP2350. No-op on RP2040 (field doesn't exist).
#[cfg(not(feature = "chip-rp2040"))]
macro_rules! pad_set_iso_false {
    ($w:expr) => {
        $w.set_iso(false)
    };
}

#[cfg(feature = "chip-rp2040")]
macro_rules! pad_set_iso_false {
    ($w:expr) => {};
}

pub(crate) use pad_set_iso_false;

/// Get hardware timer. RP2350: TIMER0, RP2040: TIMER.
#[inline(always)]
pub fn timer() -> pac::timer::Timer {
    #[cfg(not(feature = "chip-rp2040"))]
    {
        pac::TIMER0
    }
    #[cfg(feature = "chip-rp2040")]
    {
        pac::TIMER
    }
}

/// Get PAC PIO instance by index.
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
