//! Chip abstraction layer.
//!
//! Constants are generated from silicon TOML `[kernel]` sections by build.rs.
//! Helper functions centralize the remaining PAC API differences.

// Generated constants from silicon TOML (RP targets only — BCM2712 skips this).
#[cfg(feature = "rp")]
include!(concat!(env!("OUT_DIR"), "/chip_generated.rs"));

// BCM2712: provide equivalent constants directly (no chip_generated.rs).
#[cfg(feature = "chip-bcm2712")]
pub const STATE_ARENA_SIZE: usize = 256 * 1024;
#[cfg(feature = "chip-bcm2712")]
pub const BUFFER_ARENA_SIZE: usize = 32 * 1024;
#[cfg(feature = "chip-bcm2712")]
pub const MAX_MODULE_CONFIG_SIZE: usize = 16 * 1024;

// ============================================================================
// RP-specific PAC helpers (not compiled for aarch64)
// ============================================================================

#[cfg(feature = "rp")]
use embassy_rp::pac;

/// Write DMA transfer count. RP2350 has MODE+COUNT fields; RP2040 is plain u32.
#[cfg(feature = "rp")]
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
#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
macro_rules! pad_set_iso_false {
    ($w:expr) => { $w.set_iso(false) };
}

#[cfg(feature = "chip-rp2040")]
macro_rules! pad_set_iso_false {
    ($w:expr) => { };
}

#[cfg(feature = "rp")]
pub(crate) use pad_set_iso_false;

/// Get hardware timer. RP2350: TIMER0, RP2040: TIMER.
#[cfg(feature = "rp")]
#[inline(always)]
pub fn timer() -> pac::timer::Timer {
    #[cfg(not(feature = "chip-rp2040"))]
    { pac::TIMER0 }
    #[cfg(feature = "chip-rp2040")]
    { pac::TIMER }
}

/// Get PAC PIO instance by index.
#[cfg(feature = "rp")]
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
#[cfg(feature = "rp")]
#[inline(always)]
pub const fn has_pio_gpiobase() -> bool {
    !IS_RP2040
}
