// HAL contract: SPI.
//
// Layer: contracts/hal (public, stable).
//
// Portable SPI operations with async transfer start/poll. Chip backings
// live in `platform/<chip>/*`.

pub use super::super::super::registry::spi::BEGIN;
pub use super::super::super::registry::spi::CLAIM;
pub use super::super::super::registry::spi::CLOSE;
pub use super::super::super::registry::spi::CONFIGURE;
pub use super::super::super::registry::spi::END;
pub use super::super::super::registry::spi::OPEN;
pub use super::super::super::registry::spi::POLL_BYTE;
pub use super::super::super::registry::spi::SET_CS;
pub use super::super::super::registry::spi::TRANSFER_POLL;
pub use super::super::super::registry::spi::TRANSFER_START;

/// The SPI modes this controller drives, as the [`caps`] word. `handle = -1`
/// (or a bound handle); `arg` out is exactly 4 bytes, the `u32` LE word; no
/// `data`. Returns 0. Every provider implements it; `ENOSYS` from `CAPS`
/// means there is no provider. A caller opens or configures a mode only
/// when its bit is set.
pub use super::super::super::registry::spi::CAPS;

/// [`CAPS`] bits: bit `m` for SPI mode `m` (CPOL = m >> 1, CPHA = m & 1).
pub mod caps {
    pub const MODE0: u32 = 1 << 0;
    pub const MODE1: u32 = 1 << 1;
    pub const MODE2: u32 = 1 << 2;
    pub const MODE3: u32 = 1 << 3;
}

/// The controller's clock ceiling. `handle = -1` (or a bound handle); `arg`
/// out is exactly [`describe::LEN`] bytes, `[max_freq_hz: u32 LE]`; no
/// `data`. Returns 0.
pub use super::super::super::registry::spi::DESCRIBE;

/// [`DESCRIBE`]'s answer record.
pub mod describe {
    /// Exact length, in bytes.
    pub const LEN: usize = 4;
    /// `u32` LE — the highest SCK frequency the controller drives, in Hz.
    pub const MAX_FREQ_HZ: usize = 0;
}

/// SPI `OPEN`'s argument: `[bus u8][cs_pin u8][mode u8][0 u8][freq_hz u32]`.
/// The provider claims the chip-select pin itself as part of the claim
/// (`cs_pin` [`open::NO_CS`]: the device's chip select is the caller's
/// concern, or the controller's own).
pub mod open {
    /// Exact length, in bytes.
    pub const ARG_LEN: usize = 8;
    /// `cs_pin` for no chip-select pin.
    pub const NO_CS: u8 = 0xFF;

    /// A decoded `OPEN` argument.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Open {
        pub bus: u8,
        pub cs_pin: u8,
        pub mode: u8,
        pub freq_hz: u32,
    }

    pub const fn encode(o: &Open) -> [u8; ARG_LEN] {
        let f = o.freq_hz.to_le_bytes();
        [o.bus, o.cs_pin, o.mode, 0, f[0], f[1], f[2], f[3]]
    }

    /// `None` unless `arg` is exactly one argument.
    pub fn parse(arg: &[u8]) -> Option<Open> {
        let b: &[u8; ARG_LEN] = arg.try_into().ok()?;
        Some(Open {
            bus: b[0],
            cs_pin: b[1],
            mode: b[2],
            freq_hz: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        })
    }
}

/// `TRANSFER_START` argument: `[lend u32][offset u32][len u32][fill u8]`.
///
/// `handle` is the caller's SPI handle. The transfer runs over `len` bytes
/// at `offset` in a span the caller lent on that handle (`lend::OPEN`), and
/// the lend's direction is the transfer's: an in lend (the provider reads it)
/// is transmitted and what comes back is discarded; an out lend (the
/// provider writes it) receives while `fill` is transmitted; an inout lend
/// is full duplex in place — each byte sent is replaced by the byte
/// received. The span is the provider's until `TRANSFER_POLL` (or
/// `POLL_BYTE`) reports the transfer finished.
pub mod transfer_start {
    /// `u32` LE — the lend's cookie.
    pub const LEND: usize = 0;
    /// `u32` LE — offset of the bytes inside the lend.
    pub const OFFSET: usize = 4;
    /// `u32` LE — bytes to clock.
    pub const LEN: usize = 8;
    /// `u8` — the byte transmitted under an out lend.
    pub const FILL: usize = 12;
    /// Total length, in bytes.
    pub const ARG_LEN: usize = 13;

    pub const fn encode(lend: u32, offset: u32, len: u32, fill: u8) -> [u8; ARG_LEN] {
        let l = lend.to_le_bytes();
        let o = offset.to_le_bytes();
        let n = len.to_le_bytes();
        [
            l[0], l[1], l[2], l[3], o[0], o[1], o[2], o[3], n[0], n[1], n[2], n[3], fill,
        ]
    }

    /// `(lend, offset, len, fill)` from an argument.
    pub fn decode(arg: &[u8]) -> Option<(u32, u32, u32, u8)> {
        let f = |at: usize| -> Option<u32> {
            Some(u32::from_le_bytes(arg.get(at..at + 4)?.try_into().ok()?))
        };
        Some((f(LEND)?, f(OFFSET)?, f(LEN)?, *arg.get(FILL)?))
    }
}
