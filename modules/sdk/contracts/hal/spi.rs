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
pub use super::super::super::registry::spi::GET_CAPS;
pub use super::super::super::registry::spi::OPEN;
pub use super::super::super::registry::spi::POLL_BYTE;
pub use super::super::super::registry::spi::SET_CS;
pub use super::super::super::registry::spi::TRANSFER_POLL;
pub use super::super::super::registry::spi::TRANSFER_START;

/// Arguments for SPI `OPEN` via `provider_call`.
#[repr(C)]
pub struct OpenArgs {
    pub cs_handle: i32,
    pub freq_hz: u32,
    pub bus: u8,
    pub mode: u8,
    pub _pad: [u8; 2],
}

/// Arguments for SPI `TRANSFER_START` via `provider_call`.
#[repr(C)]
pub struct TransferStartArgs {
    pub tx: *const u8,
    pub rx: *mut u8,
    pub len: u32,
    pub fill: u8,
    pub _pad: [u8; 3],
}
