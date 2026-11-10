// Platform: RP SPI register bridge.
//
// Layer: platform/rp (chip-specific, unstable).
//
// Used by the spi_pl022 PIC provider module. Portable consumers
// should call the HAL SPI contract (`contracts/hal/spi.rs`) instead.

pub use super::super::super::registry::rp_raw::SPI_BUS_INFO as BUS_INFO;
pub use super::super::super::registry::rp_raw::SPI_PIN_INIT as PIN_INIT;
pub use super::super::super::registry::rp_raw::SPI_REG_READ as REG_READ;
pub use super::super::super::registry::rp_raw::SPI_REG_WRITE as REG_WRITE;
pub use super::super::super::registry::rp_raw::SPI_SET_ENABLE as SET_ENABLE;
