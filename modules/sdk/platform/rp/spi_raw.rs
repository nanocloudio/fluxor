// Platform: RP SPI register bridge.
//
// Layer: platform/rp (chip-specific, unstable).
//
// Used by the spi_pl022 PIC provider module. Portable consumers
// should call the HAL SPI contract (`contracts/hal/spi.rs`) instead.

pub const REG_WRITE: u32 = 0x0CA0;
pub const REG_READ: u32 = 0x0CA1;
pub const BUS_INFO: u32 = 0x0CA2;
pub const PIN_INIT: u32 = 0x0CA3;
pub const SET_ENABLE: u32 = 0x0CA4;
