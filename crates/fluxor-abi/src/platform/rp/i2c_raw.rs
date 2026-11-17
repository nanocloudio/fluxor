// Platform: RP I2C register bridge.
//
// Layer: platform/rp (chip-specific, unstable).
//
// Used by the i2c_dw PIC provider module.

/// The claimed bus's DMA pacing: arg out `[tx_dreq u8][rx_dreq u8][0 u16]`
/// (4 bytes). A transfer names its FIFO by DREQ.
pub use super::super::super::registry::rp_raw::I2C_BUS_INFO as BUS_INFO;
pub use super::super::super::registry::rp_raw::I2C_PIN_INIT as PIN_INIT;
pub use super::super::super::registry::rp_raw::I2C_REG_READ as REG_READ;
pub use super::super::super::registry::rp_raw::I2C_REG_WRITE as REG_WRITE;
pub use super::super::super::registry::rp_raw::I2C_SET_ENABLE as SET_ENABLE;
