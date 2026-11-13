// Platform: RP UART register bridge.
//
// Layer: platform/rp (chip-specific, unstable).
//
// Used by the uart_pl011 PIC provider module.

pub use super::super::super::registry::rp_raw::UART_PIN_INIT as PIN_INIT;
pub use super::super::super::registry::rp_raw::UART_REG_READ as REG_READ;
pub use super::super::super::registry::rp_raw::UART_REG_WRITE as REG_WRITE;
pub use super::super::super::registry::rp_raw::UART_SET_ENABLE as SET_ENABLE;
