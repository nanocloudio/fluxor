// Platform: RP UART register bridge.
//
// Layer: platform/rp (chip-specific, unstable).
//
// Used by the uart_pl011 PIC provider module.

pub const REG_WRITE: u32 = 0x0CC0;
pub const REG_READ: u32 = 0x0CC1;
pub const PIN_INIT: u32 = 0x0CC2;
pub const SET_ENABLE: u32 = 0x0CC3;
