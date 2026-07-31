// Platform: RP I2C register bridge.
//
// Layer: platform/rp (chip-specific, unstable).
//
// Used by the i2c_dw PIC provider module.

pub const REG_WRITE: u32 = 0x0CB0;
pub const REG_READ: u32 = 0x0CB1;
pub const BUS_INFO: u32 = 0x0CB2;
pub const PIN_INIT: u32 = 0x0CB3;
pub const SET_ENABLE: u32 = 0x0CB4;
