// HAL contract: I2C.
//
// Layer: contracts/hal (public, stable).

pub const OPEN: u32 = 0x0300;
pub const CLOSE: u32 = 0x0301;
pub const WRITE: u32 = 0x0302;
pub const READ: u32 = 0x0303;
pub const WRITE_READ: u32 = 0x0304;
pub const CLAIM: u32 = 0x0305;
pub const RELEASE: u32 = 0x0306;
pub const GET_CAPS: u32 = 0x0307;
