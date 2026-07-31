// HAL contract: SPI.
//
// Layer: contracts/hal (public, stable).
//
// Portable SPI operations with async transfer start/poll. Chip backings
// live in `platform/<chip>/*`.

pub const OPEN: u32 = 0x0200;
pub const CLOSE: u32 = 0x0201;
pub const BEGIN: u32 = 0x0202;
pub const END: u32 = 0x0203;
pub const SET_CS: u32 = 0x0204;
pub const CLAIM: u32 = 0x0205;
pub const CONFIGURE: u32 = 0x0206;
pub const TRANSFER_START: u32 = 0x0207;
pub const TRANSFER_POLL: u32 = 0x0208;
pub const POLL_BYTE: u32 = 0x0209;
pub const GET_CAPS: u32 = 0x020A;

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
