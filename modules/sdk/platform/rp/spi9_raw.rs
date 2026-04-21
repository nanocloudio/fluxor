// Platform: RP 9-bit SPI bit-bang raw bridge.
//
// Layer: platform/rp (chip-specific, unstable).
//
// Used by the ST7701S display driver (9-bit SPI command mode).

/// Send a 9-bit SPI command + data block.
/// handle=-1, arg=[cs:u8, sck:u8, sda:u8, cmd:u8, data_len:u8, data[0..data_len]].
/// Total arg_len = 5 + data_len. Drives SIO pins directly via PAC.
pub const SEND: u32 = 0x0C90;
/// Execute 9-bit SPI reset sequence.
/// handle=-1, arg=[rst:u8, cs:u8, sck:u8, sda:u8] (4 bytes).
/// RST high 20ms → low 20ms → high 200ms, then inits SIO pins.
pub const RESET: u32 = 0x0C91;
/// Set 9-bit SPI CS pin level explicitly.
/// handle=-1, arg=[cs_pin:u8, level:u8] (2 bytes). level: 0=low, 1=high.
/// Used to hold CS low across delays (e.g. SLEEP_OUT 120ms).
pub const CS_SET: u32 = 0x0C92;
