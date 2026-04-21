// HAL contract: PIO (Programmable I/O).
//
// Layer: contracts/hal (public, stable).
//
// PIO is RP-specific hardware, but the stream / cmd abstraction is
// chip-agnostic. Portable modules use the opcodes below; the raw
// register escape hatch (`PIO_SM_EXEC`, `PIO_INSTR_WRITE`, …) lives in
// `platform/rp/pio_raw.rs`.

// Streaming (unidirectional, continuous DMA — I2S, LED strips, etc.)
pub const STREAM_ALLOC: u32 = 0x0400;
pub const STREAM_LOAD_PROGRAM: u32 = 0x0401;
pub const STREAM_GET_BUFFER: u32 = 0x0402;
pub const STREAM_CONFIGURE: u32 = 0x0403;
pub const STREAM_CAN_PUSH: u32 = 0x0404;
pub const STREAM_PUSH: u32 = 0x0405;
pub const STREAM_FREE: u32 = 0x0406;
pub const STREAM_TIME: u32 = 0x0407;
pub const DIRECT_BUFFER: u32 = 0x0408;
pub const DIRECT_PUSH: u32 = 0x0409;
/// Program load status: 0=none, 1=pending, 2=loaded, 3=error.
pub const PROGRAM_STATUS: u32 = 0x040A;
/// Set consumption rate (units/sec, Q16.16 fixed point). arg = &u32.
pub const STREAM_SET_RATE: u32 = 0x040B;

// Command/response (bidirectional, discrete transfers — gSPI, etc.)
pub const CMD_ALLOC: u32 = 0x0410;
pub const CMD_LOAD_PROGRAM: u32 = 0x0411;
pub const CMD_CONFIGURE: u32 = 0x0412;
/// Synchronous transfer: executes PIO DMA inline (PAC-level busy-wait).
/// Returns total bytes on success, negative errno on error.
pub const CMD_TRANSFER: u32 = 0x0413;
pub const CMD_POLL: u32 = 0x0414;
pub const CMD_FREE: u32 = 0x0415;

// RX Stream (unidirectional input, continuous DMA capture — mic, ADC streams, etc.)
pub const RX_STREAM_ALLOC: u32 = 0x0420;
pub const RX_STREAM_LOAD_PROGRAM: u32 = 0x0421;
pub const RX_STREAM_CONFIGURE: u32 = 0x0422;
pub const RX_STREAM_CAN_PULL: u32 = 0x0423;
pub const RX_STREAM_PULL: u32 = 0x0424;
pub const RX_STREAM_FREE: u32 = 0x0425;
pub const RX_STREAM_GET_BUFFER: u32 = 0x0426;
pub const RX_STREAM_SET_RATE: u32 = 0x0427;

/// Arguments for `STREAM_LOAD_PROGRAM` via `provider_call`.
#[repr(C)]
pub struct LoadProgramArgs {
    pub program: *const u16,
    pub program_len: u32,
    pub wrap_target: u8,
    pub wrap: u8,
    pub sideset_bits: u8,
    pub options: u8,
}

/// Arguments for `CMD_CONFIGURE` via `provider_call`.
#[repr(C)]
pub struct CmdConfigureArgs {
    pub data_pin: u8,
    pub clk_pin: u8,
    pub _pad: [u8; 2],
    pub clock_div: u32,
}

/// Arguments for `CMD_TRANSFER` via `provider_call`.
#[repr(C)]
pub struct CmdTransferArgs {
    pub tx_ptr: *const u8,
    pub tx_len: u32,
    pub rx_ptr: *mut u8,
    pub rx_len: u32,
}
