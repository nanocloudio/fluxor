// HAL contract: PIO (Programmable I/O) — RP state-machine mechanics.
//
// Layer: platform/rp (RP-silicon mechanics).
//
// This surface is the RP PIO instruction engine: 16-bit programs, wrap
// targets, side-set, state-machine pin config, and the stream/cmd DMA plumbing
// that runs those programs (I2S, LED strips, cyw43 SPI, display bit-bang). The
// genuinely platform-independent audio-clock query has been lifted out to the
// `contracts::stream_clock` capability (opcode class 0x1Cxx) so hosts answer it
// without any PIO hardware; the `STREAM_TIME` op below remains only as the RP
// backend's per-stream clock, which the kernel falls back to when no dedicated
// STREAM_CLOCK provider is registered.
//
// The raw register escape hatch (`PIO_SM_EXEC`, `PIO_INSTR_WRITE`, …) lives in
// `platform/rp/pio_raw.rs`.

// Streaming (unidirectional, continuous DMA — I2S, LED strips, etc.)
pub use super::super::super::registry::pio::DIRECT_BUFFER;
pub use super::super::super::registry::pio::DIRECT_PUSH;
/// Program load status: 0=none, 1=pending, 2=loaded, 3=error.
pub use super::super::super::registry::pio::PROGRAM_STATUS;
pub use super::super::super::registry::pio::STREAM_ALLOC;
pub use super::super::super::registry::pio::STREAM_CAN_PUSH;
pub use super::super::super::registry::pio::STREAM_CONFIGURE;
pub use super::super::super::registry::pio::STREAM_FREE;
pub use super::super::super::registry::pio::STREAM_GET_BUFFER;
pub use super::super::super::registry::pio::STREAM_LOAD_PROGRAM;
pub use super::super::super::registry::pio::STREAM_PUSH;
/// Set consumption rate (units/sec, Q16.16 fixed point). arg = &u32.
pub use super::super::super::registry::pio::STREAM_SET_RATE;
pub use super::super::super::registry::pio::STREAM_TIME;

// Command/response (bidirectional, discrete transfers — gSPI, etc.)
pub use super::super::super::registry::pio::CMD_ALLOC;
pub use super::super::super::registry::pio::CMD_CONFIGURE;
pub use super::super::super::registry::pio::CMD_FREE;
/// The slot's data pin level while no transfer is in flight: 1 high,
/// 0 low, `EBUSY` during a transfer. A bus peripheral that raises its
/// data line when it has something to say is asked this before it is
/// asked anything over the bus.
pub use super::super::super::registry::pio::CMD_LEVEL;
pub use super::super::super::registry::pio::CMD_LOAD_PROGRAM;
pub use super::super::super::registry::pio::CMD_POLL;
/// Synchronous transfer: executes PIO DMA inline (PAC-level busy-wait).
/// Returns total bytes on success, negative errno on error.
pub use super::super::super::registry::pio::CMD_TRANSFER;

// RX Stream (unidirectional input, continuous DMA capture — mic, ADC streams, etc.)
pub use super::super::super::registry::pio::RX_STREAM_ALLOC;
pub use super::super::super::registry::pio::RX_STREAM_CAN_PULL;
pub use super::super::super::registry::pio::RX_STREAM_CONFIGURE;
pub use super::super::super::registry::pio::RX_STREAM_FREE;
pub use super::super::super::registry::pio::RX_STREAM_GET_BUFFER;
pub use super::super::super::registry::pio::RX_STREAM_LOAD_PROGRAM;
pub use super::super::super::registry::pio::RX_STREAM_PULL;
pub use super::super::super::registry::pio::RX_STREAM_SET_RATE;

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
