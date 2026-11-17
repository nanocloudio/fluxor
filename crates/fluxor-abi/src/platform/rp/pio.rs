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
/// Program load status: 0=none, 1=pending, 2=loaded, 3=error.
pub use super::super::super::registry::pio::PROGRAM_STATUS;
pub use super::super::super::registry::pio::STREAM_ALLOC;
/// 1 when `STREAM_PUSH` would take a buffer now, 0 while the last one
/// waits for the DMA. No `arg`.
pub use super::super::super::registry::pio::STREAM_CAN_PUSH;
pub use super::super::super::registry::pio::STREAM_CONFIGURE;
pub use super::super::super::registry::pio::STREAM_FREE;
/// The stream's program. arg in = [`load_program`]; `data` in = the
/// program.
pub use super::super::super::registry::pio::STREAM_LOAD_PROGRAM;
/// Queue the next buffer. No `arg`; `data` in = the words (u32 LE), at
/// least one, at most the slot's buffer, copied into the stream's back
/// buffer during the call. Returns 0, or `EBUSY` while the last buffer
/// still waits.
pub use super::super::super::registry::pio::STREAM_PUSH;
/// Set consumption rate (units/sec, Q16.16 fixed point). arg = `[rate u32 LE]`.
pub use super::super::super::registry::pio::STREAM_SET_RATE;
pub use super::super::super::registry::pio::STREAM_TIME;

// Command/response (bidirectional, discrete transfers — gSPI, etc.)
pub use super::super::super::registry::pio::CMD_ALLOC;
/// arg in = [`CmdConfigureArgs`].
pub use super::super::super::registry::pio::CMD_CONFIGURE;
pub use super::super::super::registry::pio::CMD_FREE;
/// The slot's data pin level while no transfer is in flight: 1 high,
/// 0 low, `EBUSY` during a transfer. A bus peripheral that raises its
/// data line when it has something to say is asked this before it is
/// asked anything over the bus.
pub use super::super::super::registry::pio::CMD_LEVEL;
/// The command slot's program. arg in = [`load_program`]; `data` in = the
/// program.
pub use super::super::super::registry::pio::CMD_LOAD_PROGRAM;
/// Completion of the transfer `CMD_TRANSFER` started: `EAGAIN` while it
/// runs; once done, the received words are written to `data` (out, up to
/// its length) and the frame's total byte count returned; 0 when nothing is
/// in flight. No `arg`.
pub use super::super::super::registry::pio::CMD_POLL;
/// Start one command frame. `data` in = the frame: `[tx_words u32 LE]`,
/// that many words to send, then `[rx_words u32 LE]` to receive. The frame
/// is copied in during the call; returns 0 once started. No `arg`.
pub use super::super::super::registry::pio::CMD_TRANSFER;

// RX Stream (unidirectional input, continuous DMA capture — mic, ADC streams, etc.)
pub use super::super::super::registry::pio::RX_STREAM_ALLOC;
/// 1 when a captured buffer is ready for `RX_STREAM_PULL`, else 0.
pub use super::super::super::registry::pio::RX_STREAM_CAN_PULL;
pub use super::super::super::registry::pio::RX_STREAM_CONFIGURE;
pub use super::super::super::registry::pio::RX_STREAM_FREE;
/// The RX stream's program. arg in = [`load_program`]; `data` in = the
/// program.
pub use super::super::super::registry::pio::RX_STREAM_LOAD_PROGRAM;
/// Take the captured buffer. No `arg`; `data` out receives its words
/// (u32 LE), as many as fit. The buffer goes back to the DMA either way.
/// Returns the bytes written, 0 when no buffer is ready.
pub use super::super::super::registry::pio::RX_STREAM_PULL;
pub use super::super::super::registry::pio::RX_STREAM_SET_RATE;

/// The most instructions a program holds (the PIO instruction memory).
pub const PROGRAM_MAX: usize = 32;

/// `*_LOAD_PROGRAM` argument: `[wrap_target u8][wrap u8][sideset_bits u8]
/// [options u8]`. The program is the call's `data`: 1..=[`PROGRAM_MAX`]
/// instructions, u16 LE each, copied during the call.
pub mod load_program {
    /// `u8` — the instruction the program wraps to.
    pub const WRAP_TARGET: usize = 0;
    /// `u8` — the instruction after which it wraps.
    pub const WRAP: usize = 1;
    /// `u8` — side-set bits, 0..=5.
    pub const SIDESET_BITS: usize = 2;
    /// `u8` — [`options`].
    pub const OPTIONS: usize = 3;
    /// Total length, in bytes.
    pub const ARG_LEN: usize = 4;

    /// `options` bits.
    pub mod options {
        /// Side-set is optional (the enable bit is used).
        pub const SIDESET_OPTIONAL: u8 = 0x01;
        /// Side-set drives pin directions, not levels.
        pub const SIDESET_PINDIRS: u8 = 0x02;
    }

    pub const fn encode(wrap_target: u8, wrap: u8, sideset_bits: u8, options: u8) -> [u8; ARG_LEN] {
        [wrap_target, wrap, sideset_bits, options]
    }

    /// `(wrap_target, wrap, sideset_bits, options)` from an argument.
    pub fn decode(arg: &[u8]) -> Option<(u8, u8, u8, u8)> {
        match arg {
            [t, w, s, o, ..] => Some((*t, *w, *s, *o)),
            _ => None,
        }
    }
}

/// Arguments for `CMD_CONFIGURE` via `provider_call`.
#[repr(C)]
pub struct CmdConfigureArgs {
    pub data_pin: u8,
    pub clk_pin: u8,
    pub _pad: [u8; 2],
    pub clock_div: u32,
}
