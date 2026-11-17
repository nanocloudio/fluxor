// Platform: RP DMA raw register bridge.
//
// Layer: platform/rp (chip-specific, unstable).
//
// Two distinct public contracts, each with a coherent handle type:
//
//   channel::*  — PLATFORM_DMA contract
//     Raw DMA channel alloc + manual transfer. Handle = the tagged channel
//     `channel::ALLOC` returns. The caller polls BUSY itself. Suited to
//     driver-controlled transfers (`spi_pl022`, `pio_rp` CMD transfers).
//
//   fd::*       — PLATFORM_DMA_FD contract
//     Async DMA fd with ping-pong queuing. Handle = tagged DMA fd. The
//     kernel manages two underlying channels and exposes poll/queue
//     semantics for zero-gap chaining. Suited to streaming workloads
//     (`pio_rp` streams, `st7701s` display DMA).
//
// A transfer moves memory to or from one peripheral FIFO and names no
// address. The FIFO is the one its DREQ paces — a PIO state machine's TX or
// RX FIFO, an SPI, UART or I2C data register — on an instance the caller
// holds a raw claim on (`raw_claim::CLAIM`); a TX DREQ moves memory to the
// FIFO, an RX DREQ moves the FIFO to memory. The memory side is a span the
// caller lent on the transfer's own handle (`lend::OPEN` with the channel or
// fd handle as the session; in for a TX DREQ, out for RX), named by the
// lend's cookie and an offset into it. The kernel checks that every unit the
// transfer touches lies inside the lend.
//
// Drivers declare the contracts they need in their manifest:
//   [[resources]]
//   requires_contract = "platform_dma"       # channel family
//   [[resources]]
//   requires_contract = "platform_dma_fd"    # fd family

/// The transfer argument of `channel::START` and `fd::START`:
/// `[lend u32][offset u32][count u32][dreq u8][flags u8]`.
pub mod start {
    /// `u32` LE — the cookie of the caller's lend on this handle.
    pub const LEND: usize = 0;
    /// `u32` LE — the memory side's offset inside the lend.
    pub const OFFSET: usize = 4;
    /// `u32` LE — transfer units.
    pub const COUNT: usize = 8;
    /// `u8` — the DREQ pacing the transfer, which names its FIFO.
    pub const DREQ: usize = 12;
    /// `u8` — [`super::flags`].
    pub const FLAGS: usize = 13;
    /// Total length, in bytes.
    pub const LEN: usize = 14;

    /// The argument for a transfer of `count` units from or into
    /// `[offset..]` of lend `lend`, paced by `dreq`.
    pub const fn encode(lend: u32, offset: u32, count: u32, dreq: u8, flags: u8) -> [u8; LEN] {
        let l = lend.to_le_bytes();
        let o = offset.to_le_bytes();
        let c = count.to_le_bytes();
        [
            l[0], l[1], l[2], l[3], o[0], o[1], o[2], o[3], c[0], c[1], c[2], c[3], dreq, flags,
        ]
    }
}

/// The argument of `fd::QUEUE` and `fd::RESTART`: `[lend u32][offset u32]
/// [count u32]` — the next memory span for an fd whose `START` moved memory
/// to a FIFO.
pub mod reload {
    /// Total length, in bytes.
    pub const LEN: usize = 12;

    pub const fn encode(lend: u32, offset: u32, count: u32) -> [u8; LEN] {
        let l = lend.to_le_bytes();
        let o = offset.to_le_bytes();
        let c = count.to_le_bytes();
        [
            l[0], l[1], l[2], l[3], o[0], o[1], o[2], o[3], c[0], c[1], c[2], c[3],
        ]
    }
}

/// `flags` of a transfer.
pub mod flags {
    /// The memory side advances one unit per transfer; clear, every unit
    /// moves the same memory (a fill byte, a discard word).
    pub const INCR: u8 = 0x01;
    /// The unit width field.
    pub const SIZE_MASK: u8 = 0x0C;
    pub const SIZE_BYTE: u8 = 0x00;
    pub const SIZE_HALF: u8 = 0x04;
    pub const SIZE_WORD: u8 = 0x08;
}

pub mod channel {
    //! PLATFORM_DMA contract opcodes. Handle = the tagged channel.

    /// Allocate a DMA channel. Returns its handle or <0.
    /// Issued via `provider_open(PLATFORM_DMA, channel::ALLOC, null, 0)`.
    pub use super::super::super::super::registry::platform_dma::ALLOC;

    /// Free a DMA channel. `handle = ch`, no arg.
    pub use super::super::super::super::registry::platform_dma::FREE;

    /// The channel number the handle holds: `arg` out `[ch u8]`, which a
    /// platform op that names its channels (`pio_raw` `CMD_TRANSFER`)
    /// carries.
    pub use super::super::super::super::registry::platform_dma::CHANNEL;

    /// Start a transfer (non-blocking). `handle = ch`, arg =
    /// [`super::start`] against a lend on `ch`.
    pub use super::super::super::super::registry::platform_dma::START;

    /// Poll channel busy status. `handle = ch`, no arg. Returns 1 if busy,
    /// 0 if done.
    pub use super::super::super::super::registry::platform_dma::BUSY;

    /// Abort a transfer. `handle = ch`, no arg.
    pub use super::super::super::super::registry::platform_dma::ABORT;
}

pub mod fd {
    //! PLATFORM_DMA_FD contract opcodes. Handle = a DMA fd.

    /// Create a DMA fd: allocates two underlying channels, returns its
    /// handle. Issued via `provider_open(PLATFORM_DMA_FD, fd::CREATE,
    /// null, 0)`.
    pub use super::super::super::super::registry::platform_dma_fd::CREATE;

    /// Start a transfer on the fd (full configuration). `handle = fd`,
    /// arg = [`super::start`] against a lend on `fd`.
    pub use super::super::super::super::registry::platform_dma_fd::START;

    /// Re-trigger the active channel from a new memory span, keeping the
    /// FIFO, DREQ and flags of `START` (memory-to-FIFO fds only).
    /// `handle = fd`, arg = [`super::reload`].
    pub use super::super::super::super::registry::platform_dma_fd::RESTART;

    /// Free the fd: frees both channels, releases the slot. `handle = fd`,
    /// no arg.
    pub use super::super::super::super::registry::platform_dma_fd::FREE;

    /// Queue the next transfer (ping-pong): configures the inactive channel
    /// and chains the active one to it for zero-gap hand-off
    /// (memory-to-FIFO fds only). `handle = fd`, arg = [`super::reload`].
    pub use super::super::super::super::registry::platform_dma_fd::QUEUE;
}
