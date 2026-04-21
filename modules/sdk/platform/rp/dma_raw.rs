// Platform: RP DMA raw register bridge.
//
// Layer: platform/rp (chip-specific, unstable).
//
// Two distinct public contracts, each with a coherent handle type:
//
//   channel::*  — PLATFORM_DMA contract (id 0x0008)
//     Raw DMA channel alloc + manual transfer.
//     Handle = channel number (0..15, typically 8..15 on RP).
//     Caller manages read/write addresses, count, dreq, flags and polls
//     BUSY itself. Suited to synchronous, driver-controlled transfers
//     (`spi_pl022`, `pio_rp` CMD transfers).
//
//   fd::*       — PLATFORM_DMA_FD contract (id 0x0011)
//     Async DMA fd with ping-pong queuing.
//     Handle = tagged DMA fd (FD_TAG_DMA, high bits set).
//     Kernel manages two underlying channels and exposes poll/queue
//     semantics for zero-gap chaining. Suited to streaming workloads
//     (`pio_rp` streams, `st7701s` display DMA).
//
// Drivers declare the contracts they need in their manifest:
//   [[resources]]
//   requires_contract = "platform_dma"       # channel family
//   [[resources]]
//   requires_contract = "platform_dma_fd"    # fd family
//
// The two contracts are dispatched via separate vtable slots; opening
// one does not grant access to the other. pio_rp declares both
// because it legitimately uses raw channels for CMD transfers and fds
// for streams.

pub mod channel {
    //! PLATFORM_DMA contract opcodes. Handle = raw DMA channel number.

    /// Allocate a DMA channel. Returns channel number (i32 >= 0) or <0.
    /// Issued via `provider_open(PLATFORM_DMA, channel::ALLOC, null, 0)`.
    pub const ALLOC: u32 = 0x0C80;

    /// Free a DMA channel. `handle = ch`, arg = empty.
    pub const FREE: u32 = 0x0C81;

    /// Start a DMA transfer (non-blocking).
    /// `handle = ch`, arg = [read_addr:u32 LE, write_addr:u32 LE,
    /// count:u32 LE, dreq:u8, flags:u8] (14 bytes).
    /// flags: bit0=incr_read, bit1=incr_write, bit2=data_size (0=16-bit, 1=32-bit).
    pub const START: u32 = 0x0C82;

    /// Poll DMA channel busy status.
    /// `handle = ch`, arg = empty. Returns 1 if busy, 0 if done.
    pub const BUSY: u32 = 0x0C83;

    /// Abort a DMA transfer.
    /// `handle = ch`, arg = empty.
    pub const ABORT: u32 = 0x0C84;
}

pub mod fd {
    //! PLATFORM_DMA_FD contract opcodes. Handle = tagged DMA fd.

    /// Create a DMA fd: allocates two underlying channels, returns
    /// tagged fd. Issued via `provider_open(PLATFORM_DMA_FD,
    /// fd::CREATE, null, 0)`.
    pub const CREATE: u32 = 0x0C85;

    /// Start a DMA transfer on a DMA fd (full configuration).
    /// `handle = fd`, arg = [read_addr:u32 LE, write_addr:u32 LE,
    /// count:u32 LE, dreq:u8, flags:u8] (14 bytes).
    /// flags: bit0=incr_read, bit1=incr_write, bit2=data_size (0=16-bit, 1=32-bit).
    pub const START: u32 = 0x0C86;

    /// Fast DMA re-trigger via AL3 registers (preserves
    /// write_addr/dreq/flags from CREATE).
    /// `handle = fd`, arg = [read_addr:u32 LE, count:u32 LE] (8 bytes).
    pub const RESTART: u32 = 0x0C87;

    /// Free a DMA fd: frees both DMA channels, releases slot.
    /// `handle = fd`, arg = empty.
    pub const FREE: u32 = 0x0C88;

    /// Queue next DMA transfer (ping-pong). Configures the inactive
    /// channel and sets CHAIN_TO on the active channel for zero-gap
    /// hardware handoff.
    /// `handle = fd`, arg = [read_addr:u32 LE, count:u32 LE] (8 bytes).
    pub const QUEUE: u32 = 0x0C89;
}
