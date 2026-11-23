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
//     semantics for zero-gap chaining, or runs a scan list (`list_start`)
//     whose timing depends on no software. Suited to streaming workloads
//     (`pio_rp` streams, a panel's scan-out, a PIO audio sink).
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

/// The argument of `fd::LIST_START`: `[lend u32][entries u16][dreq u8]
/// [flags u8][fill u32][count u32]`.
///
/// A scan list is a cyclic sequence of `entries` transfers to one FIFO,
/// each exactly `count` units: a span of the fd's lend when the entry is
/// armed, the fill value otherwise. The list starts with every entry fill
/// and runs until the fd is freed; an armed entry is sent once and returns
/// to fill. Every entry moves the same number of units whatever its state,
/// so the FIFO's consumer never loses alignment with the data.
pub mod list_start {
    /// `u32` LE — the cookie of the caller's lend on this fd.
    pub const LEND: usize = 0;
    /// `u16` LE — entries in the list, at least 2.
    pub const ENTRIES: usize = 4;
    /// `u8` — the DREQ pacing the list, which names its FIFO.
    pub const DREQ: usize = 6;
    /// `u8` — [`super::flags`]: the unit size. `INCR` is implied for an
    /// armed entry and never applies to fill.
    pub const FLAGS: usize = 7;
    /// `u32` LE — the fill value; its low unit bytes are what a fill entry
    /// sends.
    pub const FILL: usize = 8;
    /// `u32` LE — units every entry moves.
    pub const COUNT: usize = 12;
    /// Total length, in bytes.
    pub const LEN: usize = 16;

    /// The fewest entries a list has. An entry can be armed while it is
    /// neither the one being sent nor the one loaded next, so a list needs
    /// a third entry for any of its entries ever to be armed.
    pub const MIN_ENTRIES: u16 = 3;

    pub const fn encode(
        lend: u32,
        entries: u16,
        dreq: u8,
        flags: u8,
        fill: u32,
        count: u32,
    ) -> [u8; LEN] {
        let l = lend.to_le_bytes();
        let e = entries.to_le_bytes();
        let f = fill.to_le_bytes();
        let c = count.to_le_bytes();
        [
            l[0], l[1], l[2], l[3], e[0], e[1], dreq, flags, f[0], f[1], f[2], f[3], c[0], c[1],
            c[2], c[3],
        ]
    }

    /// The argument's fields.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Args {
        pub lend: u32,
        pub entries: u16,
        pub dreq: u8,
        pub flags: u8,
        pub fill: u32,
        pub count: u32,
    }

    /// Read the argument. `None` for any other length, fewer than
    /// `MIN_ENTRIES` entries, or a zero `count`.
    pub const fn decode(b: &[u8]) -> Option<Args> {
        if b.len() != LEN {
            return None;
        }
        let a = Args {
            lend: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            entries: u16::from_le_bytes([b[4], b[5]]),
            dreq: b[DREQ],
            flags: b[FLAGS],
            fill: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            count: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        };
        if a.entries < MIN_ENTRIES || a.count == 0 {
            return None;
        }
        Some(a)
    }
}

/// The argument of `fd::LIST_ARM`: `[entry u16][0 u16][offset u32]` —
/// entry `entry` sends the list's `count` units from `offset` in the lend
/// the next time the scan reaches it.
pub mod list_arm {
    /// `u16` LE — the entry.
    pub const ENTRY: usize = 0;
    /// `u16` — zero.
    pub const RESERVED: usize = 2;
    /// `u32` LE — the span's offset inside the lend.
    pub const OFFSET: usize = 4;
    /// Total length, in bytes.
    pub const LEN: usize = 8;

    pub const fn encode(entry: u16, offset: u32) -> [u8; LEN] {
        let e = entry.to_le_bytes();
        let o = offset.to_le_bytes();
        [e[0], e[1], 0, 0, o[0], o[1], o[2], o[3]]
    }

    /// Read the argument as `(entry, offset)`. `None` for any other length
    /// or a non-zero reserved word.
    pub const fn decode(b: &[u8]) -> Option<(u16, u32)> {
        if b.len() != LEN || b[2] != 0 || b[3] != 0 {
            return None;
        }
        Some((
            u16::from_le_bytes([b[0], b[1]]),
            u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        ))
    }
}

/// The answer of `fd::LIST_STATUS`: `[position u32][underruns u32]`, both
/// wrapping counts since `LIST_START`.
///
/// The kernel counts from where the scan stands in the list each time it
/// looks (the completion interrupt, an arm, a status read), so the counts
/// are exact while it looks at least once a lap. Across a span in which it
/// cannot look for a lap or longer (a flash erase that outlasts the list's
/// period), whole laps go uncounted: both counts move on by the entries
/// passed modulo the list's length.
pub mod list_status {
    /// `u32` LE — entries sent, as counted.
    pub const POSITION: usize = 0;
    /// `u32` LE — entries sent as fill, as counted.
    pub const UNDERRUNS: usize = 4;
    /// Total length, in bytes.
    pub const LEN: usize = 8;

    pub const fn encode(position: u32, underruns: u32) -> [u8; LEN] {
        let p = position.to_le_bytes();
        let u = underruns.to_le_bytes();
        [p[0], p[1], p[2], p[3], u[0], u[1], u[2], u[3]]
    }

    /// Read the answer as `(position, underruns)`. `None` for any other
    /// length.
    pub const fn decode(b: &[u8]) -> Option<(u32, u32)> {
        if b.len() != LEN {
            return None;
        }
        Some((
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        ))
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

    /// Start a scan list on the fd, every entry fill. `handle = fd`, arg =
    /// [`super::list_start`] against a lend on `fd`. `EBUSY` while a
    /// `START` transfer runs on the fd; `EINVAL` if `count` units exceed
    /// the lend or the list has fewer than two entries; `ENOMEM` when the
    /// kernel has no room for the list. While a list runs, `START`,
    /// `RESTART` and `QUEUE` answer `EBUSY`, `FREE` stops it, and the fd
    /// polls readable when entries have been sent since the last
    /// `LIST_STATUS`.
    pub use super::super::super::super::registry::platform_dma_fd::LIST_START;

    /// Arm one entry. `handle = fd`, arg = [`super::list_arm`]. `EINVAL`
    /// past the lend or the list; `EBUSY` if the entry is armed, being
    /// sent, or the next to be sent.
    pub use super::super::super::super::registry::platform_dma_fd::LIST_ARM;

    /// How far the scan has run. `handle = fd`, arg out =
    /// [`super::list_status`].
    pub use super::super::super::super::registry::platform_dma_fd::LIST_STATUS;
}
