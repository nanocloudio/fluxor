// ============================================================================
// Channel Poll Constants
// ============================================================================

pub const POLL_IN: u32 = 0x01;
pub const POLL_OUT: u32 = 0x02;
pub const POLL_ERR: u32 = 0x04;
pub const POLL_HUP: u32 = 0x08;
pub const POLL_CONN: u32 = 0x10;

// ============================================================================
// Common Error Codes (from kernel errno)
// ============================================================================

pub const E_AGAIN: i32 = -11;
pub const E_BUSY: i32 = -16;
pub const E_INVAL: i32 = -22;
pub const E_INPROGRESS: i32 = -36;
pub const E_NOSYS: i32 = -38;
pub const E_CONNREFUSED: i32 = -111;

// ============================================================================
// Socket Types (net_proto / Stream Surface v1)
// ============================================================================

/// Stream-oriented socket (TCP). Only valid SOCK_TYPE for NET_CMD_CONNECT
/// now that datagram traffic has moved to the datagram surface.
pub const SOCK_TYPE_STREAM: u8 = 1;

/// Flag ORed onto opcode to dispatch to the next provider below the caller.
pub const CHAIN_NEXT: u32 = 0x0001_0000;

// ============================================================================
// Network Interface State (emitted as MSG_NETIF_STATE payload byte on the
// driver's dedicated state output port; consumer modules read from the
// wired state input port)
// ============================================================================

pub const NETIF_STATE_DOWN: u8 = 0;
pub const NETIF_STATE_NO_LINK: u8 = 2;
pub const NETIF_STATE_NO_ADDRESS: u8 = 4;
pub const NETIF_STATE_READY: u8 = 5;
pub const NETIF_STATE_ERROR: u8 = 255;

// ============================================================================
// Channel Ioctl Commands
// ============================================================================

pub const IOCTL_NOTIFY: u32 = 1;
pub const IOCTL_POLL_NOTIFY: u32 = 2;
pub const IOCTL_FLUSH: u32 = 3;
pub const IOCTL_EOF: u32 = 4;

// ============================================================================
// Block Source Ioctls
// ============================================================================
//
// Every one of these addresses the device by **64-bit LBA**. At 512-byte
// sectors a 32-bit LBA tops out at 2 TiB, which is smaller than drives that
// are already on the bench, and the ceiling is invisible until a caller
// silently addresses the wrong sector. A producer whose hardware cannot go
// that far — SD block addressing is 32-bit by specification — refuses an
// out-of-range LBA rather than truncating it: a request the device cannot
// serve must fail, not land somewhere else.

/// Field offsets of the block ioctls' shared argument.
///
/// These are constants rather than prose because the layout *is* the wire
/// surface. A doc comment describing it is invisible to the ABI source pin,
/// so widening a field here would not move the digest and every consumer
/// built against the old layout would keep loading — reading a truncated LBA
/// and a buffer pointer from the wrong offset. Naming the offsets puts the
/// layout in the token stream the pin hashes.
pub mod blk_arg {
    /// Total argument length, in bytes.
    pub const LEN: usize = 24;
    /// `u64` LE — absolute logical block address.
    pub const LBA: usize = 0;
    /// `u16` LE — sector count. Clamped by the producer.
    pub const NLB: usize = 8;
    /// `u64` LE — caller's data buffer.
    pub const BUF_PTR: usize = 16;
}

/// Block-source ioctl on a 512-byte sector channel: request a multi-
/// sector read in a single device command. Producers that support it
/// (currently `nvme`) parse the shared `blk_arg` layout, submit one Read
/// with `nlb` LBAs, and stream `nlb * 512` bytes back-to-back on the channel
/// without further IOCTLs — amortizing the per-command round trip across a
/// whole cluster of sectors. `buf_ptr` is unused: the data comes back on the
/// channel, not into a caller buffer.
///
/// This is the *streaming* counterpart of [`IOCTL_BLOCKS_READ_LBAS_SYNC`],
/// for a consumer participating in the channel state machine rather than one
/// that needs bytes inside its own dispatch. `nlb` is clamped on the
/// producer side; `ENOSYS` means the consumer should fall back to per-sector
/// `IOCTL_NOTIFY`.
pub const IOCTL_BLOCKS_READ_NLB: u32 = 0x4E56_0002;

/// Block-source ioctl: synchronously read `nlb` sectors at `lba`
/// directly into the caller-supplied buffer. The producer submits
/// the device command, spin-polls completion, and copies the data
/// out before returning — no channel involvement. Used by
/// synchronous file-system providers (`fat32`'s FS_CONTRACT
/// dispatch) where the consumer needs bytes immediately and cannot
/// participate in the channel state machine.
///
/// arg layout (24 bytes, little-endian):
///   [lba: u64][nlb: u16][_pad: u16][_pad: u32][buf_ptr: u64]
/// `buf_ptr` must point to ≥ `nlb * 512` writable bytes. `nlb` is
/// clamped to the producer's per-command sector limit (NVMe MAX_NLB).
/// Returns 0 on success, negative errno on submit / completion error.
pub const IOCTL_BLOCKS_READ_LBAS_SYNC: u32 = 0x4E56_0003;

/// Block-source ioctl: synchronously write `nlb` sectors at `lba`
/// from the caller-supplied buffer. The symmetric counterpart of
/// [`IOCTL_BLOCKS_READ_LBAS_SYNC`] — the producer copies the data into
/// its DMA scratch, submits the device Write command, and spin-polls
/// completion before returning. Used by synchronous file-system
/// providers (`fat32`'s FS_CONTRACT write path) that must land FAT /
/// directory / data sectors and know they reached the controller
/// within the `provider_call`, since the async `WS_*` channel state
/// machine cannot advance inside a synchronous dispatch.
///
/// Durability note: this guarantees the write reached the controller,
/// not that it is NAND-committed. A subsequent device flush
/// (`PAGER_OP_FLUSH`, which issues an NVMe Flush) is required for
/// fsync-grade durability.
///
/// arg layout (24 bytes, little-endian):
///   [lba: u64][nlb: u16][_pad: u16][_pad: u32][buf_ptr: u64]
/// `buf_ptr` must point to ≥ `nlb * 512` readable bytes. `nlb` is
/// clamped to the producer's per-command sector limit (NVMe MAX_NLB).
/// Returns 0 on success, negative errno on submit / completion error.
pub const IOCTL_BLOCKS_WRITE_LBAS_SYNC: u32 = 0x4E56_0004;

/// Block-source ioctl: synchronously commit the device's volatile
/// write cache to non-volatile media (NVMe Flush, opcode 0x00).
/// Drains any in-flight async writes first. `arg` is ignored (pass
/// null). Returns 0 on success, negative errno otherwise. Used by
/// synchronous file-system providers (`fat32`'s `FS_FSYNC`) to give
/// callers true fsync-grade durability after `IOCTL_BLOCKS_WRITE_LBAS_SYNC`.
pub const IOCTL_BLOCKS_FLUSH_SYNC: u32 = 0x4E56_0005;

/// Block-source ioctl: report the block source's own geometry.
///
/// arg layout (12 bytes, little-endian, written by the producer):
///   [logical_block_size: u32][block_count: u64]
///
/// A consumer that has not asked has no licence to assume 512. The
/// filesystem block a provider addresses in and the logical block the device
/// addresses in are independent — ext2/3/4 uses 1K–4K filesystem blocks, and
/// 4Kn NVMe namespaces report a 4096-byte logical block — so a provider that
/// assumes they match is correct only by coincidence.
///
/// `E_AGAIN` while the device has not finished attaching: geometry is a
/// property of the attached namespace, and a pessimistic guess latched by a
/// consumer is worse than making it ask again. `E_NOSYS` from a source that
/// cannot describe itself means 512, which is the answer for every block
/// source that predates this query — stated here rather than assumed at each
/// consumer.
pub const IOCTL_BLOCKS_GEOMETRY: u32 = 0x4E56_0009;

/// Block-source ioctl: submit `nlb` sectors at `lba` from the caller's
/// buffer **without waiting** — the producer copies the data into a
/// dedicated in-flight DMA slot, submits the Write, and returns
/// immediately (the completion is harvested later). This is the
/// pipelined counterpart of [`IOCTL_BLOCKS_WRITE_LBAS_SYNC`]: it lets a
/// durable writer (the WAL) keep multiple writes in flight instead of
/// spin-polling each one, which is the single biggest write-throughput
/// lever.
///
/// arg layout (24 bytes, little-endian) — identical to the SYNC form:
///   [lba: u64][nlb: u16][_pad: u16][_pad: u32][buf_ptr: u64]
/// Returns 0 on success (queued), `E_AGAIN` when all in-flight slots
/// are busy (caller retries next step), or a negative errno on submit
/// error. Durability is NOT implied by return — the caller fences with
/// [`IOCTL_BLOCKS_FENCE_SUBMIT`] / [`IOCTL_BLOCKS_FENCE_POLL`].
pub const IOCTL_BLOCKS_WRITE_LBAS_ASYNC: u32 = 0x4E56_0006;

/// Block-source ioctl: open a durability fence over every async write
/// submitted so far. Harvests any completions first, then writes the
/// current submit high-water (`u64` LE, 8 bytes) into `arg` as a
/// ticket. `arg` must point at ≥ 8 writable bytes. Returns 0. The
/// caller polls the ticket with [`IOCTL_BLOCKS_FENCE_POLL`].
pub const IOCTL_BLOCKS_FENCE_SUBMIT: u32 = 0x4E56_0007;

/// Block-source ioctl: non-blocking poll of a fence ticket. `arg` holds
/// the `u64` LE ticket from [`IOCTL_BLOCKS_FENCE_SUBMIT`]. Harvests
/// completions, then returns 0 = durable (all writes ≤ ticket are on
/// non-volatile media), 1 = pending, or a negative errno if any harvested
/// write failed (the error is latched-and-cleared, exactly as the sync
/// flush path surfaces a failed CQE).
pub const IOCTL_BLOCKS_FENCE_POLL: u32 = 0x4E56_0008;

// ============================================================================
// FMP Well-Known Message Types (pre-computed FNV-1a hashes)
// ============================================================================

// WiFi lifecycle
pub const MSG_RADIO_READY: u32 = fnv1a(b"radio_ready");
pub const MSG_CONNECTED: u32 = fnv1a(b"connected");
pub const MSG_DISCONNECTED: u32 = fnv1a(b"disconnected");

// Netif state change. Payload: [state: u8] using NETIF_STATE_* values above.
// Emitted by drivers (cyw43, ch9120, …) on a dedicated "netif_state" output
// port; read by consumers (wifi, ip, …) on a wired input port.
pub const MSG_NETIF_STATE: u32 = fnv1a(b"netif_state");
pub const MSG_CONNECT: u32 = fnv1a(b"connect");
pub const MSG_DISCONNECT: u32 = fnv1a(b"disconnect");
pub const MSG_SCAN: u32 = fnv1a(b"scan");
pub const MSG_SCAN_DONE: u32 = fnv1a(b"scan_done");
pub const MSG_SCAN_RESULT: u32 = fnv1a(b"scan_result");

// UI / control
pub const MSG_CLICK: u32 = fnv1a(b"click");
pub const MSG_LONG_PRESS: u32 = fnv1a(b"long_press");
pub const MSG_PRESS: u32 = fnv1a(b"press");
pub const MSG_RELEASE: u32 = fnv1a(b"release");
pub const MSG_TOGGLE: u32 = fnv1a(b"toggle");
pub const MSG_NEXT: u32 = fnv1a(b"next");
pub const MSG_PREV: u32 = fnv1a(b"prev");
pub const MSG_SELECT: u32 = fnv1a(b"select");
pub const MSG_STATUS: u32 = fnv1a(b"status");
pub const MSG_ON: u32 = fnv1a(b"on");
pub const MSG_OFF: u32 = fnv1a(b"off");
pub const MSG_BLINK: u32 = fnv1a(b"blink");
