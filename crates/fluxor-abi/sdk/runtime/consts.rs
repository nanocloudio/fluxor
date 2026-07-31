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

/// Block-source ioctl on a 512-byte sector channel: request a multi-
/// sector read in a single device command. Producers that support
/// it (currently `nvme`) parse `arg = [lba: u32 LE, nlb: u16 LE,
/// _pad: u16]` (8 bytes), submit one Read with `nlb` LBAs, and
/// stream `nlb * 512` bytes back-to-back on the channel without
/// further IOCTLs. Consumers (fat32) use this to amortize the per-
/// command roundtrip across a whole cluster of sectors. `nlb` is
/// clamped on the producer side; ENOSYS from the producer means
/// the consumer should fall back to per-sector `IOCTL_NOTIFY`.
pub const IOCTL_BLOCKS_READ_NLB: u32 = 0x4E56_0002;

/// Block-source ioctl: synchronously read `nlb` sectors at `lba`
/// directly into the caller-supplied buffer. The producer submits
/// the device command, spin-polls completion, and copies the data
/// out before returning — no channel involvement. Used by
/// synchronous file-system providers (`fat32`'s FS_CONTRACT
/// dispatch) where the consumer needs bytes immediately and cannot
/// participate in the channel state machine.
///
/// arg layout (16 bytes, little-endian):
///   [lba: u32][nlb: u16][_pad: u16][buf_ptr: u64]
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
/// arg layout (16 bytes, little-endian):
///   [lba: u32][nlb: u16][_pad: u16][buf_ptr: u64]
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

/// Block-source ioctl: submit `nlb` sectors at `lba` from the caller's
/// buffer **without waiting** — the producer copies the data into a
/// dedicated in-flight DMA slot, submits the Write, and returns
/// immediately (the completion is harvested later). This is the
/// pipelined counterpart of [`IOCTL_BLOCKS_WRITE_LBAS_SYNC`]: it lets a
/// durable writer (the WAL) keep multiple writes in flight instead of
/// spin-polling each one, which is the single biggest write-throughput
/// lever (see clustor `rfc_async_wal_fsync.md`).
///
/// arg layout (16 bytes, little-endian) — identical to the SYNC form:
///   [lba: u32][nlb: u16][_pad: u16][buf_ptr: u64]
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

