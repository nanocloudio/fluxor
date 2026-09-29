// ============================================================================
// Channel Poll Constants
// ============================================================================

pub const POLL_IN: u32 = 0x01;
pub const POLL_OUT: u32 = 0x02;
pub const POLL_ERR: u32 = 0x04;
pub const POLL_HUP: u32 = 0x08;
pub const POLL_CONN: u32 = 0x10;
/// The channel has carried at least one byte since its last flush.
/// Poll for `POLL_HUP | POLL_WROTE` to tell a stream that ended from
/// one that never started — `POLL_HUP` alone does not distinguish them.
pub const POLL_WROTE: u32 = 0x20;

// ============================================================================
// Common Error Codes (from kernel errno)
// ============================================================================

pub const E_IO: i32 = -5;
pub const E_AGAIN: i32 = -11;
pub const E_BUSY: i32 = -16;
pub const E_INVAL: i32 = -22;
pub const E_INPROGRESS: i32 = -36;
pub const E_NOSYS: i32 = -38;
pub const E_CONNREFUSED: i32 = -111;

// ============================================================================
// Socket Types (net_proto / Stream Surface v1)
// ============================================================================

/// Stream-oriented socket (TCP). The only valid SOCK_TYPE for
/// NET_CMD_CONNECT_TO; datagram traffic uses the datagram surface.
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

// ============================================================================
// Stream staging
// ============================================================================

/// What a channel being staged as a stream is currently saying.
///
/// `POLL_HUP` alone does not carry the distinction this enum makes, so a
/// consumer deriving it by hand from that bit has to guess. This is the
/// one place the derivation is written.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StreamStatus {
    /// The producer is still attached and has not hung up. Keep reading.
    Open,
    /// The producer hung up AFTER writing. This is end-of-stream: what
    /// has been staged so far is the whole of it.
    Ended,
    /// The producer hung up having never written a byte.
    ///
    /// This is NOT an empty stream that completed. A producer that was
    /// terminated, faulted, or retired before its first write hangs up
    /// its outputs exactly as a finished one does, so this is the state
    /// a consumer must not treat as a complete source. Wait, or fail
    /// loudly — do not proceed as though zero bytes were the answer.
    NeverStarted,
}

/// Classify a channel a consumer is staging as a stream.
///
/// Reads `POLL_HUP` and `POLL_WROTE` in one poll so the two cannot
/// disagree across calls.
///
/// # Safety
///
/// `sys` must be the module's syscall table and `chan` one of its
/// channel handles.
pub unsafe fn stream_status(sys: &SyscallTable, chan: i32) -> StreamStatus {
    let ready = (sys.channel_poll)(chan, POLL_HUP | POLL_WROTE);
    if ready < 0 {
        return StreamStatus::Open;
    }
    let ready = ready as u32;
    if ready & POLL_HUP == 0 {
        StreamStatus::Open
    } else if ready & POLL_WROTE != 0 {
        StreamStatus::Ended
    } else {
        StreamStatus::NeverStarted
    }
}
