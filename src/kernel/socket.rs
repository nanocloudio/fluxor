//! Socket — network socket support.
//!
//! The kernel provides slot management, TX/RX ring buffers, and an
//! async-to-sync operation bridge. All transport semantics (TCP state
//! machine, connection lifecycle, type validation) are owned by the
//! socket provider module (e.g. the IP stack).
//!
//! The kernel stores socket type and state as opaque u8 values and
//! never branches on them. Provider modules set state and poll_flags
//! via SERVICE_SET_STATE and SERVICE_COMPLETE_OP.

use core::cell::UnsafeCell;
use portable_atomic::{AtomicU8, AtomicU16, AtomicI32, AtomicBool, Ordering};

use crate::abi::ChannelAddr;
use crate::kernel::errno;
use crate::kernel::ringbuf::RingBufState;

// ============================================================================
// Socket Parameters
// ============================================================================

/// Maximum concurrent sockets (8 sockets × 1KB = 8KB total socket buffer RAM)
pub const MAX_SOCKETS: usize = 8;

/// Socket receive buffer size per socket.
/// Linux uses 4KB for TLS record support; embedded uses 512B.
#[cfg(feature = "host-linux")]
const SOCKET_RX_BUF_SIZE: usize = 4096;
#[cfg(not(feature = "host-linux"))]
const SOCKET_RX_BUF_SIZE: usize = 512;

/// Socket transmit buffer size per socket.
#[cfg(feature = "host-linux")]
const SOCKET_TX_BUF_SIZE: usize = 4096;
#[cfg(not(feature = "host-linux"))]
const SOCKET_TX_BUF_SIZE: usize = 512;

// ============================================================================
// Ringbuffer for TX/RX
// ============================================================================

/// Ringbuffer with inline storage for socket data.
///
/// Wraps shared `RingBufState` with a fixed-size `[u8; N]` buffer.
struct RingBuffer<const N: usize> {
    buf: [u8; N],
    state: RingBufState,
}

impl<const N: usize> RingBuffer<N> {
    const fn new() -> Self {
        Self {
            buf: [0u8; N],
            state: RingBufState::with_capacity(N),
        }
    }

    fn write(&mut self, data: &[u8]) -> usize {
        self.state.write(&mut self.buf, data)
    }

    fn read(&mut self, out: &mut [u8]) -> usize {
        self.state.read(&self.buf, out)
    }

    fn available(&self) -> usize {
        self.state.len()
    }

    fn space(&self) -> usize {
        self.state.space()
    }

    fn clear(&mut self) {
        self.state.clear();
    }
}

// ============================================================================
// Socket Operations (Async-to-Sync Bridge)
// ============================================================================

/// Pending socket operation
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketOp {
    /// No operation pending
    None = 0,
    /// Connect to remote address
    Connect = 1,
    /// Bind to local port
    Bind = 2,
    /// Listen for connections
    Listen = 3,
    /// Accept incoming connection
    Accept = 4,
    /// Close socket
    Close = 5,
}

/// Socket slot with TX/RX ringbuffers
pub struct SocketSlot {
    /// Socket type (opaque u8, meaning defined by provider module)
    socket_type: AtomicU8,
    /// Current state (opaque u8, meaning defined by provider module)
    state: AtomicU8,
    /// Provider-controlled poll readiness flags (POLL_CONN, POLL_HUP, POLL_ERR).
    /// POLL_IN/POLL_OUT are derived from buffer state, not stored here.
    poll_flags: AtomicU8,
    /// In use flag
    in_use: AtomicBool,
    /// Pending operation
    pending_op: AtomicU8,
    /// Operation result (0 = success, negative = error)
    op_result: AtomicI32,
    /// Local identifier
    local_id: AtomicU16,
    /// Remote endpoint
    remote_endpoint: AtomicI32,
    /// Remote identifier
    remote_id: AtomicU16,
    /// Associated channel handle (-1 if none)
    channel_handle: AtomicI32,
    /// Lock for buffer access
    lock: AtomicBool,
    /// Transmit buffer (module writes here, async runner drains to network)
    tx_buf: UnsafeCell<RingBuffer<SOCKET_TX_BUF_SIZE>>,
    /// Receive buffer (async runner fills from network, module reads here)
    rx_buf: UnsafeCell<RingBuffer<SOCKET_RX_BUF_SIZE>>,
}

// Safety: Access to tx_buf/rx_buf is protected by the spinlock
unsafe impl Sync for SocketSlot {}

impl SocketSlot {
    pub const fn new() -> Self {
        Self {
            socket_type: AtomicU8::new(0),
            state: AtomicU8::new(0),
            poll_flags: AtomicU8::new(0),
            in_use: AtomicBool::new(false),
            pending_op: AtomicU8::new(SocketOp::None as u8),
            op_result: AtomicI32::new(0),
            local_id: AtomicU16::new(0),
            remote_endpoint: AtomicI32::new(0),
            remote_id: AtomicU16::new(0),
            channel_handle: AtomicI32::new(-1),
            lock: AtomicBool::new(false),
            tx_buf: UnsafeCell::new(RingBuffer::new()),
            rx_buf: UnsafeCell::new(RingBuffer::new()),
        }
    }

    /// Execute closure with lock held on buffers
    fn with_lock<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut RingBuffer<SOCKET_TX_BUF_SIZE>, &mut RingBuffer<SOCKET_RX_BUF_SIZE>) -> R,
    {
        // Spinlock acquire
        while self
            .lock
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // Safety: we hold the lock
        let result = unsafe { f(&mut *self.tx_buf.get(), &mut *self.rx_buf.get()) };
        self.lock.store(false, Ordering::Release);
        result
    }

    /// Write data to TX buffer (module calls this via socket_send)
    pub fn tx_write(&self, data: &[u8]) -> usize {
        self.with_lock(|tx, _rx| tx.write(data))
    }

    /// Read data from TX buffer (async runner calls this to drain to network)
    pub fn tx_read(&self, out: &mut [u8]) -> usize {
        self.with_lock(|tx, _rx| tx.read(out))
    }

    /// Write data to RX buffer (async runner calls this from network)
    pub fn rx_write(&self, data: &[u8]) -> usize {
        self.with_lock(|_tx, rx| rx.write(data))
    }

    /// Read data from RX buffer (module calls this via socket_recv)
    pub fn rx_read(&self, out: &mut [u8]) -> usize {
        self.with_lock(|_tx, rx| rx.read(out))
    }

    /// Get TX buffer space available
    pub fn tx_space(&self) -> usize {
        self.with_lock(|tx, _rx| tx.space())
    }

    /// Get RX data available
    pub fn rx_available(&self) -> usize {
        self.with_lock(|_tx, rx| rx.available())
    }

    /// Get RX buffer space available
    pub fn rx_space(&self) -> usize {
        self.with_lock(|_tx, rx| rx.space())
    }

    /// Get TX data pending (to be sent)
    pub fn tx_pending(&self) -> usize {
        self.with_lock(|tx, _rx| tx.available())
    }

    pub fn is_free(&self) -> bool {
        !self.in_use.load(Ordering::Acquire)
    }

    /// Get opaque state value (provider-defined).
    pub fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    /// Set opaque state value (provider-defined).
    pub fn set_state(&self, state: u8) {
        self.state.store(state, Ordering::Release);
    }

    /// Set provider-controlled poll flags (POLL_CONN, POLL_HUP, POLL_ERR bits).
    pub fn set_poll_flags(&self, flags: u8) {
        self.poll_flags.store(flags, Ordering::Release);
    }

    /// Get provider-controlled poll flags.
    pub fn poll_flags(&self) -> u8 {
        self.poll_flags.load(Ordering::Acquire)
    }

    /// Try to allocate this socket slot.
    /// `sock_type` is opaque (provider-defined).
    pub fn try_allocate(&self, sock_type: u8) -> bool {
        if self.in_use.compare_exchange(
            false,
            true,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ).is_ok() {
            self.socket_type.store(sock_type, Ordering::Release);
            self.state.store(1, Ordering::Release); // 1 = allocated by convention
            self.poll_flags.store(0, Ordering::Release);
            self.pending_op.store(SocketOp::None as u8, Ordering::Release);
            self.op_result.store(0, Ordering::Release);
            self.with_lock(|tx, rx| {
                tx.clear();
                rx.clear();
            });
            true
        } else {
            false
        }
    }

    /// Reset socket slot to free state
    pub fn reset(&self) {
        self.state.store(0, Ordering::Release);
        self.poll_flags.store(0, Ordering::Release);
        self.socket_type.store(0, Ordering::Release);
        self.pending_op.store(SocketOp::None as u8, Ordering::Release);
        self.local_id.store(0, Ordering::Release);
        self.remote_endpoint.store(0, Ordering::Release);
        self.remote_id.store(0, Ordering::Release);
        self.channel_handle.store(-1, Ordering::Release);
        // Clear buffers
        self.with_lock(|tx, rx| {
            tx.clear();
            rx.clear();
        });
        self.in_use.store(false, Ordering::Release);
    }

    /// Queue an operation
    pub fn queue_op(&self, op: SocketOp) -> bool {
        let current = self.pending_op.load(Ordering::Acquire);
        if current != SocketOp::None as u8 {
            return false;
        }
        self.pending_op.store(op as u8, Ordering::Release);
        true
    }

    /// Get pending operation
    pub fn pending_op(&self) -> SocketOp {
        match self.pending_op.load(Ordering::Acquire) {
            1 => SocketOp::Connect,
            2 => SocketOp::Bind,
            3 => SocketOp::Listen,
            4 => SocketOp::Accept,
            5 => SocketOp::Close,
            _ => SocketOp::None,
        }
    }

    /// Complete pending operation
    pub fn complete_op(&self, result: i32) {
        self.op_result.store(result, Ordering::Release);
        self.pending_op.store(SocketOp::None as u8, Ordering::Release);
    }

    /// Get operation result
    pub fn op_result(&self) -> i32 {
        self.op_result.load(Ordering::Acquire)
    }

    /// Set remote endpoint for connect
    pub fn set_remote(&self, endpoint: u32, id: u16) {
        self.remote_endpoint.store(endpoint as i32, Ordering::Release);
        self.remote_id.store(id, Ordering::Release);
    }

    /// Set channel handle (for bridging socket to channel)
    pub fn set_channel(&self, handle: i32) {
        self.channel_handle.store(handle, Ordering::Release);
    }

    /// Get channel handle
    pub fn channel_handle(&self) -> i32 {
        self.channel_handle.load(Ordering::Acquire)
    }

    /// Get socket type
    pub fn socket_type(&self) -> u8 {
        self.socket_type.load(Ordering::Acquire)
    }

    /// Get remote endpoint
    pub fn remote_endpoint(&self) -> u32 {
        self.remote_endpoint.load(Ordering::Acquire) as u32
    }

    /// Get remote identifier
    pub fn remote_id(&self) -> u16 {
        self.remote_id.load(Ordering::Acquire)
    }

    /// Get local identifier
    pub fn local_id(&self) -> u16 {
        self.local_id.load(Ordering::Acquire)
    }
}

impl Default for SocketSlot {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Socket Table
// ============================================================================

static SOCKET_SLOTS: [SocketSlot; MAX_SOCKETS] = [const { SocketSlot::new() }; MAX_SOCKETS];

// ============================================================================
// Socket Service
// ============================================================================

/// Error codes (aliases into kernel::errno)
pub const SOCK_OK: i32 = errno::OK;
pub const SOCK_ERROR: i32 = errno::ERROR;
pub const SOCK_EAGAIN: i32 = errno::EAGAIN;
pub const SOCK_EBUSY: i32 = errno::EBUSY;
pub const SOCK_EINVAL: i32 = errno::EINVAL;
pub const SOCK_EINPROGRESS: i32 = errno::EINPROGRESS;
pub const SOCK_ENODEV: i32 = errno::ENODEV;
pub const SOCK_ENOTCONN: i32 = errno::ENOTCONN;

/// Socket service
pub struct SocketService;

impl SocketService {
    /// Allocate a new socket. `sock_type` is opaque (provider-defined).
    pub fn open(sock_type: u8) -> i32 {
        // Find free slot
        for (i, slot) in SOCKET_SLOTS.iter().enumerate() {
            if slot.try_allocate(sock_type) {
                return i as i32;
            }
        }

        SOCK_EBUSY
    }

    /// Connect socket to remote address. Queues op for provider.
    pub fn connect(handle: i32, addr: &ChannelAddr) -> i32 {
        let slot = match Self::get_slot(handle) {
            Some(s) => s,
            None => return SOCK_EINVAL,
        };

        slot.set_remote(addr.addr, addr.endpoint);
        if !slot.queue_op(SocketOp::Connect) {
            return SOCK_EBUSY;
        }

        SOCK_EINPROGRESS
    }

    /// Bind socket to local port. Queues op for provider.
    pub fn bind(handle: i32, port: u16) -> i32 {
        let slot = match Self::get_slot(handle) {
            Some(s) => s,
            None => return SOCK_EINVAL,
        };

        slot.local_id.store(port, Ordering::Release);

        if !slot.queue_op(SocketOp::Bind) {
            return SOCK_EBUSY;
        }

        SOCK_EINPROGRESS
    }

    /// Start listening for connections. Queues op for provider.
    pub fn listen(handle: i32, _backlog: i32) -> i32 {
        let slot = match Self::get_slot(handle) {
            Some(s) => s,
            None => return SOCK_EINVAL,
        };

        if !slot.queue_op(SocketOp::Listen) {
            return SOCK_EBUSY;
        }

        SOCK_EINPROGRESS
    }

    /// Accept incoming connection. Queues op for provider.
    pub fn accept(handle: i32) -> i32 {
        let slot = match Self::get_slot(handle) {
            Some(s) => s,
            None => return SOCK_EINVAL,
        };

        if !slot.queue_op(SocketOp::Accept) {
            return SOCK_EBUSY;
        }

        SOCK_EINPROGRESS
    }

    /// Poll socket readiness. Buffer state drives POLL_IN/POLL_OUT.
    /// Provider-set poll_flags drive POLL_CONN/POLL_HUP/POLL_ERR.
    pub fn poll(handle: i32, events: u8) -> i32 {
        use crate::kernel::channel::{POLL_IN, POLL_OUT};

        let slot = match Self::get_slot(handle) {
            Some(s) => s,
            None => return SOCK_EINVAL,
        };

        let mut result = 0u8;

        // Buffer-derived readiness
        if (events & POLL_IN) != 0 && slot.rx_available() > 0 {
            result |= POLL_IN;
        }
        if (events & POLL_OUT) != 0 && slot.tx_space() > 0 {
            result |= POLL_OUT;
        }

        // Provider-controlled lifecycle flags (CONN, HUP, ERR)
        result |= events & slot.poll_flags();

        result as i32
    }

    /// Close socket.
    /// Overrides any pending operation — close takes priority.
    pub fn close(handle: i32) -> i32 {
        let slot = match Self::get_slot(handle) {
            Some(s) => s,
            None => return SOCK_EINVAL,
        };

        if slot.is_free() {
            return SOCK_EINVAL;
        }

        // Force-override any pending operation — close takes priority
        slot.pending_op.store(SocketOp::Close as u8, Ordering::Release);

        SOCK_OK
    }

    /// Get socket slot by handle
    pub fn get_slot(handle: i32) -> Option<&'static SocketSlot> {
        if handle < 0 || handle >= MAX_SOCKETS as i32 {
            return None;
        }
        let slot = &SOCKET_SLOTS[handle as usize];
        if slot.is_free() {
            return None;
        }
        Some(slot)
    }

    /// Get slot by index (for async runner)
    pub fn get_slot_by_index(index: usize) -> Option<&'static SocketSlot> {
        SOCKET_SLOTS.get(index)
    }
}

