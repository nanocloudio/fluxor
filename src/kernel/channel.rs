//! Channel - kernel-managed pipes for inter-module data flow.
//!
//! Channels are FIFO buffers that connect modules in the processing graph.
//! The kernel allocates channels at config time and passes handles to modules.
//!
//! Channels are distinct from sockets:
//! - Channels (pipes): Fixed graph wiring between modules, kernel-managed
//! - Sockets: Network connections that modules create internally via socket_* syscalls
//!
//! From a module's perspective, channels are for reading/writing to adjacent
//! modules in the graph. For network I/O, use the socket_* syscalls instead.
//!
//! ## Buffer Modes
//!
//! Each channel's buffer supports two usage modes:
//! - **FIFO:** Ring buffer via channel_write/channel_read (copy semantics, partial OK)
//! - **Mailbox:** Zero-copy via buffer_acquire_write/release/acquire_read/release
//!
//! Mailbox mode is not a separate channel type — it is enabled only when the
//! scheduler aliases two or more edges via `buffer_group` in `open_channels`.
//! See `scheduler::open_channels` for the aliasing rules.
//!
//! ## Mailbox size semantics
//!
//! `channel_read`/`channel_write` work transparently on both FIFO and mailbox
//! channels but enforce exact-size semantics for mailbox:
//!
//! - **channel_read**: if the caller's buffer is smaller than the mailbox payload,
//!   the read is cancelled (`mailbox_cancel_read`) and EINVAL is returned. The
//!   payload stays in READY state for a retry with a larger buffer.
//! - **channel_write**: if the data exceeds the buffer capacity, the acquire is
//!   cancelled (`mailbox_flush`) and EINVAL is returned.
//!
//! No silent truncation occurs in either direction.
//!
//! ## buffer_acquire_write capacity_out semantics
//!
//! `buffer_acquire_write` returns `(null, capacity_out)` in two distinct cases:
//!
//! - **Not a mailbox channel** (`mailbox` flag is false): `capacity_out = 0`.
//! - **Mailbox channel, buffer busy** (not in STREAMING state): `capacity_out > 0`
//!   (the actual buffer capacity).
//!
//! Producers must check `capacity_out` to distinguish these cases. Treating a
//! busy mailbox as "not mailbox" and falling back to FIFO writes would corrupt
//! the in-flight mailbox data.
//!
//! ## In-place processing
//!
//! `buffer_acquire_inplace` allows a downstream module to modify the mailbox
//! buffer in place (READY → PRODUCER). On release, the buffer transitions to
//! READY_PROCESSED instead of READY, which prevents a second in-place module
//! from re-processing the same buffer. The final consumer (`acquire_read`)
//! accepts both READY and READY_PROCESSED.
//!
//! Current design supports at most one in-place module per alias chain. For
//! multiple transforms, insert a FIFO copy step between them.
//!
//! ## FIFO→Mailbox chaining
//!
//! FIFO and mailbox channels coexist in a pipeline: use FIFO where the producer
//! writes incrementally, switch to a mailbox chain at the first module that can
//! produce whole buffers. See `docs/architecture/pipeline.md` §FIFO→Mailbox.

use core::cell::UnsafeCell;
use portable_atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicI8, Ordering};

use crate::kernel::buffer_pool::{self, BUFFER_SIZE};
use crate::kernel::config::MAX_GRAPH_EDGES;
use crate::kernel::errno;
use crate::kernel::ringbuf::RingBufState;
use log::{debug, trace};

// ============================================================================
// Channel Types & Events
// ============================================================================

/// Maximum channels matches max graph edges to support fan-in/out expansion
pub const MAX_CHANNELS: usize = MAX_GRAPH_EDGES;

/// Pipe channel type (FIFO buffer) - the only channel type
pub const CHANNEL_TYPE_PIPE: u8 = 3;

// Poll flags — re-exported from abi::poll for kernel-internal use.
pub use crate::abi::poll::IN as POLL_IN;
pub use crate::abi::poll::OUT as POLL_OUT;
pub use crate::abi::poll::ERR as POLL_ERR;
pub use crate::abi::poll::HUP as POLL_HUP;
pub use crate::abi::poll::CONN as POLL_CONN;

// ============================================================================
// Ioctl Commands (stable ABI values — modules hardcode these)
// ============================================================================

/// Post a u32 notification value to a channel's sideband slot.
/// Semantics are channel-defined (seek position, sample rate, etc.).
pub const IOCTL_NOTIFY: u32 = 1;

/// Atomically read and clear the sideband notification. arg: pointer to u32 output.
/// Returns CHAN_OK if value was pending (written to arg), CHAN_EAGAIN if not.
pub const IOCTL_POLL_NOTIFY: u32 = 2;

/// Full channel reset: clears ring buffer (or mailbox state), HUP flag,
/// sticky event flags (HUP/ERR), and aux_u32. After flush the channel
/// behaves as if freshly opened.
pub const IOCTL_FLUSH: u32 = 3;

/// Set HUP flag (end-of-stream signal from producer).
/// Consumer detects via channel_poll/fd_poll with POLL_HUP.
pub const IOCTL_SET_HUP: u32 = 4;

/// No auxiliary value pending (sentinel).
const NO_AUX_PENDING: u32 = u32::MAX;

// ============================================================================
// Error Codes (aliases into kernel::errno)
// ============================================================================

pub const CHAN_OK: i32 = errno::OK;
pub const CHAN_ERROR: i32 = errno::ERROR;
pub const CHAN_EAGAIN: i32 = errno::EAGAIN;
pub const CHAN_EBUSY: i32 = errno::EBUSY;
pub const CHAN_EINVAL: i32 = errno::EINVAL;
pub const CHAN_EINPROGRESS: i32 = errno::EINPROGRESS;
pub const CHAN_ENOSYS: i32 = errno::ENOSYS;
pub const CHAN_ENOTCONN: i32 = errno::ENOTCONN;
pub const CHAN_ECONNREFUSED: i32 = errno::ECONNREFUSED;
pub const CHAN_ETIMEDOUT: i32 = errno::ETIMEDOUT;

// ============================================================================
// Channel Storage
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChannelState {
    Free = 0,
    Allocated = 1,
    Connected = 2,
}

/// FIFO state for circular buffer operations.
///
/// Uses shared `RingBufState` from `kernel::ringbuf`.
/// `capacity` is set at channel open time from the arena-allocated buffer size.
type FifoState = RingBufState;

struct ChannelSlot {
    state: AtomicU8,
    chan_type: AtomicU8,
    sticky_events: AtomicU8,
    lock: AtomicBool,
    /// HUP flag (producer signals end-of-stream / completion)
    hup_flag: AtomicBool,
    /// Channel is in mailbox mode (zero-copy buffer handoff).
    /// Set by the scheduler for aliased channels (buffer_group != 0).
    /// When false, buffer_acquire_write returns null, forcing FIFO mode.
    mailbox: AtomicBool,
    /// Auxiliary u32 value (module-defined: seek position, file index, etc.)
    /// NO_AUX_PENDING if none pending.
    aux_u32: AtomicU32,
    /// Index into buffer registry (-1 if no buffer allocated)
    buffer_slot: AtomicI8,
    /// FIFO state for circular buffer operations
    fifo: UnsafeCell<FifoState>,
}

unsafe impl Sync for ChannelSlot {}

impl ChannelSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(ChannelState::Free as u8),
            chan_type: AtomicU8::new(0),
            sticky_events: AtomicU8::new(0),
            lock: AtomicBool::new(false),
            hup_flag: AtomicBool::new(false),
            mailbox: AtomicBool::new(false),
            aux_u32: AtomicU32::new(NO_AUX_PENDING),
            buffer_slot: AtomicI8::new(-1),
            fifo: UnsafeCell::new(FifoState::new()),
        }
    }

    fn try_allocate(&self, idx: usize, buf_capacity: usize) -> bool {
        if self
            .state
            .compare_exchange(
                ChannelState::Free as u8,
                ChannelState::Allocated as u8,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            // Allocate an arena-backed buffer of the requested size
            let buf_slot = buffer_pool::alloc_streaming(idx as i8, buf_capacity);
            if buf_slot < 0 {
                // No buffer available, rollback
                self.state.store(ChannelState::Free as u8, Ordering::Release);
                return false;
            }
            self.buffer_slot.store(buf_slot as i8, Ordering::Release);
            self.chan_type.store(CHANNEL_TYPE_PIPE, Ordering::Release);
            self.sticky_events.store(0, Ordering::Release);
            // Initialize FIFO with the allocated capacity
            unsafe {
                (*self.fifo.get()).init(buf_capacity);
            }
            true
        } else {
            false
        }
    }

    fn reset(&self) {
        // Free buffer back to registry
        let buf_slot = self.buffer_slot.swap(-1, Ordering::AcqRel);
        if buf_slot >= 0 {
            buffer_pool::free_streaming(buf_slot as i32);
        }
        self.state.store(ChannelState::Free as u8, Ordering::Release);
        self.chan_type.store(0, Ordering::Release);
        self.sticky_events.store(0, Ordering::Release);
        self.hup_flag.store(false, Ordering::Release);
        self.mailbox.store(false, Ordering::Release);
        self.aux_u32.store(NO_AUX_PENDING, Ordering::Release);
        unsafe {
            *self.fifo.get() = FifoState::new();
        }
    }

    fn is_pipe(&self) -> bool {
        self.chan_type.load(Ordering::Acquire) == CHANNEL_TYPE_PIPE
    }

    fn get_buffer_ptr(&self) -> *mut u8 {
        let slot = self.buffer_slot.load(Ordering::Acquire);
        if slot < 0 {
            return core::ptr::null_mut();
        }
        buffer_pool::get_streaming_ptr(slot as i32)
    }

    fn with_lock<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut FifoState, Option<&mut [u8]>) -> R,
    {
        // Bounded spin with yield to prevent starvation under cross-core contention.
        // The critical section is short (ring buffer read/write), so contention is brief.
        let mut spins = 0u32;
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            spins += 1;
            if spins > 256 {
                #[cfg(target_arch = "aarch64")]
                unsafe { core::arch::asm!("yield", options(nomem, nostack)); }
                spins = 0;
            }
            core::hint::spin_loop();
        }
        let buf_ptr = self.get_buffer_ptr();
        let fifo = unsafe { &mut *self.fifo.get() };
        let storage = if buf_ptr.is_null() {
            None
        } else {
            Some(unsafe { core::slice::from_raw_parts_mut(buf_ptr, fifo.capacity()) })
        };
        let result = f(fifo, storage);
        self.lock.store(false, Ordering::Release);
        result
    }
}

static CHANNELS: [ChannelSlot; MAX_CHANNELS] = [const { ChannelSlot::new() }; MAX_CHANNELS];

// ============================================================================
// Channel API
// ============================================================================

pub fn channel_open(chan_type: u8, config: *const u8, config_len: usize) -> i32 {
    if chan_type != CHANNEL_TYPE_PIPE {
        return CHAN_EINVAL;
    }
    // Read requested buffer size from config (2 bytes LE), or use default.
    // Always rounds up to a power of two — ring buffer uses bitwise AND
    // for wrap-around instead of modulo (saves ~20-40 cycles on CM33).
    let buf_capacity = if !config.is_null() && config_len >= 2 {
        let size = unsafe {
            u16::from_le_bytes([*config, *config.add(1)]) as usize
        };
        // Clamp to sane range, then round up to power of two
        let clamped = size.max(64).min(4096);
        clamped.next_power_of_two()
    } else {
        BUFFER_SIZE // 2048 default (already power of 2)
    };

    // Allocate a pipe channel with an arena-backed buffer
    for (idx, slot) in CHANNELS.iter().enumerate() {
        if slot.try_allocate(idx, buf_capacity) {
            slot.state
                .store(ChannelState::Connected as u8, Ordering::Release);
            debug!("channel_open: allocated channel {} buf_size={}", idx, buf_capacity);
            return idx as i32;
        }
    }
    CHAN_EBUSY
}

pub fn channel_close(handle: i32) {
    if handle < 0 {
        return;
    }
    let idx = handle as usize;
    if idx >= MAX_CHANNELS {
        return;
    }
    CHANNELS[idx].reset();
}

pub unsafe fn channel_read(handle: i32, buf: *mut u8, len: usize) -> i32 {
    if buf.is_null() {
        return CHAN_EINVAL;
    }
    if handle < 0 {
        return CHAN_EINVAL;
    }
    let idx = handle as usize;
    if idx >= MAX_CHANNELS {
        return CHAN_EINVAL;
    }
    let slot = &CHANNELS[idx];
    if !slot.is_pipe() {
        return CHAN_EINVAL;
    }
    if slot.mailbox.load(Ordering::Acquire) {
        // Mailbox channel: acquire → copy to caller's buffer → release.
        // Unlike FIFO, mailbox release is all-or-nothing — partial reads
        // would discard the unreturned tail. Require the caller to provide
        // a buffer large enough for the entire payload.
        let buf_slot = slot.buffer_slot.load(Ordering::Acquire) as i32;
        if buf_slot < 0 {
            return CHAN_EAGAIN;
        }
        let (mbox_ptr, mbox_len) = buffer_pool::mailbox_acquire_read(buf_slot);
        if mbox_ptr.is_null() {
            return CHAN_EAGAIN; // No data ready (not in READY state)
        }
        if (len as u32) < mbox_len {
            // Caller's buffer too small — cancel the acquire so the payload
            // stays in READY state for a retry with a larger buffer.
            buffer_pool::mailbox_cancel_read(buf_slot);
            return CHAN_EINVAL;
        }
        let copy_len = mbox_len as usize;
        core::ptr::copy_nonoverlapping(mbox_ptr, buf, copy_len);
        buffer_pool::mailbox_release_read(buf_slot);
        trace!("chan_read h={} mailbox copy_len={}", handle, copy_len);
        return copy_len as i32;
    }
    let out = core::slice::from_raw_parts_mut(buf, len);
    let read = slot.with_lock(|fifo, storage| {
        let Some(storage) = storage else { return -1i32 };
        fifo.read(storage, out) as i32
    });
    if read < 0 {
        return CHAN_EINVAL; // Channel buffer not allocated
    }
    if read == 0 {
        CHAN_EAGAIN
    } else {
        read
    }
}

pub unsafe fn channel_write(handle: i32, data: *const u8, len: usize) -> i32 {
    if data.is_null() {
        return CHAN_EINVAL;
    }
    if handle < 0 {
        return CHAN_EINVAL;
    }
    let idx = handle as usize;
    if idx >= MAX_CHANNELS {
        return CHAN_EINVAL;
    }
    let slot = &CHANNELS[idx];
    if !slot.is_pipe() {
        return CHAN_EINVAL;
    }
    if slot.mailbox.load(Ordering::Acquire) {
        // Mailbox channel: acquire → copy from caller's buffer → release.
        // Unlike FIFO, mailbox release publishes the entire payload atomically —
        // a short write would discard the remainder on the next cycle.
        // Reject writes that exceed buffer capacity.
        let buf_slot = slot.buffer_slot.load(Ordering::Acquire) as i32;
        if buf_slot < 0 {
            return CHAN_EAGAIN;
        }
        let (mbox_ptr, cap) = buffer_pool::mailbox_acquire_write(buf_slot);
        if mbox_ptr.is_null() {
            return CHAN_EAGAIN; // Buffer busy (not in STREAMING state)
        }
        if len as u32 > cap {
            // Payload exceeds buffer capacity — cancel the acquire so the
            // mailbox returns to STREAMING for a retry with smaller data.
            buffer_pool::mailbox_flush(buf_slot);
            return CHAN_EINVAL;
        }
        core::ptr::copy_nonoverlapping(data, mbox_ptr, len);
        buffer_pool::mailbox_release_write(buf_slot, len as u32);
        trace!("chan_write h={} mailbox len={}", handle, len);
        return len as i32;
    }
    let input = core::slice::from_raw_parts(data, len);
    let written = slot.with_lock(|fifo, storage| {
        let Some(storage) = storage else { return -1i32 };
        fifo.write(storage, input) as i32
    });
    if written < 0 {
        return CHAN_EINVAL; // Channel buffer not allocated
    }
    if written == 0 {
        CHAN_EAGAIN
    } else {
        written
    }
}

pub fn channel_poll(handle: i32, events: u8) -> i32 {
    if handle < 0 {
        return CHAN_EINVAL;
    }
    let idx = handle as usize;
    if idx >= MAX_CHANNELS {
        return CHAN_EINVAL;
    }
    let slot = &CHANNELS[idx];
    if !slot.is_pipe() {
        return CHAN_EINVAL;
    }
    let mut ready = 0u8;
    if slot.mailbox.load(Ordering::Acquire) {
        // Mailbox channels: check buffer state for readiness.
        // POLL_IN = mailbox has data (READY/READY_PROCESSED state).
        // POLL_OUT = mailbox can accept a write (STREAMING state).
        // channel_read/channel_write handle mailbox transparently, so
        // poll semantics are consistent for both FIFO and mailbox modes.
        let buf_slot = slot.buffer_slot.load(Ordering::Acquire);
        if buf_slot >= 0 {
            if (events & POLL_IN) != 0 && buffer_pool::mailbox_has_data(buf_slot as i32) {
                ready |= POLL_IN;
            }
            if (events & POLL_OUT) != 0 && buffer_pool::mailbox_can_write(buf_slot as i32) {
                ready |= POLL_OUT;
            }
        }
    } else {
        // FIFO channels: check ring buffer occupancy
        let (readable, writable) = slot.with_lock(|fifo, _storage| {
            (fifo.is_readable(), fifo.is_writable())
        });
        if (events & POLL_IN) != 0 && readable {
            ready |= POLL_IN;
        }
        if (events & POLL_OUT) != 0 && writable {
            ready |= POLL_OUT;
        }
    }
    // Include persistent flags (HUP, ERR) if requested
    let persistent = slot.sticky_events.load(Ordering::Acquire);
    if (events & POLL_HUP) != 0 {
        // Check both: permanent HUP (from scheduler) and hup_flag (from IOCTL_SET_HUP).
        // hup_flag is non-destructive here — cleared by IOCTL_FLUSH when
        // the consumer starts a new stream.
        if (persistent & POLL_HUP) != 0 || slot.hup_flag.load(Ordering::Acquire) {
            ready |= POLL_HUP;
        }
    }
    if (events & POLL_ERR) != 0 && (persistent & POLL_ERR) != 0 {
        ready |= POLL_ERR;
    }
    trace!(
        "chan_poll h={} events=0x{:02x} ready=0x{:02x}",
        handle, events, ready
    );
    ready as i32
}

pub fn channel_ioctl(handle: i32, cmd: u32, arg: *mut u8) -> i32 {
    if handle < 0 {
        return CHAN_EINVAL;
    }
    let idx = handle as usize;
    if idx >= MAX_CHANNELS {
        return CHAN_EINVAL;
    }
    let slot = &CHANNELS[idx];
    if !slot.is_pipe() {
        return CHAN_EINVAL;
    }

    match cmd {
        IOCTL_NOTIFY => {
            // Post sideband notification value
            if arg.is_null() {
                return CHAN_EINVAL;
            }
            let val = unsafe { *(arg as *const u32) };
            slot.aux_u32.store(val, Ordering::Release);
            debug!("chan_ioctl h={} NOTIFY val={}", handle, val);
            CHAN_OK
        }
        IOCTL_POLL_NOTIFY => {
            // Atomically read and clear sideband notification
            if arg.is_null() {
                return CHAN_EINVAL;
            }
            let val = slot.aux_u32.swap(NO_AUX_PENDING, Ordering::AcqRel);
            if val == NO_AUX_PENDING {
                CHAN_EAGAIN
            } else {
                unsafe { *(arg as *mut u32) = val; }
                debug!("chan_ioctl h={} POLL_NOTIFY val={}", handle, val);
                CHAN_OK
            }
        }
        IOCTL_FLUSH => {
            // Clear ring buffer and reset flags
            if slot.mailbox.load(Ordering::Acquire) {
                // Mailbox: reset buffer slot back to STREAMING so it can be reused
                let buf_slot = slot.buffer_slot.load(Ordering::Acquire);
                if buf_slot >= 0 {
                    buffer_pool::mailbox_flush(buf_slot as i32);
                }
            } else {
                // FIFO: flush ring buffer
                slot.with_lock(|fifo, _storage| {
                    fifo.clear();
                });
            }
            slot.hup_flag.store(false, Ordering::Release);
            slot.sticky_events.store(0, Ordering::Release);
            slot.aux_u32.store(NO_AUX_PENDING, Ordering::Release);
            debug!("chan_ioctl h={} FLUSH", handle);
            CHAN_OK
        }
        IOCTL_SET_HUP => {
            // Set HUP flag (producer signals completion / end-of-stream)
            slot.hup_flag.store(true, Ordering::Release);
            debug!("chan_ioctl h={} SET_HUP", handle);
            CHAN_OK
        }
        _ => CHAN_ENOSYS,
    }
}

/// Enable mailbox mode on a channel.
///
/// Called by the scheduler for aliased channels (buffer_group != 0).
/// When set, buffer_acquire_write and buffer_acquire_inplace are allowed
/// on this channel, enabling zero-copy producer→consumer handoff and
/// in-place processing by intermediate modules.
pub fn channel_set_mailbox(handle: i32) {
    if handle < 0 {
        return;
    }
    let idx = handle as usize;
    if idx >= MAX_CHANNELS {
        return;
    }
    CHANNELS[idx].mailbox.store(true, Ordering::Release);
    debug!("channel_set_mailbox: ch {} enabled", handle);
}

/// Return readable bytes in channel's ring buffer (0 for invalid/mailbox/empty).
pub fn channel_readable_bytes(handle: i32) -> usize {
    if handle < 0 { return 0; }
    let idx = handle as usize;
    if idx >= MAX_CHANNELS { return 0; }
    let slot = &CHANNELS[idx];
    if !slot.is_pipe() { return 0; }
    if slot.mailbox.load(Ordering::Acquire) { return 0; }
    slot.with_lock(|fifo, _| fifo.len())
}

/// Return true if channel is in mailbox mode.
pub fn channel_is_mailbox(handle: i32) -> bool {
    if handle < 0 { return false; }
    let idx = handle as usize;
    if idx >= MAX_CHANNELS { return false; }
    CHANNELS[idx].mailbox.load(Ordering::Acquire)
}

/// Set persistent flags (HUP, ERR) on a channel.
///
/// These flags are returned by channel_poll() and indicate:
/// - POLL_HUP: Writer has finished (upstream module done)
/// - POLL_ERR: Writer encountered an error (upstream module error)
///
/// Once set, these flags persist until the channel is closed.
pub fn channel_set_flags(handle: i32, flags: u8) {
    if handle < 0 {
        return;
    }
    let idx = handle as usize;
    if idx >= MAX_CHANNELS {
        return;
    }
    let slot = &CHANNELS[idx];
    // Atomically OR the new flags with existing flags
    slot.sticky_events.fetch_or(flags, Ordering::Release);
}

// ============================================================================
// Syscall Entry Points
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn syscall_channel_open(
    chan_type: u8,
    config: *const u8,
    config_len: usize,
) -> i32 {
    channel_open(chan_type, config, config_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn syscall_channel_close(handle: i32) {
    channel_close(handle);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_channel_read(handle: i32, buf: *mut u8, len: usize) -> i32 {
    channel_read(handle, buf, len)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_channel_write(handle: i32, data: *const u8, len: usize) -> i32 {
    channel_write(handle, data, len)
}

#[unsafe(no_mangle)]
pub extern "C" fn syscall_channel_poll(handle: i32, events: u8) -> i32 {
    channel_poll(handle, events)
}

#[unsafe(no_mangle)]
pub extern "C" fn syscall_channel_ioctl(handle: i32, cmd: u32, arg: *mut u8) -> i32 {
    channel_ioctl(handle, cmd, arg)
}

// ============================================================================
// Zero-Copy Mailbox Syscalls
// ============================================================================
//
// These use the channel's own arena-allocated buffer as a single-message
// mailbox. The buffer transitions:
//   STREAMING (idle) → PRODUCER (writing) → READY (data) → CONSUMER (reading) → STREAMING
//
// No pool scan needed — the channel knows its buffer slot directly.

/// Acquire write access to the channel's buffer (mailbox mode).
///
/// Returns pointer to buffer data for direct writing, or null if:
/// - Channel is not in mailbox mode (FIFO-only channels return null)
/// - Buffer is not in idle state (previous message not yet consumed)
///
/// The mailbox flag is set by the scheduler for aliased channels (buffer_group != 0).
/// This prevents producers from accidentally using mailbox mode on FIFO channels,
/// which would cause data loss (FIFO reads check ring buffer head/tail, not buffer state).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_buffer_acquire_write(chan: i32, capacity_out: *mut u32) -> *mut u8 {
    if chan < 0 || chan as usize >= MAX_CHANNELS {
        if !capacity_out.is_null() { *capacity_out = 0; }
        return core::ptr::null_mut();
    }

    let channel = &CHANNELS[chan as usize];

    // Only allow mailbox writes on channels explicitly marked for mailbox mode
    if !channel.mailbox.load(Ordering::Acquire) {
        if !capacity_out.is_null() { *capacity_out = 0; }
        return core::ptr::null_mut();
    }

    let buf_slot = channel.buffer_slot.load(Ordering::Acquire);
    if buf_slot < 0 {
        if !capacity_out.is_null() { *capacity_out = 0; }
        return core::ptr::null_mut();
    }

    // Transition channel's buffer: STREAMING → PRODUCER
    let (ptr, cap) = buffer_pool::mailbox_acquire_write(buf_slot as i32);
    if ptr.is_null() {
        // Buffer is busy (not STREAMING) — signal mailbox-busy to the caller
        // by writing the buffer capacity. This lets producers distinguish
        // "not a mailbox channel" (capacity_out=0) from "mailbox channel,
        // buffer busy" (capacity_out>0) and avoid falling back to FIFO writes
        // that would corrupt the pending mailbox data.
        if !capacity_out.is_null() {
            *capacity_out = buffer_pool::get_capacity(buf_slot as i32);
        }
        return core::ptr::null_mut();
    }

    if !capacity_out.is_null() {
        *capacity_out = cap;
    }
    ptr
}

/// Release buffer after writing (mailbox mode: PRODUCER → READY).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_buffer_release_write(chan: i32, len: u32) -> i32 {
    if chan < 0 || chan as usize >= MAX_CHANNELS {
        return CHAN_EINVAL;
    }

    let channel = &CHANNELS[chan as usize];
    let buf_slot = channel.buffer_slot.load(Ordering::Acquire);
    if buf_slot < 0 {
        return CHAN_EINVAL;
    }

    buffer_pool::mailbox_release_write(buf_slot as i32, len)
}

/// Acquire read access to the channel's buffer (mailbox mode: READY → CONSUMER).
///
/// Returns pointer to buffer data, or null if no message ready.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_buffer_acquire_read(chan: i32, len_out: *mut u32) -> *const u8 {
    if chan < 0 || chan as usize >= MAX_CHANNELS {
        return core::ptr::null();
    }

    let channel = &CHANNELS[chan as usize];
    let buf_slot = channel.buffer_slot.load(Ordering::Acquire);
    if buf_slot < 0 {
        return core::ptr::null();
    }

    let (ptr, len) = buffer_pool::mailbox_acquire_read(buf_slot as i32);
    if ptr.is_null() {
        return core::ptr::null();
    }

    if !len_out.is_null() {
        *len_out = len;
    }
    ptr
}

/// Release buffer after reading (mailbox mode: CONSUMER → STREAMING).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_buffer_release_read(chan: i32) -> i32 {
    if chan < 0 || chan as usize >= MAX_CHANNELS {
        return CHAN_EINVAL;
    }

    let channel = &CHANNELS[chan as usize];
    let buf_slot = channel.buffer_slot.load(Ordering::Acquire);
    if buf_slot < 0 {
        return CHAN_EINVAL;
    }

    buffer_pool::mailbox_release_read(buf_slot as i32)
}

/// Acquire in-place access to the channel's buffer (READY → PRODUCER).
///
/// For aliased buffer chains where an in-place module reads and modifies
/// the upstream module's output buffer directly. Returns a mutable pointer
/// to the existing data. After processing, call buffer_release_write to
/// transition back to READY for the next module in the chain.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_buffer_acquire_inplace(chan: i32, len_out: *mut u32) -> *mut u8 {
    if chan < 0 || chan as usize >= MAX_CHANNELS {
        return core::ptr::null_mut();
    }

    let channel = &CHANNELS[chan as usize];
    let buf_slot = channel.buffer_slot.load(Ordering::Acquire);
    if buf_slot < 0 {
        return core::ptr::null_mut();
    }

    // Transition channel's buffer: READY → PRODUCER
    let (ptr, len) = buffer_pool::mailbox_acquire_inplace(buf_slot as i32);
    if ptr.is_null() {
        return core::ptr::null_mut();
    }

    if !len_out.is_null() {
        *len_out = len;
    }
    ptr
}
