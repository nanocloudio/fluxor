//! Unified file descriptor table — tagged handles and unified poll.
//!
//! Every kernel resource handle (channel, event, PIO, etc.) is encoded
//! as a tagged i32: bits [30..27] = type tag (4 bits), bits [26..0] = slot index.
//! Bit 31 is always 0, so tagged fds are positive and error codes (negative) are unambiguous.
//!
//! `fd_poll` provides non-destructive (peek) readiness checks across all handle types.
//! Modules use `fd_poll` for readiness, then the per-type API for consumption.

use portable_atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use crate::kernel::channel::{self, POLL_IN};
use crate::kernel::errno;
use crate::kernel::event;
use crate::kernel::hal;
// ============================================================================
// Tag constants
// ============================================================================

pub const FD_TAG_CHANNEL: i32 = 0;
pub const FD_TAG_EVENT: i32 = 2;
pub const FD_TAG_TIMER: i32 = 3;
// Tags 4-6 were PIO stream/cmd/rx (removed — PIC module handles PIO directly)
pub const FD_TAG_DMA: i32 = 7;
pub const FD_TAG_BRIDGE: i32 = 8;

const TAG_SHIFT: u32 = 27;
const SLOT_MASK: i32 = 0x07FF_FFFF;

// ============================================================================
// Encode / decode
// ============================================================================

/// Encode a type tag and slot index into a tagged fd.
/// Only call on success (slot >= 0). Error codes pass through unchanged.
#[inline]
pub fn tag_fd(tag: i32, slot: i32) -> i32 {
    if slot < 0 {
        return slot; // error code, don't tag
    }
    (tag << TAG_SHIFT) | (slot & SLOT_MASK)
}

/// Decode a tagged fd into (tag, slot).
#[inline]
pub fn untag_fd(fd: i32) -> (i32, i32) {
    let tag = (fd >> TAG_SHIFT) & 0xF; // 4 bits
    let slot = fd & SLOT_MASK;
    (tag, slot)
}

/// Strip the tag from a handle, returning just the slot index.
/// Use at typed syscall entry points to accept both tagged and raw handles.
#[inline]
pub fn slot_of(fd: i32) -> i32 {
    fd & SLOT_MASK
}

// ============================================================================
// Timer-as-fd
// ============================================================================

const MAX_TIMERS: usize = 16;

struct TimerSlot {
    allocated: AtomicBool,
    active: AtomicBool,
    owner: AtomicU8,
    /// Deadline in milliseconds (from Instant epoch), wrapping-safe comparison
    deadline_ms: AtomicU32,
}

impl TimerSlot {
    const fn new() -> Self {
        Self {
            allocated: AtomicBool::new(false),
            active: AtomicBool::new(false),
            owner: AtomicU8::new(0xFF),
            deadline_ms: AtomicU32::new(0),
        }
    }
}

static TIMER_SLOTS: [TimerSlot; MAX_TIMERS] = [const { TimerSlot::new() }; MAX_TIMERS];

fn now_ms() -> u32 {
    hal::now_millis() as u32
}

/// Create a new timer owned by the current module.
/// Returns tagged fd or negative errno.
pub fn timer_create() -> i32 {
    let owner = crate::kernel::scheduler::current_module_index() as u8;
    for i in 0..MAX_TIMERS {
        if TIMER_SLOTS[i]
            .allocated
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            TIMER_SLOTS[i].active.store(false, Ordering::Release);
            TIMER_SLOTS[i].owner.store(owner, Ordering::Release);
            TIMER_SLOTS[i].deadline_ms.store(0, Ordering::Release);
            return tag_fd(FD_TAG_TIMER, i as i32);
        }
    }
    errno::ENOMEM
}

/// Start (or restart) a timer with a delay in milliseconds.
/// The fd must be a tagged timer handle.
pub fn timer_set(fd: i32, delay_ms: u32) -> i32 {
    let slot = slot_of(fd);
    if slot < 0 || slot as usize >= MAX_TIMERS {
        return errno::EINVAL;
    }
    let timer = &TIMER_SLOTS[slot as usize];
    if !timer.allocated.load(Ordering::Acquire) {
        return errno::EINVAL;
    }
    let deadline = now_ms().wrapping_add(delay_ms);
    timer.deadline_ms.store(deadline, Ordering::Release);
    timer.active.store(true, Ordering::Release);
    0
}

/// Cancel an active timer (stop it without destroying).
pub fn timer_cancel(fd: i32) -> i32 {
    let slot = slot_of(fd);
    if slot < 0 || slot as usize >= MAX_TIMERS {
        return errno::EINVAL;
    }
    let timer = &TIMER_SLOTS[slot as usize];
    if !timer.allocated.load(Ordering::Acquire) {
        return errno::EINVAL;
    }
    timer.active.store(false, Ordering::Release);
    0
}

/// Destroy a timer and free its slot.
pub fn timer_destroy(fd: i32) -> i32 {
    let slot = slot_of(fd);
    if slot < 0 || slot as usize >= MAX_TIMERS {
        return errno::EINVAL;
    }
    let timer = &TIMER_SLOTS[slot as usize];
    if !timer.allocated.load(Ordering::Acquire) {
        return errno::EINVAL;
    }
    timer.active.store(false, Ordering::Release);
    timer.owner.store(0xFF, Ordering::Release);
    timer.allocated.store(false, Ordering::Release);
    0
}

/// Non-destructive check: has this timer expired?
fn timer_is_expired(slot: i32) -> bool {
    if slot < 0 || slot as usize >= MAX_TIMERS {
        return false;
    }
    let timer = &TIMER_SLOTS[slot as usize];
    if !timer.allocated.load(Ordering::Acquire) || !timer.active.load(Ordering::Acquire) {
        return false;
    }
    let deadline = timer.deadline_ms.load(Ordering::Acquire);
    let now = now_ms();
    // Wrapping-safe: (now - deadline) as signed >= 0 means expired
    (now.wrapping_sub(deadline) as i32) >= 0
}

/// Release all timer slots owned by a specific module. Called on module finish.
pub fn release_timers_owned_by(module_idx: u8) {
    for i in 0..MAX_TIMERS {
        let timer = &TIMER_SLOTS[i];
        if !timer.allocated.load(Ordering::Acquire) {
            continue;
        }
        if timer.owner.load(Ordering::Acquire) != module_idx {
            continue;
        }
        timer.active.store(false, Ordering::Release);
        timer.owner.store(0xFF, Ordering::Release);
        timer.allocated.store(false, Ordering::Release);
    }
}

// ============================================================================
// DMA-as-fd — platform-specific, delegated to syscalls module
// ============================================================================

// DMA FD operations (create, start, queue, restart, free, poll, release)
// are platform-specific (RP-only, using PAC DMA registers).
// They remain in syscalls.rs / rp/providers.rs behind the platform include!.
// The fd_poll dispatch below routes DMA tags to the platform's dma_fd_poll function.

/// Platform DMA FD poll function pointer — set by RP platform at init.
static mut DMA_FD_POLL_FN: Option<fn(i32) -> bool> = None;

/// Register a platform DMA FD poll function (called from platform init).
pub fn register_dma_fd_poll(f: fn(i32) -> bool) {
    unsafe { DMA_FD_POLL_FN = Some(f); }
}

// ============================================================================
// Unified poll
// ============================================================================

/// Non-destructive poll across all handle types.
///
/// Returns a bitmask of ready events (POLL_IN, POLL_OUT, POLL_ERR, POLL_HUP),
/// or a negative errno on error.
///
/// Unlike per-type polls (e.g. `event_poll` which clears the signal),
/// `fd_poll` is peek-only — it never consumes state.
pub fn fd_poll(fd: i32, events: u8) -> i32 {
    if fd < 0 {
        return errno::EINVAL;
    }
    let ev = events as u32;
    let (tag, slot) = untag_fd(fd);
    match tag {
        FD_TAG_CHANNEL => {
            // channel_poll is already non-destructive and returns a bitmask
            channel::channel_poll(slot, ev)
        }
        FD_TAG_EVENT => {
            // Non-destructive peek (load, not swap)
            let mut ready = 0u32;
            if (ev & POLL_IN) != 0 && event::event_is_signaled(slot) {
                ready |= POLL_IN;
            }
            ready as i32
        }
        FD_TAG_TIMER => {
            // Timer expired -> POLL_IN
            let mut ready = 0u32;
            if (ev & POLL_IN) != 0 && timer_is_expired(slot) {
                ready |= POLL_IN;
            }
            ready as i32
        }
        FD_TAG_DMA => {
            // Route to platform DMA FD poll (RP-only; returns false on other platforms)
            let mut ready = 0u32;
            if (ev & POLL_IN) != 0 {
                let poll_fn = unsafe { DMA_FD_POLL_FN };
                if let Some(f) = poll_fn {
                    if f(slot) {
                        ready |= POLL_IN;
                    }
                }
            }
            ready as i32
        }
        FD_TAG_BRIDGE => {
            let mut ready = 0u32;
            if (ev & POLL_IN) != 0 {
                let poll = crate::kernel::bridge::bridge_dispatch(slot as usize, 2, core::ptr::null_mut(), 0);
                if poll > 0 { ready |= POLL_IN; }
            }
            ready as i32
        }
        _ => errno::EINVAL,
    }
}

// ============================================================================
// Batch poll
// ============================================================================

/// Poll multiple fds in one call. Returns count of fds with ready events.
///
/// For each fd, writes the ready bitmask to `ready[i]` (0 if nothing ready or error).
/// This is the `select()`/`epoll()` equivalent for modules.
pub fn fd_poll_multi(fds: &[i32], events: &[u8], ready: &mut [u8]) -> i32 {
    let mut count = 0i32;
    for i in 0..fds.len() {
        let result = fd_poll(fds[i], events[i]);
        if result > 0 {
            ready[i] = result as u8;
            count += 1;
        } else {
            ready[i] = 0;
        }
    }
    count
}
