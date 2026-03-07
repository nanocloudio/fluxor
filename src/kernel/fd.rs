//! Unified file descriptor table — tagged handles and unified poll.
//!
//! Every kernel resource handle (channel, socket, event, PIO, etc.) is encoded
//! as a tagged i32: bits [30..27] = type tag (4 bits), bits [26..0] = slot index.
//! Bit 31 is always 0, so tagged fds are positive and error codes (negative) are unambiguous.
//!
//! `fd_poll` provides non-destructive (peek) readiness checks across all handle types.
//! Modules use `fd_poll` for readiness, then the per-type API for consumption.

use portable_atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering, compiler_fence};
use embassy_time::Instant;

use crate::kernel::channel::{self, POLL_IN, POLL_OUT};
use crate::kernel::errno;
use crate::kernel::event;
use crate::kernel::socket::SocketService;
use crate::io::pio::{PioStreamService, PioCmdService, PioRxStreamService};

// ============================================================================
// Tag constants
// ============================================================================

pub const FD_TAG_CHANNEL: i32 = 0;
pub const FD_TAG_SOCKET: i32 = 1;
pub const FD_TAG_EVENT: i32 = 2;
pub const FD_TAG_TIMER: i32 = 3;
pub const FD_TAG_PIO_STREAM: i32 = 4;
pub const FD_TAG_PIO_CMD: i32 = 5;
pub const FD_TAG_PIO_RX_STREAM: i32 = 6;
pub const FD_TAG_DMA: i32 = 7;

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
    Instant::now().as_millis() as u32
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
// DMA-as-fd
// ============================================================================

const MAX_DMA_FDS: usize = 8;

struct DmaFdSlot {
    allocated: AtomicBool,
    owner: AtomicU8,
    channel_a: AtomicU8,      // First DMA channel (8-15)
    channel_b: AtomicU8,      // Second DMA channel for ping-pong
    active_is_b: AtomicBool,  // false=A active, true=B active
    pending: AtomicBool,      // queue() called since last poll-ready
}

impl DmaFdSlot {
    const fn new() -> Self {
        Self {
            allocated: AtomicBool::new(false),
            owner: AtomicU8::new(0xFF),
            channel_a: AtomicU8::new(0xFF),
            channel_b: AtomicU8::new(0xFF),
            active_is_b: AtomicBool::new(false),
            pending: AtomicBool::new(false),
        }
    }

    fn active_ch(&self) -> u8 {
        if self.active_is_b.load(Ordering::Acquire) {
            self.channel_b.load(Ordering::Acquire)
        } else {
            self.channel_a.load(Ordering::Acquire)
        }
    }

    fn inactive_ch(&self) -> u8 {
        if self.active_is_b.load(Ordering::Acquire) {
            self.channel_a.load(Ordering::Acquire)
        } else {
            self.channel_b.load(Ordering::Acquire)
        }
    }
}

static DMA_FD_SLOTS: [DmaFdSlot; MAX_DMA_FDS] = [const { DmaFdSlot::new() }; MAX_DMA_FDS];

/// Create a new DMA FD: allocates two DMA channels (CH8-15) for ping-pong and
/// wraps them in a tagged fd. Returns tagged fd or negative errno.
pub fn dma_fd_create() -> i32 {
    let ch_a = crate::kernel::syscalls::dma_alloc_channel();
    if ch_a < 0 {
        return ch_a;
    }
    let ch_b = crate::kernel::syscalls::dma_alloc_channel();
    if ch_b < 0 {
        crate::kernel::syscalls::dma_free_channel(ch_a as u8);
        return ch_b;
    }
    let owner = crate::kernel::scheduler::current_module_index() as u8;
    for i in 0..MAX_DMA_FDS {
        if DMA_FD_SLOTS[i]
            .allocated
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            DMA_FD_SLOTS[i].owner.store(owner, Ordering::Release);
            DMA_FD_SLOTS[i].channel_a.store(ch_a as u8, Ordering::Release);
            DMA_FD_SLOTS[i].channel_b.store(ch_b as u8, Ordering::Release);
            DMA_FD_SLOTS[i].active_is_b.store(false, Ordering::Release);
            DMA_FD_SLOTS[i].pending.store(false, Ordering::Release);
            return tag_fd(FD_TAG_DMA, i as i32);
        }
    }
    crate::kernel::syscalls::dma_free_channel(ch_a as u8);
    crate::kernel::syscalls::dma_free_channel(ch_b as u8);
    errno::ENOMEM
}

/// Start a full DMA transfer on a DMA FD.
/// Configures and starts channel A. Pre-configures channel B with same
/// WRITE_ADDR/DREQ/flags but doesn't start it (ready for dma_fd_queue).
pub fn dma_fd_start(fd: i32, read_addr: u32, write_addr: u32, count: u32, dreq: u8, flags: u8) -> i32 {
    let slot = slot_of(fd);
    if slot < 0 || slot as usize >= MAX_DMA_FDS {
        return errno::EINVAL;
    }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) {
        return errno::EINVAL;
    }
    let ch_a = dma.channel_a.load(Ordering::Acquire);
    let ch_b = dma.channel_b.load(Ordering::Acquire);

    // Start channel A
    let rc = unsafe { crate::kernel::syscalls::dma_start_raw(ch_a, read_addr, write_addr, count, dreq, flags) };
    if rc < 0 { return rc; }

    // Pre-configure channel B with same WRITE_ADDR, DREQ, flags — but don't start.
    // Write WRITE_ADDR, then write CTRL (not CTRL_TRIG) with EN=false, CHAIN_TO=self.
    unsafe { dma_preconfigure_inactive(ch_b, write_addr, dreq, flags); }

    dma.active_is_b.store(false, Ordering::Release);
    dma.pending.store(false, Ordering::Release);
    rc
}

/// Pre-configure a DMA channel's WRITE_ADDR and CTRL without starting it.
/// CHAIN_TO = self (no chaining until queue sets it on the active channel).
unsafe fn dma_preconfigure_inactive(ch: u8, write_addr: u32, dreq: u8, flags: u8) {
    use embassy_rp::pac;
    let dma_ch = pac::DMA.ch(ch as usize);

    // Set WRITE_ADDR
    dma_ch.write_addr().write_value(write_addr);

    let incr_read = flags & 0x01 != 0;
    let incr_write = flags & 0x02 != 0;
    let data_size = if flags & 0x04 != 0 {
        pac::dma::vals::DataSize::SIZE_WORD
    } else {
        pac::dma::vals::DataSize::SIZE_HALFWORD
    };

    // Write to AL1_CTRL (no trigger) — build CtrlTrig for correct bit positions,
    // then write its raw u32 value through the al1_ctrl register.
    let mut ctrl = pac::dma::regs::CtrlTrig(0);
    ctrl.set_en(true);            // EN so chaining can trigger it
    ctrl.set_incr_read(incr_read);
    ctrl.set_incr_write(incr_write);
    ctrl.set_data_size(data_size);
    ctrl.set_treq_sel(pac::dma::vals::TreqSel::from(dreq));
    ctrl.set_chain_to(ch);        // CHAIN_TO=self (no chain yet)
    dma_ch.al1_ctrl().write_value(ctrl.0);
}

/// Queue next DMA transfer for ping-pong. Configures the inactive channel and
/// sets CHAIN_TO on the active channel so the queued transfer starts automatically
/// when the current one completes — zero-gap handoff via hardware chaining.
pub fn dma_fd_queue(fd: i32, read_addr: u32, count: u32) -> i32 {
    let slot = slot_of(fd);
    if slot < 0 || slot as usize >= MAX_DMA_FDS {
        return errno::EINVAL;
    }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) {
        return errno::EINVAL;
    }
    let active = dma.active_ch();
    let inactive = dma.inactive_ch();

    {
        use embassy_rp::pac;
        let inactive_ch = pac::DMA.ch(inactive as usize);
        let active_ch = pac::DMA.ch(active as usize);

        // Configure inactive channel's READ_ADDR and TRANS_COUNT (non-trigger writes)
        inactive_ch.read_addr().write_value(read_addr);
        super::chip::dma_write_trans_count(&inactive_ch, count);

        compiler_fence(Ordering::SeqCst);

        // Set active channel's CHAIN_TO → inactive channel (enable chaining)
        // Read via al1_ctrl (no trigger), modify CHAIN_TO, write back via al1_ctrl
        let mut ctrl = pac::dma::regs::CtrlTrig(active_ch.al1_ctrl().read());
        ctrl.set_chain_to(inactive);
        active_ch.al1_ctrl().write_value(ctrl.0);

        compiler_fence(Ordering::SeqCst);

        // Edge case: if active channel already completed before we set CHAIN_TO,
        // the chain won't fire. Manually start inactive and swap.
        if !active_ch.ctrl_trig().read().busy() {
            // Active already done — manually trigger inactive via AL3 registers
            inactive_ch.al3_trans_count().write_value(count);
            inactive_ch.al3_read_addr_trig().write_value(read_addr);

            // Reset completed channel's CHAIN_TO to self
            ctrl.set_chain_to(active);
            active_ch.al1_ctrl().write_value(ctrl.0);

            // Swap active
            dma.active_is_b.store(!dma.active_is_b.load(Ordering::Acquire), Ordering::Release);
        }
    }

    dma.pending.store(true, Ordering::Release);
    0
}

/// Fast DMA re-trigger via AL3 registers (count + read_addr_trig).
/// Preserves existing write_addr, dreq, flags from the initial start.
/// Operates on the active channel only (no ping-pong).
pub fn dma_fd_restart(fd: i32, read_addr: u32, count: u32) -> i32 {
    let slot = slot_of(fd);
    if slot < 0 || slot as usize >= MAX_DMA_FDS {
        return errno::EINVAL;
    }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) {
        return errno::EINVAL;
    }
    let ch = dma.active_ch();
    unsafe { crate::kernel::syscalls::dma_restart_raw(ch, read_addr, count) }
}

/// Free a DMA FD: aborts both channels, frees them, releases slot.
pub fn dma_fd_free(fd: i32) -> i32 {
    let slot = slot_of(fd);
    if slot < 0 || slot as usize >= MAX_DMA_FDS {
        return errno::EINVAL;
    }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) {
        return errno::EINVAL;
    }
    let ch_a = dma.channel_a.load(Ordering::Acquire);
    let ch_b = dma.channel_b.load(Ordering::Acquire);
    crate::kernel::syscalls::dma_abort(ch_a);
    crate::kernel::syscalls::dma_abort(ch_b);
    crate::kernel::syscalls::dma_free_channel(ch_a);
    crate::kernel::syscalls::dma_free_channel(ch_b);
    dma.channel_a.store(0xFF, Ordering::Release);
    dma.channel_b.store(0xFF, Ordering::Release);
    dma.pending.store(false, Ordering::Release);
    dma.active_is_b.store(false, Ordering::Release);
    dma.owner.store(0xFF, Ordering::Release);
    dma.allocated.store(false, Ordering::Release);
    0
}

/// Poll a DMA FD for readiness. With ping-pong:
/// - Active channel busy → not ready
/// - Active channel done + pending=true → swap active, clear pending, reset CHAIN_TO → POLL_IN
/// - Active channel done + pending=false → idle (DMA stopped) → POLL_IN
fn dma_fd_poll_ready(slot: i32) -> bool {
    if slot < 0 || slot as usize >= MAX_DMA_FDS {
        return false;
    }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) {
        return false;
    }
    let active = dma.active_ch();
    use embassy_rp::pac;
    if pac::DMA.ch(active as usize).ctrl_trig().read().busy() {
        return false;
    }

    // Active channel completed
    if dma.pending.load(Ordering::Acquire) {
        // Chaining happened (or we manually triggered in queue). Swap active.
        // Reset completed channel's CHAIN_TO to self (prevent stale re-chain).
        {
            let dma_ch = pac::DMA.ch(active as usize);
            let mut ctrl = pac::dma::regs::CtrlTrig(dma_ch.al1_ctrl().read());
            ctrl.set_chain_to(active);
            dma_ch.al1_ctrl().write_value(ctrl.0);
        }
        dma.active_is_b.store(!dma.active_is_b.load(Ordering::Acquire), Ordering::Release);
        dma.pending.store(false, Ordering::Release);
    }

    true
}

/// Release all DMA FD slots owned by a specific module. Called on module finish.
pub fn release_dma_fds_owned_by(module_idx: u8) {
    for i in 0..MAX_DMA_FDS {
        let dma = &DMA_FD_SLOTS[i];
        if !dma.allocated.load(Ordering::Acquire) {
            continue;
        }
        if dma.owner.load(Ordering::Acquire) != module_idx {
            continue;
        }
        let ch_a = dma.channel_a.load(Ordering::Acquire);
        let ch_b = dma.channel_b.load(Ordering::Acquire);
        if ch_a != 0xFF {
            crate::kernel::syscalls::dma_abort(ch_a);
            crate::kernel::syscalls::dma_free_channel(ch_a);
        }
        if ch_b != 0xFF {
            crate::kernel::syscalls::dma_abort(ch_b);
            crate::kernel::syscalls::dma_free_channel(ch_b);
        }
        dma.channel_a.store(0xFF, Ordering::Release);
        dma.channel_b.store(0xFF, Ordering::Release);
        dma.pending.store(false, Ordering::Release);
        dma.active_is_b.store(false, Ordering::Release);
        dma.owner.store(0xFF, Ordering::Release);
        dma.allocated.store(false, Ordering::Release);
    }
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
    let (tag, slot) = untag_fd(fd);
    match tag {
        FD_TAG_CHANNEL => {
            // channel_poll is already non-destructive and returns a bitmask
            channel::channel_poll(slot, events)
        }
        FD_TAG_SOCKET => {
            // socket poll is already non-destructive and returns a bitmask
            SocketService::poll(slot, events)
        }
        FD_TAG_EVENT => {
            // Non-destructive peek (load, not swap)
            let mut ready = 0u8;
            if (events & POLL_IN) != 0 && event::event_is_signaled(slot) {
                ready |= POLL_IN;
            }
            ready as i32
        }
        FD_TAG_TIMER => {
            // Timer expired → POLL_IN
            let mut ready = 0u8;
            if (events & POLL_IN) != 0 && timer_is_expired(slot) {
                ready |= POLL_IN;
            }
            ready as i32
        }
        FD_TAG_PIO_STREAM => {
            // can_push → POLL_OUT
            let mut ready = 0u8;
            if (events & POLL_OUT) != 0 && PioStreamService::can_push(slot) > 0 {
                ready |= POLL_OUT;
            }
            ready as i32
        }
        FD_TAG_PIO_CMD => {
            // poll() returns 0=busy, >0=done, <0=error — non-destructive read
            let mut ready = 0u8;
            if (events & POLL_IN) != 0 {
                let result = PioCmdService::poll(slot);
                if result > 0 {
                    ready |= POLL_IN;
                }
            }
            ready as i32
        }
        FD_TAG_PIO_RX_STREAM => {
            // can_pull → POLL_IN (data available for reading)
            let mut ready = 0u8;
            if (events & POLL_IN) != 0 && PioRxStreamService::can_pull(slot) > 0 {
                ready |= POLL_IN;
            }
            ready as i32
        }
        FD_TAG_DMA => {
            // DMA active channel done → POLL_IN (with ping-pong swap if pending)
            let mut ready = 0u8;
            if (events & POLL_IN) != 0 && dma_fd_poll_ready(slot) {
                ready |= POLL_IN;
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
