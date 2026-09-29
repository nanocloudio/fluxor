//! The kernel's side of the `storage.block` channel protocol.
//!
//! Every `channel::IOCTL` a module issues passes through the provider-call
//! arm in `syscalls.rs`, and the block commands among them get two guarantees
//! there that no source has to provide for itself.
//!
//! # Argument lengths
//!
//! A channel ioctl handler receives a command and a pointer, never a length,
//! so it cannot tell a full record from a short buffer. The contract fixes
//! the record each block command carries, and [`arg_len`] states those sizes
//! once: a call whose payload is any other length is refused before a handler
//! runs. A handler can therefore read and write its whole record and a null
//! payload never reaches it.
//!
//! # Lent buffers
//!
//! `SUBMIT` lends the caller's buffer to the source until the completion is
//! reaped, and the source may write into it at any moment in between: from a
//! DMA engine, with no code of the caller running. The ledger records each
//! lend from `SUBMIT` until the `REAP` that returns its completion, keyed by
//! the channel and the request's tag.
//!
//! The ledger exists for the one event that ends the caller without ending
//! the lend: tearing down the caller's owner. Its memory goes back to the pool
//! and is handed to the next module, and the source's late write would land in
//! that module's state. A torn-down module that still has lends is therefore
//! **quarantined**: its memory, its slot and the channels carrying its lends
//! are kept, nothing steps it, and once per tick the kernel reaps its
//! completions on its behalf. When the last lend is back, the memory is
//! released, the channels are closed and the slot is free again. Nothing here
//! depends on the source behaving: a source that never completes keeps the
//! memory it was lent, which is a leak and not a corruption.
//!
//! A lend is dropped without being reaped when its channel is torn down, which
//! clears the source's handler. Either the source's own owner is going, and
//! its platform handles (DMA among them) are released first, or the caller's
//! owner is going, which is the quarantine above.

use core::cell::UnsafeCell;

use portable_atomic::{AtomicBool, AtomicU32, Ordering};

use crate::abi::contracts::storage::block::{caps, cpl, ioctl, req, Req};
use crate::kernel::boot::config::MAX_MODULES;
use crate::kernel::module::loader::ModuleMemory;
use crate::kernel::sys::errno;

/// The payload length of a block command: the one record it carries, or for
/// `EXEC` the request followed by the completion the source writes.
pub const fn arg_len(cmd: u32) -> Option<usize> {
    match cmd {
        ioctl::CAPS => Some(caps::LEN),
        ioctl::SUBMIT | ioctl::READ_STREAM => Some(req::LEN),
        ioctl::REAP => Some(cpl::LEN),
        ioctl::EXEC => Some(req::LEN + cpl::LEN),
        _ => None,
    }
}

/// Buffers lent to sources, across every caller.
const MAX_LENDS: usize = 128;
/// Torn-down modules waiting for their lends at once.
const MAX_QUARANTINED: usize = 8;
/// Channels whose close is waiting for the same.
const MAX_ADOPTED: usize = 16;
/// Completions reaped per channel per tick on a quarantined module's behalf.
const REAPS_PER_TICK: usize = 8;
/// A quarantine older than this is reported, once.
const OVERDUE_MS: u64 = 5_000;

const NO_CHAN: i32 = -1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Free,
    /// `SUBMIT` is being dispatched; nothing is lent yet.
    Reserved,
    Lent,
}

#[derive(Clone, Copy)]
struct Lend {
    phase: Phase,
    chan: i32,
    tag: u64,
    /// The module whose memory the buffer is in.
    holder: u8,
    /// The holder is being torn down: the kernel reaps this lend itself.
    dying: bool,
}

impl Lend {
    const FREE: Lend = Lend {
        phase: Phase::Free,
        chan: NO_CHAN,
        tag: 0,
        holder: 0,
        dying: false,
    };
}

struct Quarantined {
    module: u8,
    memory: ModuleMemory,
    since_ms: u64,
    reported: bool,
}

struct Ledger {
    lends: [Lend; MAX_LENDS],
    quarantined: [Option<Quarantined>; MAX_QUARANTINED],
    /// Channels the ledger will close once no lend rides on them.
    adopted: [i32; MAX_ADOPTED],
}

impl Ledger {
    const fn new() -> Self {
        Self {
            lends: [Lend::FREE; MAX_LENDS],
            quarantined: [const { None }; MAX_QUARANTINED],
            adopted: [NO_CHAN; MAX_ADOPTED],
        }
    }

    fn live(&self) -> impl Iterator<Item = &Lend> {
        self.lends.iter().filter(|l| l.phase != Phase::Free)
    }

    fn retire(&mut self, chan: i32, tag: u64) {
        if let Some(l) = self
            .lends
            .iter_mut()
            .find(|l| l.phase == Phase::Lent && l.chan == chan && l.tag == tag)
        {
            *l = Lend::FREE;
        }
    }

    fn lends_on(&self, chan: i32) -> bool {
        self.live().any(|l| l.chan == chan)
    }

    fn holds(&self, module: usize) -> bool {
        self.live()
            .any(|l| l.phase == Phase::Lent && l.holder as usize == module)
    }
}

/// The ledger and the lock that serialises it across cores.
///
/// The lock is held only for table edits, never across a handler: a source
/// that forwards a request to another source submits again from inside its own
/// handler.
struct Table {
    lock: AtomicBool,
    inner: UnsafeCell<Ledger>,
}

// SAFETY: every access to `inner` is inside `with`, which holds `lock`.
unsafe impl Sync for Table {}

static LEDGER: Table = Table {
    lock: AtomicBool::new(false),
    inner: UnsafeCell::new(Ledger::new()),
};

/// Quarantined modules; lets the per-tick pump return at once when there are none.
static QUARANTINE_COUNT: AtomicU32 = AtomicU32::new(0);
/// Only one core pumps at a time.
static PUMPING: AtomicBool = AtomicBool::new(false);

fn with<R>(f: impl FnOnce(&mut Ledger) -> R) -> R {
    while LEDGER
        .lock
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: the lock above gives this thread exclusive access.
    let r = f(unsafe { &mut *LEDGER.inner.get() });
    LEDGER.lock.store(false, Ordering::Release);
    r
}

/// A `SUBMIT` accounted before dispatch and settled after it.
pub struct Pending(Option<usize>);

/// Account a block command `holder` is about to issue on `chan`. `arg` and
/// `len` are the payload, already checked against [`arg_len`]; it is read here
/// and not held across the handler, which writes through the same pointer.
///
/// # Safety
/// `arg` is readable for `len` bytes, or `len` is zero.
///
/// A `SUBMIT` that lends a buffer takes a ledger entry first, so a full ledger
/// is back-pressure (`EAGAIN`) before the source has accepted anything, and a
/// tag already in flight on the channel is refused: tags identify the
/// completion that retires the lend.
pub unsafe fn begin(
    chan: i32,
    holder: usize,
    cmd: u32,
    arg: *const u8,
    len: usize,
) -> Result<Pending, i32> {
    if cmd != ioctl::SUBMIT || holder >= MAX_MODULES || len == 0 {
        return Ok(Pending(None));
    }
    // SAFETY: the caller's contract; `len` is non-zero here.
    let arg = unsafe { core::slice::from_raw_parts(arg, len) };
    let Some(r) = Req::decode(arg) else {
        return Err(errno::EINVAL);
    };
    if r.buf_len == 0 {
        return Ok(Pending(None));
    }
    with(|l| {
        if l.live().any(|x| x.chan == chan && x.tag == r.tag) {
            return Err(errno::EINVAL);
        }
        match l.lends.iter().position(|x| x.phase == Phase::Free) {
            Some(i) => {
                l.lends[i] = Lend {
                    phase: Phase::Reserved,
                    chan,
                    tag: r.tag,
                    holder: holder as u8,
                    dying: false,
                };
                Ok(Pending(Some(i)))
            }
            None => Err(errno::EAGAIN),
        }
    })
}

/// Settle a command after its handler returned `rc`. `arg` and `len` are the
/// payload the handler saw, which a `REAP` has filled with the completion.
///
/// # Safety
/// `arg` is readable for `len` bytes, or `len` is zero.
pub unsafe fn finish(pending: Pending, chan: i32, cmd: u32, rc: i32, arg: *const u8, len: usize) {
    if let Some(i) = pending.0 {
        with(|l| {
            // The entry is still the reservation unless its channel was torn
            // down while the source was handling the request.
            if l.lends[i].phase != Phase::Reserved {
                return;
            }
            if rc == 0 {
                l.lends[i].phase = Phase::Lent;
            } else {
                l.lends[i] = Lend::FREE;
            }
        });
        return;
    }
    if cmd == ioctl::REAP && rc == 1 && len >= cpl::LEN {
        // SAFETY: the caller's contract; `len` is non-zero here.
        let arg = unsafe { core::slice::from_raw_parts(arg, len) };
        if let Some(t) = arg.get(cpl::TAG..cpl::TAG + 8) {
            let tag = u64::from_le_bytes([t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]]);
            with(|l| l.retire(chan, tag));
        }
    }
}

/// Whether `module` has a buffer lent to a source.
pub fn holds_lends(module: usize) -> bool {
    with(|l| l.holds(module))
}

/// `module` is being torn down: from here the kernel reaps its lends.
pub fn mark_dying(module: usize) {
    with(|l| {
        for x in l.lends.iter_mut() {
            if x.phase == Phase::Lent && x.holder as usize == module {
                x.dying = true;
            }
        }
    });
}

/// Whether a lend of a torn-down module rides on `chan`. If so the ledger
/// closes the channel itself once the lends are back, and the caller must not.
pub fn adopt_channel(chan: i32) -> bool {
    with(|l| {
        if !l.live().any(|x| x.chan == chan && x.dying) {
            return false;
        }
        if l.adopted.contains(&chan) {
            return true;
        }
        match l.adopted.iter_mut().find(|c| **c == NO_CHAN) {
            Some(c) => {
                *c = chan;
                true
            }
            // No room to remember it: leave the channel open for good rather
            // than close it under a lend.
            None => true,
        }
    })
}

/// Keep `memory`, which was `module`'s, until its lends are back. The slot is
/// unavailable meanwhile ([`slot_quarantined`]).
pub fn quarantine(module: usize, memory: ModuleMemory) {
    let kept = with(|l| match l.quarantined.iter_mut().find(|q| q.is_none()) {
        Some(q) => {
            *q = Some(Quarantined {
                module: module as u8,
                memory,
                since_ms: crate::kernel::sys::hal::now_millis(),
                reported: false,
            });
            None
        }
        None => Some(memory),
    });
    match kept {
        None => {
            QUARANTINE_COUNT.fetch_add(1, Ordering::AcqRel);
        }
        Some(_unreleased) => {
            // More torn-down modules waiting than the ledger can track: the
            // memory stays lent and unowned, which is safe and is lost.
            // `ModuleMemory` releases nothing on drop.
            log::error!(
                "[block] module {module} torn down with buffers lent and no room to wait; \
                 its memory is not released"
            );
        }
    }
}

/// Whether `slot` still holds a torn-down module's memory.
pub fn slot_quarantined(slot: usize) -> bool {
    QUARANTINE_COUNT.load(Ordering::Acquire) != 0
        && with(|l| {
            l.quarantined
                .iter()
                .flatten()
                .any(|q| q.module as usize == slot)
        })
}

/// A channel is being closed, which clears its handler: nothing can reap a
/// lend on it again, and nothing but a torn-down source's DMA, already
/// released, could still write to one.
pub fn channel_closed(chan: i32) {
    with(|l| {
        for x in l.lends.iter_mut() {
            if x.chan == chan {
                *x = Lend::FREE;
            }
        }
    });
}

/// Forget everything: the whole graph is being replaced. The arenas are reset
/// wholesale by the caller, so the quarantined ranges are not released one by
/// one (`ModuleMemory` releases nothing on drop).
pub fn reset() {
    with(|l| *l = Ledger::new());
    QUARANTINE_COUNT.store(0, Ordering::Release);
}

/// Once per scheduler tick: reap the completions of quarantined modules'
/// lends, and release a module once its last lend is back.
pub fn pump() {
    if QUARANTINE_COUNT.load(Ordering::Acquire) == 0 {
        return;
    }
    if crate::kernel::sys::hal::core_id() != 0 {
        return;
    }
    if PUMPING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    pump_locked();
    PUMPING.store(false, Ordering::Release);
}

fn pump_locked() {
    // Channels carrying a dying lend, each once.
    let mut chans = [NO_CHAN; MAX_LENDS];
    let mut n = 0;
    with(|l| {
        for x in l.live().filter(|x| x.dying) {
            if !chans[..n].contains(&x.chan) {
                chans[n] = x.chan;
                n += 1;
            }
        }
    });
    for &chan in &chans[..n] {
        for _ in 0..REAPS_PER_TICK {
            let mut c = [0u8; cpl::LEN];
            let rc = crate::kernel::ipc::channel::channel_ioctl(chan, ioctl::REAP, c.as_mut_ptr());
            if rc == 1 {
                // SAFETY: `c` is a local array of `cpl::LEN` bytes.
                unsafe { finish(Pending(None), chan, ioctl::REAP, rc, c.as_ptr(), c.len()) };
            } else {
                if rc == crate::kernel::ipc::channel::CHAN_ENOSYS
                    || rc == crate::kernel::ipc::channel::CHAN_EINVAL
                {
                    // Nothing answers on this channel any more.
                    channel_closed(chan);
                }
                break;
            }
        }
    }

    // Release every module whose lends are all back, and close the channels
    // that carried them.
    let now = crate::kernel::sys::hal::now_millis();
    let mut done: [Option<(u8, ModuleMemory)>; MAX_QUARANTINED] = [const { None }; MAX_QUARANTINED];
    let mut close = [NO_CHAN; MAX_ADOPTED];
    with(|l| {
        let Ledger {
            lends, quarantined, ..
        } = &mut *l;
        for (slot, out) in quarantined.iter_mut().zip(done.iter_mut()) {
            let Some(q) = slot.as_mut() else {
                continue;
            };
            if lends
                .iter()
                .any(|x| x.phase == Phase::Lent && x.holder == q.module)
            {
                if !q.reported && now.saturating_sub(q.since_ms) > OVERDUE_MS {
                    q.reported = true;
                    log::warn!(
                        "[block] module {} is torn down and its buffers are still lent \
                         after {} ms; its memory is held",
                        q.module,
                        OVERDUE_MS
                    );
                }
                continue;
            }
            if let Some(q) = slot.take() {
                *out = Some((q.module, q.memory));
            }
        }
        for (slot, c) in close.iter_mut().enumerate() {
            let chan = l.adopted[slot];
            if chan != NO_CHAN && !l.lends_on(chan) {
                *c = chan;
                l.adopted[slot] = NO_CHAN;
            }
        }
    });
    for &chan in close.iter().filter(|c| **c != NO_CHAN) {
        crate::kernel::module::syscalls::channel_close(chan);
    }
    for (module, memory) in done.into_iter().flatten() {
        crate::kernel::mem::elastic::reclaim_module(module);
        // SAFETY: no lend rides on this module's memory, the module was torn
        // down before it was quarantined and is not stepped, and its slot has
        // not been handed out since (`slot_quarantined`).
        unsafe { memory.release() };
        QUARANTINE_COUNT.fetch_sub(1, Ordering::AcqRel);
    }
}
