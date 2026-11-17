//! Lends: a module's memory registered for another module to use past one
//! call.
//!
//! A call's `data` span lives for the call. Memory a provider must keep using
//! after it returns — a block cache a source DMAs into, a buffer an SPI
//! transfer runs over — is a lend. The lender opens it on the handle of the
//! session it lends to (`lend::OPEN`, handle = that session, `data` = the
//! span) and names it in that session's requests by a cookie it chooses. The
//! module serving the session, and only it, resolves the cookie to the span
//! (`RESOLVE`, which counts one borrow) and gives it back when it is done
//! with it (`RETURN`) — before it reports the request complete.
//!
//! The kernel parses no request. It knows three things per lend: whose memory
//! it is, which provider may borrow it under which of its own handles, and
//! how many borrows are out.
//!
//! # Teardown
//!
//! A lender that goes while a borrow is out cannot have its memory reused: the
//! borrower may still write it, from a DMA engine, with no code of either
//! module running. Its memory, slot and lends are kept — **quarantined** —
//! and released once the last borrow comes back. Nothing depends on the
//! borrower behaving: one that never returns keeps the memory it was lent,
//! which is a leak, not a corruption, and is reported once it is overdue.
//!
//! A borrower that goes ends its borrows with it: its platform handles (DMA
//! among them) are released before its lends are, so nothing writes through
//! them afterwards.

use core::cell::UnsafeCell;

use portable_atomic::{AtomicBool, AtomicU32, Ordering};

use crate::abi::contracts::resource::POOL_LENDS;
use crate::kernel::exec::scheduler::{ModuleId, NO_MODULE};
use crate::kernel::module::loader::ModuleMemory;
use crate::kernel::module::user_span::UserSpan;
use crate::kernel::sys::errno;

/// Lend directions, as `lend::OPEN` names them: what the borrower may do.
pub mod dir {
    /// The borrower reads the span.
    pub const IN: u8 = 1;
    /// The borrower writes the span.
    pub const OUT: u8 = 2;
    /// Both.
    pub const INOUT: u8 = 3;
}

/// `lend::OPEN` argument: `[dir u8][0 u8; 3][cookie u32 LE]`.
pub const OPEN_ARG_LEN: usize = 8;
/// `RESOLVE` argument in: `[inner i32 LE][cookie u32 LE]`; out:
/// `[addr u64 LE][len u32 LE][dir u8]`.
pub const RESOLVE_ARG_LEN: usize = 13;
/// `RETURN` argument: `[inner i32 LE][cookie u32 LE]`.
pub const RETURN_ARG_LEN: usize = 8;

/// Lends at once: the plan's `lends` pool.
const MAX_LENDS: usize = crate::kernel::config::static_slots(POOL_LENDS);
/// Torn-down lenders waiting for their borrows at once.
const MAX_QUARANTINED: usize = 8;
/// A quarantine older than this is reported, once.
const OVERDUE_MS: u64 = 5_000;

/// The lend contract's id: the contract field of every lend handle.
const LEND: u16 = crate::abi::registry::lend::ID;
const GEN_MASK: u16 = crate::abi::kernel_abi::handle::GEN_MASK;
#[allow(
    clippy::absurd_extreme_comparisons,
    reason = "a table the boot plan sizes compiles to 0 slots here; `size` holds it to the same bound"
)]
const _: () = assert!(MAX_LENDS <= crate::abi::kernel_abi::handle::INDEX_LIMIT);

#[derive(Clone, Copy)]
struct Lend {
    live: bool,
    generation: u16,
    lender: ModuleId,
    /// The module serving the session the lend is bound to, or
    /// [`NO_MODULE`] for a kernel provider; the only one that may resolve it.
    borrower: ModuleId,
    /// The borrower's own handle for that session.
    inner: i32,
    cookie: u32,
    dir: u8,
    addr: usize,
    len: usize,
    borrows: u16,
    /// The lender closed it, or went, with borrows out: freed by the last
    /// `RETURN`.
    closing: bool,
}

impl Lend {
    const FREE: Lend = Lend {
        live: false,
        generation: 0,
        lender: NO_MODULE,
        borrower: NO_MODULE,
        inner: -1,
        cookie: 0,
        dir: 0,
        addr: 0,
        len: 0,
        borrows: 0,
        closing: false,
    };

    fn free(&mut self) {
        let generation = self.generation;
        *self = Lend::FREE;
        self.generation = generation;
    }
}

struct Quarantined {
    module: ModuleId,
    memory: ModuleMemory,
    since_ms: u64,
    reported: bool,
}

struct Ledger {
    quarantined: [Option<Quarantined>; MAX_QUARANTINED],
}

/// The lend table, its quarantine list, and the lock that serialises both
/// across cores: a borrower returns on its own core while the lender steps on
/// another. Held only for table edits, never across module code.
struct Shared {
    lock: AtomicBool,
    ledger: UnsafeCell<Ledger>,
}

// SAFETY: every access to `ledger` and to `LENDS` is inside `with`, which
// holds `lock`.
unsafe impl Sync for Shared {}

static SHARED: Shared = Shared {
    lock: AtomicBool::new(false),
    ledger: UnsafeCell::new(Ledger {
        quarantined: [const { None }; MAX_QUARANTINED],
    }),
};

static mut LENDS: crate::kernel::mem::table::Table<Lend, MAX_LENDS> =
    crate::boot_table!(MAX_LENDS, Lend::FREE, POOL_LENDS);

/// Quarantined lenders; lets the per-tick pump return at once when there
/// are none.
static QUARANTINE_COUNT: AtomicU32 = AtomicU32::new(0);

fn with<R>(f: impl FnOnce(&mut [Lend], &mut Ledger) -> R) -> R {
    while SHARED
        .lock
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: the lock above gives this thread exclusive access to both.
    let r = unsafe {
        let t = &mut *core::ptr::addr_of_mut!(LENDS);
        t.size_unplanned(|| crate::kernel::sys::resource_ledger::ceiling(POOL_LENDS) as usize);
        f(&mut t[..], &mut *SHARED.ledger.get())
    };
    SHARED.lock.store(false, Ordering::Release);
    r
}

/// Size the table to `n` slots, all live.
///
/// # Safety
/// Graph-preparation context: no reference into the table is live.
pub unsafe fn size(n: usize) -> Result<(), crate::kernel::mem::table::TableError> {
    // A lend handle holds its slot in the handle's index field.
    if n > crate::abi::kernel_abi::handle::INDEX_LIMIT {
        return Err(crate::kernel::mem::table::TableError::Ceiling);
    }
    // SAFETY: the caller's contract.
    let t = unsafe { &*core::ptr::addr_of!(LENDS) };
    // SAFETY: as above.
    unsafe { t.reserve(n)? };
    t.grow(n)
}

/// Lends open now — the ledger's sample for `POOL_LENDS`.
pub fn in_use() -> usize {
    with(|lends, _| lends.iter().filter(|l| l.live).count())
}

fn handle_of(idx: usize, generation: u16) -> i32 {
    crate::abi::kernel_abi::handle::encode(LEND, generation, idx as u32)
}

/// The table index a lend handle names, if it is one at the generation it
/// was minted at.
fn index_of(lends: &[Lend], h: i32) -> Option<usize> {
    let (c, generation, idx) = crate::abi::kernel_abi::handle::decode(h)?;
    if c != LEND {
        return None;
    }
    let idx = idx as usize;
    lends
        .get(idx)
        .filter(|l| l.live && l.generation == generation)
        .map(|_| idx)
}

/// `lend::OPEN`: lend `span` to the provider serving `session`, as the
/// calling module. `arg` is `[dir u8][0; 3][cookie u32]`.
pub fn open(session: i32, arg: &[u8], span: &mut UserSpan<'_>) -> i32 {
    let Some(arg) = arg.get(..OPEN_ARG_LEN) else {
        return errno::EINVAL;
    };
    let d = arg[0];
    let cookie = u32::from_le_bytes([arg[4], arg[5], arg[6], arg[7]]);
    if !matches!(d, dir::IN | dir::OUT | dir::INOUT) || span.is_empty() {
        return errno::EINVAL;
    }
    let Some((borrower, inner)) = crate::kernel::module::provider::session_server(session) else {
        return errno::EBADF;
    };
    let lender = crate::kernel::exec::scheduler::current_module_id();
    let (addr, len) = span.as_raw();
    with(|lends, _| {
        if lends
            .iter()
            .any(|l| l.live && l.borrower == borrower && l.inner == inner && l.cookie == cookie)
        {
            return errno::EEXIST;
        }
        let Some(idx) = lends.iter().position(|l| !l.live) else {
            crate::kernel::sys::resource_ledger::deny(POOL_LENDS);
            return errno::ENOSPC;
        };
        let generation = lends[idx].generation.wrapping_add(1) & GEN_MASK;
        lends[idx] = Lend {
            live: true,
            generation,
            lender,
            borrower,
            inner,
            cookie,
            dir: d,
            addr: addr as usize,
            len,
            borrows: 0,
            closing: false,
        };
        handle_of(idx, generation)
    })
}

/// `lend::CLOSE`, by the lender. A lend with borrows out is freed by its
/// last `RETURN`; the lender's name for it is gone either way.
pub fn close(h: i32) -> i32 {
    let caller = crate::kernel::exec::scheduler::current_module_id();
    with(|lends, _| {
        let Some(idx) = index_of(lends, h) else {
            return errno::EBADF;
        };
        let l = &mut lends[idx];
        if l.lender != caller || l.closing {
            return errno::EBADF;
        }
        if l.borrows == 0 {
            l.free();
        } else {
            l.closing = true;
        }
        0
    })
}

/// `RESOLVE`, by the borrower: the span bound to its session `inner` under
/// `cookie`, one more borrow out. `arg` is `[inner i32][cookie u32]` in and
/// `[addr u64][len u32][dir u8]` out.
pub fn resolve(arg: &mut [u8]) -> i32 {
    let Some(arg) = arg.get_mut(..RESOLVE_ARG_LEN) else {
        return errno::EINVAL;
    };
    let inner = i32::from_le_bytes([arg[0], arg[1], arg[2], arg[3]]);
    let cookie = u32::from_le_bytes([arg[4], arg[5], arg[6], arg[7]]);
    let caller = crate::kernel::exec::scheduler::current_module_id();
    let found = with(|lends, _| {
        let l = lends.iter_mut().find(|l| {
            l.live && !l.closing && l.borrower == caller && l.inner == inner && l.cookie == cookie
        })?;
        l.borrows = l.borrows.checked_add(1)?;
        Some((l.addr, l.len, l.dir))
    });
    let Some((addr, len, d)) = found else {
        return errno::ENOENT;
    };
    arg[0..8].copy_from_slice(&(addr as u64).to_le_bytes());
    arg[8..12].copy_from_slice(&(len as u32).to_le_bytes());
    arg[12] = d;
    0
}

/// A kernel provider's view of a span lent to it: the span `lender` lent on
/// the kernel handle `inner` under `cookie`, as `(addr, len, dir)`. The
/// kernel counts no borrow: it uses the span only while `inner` is live, and
/// a module's platform handles are released (their transfers stopped) before
/// its lends are, so the span cannot be released under it.
pub fn resolve_kernel(inner: i32, cookie: u32, lender: ModuleId) -> Option<(usize, usize, u8)> {
    with(|lends, _| {
        lends
            .iter()
            .find(|l| {
                l.live
                    && !l.closing
                    && l.borrower == NO_MODULE
                    && l.inner == inner
                    && l.cookie == cookie
                    && l.lender == lender
            })
            .map(|l| (l.addr, l.len, l.dir))
    })
}

/// `RETURN`, by the borrower: one borrow of `[inner i32][cookie u32]` back.
pub fn give_back(arg: &[u8]) -> i32 {
    let Some(arg) = arg.get(..RETURN_ARG_LEN) else {
        return errno::EINVAL;
    };
    let inner = i32::from_le_bytes([arg[0], arg[1], arg[2], arg[3]]);
    let cookie = u32::from_le_bytes([arg[4], arg[5], arg[6], arg[7]]);
    let caller = crate::kernel::exec::scheduler::current_module_id();
    with(|lends, _| {
        let Some(l) = lends
            .iter_mut()
            .find(|l| l.live && l.borrower == caller && l.inner == inner && l.cookie == cookie)
        else {
            return errno::ENOENT;
        };
        if l.borrows == 0 {
            return errno::EINVAL;
        }
        l.borrows -= 1;
        if l.borrows == 0 && l.closing {
            l.free();
        }
        0
    })
}

/// Whether `module` lent memory that is borrowed now.
pub fn lent_out(module: usize) -> bool {
    with(|lends, _| {
        lends
            .iter()
            .any(|l| l.live && l.lender as usize == module && l.borrows != 0)
    })
}

/// `module` is going. As a lender: every lend not borrowed is freed, and one
/// that is waits for its last `RETURN` (the caller quarantines the memory,
/// [`quarantine`]). As a borrower: its borrows end and nothing more can be
/// resolved under the sessions it served.
pub fn release_module(module: usize) {
    with(|lends, _| {
        for l in lends.iter_mut().filter(|l| l.live) {
            if l.borrower as usize == module {
                l.borrower = NO_MODULE;
                l.inner = -1;
                l.borrows = 0;
                if l.closing {
                    l.free();
                    continue;
                }
            }
            if l.lender as usize == module {
                if l.borrows == 0 {
                    l.free();
                } else {
                    l.closing = true;
                }
            }
        }
    });
}

/// Keep `memory`, which was `module`'s, until its lends are returned. The
/// slot is unavailable meanwhile ([`slot_quarantined`]).
pub fn quarantine(module: usize, memory: ModuleMemory) {
    let kept = with(
        |_, ledger| match ledger.quarantined.iter_mut().find(|q| q.is_none()) {
            Some(q) => {
                *q = Some(Quarantined {
                    module: module as ModuleId,
                    memory,
                    since_ms: crate::kernel::sys::hal::now_millis(),
                    reported: false,
                });
                None
            }
            None => Some(memory),
        },
    );
    match kept {
        None => {
            QUARANTINE_COUNT.fetch_add(1, Ordering::AcqRel);
        }
        Some(_unreleased) => {
            // More torn-down lenders waiting than the ledger tracks: the
            // memory stays lent and unowned, which is safe and is lost.
            // `ModuleMemory` releases nothing on drop.
            log::error!(
                "[lend] module {module} torn down with memory borrowed and no room to wait; \
                 its memory is not released"
            );
        }
    }
}

/// Whether `slot` still holds a torn-down lender's memory.
pub fn slot_quarantined(slot: usize) -> bool {
    QUARANTINE_COUNT.load(Ordering::Acquire) != 0
        && with(|_, ledger| {
            ledger
                .quarantined
                .iter()
                .flatten()
                .any(|q| q.module as usize == slot)
        })
}

/// Forget everything: the whole graph is being replaced. The arenas are reset
/// wholesale by the caller, so the quarantined ranges are not released one by
/// one (`ModuleMemory` releases nothing on drop).
pub fn reset() {
    with(|lends, ledger| {
        for l in lends.iter_mut() {
            l.free();
        }
        for q in ledger.quarantined.iter_mut() {
            *q = None;
        }
    });
    QUARANTINE_COUNT.store(0, Ordering::Release);
}

/// Once per scheduler tick, on core 0: release every quarantined lender whose
/// borrows are all back.
pub fn pump() {
    if QUARANTINE_COUNT.load(Ordering::Acquire) == 0 || crate::kernel::sys::hal::core_id() != 0 {
        return;
    }
    let now = crate::kernel::sys::hal::now_millis();
    let mut done: [Option<(ModuleId, ModuleMemory)>; MAX_QUARANTINED] =
        [const { None }; MAX_QUARANTINED];
    with(|lends, ledger| {
        for (slot, out) in ledger.quarantined.iter_mut().zip(done.iter_mut()) {
            let Some(q) = slot.as_mut() else {
                continue;
            };
            if lends.iter().any(|l| l.live && l.lender == q.module) {
                if !q.reported && now.saturating_sub(q.since_ms) > OVERDUE_MS {
                    q.reported = true;
                    log::warn!(
                        "[lend] module {} is torn down and its memory is still borrowed after \
                         {OVERDUE_MS} ms; its memory is held",
                        q.module
                    );
                }
                continue;
            }
            if let Some(q) = slot.take() {
                *out = Some((q.module, q.memory));
            }
        }
    });
    for (module, memory) in done.into_iter().flatten() {
        crate::kernel::mem::elastic::reclaim_module(module);
        // SAFETY: no lend rides on this module's memory, the module was torn
        // down before it was quarantined and is not stepped, and its slot has
        // not been handed out since (`slot_quarantined`).
        unsafe { memory.release() };
        QUARANTINE_COUNT.fetch_sub(1, Ordering::AcqRel);
    }
}
