//! The carve allocator: kernel tables taken from the top of one zone of
//! memory, one way and downwards.
//!
//! A bare-metal kernel has no heap, so a table sized at boot from the graph
//! (`kernel::mem::table`) needs memory from somewhere that is not a table's
//! own static. The platform hands this module one zone, and the arithmetic of
//! splitting it lives in `kernel::mem::pool_plan`:
//!
//! - **bcm2712**: the DRAM the device tree describes above the boot image
//!   (`platform/bcm2712/memmap.rs`). Carves come off its top and the module
//!   state arena (`kernel::module::loader`) owns the rest from the bottom up.
//!   The boundary between them is the carve floor: a carve that would reach
//!   memory the state arena has handed out is refused, and the arena's
//!   capacity is whatever the carves have left it.
//! - **RP**: one static pool in `.bss`, [`POOL`], of the silicon's
//!   `[kernel] kernel_pool_kb` — what its static-RAM budget holds beside the
//!   kernel's fixed statics. Each graph plans it afresh ([`begin_plan`]): the
//!   tables its plan sizes are carved off the top, then [`place_arenas`] takes
//!   the channel buffer arena off what they left and gives the state arena
//!   the rest. Two graphs split the same pool differently, and a graph whose
//!   plan the pool cannot hold is refused at boot, naming the pool that did
//!   not fit. A rebuild moves the carve's sized tag ([`sized_tag`]), which
//!   forgets every table carved for the previous graph (`Raw::revalidate` in
//!   `kernel::mem::table`).
//! - **Permanent carves** ([`carve`]) back the boot-sized tables. They are
//!   never returned — a table may be read from any core, so its block cannot
//!   be proven free — and every one is zeroed as it is carved, never the
//!   zone wholesale. On RP they last until the next plan.
//! - **Transient blocks** ([`take`] / [`give`]) back the graph builder's
//!   scratch and the boot config's parse lists on bcm2712, which live while a
//!   graph is prepared. A block given back is kept on a short recycle list
//!   and handed out again to the next ask it fits, so a rebuild reuses the
//!   last one's memory instead of carving more. A recycled block is not
//!   re-zeroed: every user writes each slot it exposes.
//!
//! All of it runs while a graph is prepared or a subgraph is added, never on
//! a module's step. The bookkeeping is serialised by one lock, held only over
//! bounded work.

use portable_atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

/// Blocks the recycle list holds. Graph preparation has at most a handful of
/// transient blocks live at once (the module list, the edge list, three
/// wiring scratches, the fan scan); a block given back when the list is full
/// replaces the smallest, which is leaked and counted.
pub const RECYCLE_SLOTS: usize = 16;
/// Granularity of a fresh transient block, so a list that grows by one slot
/// at a time does not carve once per slot.
#[cfg(feature = "chip-bcm2712")]
const TRANSIENT_GRAIN: usize = 4096;

static LOCK: AtomicBool = AtomicBool::new(false);
static ZONE_LO: AtomicUsize = AtomicUsize::new(0);
static ZONE_HI: AtomicUsize = AtomicUsize::new(0);
/// Lowest carved address: `[FLOOR, ZONE_HI)` is the carves'.
static FLOOR: AtomicUsize = AtomicUsize::new(0);
/// Bytes carved for permanent tables.
static PERMANENT: AtomicUsize = AtomicUsize::new(0);
/// Bytes carved for transient blocks.
static TRANSIENT: AtomicUsize = AtomicUsize::new(0);
/// Bytes of transient blocks dropped off a full recycle list.
static LEAKED: AtomicUsize = AtomicUsize::new(0);
/// Carves refused: the zone could not hold them.
static REFUSED: AtomicUsize = AtomicUsize::new(0);
/// The plan the carves belong to, as the state word a table sized under it
/// holds (`kernel::mem::table`): 2 at boot, moved by each [`begin_plan`]
/// (RP). A table carved under an older tag is forgotten before it is used
/// again.
static SIZED_TAG: AtomicU32 = AtomicU32::new(2);

/// RP: the kernel's one static pool, split per graph between its tables and
/// its arenas. Zero-initialised `.bss`, so the state arena starts known-zero.
/// Aligned for the MPU's smallest region granule and the channel buffers'
/// cache-line alignment alike.
#[cfg(feature = "rp")]
#[repr(C, align(256))]
struct Pool([u8; crate::kernel::config::KERNEL_POOL_SIZE]);
#[cfg(feature = "rp")]
static mut POOL: Pool = Pool([0; crate::kernel::config::KERNEL_POOL_SIZE]);

/// The recycle list, touched only under `LOCK`.
#[cfg(feature = "chip-bcm2712")]
struct Recycle {
    ptr: [usize; RECYCLE_SLOTS],
    size: [usize; RECYCLE_SLOTS],
}
#[cfg(feature = "chip-bcm2712")]
static mut RECYCLE: Recycle = Recycle {
    ptr: [0; RECYCLE_SLOTS],
    size: [0; RECYCLE_SLOTS],
};

struct Guard;
impl Guard {
    fn acquire() -> Self {
        while LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Guard
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        LOCK.store(false, Ordering::Release);
    }
}

/// Give the allocator its zone, `[lo, hi)`. Called once at boot, before any
/// table is sized (on RP the zone is [`POOL`], installed on first use).
pub fn install(lo: usize, hi: usize) {
    let _g = Guard::acquire();
    ZONE_LO.store(lo, Ordering::Relaxed);
    ZONE_HI.store(hi, Ordering::Relaxed);
    FLOOR.store(hi, Ordering::Release);
}

/// `(lo, hi)` of the zone; `(0, 0)` before [`install`].
pub fn zone() -> (usize, usize) {
    (
        ZONE_LO.load(Ordering::Relaxed),
        ZONE_HI.load(Ordering::Relaxed),
    )
}

/// The current plan's sized tag (see [`SIZED_TAG`]).
#[inline(always)]
pub fn sized_tag() -> u32 {
    SIZED_TAG.load(Ordering::Acquire)
}

/// RP: the zone is the static pool. Installed on the first carve, under the
/// lock, so a table sized before the platform's boot code runs still has it.
#[cfg(feature = "rp")]
fn ensure_zone() {
    if ZONE_HI.load(Ordering::Relaxed) == 0 {
        let lo = core::ptr::addr_of_mut!(POOL).cast::<u8>() as usize;
        let hi = lo + crate::kernel::config::KERNEL_POOL_SIZE;
        ZONE_LO.store(lo, Ordering::Relaxed);
        ZONE_HI.store(hi, Ordering::Relaxed);
        FLOOR.store(hi, Ordering::Release);
    }
}

/// The carve floor: everything at or above it is carved.
pub fn floor() -> usize {
    FLOOR.load(Ordering::Acquire)
}

/// `(permanent, transient, leaked, refused)` bytes and refusals, for
/// telemetry.
pub fn stats() -> (usize, usize, usize, usize) {
    (
        PERMANENT.load(Ordering::Relaxed),
        TRANSIENT.load(Ordering::Relaxed),
        LEAKED.load(Ordering::Relaxed),
        REFUSED.load(Ordering::Relaxed),
    )
}

/// Move the floor down by `bytes` at `align`, under the lock. `None` when the
/// zone cannot hold it or the state arena owns the memory below.
fn lower_floor(bytes: usize, align: usize) -> Option<usize> {
    #[cfg(feature = "rp")]
    ensure_zone();
    let floor = FLOOR.load(Ordering::Relaxed);
    let lo = ZONE_LO.load(Ordering::Relaxed);
    let carved = super::pool_plan::carve_down(floor, lo, bytes, align);
    let Some(new) = carved.filter(|&n| crate::kernel::module::loader::cede_arena_above(n)) else {
        REFUSED.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    FLOOR.store(new, Ordering::Release);
    Some(new)
}

/// Carve `bytes` at `align` for a table that lives as long as the kernel.
/// The memory is zeroed. `None` when the zone cannot hold it.
pub fn carve(bytes: usize, align: usize) -> Option<*mut u8> {
    if bytes == 0 {
        return Some(align.max(1) as *mut u8);
    }
    let at = {
        let _g = Guard::acquire();
        lower_floor(bytes, align)?
    };
    PERMANENT.fetch_add(bytes, Ordering::Relaxed);
    // SAFETY: `[at, at + bytes)` was just carved for this caller alone, and it
    // lies in the zone the platform mapped as DRAM.
    unsafe { core::ptr::write_bytes(at as *mut u8, 0, bytes) };
    Some(at as *mut u8)
}

/// A transient block of at least `bytes` at `align`: `(ptr, size)`. A recycled
/// block is handed out as it was given back, unzeroed; a fresh one is zeroed.
#[cfg(feature = "chip-bcm2712")]
pub fn take(bytes: usize, align: usize) -> Option<(*mut u8, usize)> {
    let align = align.max(16);
    {
        let _g = Guard::acquire();
        // SAFETY: the recycle list is touched only under the lock.
        let r = unsafe { &mut *core::ptr::addr_of_mut!(RECYCLE) };
        let mut best: Option<usize> = None;
        for i in 0..RECYCLE_SLOTS {
            let (p, s) = (r.ptr[i], r.size[i]);
            if p != 0 && s >= bytes && p & (align - 1) == 0 && best.is_none_or(|b| s < r.size[b]) {
                best = Some(i);
            }
        }
        if let Some(i) = best {
            let out = (r.ptr[i] as *mut u8, r.size[i]);
            r.ptr[i] = 0;
            r.size[i] = 0;
            return Some(out);
        }
    }
    let size = bytes.max(1).div_ceil(TRANSIENT_GRAIN) * TRANSIENT_GRAIN;
    let at = {
        let _g = Guard::acquire();
        lower_floor(size, align)?
    };
    TRANSIENT.fetch_add(size, Ordering::Relaxed);
    // SAFETY: as in `carve`.
    unsafe { core::ptr::write_bytes(at as *mut u8, 0, size) };
    Some((at as *mut u8, size))
}

/// Return a transient block from [`take`].
///
/// # Safety
/// `(ptr, size)` is exactly what `take` returned, and nothing references it
/// any more.
#[cfg(feature = "chip-bcm2712")]
pub unsafe fn give(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    let _g = Guard::acquire();
    // SAFETY: the recycle list is touched only under the lock.
    let r = unsafe { &mut *core::ptr::addr_of_mut!(RECYCLE) };
    let mut smallest = 0usize;
    for i in 0..RECYCLE_SLOTS {
        if r.ptr[i] == 0 {
            r.ptr[i] = ptr as usize;
            r.size[i] = size;
            return;
        }
        if r.size[i] < r.size[smallest] {
            smallest = i;
        }
    }
    if r.size[smallest] < size {
        LEAKED.fetch_add(r.size[smallest], Ordering::Relaxed);
        r.ptr[smallest] = ptr as usize;
        r.size[smallest] = size;
    } else {
        LEAKED.fetch_add(size, Ordering::Relaxed);
    }
}

// ── RP: one static pool, planned per graph ────────────────────────────────

/// A plan of the RP pool in progress ([`begin_plan`]). Interrupts stay masked
/// while it lives: between the sized tag moving and the last table being
/// reserved again, a table an interrupt handler reaches may be one the plan
/// has not reached yet, and sizing it from the handler would contend for the
/// carve lock the interrupted plan holds. Dropping it restores them.
#[cfg(feature = "rp")]
pub struct PlanWindow {
    irq: u32,
}

#[cfg(feature = "rp")]
impl Drop for PlanWindow {
    fn drop(&mut self) {
        crate::kernel::sys::hal::restore_interrupts(self.irq);
    }
}

/// Bytes the previous plan's carves reached down to, as an offset from the
/// zone's bottom: memory the next plan may give the state arena dirty.
#[cfg(feature = "rp")]
static LAST_FLOOR: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Start planning the pool for a graph: every table, the buffer arena and the
/// state arena of the previous plan are forgotten and the whole pool is free
/// again. Graph preparation only — no module runs, and nothing the previous
/// graph held is live (`prepare_graph` resets all of it after the plan).
#[cfg(feature = "rp")]
pub fn begin_plan() -> PlanWindow {
    let irq = crate::kernel::sys::hal::disable_interrupts();
    {
        let _g = Guard::acquire();
        ensure_zone();
        let lo = ZONE_LO.load(Ordering::Relaxed);
        let floor = FLOOR.load(Ordering::Relaxed);
        LAST_FLOOR.store(floor - lo, Ordering::Relaxed);
        FLOOR.store(ZONE_HI.load(Ordering::Relaxed), Ordering::Release);
        PERMANENT.store(0, Ordering::Relaxed);
        SIZED_TAG.fetch_add(1, Ordering::AcqRel);
    }
    crate::kernel::module::loader::uninstall_arena();
    crate::kernel::ipc::buffer_pool::uninstall_arena();
    PlanWindow { irq }
}

/// The split [`place_arenas`] made: bytes carved for tables, the buffer
/// arena and the state arena.
#[cfg(feature = "rp")]
#[derive(Clone, Copy, Debug)]
pub struct Split {
    pub tables: usize,
    pub buffer: usize,
    pub state: usize,
}

/// Finish the plan: carve the channel buffer arena (`buffer` bytes, the
/// plan's `buffer_arena` ceiling) off what the tables left and give the
/// module state arena the rest. `state_asked` is the envelope's state-arena
/// entry, when there is one. `Err` names the arena the pool could not hold.
#[cfg(feature = "rp")]
pub fn place_arenas(
    buffer: usize,
    state_asked: Option<usize>,
) -> Result<Split, super::pool_plan::Refusal> {
    let align = crate::kernel::ipc::ring_size::RING_ALIGN as usize;
    let (lo, split) = {
        let _g = Guard::acquire();
        let lo = ZONE_LO.load(Ordering::Relaxed);
        let floor = FLOOR.load(Ordering::Relaxed);
        let split = super::pool_plan::place_arenas(lo, floor, buffer, align, state_asked)?;
        FLOOR.store(split.floor, Ordering::Release);
        (lo, split)
    };
    let hi = ZONE_HI.load(Ordering::Relaxed);
    // The previous plan's tables sat at and above its floor; whatever of that
    // the new state arena takes is dirty.
    let dirty_from = LAST_FLOOR.load(Ordering::Relaxed).min(split.state);
    crate::kernel::module::loader::install_planned_arena(split.state_at, split.state, dirty_from);
    // The buffer arena zeroes every buffer it hands out.
    crate::kernel::ipc::buffer_pool::install_arena(split.buffer_at as *mut u8, split.buffer);
    Ok(Split {
        tables: hi - lo - split.state - split.buffer,
        buffer: split.buffer,
        state: split.state,
    })
}

/// Finish the graph's plan of the pool: place the arenas at the plan's
/// ceilings ([`place_arenas`]) and report the split. A pool that cannot hold
/// them is refused at boot naming the arena's pool; the caller fails the
/// graph.
#[cfg(feature = "rp")]
pub fn finish_plan() -> Result<Split, crate::kernel::sys::resource_ledger::Refused> {
    use super::pool_plan::Over;
    use crate::abi::contracts::resource as res;
    use crate::kernel::sys::resource_ledger as ledger;
    let buffer = ledger::ceiling_bytes(res::POOL_BUFFER_ARENA) as usize;
    let state_asked = ledger::enforced(res::POOL_STATE_ARENA).map(|n| n as usize);
    match place_arenas(buffer, state_asked) {
        Ok(split) => {
            log::info!(
                "[pool] {} B: tables {} B, buffer arena {} B, state arena {} B",
                crate::kernel::config::KERNEL_POOL_SIZE,
                split.tables,
                split.buffer,
                split.state
            );
            Ok(split)
        }
        Err(r) => {
            let pool = match r.over {
                Over::BufferArena => res::POOL_BUFFER_ARENA,
                Over::StateArena => res::POOL_STATE_ARENA,
            };
            log::error!(
                "[pool] the kernel's static pool ({} B) cannot hold the plan: {} B asked, {} B \
                 left beside the graph's tables",
                crate::kernel::config::KERNEL_POOL_SIZE,
                r.asked,
                r.room
            );
            ledger::refuse(
                pool,
                "past what the kernel's static pool holds beside the tables",
            );
            Err(ledger::Refused)
        }
    }
}
