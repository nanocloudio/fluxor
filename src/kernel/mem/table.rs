//! Kernel tables sized at boot.
//!
//! A kernel table — the scheduler's per-module arrays, the channel slots, the
//! event and timer slots, the owner table — is a [`Table`]. Its storage is a
//! platform choice, made here and nowhere else:
//!
//! - **Linux** sizes every table from the graph it boots
//!   (`resource_ledger::plan`). [`Table::reserve`] allocates the table's
//!   ceiling — what the graph derives plus its live-add reserve — as one
//!   block, which the host backs with pages only as slots are written, and
//!   [`Table::grow`] commits it a [`SEGMENT`] of slots at a time: at boot for
//!   the slots the graph needs, at a live add for the slots the added
//!   subgraph needs. A committed slot never moves, and indexing is one bounds
//!   check and an offset. A table reaches past its ceiling by refusing, never
//!   by reallocating under its readers.
//! - **bcm2712** sizes its tables from the same plan, with no heap: the
//!   table's block is a carve (`kernel::mem::carve`) off the top of the DRAM
//!   zone the device tree describes, zeroed when it is carved. `reserve`
//!   carves the ceiling and initialises every slot of it, so the table is
//!   whole from then on and `grow` is a bounds check: an array whose size is
//!   chosen at boot rather than at compile time.
//! - **RP** (rp2040, rp2350) sizes its tables from the same plan, with no
//!   heap and no DRAM to carve: the carve allocator's zone is one static pool
//!   in `.bss` (`kernel::config::KERNEL_POOL_SIZE`), which the graph's plan
//!   splits between the tables, the channel buffer arena and the module state
//!   arena (`kernel::mem::carve::begin_plan` / `place_arenas`). A rebuild
//!   plans the pool afresh: it moves the carve's **sized tag**, every table
//!   carved under an older tag reads as unsized, and the plan reserves it
//!   again in the new split. Within a plan a table behaves as bcm2712's.
//! - **wasm** keeps a static array of the profile's compiled size `N`: the
//!   table is whole from the start, `reserve` admits any ceiling up to `N` and
//!   refuses one above it, and `grow` is a bounds check.
//!
//! Every backend dereferences the table to a slice of its committed slots, so
//! a walk iterates the live count (`table.len()`), never a compiled constant,
//! and `table[i]` past it is a bounds error exactly as it is for an array.
//!
//! A table no plan has sized yet (a kernel driven without a booted graph, as a
//! harness does) sizes itself on its first read: to its pool's plan ceiling
//! when it names one, else to nothing. A plan that reaches the table first
//! sizes it to the plan's ceiling directly; one that comes after a first-use
//! sizing keeps the slots that sizing committed.
//!
//! A reservation larger than the table's block moves the table to a new block.
//! What becomes of the old one is the platform's:
//!
//! - **bcm2712** hands it back to the carve zone's free extents at once
//!   (`carve::retire`), and the next carve takes from them before it lowers
//!   the floor, so a rebuild to a larger graph reuses what the previous
//!   graph's tables held. That is sound because a reservation runs only
//!   where no core can still read the table (see [`Table::reserve`]).
//! - **Linux** frees it to the host's allocator at once. The hosted runtime
//!   reads its tables from the scheduler thread alone, which runs the
//!   reservation between passes (see [`Table::reserve`]).
//! - **RP** leaves it in the pool until the next plan, which frees the whole
//!   pool.
//!
//! A rebuild that asks no more than the table holds reuses it in place.
//!
//! [`ParseTable`] is the parse-side counterpart for the boot config's module
//! and edge lists: it grows as the parser (or a test that builds a config by
//! hand) writes entries, and reads past its end as the table's empty value.
//! On bcm2712 its storage is a transient carve block, returned for reuse when
//! the list is dropped, so a rebuild reuses the last parse's memory. RP keeps
//! the format's array: the config blob's graph section is laid out for its
//! compiled slot count there.
//!
//! None of this runs on a step: a table is reserved and committed while a
//! graph is prepared or a subgraph is added.

use core::ops::{Deref, DerefMut, Index, IndexMut};

/// Slots committed at once. A segment is the unit a live add grows a table by,
/// so a burst of single-slot adds touches fresh memory once per 64 slots.
pub const SEGMENT: usize = 64;

/// `n` rounded up to a whole number of segments.
#[inline]
pub const fn segments(n: usize) -> usize {
    n.div_ceil(SEGMENT) * SEGMENT
}

/// Why a table refused its size or its growth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError {
    /// The ask is past the table's ceiling (static size, or the ceiling the
    /// boot plan reserved).
    Ceiling,
    /// The host refused the memory.
    NoMemory,
}

/// Build a [`Table`] whose every slot starts as `$init` (a constant
/// expression). `$n` is the compiled size the static backend holds.
///
/// With a third argument, a resource-pool id, a planned table that no plan has
/// sized sizes itself on first use to that pool's ceiling — the plan's
/// defaults — all committed: a kernel used without a booted graph (a harness
/// driving one subsystem) still has its tables. A booted kernel plans every
/// table before anything reads it.
#[macro_export]
macro_rules! boot_table {
    ($n:expr, $init:expr) => {{
        #[cfg(any(feature = "host-linux", feature = "chip-bcm2712", feature = "rp"))]
        {
            $crate::kernel::mem::table::Table::new(|_| $init)
        }
        #[cfg(not(any(feature = "host-linux", feature = "chip-bcm2712", feature = "rp")))]
        {
            $crate::kernel::mem::table::Table::from_array([const { $init }; $n])
        }
    }};
    ($n:expr, $init:expr, $pool:expr) => {{
        #[cfg(any(feature = "host-linux", feature = "chip-bcm2712", feature = "rp"))]
        {
            $crate::kernel::mem::table::Table::new_planned(
                |_| $init,
                || $crate::kernel::sys::resource_ledger::ceiling($pool) as usize,
            )
        }
        #[cfg(not(any(feature = "host-linux", feature = "chip-bcm2712", feature = "rp")))]
        {
            let _ = $pool;
            $crate::kernel::mem::table::Table::from_array([const { $init }; $n])
        }
    }};
    // `$per` slots per slot of `$pool`: a table keyed by a pool's index and a
    // second, bounded one (an owner slot and an execution domain).
    ($n:expr, $init:expr, $pool:expr, $per:expr) => {{
        #[cfg(any(feature = "host-linux", feature = "chip-bcm2712", feature = "rp"))]
        {
            $crate::kernel::mem::table::Table::new_planned(
                |_| $init,
                || $crate::kernel::sys::resource_ledger::ceiling($pool) as usize * $per,
            )
        }
        #[cfg(not(any(feature = "host-linux", feature = "chip-bcm2712", feature = "rp")))]
        {
            let _ = ($pool, $per);
            $crate::kernel::mem::table::Table::from_array([const { $init }; $n])
        }
    }};
}

// ── Linux, bcm2712 and RP: sized from the plan ────────────────────────────
//
// The bookkeeping is one non-generic core ([`Raw`]): only the slot writes
// ([`fill_impl`]) and, on Linux, the drop are per element type. A kernel has
// some fifty tables of different types; a generic body per type is what an
// RP2040's flash cannot spare. A read is one comparison of the state word
// against the current sized tag, then the slice.

#[cfg(any(feature = "host-linux", feature = "chip-bcm2712", feature = "rp"))]
mod imp {
    use super::{segments, TableError};
    use core::marker::PhantomData;
    use portable_atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

    /// `Raw::state`: no reservation yet; a first-use sizing in progress; any
    /// value from 2 up is sized, under the sized tag it holds ([`sized`]).
    const UNSIZED: u32 = 0;
    const SIZING: u32 = 1;

    /// The state word of a table sized now. On RP it moves with the carve
    /// plan (`kernel::mem::carve::sized_tag`): a table sized under an older
    /// plan reads as stale and is forgotten before it is used.
    #[inline(always)]
    fn sized() -> u32 {
        #[cfg(feature = "rp")]
        {
            crate::kernel::mem::carve::sized_tag()
        }
        #[cfg(not(feature = "rp"))]
        {
            2
        }
    }

    fn no_default() -> usize {
        0
    }

    /// Bytes of table blocks the host's allocator holds for the kernel's
    /// tables now, every table together (Linux).
    #[cfg(feature = "host-linux")]
    pub(super) static HOST_BLOCK_BYTES: AtomicUsize = AtomicUsize::new(0);

    /// A block of `bytes` at `align` from the host's allocator on Linux.
    #[cfg(feature = "host-linux")]
    fn alloc_block(bytes: usize, align: usize) -> Result<*mut u8, TableError> {
        let layout =
            std::alloc::Layout::from_size_align(bytes, align).map_err(|_| TableError::NoMemory)?;
        // SAFETY: `layout` is non-zero-sized (the caller asks for `ceiling > 0`
        // slots of a type that is not a ZST).
        let fresh = unsafe { std::alloc::alloc(layout) };
        if fresh.is_null() {
            Err(TableError::NoMemory)
        } else {
            HOST_BLOCK_BYTES.fetch_add(bytes, Ordering::Relaxed);
            Ok(fresh)
        }
    }

    /// Return a block [`alloc_block`] gave, of `bytes` at `align`, to the
    /// host's allocator. Its values have moved or been dropped.
    ///
    /// # Safety
    /// `ptr` is that block, and nothing can still read or write it.
    #[cfg(feature = "host-linux")]
    unsafe fn free_block(ptr: *mut u8, bytes: usize, align: usize) {
        if let Ok(layout) = std::alloc::Layout::from_size_align(bytes, align) {
            // SAFETY: the caller's contract; `ptr` was allocated with this
            // layout.
            unsafe { std::alloc::dealloc(ptr, layout) };
            HOST_BLOCK_BYTES.fetch_sub(bytes, Ordering::Relaxed);
        }
    }

    /// A block of `bytes` at `align`: a zeroed carve — from the DRAM zone on
    /// bcm2712, from the static pool on RP.
    #[cfg(any(feature = "chip-bcm2712", feature = "rp"))]
    fn alloc_block(bytes: usize, align: usize) -> Result<*mut u8, TableError> {
        crate::kernel::mem::carve::carve(bytes, align).ok_or(TableError::NoMemory)
    }

    /// The type-erased table: its block, bounds and state.
    struct Raw {
        /// The reserved block (`reserved` slots), or `dangling` before the
        /// first `reserve`.
        ptr: AtomicPtr<u8>,
        /// Slots the block has room for.
        reserved: AtomicUsize,
        /// Slots `grow` may commit up to.
        ceiling: AtomicUsize,
        /// Committed slots: `[0, len)` are initialised.
        len: AtomicUsize,
        /// [`UNSIZED`], [`SIZING`] or a sized tag.
        state: AtomicU32,
        /// Held while slots are being committed, so two growers never
        /// initialise the same slot under a reader one of them already
        /// exposed it to.
        growing: AtomicBool,
        /// Slots a table no plan has sized takes on first use.
        default_len: fn() -> usize,
        /// Write slots `[from, to)` of the block with the table's initial
        /// values (`fill_impl` for the element type).
        fill: unsafe fn(&Raw, usize, usize),
        /// The element's size and alignment.
        size: usize,
        align: usize,
        /// RP: the aligned non-null pointer a forgotten table's empty slice
        /// reads from.
        #[cfg(feature = "rp")]
        dangling: *mut u8,
    }

    /// A table of `T` sized at boot. `N` is unused here: the plan sizes the
    /// table, and `N` names only the compiled size the static backend would
    /// hold.
    #[repr(C)]
    pub struct Table<T, const N: usize> {
        /// First, so `fill_impl` finds the table from its core.
        raw: Raw,
        init: fn(usize) -> T,
        _slots: PhantomData<T>,
    }

    // SAFETY: the table is a block of `T`s with atomically published bounds;
    // sharing it shares the `T`s, so it is as `Sync`/`Send` as `T` is.
    unsafe impl<T: Sync, const N: usize> Sync for Table<T, N> {}
    // SAFETY: as above — moving the table moves ownership of its `T`s.
    unsafe impl<T: Send, const N: usize> Send for Table<T, N> {}

    /// Write slots `[from, to)` of `raw`'s block with the initial values.
    ///
    /// # Safety
    /// `raw` is the `raw` field of a `Table<T, N>`; the slots are inside its
    /// block, uninitialised, and its `growing` flag (or sole ownership) keeps
    /// every other writer out.
    unsafe fn fill_impl<T, const N: usize>(raw: &Raw, from: usize, to: usize) {
        // SAFETY: `raw` is the first field of a `#[repr(C)]` `Table<T, N>`.
        let table = unsafe { &*(raw as *const Raw as *const Table<T, N>) };
        let ptr = raw.ptr.load(Ordering::Acquire) as *mut T;
        for i in from..to {
            // SAFETY: the caller's contract.
            unsafe { ptr.add(i).write((table.init)(i)) };
        }
    }

    impl Raw {
        /// A table read under an older sized tag (RP: an older plan) is
        /// forgotten: its block belongs to the new plan now, and the table
        /// starts unsized, as at boot. Its values are dropped without being
        /// read: the plan that moved the tag is a rebuild, which resets every
        /// table it re-reserves.
        #[inline]
        fn revalidate(&self) {
            #[cfg(feature = "rp")]
            {
                let s = self.state.load(Ordering::Acquire);
                if s > SIZING && s != sized() {
                    self.len.store(0, Ordering::Release);
                    self.ceiling.store(0, Ordering::Relaxed);
                    self.reserved.store(0, Ordering::Relaxed);
                    self.ptr.store(self.dangling, Ordering::Release);
                    self.state.store(UNSIZED, Ordering::Release);
                }
            }
        }

        /// The slow half of a read: revalidate, then size on first use.
        #[cold]
        #[inline(never)]
        fn ready(&self) {
            self.revalidate();
            if self.state.load(Ordering::Acquire) != sized() {
                self.size_on_first_use();
            }
        }

        /// Size an unplanned table on its first use (see `new_planned`).
        #[cold]
        #[inline(never)]
        fn size_on_first_use(&self) {
            match self
                .state
                .compare_exchange(UNSIZED, SIZING, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    let n = (self.default_len)();
                    // SAFETY: an unsized table has no slots, so nothing holds a
                    // reference into it.
                    if unsafe { self.reserve_inner(n) }.is_ok() {
                        let _ = self.grow(n);
                    }
                    self.state.store(sized(), Ordering::Release);
                }
                Err(_) => {
                    while self.state.load(Ordering::Acquire) != sized() {
                        core::hint::spin_loop();
                    }
                }
            }
        }

        #[inline(never)]
        unsafe fn reserve(&self, ceiling: usize) -> Result<(), TableError> {
            self.revalidate();
            // A plan that sizes the table first takes it straight to the
            // plan's ceiling, so its first-use default is never allocated
            // beside it; one that comes after a first-use sizing keeps the
            // slots that sizing committed.
            loop {
                match self.state.compare_exchange(
                    UNSIZED,
                    SIZING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        // SAFETY: the caller's contract; an unsized table has
                        // no slots, so nothing holds a reference into it.
                        let r = unsafe { self.reserve_inner(ceiling) };
                        self.state.store(sized(), Ordering::Release);
                        return r;
                    }
                    Err(SIZING) => core::hint::spin_loop(),
                    Err(_) => break,
                }
            }
            // SAFETY: the caller's contract.
            unsafe { self.reserve_inner(ceiling) }
        }

        unsafe fn reserve_inner(&self, ceiling: usize) -> Result<(), TableError> {
            let len = self.len.load(Ordering::Acquire);
            let ceiling = ceiling.max(len);
            let reserved = self.reserved.load(Ordering::Relaxed);
            if self.size == 0 {
                self.reserved.store(usize::MAX, Ordering::Relaxed);
            } else if ceiling > reserved {
                let bytes = ceiling.checked_mul(self.size).ok_or(TableError::NoMemory)?;
                let fresh = alloc_block(bytes, self.align)?;
                let old = self.ptr.load(Ordering::Acquire);
                if len > 0 {
                    // SAFETY: `[0, len)` of `old` is initialised and `fresh`
                    // has room for `ceiling >= len` slots; the blocks are
                    // distinct allocations. The values move (bitwise) and the
                    // old block is abandoned without dropping them.
                    unsafe { core::ptr::copy_nonoverlapping(old, fresh, len * self.size) };
                }
                self.ptr.store(fresh, Ordering::Release);
                self.reserved.store(ceiling, Ordering::Relaxed);
                // The old block is freed: to the carve zone on bcm2712, to the
                // host's allocator on Linux. Its values moved to `fresh`
                // bitwise and are not dropped there.
                #[cfg(feature = "chip-bcm2712")]
                if reserved > 0 {
                    // SAFETY: `old` is the block `alloc_block` carved for
                    // `reserved` slots, and `reserve`'s contract holds: no
                    // core is inside a read of this table, so once `fresh`
                    // is published nothing can reach `old` (the argument is
                    // set out on `Table::reserve`).
                    unsafe { crate::kernel::mem::carve::retire(old, reserved * self.size) };
                }
                #[cfg(feature = "host-linux")]
                if reserved > 0 {
                    // SAFETY: `old` is the block `alloc_block` allocated for
                    // `reserved` slots, and `reserve`'s contract holds: no
                    // thread is inside a read of this table (the argument is
                    // set out on `Table::reserve`).
                    unsafe { free_block(old, reserved * self.size, self.align) };
                }
            }
            self.ceiling.store(ceiling, Ordering::Relaxed);
            // bcm2712 and RP: the whole ceiling is committed now, so `grow` is
            // a bounds check and no slot is initialised on a live add.
            #[cfg(any(feature = "chip-bcm2712", feature = "rp"))]
            self.grow(ceiling)?;
            Ok(())
        }

        #[inline(never)]
        fn grow(&self, n: usize) -> Result<(), TableError> {
            self.revalidate();
            if self.state.load(Ordering::Acquire) == UNSIZED {
                self.size_on_first_use();
            }
            if n <= self.len.load(Ordering::Acquire) {
                return Ok(());
            }
            while self
                .growing
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            let r = self.grow_locked(n);
            self.growing.store(false, Ordering::Release);
            r
        }

        fn grow_locked(&self, n: usize) -> Result<(), TableError> {
            let len = self.len.load(Ordering::Acquire);
            if n <= len {
                return Ok(());
            }
            let ceiling = self.ceiling.load(Ordering::Relaxed);
            if n > ceiling {
                return Err(TableError::Ceiling);
            }
            let target = segments(n).min(ceiling);
            // SAFETY: `[len, target)` is inside the block (`target <= ceiling
            // <= reserved`) and uninitialised; `growing` keeps any other
            // grower out.
            unsafe { (self.fill)(self, len, target) };
            self.len.store(target, Ordering::Release);
            Ok(())
        }

        #[cold]
        #[inline(never)]
        fn size_unplanned(&self, n: usize) {
            if self
                .state
                .compare_exchange(UNSIZED, SIZING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // SAFETY: an unsized table has no slots, so nothing can hold a
                // reference into it.
                if unsafe { self.reserve_inner(n) }.is_ok() {
                    let _ = self.grow(n);
                }
                self.state.store(sized(), Ordering::Release);
            }
        }
    }

    impl<T, const N: usize> Table<T, N> {
        /// An empty table whose slot `i` starts as `init(i)`.
        pub const fn new(init: fn(usize) -> T) -> Self {
            Self::new_planned(init, no_default)
        }

        /// An empty table that, if no plan sizes it before its first use,
        /// sizes itself to `default_len()` slots, all committed.
        pub const fn new_planned(init: fn(usize) -> T, default_len: fn() -> usize) -> Self {
            let dangling = core::ptr::NonNull::<T>::dangling().as_ptr() as *mut u8;
            Self {
                raw: Raw {
                    ptr: AtomicPtr::new(dangling),
                    reserved: AtomicUsize::new(0),
                    ceiling: AtomicUsize::new(0),
                    len: AtomicUsize::new(0),
                    state: AtomicU32::new(UNSIZED),
                    growing: AtomicBool::new(false),
                    default_len,
                    fill: fill_impl::<T, N>,
                    size: core::mem::size_of::<T>(),
                    align: core::mem::align_of::<T>(),
                    #[cfg(feature = "rp")]
                    dangling,
                },
                init,
                _slots: PhantomData,
            }
        }

        /// The most slots `grow` may commit. A planned table no plan has sized
        /// takes its plan default first, as a read of its slots does, so the
        /// ceiling is never reported as 0 for a table that would hold more.
        pub fn ceiling(&self) -> usize {
            if self.raw.state.load(Ordering::Acquire) != sized() {
                self.raw.ready();
            }
            self.raw.ceiling.load(Ordering::Relaxed)
        }

        /// Set the table's ceiling to `ceiling` slots, allocating a block for
        /// them when the table's block is smaller. Committed slots keep their
        /// values. A ceiling below the committed count is raised to it.
        ///
        /// # Safety
        /// When `ceiling` exceeds what is reserved the table moves to a new
        /// block, so no reference into the table may be live, and no core
        /// may be inside a read of it, from the call until it returns:
        /// callers reserve while a graph is prepared (or the platform boots),
        /// never while one runs.
        ///
        /// On bcm2712 the old block is handed back to the carve zone at once,
        /// so the contract is what keeps a reader off freed memory. Every
        /// reservation there satisfies it:
        ///
        /// - The kernel's tables are reserved by `size_kernel_tables` (and
        ///   the cross-domain bridge tables by `multicore::size_cross` after
        ///   it) on the boot core, in `prepare_graph`. At boot that runs
        ///   before the secondary cores are woken into their run loops. For a
        ///   rebuild it runs inside the reconfigure quiesce
        ///   (`poll_rebuild_bridge`): every non-primary domain has parked at
        ///   its tick boundary — outside any step, holding no slice of any
        ///   table, since a slice lives only within the call that reads it —
        ///   before `prepare_graph` starts, and resumes only after it
        ///   returns, when its next read loads the new block (the quiesce
        ///   flag's release store orders the move before it).
        /// - The interrupt handlers that read a table (a device IRQ bound to
        ///   an event, signalling it) are delivered to the boot core
        ///   (`gic::irq_bind` routes event bindings to core 0), the core the
        ///   move runs on. A handler that preempts the move runs to
        ///   completion before the move continues, so none holds the old
        ///   block when it is handed back. A Tier 1b or Tier 2 handler, which
        ///   may run on a parked core, steps no module while a graph is
        ///   prepared: `prepare_graph` closes ISR-tier dispatch and waits out
        ///   every handler in flight (`isr_tier::close_dispatch`) before it
        ///   sizes a table.
        /// - A table a lock guards (the net-attach lane tables) is reserved
        ///   under that lock, which every reader of it holds.
        ///
        /// On Linux the old block is freed to the host's allocator at once,
        /// and the contract holds because the hosted runtime reads its tables
        /// from one thread:
        ///
        /// - The scheduler — every domain, every module step, every syscall
        ///   and provider call a module makes — runs on the main thread
        ///   (`platform/linux.rs`), and a rebuild is taken there between
        ///   passes (`take_rebuild_request` in the main loop), when no pass
        ///   holds a slice. Each pass borrows the tables afresh.
        /// - Every other thread of the runtime exchanges with the scheduler
        ///   through state of its own and never reads a kernel table: the
        ///   process executor's pipe pumps and the CLI's stdin and stdout
        ///   pumps move bytes through an `ExtBridge`; the `host_mount`
        ///   workers run host filesystem calls and publish a result slot; the
        ///   resolver, GPU and display threads take jobs and frames over
        ///   channels or a mutex; the `net_route` prober and announcer read
        ///   the platform's own route state under its mutex; the audio
        ///   callback drains a sample queue. Their log records reach the
        ///   owner-attribution tee, which reads the module owner table only
        ///   on the scheduler thread (`SCHED_TID`) and returns before it on
        ///   any other.
        /// - The stop-signal handler (`stop.rs`) touches atomics only.
        ///
        /// RP keeps the old block (see the module documentation).
        pub unsafe fn reserve(&self, ceiling: usize) -> Result<(), TableError> {
            // SAFETY: the caller's contract.
            unsafe { self.raw.reserve(ceiling) }
        }

        /// Commit slots until at least `n` are live (a whole number of
        /// segments, capped at the ceiling). `Err(Ceiling)` when `n` is past
        /// the ceiling; nothing is committed then.
        ///
        /// Callable through `&self` on a shared table: new slots are written
        /// before the count that exposes them is published.
        pub fn grow(&self, n: usize) -> Result<(), TableError> {
            self.raw.grow(n)
        }

        /// Size a table that no plan has sized yet — a kernel used without a
        /// booted graph (a harness driving one subsystem) — to `n` slots, all
        /// committed. A table a plan has sized is left alone.
        #[inline]
        pub fn size_unplanned(&self, n: impl FnOnce() -> usize) {
            if self.raw.state.load(Ordering::Acquire) != sized() {
                self.raw.revalidate();
                if self.raw.state.load(Ordering::Acquire) == UNSIZED {
                    self.raw.size_unplanned(n());
                }
            }
        }

        /// Return every committed slot to its initial value.
        pub fn reinit(&mut self) {
            let init = self.init;
            for (i, slot) in self.iter_mut().enumerate() {
                *slot = init(i);
            }
        }

        #[inline]
        pub(super) fn slice(&self) -> &[T] {
            if self.raw.state.load(Ordering::Acquire) != sized() {
                self.raw.ready();
            }
            let len = self.raw.len.load(Ordering::Acquire);
            // SAFETY: `[0, len)` of the block is initialised, the pointer is
            // aligned and non-null (the dangling one when the table is empty),
            // and the block is not moved while a reference is live
            // (`reserve`'s contract).
            unsafe {
                core::slice::from_raw_parts(self.raw.ptr.load(Ordering::Acquire) as *const T, len)
            }
        }

        #[inline]
        pub(super) fn slice_mut(&mut self) -> &mut [T] {
            if self.raw.state.load(Ordering::Acquire) != sized() {
                self.raw.ready();
            }
            let len = *self.raw.len.get_mut();
            // SAFETY: as `slice`, with `&mut self` making the borrow unique.
            unsafe { core::slice::from_raw_parts_mut(*self.raw.ptr.get_mut() as *mut T, len) }
        }
    }

    #[cfg(feature = "host-linux")]
    impl<T, const N: usize> Drop for Table<T, N> {
        fn drop(&mut self) {
            let reserved = *self.raw.reserved.get_mut();
            if reserved == 0 || self.raw.size == 0 {
                return;
            }
            let ptr = *self.raw.ptr.get_mut() as *mut T;
            let len = *self.raw.len.get_mut();
            // SAFETY: `[0, len)` is initialised and owned by this table.
            unsafe { core::ptr::drop_in_place(core::ptr::slice_from_raw_parts_mut(ptr, len)) };
            // SAFETY: the table's own block, allocated for `reserved` slots;
            // the table is going away.
            unsafe { free_block(ptr as *mut u8, reserved * self.raw.size, self.raw.align) };
        }
    }
}

// ── wasm: the profile's static array ──────────────────────────────────────

#[cfg(not(any(feature = "host-linux", feature = "chip-bcm2712", feature = "rp")))]
mod imp {
    use super::TableError;

    /// A table of `N` slots, whole from the start.
    pub struct Table<T, const N: usize> {
        items: [T; N],
    }

    impl<T, const N: usize> Table<T, N> {
        /// A table holding `items`.
        pub const fn from_array(items: [T; N]) -> Self {
            Self { items }
        }

        /// The static size.
        pub const fn ceiling(&self) -> usize {
            N
        }

        /// Admit a ceiling of `ceiling` slots: the table already holds `N`.
        ///
        /// # Safety
        /// None on this backend; `unsafe` for parity with the Linux one.
        pub unsafe fn reserve(&self, ceiling: usize) -> Result<(), TableError> {
            if ceiling > N {
                Err(TableError::Ceiling)
            } else {
                Ok(())
            }
        }

        /// A static table is sized by its type.
        pub fn size_unplanned(&self, _n: impl FnOnce() -> usize) {}

        /// Every slot is live already; refuse only past `N`.
        pub fn grow(&self, n: usize) -> Result<(), TableError> {
            if n > N {
                Err(TableError::Ceiling)
            } else {
                Ok(())
            }
        }

        #[inline]
        pub(super) fn slice(&self) -> &[T] {
            &self.items
        }

        #[inline]
        pub(super) fn slice_mut(&mut self) -> &mut [T] {
            &mut self.items
        }
    }
}

pub use imp::Table;

/// Bytes the host's allocator holds for the kernel's table blocks now, every
/// table together (Linux): what a test reads to see a moved block freed.
#[cfg(feature = "host-linux")]
pub fn host_block_bytes() -> usize {
    imp::HOST_BLOCK_BYTES.load(portable_atomic::Ordering::Relaxed)
}

impl<T, const N: usize> Deref for Table<T, N> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        self.slice()
    }
}

impl<T, const N: usize> DerefMut for Table<T, N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        self.slice_mut()
    }
}

// ── Parse tables ──────────────────────────────────────────────────────────

/// A list the boot-config parser fills: the module entries and the graph
/// edges. Writing slot `i` makes the list at least `i + 1` long (up to the
/// format's ceiling `N`); reading past the end reads the empty value. On the
/// static platforms it is an array of `N`.
#[cfg(feature = "host-linux")]
pub struct ParseTable<T: Copy, const N: usize> {
    items: std::vec::Vec<T>,
    empty: T,
}

#[cfg(feature = "host-linux")]
impl<T: Copy, const N: usize> ParseTable<T, N> {
    /// An empty list whose unwritten slots read as `empty`.
    pub const fn new(empty: T) -> Self {
        Self {
            items: std::vec::Vec::new(),
            empty,
        }
    }

    /// Room for `n` entries, so the parser's writes do not reallocate.
    pub fn reserve_entries(&mut self, n: usize) {
        let n = n.min(N);
        if n > self.items.len() {
            self.items.reserve(n - self.items.len());
        }
    }

    /// Drop every entry.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// The format ceiling.
    pub const fn ceiling(&self) -> usize {
        N
    }
}

#[cfg(feature = "host-linux")]
impl<T: Copy, const N: usize> Index<usize> for ParseTable<T, N> {
    type Output = T;
    #[inline]
    fn index(&self, i: usize) -> &T {
        self.items.get(i).unwrap_or(&self.empty)
    }
}

#[cfg(feature = "host-linux")]
impl<T: Copy, const N: usize> IndexMut<usize> for ParseTable<T, N> {
    fn index_mut(&mut self, i: usize) -> &mut T {
        assert!(i < N, "parse table index {i} past its format ceiling {N}");
        if i >= self.items.len() {
            self.items.resize(i + 1, self.empty);
        }
        &mut self.items[i]
    }
}

/// Range indexing as an array's: over the entries written.
macro_rules! parse_table_ranges {
    ($($r:ty),*) => {$(
        #[cfg(feature = "host-linux")]
        impl<T: Copy, const N: usize> Index<$r> for ParseTable<T, N> {
            type Output = [T];
            #[inline]
            fn index(&self, r: $r) -> &[T] {
                &self.items[r]
            }
        }
        #[cfg(feature = "host-linux")]
        impl<T: Copy, const N: usize> IndexMut<$r> for ParseTable<T, N> {
            #[inline]
            fn index_mut(&mut self, r: $r) -> &mut [T] {
                &mut self.items[r]
            }
        }
    )*};
}
parse_table_ranges!(
    core::ops::Range<usize>,
    core::ops::RangeTo<usize>,
    core::ops::RangeFrom<usize>,
    core::ops::RangeFull,
    core::ops::RangeInclusive<usize>,
    core::ops::RangeToInclusive<usize>
);

#[cfg(feature = "host-linux")]
impl<T: Copy, const N: usize> Deref for ParseTable<T, N> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        &self.items
    }
}

#[cfg(feature = "host-linux")]
impl<T: Copy, const N: usize> DerefMut for ParseTable<T, N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.items
    }
}

#[cfg(feature = "host-linux")]
impl<T: Copy, const N: usize> Clone for ParseTable<T, N> {
    fn clone(&self) -> Self {
        Self {
            items: self.items.clone(),
            empty: self.empty,
        }
    }
}

// ── bcm2712: parse lists and scratch in transient carve blocks ────────────

/// A transient block of `n` slots of `T` from the carve allocator, or a null
/// block when `n` is 0 or the zone is exhausted.
#[cfg(feature = "chip-bcm2712")]
fn take_slots<T>(n: usize) -> (*mut T, usize) {
    let size = core::mem::size_of::<T>();
    if n == 0 || size == 0 {
        return (
            core::ptr::NonNull::dangling().as_ptr(),
            if size == 0 { usize::MAX } else { 0 },
        );
    }
    match n
        .checked_mul(size)
        .and_then(|bytes| crate::kernel::mem::carve::take(bytes, core::mem::align_of::<T>()))
    {
        Some((p, bytes)) => (p as *mut T, bytes / size),
        None => {
            log::error!("[carve] transient block of {n} slots refused: the DRAM zone is exhausted");
            (core::ptr::NonNull::dangling().as_ptr(), 0)
        }
    }
}

/// Return a block from [`take_slots`].
///
/// # Safety
/// `(ptr, cap)` is what `take_slots` returned and nothing references it.
#[cfg(feature = "chip-bcm2712")]
unsafe fn give_slots<T>(ptr: *mut T, cap: usize) {
    let size = core::mem::size_of::<T>();
    if size == 0 || cap == 0 {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { crate::kernel::mem::carve::give(ptr as *mut u8, cap * size) };
}

/// The bcm2712 parse list: a growable list in a transient carve block,
/// handed back for reuse when the list is dropped (the parser resets its
/// config by assigning an empty one, which drops the old).
#[cfg(feature = "chip-bcm2712")]
pub struct ParseTable<T: Copy, const N: usize> {
    ptr: *mut T,
    len: usize,
    cap: usize,
    empty: T,
    /// Where a write lands when the block could not grow: dropped, counted.
    sink: T,
}

// SAFETY: the list owns its block exclusively; moving it moves that ownership.
#[cfg(feature = "chip-bcm2712")]
unsafe impl<T: Copy + Send, const N: usize> Send for ParseTable<T, N> {}

#[cfg(feature = "chip-bcm2712")]
impl<T: Copy, const N: usize> ParseTable<T, N> {
    /// An empty list whose unwritten slots read as `empty`.
    pub const fn new(empty: T) -> Self {
        Self {
            ptr: core::ptr::null_mut(),
            len: 0,
            cap: 0,
            empty,
            sink: empty,
        }
    }

    /// Move to a block of at least `n` slots, keeping the entries.
    fn regrow(&mut self, n: usize) -> bool {
        let (fresh, cap) = take_slots::<T>(n);
        if cap < n {
            if cap > 0 {
                // SAFETY: the block `take_slots` just returned, unused.
                unsafe { give_slots(fresh, cap) };
            }
            return false;
        }
        if self.len > 0 {
            // SAFETY: `[0, len)` of the old block is initialised; the new one
            // holds `cap >= n > len` slots; distinct blocks.
            unsafe { core::ptr::copy_nonoverlapping(self.ptr, fresh, self.len) };
        }
        let (old, old_cap) = (self.ptr, self.cap);
        self.ptr = fresh;
        self.cap = cap;
        if !old.is_null() {
            // SAFETY: the old block, which nothing references any more.
            unsafe { give_slots(old, old_cap) };
        }
        true
    }

    /// Room for `n` entries, so the parser's writes do not regrow.
    pub fn reserve_entries(&mut self, n: usize) {
        let n = n.min(N);
        if n > self.cap {
            self.regrow(n);
        }
    }

    /// Drop every entry.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// The format ceiling.
    pub const fn ceiling(&self) -> usize {
        N
    }
}

#[cfg(feature = "chip-bcm2712")]
impl<T: Copy, const N: usize> Drop for ParseTable<T, N> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: the list's own block; it is going away.
            unsafe { give_slots(self.ptr, self.cap) };
        }
    }
}

#[cfg(feature = "chip-bcm2712")]
impl<T: Copy, const N: usize> Index<usize> for ParseTable<T, N> {
    type Output = T;
    #[inline]
    fn index(&self, i: usize) -> &T {
        self.get(i).unwrap_or(&self.empty)
    }
}

#[cfg(feature = "chip-bcm2712")]
impl<T: Copy, const N: usize> IndexMut<usize> for ParseTable<T, N> {
    fn index_mut(&mut self, i: usize) -> &mut T {
        if i >= N {
            log::error!("[config] parse list index {i} past its format ceiling {N}; dropped");
            return &mut self.sink;
        }
        if i >= self.len {
            if i >= self.cap && !self.regrow((i + 1).max(self.cap * 2).max(16).min(N)) {
                log::error!(
                    "[config] parse list could not grow to {} entries; dropped",
                    i + 1
                );
                return &mut self.sink;
            }
            for k in self.len..=i {
                // SAFETY: `k < cap`, inside the block.
                unsafe { self.ptr.add(k).write(self.empty) };
            }
            self.len = i + 1;
        }
        // SAFETY: `i < len`, initialised.
        unsafe { &mut *self.ptr.add(i) }
    }
}

#[cfg(feature = "chip-bcm2712")]
macro_rules! parse_table_ranges_bcm {
    ($($r:ty),*) => {$(
        impl<T: Copy, const N: usize> Index<$r> for ParseTable<T, N> {
            type Output = [T];
            #[inline]
            fn index(&self, r: $r) -> &[T] {
                &(**self)[r]
            }
        }
        impl<T: Copy, const N: usize> IndexMut<$r> for ParseTable<T, N> {
            #[inline]
            fn index_mut(&mut self, r: $r) -> &mut [T] {
                &mut (**self)[r]
            }
        }
    )*};
}
#[cfg(feature = "chip-bcm2712")]
parse_table_ranges_bcm!(
    core::ops::Range<usize>,
    core::ops::RangeTo<usize>,
    core::ops::RangeFrom<usize>,
    core::ops::RangeFull,
    core::ops::RangeInclusive<usize>,
    core::ops::RangeToInclusive<usize>
);

#[cfg(feature = "chip-bcm2712")]
impl<T: Copy, const N: usize> Deref for ParseTable<T, N> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: `[0, len)` of the block is initialised and owned by the list.
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
}

#[cfg(feature = "chip-bcm2712")]
impl<T: Copy, const N: usize> DerefMut for ParseTable<T, N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        if self.len == 0 {
            return &mut [];
        }
        // SAFETY: as `deref`, with `&mut self` making the borrow unique.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

#[cfg(feature = "chip-bcm2712")]
impl<T: Copy, const N: usize> Clone for ParseTable<T, N> {
    fn clone(&self) -> Self {
        let mut out = Self::new(self.empty);
        if self.len > 0 && out.regrow(self.len) {
            // SAFETY: `[0, len)` of `self` is initialised; `out` holds at least
            // `len` slots; distinct blocks.
            unsafe { core::ptr::copy_nonoverlapping(self.ptr, out.ptr, self.len) };
            out.len = self.len;
        }
        out
    }
}

/// Build-time scratch on bcm2712 (see [`scratch!`]): `n` slots in a transient
/// carve block, handed back when it is dropped.
#[cfg(feature = "chip-bcm2712")]
pub struct Scratch<T: Clone> {
    ptr: *mut T,
    len: usize,
    cap: usize,
}

#[cfg(feature = "chip-bcm2712")]
impl<T: Clone> Scratch<T> {
    /// `n` slots of `init`. Empty when the zone cannot hold it (logged).
    pub fn new(init: T, n: usize) -> Self {
        let (ptr, cap) = take_slots::<T>(n);
        let len = if cap >= n { n } else { 0 };
        for k in 0..len {
            // SAFETY: `k < n <= cap`, inside the block.
            unsafe { ptr.add(k).write(init.clone()) };
        }
        Self { ptr, len, cap }
    }
}

#[cfg(feature = "chip-bcm2712")]
impl<T: Clone> Drop for Scratch<T> {
    fn drop(&mut self) {
        // SAFETY: `[0, len)` is initialised and owned by the scratch.
        unsafe {
            core::ptr::drop_in_place(core::ptr::slice_from_raw_parts_mut(self.ptr, self.len));
            give_slots(self.ptr, self.cap);
        }
    }
}

#[cfg(feature = "chip-bcm2712")]
impl<T: Clone> Deref for Scratch<T> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        // SAFETY: `[0, len)` is initialised; the pointer is non-null (a
        // dangling one for an empty scratch).
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
}

#[cfg(feature = "chip-bcm2712")]
impl<T: Clone> DerefMut for Scratch<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        // SAFETY: as `deref`, unique through `&mut self`.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

/// The static platforms' parse table: the array of `N`.
#[cfg(not(any(feature = "host-linux", feature = "chip-bcm2712")))]
#[derive(Clone, Copy)]
pub struct ParseTable<T: Copy, const N: usize> {
    items: [T; N],
}

#[cfg(not(any(feature = "host-linux", feature = "chip-bcm2712")))]
impl<T: Copy, const N: usize> ParseTable<T, N> {
    /// `N` slots of `empty`.
    pub const fn new(empty: T) -> Self {
        Self { items: [empty; N] }
    }

    /// The list already holds `N`.
    pub fn reserve_entries(&mut self, _n: usize) {}

    /// The format ceiling.
    pub const fn ceiling(&self) -> usize {
        N
    }
}

#[cfg(not(any(feature = "host-linux", feature = "chip-bcm2712")))]
impl<T: Copy, const N: usize> Index<usize> for ParseTable<T, N> {
    type Output = T;
    #[inline]
    fn index(&self, i: usize) -> &T {
        &self.items[i]
    }
}

#[cfg(not(any(feature = "host-linux", feature = "chip-bcm2712")))]
impl<T: Copy, const N: usize> IndexMut<usize> for ParseTable<T, N> {
    #[inline]
    fn index_mut(&mut self, i: usize) -> &mut T {
        &mut self.items[i]
    }
}

#[cfg(not(any(feature = "host-linux", feature = "chip-bcm2712")))]
impl<T: Copy, const N: usize> Deref for ParseTable<T, N> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        &self.items
    }
}

#[cfg(not(any(feature = "host-linux", feature = "chip-bcm2712")))]
impl<T: Copy, const N: usize> DerefMut for ParseTable<T, N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.items
    }
}

// ── Scratch ───────────────────────────────────────────────────────────────

/// Build-time scratch of `n` slots of `$init`: a `Vec` on Linux (where `n` is
/// the graph's live count), a transient carve block on bcm2712, the static
/// size `$cap` on the other platforms. Graph preparation and live adds use
/// it; a step never does.
#[macro_export]
macro_rules! scratch {
    ($init:expr; $cap:expr, $n:expr) => {{
        #[cfg(feature = "host-linux")]
        {
            let _ = $cap;
            ::std::vec![$init; $n]
        }
        #[cfg(feature = "chip-bcm2712")]
        {
            let _ = $cap;
            $crate::kernel::mem::table::Scratch::new($init, $n)
        }
        #[cfg(not(any(feature = "host-linux", feature = "chip-bcm2712")))]
        {
            let _ = $n;
            [$init; $cap]
        }
    }};
}
