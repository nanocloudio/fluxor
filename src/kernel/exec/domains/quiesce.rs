//! Parking the other cores while the primary does what they must not run
//! beside.
//!
//! A quiesce is a generation: the word is odd while one is in flight, and
//! each request and each release advances it. A core parks by recording the
//! generation it parked in and waits for the generation to move. The primary
//! waits for every core that has entered its loop to record the current
//! generation. Recording the generation, not a count, keeps a core that is
//! still leaving one quiesce from being taken as parked in the next. A core
//! enters its loop by setting its bit and then reading the generation, and
//! the primary requests by advancing the generation and then reading the
//! bits, all sequentially consistent: either the primary waits for that
//! core, or the core sees the request and parks anyway.
//!
//! The protocol is keyed by core. A parked core parks every domain its loop
//! passes over, and core 0, which requests, never parks.
//!
//! Two quiesces exist ([`STRUCTURAL`], [`STEP`]); they differ only in where
//! a core looks for the request.

use core::sync::atomic::{AtomicU32, Ordering};

/// Cores a quiesce covers: the scheduler's `MAX_DOMAINS`, since no target
/// runs more domain loops than domains.
pub const MAX_CORES: usize = 4;

/// How a core parks: called with the generation word, the core's parked
/// word and the generation in flight, it stores the generation into the
/// parked word (which is what tells the primary the core is parked) and
/// returns once the generation word has moved. A platform whose parked core
/// must not fetch from a memory the primary is about to take away supplies a
/// wait that stores and waits from RAM.
pub type ParkWait = fn(generation_word: &AtomicU32, parked_word: &AtomicU32, generation: u32);

/// One quiesce: its generation, the cores in their loops, and where each
/// last parked.
pub struct Quiesce {
    /// Odd while a quiesce is in flight.
    generation: AtomicU32,
    /// Bit `c` set once core `c` has entered its loop, which it never
    /// leaves.
    in_loop: AtomicU32,
    /// The generation each core last parked in (0, which is even, before its
    /// first).
    parked_in: [AtomicU32; MAX_CORES],
    /// Bit `c` set while core `c` is suspended inside a call the primary is
    /// running for it: it counts as parked in whatever request is in flight.
    away: AtomicU32,
    /// Parks taken, over every core.
    parks: AtomicU32,
}

impl Default for Quiesce {
    fn default() -> Self {
        Self::new()
    }
}

impl Quiesce {
    pub const fn new() -> Self {
        Self {
            generation: AtomicU32::new(0),
            in_loop: AtomicU32::new(0),
            parked_in: [const { AtomicU32::new(0) }; MAX_CORES],
            away: AtomicU32::new(0),
            parks: AtomicU32::new(0),
        }
    }

    /// Core `core` has entered its loop: from here a request waits for it.
    /// Core 0 is never waited for.
    pub fn enter_loop(&self, core: usize) {
        if core != 0 && core < MAX_CORES {
            self.in_loop.fetch_or(1 << core, Ordering::SeqCst);
        }
    }

    /// Core `core` no longer runs a loop (the primary stopped it): requests
    /// stop waiting for it.
    pub fn leave_loop(&self, core: usize) {
        if core != 0 && core < MAX_CORES {
            self.in_loop.fetch_and(!(1 << core), Ordering::SeqCst);
        }
    }

    /// Whether core `core` has entered its loop.
    pub fn in_loop(&self, core: usize) -> bool {
        core < MAX_CORES && self.in_loop.load(Ordering::SeqCst) & (1 << core) != 0
    }

    /// Whether a quiesce is in flight.
    pub fn requested(&self) -> bool {
        self.generation.load(Ordering::SeqCst) & 1 == 1
    }

    /// Primary-only. Ask every other core to park at its next park point.
    /// Paired with [`Self::release`]. The caller wakes the cores.
    pub fn request(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Primary-only. Release the parked cores. The caller wakes them.
    pub fn release(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// A core's park point: a no-op on core 0 and when no quiesce is in
    /// flight; otherwise the core parks in `wait`, which records the
    /// generation and returns once [`Self::release`] has advanced it.
    /// Returns whether it parked.
    #[inline]
    pub fn park_if_requested(&self, core: usize, wait: ParkWait) -> bool {
        if core == 0 || core >= MAX_CORES {
            return false;
        }
        let generation = self.generation.load(Ordering::SeqCst);
        if generation & 1 == 0 {
            return false;
        }
        self.parks.fetch_add(1, Ordering::Relaxed);
        wait(&self.generation, &self.parked_in[core], generation);
        true
    }

    /// Primary-only. Mark core `core` suspended inside a call the primary
    /// runs for it (`true`), or back from it (`false`). While marked it
    /// counts as parked: it runs nothing until the call returns, which is
    /// after the primary has released whatever the call itself requested.
    pub fn set_away(&self, core: usize, away: bool) {
        if core == 0 || core >= MAX_CORES {
            return;
        }
        if away {
            self.away.fetch_or(1 << core, Ordering::SeqCst);
        } else {
            self.away.fetch_and(!(1 << core), Ordering::SeqCst);
        }
    }

    /// Whether every other core in its loop has parked in the request in
    /// flight, or is suspended in a call the primary is running for it.
    pub fn all_parked(&self) -> bool {
        let generation = self.generation.load(Ordering::Relaxed);
        let in_loop = self.in_loop.load(Ordering::SeqCst);
        let away = self.away.load(Ordering::SeqCst);
        (1..MAX_CORES)
            .filter(|&c| in_loop & !away & (1 << c) != 0)
            .all(|c| self.parked_in[c].load(Ordering::Acquire) == generation)
    }

    /// Whether core `core` has parked in the request in flight: it is in
    /// its park, which on a platform whose parks keep to RAM means it
    /// fetches nothing from flash. A core away in a call is not parked here.
    pub fn parked(&self, core: usize) -> bool {
        let generation = self.generation.load(Ordering::SeqCst);
        generation & 1 == 1
            && core < MAX_CORES
            && self.parked_in[core].load(Ordering::Acquire) == generation
    }

    /// Primary-only, after [`Self::request`]: spin until every other core in
    /// its loop has parked.
    pub fn wait_parked(&self) {
        while !self.all_parked() {
            core::hint::spin_loop();
        }
    }

    /// Primary-only, after [`Self::request`]: spin until every other core in
    /// its loop has parked or `expired` says the wait is over. Returns
    /// whether they parked; on `false` the caller releases the request.
    pub fn wait_parked_until(&self, mut expired: impl FnMut() -> bool) -> bool {
        loop {
            if self.all_parked() {
                return true;
            }
            if expired() {
                return self.all_parked();
            }
            core::hint::spin_loop();
        }
    }

    /// Parks taken since boot, over every core.
    pub fn parks(&self) -> u32 {
        self.parks.load(Ordering::Relaxed)
    }
}

/// The quiesce for a structural change (a graph rebuild, a live add or
/// removal, a fault that tears a module down): cores park at their pass
/// boundary, outside any step.
pub static STRUCTURAL: Quiesce = Quiesce::new();

/// The quiesce for work that changes no structure but that no other core may
/// run beside (taking execute-in-place flash away): cores park between
/// module steps, so the primary waits for one step and not a whole pass.
pub static STEP: Quiesce = Quiesce::new();

/// Whether core `core` has joined both quiesces, so that each waits for it
/// to park. A core joins them one after the other as it enters its loop;
/// one that has joined only [`STRUCTURAL`] is still on its way in, and a
/// step request would find nothing in [`STEP`] to wait for while it runs.
pub fn joined(core: usize) -> bool {
    STRUCTURAL.in_loop(core) && STEP.in_loop(core)
}
