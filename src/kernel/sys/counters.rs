//! The `counters` contract: a cycle counter and instruction-cache hit and
//! access counts, read by a granted module around a region of its own code.
//!
//! The kernel serves the two ops and owns the cache counts. A platform
//! names its [`Source`] once at boot ([`install`]): what its counters are,
//! and a hook that answers the calling core's live cycle count and the
//! cache counts gone by since the hook last ran. Hardware cache counters
//! are 32 bits wide and either stick at their top (and are cleared by the
//! hook each time it reads them) or wrap; either way the hook answers a
//! delta, and the kernel adds it to 64-bit totals ([`Totals`]). `READ`
//! answers the totals' low 32 bits, which wrap, so a module subtracts two
//! reads with wrapping arithmetic.
//!
//! The hook and the addition run under one lock with this core's interrupts
//! masked: two cores reading at once, or a read beside the periodic drain,
//! neither count a delta twice nor lose one. Each core that has read drains
//! its counters at least once a second from its pass ([`housekeep`]), so a
//! counter is read again well before it sticks or wraps past a second lap.
//!
//! A platform that names no source has the system microsecond clock as its
//! cycle counter and no cache counters; a counter a target lacks answers
//! with its bit clear and its counts zero.

use portable_atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

use crate::abi::contracts::counters as wire;
use crate::kernel::sys::errno;
use crate::kernel::sys::guard::KernelGuard;
use crate::kernel::sys::hal;

/// Cores with totals of their own, when the cache counts are each core's.
pub const MAX_CORES: usize = 4;

/// The longest a core's cache counters go undrained once it has read them.
pub const DRAIN_INTERVAL_MS: u32 = 1_000;

/// What a platform's counters are and how they are read.
pub struct Source {
    /// `wire::CLOCK_CORE` or `wire::CLOCK_SYSTEM`: what a cycle is.
    pub cycles_clock: u8,
    /// `wire::SCOPE_CORE` or `wire::SCOPE_NODE` where the target has cache
    /// counters; `wire::SCOPE_NONE` where it has none.
    pub icache_scope: u8,
    /// The rate of the cycle counter in hertz: the core clock now, or the
    /// counter's own fixed rate.
    pub cycles_hz: fn() -> u32,
    /// Read the counters on the calling core. Writes into `drain` the cache
    /// hits and accesses counted since this hook last ran (on this core,
    /// where the counts are each core's); answers the `present` mask and
    /// the calling core's live cycle count. Called under the kernel's lock,
    /// interrupts masked.
    pub read: fn(drain: &mut [u32; 2]) -> (u8, u32),
}

/// 64-bit cache totals widened from 32-bit deltas.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub hit: u64,
    pub access: u64,
}

impl Totals {
    /// Add one drain's deltas, `[hit, access]`.
    pub const fn add(&mut self, drain: [u32; 2]) {
        self.hit = self.hit.wrapping_add(drain[0] as u64);
        self.access = self.access.wrapping_add(drain[1] as u64);
    }

    /// The 32-bit view a `READ` answers: `(hit, access)`, wrapping.
    pub const fn low(&self) -> (u32, u32) {
        (self.hit as u32, self.access as u32)
    }
}

/// What a free-running 32-bit counter has counted between two reads `last`
/// and `now` of it, across at most one wrap.
pub const fn wrapping_delta(last: u32, now: u32) -> u32 {
    now.wrapping_sub(last)
}

/// The platform [`install`] named; null before it.
static SOURCE: AtomicPtr<Source> = AtomicPtr::new(core::ptr::null_mut());

/// Held, with interrupts masked, across a hook call and the addition of
/// what it drained.
static LOCK: AtomicBool = AtomicBool::new(false);

/// The totals: each core's own where the scope is the core, entry 0 where
/// it is the node. Read and written under [`LOCK`] alone.
struct AllTotals(core::cell::UnsafeCell<[Totals; MAX_CORES]>);
// SAFETY: every access holds `LOCK`.
unsafe impl Sync for AllTotals {}
static TOTALS: AllTotals = AllTotals(core::cell::UnsafeCell::new(
    [Totals { hit: 0, access: 0 }; MAX_CORES],
));

/// When each core last drained, in wrapping milliseconds and never 0; 0 for
/// a core that has not read its counters, which [`housekeep`] leaves alone.
static DRAINED_AT_MS: [AtomicU32; MAX_CORES] = [const { AtomicU32::new(0) }; MAX_CORES];

/// The clock [`DRAINED_AT_MS`] keeps, which never reads 0.
fn now_ms() -> u32 {
    (hal::now_millis() as u32).max(1)
}

/// Name the platform's counters, in place of the system clock alone. At
/// boot, before any module runs.
pub fn install(source: &'static Source) {
    SOURCE.store(source as *const Source as *mut Source, Ordering::Release);
}

/// The counters every target has when its platform names none: the system
/// microsecond clock as the cycle counter, and no cache counters.
static SYSTEM_CLOCK: Source = Source {
    cycles_clock: wire::CLOCK_SYSTEM,
    icache_scope: wire::SCOPE_NONE,
    cycles_hz: || 1_000_000,
    read: |_| (wire::PRESENT_CYCLES, hal::now_micros() as u32),
};

fn source() -> &'static Source {
    // SAFETY: null or the `&'static Source` `install` stored.
    unsafe { SOURCE.load(Ordering::Acquire).as_ref() }.unwrap_or(&SYSTEM_CLOCK)
}

/// The calling core's slot in the per-core tables.
fn this_core() -> usize {
    hal::core_id().min(MAX_CORES - 1)
}

/// Run the hook on this core and add what it drained, under the lock.
/// Returns the `present` mask, the live cycle count, and the totals' low
/// halves after the addition.
fn drain(source: &Source) -> (u8, u32, u32, u32) {
    let core = this_core();
    let slot = if source.icache_scope == wire::SCOPE_CORE {
        core
    } else {
        0
    };
    let guard = KernelGuard::acquire();
    while LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let mut delta = [0u32; 2];
    let (present, cycles) = (source.read)(&mut delta);
    // SAFETY: the lock is held.
    let totals = unsafe { &mut (*TOTALS.0.get())[slot] };
    if present & wire::PRESENT_ICACHE != 0 {
        totals.add(delta);
    }
    let (hit, access) = totals.low();
    LOCK.store(false, Ordering::Release);
    drop(guard);
    DRAINED_AT_MS[core].store(now_ms(), Ordering::Relaxed);
    (present, cycles, hit, access)
}

/// What this target's counters are.
pub fn describe() -> wire::Description {
    let source = source();
    let (present, ..) = drain(source);
    let has_cycles = present & wire::PRESENT_CYCLES != 0;
    let has_icache = present & wire::PRESENT_ICACHE != 0;
    wire::Description {
        present,
        cycles_clock: source.cycles_clock,
        icache_scope: if has_icache {
            source.icache_scope
        } else {
            wire::SCOPE_NONE
        },
        cycles_hz: if has_cycles { (source.cycles_hz)() } else { 0 },
    }
}

/// The counts, on the calling core.
pub fn read() -> wire::Reading {
    let (present, cycles, icache_hit, icache_access) = drain(source());
    wire::Reading {
        present,
        cycles,
        icache_hit,
        icache_access,
    }
}

/// The calling core's periodic drain, from its pass: once it has read its
/// counters, they are read again at least every [`DRAIN_INTERVAL_MS`], so
/// none sticks at its top or wraps twice between reads. One load for a core
/// that has never read them, and nothing touches the hardware for it.
pub fn housekeep() {
    let last = DRAINED_AT_MS[this_core()].load(Ordering::Relaxed);
    if last == 0 || now_ms().wrapping_sub(last) < DRAIN_INTERVAL_MS {
        return;
    }
    let _ = drain(source());
}

/// The contract's two ops: `arg` out, one 16-byte record.
pub fn dispatch(op: u32, arg: &mut [u8]) -> i32 {
    let record = match op {
        wire::DESCRIBE => wire::encode_describe(&describe()),
        wire::READ => wire::encode_read(&read()),
        _ => return errno::ENOSYS,
    };
    let (Some(record), Some(out)) = (record, arg.get_mut(..wire::READ_SIZE)) else {
        return errno::EINVAL;
    };
    out.copy_from_slice(&record);
    0
}

const _: () = assert!(wire::DESCRIBE_SIZE == wire::READ_SIZE);
