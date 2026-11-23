//! AArch64 counters for the `counters` contract.
//!
//! Two sources. One is each core's own performance monitors: the cycle
//! counter (`PMCCNTR_EL0`) and two event counters set to count L1
//! instruction-cache accesses (event `0x14`) and refills (`0x01`), a hit
//! being an access that was not a refill. The other is the generic timer
//! alone, for a machine whose monitors are not this kernel's to program.
//!
//! The monitors are per core and are not touched until a core first reads
//! them: a graph that never asks leaves every core's as the firmware left
//! them. A core answers that it has no counter when it has no monitors
//! (`ID_AA64DFR0_EL1.PMUVer` reads none), and when it did not enter the
//! kernel at EL2: only then did the kernel itself set `MDCR_EL2` on the way
//! down to EL1 so that no monitor access traps (`arch::el2_drop`). A core
//! entered at EL1 runs under a hypervisor or firmware whose trap bits it
//! cannot read, where the first access could fault, so it makes none.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::{cpu, exception::MAX_CORES, timer};
use crate::abi::contracts::counters as wire;
use crate::kernel::sys::counters::wrapping_delta;

/// `PMEVTYPER` event numbers (Arm ARM, common architectural events).
const EVENT_L1I_CACHE_REFILL: u64 = 0x01;
const EVENT_L1I_CACHE: u64 = 0x14;
/// Filter bit: count at EL2 as well, wherever the kernel runs.
const FILTER_NSH: u64 = 1 << 27;

/// Whether each core has set its monitors up, and each core's event
/// counters as last read.
static ENABLED: [AtomicBool; MAX_CORES] = [const { AtomicBool::new(false) }; MAX_CORES];
static LAST_ACCESS: [AtomicU32; MAX_CORES] = [const { AtomicU32::new(0) }; MAX_CORES];
static LAST_REFILL: [AtomicU32; MAX_CORES] = [const { AtomicU32::new(0) }; MAX_CORES];

fn this_core() -> usize {
    (cpu::current_core_id() as usize).min(MAX_CORES - 1)
}

/// Whether this core's performance monitors are the kernel's to read: it
/// implements them, and it entered at EL2, where the kernel left them
/// untrapped.
pub fn monitors_present() -> bool {
    if !cpu::entered_at_el2() {
        return false;
    }
    let dfr0: u64;
    // SAFETY: an ID register, readable at EL1.
    unsafe {
        core::arch::asm!("mrs {}, id_aa64dfr0_el1", out(reg) dfr0, options(nomem, nostack));
    }
    crate::arch::el2_drop::has_monitors(dfr0)
}

/// Set this core's monitors counting: the cycle counter and the two cache
/// events, at every exception level the kernel and its modules run at.
fn enable_this_core() {
    // SAFETY: this core's own PMU registers, present per `monitors_present`.
    unsafe {
        core::arch::asm!(
            "msr pmccfiltr_el0, {nsh}",
            "msr pmevtyper0_el0, {access}",
            "msr pmevtyper1_el0, {refill}",
            // The cycle counter (bit 31) and event counters 0 and 1.
            "msr pmcntenset_el0, {enable}",
            // PMCR: E (enable), P and C (reset the counters), LC (a 64-bit
            // cycle counter).
            "mrs {tmp}, pmcr_el0",
            "orr {tmp}, {tmp}, {control}",
            "msr pmcr_el0, {tmp}",
            "isb",
            control = in(reg) 0x47u64,
            nsh = in(reg) FILTER_NSH,
            access = in(reg) EVENT_L1I_CACHE | FILTER_NSH,
            refill = in(reg) EVENT_L1I_CACHE_REFILL | FILTER_NSH,
            enable = in(reg) (1u64 << 31) | 0b11,
            tmp = out(reg) _,
            options(nomem, nostack),
        );
    }
}

fn cycle_counter() -> u64 {
    let v: u64;
    // SAFETY: this core's cycle counter.
    unsafe { core::arch::asm!("mrs {}, pmccntr_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// The monitors' hook: this core's cycle count, and its cache accesses and
/// hits since it last read them.
pub fn monitors_read(drain: &mut [u32; 2]) -> (u8, u32) {
    if !monitors_present() {
        return (0, 0);
    }
    let core = this_core();
    if !ENABLED[core].swap(true, Ordering::AcqRel) {
        enable_this_core();
    }
    let (access, refill): (u64, u64);
    // SAFETY: this core's event counters 0 and 1.
    unsafe {
        core::arch::asm!(
            "mrs {a}, pmevcntr0_el0",
            "mrs {r}, pmevcntr1_el0",
            a = out(reg) access,
            r = out(reg) refill,
            options(nomem, nostack),
        );
    }
    let accesses = wrapping_delta(
        LAST_ACCESS[core].swap(access as u32, Ordering::Relaxed),
        access as u32,
    );
    let refills = wrapping_delta(
        LAST_REFILL[core].swap(refill as u32, Ordering::Relaxed),
        refill as u32,
    );
    drain[0] = accesses.saturating_sub(refills);
    drain[1] = accesses;
    (
        wire::PRESENT_CYCLES | wire::PRESENT_ICACHE,
        cycle_counter() as u32,
    )
}

/// How long [`monitors_hz`] watches the cycle counter, in timer ticks'
/// worth of microseconds.
const CALIBRATE_US: u32 = 250;

/// The core clock now: the cycle counter's advance over a short stretch of
/// the generic timer.
pub fn monitors_hz() -> u32 {
    if !monitors_present() || !ENABLED[this_core()].load(Ordering::Acquire) {
        return 0;
    }
    let window = u64::from(timer::us_to_ticks(CALIBRATE_US)).max(1);
    let (t0, c0) = (timer::read_timer_count_64(), cycle_counter());
    while timer::read_timer_count_64().wrapping_sub(t0) < window {
        core::hint::spin_loop();
    }
    let (t1, c1) = (timer::read_timer_count_64(), cycle_counter());
    let hz = u128::from(c1.wrapping_sub(c0)) * u128::from(timer::timer_freq())
        / u128::from(t1.wrapping_sub(t0).max(1));
    hz.min(u128::from(u32::MAX)) as u32
}

/// The generic timer's hook: its count as the cycle count, no cache counts.
pub fn timer_read(_drain: &mut [u32; 2]) -> (u8, u32) {
    (wire::PRESENT_CYCLES, timer::read_timer_count_64() as u32)
}

/// The generic timer's rate.
pub fn timer_hz() -> u32 {
    timer::timer_freq().min(u64::from(u32::MAX)) as u32
}
