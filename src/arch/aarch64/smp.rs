//! The shared domain loop's view of an AArch64 machine: how a core names
//! itself, waits, wakes the others, parks, counts time and keeps its tick.
//! Every AArch64 bare-metal platform hands these to
//! `kernel::exec::domains::Platform`.

use core::sync::atomic::{AtomicU32, Ordering};

use super::{cpu, exception, timer};

/// The running core's number.
pub fn core_id() -> usize {
    cpu::current_core_id() as usize
}

/// Make this core's earlier stores visible and end every core's wait for an
/// event.
pub fn signal() {
    cpu::signal_cores();
}

/// Wait for an event.
pub fn wait_event() {
    cpu::wait_for_event();
}

/// Wait for an interrupt.
pub fn wait_interrupt() {
    cpu::wait_for_interrupt();
}

/// Park for a quiesce: record the generation, then wait for events until the
/// generation moves.
pub fn park(generation_word: &AtomicU32, parked_word: &AtomicU32, generation: u32) {
    parked_word.store(generation, Ordering::Release);
    while generation_word.load(Ordering::Acquire) == generation {
        cpu::wait_for_event();
    }
}

/// The generic timer's counter.
pub fn counter() -> u64 {
    timer::read_timer_count_64()
}

/// Microseconds as generic-timer ticks.
pub fn us_to_ticks(us: u32) -> u32 {
    timer::us_to_ticks(us)
}

/// Interrupts core `core_id` has taken.
pub fn interrupts(core_id: usize) -> u32 {
    exception::CORE_INTERRUPTS[core_id.min(exception::MAX_CORES - 1)].load(Ordering::Relaxed)
}

/// Set core `core_id`'s tick period: the timer handler reloads from the
/// core's slot on its next fire.
pub fn set_tick(core_id: usize, period_us: u32) {
    let slot = core_id.min(exception::NEXT_DEADLINE_TICKS.len() - 1);
    exception::NEXT_DEADLINE_TICKS[slot].store(timer::us_to_ticks(period_us), Ordering::Relaxed);
}
