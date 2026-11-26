//! RP2350 core 1: the second Cortex-M33 as the core of an execution domain.
//!
//! Core 0 launches core 1 through the bootrom's inter-processor FIFO
//! sequence when a graph first gives core 1's domain modules. Core 1 then
//! waits, in RAM, until that graph is released, and runs the shared domain
//! loop for that domain
//! (`kernel::exec::domains::run`). What this file owns is the part the RP2350
//! adds:
//!
//! - **The RAM park.** Everything core 1 runs is fetched from flash, and
//!   core 0 takes execute-in-place away for a sector erase, a page program
//!   and the BOOTSEL read. Whenever core 1 waits for core 0 (before its
//!   first graph, in a quiesce) it waits in [`fluxor_rp_ram_park`], a loop
//!   in RAM with interrupts masked that records it is parked from inside the
//!   loop. Core 0 detaches XIP only while core 1 is there.
//! - **Its own interrupts.** Each core has an NVIC of its own that only it
//!   can write. A line bound for core 1 is recorded in a line set that core
//!   1 applies when it enters its loop, after every park and at each pass
//!   boundary where the set changed.
//! - **Its own timer.** Core 1's alarms are on its own instance
//!   (`chip::SECONDARY_TIMER_*`): the step guard, the loop's wake, the
//!   module timer.
//! - **Its heartbeat.** Core 1 counts every pass and every turn of the park
//!   loop; core 0 feeds the watchdog only while that count moves.
//! - **Its end.** A kernel fault or a panic on core 1 is a fault of the
//!   node. Core 1 gives up whatever it holds, leaves what happened for core
//!   0 and waits in RAM ([`stop_for_node_fault`]); core 0 reports it and
//!   resets the node. Whenever core 0 itself stops running the graph (its
//!   own fault, a halted graph, a reset) it first puts core 1 back in the
//!   bootrom ([`stop`]), so nothing runs beside the report or the reboot.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use fluxor_contracts::boot_config::ExecMode;

use crate::kernel::exec::domains::{self, core_map, quiesce};
use crate::kernel::exec::scheduler;
use crate::platform::chip;
use crate::platform::rp_regs::{read32, write32};
use crate::platform::rp_timer::alarm::SECONDARY;

/// The domain core 1 runs, from the target's map.
pub const DOMAIN: Option<usize> = core_map::secondary_domain(&chip::DOMAIN_CORES, 1);

// ── SIO inter-processor FIFO ─────────────────────────────────────────────
//
// One FIFO in each direction, four words deep. `FIFO_ST.VLD` says this
// core's incoming FIFO holds a word, `RDY` that its outgoing FIFO has room.

const SIO_BASE: usize = 0xD000_0000;
const SIO_FIFO_ST: usize = SIO_BASE + 0x50;
const SIO_FIFO_WR: usize = SIO_BASE + 0x54;
const SIO_FIFO_RD: usize = SIO_BASE + 0x58;
const FIFO_VLD: u32 = 1 << 0;
const FIFO_RDY: u32 = 1 << 1;

/// How long core 1 has to answer the launch sequence and reach its wait.
const LAUNCH_BOUND_US: u64 = 10_000;

/// The longest core 1 sleeps with nothing to do, so its heartbeat keeps
/// moving on an idle domain.
const IDLE_BOUND_US: u32 = 250_000;

// ── State shared by the two cores ────────────────────────────────────────

/// Core 1 answered the launch sequence and reached its RAM wait.
static LAUNCHED: AtomicBool = AtomicBool::new(false);
/// 0 until core 0 lets core 1 enter its domain loop; the word core 1's first
/// RAM wait watches.
static GO: AtomicU32 = AtomicU32::new(0);
/// Written 0 by core 1 from inside its first RAM wait: the sign that it has
/// left flash.
static WAITING: AtomicU32 = AtomicU32::new(1);
/// Core 1's liveness: bumped every pass and every turn of the park loop.
static HEARTBEAT: AtomicU32 = AtomicU32::new(0);
/// Interrupts core 1 has taken from its own timer.
static INTERRUPTS: AtomicU32 = AtomicU32::new(0);
/// The period of core 1's tick in microseconds: its wake alarm re-arms
/// itself by it. 0 for a domain that is not paced by a tick, whose waits arm
/// the alarm once.
static TICK_PERIOD_US: AtomicU32 = AtomicU32::new(0);

/// The interrupt lines core 1 owns, a bit per line.
static LINES_OWNED: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];
/// The owned lines that are to be enabled in core 1's NVIC.
static LINES_ENABLED: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];
/// Owned lines whose binding core 0 dropped: core 1 masks each and gives up
/// its ownership the next time it applies its line set.
static LINES_RELEASED: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];
/// Advanced whenever something core 1 must apply itself changes: its line
/// set, or the module timer.
static APPLY_GEN: AtomicU32 = AtomicU32::new(0);
/// The generation core 1 last applied. Core 1 only.
static APPLIED_GEN: AtomicU32 = AtomicU32::new(u32::MAX);

/// Whether core 1 was launched and waits for, or runs, a domain.
pub fn launched() -> bool {
    LAUNCHED.load(Ordering::Acquire)
}

/// Whether core 0 has let core 1 enter its domain loop.
pub fn running() -> bool {
    GO.load(Ordering::Acquire) != 0
}

/// Core 1's heartbeat count.
pub fn heartbeat() -> u32 {
    HEARTBEAT.load(Ordering::Relaxed)
}

/// Count an interrupt taken on core 1. Called from core 1's handlers.
#[inline]
pub fn count_interrupt() {
    INTERRUPTS.fetch_add(1, Ordering::Relaxed);
}

// ── The RAM park ─────────────────────────────────────────────────────────
//
// r0 = the word to watch, r1 = the word to record the park in, r2 = the
// value recorded and the value of the watched word to wait out, r3 = the
// heartbeat. With interrupts masked: store r2 to [r1]; then until [r0]
// differs from r2, bump [r3] and wait for an event. Restore the mask and
// return. Every instruction and every word it touches is in RAM, so the
// loop runs with execute-in-place detached. An event (`sev` from core 0)
// ends each wait; a pending interrupt cannot be taken, and is taken on
// return.
core::arch::global_asm!(
    ".section .data.ram_func.fluxor_rp_ram_park, \"awx\", %progbits",
    ".global fluxor_rp_ram_park",
    ".type fluxor_rp_ram_park, %function",
    ".thumb_func",
    ".balign 4",
    "fluxor_rp_ram_park:",
    "    push {{r4, r5}}",
    "    mrs r4, PRIMASK",
    "    cpsid i",
    "    str r2, [r1]",
    "    dmb",
    "1:",
    "    ldr r5, [r3]",
    "    adds r5, r5, #1",
    "    str r5, [r3]",
    "    ldr r5, [r0]",
    "    cmp r5, r2",
    "    bne 2f",
    "    wfe",
    "    b 1b",
    "2:",
    "    msr PRIMASK, r4",
    "    pop {{r4, r5}}",
    "    bx lr",
    ".size fluxor_rp_ram_park, . - fluxor_rp_ram_park",
    ".text",
);

unsafe extern "C" {
    /// The RAM park, in assembly above.
    fn fluxor_rp_ram_park(watch: *const u32, record: *mut u32, value: u32, heartbeat: *mut u32);
}

/// Park the calling core in RAM until `watch` no longer reads `value`,
/// having stored `value` into `record` from inside the loop.
fn ram_park(watch: &AtomicU32, record: &AtomicU32, value: u32) {
    // SAFETY: three statics in RAM; the routine keeps to RAM and returns
    // with the interrupt mask it was entered with.
    unsafe { fluxor_rp_ram_park(watch.as_ptr(), record.as_ptr(), value, HEARTBEAT.as_ptr()) };
}

/// The platform's quiesce park (`domains::Platform::park`): the RAM park on
/// the generation, then whatever core 0 changed for core 1 while it was
/// parked.
fn park(generation_word: &AtomicU32, parked_word: &AtomicU32, generation: u32) {
    // The time parked is core 0's, not the module's whose burst this core
    // may be in: its deadline moves past it before interrupts return, so a
    // guard alarm that came due while parked is not taken as a timeout.
    crate::arch::cortex_m::interrupt_free(|| {
        let parked_at = SECONDARY.now_raw_lo();
        ram_park(generation_word, parked_word, generation);
        let parked_for = SECONDARY.now_raw_lo().wrapping_sub(parked_at);
        crate::platform::rp_step_guard::rp_step_guard_defer(parked_for);
        // A park for a flash write ends with the cache empty.
        crate::platform::rp_step_guard::park_ended();
    });
    apply_if_changed();
}

// ── Launch (core 0) ──────────────────────────────────────────────────────

/// Core 1's stack. In `.uninit`, among the kernel's statics, so the
/// static-RAM ceiling counts it, and left unzeroed at boot: core 0 paints it
/// before each launch.
#[repr(C, align(8))]
struct Stack([u8; chip::SECONDARY_STACK_SIZE]);

#[link_section = ".uninit.CORE1_STACK"]
#[no_mangle]
static mut CORE1_STACK: core::mem::MaybeUninit<Stack> = core::mem::MaybeUninit::uninit();

/// The floor of core 1's stack.
#[inline]
fn stack_floor() -> usize {
    (&raw const CORE1_STACK) as usize
}

/// One past the top of core 1's stack.
#[inline]
fn stack_top() -> usize {
    stack_floor() + chip::SECONDARY_STACK_SIZE
}

/// The word free stack holds until a frame reaches it.
const STACK_PAINT: u32 = 0x5EED_57AC;

// ── Core 1's reset (core 0) ──────────────────────────────────────────────

/// PSM `FRCE_OFF`, one word below the watchdog-select register the target
/// names; bit 24 holds processor 1 in reset.
const PSM_FRCE_OFF: usize = chip::PSM_WDSEL as usize - 4;
const PSM_PROC1: u32 = 1 << 24;

/// Reads of the force bit [`reset`] waits through for it to take. The bit
/// reads back on the next access; the bound is there so that core 0's reset
/// path, which runs this before anything can report or recover, has no wait
/// without an end.
const FORCE_READS: u32 = 1024;

/// Reset core 1 into the bootrom's wait for a launch: force it off, wait for
/// that to take, and let it go again. Whatever core 1 was running stops, and
/// it runs nothing but ROM until it is launched. The force bit is never left
/// set: every later reboot finds the power-on state machine as a cold boot
/// leaves it. Touches no static, so core 0 may do it as its first act after
/// its own reset.
#[inline(always)]
pub fn reset() {
    // SAFETY: a PSM register with the atomic aliases; the writes touch only
    // processor 1's bit, and the read-back waits for the force to take.
    unsafe {
        crate::platform::rp_regs::set_bits(PSM_FRCE_OFF, PSM_PROC1);
        let mut reads = 0;
        while read32(PSM_FRCE_OFF) & PSM_PROC1 == 0 && reads < FORCE_READS {
            reads += 1;
        }
        crate::platform::rp_regs::clear_bits(PSM_FRCE_OFF, PSM_PROC1);
    }
}

/// Take core 1 out of the node: back into the bootrom's wait, holding
/// nothing. Core 0, before it stops running the graph for good (its own
/// fault report, a halted graph, a reset of the node): what core 0 does
/// next then runs beside no other core, and the lock between the cores
/// cannot be left with a holder that will never release it. Core 1 is not
/// launched again in this boot.
pub fn stop() {
    reset();
    crate::arch::critical_section_impl::abandon(1);
    GO.store(0, Ordering::Release);
    LAUNCHED.store(false, Ordering::Release);
    quiesce::STRUCTURAL.leave_loop(1);
    quiesce::STEP.leave_loop(1);
}

/// Launch core 1 into its RAM wait, if it is not there already. Core 0,
/// when a graph first gives core 1's domain modules: after the graph is
/// instantiated and before it is released, so nothing detaches XIP while
/// core 1 runs its entry from flash. A node whose graphs never place a
/// module on core 1 never starts it. Returns whether core 1 answered and
/// reached the wait within [`LAUNCH_BOUND_US`]; on `false` core 1 is back in
/// the bootrom and a graph with a domain on it is refused.
pub fn launch() -> bool {
    let Some(_) = DOMAIN else {
        return false;
    };
    if launched() {
        return true;
    }
    let launched = launch_sequence();
    if launched {
        LAUNCHED.store(true, Ordering::Release);
    } else {
        // A core that did not reach its wait runs nothing of this image.
        reset();
    }
    launched
}

/// Reset core 1, send it the bootrom's launch sequence and wait for it to
/// reach its RAM wait, all within [`LAUNCH_BOUND_US`].
fn launch_sequence() -> bool {
    crate::platform::rp_timer::start_secondary_tick();
    // Each attempt starts from a core 1 fresh out of reset, with its stack
    // painted and its wait not yet reached. The sequence below copes with
    // core 1 being anywhere on its way to the bootrom's wait.
    reset();
    WAITING.store(1, Ordering::Release);
    paint_stack();

    let top = stack_top() as u32;
    let entry = core1_entry as unsafe extern "C" fn() -> ! as usize as u32;
    // The bootrom's sequence: each word is echoed; a wrong echo starts over.
    let sequence = [0, 0, 1, chip::FLASH_BASE, top, entry | 1];
    let deadline = crate::platform::rp_timer::now_us() + LAUNCH_BOUND_US;
    let expired = || crate::platform::rp_timer::now_us() >= deadline;
    let mut at = 0;
    while at < sequence.len() {
        let word = sequence[at];
        // SAFETY: SIO FIFO registers, core 0's side; core 1 is in the
        // bootrom's wait and nothing else on core 0 uses the FIFO.
        unsafe {
            if word == 0 {
                // Drain what core 1 sent before a zero, and wake it in case
                // it waits for room.
                while read32(SIO_FIFO_ST) & FIFO_VLD != 0 {
                    let _ = read32(SIO_FIFO_RD);
                }
                crate::arch::cortex_m::sev();
            }
            while read32(SIO_FIFO_ST) & FIFO_RDY == 0 {
                if expired() {
                    return false;
                }
            }
            write32(SIO_FIFO_WR, word);
            crate::arch::cortex_m::sev();
            while read32(SIO_FIFO_ST) & FIFO_VLD == 0 {
                if expired() {
                    return false;
                }
            }
            at = if read32(SIO_FIFO_RD) == word {
                at + 1
            } else {
                0
            };
        }
    }
    // Core 1 runs its entry from flash until it reaches the RAM wait; nothing
    // may detach XIP before it has.
    while WAITING.load(Ordering::Acquire) != 0 {
        if expired() {
            return false;
        }
    }
    true
}

/// Paint core 1's stack so its depth can be read back ([`stack_peak`]).
fn paint_stack() {
    let mut word = stack_floor() as *mut u32;
    let end = stack_top() as *mut u32;
    while word < end {
        // SAFETY: core 1's stack, which nothing else uses; core 1 is not
        // running.
        unsafe {
            core::ptr::write_volatile(word, STACK_PAINT);
            word = word.add(1);
        }
    }
}

/// The deepest core 1's stack has been since launch, and its size, in bytes.
pub fn stack_peak() -> (usize, usize) {
    let floor = stack_floor();
    let top = stack_top();
    let mut word = floor as *const u32;
    // SAFETY: every address in `[floor, top)` is core 1's stack RAM.
    unsafe {
        while (word as usize) < top && core::ptr::read_volatile(word) == STACK_PAINT {
            word = word.add(1);
        }
    }
    (top - word as usize, top - floor)
}

/// The bounds of core 1's stack, `(floor, top)`.
pub fn stack_bounds() -> (usize, usize) {
    (stack_floor(), stack_top())
}

/// Let core 1 enter its domain loop. Core 0, after `domains::release`, when
/// core 1's domain has modules.
pub fn go() {
    if launched() {
        GO.store(1, Ordering::Release);
        signal();
    }
}

// ── Core 1's entry ───────────────────────────────────────────────────────

/// Where the bootrom starts core 1: on its own stack, with the shared vector
/// table. Sets up what is per core, waits in RAM for a graph, then runs its
/// domain's loop.
///
/// # Safety
/// Entered once, by the bootrom's launch, on core 1.
unsafe extern "C" fn core1_entry() -> ! {
    // SAFETY: MSPLIM is this core's own; the limit is the linker's symbol.
    unsafe {
        let limit = stack_floor() as u32;
        core::arch::asm!("msr MSPLIM, {0}", in(reg) limit, options(nomem, nostack, preserves_flags));
    }
    crate::platform::rp_counters::enable_cycle_counter();
    #[cfg(feature = "kernel-mpu")]
    crate::platform::rp_protection::init_core();
    // This core's alarms quiet, their lines enabled here, where only this
    // core can enable them.
    for (idx, irq) in [
        (
            chip::SECONDARY_TIMER_ALARM_STEP_GUARD,
            chip::SECONDARY_TIMER_IRQ_STEP_GUARD,
        ),
        (
            chip::SECONDARY_TIMER_ALARM_SCHEDULER,
            chip::SECONDARY_TIMER_IRQ_SCHEDULER,
        ),
        (
            chip::SECONDARY_TIMER_ALARM_MODULE_TIMER,
            chip::SECONDARY_TIMER_IRQ_MODULE_TIMER,
        ),
    ] {
        SECONDARY.set_enabled(idx, false);
        SECONDARY.ack(idx);
        crate::arch::cortex_m::nvic_unmask(irq);
    }

    // Until a graph gives this core's domain modules.
    ram_park(&GO, &WAITING, 0);
    // SAFETY: this core's own mask; its handlers and their lines are set up
    // above, and nothing here is inside a critical section.
    unsafe { crate::arch::cortex_m::enable_interrupts() };

    let domain = DOMAIN.unwrap_or(1);
    apply();
    if scheduler::domain_exec_mode(domain) == ExecMode::Tick {
        let period_us = domains::seed_core_tick(domain, &PLATFORM);
        SECONDARY.ack(chip::SECONDARY_TIMER_ALARM_SCHEDULER);
        SECONDARY.set_target_from_now(chip::SECONDARY_TIMER_ALARM_SCHEDULER, period_us);
        SECONDARY.set_enabled(chip::SECONDARY_TIMER_ALARM_SCHEDULER, true);
    }
    domains::run(domain, &PLATFORM)
}

// ── What core 1 applies itself ───────────────────────────────────────────

/// Bring core 1's NVIC and module timer to what core 0 recorded for it.
/// Core 1 only: on entering its loop, after every park, and at a pass
/// boundary where the record changed.
#[inline(never)]
fn apply() {
    let generation = APPLY_GEN.load(Ordering::Acquire);
    for reg in 0..LINES_OWNED.len() {
        let released = LINES_RELEASED[reg].swap(0, Ordering::AcqRel);
        let owned = LINES_OWNED[reg].load(Ordering::Acquire);
        let enabled = LINES_ENABLED[reg].load(Ordering::Acquire) & !released;
        for bit in 0..32u16 {
            if owned & (1 << bit) == 0 {
                continue;
            }
            let irq = reg as u16 * 32 + bit;
            if enabled & (1 << bit) != 0 {
                crate::arch::cortex_m::nvic_unmask(irq);
            } else {
                crate::arch::cortex_m::nvic_mask(irq);
            }
        }
        LINES_ENABLED[reg].fetch_and(!released, Ordering::AcqRel);
        LINES_OWNED[reg].fetch_and(!released, Ordering::AcqRel);
    }
    crate::platform::rp_step_guard::rp_module_timer_arm_this_core();
    APPLIED_GEN.store(generation, Ordering::Release);
}

/// [`apply`], when core 0 has changed the record since core 1 last did.
#[inline]
fn apply_if_changed() {
    if APPLY_GEN.load(Ordering::Acquire) != APPLIED_GEN.load(Ordering::Relaxed) {
        apply();
    }
}

/// Tell core 1 that what it applies itself has changed.
pub fn changed() {
    APPLY_GEN.fetch_add(1, Ordering::AcqRel);
}

/// `(register, bit)` of an NVIC line in the line sets.
fn line(irq: u32) -> Option<(usize, u32)> {
    (irq < 64).then(|| ((irq / 32) as usize, 1u32 << (irq % 32)))
}

/// Whether core 1 owns line `irq`.
pub fn owns_line(irq: u32) -> bool {
    line(irq).is_some_and(|(reg, bit)| LINES_OWNED[reg].load(Ordering::Acquire) & bit != 0)
}

/// Record line `irq` as core 1's, enabled. Core 1 enables it in its own NVIC
/// the next time it applies its line set.
pub fn bind_line(irq: u32) -> bool {
    let Some((reg, bit)) = line(irq) else {
        return false;
    };
    LINES_RELEASED[reg].fetch_and(!bit, Ordering::AcqRel);
    LINES_OWNED[reg].fetch_or(bit, Ordering::AcqRel);
    LINES_ENABLED[reg].fetch_or(bit, Ordering::AcqRel);
    changed();
    true
}

/// Mask or unmask a line core 1 owns. On core 1 the NVIC is written at once;
/// from core 0 the change is recorded for core 1 to apply.
pub fn mask_line(irq: u32, masked: bool) {
    let Some((reg, bit)) = line(irq) else {
        return;
    };
    if masked {
        LINES_ENABLED[reg].fetch_and(!bit, Ordering::AcqRel);
    } else {
        LINES_ENABLED[reg].fetch_or(bit, Ordering::AcqRel);
    }
    if chip::core_id() == 1 {
        if masked {
            crate::arch::cortex_m::nvic_mask(irq as u16);
        } else {
            crate::arch::cortex_m::nvic_unmask(irq as u16);
        }
    } else {
        changed();
    }
}

/// Drop the binding of line `irq`, which core 1 owns: core 1 masks it and
/// gives up its ownership the next time it applies its line set. Called with
/// core 1 parked, and core 1 applies the set as it leaves the park, before
/// it runs a pass.
pub fn unbind_line(irq: u32) -> bool {
    let Some((reg, bit)) = line(irq) else {
        return false;
    };
    LINES_ENABLED[reg].fetch_and(!bit, Ordering::AcqRel);
    LINES_RELEASED[reg].fetch_or(bit, Ordering::AcqRel);
    changed();
    true
}

// ── The shared loop's platform part ──────────────────────────────────────

/// Make this core's stores visible and end the other core's wait for an
/// event: the RP2350 delivers each core's `sev` to the other.
pub fn signal() {
    crate::arch::cortex_m::dmb();
    crate::arch::cortex_m::sev();
}

/// Core 1's wait: for an event from core 0 or an interrupt of its own, and
/// no longer than [`IDLE_BOUND_US`] when no tick paces it, so the heartbeat
/// keeps moving.
fn wait() {
    if TICK_PERIOD_US.load(Ordering::Relaxed) == 0 {
        let idx = chip::SECONDARY_TIMER_ALARM_SCHEDULER;
        SECONDARY.ack(idx);
        SECONDARY.set_target_from_now(idx, IDLE_BOUND_US);
        SECONDARY.set_enabled(idx, true);
    }
    crate::arch::cortex_m::wfe();
}

fn set_tick(_core_id: usize, period_us: u32) {
    TICK_PERIOD_US.store(period_us.max(1), Ordering::Relaxed);
}

fn after_pass(_domain_id: usize, _core_id: usize, _mode: ExecMode, _passes: u32) {
    HEARTBEAT.fetch_add(1, Ordering::Relaxed);
    crate::platform::rp_step_guard::pass_ended();
    apply_if_changed();
}

/// What the RP2350 supplies to the shared domain loop. Core 1 runs the loop;
/// core 0 runs its own, over its domains, and uses the quiesce and the
/// bridges through the same seam.
pub static PLATFORM: domains::Platform = domains::Platform {
    core_id: chip::core_id,
    signal,
    wait_event: wait,
    // An interrupt taken on this core ends a wait for an event too, and so
    // does core 0's `sev`: a quiesce reaches a core waiting for its tick.
    wait_interrupt: wait,
    park,
    counter: crate::platform::rp_timer::now_us,
    us_to_ticks: |us| us,
    interrupts: |_| INTERRUPTS.load(Ordering::Relaxed),
    set_tick,
    has_core: |domain_id| domains::domain_core(domain_id) == 1 && launched(),
    after_pass,
};

/// # Safety
/// ISR vector entry — invoked by the NVIC, never directly. Core 1's wake
/// alarm: a periodic tick for a `tick` domain, a single bounded sleep
/// otherwise. The waiter re-reads what it waits for.
#[no_mangle]
pub unsafe extern "C" fn TIMER0_IRQ_2() {
    let idx = chip::SECONDARY_TIMER_ALARM_SCHEDULER;
    SECONDARY.ack(idx);
    count_interrupt();
    let period = TICK_PERIOD_US.load(Ordering::Relaxed);
    if period != 0 {
        // From the target that fired, not from the counter: the cadence
        // does not drift by the handler's latency. A period the counter has
        // already passed re-arms from the counter.
        let next = SECONDARY.target(idx).wrapping_add(period);
        let now = SECONDARY.now_raw_lo();
        if next.wrapping_sub(now) > i32::MAX as u32 {
            SECONDARY.set_target(idx, now.wrapping_add(period));
        } else {
            SECONDARY.set_target(idx, next);
        }
    } else {
        SECONDARY.set_enabled(idx, false);
    }
}

// ── A fault of the node on core 1 ────────────────────────────────────────

/// How core 1 ended: a kernel fault, or a panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeFaultKind {
    Fault,
    Panic,
}

/// What core 1 left for core 0 when it stopped itself.
#[derive(Clone, Copy, Debug)]
pub struct NodeFault {
    pub kind: NodeFaultKind,
    pub pc: u32,
    pub lr: u32,
    pub cfsr: u32,
    pub bfar: u32,
    /// The module core 1 was stepping, or the scheduler's "none".
    pub module: u32,
}

/// 0 while core 1 runs; 1 after a fault, 2 after a panic. Written last, so
/// core 0 reads a whole record.
static NODE_FAULT: AtomicU32 = AtomicU32::new(0);
/// `pc, lr, cfsr, bfar, module` of the fault.
static NODE_FAULT_RECORD: [AtomicU32; 5] = [const { AtomicU32::new(0) }; 5];
/// A word that never changes and one nobody reads: what the final park
/// watches and records into.
static NEVER: AtomicU32 = AtomicU32::new(0);
static UNREAD: AtomicU32 = AtomicU32::new(0);

/// What core 1 left when it stopped itself, if it has. Core 0 reads it at
/// every pass boundary and resets the node.
pub fn node_fault() -> Option<NodeFault> {
    let kind = match NODE_FAULT.load(Ordering::Acquire) {
        0 => return None,
        1 => NodeFaultKind::Fault,
        _ => NodeFaultKind::Panic,
    };
    let word = |i: usize| NODE_FAULT_RECORD[i].load(Ordering::Relaxed);
    Some(NodeFault {
        kind,
        pc: word(0),
        lr: word(1),
        cfsr: word(2),
        bfar: word(3),
        module: word(4),
    })
}

/// End core 1 after a kernel fault or a panic on it. Core 1 only. It gives
/// up the lock between the cores if it holds it (core 0 must be able to log
/// and reset), leaves the record for core 0, wakes it, and waits in RAM with
/// its interrupts masked for the reset: it fetches nothing from flash again,
/// so an XIP detach on core 0 meanwhile is refused rather than run under it.
pub fn stop_for_node_fault(kind: NodeFaultKind, pc: u32, lr: u32, cfsr: u32, bfar: u32) -> ! {
    // SAFETY: this core never runs kernel code again.
    unsafe { crate::arch::cortex_m::disable_interrupts() };
    let module = scheduler::current_module_id();
    for (slot, value) in NODE_FAULT_RECORD
        .iter()
        .zip([pc, lr, cfsr, bfar, u32::from(module)])
    {
        slot.store(value, Ordering::Relaxed);
    }
    crate::arch::critical_section_impl::abandon(1);
    NODE_FAULT.store(
        match kind {
            NodeFaultKind::Fault => 1,
            NodeFaultKind::Panic => 2,
        },
        Ordering::Release,
    );
    signal();
    loop {
        ram_park(&NEVER, &UNREAD, 0);
    }
}

// A fault taken on core 1 may be its stack running out, and the handler
// would then have none to work on. The handler never returns to what
// faulted, so it starts again from the top of core 1's stack: r0-r3 carry
// the fault's registers through.
core::arch::global_asm!(
    ".section .text.fluxor_rp_core1_fault, \"ax\"",
    ".global fluxor_rp_core1_fault",
    ".type fluxor_rp_core1_fault, %function",
    ".thumb_func",
    "fluxor_rp_core1_fault:",
    "    ldr r12, ={stack}",
    "    add r12, r12, #{size}",
    "    msr msp, r12",
    "    ldr r12, =fluxor_rp_core1_fault_stop",
    "    bx r12",
    ".ltorg",
    ".size fluxor_rp_core1_fault, . - fluxor_rp_core1_fault",
    ".text",
    stack = sym CORE1_STACK,
    size = const chip::SECONDARY_STACK_SIZE,
);

unsafe extern "C" {
    /// The fault handler's entry on core 1, in assembly above:
    /// `(pc, lr, cfsr, bfar)` of the fault.
    pub fn fluxor_rp_core1_fault(pc: u32, lr: u32, cfsr: u32, bfar: u32) -> !;
}

/// Where [`fluxor_rp_core1_fault`] lands, on a whole stack.
#[unsafe(no_mangle)]
extern "C" fn fluxor_rp_core1_fault_stop(pc: u32, lr: u32, cfsr: u32, bfar: u32) -> ! {
    stop_for_node_fault(NodeFaultKind::Fault, pc, lr, cfsr, bfar)
}

// ── Core 0's side: the watchdog and the XIP detach ───────────────────────

/// The heartbeat core 0 last fed the watchdog on. Core 0 only.
static FED_AT: AtomicU32 = AtomicU32::new(0);

/// Whether core 0 may feed the watchdog: core 1 runs no domain, is parked
/// for core 0, or its heartbeat has moved since the last feed. A core 1
/// wedged in a module that ignores its guard stops the feeds and the
/// watchdog resets the node.
pub fn alive() -> bool {
    if !launched() || !running() {
        return true;
    }
    // Parked for core 0, or waiting for core 0 to answer a call: core 1 is
    // as live as this core is.
    if quiesce::STRUCTURAL.parked(1) || quiesce::STEP.parked(1) || domains::waiting_on_primary(1) {
        return true;
    }
    let beat = heartbeat();
    if beat != FED_AT.load(Ordering::Relaxed) {
        FED_AT.store(beat, Ordering::Relaxed);
        return true;
    }
    false
}

/// Why core 1 could not be parked for an XIP detach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParkError {
    /// Called on core 1: only core 0 detaches XIP.
    NotPrimary,
    /// Core 1 did not reach a park point within its step's deadline.
    Timeout,
}

/// Park core 1 in RAM so core 0 can take execute-in-place away. Core 0,
/// with interrupts masked. `Ok(true)`: core 1 was parked for this and the
/// caller ends with [`release_after_xip_detach`]. `Ok(false)`: core 1 is not
/// running flash code (not launched, waiting for a graph, or already parked
/// by a quiesce core 0 holds).
///
/// The wait is bounded by the deadline of the step core 1 is in, plus a
/// millisecond: core 1 parks between steps.
pub fn park_for_xip_detach() -> Result<bool, ParkError> {
    if chip::core_id() != 0 {
        return Err(ParkError::NotPrimary);
    }
    if !launched() || !running() {
        return Ok(false);
    }
    let bound = u64::from(
        crate::platform::rp_step_guard::armed_deadline_us(1)
            .unwrap_or(chip::DEFAULT_STEP_DEADLINE_US)
            .min(scheduler::STEP_BUDGET_HARD_CAP_US),
    ) + 1_000;
    let deadline = crate::platform::rp_timer::now_us() + bound;
    let expired = || crate::platform::rp_timer::now_us() >= deadline;
    // Between `go` and its loop core 1 runs flash code no quiesce waits for.
    while !domains::in_loop(1) {
        if expired() {
            return Err(ParkError::Timeout);
        }
    }
    domains::step_quiesce(expired).map_err(|domains::NotParked| ParkError::Timeout)
}

/// Release core 1 from [`park_for_xip_detach`], once XIP is back.
pub fn release_after_xip_detach() {
    domains::release_step_quiesce();
}

/// Times core 1 has parked between steps for core 0.
pub fn xip_parks() -> u32 {
    domains::step_parks()
}
