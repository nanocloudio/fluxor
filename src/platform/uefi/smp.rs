// The other cores: woken by PSCI, each on its own stack above an unmapped guard
// page, under the boot core's page tables, with its own half of the interrupt
// controller and its own timer tick.
//
// They run no modules; what they prove is that they came up and keep taking
// their tick. The boot core watches each one's tick count, and a core whose
// count stops for two seconds is reported with the last PC its tick saw: a
// lockup detector that needs nothing from the stalled core, which may have
// stopped taking interrupts.

use core::sync::atomic::{AtomicU32, Ordering};

use fluxor::arch::aarch64::{cpu, exception, gic, psci, timer};

use super::acpi;

/// Cores beyond the boot core this kernel brings up.
pub const MAX_SECONDARIES: usize = 3;
const GUARD_BYTES: usize = 4096;
const STACK_BYTES: usize = 64 * 1024;
const SLAB_BYTES: usize = GUARD_BYTES + STACK_BYTES;
const START_WAIT_US: u64 = 1_000_000;
/// The lockup probe masks the first secondary's interrupts this long after it
/// comes up.
const PROBE_AFTER_US: u64 = 3_000_000;
/// A core whose tick count has not moved for this long is reported.
const STALLED_US: u64 = 2_000_000;

#[repr(C, align(4096))]
struct Slab {
    guard: [u8; GUARD_BYTES],
    stack: [u8; STACK_BYTES],
}

#[repr(C, align(4096))]
struct Slabs([Slab; MAX_SECONDARIES]);

static mut STACKS: Slabs = Slabs(
    [const {
        Slab {
            guard: [0; GUARD_BYTES],
            stack: [0; STACK_BYTES],
        }
    }; MAX_SECONDARIES],
);

/// What each secondary needs to start, indexed by its number (1-based, slot 0
/// unused): the redistributor it owns on a GICv3, its tick period.
static mut REDISTRIBUTOR: [usize; MAX_SECONDARIES + 1] = [0; MAX_SECONDARIES + 1];
static mut PERIOD_TICKS: u32 = 0;
static mut PROBE: bool = false;
/// The `CORE_TICKS` slot each secondary counts its ticks in: the core number
/// the architecture code derives from its MPIDR (`cpu::current_core_id`).
static mut TICK_SLOT: [usize; MAX_SECONDARIES + 1] = [0; MAX_SECONDARIES + 1];
static ONLINE: [AtomicU32; MAX_SECONDARIES + 1] =
    [const { AtomicU32::new(0) }; MAX_SECONDARIES + 1];

/// The guard page under each secondary's stack, for the boot page tables.
pub fn guards() -> [u64; MAX_SECONDARIES] {
    let base = core::ptr::addr_of!(STACKS) as u64;
    core::array::from_fn(|i| base + (i * SLAB_BYTES) as u64)
}

/// Which secondary's guard page `addr` is in.
pub fn guard_core(addr: u64) -> Option<usize> {
    guards()
        .iter()
        .position(|&g| addr >= g && addr < g + GUARD_BYTES as u64)
        .map(|i| i + 1)
}

/// Wake the cores the MADT lists, up to [`MAX_SECONDARIES`] of them. A core
/// is woken only if its number (`cpu::current_core_id` as it will read there)
/// is below `exception::MAX_CORES` and no core already holds it, so each has a
/// tick slot of its own. Returns `(listed, running)`.
///
/// # Safety
/// The boot core, once, after the MMU, the GIC and its own timer are up.
pub unsafe fn start(
    machine: &acpi::Machine,
    redistributor_of: impl Fn(u64) -> Option<usize>,
    period_ticks: u32,
    probe: bool,
    now_us: impl Fn() -> u64,
) -> (usize, usize) {
    let boot: u64;
    core::arch::asm!("mrs {}, mpidr_el1", out(reg) boot, options(nomem, nostack));
    let affinity = |m: u64| m & 0xFF_00FF_FFFF;
    let number = |m: u64| ((m >> cpu::core_id_shift()) & 0xFF) as usize;
    PERIOD_TICKS = period_ticks;
    PROBE = probe;
    // The boot core's slot, clamped as the tick handler clamps it.
    let mut taken = 1u64 << number(boot).min(exception::MAX_CORES - 1);
    let mut next = 1usize;
    let mut running = 1usize;
    for listed in &machine.cpus[..machine.cpu_count] {
        let slot = number(listed.mpidr);
        if affinity(listed.mpidr) == affinity(boot)
            || next > MAX_SECONDARIES
            || slot >= exception::MAX_CORES
            || taken & (1u64 << slot) != 0
        {
            continue;
        }
        if machine.gic_version >= 3 {
            match redistributor_of(listed.mpidr) {
                Some(rd) => REDISTRIBUTOR[next] = rd,
                None => continue,
            }
        }
        taken |= 1u64 << slot;
        TICK_SLOT[next] = slot;
        core::arch::asm!("dsb sy", options(nostack));
        let rc = psci::cpu_on(listed.mpidr, trampoline as usize as u64, next as u64);
        if rc == 0 {
            let until = now_us() + START_WAIT_US;
            while ONLINE[next].load(Ordering::Acquire) == 0 && now_us() < until {
                core::hint::spin_loop();
            }
            if ONLINE[next].load(Ordering::Acquire) != 0 {
                running += 1;
            }
        } else {
            log::warn!("[smp] cpu_on mpidr={:#x} refused rc={rc}", listed.mpidr);
        }
        next += 1;
    }
    (machine.cpu_count, running)
}

/// PSCI drops the core here with its MMU off and `x0` = its number, at the EL
/// the firmware hands cores over at. FP/SIMD is opened at EL2 as `_start` opens
/// it for the boot core (`CPTR_EL2.TFP`, bit 10 with `HCR_EL2.E2H` clear), and
/// the core drops to EL1 and installs the boot core's translation.
#[unsafe(naked)]
unsafe extern "C" fn trampoline() -> ! {
    core::arch::naked_asm!(
        "mov x19, x0",
        "mrs x9, CurrentEL",
        "cmp x9, #(2 << 2)",
        "b.ne 3f",
        "mrs x9, cptr_el2",
        "bic x9, x9, #(1 << 10)",
        "msr cptr_el2, x9",
        "3:",
        fluxor::drop_to_el1!("x9", "x10", "2f"),
        "2:",
        "mrs x9, sctlr_el1",
        "bic x9, x9, #(1 << 0)",
        "bic x9, x9, #(1 << 2)",
        "bic x9, x9, #(1 << 12)",
        "msr sctlr_el1, x9",
        "isb",
        "ic iallu",
        "tlbi vmalle1",
        "dsb sy",
        "isb",
        "ldr x1, ={mair}",
        "ldr x1, [x1]",
        "msr mair_el1, x1",
        "ldr x1, ={tcr}",
        "ldr x1, [x1]",
        "msr tcr_el1, x1",
        "ldr x1, ={ttbr}",
        "ldr x1, [x1]",
        "msr ttbr0_el1, x1",
        "dsb ish",
        "isb",
        "mrs x1, sctlr_el1",
        "bic x1, x1, #(1 << 1)",
        "bic x1, x1, #(1 << 19)",
        "orr x1, x1, #(1 << 0)",
        "orr x1, x1, #(1 << 2)",
        "orr x1, x1, #(1 << 12)",
        "msr sctlr_el1, x1",
        "isb",
        "mov x1, #(3 << 20)",
        "msr cpacr_el1, x1",
        "isb",
        "msr SPSel, #1",
        "isb",
        // SP: the top of this core's slab.
        "sub x1, x19, #1",
        "ldr x2, ={stacks}",
        "ldr x3, ={slab}",
        "madd x2, x1, x3, x2",
        "add sp, x2, x3",
        "adr x4, exception_vectors",
        "msr vbar_el1, x4",
        "mov x0, x19",
        "bl {entry}",
        "1: wfe",
        "b 1b",
        stacks = sym STACKS,
        slab = const SLAB_BYTES,
        entry = sym secondary_main,
        mair = sym fluxor::arch::aarch64::boot_mmu::SECONDARY_MMU_MAIR,
        tcr = sym fluxor::arch::aarch64::boot_mmu::SECONDARY_MMU_TCR,
        ttbr = sym fluxor::arch::aarch64::boot_mmu::SECONDARY_MMU_TTBR0,
    );
}

extern "C" fn secondary_main(number: u64) -> ! {
    let n = number as usize;
    // SAFETY: written by the boot core before this core was woken, published by
    // its barrier; this core's own GIC half and timer.
    unsafe {
        let rd = REDISTRIBUTOR[n];
        if rd != 0 {
            gic::init_v3_cpu(rd);
        } else {
            gic::init_secondary();
        }
        let slot = TICK_SLOT[n].min(exception::NEXT_DEADLINE_TICKS.len() - 1);
        exception::NEXT_DEADLINE_TICKS[slot].store(PERIOD_TICKS, Ordering::Relaxed);
        timer::timer_set(PERIOD_TICKS);
        core::arch::asm!("msr daifclr, #2");
    }
    ONLINE[n].store(1, Ordering::Release);
    // SAFETY: set before this core was woken.
    let probe = unsafe { PROBE } && n == 1;
    let probe_at = timer::read_timer_count_64() + PROBE_AFTER_US * timer::timer_freq() / 1_000_000;
    loop {
        // SAFETY: parks until the tick.
        unsafe { core::arch::asm!("wfi") };
        if probe && timer::read_timer_count_64() >= probe_at {
            // The deliberate lockup: interrupts off, and spin.
            // SAFETY: masks this core's interrupts only.
            unsafe { core::arch::asm!("msr daifset, #2") };
            loop {
                core::hint::spin_loop();
            }
        }
    }
}

/// The boot core's watch over the others, called from its loops. Each stall is
/// reported once; a core that moves again can be reported again.
pub struct Watch {
    seen: [u32; MAX_SECONDARIES + 1],
    moved_at_us: [u64; MAX_SECONDARIES + 1],
    reported: [bool; MAX_SECONDARIES + 1],
}

impl Watch {
    pub const fn new() -> Self {
        Watch {
            seen: [0; MAX_SECONDARIES + 1],
            moved_at_us: [0; MAX_SECONDARIES + 1],
            reported: [false; MAX_SECONDARIES + 1],
        }
    }

    pub fn check(&mut self, now_us: u64) {
        for n in 1..=MAX_SECONDARIES {
            if ONLINE[n].load(Ordering::Acquire) == 0 {
                continue;
            }
            // SAFETY: written before the core was woken.
            let slot = unsafe { TICK_SLOT[n] }.min(exception::CORE_TICKS.len() - 1);
            let ticks = exception::CORE_TICKS[slot].load(Ordering::Relaxed);
            if ticks != self.seen[n] || self.moved_at_us[n] == 0 {
                self.seen[n] = ticks;
                self.moved_at_us[n] = now_us;
                self.reported[n] = false;
                continue;
            }
            if !self.reported[n] && now_us - self.moved_at_us[n] >= STALLED_US {
                self.reported[n] = true;
                let pc = exception::CORE_LAST_ELR[slot].load(Ordering::Relaxed);
                log::error!(
                    "[lockup] core={n} ticks={ticks} stalled_ms={} last_tick_pc={pc:#x}",
                    (now_us - self.moved_at_us[n]) / 1000
                );
            }
        }
    }
}
