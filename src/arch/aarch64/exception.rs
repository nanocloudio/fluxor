//! Exception vectors + IRQ handler — AArch64, EL1.
//!
//! The `global_asm!` block defines `exception_vectors:` (aligned to 2 KB)
//! with 16 × 128 B entries in the `VBAR_EL1` layout. The IRQ entries —
//! current EL on SP_ELx, and lower EL (an isolated module at EL0) — serve
//! the interrupt and return; the lower-EL synchronous entry is the EL0
//! isolation dispatcher's (`isolation`); every other entry fails stop:
//! it switches to the core's fault stack, latches the fault, prints it
//! and spins, because a fault in kernel code may hold a lock whose
//! abandonment would deadlock the kernel. A fail-stop entry passes its
//! slot index (`VBAR_EL1` offset / 0x80, 0–15) to [`exception_dump`] in
//! w17, so the dump names the vector it came through.
//!
//! [`irq_handler`] reads `GICC_IAR`, EOIs, then either re-arms the timer
//! tick (the platform's timer PPI) or walks `IRQ_BINDINGS` to fan out
//! through the platform's IRQ multiplexer, enter a Tier-2 module's ISR, or
//! signal a kernel event via `event_signal_from_isr`.
//!
//! What the dump can safely write to is the platform's business: it prints
//! through the sink the platform registered ([`set_dump_sink`]), which the
//! platform leaves unset until its console can take raw bytes, so an
//! early-boot fault never pokes an unmapped peripheral. The fault is also
//! stashed at a fixed address the platform names ([`set_fault_stash`]) for
//! an emulator's monitor to read. Which core is running is
//! [`super::cpu`]'s answer.

#![allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]

use core::arch::global_asm;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use super::cpu::current_core_id;
use super::gic::{self, EVENT_HANDLE_MUX, IRQ_BINDINGS, IRQ_BINDING_COUNT};
use super::timer;

/// How many cores the per-core latches cover.
pub const MAX_CORES: usize = 4;

static mut DUMP_SINK: Option<fn(&[u8])> = None;
static FAULT_STASH: AtomicUsize = AtomicUsize::new(0);
static mut STACK_GUARD_PROBE: Option<fn(u64) -> Option<usize>> = None;

/// Where `exception_dump` writes its text: raw, synchronous, usable with
/// the scheduler dead and the heap poisoned. Unset (the default) means the
/// dump is latched but not printed; the platform sets it once its console
/// hardware is initialised.
pub fn set_dump_sink(sink: fn(&[u8])) {
    // SAFETY: set at boot by the boot core before interrupts are enabled;
    // read on the exception path afterwards.
    unsafe { DUMP_SINK = Some(sink) };
}

/// A fixed RAM address where `exception_dump` stores ELR/ESR/FAR and a
/// marker (4 × u64), so an emulator's monitor can read a fault that
/// happened before any console worked. `0` disables it.
pub fn set_fault_stash(addr: usize) {
    FAULT_STASH.store(addr, Ordering::Relaxed);
}

/// How to tell whether a faulting address lies in a kernel stack's guard
/// page: the platform owns the stacks, so it answers.
pub fn set_stack_guard_probe(probe: fn(u64) -> Option<usize>) {
    // SAFETY: set at boot before interrupts are enabled; read afterwards.
    unsafe { STACK_GUARD_PROBE = Some(probe) };
}

#[inline(always)]
fn dump_sink() -> Option<fn(&[u8])> {
    // SAFETY: written once at boot, before this can run.
    unsafe { DUMP_SINK }
}

#[inline(always)]
fn stack_guard_core(addr: u64) -> Option<usize> {
    // SAFETY: written once at boot, before this can run.
    match unsafe { STACK_GUARD_PROBE } {
        Some(probe) => probe(addr),
        None => None,
    }
}

fn dump(bytes: &[u8]) {
    if let Some(sink) = dump_sink() {
        sink(bytes);
    }
}

global_asm!(
    ".section .text",
    ".balign 2048",
    ".global exception_vectors",
    "exception_vectors:",
    // Current EL with SP_EL0 (slots 0-3). The kernel always runs on SP_EL1,
    // so any of these is a kernel fault: fail stop.
    ".balign 128",
    "mov w17, #0",
    "b fluxor_el1_catch", // Synchronous
    ".balign 128",
    "mov w17, #1",
    "b fluxor_el1_catch", // IRQ
    ".balign 128",
    "mov w17, #2",
    "b fluxor_el1_catch", // FIQ
    ".balign 128",
    "mov w17, #3",
    "b fluxor_el1_catch", // SError
    // Current EL with SP_ELx (slots 4-7).
    // Synchronous: a fault in the kernel's own EL1 code — including while
    // it serves an isolated module's trap — fails stop through
    // `fluxor_el1_sync_vec` (`isolation`), never recovers: the fault may
    // hold a lock.
    ".balign 128",
    "b fluxor_el1_sync_vec", // Synchronous
    // IRQ: save the caller-saved registers (x0-x18, x29, x30) around the
    // handler. ELR/SPSR need no saving: IRQs stay masked until `eret`.
    ".balign 128",
    "sub sp, sp, #176",
    "stp x0,  x1,  [sp, #0]",
    "stp x2,  x3,  [sp, #16]",
    "stp x4,  x5,  [sp, #32]",
    "stp x6,  x7,  [sp, #48]",
    "stp x8,  x9,  [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x29, [sp, #144]",
    "str x30,      [sp, #160]",
    "bl irq_handler",
    "ldp x0,  x1,  [sp, #0]",
    "ldp x2,  x3,  [sp, #16]",
    "ldp x4,  x5,  [sp, #32]",
    "ldp x6,  x7,  [sp, #48]",
    "ldp x8,  x9,  [sp, #64]",
    "ldp x10, x11, [sp, #80]",
    "ldp x12, x13, [sp, #96]",
    "ldp x14, x15, [sp, #112]",
    "ldp x16, x17, [sp, #128]",
    "ldp x18, x29, [sp, #144]",
    "ldr x30,      [sp, #160]",
    "add sp, sp, #176",
    "eret",
    ".balign 128",
    "mov w17, #6",
    "b fluxor_el1_catch", // FIQ
    ".balign 128",
    "mov w17, #7",
    "b fluxor_el1_catch", // SError
    // Lower EL using AArch64 (slots 8-11): an isolated module at EL0.
    // Synchronous — a veneer's SVC, or an abort while the module runs —
    // goes to the EL0-isolation dispatcher (`isolation`), which serves the
    // trap or ends the call as a module fault. IRQ is served under the
    // kernel's table and may force a module past its deadline out.
    ".balign 128",
    "b fluxor_el0_lower_sync_vec", // Synchronous
    ".balign 128",
    "b fluxor_el0_lower_irq_vec", // IRQ
    ".balign 128",
    "mov w17, #10",
    "b fluxor_el1_catch", // FIQ
    ".balign 128",
    "mov w17, #11",
    "b fluxor_el1_catch", // SError
    // Lower EL using AArch32 (slots 12-15): nothing runs at AArch32 EL0.
    ".balign 128",
    "mov w17, #12",
    "b fluxor_el1_catch",
    ".balign 128",
    "mov w17, #13",
    "b fluxor_el1_catch",
    ".balign 128",
    "mov w17, #14",
    "b fluxor_el1_catch",
    ".balign 128",
    "mov w17, #15",
    "b fluxor_el1_catch",
    // The fail-stop report, entered on the core's fault stack with the
    // vector slot in w17. `.global` so `isolation`'s assembly reaches it.
    ".global unhandled_exception",
    "unhandled_exception:",
    "mrs x0, elr_el1",
    "mrs x1, esr_el1",
    "mrs x2, far_el1",
    "mov w3, w17",
    "bl exception_dump",
    // No recovery: spin, keeping the core in a diagnosable state.
    "1: b 1b",
);

/// Guard against recursive exceptions in exception_dump.
pub static EXCEPTION_DEPTH: AtomicU32 = AtomicU32::new(0);

/// Per-core fault latch. [`exception_dump`] records the faulting core's
/// syndrome and a count here so another core — the one draining the log —
/// can report a fault on a core that has stopped, where only a console on
/// that core would otherwise show it. Indexed by core id (0..MAX_CORES).
pub static CORE_FAULT_ESR: [AtomicU64; MAX_CORES] = [const { AtomicU64::new(0) }; MAX_CORES];
/// FAR_EL1 at the fault.
pub static CORE_FAULT_FAR: [AtomicU64; MAX_CORES] = [const { AtomicU64::new(0) }; MAX_CORES];
/// Faults latched on each core.
pub static CORE_FAULT_COUNT: [AtomicU32; MAX_CORES] = [const { AtomicU32::new(0) }; MAX_CORES];
/// SPSR_EL1 at the fault — M[3:0] gives the EL the fault was taken FROM
/// (0=EL0t, 4=EL1t, 5=EL1h), which disambiguates an `svc` taken at EL0 vs EL1.
pub static CORE_FAULT_SPSR: [AtomicU64; MAX_CORES] = [const { AtomicU64::new(0) }; MAX_CORES];
/// ELR_EL1 at the fault — the faulting instruction's address.
pub static CORE_FAULT_ELR: [AtomicU64; MAX_CORES] = [const { AtomicU64::new(0) }; MAX_CORES];
/// The vector slot the fault came through (`VBAR_EL1` offset / 0x80).
pub static CORE_FAULT_VECTOR: [AtomicU32; MAX_CORES] = [const { AtomicU32::new(0) }; MAX_CORES];

/// Fault counts `report_core_faults` has already logged, per core.
static CORE_FAULT_REPORTED: [AtomicU32; MAX_CORES] = [const { AtomicU32::new(0) }; MAX_CORES];

/// Log each secondary core's newly latched fault, once, from core 0 — the
/// core that owns the log drain, so the line reaches the network log even
/// though the faulting core has stopped. A fault whose address lies in a
/// kernel stack guard page is named as the stack overflow it is.
pub fn report_core_faults() {
    for c in 1..MAX_CORES {
        let n = CORE_FAULT_COUNT[c].load(Ordering::Relaxed);
        if n == CORE_FAULT_REPORTED[c].load(Ordering::Relaxed) {
            continue;
        }
        CORE_FAULT_REPORTED[c].store(n, Ordering::Relaxed);
        let far = CORE_FAULT_FAR[c].load(Ordering::Relaxed);
        let kind = match stack_guard_core(far) {
            Some(_) => "kernel-stack-overflow",
            None => "kernel",
        };
        log::error!(
            "[fault] core={} kind={} vector={} far=0x{:x} esr=0x{:x} elr=0x{:x} spsr=0x{:x}",
            c,
            kind,
            CORE_FAULT_VECTOR[c].load(Ordering::Relaxed),
            far,
            CORE_FAULT_ESR[c].load(Ordering::Relaxed),
            CORE_FAULT_ELR[c].load(Ordering::Relaxed),
            CORE_FAULT_SPSR[c].load(Ordering::Relaxed),
        );
    }
}

/// The unrecoverable-exception report: latch the fault for this core, stash
/// it, print it through the sink, and return to the spinning entry.
///
/// # Safety
/// Called from the `unhandled_exception` assembly entry with the exception
/// registers and the vector slot as arguments; writes the configured stash
/// address.
#[no_mangle]
pub unsafe extern "C" fn exception_dump(elr: u64, esr: u64, far: u64, vector: u32) {
    // Latch the fault per core BEFORE the recursion guard, so another core
    // can report it even when this core's console dump is invisible or the
    // core then hangs.
    let c = (current_core_id() as usize).min(MAX_CORES - 1);
    let spsr: u64;
    // SAFETY: reading SPSR_EL1 in the exception handler is side-effect free.
    core::arch::asm!("mrs {}, spsr_el1", out(reg) spsr, options(nomem, nostack));
    CORE_FAULT_SPSR[c].store(spsr, Ordering::Relaxed);
    CORE_FAULT_ELR[c].store(elr, Ordering::Relaxed);
    CORE_FAULT_ESR[c].store(esr, Ordering::Relaxed);
    CORE_FAULT_FAR[c].store(far, Ordering::Relaxed);
    CORE_FAULT_VECTOR[c].store(vector, Ordering::Relaxed);
    CORE_FAULT_COUNT[c].fetch_add(1, Ordering::Relaxed);

    // Prevent recursive exception storms — if we fault inside the handler,
    // just spin silently rather than faulting again.
    if EXCEPTION_DEPTH.fetch_add(1, Ordering::Relaxed) > 0 {
        return;
    }
    // Store the exception state at the platform's fixed stash address, for
    // an emulator monitor to read when no console works yet:
    // `(qemu) xp /4gx <stash>`.
    let stash = FAULT_STASH.load(Ordering::Relaxed);
    if stash != 0 {
        core::ptr::write_volatile(stash as *mut u64, elr);
        core::ptr::write_volatile((stash + 8) as *mut u64, esr);
        core::ptr::write_volatile((stash + 16) as *mut u64, far);
        core::ptr::write_volatile((stash + 24) as *mut u64, 0xDEAD_BEEF_CAFE_BABE);
    }

    // No sink yet means the console hardware is not initialised (early
    // boot): the latches above are all that can be done.
    if dump_sink().is_none() {
        return;
    }
    // The exception path writes straight to the console hardware. The log
    // ring is unusable here — the scheduler may be dead, the overlay won't
    // drain, and even the heap allocator might be poisoned. Raw MMIO is the
    // only thing we can trust.
    dump(b"\r\n!!! EXCEPTION\r\n");
    dump(b"  ELR=0x");
    exception_dump_hex64(elr);
    dump(b"\r\n  ESR=0x");
    exception_dump_hex64(esr);
    dump(b"\r\n  FAR=0x");
    exception_dump_hex64(far);
    dump(b"\r\n  vector slot ");
    exception_dump_u32(vector);
    dump(b"\r\n");
    if let Some(core) = stack_guard_core(far) {
        dump(b"  kernel stack overflow: guard page of core ");
        exception_dump_hex64(core as u64);
        dump(b"\r\n");
    }
    // Recent log tail — helps correlate the fault with whatever the
    // system logged right before it. `read_tail` does not advance the
    // SPSC tail pointer, so a concurrent drain still sees the same bytes.
    let mut buf = [0u8; 1024];
    let n = crate::kernel::sys::log_ring::read_tail(&mut buf);
    if n > 0 {
        dump(b"--- log tail (");
        exception_dump_u32(n as u32);
        dump(b" bytes) ---\r\n");
        dump(&buf[..n]);
        dump(b"\r\n--- end ---\r\n");
    }
}

/// Hex dump for the exception handler, through the raw sink — see
/// `exception_dump` for why nothing buffered is used here.
pub fn exception_dump_hex64(val: u64) {
    let hex = b"0123456789abcdef";
    let mut out = [0u8; 16];
    for (k, slot) in out.iter_mut().enumerate() {
        *slot = hex[((val >> (60 - 4 * k as u64)) & 0xf) as usize];
    }
    dump(&out);
}

/// Decimal dump for the exception handler.
fn exception_dump_u32(mut n: u32) {
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    dump(&buf[i..]);
}

/// Per-core timer period, in counter ticks: what the timer-PPI handler
/// re-arms this core's timer with on every fire, so each core (each domain
/// on multicore) paces at its own rate and no core's re-arm clobbers
/// another's. The platform seeds every slot with its default tick at boot
/// and each core's slot from its domain's tick when the core comes up; a
/// pacer may rewrite a core's slot between passes, taking effect at the
/// next fire.
pub static NEXT_DEADLINE_TICKS: [AtomicU32; MAX_CORES] = [const { AtomicU32::new(0) }; MAX_CORES];

/// Per-core timer-IRQ counts.
pub static CORE_TICKS: [AtomicU32; MAX_CORES] = [const { AtomicU32::new(0) }; MAX_CORES];

/// Per-core last interrupted PC (ELR_EL1), latched by the timer IRQ. When a
/// core's scheduler loop hangs but timer IRQs still fire, this is the PC of
/// the spinning code — map it with `rust-objdump -d` on the firmware ELF.
pub static CORE_LAST_ELR: [AtomicU64; MAX_CORES] = [const { AtomicU64::new(0) }; MAX_CORES];

/// Absolute-deadline (`cval`) re-arm. Off (the default): the timer re-arms
/// with the relative `tval` down-counter ([`timer::timer_set`]), so every
/// period also carries the IRQ-entry-to-re-arm latency and the tick grid
/// drifts against an ideal schedule. On: the handler arms an absolute
/// compare one period after the *previous* programmed deadline, so the
/// grid does not drift, with a resync guard: a deadline that fell into the
/// past during a long ISR snaps to `now + period` instead of firing a
/// catch-up burst of immediate IRQs.
///
/// Opt-in, because it changes the most timing-critical path: enable it only
/// where accumulated cross-domain skew has been measured over a long run on
/// the hardware it will run on. The platform sets it.
pub static ABSOLUTE_REARM: AtomicBool = AtomicBool::new(false);

/// Per-core last absolute deadline programmed into the timer's `cval`, in
/// counter ticks: the base the next absolute re-arm adds a period to.
/// Unused (stays 0) while [`ABSOLUTE_REARM`] is off.
pub static LAST_DEADLINE_CVAL: [AtomicU64; MAX_CORES] = [const { AtomicU64::new(0) }; MAX_CORES];

/// The IRQ entry: acknowledge, EOI, then the timer tick or the bound
/// event.
///
/// # Safety
/// Called from the IRQ vector with the caller-saved registers preserved;
/// touches the configured GIC and the binding table the boot thread built.
#[no_mangle]
pub unsafe extern "C" fn irq_handler() {
    let iar = core::ptr::read_volatile(gic::gicc_iar());
    let irq_id = iar & 0x3FF;
    // 1020-1023: nothing was pending by the time the CPU interface was
    // read (1023, spurious). Not acknowledged, so no EOI.
    if irq_id > gic::MAX_INTID {
        return;
    }
    // EOI with the whole IAR value: for an SGI it carries the source CPU.
    core::ptr::write_volatile(gic::gicc_eoir(), iar);

    if irq_id == gic::timer_ppi() {
        // Timer tick: re-arm THIS core's timer from its own period slot,
        // then count. Wall-clock time never derives from this cadence (it
        // reads the counter), so the relative re-arm's drift is harmless at
        // a fixed tick; `ABSOLUTE_REARM` removes it where the tick varies.
        // Clamp so the per-core slots stay in bounds even if a part reports
        // a higher core number than the latches cover.
        let core_id = (current_core_id() as usize).min(MAX_CORES - 1);
        let period = NEXT_DEADLINE_TICKS[core_id].load(Ordering::Relaxed);
        if ABSOLUTE_REARM.load(Ordering::Relaxed) {
            // Next deadline = previous programmed deadline + period. The
            // resync guard covers the first fire (last == 0) and a long
            // ISR: a deadline already passed snaps to now + period.
            let now = timer::read_timer_count_64();
            let mut next = LAST_DEADLINE_CVAL[core_id]
                .load(Ordering::Relaxed)
                .wrapping_add(period as u64);
            if next <= now {
                next = now.wrapping_add(period as u64);
            }
            timer::timer_set_cval(next);
            LAST_DEADLINE_CVAL[core_id].store(next, Ordering::Relaxed);
        } else {
            timer::timer_set(period);
        }
        CORE_TICKS[core_id].fetch_add(1, Ordering::Relaxed);
        // Latch the interrupted PC. If a core's scheduler loop has frozen
        // while CORE_TICKS keeps climbing, every timer IRQ interrupts the
        // spinning code at the same PC, so this names where it is stuck.
        let elr: u64;
        core::arch::asm!("mrs {}, elr_el1", out(reg) elr, options(nomem, nostack));
        CORE_LAST_ELR[core_id].store(elr, Ordering::Relaxed);
    } else {
        // Every binding for this INTID (virtio, MSI mux, Tier 2, ...).
        let n = IRQ_BINDING_COUNT;
        let mut i = 0;
        while i < n {
            let binding = &IRQ_BINDINGS[i];
            if binding.irq == irq_id {
                if binding.event_handle == crate::kernel::exec::isr_tier::ISR_TIER2_EVENT {
                    // Tier 2 (IRQ-owned) dispatch: route this hardware IRQ
                    // straight into the module's `module_isr_entry` via the
                    // trampoline, which looks the module up by IRQ number and
                    // enforces the ISR-context syscall gate.
                    let _ = crate::kernel::exec::isr_tier::isr_tier2_trampoline(irq_id as u16);
                } else if binding.event_handle == EVENT_HANDLE_MUX {
                    // The platform's multiplexer (a PCIe MSI mux: read +
                    // clear the status, fan out per-vector events, so the
                    // ISR cost is proportional to the MSIs pending).
                    if let Some(mux) = gic::irq_mux() {
                        mux();
                    }
                } else if binding.event_handle >= 0 {
                    // Acknowledge a virtio-mmio device: InterruptStatus
                    // (0x60) written back to InterruptACK (0x64).
                    if binding.mmio_base != 0 {
                        let isr =
                            core::ptr::read_volatile((binding.mmio_base + 0x60) as *const u32);
                        if isr != 0 {
                            core::ptr::write_volatile((binding.mmio_base + 0x64) as *mut u32, isr);
                        }
                    }
                    crate::kernel::ipc::event::event_signal_from_isr(binding.event_handle);
                }
            }
            i += 1;
        }
    }
}
