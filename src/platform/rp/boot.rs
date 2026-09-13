//! Fluxor's reset vector and vector table.
//!
//! # This runs before anything else, including anything that could report it
//!
//! Nothing in this file can log. The log ring is in `.bss`, which this code is
//! responsible for zeroing; the clock tree is not up, so the UART cannot be
//! configured; and the fault handlers this table installs are not reachable
//! until the table is installed. A mistake here is a board that does nothing.
//!
//! That is why the arithmetic lives in [`crate::arch::vector`] where it is
//! tested, why the layout is checked in the built image by
//! `tools/img/verify_boot_image.py`, and why this file contains as little
//! decision-making as possible — it is a sequence, not a policy.

#[cfg(feature = "rp")]
use crate::arch::vector;

#[cfg(feature = "rp")]
unsafe extern "C" {
    /// `.data`'s run address, from the linker script.
    static mut __sdata: u32;
    /// One past `.data`'s end.
    static mut __edata: u32;
    /// `.data`'s load address in flash.
    static __sidata: u32;
    /// `.bss`'s start.
    static mut __sbss: u32;
    /// One past `.bss`'s end.
    static mut __ebss: u32;
    /// The top of the stack, which the linker places at the end of RAM.
    static __stack_top: u32;
}

/// RP2040's second-stage bootloader.
///
/// The bootrom copies these 256 bytes to RAM, checksums them, and runs them
/// to configure the QSPI flash for execute-in-place. Without it the chip
/// never reaches the vector table — and the failure is silent, because
/// nothing of ours has run to report it.
///
/// `w25q080` is the part the Pico family fits. The blob carries the
/// bootrom's own checksum, which `tools/img/verify_boot_image.py` recomputes
/// on every build; a wrong blob or a wrong part is caught there rather than
/// by a board that does nothing.
///
/// RP2350 has no equivalent: its bootrom reads the IMAGE_DEF instead.
#[cfg(all(feature = "rp", feature = "chip-rp2040"))]
#[unsafe(link_section = ".boot2")]
#[used]
#[no_mangle]
pub static BOOT2: [u8; 256] = rp2040_boot2::BOOT_LOADER_W25Q080;

/// The reset handler.
///
/// # Safety
/// Called by the hardware with an uninitialised world. Must not be called
/// from Rust.
///
/// # What the order buys
///
/// `.data` and `.bss` come first because every static in the kernel is in one
/// of them, and a static read before this point holds whatever the previous
/// boot left — which on a warm reset is plausible data rather than obvious
/// rubbish, so the failure looks like corruption rather than uninitialised
/// memory.
#[cfg(feature = "rp")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Reset() -> ! {
    // SAFETY: the linker's own region symbols, and this runs once, before
    // anything reads a static.
    let initialised = unsafe {
        vector::init_memory(
            &raw mut __sdata,
            &raw mut __edata,
            &raw const __sidata,
            &raw mut __sbss,
            &raw mut __ebss,
        )
    };
    if !initialised {
        // The linker script placed sections out of order. There is nothing to
        // report it with and nothing safe to continue into: uninitialised
        // statics are not a degraded start, they are arbitrary behaviour.
        loop {
            crate::arch::cortex_m::nop();
        }
    }

    unsafe extern "C" {
        fn fluxor_rp_main() -> !;
    }
    // SAFETY: statics are live; this is the kernel entry.
    unsafe { fluxor_rp_main() }
}

/// A system exception that should never be taken.
///
/// Parks rather than returning. Returning from an unexpected exception
/// resumes the faulting instruction, which faults again — a loop that is
/// indistinguishable from a hang but burns power and hides the cause.
///
/// # Safety
/// Installed in the vector table; never called from Rust.
#[cfg(feature = "rp")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DefaultExceptionHandler() -> ! {
    loop {
        crate::arch::cortex_m::nop();
    }
}

// The fault entry: capture the exception frame's address before any
// prologue can move the stack, then hand it to Rust. A plain function
// cannot do this — the compiler is free to push registers first, and then
// `msp` no longer points at the frame the core stacked. `ldr`/`bx` rather
// than `b` because a Thumb `b` on ARMv6-M reaches only ±2 KiB.
#[cfg(feature = "rp")]
core::arch::global_asm!(
    ".section .text.FaultTrampoline, \"ax\"",
    ".global FaultTrampoline",
    ".type FaultTrampoline, %function",
    ".thumb_func",
    "FaultTrampoline:",
    "    mrs r0, msp",
    "    ldr r1, =fluxor_fault_report",
    "    bx r1",
    ".ltorg",
);

#[cfg(feature = "rp")]
unsafe extern "C" {
    /// The fault entry, in assembly above.
    fn FaultTrampoline() -> !;
    /// Where a fault goes once decoded. Defined by the runtime, which owns
    /// the console the report has to reach; this file cannot log.
    fn fluxor_fault_park(pc: u32, lr: u32, cfsr: u32, hfsr: u32, bfar: u32) -> !;
}

/// Decode a fault from its stacked frame and the fault status registers.
///
/// `frame` is the exception frame the core pushed: r0-r3, r12, lr, pc, xpsr.
///
/// # Safety
///
/// Called only from [`FaultTrampoline`], with `frame` equal to the `msp`
/// the core left pointing at the exception frame it stacked. Any other
/// caller passes a pointer that is not a frame, and the eight words read
/// through it are whatever happened to be there.
/// The status registers exist on ARMv7-M and later only; on ARMv6-M every
/// fault is a HardFault with no further detail, and reading the absent
/// registers would itself fault — inside the fault handler, which locks the
/// core up rather than reporting anything.
#[cfg(feature = "rp")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fluxor_fault_report(frame: *const u32) -> ! {
    const SCB_CFSR: usize = 0xE000_ED28;
    const SCB_HFSR: usize = 0xE000_ED2C;
    const SCB_BFAR: usize = 0xE000_ED38;

    // SAFETY: the frame pointer is what the core pushed for this exception
    // (see the function's contract); words 5 and 6 are lr and pc.
    let (lr, pc) = unsafe {
        (
            core::ptr::read_volatile(frame.add(5)),
            core::ptr::read_volatile(frame.add(6)),
        )
    };

    let (cfsr, hfsr, bfar) = if vector::slot_is_implemented(vector::index::BUS_FAULT) {
        // SAFETY: architecturally fixed SCB addresses, present on this core.
        unsafe {
            (
                core::ptr::read_volatile(SCB_CFSR as *const u32),
                core::ptr::read_volatile(SCB_HFSR as *const u32),
                core::ptr::read_volatile(SCB_BFAR as *const u32),
            )
        }
    } else {
        (0, 0, 0)
    };

    // SAFETY: the runtime defines it; the linker enforces that.
    unsafe { fluxor_fault_park(pc, lr, cfsr, hfsr, bfar) }
}

/// One entry in the vector table: either a handler or an absent slot.
///
/// A union rather than a raw `u32` so entry 0 (the stack pointer, which is
/// data) and entries 1.. (handlers, which are code) cannot be mixed up by
/// type. They have different meanings and the same representation, which is
/// exactly the situation a newtype exists for.
#[cfg(feature = "rp")]
#[repr(C)]
#[derive(Clone, Copy)]
pub union Vector {
    /// A handler address, with its Thumb bit set by the linker.
    handler: unsafe extern "C" fn() -> !,
    /// A slot this architecture does not implement. Reads as zero, which is
    /// what the architecture requires of a reserved slot.
    reserved: u32,
    /// An interrupt service routine. Same representation as `handler`; the
    /// type differs because an ISR returns and a system-exception handler
    /// here does not, and writing one as the other hides that.
    isr: unsafe extern "C" fn(),
}

#[cfg(feature = "rp")]
impl Vector {
    const fn reserved() -> Self {
        Self { reserved: 0 }
    }
    const fn handler(f: unsafe extern "C" fn() -> !) -> Self {
        Self { handler: f }
    }
    /// An interrupt service routine, which returns — unlike the system
    /// exception handlers above, which park. Same representation; the
    /// distinction is only in what the code behind it is allowed to do.
    const fn isr(f: unsafe extern "C" fn()) -> Self {
        Self { isr: f }
    }
}

/// The system-exception half of the vector table.
///
/// Entry 0 (the initial stack pointer) and entry 1 (reset) are emitted by the
/// linker script rather than here, because the stack top is a linker symbol
/// and the reset handler's address needs its Thumb bit set — both are things
/// the linker knows and Rust does not.
///
/// The reserved slots are reserved on **ARMv6-M**: RP2040 has no MemManage,
/// BusFault, UsageFault, SecureFault or DebugMonitor, and those faults
/// escalate to HardFault instead. Putting a handler there would be a claim in
/// the source that is false on that chip.
#[cfg(feature = "rp")]
#[unsafe(link_section = ".vector_table.exceptions")]
#[used]
#[no_mangle]
pub static EXCEPTIONS: [Vector; 14] = [
    Vector::handler(DefaultExceptionHandler),     // 2 NMI
    Vector::handler(FaultTrampoline),             // 3 HardFault
    exception_slot(vector::index::MEM_MANAGE),    // 4
    exception_slot(vector::index::BUS_FAULT),     // 5
    exception_slot(vector::index::USAGE_FAULT),   // 6
    exception_slot(vector::index::SECURE_FAULT),  // 7
    Vector::reserved(),                           // 8
    Vector::reserved(),                           // 9
    Vector::reserved(),                           // 10
    Vector::handler(DefaultExceptionHandler),     // 11 SVCall
    exception_slot(vector::index::DEBUG_MONITOR), // 12
    Vector::reserved(),                           // 13
    Vector::handler(DefaultExceptionHandler),     // 14 PendSV
    Vector::handler(DefaultExceptionHandler),     // 15 SysTick
];

/// A handler where the architecture implements the slot, zero where it does
/// not — so one table serves both chips without a `cfg` per entry.
#[cfg(feature = "rp")]
const fn exception_slot(slot: usize) -> Vector {
    if vector::slot_is_implemented(slot) {
        Vector::handler(FaultTrampoline)
    } else {
        Vector::reserved()
    }
}

/// Any external interrupt without a handler of its own.
///
/// Routes to the Tier 2 trampoline by IRQ number, which is what
/// `irq_bind` promises a Tier 2 module. `isr_tier2_trampoline` returns -1
/// when no module owns the line; left pending, such an interrupt would
/// re-fire for ever, so the line is masked. A module that owns the IRQ
/// clears its own peripheral source inside `module_isr_entry`.
///
/// The IRQ number is read from `ICSR.VECTACTIVE`, which the core sets to
/// the exception number being serviced: external interrupts start at 16.
///
/// # Safety
///
/// Only the vector table may call this, from exception context: it reads
/// `ICSR` to learn which line it is servicing, which is meaningless anywhere
/// else.
#[cfg(feature = "rp")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DefaultInterruptHandler() {
    const SCB_ICSR: usize = 0xE000_ED04;
    // SAFETY: an architecturally fixed SCB register; a plain read.
    let active = unsafe { core::ptr::read_volatile(SCB_ICSR as *const u32) } & 0x1ff;
    if active >= 16 {
        let irq = (active - 16) as u16;
        if crate::kernel::exec::isr_tier::isr_tier2_trampoline(irq) < 0 {
            crate::arch::cortex_m::nvic_mask(irq);
        }
    }
}

/// The external-interrupt half of the vector table.
///
/// **A short table is not a small table.** The NVIC indexes this array by
/// IRQ number with no bound of its own, and `.start_block` — the IMAGE_DEF —
/// is linked immediately after it. An IRQ with no entry therefore reads
/// `0xffffded3` as its handler address and branches there, faulting before
/// any handler exists to report it, and the table is reached: the timer
/// alarms below are unmasked by `timer::init_scheduler_alarm` and
/// `step_guard::init`, so the table has to be at least as long as the NVIC
/// is wide. `IRQ_COUNT` is that width, declared per silicon.
///
/// Everything not named is [`DefaultInterruptHandler`], which hands the IRQ
/// to the Tier 2 dispatcher and masks any line no module owns.
#[cfg(feature = "rp")]
#[unsafe(link_section = ".vector_table.interrupts")]
#[used]
#[no_mangle]
pub static __INTERRUPTS: [Vector; crate::platform::chip::IRQ_COUNT] = interrupt_table();

#[cfg(feature = "rp")]
const fn interrupt_table() -> [Vector; crate::platform::chip::IRQ_COUNT] {
    use crate::platform::chip::{TIMER_IRQ_SCHEDULER, TIMER_IRQ_STEP_GUARD, TIMER_IRQ_TIER1B};

    let mut t = [Vector::isr(DefaultInterruptHandler); crate::platform::chip::IRQ_COUNT];

    // The three timer alarms this kernel owns. Their IRQ numbers are
    // generated from the silicon TOML rather than written here, because they
    // differ between the chips — and so do the handler names, which is why
    // each is selected by cfg rather than by a shared alias.
    #[cfg(not(feature = "chip-rp2040"))]
    {
        t[TIMER_IRQ_STEP_GUARD as usize] =
            Vector::isr(crate::platform::rp_step_guard::TIMER1_IRQ_0);
        t[TIMER_IRQ_TIER1B as usize] = Vector::isr(crate::platform::rp_step_guard::TIMER1_IRQ_1);
        t[TIMER_IRQ_SCHEDULER as usize] = Vector::isr(crate::platform::rp_timer::TIMER1_IRQ_2);
    }
    #[cfg(feature = "chip-rp2040")]
    {
        t[TIMER_IRQ_STEP_GUARD as usize] = Vector::isr(crate::platform::rp_step_guard::TIMER_IRQ_3);
        t[TIMER_IRQ_TIER1B as usize] = Vector::isr(crate::platform::rp_step_guard::TIMER_IRQ_2);
        t[TIMER_IRQ_SCHEDULER as usize] = Vector::isr(crate::platform::rp_timer::TIMER_IRQ_1);
    }

    t
}
