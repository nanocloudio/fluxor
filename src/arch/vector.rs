//! The Cortex-M vector table and reset path.
//!
//! The table the core reads
//! at reset, and the `.data`/`.bss` initialisation that must happen before
//! any Rust code can safely run.
//!
//! # Why this is the riskiest thing in the platform
//!
//! Everything else in this tree fails somewhere a diagnostic can reach. This
//! fails before the first line of our code executes, so none of the logging,
//! fault recording or clock verification built for this platform applies. A
//! wrong entry here is a board that does nothing, with nothing to read.
//!
//! Two rules the hardware enforces and will not explain:
//!
//! - **Entry 0 is the initial stack pointer, not code.** The core loads it
//!   into SP before fetching anything. It must be 8-byte aligned; AAPCS
//!   requires that at every public interface and the exception entry sequence
//!   assumes it.
//! - **Entry 1 is the reset handler, and its address must have bit 0 set.**
//!   That bit selects Thumb state. Cortex-M has no ARM state to fall back to,
//!   so a cleared bit is an immediate UsageFault at reset — before the
//!   handler that would report it is reachable.
//!
//! # ARMv6-M against ARMv8-M
//!
//! The first sixteen entries are system exceptions in both, but ARMv6-M does
//! not implement MemManage, BusFault, UsageFault or SecureFault: those slots
//! are reserved and must read as zero. Filling them with handlers on RP2040
//! does not fault — the entries are simply never taken — but it hides the
//! fact that the faults they name escalate to HardFault there, which changes
//! how a crash must be diagnosed.

/// Index of each system exception in the vector table.
///
/// Named rather than spelled as numbers at the point of use: the table is an
/// array of function pointers where every entry has the same type, so a
/// handler in the wrong slot is not a type error. It is a fault handler that
/// never runs, or a timer interrupt dispatched to the supervisor call.
pub mod index {
    /// Initial stack pointer. Not a handler.
    pub const INITIAL_SP: usize = 0;
    /// Reset.
    pub const RESET: usize = 1;
    /// Non-maskable interrupt.
    pub const NMI: usize = 2;
    /// Hard fault.
    pub const HARD_FAULT: usize = 3;
    /// Memory management fault. **ARMv8-M only**; reserved on ARMv6-M.
    pub const MEM_MANAGE: usize = 4;
    /// Bus fault. ARMv8-M only.
    pub const BUS_FAULT: usize = 5;
    /// Usage fault. ARMv8-M only.
    pub const USAGE_FAULT: usize = 6;
    /// Secure fault. ARMv8-M only.
    pub const SECURE_FAULT: usize = 7;
    /// Supervisor call.
    pub const SVCALL: usize = 11;
    /// Debug monitor. ARMv8-M only.
    pub const DEBUG_MONITOR: usize = 12;
    /// Pendable service call.
    pub const PENDSV: usize = 14;
    /// System tick.
    pub const SYSTICK: usize = 15;
    /// The first external interrupt. Everything above this is a peripheral.
    pub const FIRST_IRQ: usize = 16;
}

/// Whether a slot is implemented on this architecture.
///
/// ARMv6-M reserves the four configurable-fault slots and the debug monitor.
/// Placing a handler in one is not an error the toolchain reports; it is a
/// handler that can never run, and — worse — a claim in the source that the
/// fault is handled separately when in fact it escalates to HardFault.
#[inline]
pub const fn slot_is_implemented(slot: usize) -> bool {
    #[cfg(armv6m)]
    {
        !matches!(
            slot,
            index::MEM_MANAGE
                | index::BUS_FAULT
                | index::USAGE_FAULT
                | index::SECURE_FAULT
                | index::DEBUG_MONITOR
        )
    }
    #[cfg(not(armv6m))]
    {
        let _ = slot;
        true
    }
}

/// Alignment the initial stack pointer must satisfy.
///
/// AAPCS requires 8-byte alignment at every public interface, and the
/// exception entry sequence assumes it when stacking registers. A misaligned
/// SP does not fault at reset; it produces misaligned accesses later, in
/// whatever code first stacks a doubleword.
pub const STACK_ALIGN: usize = 8;

/// Whether an initial stack pointer is usable.
///
/// Checked rather than assumed because the value comes from a linker script,
/// where it is the end of a region whose size is written by hand.
#[inline]
pub const fn stack_pointer_is_valid(sp: u32, ram_start: u32, ram_end: u32) -> bool {
    // The stack grows downwards from this address, so it may sit exactly at
    // the end of RAM — that is the normal arrangement, not an overflow.
    (sp as usize).is_multiple_of(STACK_ALIGN) && sp > ram_start && sp <= ram_end
}

/// Whether a vector-table entry is a valid Thumb function address.
///
/// Bit 0 selects Thumb state. Cortex-M implements no other state, so a
/// cleared bit is a UsageFault the moment the entry is taken — and for the
/// reset vector that is before any handler exists to report it.
#[inline]
pub const fn is_thumb_address(addr: u32) -> bool {
    addr & 1 == 1
}

/// Copy `.data` from its load address in flash to its run address in RAM, and
/// zero `.bss`.
///
/// Must run before any Rust code that touches a static. Both regions are
/// described by linker-provided symbols, so the bounds are the linker
/// script's word and are checked here rather than trusted:
///
/// - a `.data` region whose source and destination lengths disagree would
///   copy the wrong amount;
/// - an end below its start is a linker script that placed sections out of
///   order, which silently produces a gigantic length.
///
/// Returns whether the regions were well-formed. A caller that gets `false`
/// must not continue into Rust code: uninitialised statics are not a degraded
/// start, they are arbitrary behaviour.
///
/// # Safety
/// The four addresses must be the linker's own symbols for these regions, and
/// this must run exactly once, before anything reads a static.
#[inline]
pub unsafe fn init_memory(
    data_start: *mut u32,
    data_end: *mut u32,
    data_load: *const u32,
    bss_start: *mut u32,
    bss_end: *mut u32,
) -> bool {
    if data_end < data_start || bss_end < bss_start {
        return false;
    }

    // SAFETY: the caller's contract — these are the linker's own region
    // bounds, and the ordering checks above rule out a negative length.
    unsafe {
        let data_words = data_end.offset_from(data_start) as usize;
        for i in 0..data_words {
            core::ptr::write_volatile(data_start.add(i), core::ptr::read(data_load.add(i)));
        }

        let bss_words = bss_end.offset_from(bss_start) as usize;
        for i in 0..bss_words {
            core::ptr::write_volatile(bss_start.add(i), 0);
        }
    }
    true
}
