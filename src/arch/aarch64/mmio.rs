//! Device register access in the one instruction form a hypervisor can emulate.
//!
//! A trapped access reaches the hypervisor with the faulting instruction decoded
//! in its syndrome only if that instruction is a plain load or store: a
//! writeback or pair form carries none, and Nitro answers it with an external
//! abort. `read_volatile`/`write_volatile` leave the form to the compiler, which
//! folds address arithmetic into `str w, [x, #imm]!` when it can, and no emulator
//! objects, so the fault first shows on the cloud machine. Every register a
//! hypervisor may emulate (the GIC, a console UART, PCI configuration space) goes
//! through these instead.

/// # Safety
/// `addr` is a mapped device register of this width.
#[inline(always)]
pub unsafe fn read8(addr: usize) -> u8 {
    let v: u32;
    core::arch::asm!("ldrb {v:w}, [{a}]", v = out(reg) v, a = in(reg) addr, options(nostack, preserves_flags));
    v as u8
}

/// # Safety
/// As [`read8`].
#[inline(always)]
pub unsafe fn read16(addr: usize) -> u16 {
    let v: u32;
    core::arch::asm!("ldrh {v:w}, [{a}]", v = out(reg) v, a = in(reg) addr, options(nostack, preserves_flags));
    v as u16
}

/// # Safety
/// As [`read8`].
#[inline(always)]
pub unsafe fn read32(addr: usize) -> u32 {
    let v: u32;
    core::arch::asm!("ldr {v:w}, [{a}]", v = out(reg) v, a = in(reg) addr, options(nostack, preserves_flags));
    v
}

/// # Safety
/// As [`read8`].
#[inline(always)]
pub unsafe fn read64(addr: usize) -> u64 {
    let v: u64;
    core::arch::asm!("ldr {v}, [{a}]", v = out(reg) v, a = in(reg) addr, options(nostack, preserves_flags));
    v
}

/// # Safety
/// As [`read8`].
#[inline(always)]
pub unsafe fn write8(addr: usize, value: u8) {
    core::arch::asm!("strb {v:w}, [{a}]", v = in(reg) u32::from(value), a = in(reg) addr, options(nostack, preserves_flags));
}

/// # Safety
/// As [`read8`].
#[inline(always)]
pub unsafe fn write16(addr: usize, value: u16) {
    core::arch::asm!("strh {v:w}, [{a}]", v = in(reg) u32::from(value), a = in(reg) addr, options(nostack, preserves_flags));
}

/// # Safety
/// As [`read8`].
#[inline(always)]
pub unsafe fn write32(addr: usize, value: u32) {
    core::arch::asm!("str {v:w}, [{a}]", v = in(reg) value, a = in(reg) addr, options(nostack, preserves_flags));
}

/// # Safety
/// As [`read8`].
#[inline(always)]
pub unsafe fn write64(addr: usize, value: u64) {
    core::arch::asm!("str {v}, [{a}]", v = in(reg) value, a = in(reg) addr, options(nostack, preserves_flags));
}
