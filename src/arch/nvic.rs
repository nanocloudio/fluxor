//! NVIC addressing arithmetic — architecture-independent, and the part of
//! interrupt handling that can be wrong without any hardware present.
//!
//! Kept separate from [`super::cortex_m`] because that module is ARM-only
//! (it is `core::arch::asm!` throughout) and so is never compiled by a host
//! `cargo test`. An off-by-one here writes to a register outside the
//! architected NVIC block — precisely the failure that deserves a test, and
//! precisely the test that would never have run had it lived next to the asm.
//!
//! Its tests live in `tests/harness/tests/arch_nvic.rs`, per the project's
//! test-layout policy: production `src/` carries no inline tests.

/// Interrupt Set-Enable Registers, 32 interrupts per register.
pub const NVIC_ISER: usize = 0xE000_E100;
/// Interrupt Clear-Enable Registers.
pub const NVIC_ICER: usize = 0xE000_E180;

/// Split an IRQ number into `(register index, bit mask)` for an NVIC with
/// `registers` architected ISER/ICER pairs, or `None` when the number is
/// outside that window.
///
/// ARMv6-M defines exactly one pair (32 interrupts); ARMv8-M defines up to
/// sixteen. Passing the count in rather than reading a `cfg` is what makes
/// both shapes testable from a host build.
#[inline]
pub const fn slot(irq: u16, registers: u16) -> Option<(usize, u32)> {
    let reg = irq / 32;
    if reg >= registers {
        return None;
    }
    Some((reg as usize, 1u32 << (irq % 32)))
}
