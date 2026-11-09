//! The FP/SIMD frame around module code run in interrupt context.
//!
//! An AArch64 interrupt lands between any two instructions, so every vector
//! register, FPSR and FPCR may hold a live value of the code it interrupted.
//! The EL1 IRQ vector saves general registers only, and the kernel's own IRQ
//! path is kept free of vector instructions (`fluxor ci` phase
//! `irq-neon-free`). Module code is compiled `+neon` and is entitled by
//! AAPCS64 to change v0–v7, v16–v31, the upper halves of v8–v15 and FPSR, so
//! a call into a module from an IRQ goes through [`call_isr_entry`], which
//! keeps all of q0–q31, FPSR and FPCR across it.
//!
//! Every register is kept, v8–v15 included: the callee keeps only d8–d15,
//! the low halves, and restoring a `d` register zeroes the upper half of its
//! `v` register.
//!
//! Cost per call: 544 bytes of stack, 18 paired stores and 18 paired loads,
//! and two system-register reads and two writes.

/// A module's `module_isr_entry`.
pub type IsrEntry = unsafe extern "C" fn(state: *mut u8) -> i32;

// Frame, from sp: x29/x30 at 0, FPSR/FPCR at 16, q0–q31 at 32..544.
core::arch::global_asm!(
    ".text",
    ".balign 4",
    ".global fluxor_tier2_isr_frame",
    ".type fluxor_tier2_isr_frame, %function",
    "fluxor_tier2_isr_frame:",
    "sub sp, sp, #544",
    "stp x29, x30, [sp, #0]",
    "mov x29, sp",
    "mrs x9, fpsr",
    "mrs x10, fpcr",
    "stp x9, x10, [sp, #16]",
    "stp q0,  q1,  [sp, #32]",
    "stp q2,  q3,  [sp, #64]",
    "stp q4,  q5,  [sp, #96]",
    "stp q6,  q7,  [sp, #128]",
    "stp q8,  q9,  [sp, #160]",
    "stp q10, q11, [sp, #192]",
    "stp q12, q13, [sp, #224]",
    "stp q14, q15, [sp, #256]",
    "stp q16, q17, [sp, #288]",
    "stp q18, q19, [sp, #320]",
    "stp q20, q21, [sp, #352]",
    "stp q22, q23, [sp, #384]",
    "stp q24, q25, [sp, #416]",
    "stp q26, q27, [sp, #448]",
    "stp q28, q29, [sp, #480]",
    "stp q30, q31, [sp, #512]",
    "mov x9, x0",
    "mov x0, x1",
    "blr x9",
    "ldp q0,  q1,  [sp, #32]",
    "ldp q2,  q3,  [sp, #64]",
    "ldp q4,  q5,  [sp, #96]",
    "ldp q6,  q7,  [sp, #128]",
    "ldp q8,  q9,  [sp, #160]",
    "ldp q10, q11, [sp, #192]",
    "ldp q12, q13, [sp, #224]",
    "ldp q14, q15, [sp, #256]",
    "ldp q16, q17, [sp, #288]",
    "ldp q18, q19, [sp, #320]",
    "ldp q20, q21, [sp, #352]",
    "ldp q22, q23, [sp, #384]",
    "ldp q24, q25, [sp, #416]",
    "ldp q26, q27, [sp, #448]",
    "ldp q28, q29, [sp, #480]",
    "ldp q30, q31, [sp, #512]",
    "ldp x9, x10, [sp, #16]",
    "msr fpsr, x9",
    "msr fpcr, x10",
    "ldp x29, x30, [sp, #0]",
    "add sp, sp, #544",
    "ret",
    ".size fluxor_tier2_isr_frame, . - fluxor_tier2_isr_frame",
);

extern "C" {
    fn fluxor_tier2_isr_frame(entry: IsrEntry, state: *mut u8) -> i32;
}

/// Call a module's `module_isr_entry` with the interrupted context's
/// FP/SIMD state kept across it.
///
/// # Safety
/// `entry` and `state` are a registered Tier-2 module's entry and state,
/// valid for the duration of the call.
#[inline(always)]
pub unsafe fn call_isr_entry(entry: IsrEntry, state: *mut u8) -> i32 {
    fluxor_tier2_isr_frame(entry, state)
}
