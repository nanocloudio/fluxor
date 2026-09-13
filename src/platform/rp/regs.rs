//! Minimal typed MMIO for the RP family.
//!
//! Deliberately not a HAL. There is no singleton per peripheral and no
//! ownership model here: Fluxor's resource plan and provider handles already
//! own exclusivity, and a second, weaker notion of it layered underneath
//! would only disagree with the first. What this provides is the narrow thing
//! a driver actually needs — volatile access at a known address, with the
//! write semantics the hardware really has.
//!
//! # Why write semantics are typed rather than commented
//!
//! RP peripherals mix three kinds of register that look identical in C and in
//! a naive `write32`:
//!
//! - plain read/write;
//! - **write-one-to-clear**, where reading, OR-ing and writing back clears
//!   every *other* pending bit that happened to be set — a read-modify-write
//!   on a W1C register is almost always a bug, and a silent one;
//! - **atomic SET/CLR/XOR aliases**, where the RP hardware itself offers
//!   `base + 0x1000/0x2000/0x3000` to set, clear or flip bits without a
//!   read-modify-write at all.
//!
//! Naming them separately is what stops the second and third being written as
//! the first. [`modify32`] exists only for genuine read/write registers and
//! says so.

/// RP atomic register-alias offsets. Writing to `base | ATOMIC_SET` sets
/// every 1 bit in the written value and leaves the rest alone, with no
/// read-modify-write and no window for an interrupt to land inside one.
pub const ATOMIC_XOR: usize = 0x1000;
pub const ATOMIC_SET: usize = 0x2000;
pub const ATOMIC_CLR: usize = 0x3000;

/// Read a 32-bit register.
///
/// # Safety
/// `addr` must be a 4-byte-aligned, mapped MMIO address owned by the caller.
#[inline(always)]
pub unsafe fn read32(addr: usize) -> u32 {
    // SAFETY: the caller asserts the address is valid MMIO it owns.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit register.
///
/// # Safety
/// As [`read32`]. For a write-one-to-clear register use [`clear_w1c`]; for a
/// bit-granular change on a register with an atomic alias use [`set_bits`] /
/// [`clear_bits`], never a read-modify-write.
#[inline(always)]
pub unsafe fn write32(addr: usize, val: u32) {
    // SAFETY: the caller asserts the address is valid MMIO it owns.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

/// Read-modify-write a plain read/write register.
///
/// # Safety
/// As [`read32`], and additionally: `addr` must NOT be write-one-to-clear.
/// On a W1C register this clears every bit that happened to be pending at the
/// moment of the read, which is a data-loss bug that presents as randomly
/// missing interrupts.
#[inline(always)]
pub unsafe fn modify32(addr: usize, f: impl FnOnce(u32) -> u32) {
    // SAFETY: the caller asserts a plain RW register it owns.
    unsafe {
        let v = read32(addr);
        write32(addr, f(v));
    }
}

/// Set bits through the hardware's atomic SET alias.
///
/// # Safety
/// `addr` must be a register whose peripheral provides the atomic aliases
/// (the RP peripherals that do, which is most of them, but *not* the Cortex-M
/// system block).
#[inline(always)]
pub unsafe fn set_bits(addr: usize, bits: u32) {
    // SAFETY: caller asserts an alias-capable register.
    unsafe { write32(addr + ATOMIC_SET, bits) }
}

/// Clear bits through the hardware's atomic CLR alias.
///
/// # Safety
/// As [`set_bits`].
#[inline(always)]
pub unsafe fn clear_bits(addr: usize, bits: u32) {
    // SAFETY: caller asserts an alias-capable register.
    unsafe { write32(addr + ATOMIC_CLR, bits) }
}

/// Acknowledge a write-one-to-clear register by writing exactly the bits to
/// clear — never a read-modify-write.
///
/// # Safety
/// `addr` must be a W1C register the caller owns.
#[inline(always)]
pub unsafe fn clear_w1c(addr: usize, bits: u32) {
    // SAFETY: caller asserts a W1C register it owns.
    unsafe { write32(addr, bits) }
}

/// Spin until `poll` reports the hardware is ready, giving up after `limit`
/// iterations.
///
/// **Bounded.** An unbounded wait on a peripheral that never
/// becomes ready is indistinguishable from a hang, and on a single-domain
/// bare-metal target it *is* one — there is no watchdog thread to notice.
/// Returns whether the condition was observed.
#[inline]
pub fn wait_until(limit: u32, mut poll: impl FnMut() -> bool) -> bool {
    for _ in 0..limit {
        if poll() {
            return true;
        }
    }
    false
}

/// Encode a value into a field at `shift` of width `width` bits, leaving the
/// rest of `reg` untouched.
///
/// Masks the value to the field width rather than trusting the caller, so an
/// over-wide value corrupts its own field instead of a neighbouring one —
/// which is the difference between a wrong baud rate and a wrong pin mux.
#[inline]
pub const fn set_field(reg: u32, shift: u32, width: u32, value: u32) -> u32 {
    let mask = field_mask(shift, width);
    (reg & !mask) | ((value << shift) & mask)
}

/// Extract the field at `shift` of width `width`.
#[inline]
pub const fn get_field(reg: u32, shift: u32, width: u32) -> u32 {
    (reg >> shift) & width_mask(width)
}

/// Mask of a field `width` bits wide, positioned at `shift`.
#[inline]
pub const fn field_mask(shift: u32, width: u32) -> u32 {
    width_mask(width) << shift
}

/// Mask of the low `width` bits. `width >= 32` yields all ones rather than
/// overflowing the shift, which is UB in debug and wraps in release.
#[inline]
pub const fn width_mask(width: u32) -> u32 {
    if width >= 32 {
        u32::MAX
    } else {
        (1u32 << width) - 1
    }
}
