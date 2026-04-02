//! PIO utility functions for register bridges and pin setup.
//!
//! Extracted from the old embassy PIO subsystem. These are used by the
//! PIO register bridges (0x0C70-0x0C7B) in rp_providers.rs and by
//! boot-time PIO pin configuration.

use embassy_rp::pac;
use portable_atomic::{AtomicU32, Ordering};

// ============================================================================
// Instruction Memory Management
// ============================================================================

/// Bitmap of used PIO instruction memory slots per PIO block.
pub static PIO_INSTRUCTIONS_USED: [AtomicU32; 3] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

/// Get PAC PIO instance by block index (0, 1, 2).
#[inline]
pub fn pio_pac(pio_num: u8) -> pac::pio::Pio {
    crate::kernel::chip::pio_pac(pio_num)
}

/// Allocate contiguous instruction slots in a PIO block.
///
/// Uses first-fit with atomic CAS on the shared `PIO_INSTRUCTIONS_USED` bitmap.
/// Returns `(origin, mask)` where origin is the start address and mask is the
/// allocated bits to pass to `free_instruction_slots()` later.
pub fn alloc_instruction_slots(pio_num: u8, count: usize) -> Option<(u8, u32)> {
    if count == 0 || count > 32 {
        return None;
    }

    let instructions_used = &PIO_INSTRUCTIONS_USED[pio_num as usize];
    let mut current = instructions_used.load(Ordering::Acquire);

    for start in 0..=(32 - count) {
        let mask = ((1u32 << count) - 1) << start;
        if current & mask == 0 {
            match instructions_used.compare_exchange(
                current,
                current | mask,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some((start as u8, mask)),
                Err(new_current) => current = new_current,
            }
        }
    }
    None
}

/// Free previously allocated instruction slots.
pub fn free_instruction_slots(pio_num: u8, mask: u32) {
    if mask != 0 {
        PIO_INSTRUCTIONS_USED[pio_num as usize].fetch_and(!mask, Ordering::Release);
    }
}

// ============================================================================
// Config-Driven Pin Setup (bypasses Embassy typed pins)
// ============================================================================

/// Pull resistor configuration for PIO pins.
#[derive(Clone, Copy)]
pub enum PioPull {
    /// Pull-down enabled (for CYW43 DIO/DATA2 strap during power-on).
    PullDown,
    /// Pull-up enabled (default for general data/clock pins).
    PullUp,
    /// No pull resistor (matches Embassy's Pull::None for gSPI DIO/CLK).
    None,
}

/// Configure a GPIO pin for PIO use via direct PAC register writes.
///
/// Equivalent to Embassy's `make_pio_pin` but accepts a runtime pin number.
/// FUNCSEL values: PIO0=6, PIO1=7, PIO2=8.
pub fn setup_pio_pin(pin: u8, pio_num: u8, pull: PioPull) {
    debug_assert!(pin < crate::kernel::gpio::runtime_max_gpio(), "PIO pin out of range");
    let funcsel = 6 + pio_num;
    pac::IO_BANK0.gpio(pin as usize).ctrl().write(|w| {
        w.set_funcsel(funcsel as _);
    });
    pac::PADS_BANK0.gpio(pin as usize).write(|w| {
        crate::kernel::chip::pad_set_iso_false!(w);
        w.set_schmitt(true);
        w.set_slewfast(true);
        w.set_ie(true);
        w.set_od(false);
        w.set_pue(matches!(pull, PioPull::PullUp));
        w.set_pde(matches!(pull, PioPull::PullDown));
        w.set_drive(pac::pads::vals::Drive::_12M_A);
    });
}
