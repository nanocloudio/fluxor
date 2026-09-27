//! Liveness watchdog: a wedged RP board falls back to BOOTSEL.
//!
//! A module that never returns, stepped privileged, stops the main loop —
//! and the main loop is what services USB, so the board stops enumerating and
//! nothing on the host can reach it again: no console, no reset interface, no
//! picotool. The watchdog closes that hole. The main loop feeds it; if it
//! starves, the chip resets, and the next boot, finding a watchdog reset the
//! kernel armed, enters BOOTSEL instead of running the same image into the
//! same wedge, so picotool can reflash the board unattended.
//!
//! Only a reset this kernel's own watchdog caused counts: a marker in a
//! watchdog scratch register is written when it arms and cleared on every
//! deliberate reboot, so a picotool reboot or a BOOTSEL round trip is never
//! mistaken for a wedge.

use crate::platform::chip::{PSM_WDSEL, PSM_WDSEL_MASK, WATCHDOG_CTRL};
use crate::platform::rp_regs::{read32, write32};

const CTRL: usize = WATCHDOG_CTRL as usize;
const LOAD: usize = WATCHDOG_CTRL as usize + 0x04;
const REASON: usize = WATCHDOG_CTRL as usize + 0x08;
const SCRATCH0: usize = WATCHDOG_CTRL as usize + 0x0C;
/// Where the boot has got to (a [`stage`] code, low half), and the stage the
/// last wedged boot died in (high half). Watchdog scratch registers survive
/// a watchdog reset and the BOOTSEL round trip that follows, so the next
/// boot can say where its predecessor hung — which no log can, since a
/// wedge before the main loop never pumps USB and the log ring does not
/// survive the reset. One register holds both: the RP2350 bootrom's reboot
/// writes scratch 2 and 3.
const SCRATCH1: usize = WATCHDOG_CTRL as usize + 0x10;

const ENABLE: u32 = 1 << 30;
/// Hold the countdown while a debugger has the cores halted.
const PAUSE_DEBUG: u32 = (1 << 26) | (1 << 25) | (1 << 24);
/// REASON.TIMER: the last reset was the watchdog counting out.
const REASON_TIMER: u32 = 1 << 0;
/// "FLXW": the kernel's liveness watchdog was armed.
const MARKER: u32 = 0x464C_5857;

/// How long the main loop may go without feeding before the board is
/// declared wedged. Far above any legitimate step (the step guard bounds
/// those in milliseconds) and short enough that a wedged rig recovers
/// quickly.
pub const TIMEOUT_US: u32 = 4_000_000;

/// Counter ticks per microsecond of timeout: RP2040's watchdog decrements
/// twice per tick (erratum RP2040-E1), RP2350's once.
#[cfg(feature = "chip-rp2040")]
const TICKS_PER_US: u32 = 2;
#[cfg(not(feature = "chip-rp2040"))]
const TICKS_PER_US: u32 = 1;

/// Boot stages recorded in the breadcrumb.
pub mod stage {
    pub const CLOCKS: u32 = 1;
    pub const USB: u32 = 2;
    /// Building the graph; the low byte is the module being instantiated.
    pub const GRAPH: u32 = 0x100;
    pub const MAIN_LOOP: u32 = 3;
}

/// Record where the boot has got to.
#[inline]
pub fn breadcrumb(stage: u32) {
    // SAFETY: a scratch register nothing else uses; single boot thread.
    unsafe {
        write32(
            SCRATCH1,
            (read32(SCRATCH1) & 0xFFFF_0000) | (stage & 0xFFFF),
        )
    };
}

/// The stage the last wedged boot died in, if one did. Kept across boots
/// until someone has read the report ([`wedge_reported`]): a boot nobody
/// watches — a rig deploys and then power-cycles — must not consume it.
pub fn last_wedge() -> Option<u32> {
    // SAFETY: as `breadcrumb`.
    let s = unsafe { read32(SCRATCH1) } >> 16;
    (s != 0).then_some(s)
}

/// A host has the console open and is reading the boot's report: forget the
/// wedge.
pub fn wedge_reported() {
    // SAFETY: as `breadcrumb`.
    unsafe { write32(SCRATCH1, read32(SCRATCH1) & 0xFFFF) };
}

/// At boot, before anything else: if the last reset was this kernel's
/// watchdog, enter BOOTSEL. Returns only when it was not.
pub fn recover_from_wedge() {
    // SAFETY: fixed watchdog registers generated from the silicon TOML;
    // single boot thread.
    let (reason, marker) = unsafe { (read32(REASON), read32(SCRATCH0)) };
    if reason & REASON_TIMER != 0 && marker == MARKER {
        // SAFETY: as above. The stage it died in is kept for the next boot.
        unsafe {
            let at = read32(SCRATCH1) & 0xFFFF;
            write32(SCRATCH1, (at << 16) | at);
            write32(SCRATCH0, 0);
        }
        // Mass storage hidden: a rig reflashes over PICOBOOT.
        let _ = crate::platform::rp_bootrom::enter_bootsel(true);
    }
}

/// Start the watchdog's tick. RP2350 feeds it from its own TICKS
/// generator, which does not run until enabled; RP2040's watchdog tick is the
/// one its timer already uses.
fn start_tick() {
    #[cfg(not(feature = "chip-rp2040"))]
    {
        const WATCHDOG_TICK_CTRL: usize = 0x30;
        const WATCHDOG_TICK_CYCLES: usize = 0x34;
        let base = crate::platform::chip::TICKS_BASE as usize;
        let cycles = crate::platform::chip::XOSC_HZ / 1_000_000;
        // SAFETY: TICKS registers from the silicon TOML; boot thread.
        unsafe {
            write32(base + WATCHDOG_TICK_CYCLES, cycles);
            write32(base + WATCHDOG_TICK_CTRL, 1);
        }
    }
}

/// The longest the counter holds: its 24-bit load value at this chip's
/// tick rate. Bounds the boot, from clock bring-up to the main loop.
pub const BOOT_TIMEOUT_US: u32 = 0x00FF_FFFF / TICKS_PER_US;

/// Arm the watchdog: a whole-chip reset if the main loop stops feeding it
/// for [`TIMEOUT_US`].
pub fn arm() {
    arm_for(TIMEOUT_US);
}

/// Arm the watchdog for a boot or a graph build, which nothing feeds until
/// the main loop starts: a hang anywhere in it — the device stack, a
/// module's construction — still ends in BOOTSEL, after
/// [`BOOT_TIMEOUT_US`].
pub fn arm_for_boot() {
    arm_for(BOOT_TIMEOUT_US);
}

fn arm_for(timeout_us: u32) {
    start_tick();
    // SAFETY: fixed registers from the silicon TOML; the boot thread.
    unsafe {
        write32(PSM_WDSEL as usize, PSM_WDSEL_MASK);
        write32(SCRATCH0, MARKER);
        write32(LOAD, timeout_us * TICKS_PER_US);
        write32(CTRL, ENABLE | PAUSE_DEBUG);
    }
}

/// Feed the watchdog from the main loop.
#[inline]
pub fn feed() {
    // SAFETY: a write to LOAD reloads the countdown; no other effect.
    unsafe { write32(LOAD, TIMEOUT_US * TICKS_PER_US) };
}

/// Feed the watchdog during a boot-length wait that is bounded by its own
/// timeout.
#[inline]
pub fn feed_boot() {
    // SAFETY: as `feed`.
    unsafe { write32(LOAD, BOOT_TIMEOUT_US * TICKS_PER_US) };
}

/// Stop the watchdog and clear its marker: before a deliberate reboot, and
/// when the kernel parks reporting — a parked board still services USB and
/// is reachable, and a reset would lose what it is reporting.
pub fn disarm() {
    // SAFETY: fixed registers from the silicon TOML.
    unsafe {
        write32(CTRL, 0);
        write32(SCRATCH0, 0);
    }
}
