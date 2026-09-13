//! RP clock measurement — what the clock tree is *actually* running at.
//!
//! Every other frequency in the kernel is a declared intent: the silicon TOML
//! says 150 MHz, the PLL is programmed for 150 MHz, and the constant says
//! 150 MHz. Nothing in that chain observes the hardware. A PLL that failed to
//! lock, a crystal that is not the one the board TOML claims, or a divider
//! left at its reset value all produce a system that runs at the wrong speed
//! while every constant still reads correctly — and the symptom is a UART at
//! the wrong baud or a timer that lies, several layers from the cause.
//!
//! RP has a frequency counter (FC0) for exactly this. It counts a selected
//! clock against the reference over a fixed interval and reports kHz. This
//! module is the read-only window onto it.

/// Address arithmetic for the FC0 block, host-testable.
///
/// FC0 sits at a different offset within CLOCKS on the two chips — RP2040
/// 0x80, RP2350 0x8c — but its registers run in the same order from there.
pub mod addr {
    /// The reference frequency FC0 measures against, in kHz.
    pub const REF_KHZ: usize = 0x00;
    /// Lower bound; a result below it sets the `FAIL` status.
    pub const MIN_KHZ: usize = 0x04;
    /// Upper bound.
    pub const MAX_KHZ: usize = 0x08;
    /// Delay before counting starts, in reference cycles.
    pub const DELAY: usize = 0x0c;
    /// Measurement interval, as a power of two.
    pub const INTERVAL: usize = 0x10;
    /// Which clock to measure.
    pub const SRC: usize = 0x14;
    /// Status; `DONE` is bit 4.
    pub const STATUS: usize = 0x18;
    /// Result: kHz in bits 5..31, fractional part in bits 0..4.
    pub const RESULT: usize = 0x1c;

    /// Address of an FC0 register.
    #[inline]
    pub const fn fc0(clocks_base: usize, fc0_offset: usize, reg: usize) -> usize {
        clocks_base + fc0_offset + reg
    }
}

/// `DONE` within `FC0_STATUS`.
pub const STATUS_DONE: u32 = 1 << 4;
/// Shift of the kHz field within `FC0_RESULT`.
pub const RESULT_KHZ_LSB: u32 = 5;
/// Width of the kHz field within `FC0_RESULT`.
pub const RESULT_KHZ_WIDTH: u32 = 25;

/// Which clock FC0 should measure. The selector values are the same on both
/// chips, unusually for this peripheral.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Source {
    /// The reference clock.
    Ref = 0x08,
    /// The system clock.
    Sys = 0x09,
    /// The USB clock, which must be 48 MHz for USB to enumerate.
    Usb = 0x0b,
    /// The crystal oscillator.
    Xosc = 0x05,
}

/// Convert a raw `FC0_RESULT` to kHz, discarding the fractional part.
///
/// Split out so the field extraction is checked on a host: the kHz field
/// starts at bit 5, and reading the register as a plain integer — which is
/// the obvious mistake — reports a frequency 32 times too large.
#[inline]
pub const fn result_khz(raw: u32) -> u32 {
    (raw >> RESULT_KHZ_LSB) & ((1u32 << RESULT_KHZ_WIDTH) - 1)
}

#[cfg(feature = "rp")]
pub use rp::*;

#[cfg(feature = "rp")]
mod rp {
    use super::{addr, result_khz, Source, STATUS_DONE};
    use crate::platform::chip::{CLOCKS_BASE, CLOCKS_FC0_OFFSET, XOSC_HZ};
    use crate::platform::rp_regs::{read32, wait_until, write32};

    /// Poll budget for a measurement to complete.
    ///
    /// The measurement itself takes about a millisecond; this is generous
    /// against that. Bounded because FC0 never reports `DONE` if its source
    /// is not running, and an unbounded wait on a dead clock is a hang.
    const MEASURE_LIMIT: u32 = 1_000_000;

    fn reg(r: usize) -> usize {
        addr::fc0(CLOCKS_BASE as usize, CLOCKS_FC0_OFFSET as usize, r)
    }

    /// Measure a clock, in kHz. `None` if the measurement did not complete,
    /// which means the selected clock is not running.
    ///
    /// **Not re-entrant, and not interrupt-safe**: FC0 is a single shared
    /// counter, so two callers overlapping produce one wrong answer and one
    /// missing one. Intended for boot-time verification and for an explicit
    /// diagnostic query, not for a hot path.
    pub fn measure_khz(src: Source) -> Option<u32> {
        // The reference is the crystal, which is a board fact.
        let ref_khz = XOSC_HZ / 1000;
        // SAFETY: generated CLOCKS base and FC0 offset for this silicon.
        unsafe {
            write32(reg(addr::REF_KHZ), ref_khz);
            // No bounds: a measurement outside them sets FAIL rather than
            // reporting, and this function's job is to report what is there.
            write32(reg(addr::MIN_KHZ), 0);
            write32(reg(addr::MAX_KHZ), u32::MAX >> 7);
            write32(reg(addr::DELAY), 1);
            // 2^10 reference cycles: about a millisecond at 12 MHz, which
            // resolves to 1 kHz — ample to tell 150 MHz from 125 MHz.
            write32(reg(addr::INTERVAL), 10);
            write32(reg(addr::SRC), src as u32);

            if !wait_until(MEASURE_LIMIT, || {
                read32(reg(addr::STATUS)) & STATUS_DONE != 0
            }) {
                // Leave FC0 idle so a failed measurement does not keep the
                // counter pointed at a dead clock.
                write32(reg(addr::SRC), 0);
                return None;
            }
            let khz = result_khz(read32(reg(addr::RESULT)));
            write32(reg(addr::SRC), 0);
            Some(khz)
        }
    }

    /// Whether a measured frequency is within `tolerance_permille` of what
    /// was asked for.
    ///
    /// FC0's own resolution and the crystal's tolerance both land here, so
    /// this is a band rather than an equality. A clock that is out by a
    /// factor — a PLL that never locked, or a divider left at reset — misses
    /// any sane band by a wide margin, which is the case worth catching.
    #[must_use]
    pub fn within_tolerance(measured_hz: u32, expected_hz: u32, tolerance_permille: u32) -> bool {
        let margin = (expected_hz as u64 * tolerance_permille as u64) / 1000;
        let delta = (measured_hz as i64 - expected_hz as i64).unsigned_abs();
        delta <= margin
    }

    /// The measured system clock, in Hz.
    ///
    /// Falls back to the declared constant when FC0 cannot measure — the
    /// caller asked for a frequency, and a declared one is more useful than
    /// nothing. The two disagreeing is itself the interesting signal, which
    /// is what [`verify`] reports.
    pub fn measured_sys_hz() -> u32 {
        measure_khz(Source::Sys)
            .map(|khz| khz * 1000)
            .unwrap_or(crate::platform::chip::SYS_CLK_HZ)
    }

    /// Compare the clock tree against what was asked for, logging each one.
    ///
    /// Called once at boot. This is the only thing in the kernel that can
    /// tell "the PLL is at 150 MHz" from "we asked for 150 MHz", and the
    /// distinction is invisible until something downstream misbehaves.
    pub fn verify() {
        use crate::platform::chip::{SYS_CLK_HZ, USB_CLK_HZ, XOSC_HZ};
        // 5% covers FC0's resolution and crystal tolerance together, while
        // still failing a clock that is out by a divider or a PLL multiple.
        const TOLERANCE_PERMILLE: u32 = 50;

        for (name, src, expected) in [
            ("sys", Source::Sys, SYS_CLK_HZ),
            ("usb", Source::Usb, USB_CLK_HZ),
            ("xosc", Source::Xosc, XOSC_HZ),
        ] {
            match measure_khz(src) {
                Some(khz) => {
                    let hz = khz * 1000;
                    if within_tolerance(hz, expected, TOLERANCE_PERMILLE) {
                        // info, not debug: the runtime level is Info, so a
                        // debug line here would make a healthy clock tree
                        // indistinguishable from a verification that never
                        // ran. This is one line per boot and it is the only
                        // evidence anywhere that the measured tree matches
                        // the declared one.
                        log::info!("[clocks] {name}={hz} Hz (asked {expected})");
                    } else {
                        log::warn!("[clocks] {name}={hz} Hz but {expected} was asked for");
                    }
                }
                None => log::warn!("[clocks] {name} is not running"),
            }
        }
    }
}

// ============================================================================
// PLL configuration
// ============================================================================

/// PLL divider selection.
///
/// The arithmetic is the dangerous part and it is all here, away from the
/// registers, so it can be checked exhaustively. A wrong divider does not
/// fail cleanly: either the PLL never locks (a board that hangs before any
/// diagnostic exists) or it locks at the wrong frequency, and everything
/// downstream — timers, UART baud, USB — is wrong by the same ratio while
/// every constant in the build still agrees with every other constant.
pub mod pll {
    /// Lowest VCO frequency the PLL is specified for.
    pub const VCO_MIN_HZ: u64 = 750_000_000;
    /// Highest VCO frequency the PLL is specified for.
    pub const VCO_MAX_HZ: u64 = 1_600_000_000;
    /// Smallest feedback divider.
    pub const FBDIV_MIN: u32 = 16;
    /// Largest feedback divider.
    pub const FBDIV_MAX: u32 = 320;
    /// Largest post-divider. Both are three-bit fields, and zero is not a
    /// divider.
    pub const POSTDIV_MAX: u32 = 7;

    /// A solved PLL configuration.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Config {
        /// Reference divider.
        pub refdiv: u32,
        /// Feedback divider: VCO = reference / refdiv * fbdiv.
        pub fbdiv: u32,
        /// First post-divider. Must be at least as large as the second.
        pub postdiv1: u32,
        /// Second post-divider.
        pub postdiv2: u32,
    }

    impl Config {
        /// The VCO frequency this configuration runs the oscillator at.
        pub const fn vco_hz(&self, ref_hz: u32) -> u64 {
            (ref_hz as u64 / self.refdiv as u64) * self.fbdiv as u64
        }

        /// The output frequency this configuration produces.
        pub const fn output_hz(&self, ref_hz: u32) -> u64 {
            self.vco_hz(ref_hz) / (self.postdiv1 as u64 * self.postdiv2 as u64)
        }
    }

    /// Find dividers producing exactly `target_hz` from `ref_hz`.
    ///
    /// Exact only: a PLL that is close is a system whose every derived clock
    /// is wrong by the same ratio, and USB in particular will not enumerate
    /// off an approximate 48 MHz. Returning `None` rather than the nearest
    /// match is what turns "this frequency is unattainable" into a build
    /// failure rather than a board that half-works.
    ///
    /// The search order matches the pico-sdk's exactly — feedback divider
    /// descending, then both post-dividers descending — and that is
    /// deliberate. Several divider combinations produce the same output
    /// frequency and all of them are arithmetically correct, but the SDK's
    /// choices are the ones running on every Pico in the field. Picking a
    /// different valid answer would be substituting untested numbers for
    /// proven ones in a peripheral whose failure mode is a board that does
    /// not start.
    pub const fn solve(ref_hz: u32, target_hz: u32) -> Option<Config> {
        // refdiv 1 is what every RP board uses with a 12 MHz crystal; the
        // search is over fbdiv and the two post-dividers.
        let refdiv = 1u32;
        let reference = ref_hz as u64 / refdiv as u64;

        let mut fbdiv = FBDIV_MAX;
        while fbdiv >= FBDIV_MIN {
            let vco = reference * fbdiv as u64;
            if vco < VCO_MIN_HZ || vco > VCO_MAX_HZ {
                fbdiv -= 1;
                continue;
            }
            let mut pd1 = POSTDIV_MAX;
            while pd1 >= 1 {
                // postdiv1 >= postdiv2 is a hardware requirement, not a
                // convention: the dividers are not interchangeable.
                let mut pd2 = pd1;
                while pd2 >= 1 {
                    let divisor = pd1 as u64 * pd2 as u64;
                    if vco.is_multiple_of(divisor) && vco / divisor == target_hz as u64 {
                        return Some(Config {
                            refdiv,
                            fbdiv,
                            postdiv1: pd1,
                            postdiv2: pd2,
                        });
                    }
                    pd2 -= 1;
                }
                pd1 -= 1;
            }
            fbdiv -= 1;
        }
        None
    }

    /// The USB PLL's configuration, which is **specified rather than
    /// solved**.
    ///
    /// Several divider combinations produce 48 MHz from a 12 MHz crystal, and
    /// [`solve`] finds a different one first. The SDK does not use its search
    /// for USB: it hardcodes a 1200 MHz VCO with both post-dividers at 5, and
    /// that is the configuration every Pico in the field enumerates on.
    ///
    /// USB is the wrong place to substitute an untested-but-arithmetically-
    /// equal answer. A host that will not enumerate gives no reason why, and
    /// the difference between two 48 MHz configurations is jitter — which
    /// does not show up in any number this code can check.
    pub const USB: Config = Config {
        refdiv: 1,
        fbdiv: 100,
        postdiv1: 5,
        postdiv2: 5,
    };

    /// Whether a configuration is within every hardware limit.
    ///
    /// Checked separately from solving so a hand-written configuration —
    /// which a board might one day carry for a frequency the solver cannot
    /// reach — is held to the same constraints.
    pub const fn is_valid(cfg: &Config, ref_hz: u32) -> bool {
        if cfg.refdiv == 0 || cfg.fbdiv < FBDIV_MIN || cfg.fbdiv > FBDIV_MAX {
            return false;
        }
        if cfg.postdiv1 == 0 || cfg.postdiv1 > POSTDIV_MAX {
            return false;
        }
        if cfg.postdiv2 == 0 || cfg.postdiv2 > POSTDIV_MAX {
            return false;
        }
        if cfg.postdiv1 < cfg.postdiv2 {
            return false;
        }
        let vco = cfg.vco_hz(ref_hz);
        vco >= VCO_MIN_HZ && vco <= VCO_MAX_HZ
    }
}

// ============================================================================
// Clock bring-up
// ============================================================================

/// Bring the crystal oscillator and PLLs up, and point the clock tree at
/// them.
///
/// # Ordering is the whole thing
///
/// Every step here depends on the one before it having actually completed,
/// and the hardware does not enforce that:
///
/// - a PLL fed by an oscillator that has not stabilised locks to a frequency
///   that then drifts;
/// - switching `clk_sys` to a PLL that has not locked stops the core, because
///   the clock it is executing from goes away mid-instruction;
/// - switching away from a running clock without first moving dependants to a
///   glitchless source produces a runt pulse, which is a reset in every
///   practical sense and has no diagnostic.
///
/// So each wait is real and each is bounded, and the whole function reports
/// failure rather than continuing on the assumption a step worked.
#[cfg(feature = "rp")]
pub mod bringup {
    use super::pll::{self, Config};
    use crate::platform::rp_regs::{clear_bits, modify32, read32, wait_until, write32};

    /// XOSC register offsets.
    mod xosc {
        pub const CTRL: usize = 0x00;
        pub const STATUS: usize = 0x04;
        pub const STARTUP: usize = 0x0c;
        /// `STATUS.STABLE`.
        pub const STABLE: u32 = 1 << 31;
        /// `CTRL.FREQ_RANGE` for a 1–15 MHz crystal, which covers the 12 MHz
        /// every RP board in this tree fits.
        pub const FREQ_RANGE_1_15MHZ: u32 = 0xaa0;
        /// `CTRL.ENABLE`, a magic value rather than a bit — a stray write
        /// cannot enable the oscillator by accident.
        pub const ENABLE: u32 = 0xfab << 12;
    }

    /// PLL register offsets. Shared by both PLLs and both chips.
    mod pll_reg {
        pub const CS: usize = 0x00;
        pub const PWR: usize = 0x04;
        pub const FBDIV_INT: usize = 0x08;
        pub const PRIM: usize = 0x0c;
        /// `CS.LOCK`.
        pub const LOCK: u32 = 1 << 31;
        /// `PWR.PD` — the main power-down.
        pub const PD: u32 = 1 << 0;
        /// `PWR.POSTDIVPD` — the post-divider power-down.
        pub const POSTDIVPD: u32 = 1 << 3;
        /// `PWR.VCOPD` — the oscillator power-down.
        pub const VCOPD: u32 = 1 << 5;
        /// `PRIM.POSTDIV1` position.
        pub const POSTDIV1_LSB: u32 = 16;
        /// `PRIM.POSTDIV2` position.
        pub const POSTDIV2_LSB: u32 = 12;
    }

    /// CLOCKS register offsets. Only CLK_USB_CTRL differs between the chips,
    /// so it is generated and the rest are here.
    mod clk {
        pub const CLK_REF_CTRL: usize = 0x30;
        pub const CLK_REF_SELECTED: usize = 0x38;
        pub const CLK_SYS_CTRL: usize = 0x3c;
        pub const CLK_SYS_SELECTED: usize = 0x44;
        pub const CLK_PERI_CTRL: usize = 0x48;
        /// `CLK_REF_CTRL.SRC` = XOSC.
        pub const REF_SRC_XOSC: u32 = 0x2;
        /// `CLK_SYS_CTRL.SRC` = the reference clock, which is glitchless.
        pub const SYS_SRC_REF: u32 = 0x0;
        /// `CLK_SYS_CTRL.SRC` = the aux mux.
        pub const SYS_SRC_AUX: u32 = 0x1;
        /// `CLK_SYS_CTRL.AUXSRC` = PLL_SYS.
        pub const SYS_AUXSRC_PLL: u32 = 0x0;
        /// `CLK_PERI_CTRL.AUXSRC` = clk_sys. The peripheral mux has its own
        /// numbering; it is not the clk_sys mux's, and the two disagree from
        /// entry 1 onwards.
        pub const PERI_AUXSRC_SYS: u32 = 0x0;
        /// `CLK_PERI_CTRL.AUXSRC` = XOSC.
        pub const PERI_AUXSRC_XOSC: u32 = 0x4;
        /// `AUXSRC` position in both CTRL registers.
        pub const AUXSRC_LSB: u32 = 5;
        /// `ENABLE` in the peripheral and USB clock controls.
        pub const ENABLE: u32 = 1 << 11;
    }

    /// Spin budget for a bring-up step: an oscillator stabilising, a PLL
    /// locking, a peripheral leaving reset.
    ///
    /// A count of polls rather than a duration, because bring-up runs before
    /// there is a timer to ask. The core clock changes underneath it — these
    /// waits run both on the crystal and on the PLL afterwards — so the real
    /// time it allows varies with the clock by more than a factor of ten. It
    /// is a bound on hanging, not a deadline: every step it covers either
    /// completes in microseconds or never completes at all, and the number
    /// only has to be far above the first and finite for the second.
    const LIMIT: u32 = 1_000_000;

    /// Why bring-up failed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ClockError {
        /// The crystal never reported stable.
        XoscUnstable,
        /// A PLL never locked to its configuration.
        PllNoLock,
        /// The requested system frequency has no exact divider solution.
        Unattainable,
        /// A clock mux did not report the source it was told to select.
        MuxNotSelected,
        /// The requested frequency needs a core voltage this bring-up does
        /// not set. See [`DEFAULT_VOLTAGE_MAX_HZ`].
        NeedsRaisedCoreVoltage,
        /// A peripheral never reported itself out of reset.
        ResetNotReleased,
    }

    /// Start the crystal oscillator and wait for it to stabilise.
    ///
    /// Called by both entry points below rather than sequenced between
    /// them, because either may be the first: a boot that brings the console
    /// up early has already started the crystal by the time the tree is
    /// built, and one that goes straight to the tree has not. Both calls
    /// write the same configuration and then wait on `STABLE`, so the
    /// second returns as soon as it reads a crystal that is already
    /// running.
    fn start_xosc() -> Result<(), ClockError> {
        use crate::platform::chip::XOSC_BASE;
        let base = XOSC_BASE as usize;
        // SAFETY: the generated XOSC base for this silicon; single writer at
        // boot, before anything depends on the clock tree.
        unsafe {
            // The startup delay is counted in multiples of 256 crystal
            // cycles. One millisecond at 12 MHz is 12000 cycles, so 47
            // counts — rounded up, because too short means the PLL is fed an
            // oscillator that has not settled.
            write32(base + xosc::STARTUP, 47);
            write32(base + xosc::CTRL, xosc::FREQ_RANGE_1_15MHZ | xosc::ENABLE);
            if wait_until(LIMIT, || read32(base + xosc::STATUS) & xosc::STABLE != 0) {
                Ok(())
            } else {
                Err(ClockError::XoscUnstable)
            }
        }
    }

    /// Take a peripheral out of reset and wait for it to report ready.
    ///
    /// `RESET` is write-1-to-hold, so clearing the bit releases it, and
    /// `RESET_DONE` (at +0x08) reads 1 once the peripheral is usable. The
    /// wait is not optional: the registers of a peripheral still in reset
    /// accept writes and keep their reset values.
    fn unreset_wait(bit: u32) -> Result<(), ClockError> {
        use crate::platform::chip::RESETS_BASE;
        let resets = RESETS_BASE as usize;
        let mask = 1u32 << bit;
        // SAFETY: the generated RESETS base for this silicon; single writer
        // at boot.
        unsafe {
            clear_bits(resets, mask);
            if wait_until(LIMIT, || read32(resets + 0x08) & mask != 0) {
                Ok(())
            } else {
                Err(ClockError::ResetNotReleased)
            }
        }
    }

    /// Release every peripheral this runtime is responsible for from reset.
    ///
    /// **Nothing on an RP part works before this.** Every peripheral comes
    /// out of power-on held in reset, and a peripheral in reset accepts
    /// configuration writes while keeping its reset values — so a driver
    /// that runs too early does not fail, it configures nothing, and the
    /// board that results does nothing for no stated reason. Under the
    /// Boot owns this.
    ///
    /// Which bits are released is a silicon fact — the positions move
    /// between the chips — so the mask is generated rather than written
    /// here. What it excludes is the interesting part, and each exclusion
    /// bites differently: the QSPI pair is the flash this code is executing
    /// from, the PLLs are what clock us, and USBCTRL belongs to the device
    /// stack, which sequences its own reset against enumeration.
    ///
    /// Returns whether every released peripheral reported ready.
    pub fn release_peripherals() -> bool {
        use crate::platform::chip::{RESETS_BASE, RESETS_RELEASE_MASK, RESETS_REQUIRED_MASK};
        let resets = RESETS_BASE as usize;
        // Release everything, then wait only for the peripherals this
        // runtime drives. A bit can be safe to release and still never
        // report done — ADC and HSTX have clock generators this bring-up
        // does not configure — and waiting on one of those makes a
        // peripheral nobody uses into a boot failure.
        //
        // SAFETY: the generated RESETS base for this silicon; single writer
        // at boot, before any driver touches a peripheral.
        unsafe {
            clear_bits(resets, RESETS_RELEASE_MASK);
            wait_until(LIMIT, || {
                read32(resets + 0x08) & RESETS_REQUIRED_MASK == RESETS_REQUIRED_MASK
            })
        }
    }

    /// Configure and lock one PLL.
    ///
    /// **The reset release comes first, and nothing works without it.** Both
    /// PLLs are held in reset out of power-on. A PLL in reset accepts every
    /// configuration write and keeps its reset values, so `LOCK` never
    /// asserts and the wait below times out — reported as "this PLL would
    /// not lock", when in truth it was never powered up to try.
    ///
    /// The post-dividers are written **after** the lock, not before. The PLL
    /// locks on the VCO, and the datasheet's sequence powers the
    /// post-dividers up separately once it has — doing both at once means
    /// waiting for a lock on a configuration that is still changing.
    fn start_pll(base: usize, reset_bit: u32, cfg: &Config) -> Result<(), ClockError> {
        unreset_wait(reset_bit)?;
        // SAFETY: a generated PLL base for this silicon.
        unsafe {
            write32(base + pll_reg::CS, cfg.refdiv);
            write32(base + pll_reg::FBDIV_INT, cfg.fbdiv);

            // Power up the main block and the VCO; the post-dividers stay
            // down until the lock.
            modify32(base + pll_reg::PWR, |v| v & !(pll_reg::PD | pll_reg::VCOPD));

            if !wait_until(LIMIT, || read32(base + pll_reg::CS) & pll_reg::LOCK != 0) {
                return Err(ClockError::PllNoLock);
            }

            write32(
                base + pll_reg::PRIM,
                (cfg.postdiv1 << pll_reg::POSTDIV1_LSB) | (cfg.postdiv2 << pll_reg::POSTDIV2_LSB),
            );
            modify32(base + pll_reg::PWR, |v| v & !pll_reg::POSTDIVPD);
        }
        Ok(())
    }

    /// The highest system frequency the default core voltage supports.
    ///
    /// **This bring-up does not touch the voltage regulator**, and that is
    /// correct for both production profiles: RP2040 at 125 MHz and RP2350 at
    /// 150 MHz both run at the default V1_10.
    ///
    /// It is *not* correct above that. RP2040 requires V1_15 beyond 133 MHz,
    /// and RP2350 has no documented support for running at voltages or clock
    /// speeds other than the defaults. The declared overclock profile is
    /// 240 MHz, which is past RP2040's rule on paper and past anything
    /// documented for RP2350.
    ///
    /// So [`init`] refuses rather than running out of spec. An overclock that
    /// needs a voltage change is a piece of work to do deliberately, not a
    /// number to raise and hope about: undervolted silicon does not fail
    /// cleanly, it computes wrongly under load.
    #[cfg(feature = "chip-rp2040")]
    pub const DEFAULT_VOLTAGE_MAX_HZ: u32 = 133_000_000;
    /// As above. RP2350's production default is 150 MHz.
    #[cfg(not(feature = "chip-rp2040"))]
    pub const DEFAULT_VOLTAGE_MAX_HZ: u32 = 150_000_000;

    /// Start the crystal and run the peripherals from it, at `ref_hz`.
    ///
    /// **This exists so the console can speak before the PLLs.** `clk_peri`
    /// is disabled out of reset, so a UART configured before this has no
    /// clock: it accepts a few bytes into its FIFO, never shifts them out,
    /// and then drops the rest. A board that fails during [`init`] therefore
    /// reports nothing — which is the one failure this console exists to
    /// make visible.
    ///
    /// The crystal is the earliest source that is exact. ROSC is running
    /// sooner but its frequency is uncalibrated, so a UART divided from it
    /// produces framing errors rather than text.
    ///
    /// Returns the frequency `clk_peri` is now running at, for the caller to
    /// compute its divisors from.
    pub fn start_peri_from_xosc(ref_hz: u32) -> Result<u32, ClockError> {
        use crate::platform::chip::CLOCKS_BASE;

        start_xosc()?;

        let clocks = CLOCKS_BASE as usize;
        // SAFETY: the generated CLOCKS base for this silicon.
        unsafe {
            modify32(clocks + clk::CLK_REF_CTRL, |v| {
                (v & !0x3) | clk::REF_SRC_XOSC
            });
            if !wait_until(LIMIT, || {
                read32(clocks + clk::CLK_REF_SELECTED) & (1 << clk::REF_SRC_XOSC) != 0
            }) {
                return Err(ClockError::MuxNotSelected);
            }
            // `clk_peri`'s AUXSRC numbering is its own: 0 is clk_sys, and
            // the crystal is `PERI_AUXSRC_XOSC`. Reusing the clk_sys
            // encoding here would silently select a different parent.
            write32(
                clocks + clk::CLK_PERI_CTRL,
                clk::ENABLE | (clk::PERI_AUXSRC_XOSC << clk::AUXSRC_LSB),
            );
        }
        Ok(ref_hz)
    }

    /// Bring up the whole tree: crystal, both PLLs, and the clock muxes.
    ///
    /// Returns the configuration the system clock ended up on, so a caller
    /// can compare it against what was asked for.
    pub fn init(ref_hz: u32, sys_hz: u32) -> Result<Config, ClockError> {
        use crate::platform::chip::{
            CLOCKS_BASE, CLOCKS_CLK_USB_CTRL_OFFSET, PLL_SYS_BASE, PLL_USB_BASE,
            RESETS_PLL_SYS_BIT, RESETS_PLL_USB_BIT,
        };

        // Before anything is touched: refuse a frequency the default core
        // voltage does not support. Undervolted silicon does not fail
        // cleanly -- it computes wrongly under load, which is the hardest
        // possible fault to attribute.
        if sys_hz > DEFAULT_VOLTAGE_MAX_HZ {
            return Err(ClockError::NeedsRaisedCoreVoltage);
        }

        let sys = pll::solve(ref_hz, sys_hz).ok_or(ClockError::Unattainable)?;
        if !pll::is_valid(&sys, ref_hz) {
            return Err(ClockError::Unattainable);
        }

        start_xosc()?;

        let clocks = CLOCKS_BASE as usize;
        // SAFETY: the generated CLOCKS base for this silicon.
        unsafe {
            // Move clk_sys off anything PLL-derived before touching the PLLs.
            // Switching away from a running clock without first parking
            // dependants on a glitchless source produces a runt pulse, which
            // is a reset in every practical sense and leaves no diagnostic.
            modify32(clocks + clk::CLK_SYS_CTRL, |v| {
                (v & !0x3) | clk::SYS_SRC_REF
            });
            if !wait_until(LIMIT, || read32(clocks + clk::CLK_SYS_SELECTED) & 1 != 0) {
                return Err(ClockError::MuxNotSelected);
            }
        }

        start_pll(PLL_SYS_BASE as usize, RESETS_PLL_SYS_BIT, &sys)?;
        start_pll(PLL_USB_BASE as usize, RESETS_PLL_USB_BIT, &pll::USB)?;

        // SAFETY: as above.
        unsafe {
            // The reference clock runs from the crystal, which is what the
            // monotonic tick divides down from.
            modify32(clocks + clk::CLK_REF_CTRL, |v| {
                (v & !0x3) | clk::REF_SRC_XOSC
            });
            if !wait_until(LIMIT, || {
                read32(clocks + clk::CLK_REF_SELECTED) & (1 << clk::REF_SRC_XOSC) != 0
            }) {
                return Err(ClockError::MuxNotSelected);
            }

            // Now the system clock, via the aux mux. AUXSRC first, then SRC:
            // selecting the mux before its input is chosen would run the core
            // from whatever the aux mux happened to hold.
            modify32(clocks + clk::CLK_SYS_CTRL, |v| {
                (v & !(0x7 << clk::AUXSRC_LSB)) | (clk::SYS_AUXSRC_PLL << clk::AUXSRC_LSB)
            });
            modify32(clocks + clk::CLK_SYS_CTRL, |v| {
                (v & !0x3) | clk::SYS_SRC_AUX
            });
            if !wait_until(LIMIT, || {
                read32(clocks + clk::CLK_SYS_SELECTED) & (1 << clk::SYS_SRC_AUX) != 0
            }) {
                return Err(ClockError::MuxNotSelected);
            }

            // Peripherals follow clk_sys; USB takes its own PLL, because 48
            // MHz is not a division of every system frequency.
            write32(
                clocks + clk::CLK_PERI_CTRL,
                clk::ENABLE | (clk::PERI_AUXSRC_SYS << clk::AUXSRC_LSB),
            );
            write32(clocks + CLOCKS_CLK_USB_CTRL_OFFSET as usize, clk::ENABLE);
        }

        Ok(sys)
    }
}
