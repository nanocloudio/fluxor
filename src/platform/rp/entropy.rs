//! RP entropy sources and the conditioning between them and callers.
//!
//! # What was here before
//!
//! One function, used for key material on both chips:
//!
//! ```text
//! while bit < 8 {
//!     byte = (byte << 1) | pac::ROSC.randombit().read().randombit();
//!     bit += 1;
//! }
//! ```
//!
//! documented as "genuine hardware entropy suitable for seeding
//! cryptographic keys". It was neither, for three independent reasons.
//!
//! **It sampled far too fast.** The ring oscillator ticks a few times per
//! microsecond; the SDK paces `RANDOMBIT` reads at one per 10 µs and says
//! why. That loop reads it back to back — at 150 MHz, several reads per
//! *tick*. Consecutive bits are therefore overwhelmingly the same sampled
//! oscillator state, so a "random" byte is mostly runs of one value.
//!
//! **It applied no conditioning.** Raw oscillator bits went straight into
//! key material. The SDK hashes every entropy source before use; a raw ring
//! oscillator is a biased source, not a uniform one.
//!
//! **It ignored the hardware.** RP2350 has a real TRNG with continuous
//! health tests. Both chips were using the ring oscillator regardless.
//!
//! # What is here now
//!
//! A source with a declared quality tier, and a conditioning step that no
//! caller can skip:
//!
//! - **RP2350** reads its TRNG, and a health-test failure is reported rather
//!   than averaged away.
//! - **RP2040** has no TRNG. It paces the ring oscillator as the datasheet
//!   requires and declares itself [`Quality::ConditionedRosc`] — not a
//!   hardware CSPRNG, because it is not one.
//!
//! Both feed SHA-256 conditioning, so what reaches a caller is a uniform
//! function of the collected entropy rather than the raw source.

/// How good the underlying entropy source is.
///
/// Declared, not assumed. A caller that needs a hardware CSPRNG can ask,
/// and on RP2040 the answer is no — which is the honest answer and the one
/// a raw source must be able to state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quality {
    /// A hardware TRNG with continuous health tests (RP2350).
    HardwareTrng,
    /// A ring oscillator, sampled at the rate the datasheet allows and
    /// conditioned through a hash. Adequate for seeding; **not** a hardware
    /// CSPRNG, and it must not be described as one.
    ConditionedRosc,
}

/// Minimum interval between `RANDOMBIT` samples, in microseconds.
///
/// The SDK's `PICO_RAND_MIN_ROSC_BIT_SAMPLE_TIME_US`. The ring oscillator
/// ticks only a few times per microsecond, so sampling faster than this
/// returns the same oscillator state more than once — which reads as a run
/// of identical bits and is not entropy at all.
pub const ROSC_MIN_SAMPLE_US: u64 = 10;

/// TRNG register offsets (RP2350). Host-testable.
pub mod trng_reg {
    /// Interrupt status: EHR valid, autocorrelation error, CRNGT error.
    pub const RNG_ISR: usize = 0x104;
    /// Interrupt clear.
    pub const RNG_ICR: usize = 0x108;
    /// Whether the entropy holding register has a full block.
    pub const TRNG_VALID: usize = 0x110;
    /// First of six entropy holding registers.
    pub const EHR_DATA0: usize = 0x114;
    /// Enable the random source.
    pub const RND_SOURCE_ENABLE: usize = 0x12c;
    /// Sample counter — how long to collect before a block is ready.
    pub const SAMPLE_CNT1: usize = 0x130;
    /// Interrupt mask.
    pub const RNG_IMR: usize = 0x100;

    /// Words in the entropy holding register: 192 bits.
    pub const EHR_WORDS: usize = 6;

    /// `RNG_ISR.EHR_VALID` — a block is ready.
    pub const ISR_EHR_VALID: u32 = 1 << 0;
    /// `RNG_ISR.AUTOCORR_ERR` — the autocorrelation health test failed.
    /// **This is a hard failure**: the source is producing correlated bits.
    pub const ISR_AUTOCORR_ERR: u32 = 1 << 1;
    /// `RNG_ISR.CRNGT_ERR` — the continuous RNG test failed: two successive
    /// blocks were identical.
    pub const ISR_CRNGT_ERR: u32 = 1 << 2;
    /// Every health-test error bit.
    pub const ISR_HEALTH_ERRORS: u32 = ISR_AUTOCORR_ERR | ISR_CRNGT_ERR;

    /// `RND_SOURCE_ENABLE.RND_SRC_EN`.
    pub const SRC_ENABLE: u32 = 1 << 0;

    /// Address of an EHR word.
    #[inline]
    pub const fn ehr(base: usize, word: usize) -> usize {
        base + EHR_DATA0 + word * 4
    }
}

#[cfg(feature = "rp")]
pub use rp::*;

#[cfg(feature = "rp")]
mod rp {
    #[cfg(not(feature = "chip-rp2040"))]
    use super::trng_reg;
    use super::Quality;
    #[cfg(feature = "chip-rp2040")]
    use super::ROSC_MIN_SAMPLE_US;

    /// This platform's entropy quality.
    pub const fn quality() -> Quality {
        #[cfg(feature = "chip-rp2040")]
        {
            Quality::ConditionedRosc
        }
        #[cfg(not(feature = "chip-rp2040"))]
        {
            Quality::HardwareTrng
        }
    }

    /// Why an entropy request failed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum EntropyError {
        /// A continuous health test failed. The source is producing
        /// correlated or repeated output and must not be used.
        HealthTestFailed,
        /// The source did not produce a block within its budget.
        Timeout,
    }

    /// Collect raw entropy into `out`, returning how many bytes were filled.
    ///
    /// This is the *source*, not the answer: callers go through
    /// [`fill_conditioned`], which hashes what this produces.
    #[cfg(not(feature = "chip-rp2040"))]
    fn collect_raw(out: &mut [u8]) -> Result<usize, EntropyError> {
        use crate::platform::chip::TRNG_BASE;
        use crate::platform::rp_regs::{read32, wait_until, write32};

        const BLOCK_LIMIT: u32 = 1_000_000;
        let base = TRNG_BASE as usize;
        let mut filled = 0;

        // SAFETY: the generated TRNG base for this silicon.
        unsafe {
            // Mask the interrupt — the status register is polled, and an
            // unhandled TRNG interrupt would be an unowned IRQ.
            write32(base + trng_reg::RNG_IMR, u32::MAX);
            write32(base + trng_reg::RND_SOURCE_ENABLE, trng_reg::SRC_ENABLE);

            while filled < out.len() {
                if !wait_until(BLOCK_LIMIT, || read32(base + trng_reg::TRNG_VALID) & 1 != 0) {
                    write32(base + trng_reg::RND_SOURCE_ENABLE, 0);
                    return Err(EntropyError::Timeout);
                }

                // Health first, and fail closed. Averaging a failed health
                // test into the pool is how a broken source becomes
                // invisible — the output still looks random to anyone who
                // is not testing for it.
                let isr = read32(base + trng_reg::RNG_ISR);
                if isr & trng_reg::ISR_HEALTH_ERRORS != 0 {
                    write32(base + trng_reg::RNG_ICR, isr);
                    write32(base + trng_reg::RND_SOURCE_ENABLE, 0);
                    return Err(EntropyError::HealthTestFailed);
                }

                for word in 0..trng_reg::EHR_WORDS {
                    let v = read32(trng_reg::ehr(base, word)).to_le_bytes();
                    for b in v {
                        if filled < out.len() {
                            out[filled] = b;
                            filled += 1;
                        }
                    }
                }
                // Reading all six EHR words re-arms the source.
            }
            write32(base + trng_reg::RND_SOURCE_ENABLE, 0);
        }
        Ok(filled)
    }

    /// Collect raw entropy from the ring oscillator, paced.
    ///
    /// RP2040 has no TRNG. The pacing is not optional: sampling faster than
    /// the oscillator ticks returns the same state repeatedly, which is a
    /// run of identical bits rather than entropy.
    #[cfg(feature = "chip-rp2040")]
    fn collect_raw(out: &mut [u8]) -> Result<usize, EntropyError> {
        use crate::platform::chip::{ROSC_BASE, ROSC_RANDOMBIT_OFFSET};
        use crate::platform::rp_regs::read32;

        let addr = ROSC_BASE as usize + ROSC_RANDOMBIT_OFFSET as usize;
        for byte in out.iter_mut() {
            let mut acc = 0u8;
            for _ in 0..8 {
                let t0 = crate::platform::rp_timer::now_us();
                // SAFETY: the generated ROSC base and offset for this
                // silicon; RANDOMBIT is read-only.
                acc = (acc << 1) | (unsafe { read32(addr) } as u8 & 1);
                // Wait out the oscillator's minimum sample interval. The
                // whole value of this source depends on this delay.
                while crate::platform::rp_timer::now_us().wrapping_sub(t0) < ROSC_MIN_SAMPLE_US {}
            }
            *byte = acc;
        }
        Ok(out.len())
    }

    /// Bytes of raw source material collected per 32 bytes of output.
    ///
    /// Two-to-one, so the hash is compressing rather than stretching: a
    /// biased source carries less entropy per bit than its width suggests,
    /// and taking the same number of bytes out as went in would quietly
    /// assume otherwise.
    const RAW_PER_BLOCK: usize = 64;

    /// Fill `buf` with conditioned entropy.
    ///
    /// Raw source bytes are hashed rather than handed over. The source is
    /// biased — a ring oscillator certainly, a TRNG block plausibly — and a
    /// hash turns a biased-but-unpredictable input into a uniform output.
    /// Every caller goes through here; there is no raw path out.
    pub fn fill_conditioned(buf: &mut [u8]) -> Result<(), EntropyError> {
        use crate::kernel::security::crypto::sha256::Sha256;

        let mut written = 0;
        let mut counter: u32 = 0;
        while written < buf.len() {
            let mut raw = [0u8; RAW_PER_BLOCK];
            collect_raw(&mut raw)?;

            let mut h = Sha256::new();
            h.update(&raw);
            // A counter so two blocks drawn from identical raw material
            // cannot be identical, which the continuous test would flag as
            // a failure it is not.
            h.update(&counter.to_le_bytes());
            let block = h.finalize();
            counter = counter.wrapping_add(1);

            let n = core::cmp::min(block.len(), buf.len() - written);
            buf[written..written + n].copy_from_slice(&block[..n]);
            written += n;
        }
        Ok(())
    }
}
