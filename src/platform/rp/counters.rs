//! RP cycle and execute-in-place cache counters: the `counters` contract's
//! source on RP2040 and RP2350, and the cycle count the interrupt-mode
//! budget measures with.
//!
//! **Cache.** `XIP_CTRL`'s `CTR_HIT` and `CTR_ACC` count hits and accesses
//! of the one execute-in-place cache every core and every flash-reading DMA
//! channel shares: 32-bit counters that stick at their top and clear on any
//! write (RP2350 datasheet §4.4.5, tables 452 and 453; RP2040 datasheet
//! §2.6.3.6, the same offsets). A drain reads both and clears both.
//!
//! **Cycles.** A Cortex-M33 has DWT `CYCCNT`, one per core, counting the
//! core clock. A Cortex-M0+ has no cycle counter, so on RP2040 a cycle
//! count is the 1 MHz timer scaled by the system clock in megahertz, with
//! wrapping multiplication: two counts still subtract to the cycles
//! between them, at one microsecond's resolution. The contract's own
//! `cycles` on RP2040 is the timer itself, declared as a system clock at
//! 1 MHz.

/// `CTR_HIT` within the XIP control block: cache hits.
pub const XIP_CTR_HIT: usize = 0x0c;
/// `CTR_ACC` within the XIP control block: cache accesses, hit or not.
pub const XIP_CTR_ACC: usize = 0x10;

/// A cycle count from a 1 MHz timer reading `timer_us` on a system clock of
/// `sys_mhz` megahertz. Wrapping: the difference of two counts taken less
/// than 2^32 cycles apart is the cycles between them, across a wrap of
/// either the timer or the product.
pub const fn cycles_from_timer(timer_us: u32, sys_mhz: u32) -> u32 {
    timer_us.wrapping_mul(sys_mhz)
}

#[cfg(feature = "rp")]
pub use on_chip::*;

#[cfg(feature = "rp")]
mod on_chip {
    use super::*;
    use crate::abi::contracts::counters as wire;
    use crate::kernel::sys::counters::Source;
    use crate::platform::chip;
    use crate::platform::rp_regs::{read32, write32};

    /// The system clock in megahertz.
    const SYS_MHZ: u32 = chip::SYS_CLK_HZ / 1_000_000;

    /// Enable the calling core's cycle counter, where the core has one.
    pub fn enable_cycle_counter() {
        #[cfg(not(feature = "chip-rp2040"))]
        // SAFETY: DEMCR (TRCENA) and DWT_CTRL (CYCCNTENA), this core's own
        // debug registers.
        unsafe {
            let demcr = 0xE000_EDFC as *mut u32;
            core::ptr::write_volatile(demcr, core::ptr::read_volatile(demcr) | (1 << 24));
            let dwt_ctrl = 0xE000_1000 as *mut u32;
            core::ptr::write_volatile(dwt_ctrl, core::ptr::read_volatile(dwt_ctrl) | 1);
        }
    }

    /// The calling core's cycle count: what the interrupt-mode budget
    /// subtracts two reads of.
    #[inline]
    pub fn cycle_count() -> u32 {
        #[cfg(not(feature = "chip-rp2040"))]
        // SAFETY: DWT CYCCNT, this core's own, enabled at boot.
        unsafe {
            core::ptr::read_volatile(0xE000_1004 as *const u32)
        }
        #[cfg(feature = "chip-rp2040")]
        cycles_from_timer(crate::platform::rp_timer::alarm::now_raw_lo(), SYS_MHZ)
    }

    /// The contract's `cycles` on the calling core: the core's cycle counter
    /// where it has one, the 1 MHz timer where it has none.
    fn contract_cycles() -> u32 {
        #[cfg(not(feature = "chip-rp2040"))]
        {
            cycle_count()
        }
        #[cfg(feature = "chip-rp2040")]
        crate::platform::rp_timer::alarm::now_raw_lo()
    }

    /// The rate of [`contract_cycles`].
    fn contract_cycles_hz() -> u32 {
        #[cfg(not(feature = "chip-rp2040"))]
        {
            chip::SYS_CLK_HZ
        }
        #[cfg(feature = "chip-rp2040")]
        1_000_000
    }

    /// Read and clear the cache counters; answer the live cycle count.
    fn read(drain: &mut [u32; 2]) -> (u8, u32) {
        let base = chip::XIP_CTRL_BASE as usize;
        // SAFETY: the XIP control block of this silicon; a read of each
        // counter and a write that clears it. Hits first, so the accesses
        // read are never fewer than the hits.
        unsafe {
            drain[0] = read32(base + XIP_CTR_HIT);
            drain[1] = read32(base + XIP_CTR_ACC);
            write32(base + XIP_CTR_HIT, 0);
            write32(base + XIP_CTR_ACC, 0);
        }
        (
            wire::PRESENT_CYCLES | wire::PRESENT_ICACHE,
            contract_cycles(),
        )
    }

    /// The RP counters.
    pub static SOURCE: Source = Source {
        cycles_clock: if cfg!(feature = "chip-rp2040") {
            wire::CLOCK_SYSTEM
        } else {
            wire::CLOCK_CORE
        },
        icache_scope: wire::SCOPE_NODE,
        cycles_hz: contract_cycles_hz,
        read,
    };

    const _: () = assert!(SYS_MHZ * 1_000_000 == chip::SYS_CLK_HZ);
}
