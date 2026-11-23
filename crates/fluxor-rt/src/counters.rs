//! The module side of the `counters` contract
//! (`abi::contracts::counters`): the cycle counter and instruction-cache
//! counts, read around a region of the module's own code.
//!
//! A module reaches them with `grants = ["counters"]`. Every count wraps:
//! subtract two readings with `elapsed`. A reading costs cycles of its own,
//! which `calibrate` measures the way this module pays them (directly, or
//! through the gateway when it is gated), for a probe to subtract.

use crate::*;
use abi::contracts::counters as wire;

pub use wire::{
    Description, Reading, CLOCK_CORE, CLOCK_SYSTEM, PRESENT_CYCLES, PRESENT_ICACHE, SCOPE_CORE,
    SCOPE_NODE, SCOPE_NONE,
};

/// Back-to-back reads `calibrate` makes.
pub const CALIBRATE_READS: usize = 16;

/// What this target's counters are. `None` when the call is refused (no
/// grant) or the answer is not one the contract admits.
pub unsafe fn describe(sys: &SyscallTable) -> Option<Description> {
    let mut buf = [0u8; wire::DESCRIBE_SIZE];
    let rc = (sys.provider_call)(
        -1,
        wire::DESCRIBE,
        buf.as_mut_ptr(),
        buf.len(),
        core::ptr::null_mut(),
        0,
    );
    if rc < 0 {
        return None;
    }
    wire::decode_describe(&buf)
}

/// The counts now. `None` when the call is refused or the record is not
/// one the contract admits.
#[inline(always)]
pub unsafe fn read(sys: &SyscallTable) -> Option<Reading> {
    let mut buf = [0u8; wire::READ_SIZE];
    let rc = (sys.provider_call)(
        -1,
        wire::READ,
        buf.as_mut_ptr(),
        buf.len(),
        core::ptr::null_mut(),
        0,
    );
    if rc < 0 {
        return None;
    }
    wire::decode_read(&buf)
}

/// What ran between two readings, `before` first.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Elapsed {
    pub cycles: u32,
    pub icache_hit: u32,
    pub icache_access: u32,
}

/// The counts between `before` and `after`, each with wrapping arithmetic.
pub const fn elapsed(before: &Reading, after: &Reading) -> Elapsed {
    Elapsed {
        cycles: after.cycles.wrapping_sub(before.cycles),
        icache_hit: after.icache_hit.wrapping_sub(before.icache_hit),
        icache_access: after.icache_access.wrapping_sub(before.icache_access),
    }
}

/// The cycles one `read` costs this module: the smallest difference
/// between consecutive readings over `CALIBRATE_READS` back-to-back reads.
/// `None` when a read is refused or the target has no cycle counter.
pub unsafe fn calibrate(sys: &SyscallTable) -> Option<u32> {
    let mut last = read(sys)?;
    if last.present & PRESENT_CYCLES == 0 {
        return None;
    }
    let mut least = u32::MAX;
    let mut i = 1;
    while i < CALIBRATE_READS {
        let now = read(sys)?;
        least = least.min(now.cycles.wrapping_sub(last.cycles));
        last = now;
        i += 1;
    }
    Some(least)
}
