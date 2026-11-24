//! Execution domains on their cores: the loop a core runs for its domain, the
//! bridges between domains on different cores, and the quiesce that parks
//! every other core while the primary changes the graph.
//!
//! A target maps each domain to a core ([`core_map`]); the boot core runs
//! domain 0. The platform starts its cores and enters [`run`] on each
//! secondary; everything that decides what a pass does is here, so every
//! platform with more than one core steps a graph the same way. What differs
//! is passed in as a [`Platform`]: how a core waits, wakes and parks, which
//! domains have a core, and the housekeeping a platform does after each pass
//! and after a domain's modules step.
//!
//! Boot, on the primary: [`install`], `prepare_graph`, then
//! [`cross::bridge_edges`], then [`instantiate`] (or the platform's own
//! instantiation and [`record_module_counts`]), then [`coreless_domain`] (a
//! graph with a domain no core runs is refused), then [`release`] (the
//! secondaries enter their loops), then the primary's loop: [`run`] for
//! domain 0, or the platform's own loop over core 0's domains.

pub mod core_map;
/// Compiled beside [`quiesce`], whose core count it shares.
#[cfg(target_has_atomic = "32")]
pub mod primary_call;
/// Compiled where the processor has compare-and-swap: a target without it
/// (ARMv6-M) runs every domain on one loop and has no other core to park.
#[cfg(target_has_atomic = "32")]
pub mod quiesce;

#[cfg(all(feature = "smp", target_os = "none"))]
pub mod cross;

#[cfg(all(feature = "smp", target_os = "none"))]
pub use self::smp::*;

/// The core this build runs `domain` on.
pub const fn domain_core(domain: usize) -> usize {
    core_map::core_of(&crate::platform::chip::DOMAIN_CORES, domain)
}

/// Whether an edge between domains `from` and `to` crosses cores in this
/// build.
pub const fn crosses_cores(from: usize, to: usize) -> bool {
    core_map::crosses_cores(&crate::platform::chip::DOMAIN_CORES, from, to)
}

/// The domains `core`'s loop passes over in this build, a bit per domain.
pub const fn core_domains(core: usize) -> u8 {
    core_map::domains_of(&crate::platform::chip::DOMAIN_CORES, core)
}

/// The loop, the instantiation and the quiesce entry points of a kernel that
/// runs domains on more than one core.
#[cfg(all(feature = "smp", target_os = "none"))]
mod smp;
