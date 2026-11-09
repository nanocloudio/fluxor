//! The Linux platform's owner release, library half.
//!
//! The kernel delivers one release edge for every owner it frees
//! (`provider::notify_owner_released`, at the top of
//! `scheduler::free_owner`), whichever path freed it: the drain driver, the
//! workload verbs (KILL/DESTROY), `reconfigure::FREE_OWNER`, admission
//! rollback. The runtime's owner-release hook answers it here, so what an
//! owner holds through this library's providers goes with the owner on every
//! one of those paths, and no path has to remember to close anything itself.

use crate::kernel::workload::owner::OwnerHandle;

/// Release everything `owner` holds through this library's providers, while
/// the owner still resolves: its network endpoints first, so nothing still
/// accepts for an owner that is going; then its host-process workloads and
/// the terminal sessions it opened into them, so no host process outlives
/// it; then its root and what it opened through it (`owner_root::release`).
pub fn release_owner(owner: OwnerHandle) {
    if owner.is_system() {
        return;
    }
    super::providers::linux_net_close_owner_conns(owner);
    super::workload::linux_workload_close_owner(owner);
    // SAFETY: owner release runs on the scheduler thread, as every dispatch.
    unsafe {
        super::host_backend::hp_tty_release_owner(owner);
    }
    super::owner_root::release(owner);
}
