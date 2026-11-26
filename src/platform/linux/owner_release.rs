//! The Linux platform's owner release, library half.
//!
//! The kernel delivers one release edge for every owner it frees
//! (`provider::notify_owner_released`, at the top of
//! `scheduler::free_owner`), whichever path freed it: the drain driver, the
//! workload verbs (KILL/DESTROY), `reconfigure::FREE_OWNER`, admission
//! rollback. The `workload` provider observes it (`OWNER_RELEASED`) and
//! answers it here, so what an owner holds through this library's providers
//! goes with the owner on every one of those paths, and no path has to
//! remember to close anything itself.

use crate::kernel::workload::owner::OwnerHandle;

/// Release everything `owner` holds through this library's providers, while
/// the owner still resolves: its host-process workloads and the terminal
/// sessions it opened into them, so no host process outlives it; then the
/// host files and processes an owner acting with the node's authority opened
/// and spawned. Its network endpoints are the network provider's, which
/// observes the same release through its `host_lane` and has let go of them
/// when its observer returns.
pub fn release_owner(owner: OwnerHandle) {
    if owner.is_node() {
        return;
    }
    super::workload::linux_workload_close_owner(owner);
    // SAFETY: owner release runs on the scheduler thread, as every dispatch.
    unsafe {
        super::host_backend::hp_tty_release_owner(owner);
        super::providers::release_owner_files(owner);
        super::providers::release_owner_procs(owner);
    }
}
