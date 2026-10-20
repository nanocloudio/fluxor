//! What a workload may hold of the node's storage, and what holding it costs.
//!
//! A workload reaches the node's storage only through what its admission
//! granted ([`StorageGrant`]), recorded on its owner: the default grant for a
//! live add or a planned owner, the header's `storage` byte for a `CREATE`.
//! Each platform's owner
//! root resolves a workload's storage through that grant and charges the
//! owner's ledger by the costs here, so a workload is granted and charged the
//! same on every node.
//!
//! A workload is never given the node's own namespace, and never a Unix
//! credential: what it may reach is a grant on its owner, and the platform
//! makes the grant real inside a root of its own.

use crate::kernel::exec::scheduler;
use crate::kernel::workload::owner::{OwnerHandle, OwnerState};

/// What a workload is granted of the node's storage.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StorageGrant {
    /// No node storage: the platform's `fs`, `storage.object` and
    /// `storage.namespace` answer the workload `EACCES`. What it keeps, it
    /// keeps in a provider of its own over a volume lent to it.
    None,
    /// A root of the owner's own on the node's storage, made on first use
    /// and removed when the owner is released. The default grant.
    OwnRoot,
}

impl StorageGrant {
    /// The grant a `CREATE` header's `storage` byte names, or `None` for a
    /// value no grant has.
    pub const fn from_wire(b: u8) -> Option<StorageGrant> {
        use crate::abi::contracts::workload as wl;
        match b {
            wl::STORAGE_OWN_ROOT => Some(StorageGrant::OwnRoot),
            wl::STORAGE_NONE => Some(StorageGrant::None),
            _ => None,
        }
    }
}

/// What a name costs its owner besides a file's bytes: an inode and a
/// directory entry.
pub const ENTRY_COST: u64 = 4096;

/// What a regular file of `size` bytes costs its owner.
pub const fn file_cost(size: u64) -> u64 {
    ENTRY_COST.saturating_add(size)
}

/// The fixed cost of one store entry besides its key and value: its log
/// record's framing and its place in the index.
pub const STORE_ENTRY_OVERHEAD: u64 = 64;

/// What one store entry costs its owner: its key, its value and
/// [`STORE_ENTRY_OVERHEAD`], so an owner cannot fill a store with keys or
/// empty values it is never charged for.
pub const fn store_entry_cost(key_len: usize, value_len: usize) -> u64 {
    STORE_ENTRY_OVERHEAD
        .saturating_add(key_len as u64)
        .saturating_add(value_len as u64)
}

/// Files one owner may hold open through its root at once, so no workload
/// can take the table the node and every other workload open files from.
pub const OWNER_MAX_OPEN_FILES: usize = 32;

/// Whether `owner`'s storage is rooted: a workload's is. The node's storage
/// is the node's own, and so is that of an owner acting with the node's
/// authority; the platform neither roots, charges nor removes it.
pub fn rooted(owner: OwnerHandle) -> bool {
    !scheduler::owners().authority_of(owner).is_system()
}

/// Whether `owner` may come to hold storage: one whose grant gives it a
/// root, being admitted or running. An owner being drained or revoked makes
/// no root, so nothing it does on its way out can bring back a root its
/// release removed.
pub fn may_hold_storage(owner: OwnerHandle) -> bool {
    !owner.is_system()
        && scheduler::owners().lookup(owner).is_some_and(|e| {
            e.acct.storage_grant == StorageGrant::OwnRoot
                && matches!(
                    e.state,
                    OwnerState::Reserved | OwnerState::Active | OwnerState::Paused
                )
        })
}
