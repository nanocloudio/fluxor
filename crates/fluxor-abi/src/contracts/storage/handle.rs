// Contract: storage/handle — leased mesh Handles for storage surfaces.
//
// Layer: contracts/storage (public, stable).
//
// Opening a namespace prefix, an object, or an event stream produces
// a *handle* — the value the caller subsequently uses to read,
// watch, or close. Storage handles compose the mesh primitives
// defined in `docs/architecture/mesh.md`:
//
//   - Handle (mesh primitive #3) — `(ObjectId, Capability,
//     LocationHint)`. The only way to touch the mesh.
//   - Lease  (mesh primitive #8) — every authority and resource
//     claim is finite unless renewed; expressed as `not_after`.
//
// A storage handle is a leased mesh Handle parameterised by the
// surface that issued it (namespace, object, stream). One revocable
// identity primitive serves every storage provider — FAT32, a local
// or distributed log-structured store, HTTP-as-FS, an S3 adapter —
// without each growing its own FD shape.
//
// ## Lifecycle
//
//   - The provider maps `(ObjectId, Capability, LocationHint)` to a
//     small integer slot index in its slot table. The integer is
//     what crosses the syscall boundary; the `StorageHandle` struct
//     is the typed Rust view inside the provider and any host-side
//     caller that has the slot mapping.
//   - A provider that binds a handle to a verified `mesh::capability`
//     grant carries the grant's object and permission bits in the
//     handle, requires the bit [`StorageAccess`] names for each op,
//     and never lets the lease outlive the grant. The providers in
//     this tree issue plain slot indices and check none of this.
//   - `not_after` is an absolute monotonic timestamp (kernel
//     `time_ns`). A provider that tracks it refuses ops with
//     `now >= not_after` and frees the slot.
//   - Revocation is provider-driven: a FAT32 unmount, a cluster
//     reconfiguration, or an explicit `revoke` from the issuer
//     flips `revoked` and frees the slot. Callers see the next op
//     fail with `EACCES` (capability invalidated) or `ENODEV` (slot
//     freed).
//
// ## Surface kinds
//
// The `kind` field carries the surface that issued the handle. A
// provider that satisfies multiple surfaces (e.g. a local FS that
// is `file.data` + `storage.namespace[readonly]`) issues handles
// with matching kinds — `kind` is what the consumer dispatches on.

use super::super::super::fence::ObjectId;

/// The longest key or entry name any storage surface carries. One bound for
/// one concept: it is the `storage.namespace` `name_len` and trailing-cursor
/// widths (a `u8`), the `storage.object` `LIST` cursor, and what the kernel
/// gateway's argument copy is sized to carry (a prefix and a cursor of this
/// length in one `LIST` request). A provider refuses to create a longer key,
/// and refuses a listing that meets one rather than skip it.
pub const STORAGE_KEY_MAX: usize = 255;

/// Surface kind a `StorageHandle` addresses. Numeric so it
/// round-trips through the `STAT` / `LIST` output buffers in
/// `namespace.rs` (`kind: u8`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleKind {
    /// Handle into the `storage.object` surface — addressable by
    /// key, readable via `GET` / `RANGE_GET`.
    Object = 0,
    /// Handle into the `storage.namespace` surface — addressable
    /// by prefix, enumerable via `LIST`, watchable via
    /// `SUBSCRIBE`.
    Namespace = 1,
    /// Handle onto a byte / event stream — the `file.data` surface
    /// or the `event.log` content-type pattern.
    Stream = 2,
}

/// What a storage operation needs from the capability it runs under.
///
/// Storage has no permission vocabulary of its own: a handle carries the
/// mesh permission bits of the grant it was opened under
/// (`mesh::capability::perm`), and each operation class needs one of them.
/// One authority model serves every object — a chain that grants a volume
/// is verified, narrowed and delegated exactly as one that grants a sensor.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageAccess {
    /// Bytes and metadata: `GET`, `HEAD`, `RANGE_GET`, `LIST`, `LOOKUP`,
    /// `STAT`.
    Read = 0,
    /// Mutation: `PUT`, the streamed put, `DELETE`, `RENAME`, `BIND`. A
    /// write is a command to the object.
    Write = 1,
    /// A change feed: `SUBSCRIBE`, `CHANGES`.
    Subscribe = 2,
    /// Handing a narrower grant on to another holder.
    Delegate = 3,
}

impl StorageAccess {
    /// The mesh permission bit this access needs.
    pub const fn permission(self) -> u16 {
        use super::super::mesh::capability::perm;
        match self {
            Self::Read => perm::READ_STATE,
            Self::Write => perm::SEND_COMMAND,
            Self::Subscribe => perm::SUBSCRIBE,
            Self::Delegate => perm::DELEGATE,
        }
    }
}

/// Opaque location hint — the mesh's `LocationHint` round-tripped
/// here as a fixed-size byte blob so this contract does not pull
/// the mesh implementation in. Providers encode whatever address
/// shape they need (device path, peer node id, URL fingerprint)
/// up to 16 bytes; longer hints are truncated and the consumer
/// falls back to discovery.
pub type LocationHintBlob = [u8; 16];

/// Leased mesh Handle specialised for storage surfaces.
///
/// The Rust view of a storage handle inside a provider or a
/// host-side caller that has access to the slot table. Across the
/// kernel syscall boundary the provider exposes a small i32 slot
/// index — the typed handle is reconstituted from the slot on
/// entry.
#[derive(Clone, Copy, Debug)]
pub struct StorageHandle {
    /// Mesh object identity this handle addresses.
    pub object: ObjectId,
    /// Surface kind — gates which contract opcodes apply.
    pub kind: HandleKind,
    /// The mesh permission bits of the grant the handle was opened under
    /// (`mesh::capability::Grant::permissions`).
    pub permissions: u16,
    /// Provider-local slot index — the value that crosses the
    /// syscall boundary as the `handle` argument.
    pub slot: u16,
    /// Absolute lease expiry, in the same monotonic clock the
    /// kernel uses for `time_ns`. A provider that tracks it MUST refuse
    /// ops with `now >= not_after` and free the slot. A handle opened under
    /// a capability never outlives its grant: see [`lease_bound_ns`].
    pub not_after: u64,
    /// Opaque mesh `LocationHint` blob. Zero-filled when the
    /// handle is local-only.
    pub hint: LocationHintBlob,
    /// Revoked flag — set by the issuer or the provider on
    /// unmount / reconfigure / explicit revoke.
    pub revoked: bool,
}

impl StorageHandle {
    /// True iff the handle's lease still covers `now_ns` and the
    /// handle has not been revoked.
    pub fn is_live(&self, now_ns: u64) -> bool {
        !self.revoked && now_ns < self.not_after
    }

    /// True iff the handle's grant carries what `access` needs.
    pub fn allows(&self, access: StorageAccess) -> bool {
        let need = access.permission();
        self.permissions & need == need
    }
}

/// The monotonic instant a grant expiring at `grant_not_after` (unix
/// seconds) ends, given one `TRUSTED_UNIX` reading `(unix_seconds,
/// monotonic_us)` taken at a single instant. A provider minting a handle
/// under a grant takes the earlier of this and its own lease, so the handle
/// dies with the grant even if the wall clock is later stepped.
pub const fn lease_bound_ns(grant_not_after: u32, unix_seconds: u64, monotonic_us: u64) -> u64 {
    let now_ns = monotonic_us.saturating_mul(1000);
    let remaining_s = (grant_not_after as u64).saturating_sub(unix_seconds);
    now_ns.saturating_add(remaining_s.saturating_mul(1_000_000_000))
}
