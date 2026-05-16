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
// identity primitive serves every storage provider — FAT32,
// Loam-local, Loam-distributed, HTTP-as-FS, S3 adapter — without
// each growing its own FD shape.
//
// ## Lifecycle
//
//   - The provider maps `(ObjectId, Capability, LocationHint)` to a
//     small integer slot index in its slot table. The integer is
//     what crosses the syscall boundary; the `StorageHandle` struct
//     is the typed Rust view inside the provider and any host-side
//     caller that has the slot mapping.
//   - `not_after` is an absolute monotonic timestamp (kernel
//     `time_ns`). Providers refuse ops with `now >= not_after` and
//     free the slot.
//   - Revocation is provider-driven: a FAT32 unmount, a Clustor
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

use super::super::fence::ObjectId;

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

/// Permission bits the storage capability advertises. Subset of the
/// mesh `Permission` flags, narrowed to what storage ops actually
/// gate on. Carried in `StorageHandle::permissions`.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoragePerm {
    /// Read the entry's bytes / metadata.
    Read = 1 << 0,
    /// Write / put / rename / delete.
    Write = 1 << 1,
    /// Open a subscription on this entry / prefix.
    Subscribe = 1 << 2,
    /// Delegate this capability to another principal.
    Delegate = 1 << 3,
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
    /// OR-combined `StoragePerm` flags.
    pub permissions: u16,
    /// Provider-local slot index — the value that crosses the
    /// syscall boundary as the `handle` argument.
    pub slot: u16,
    /// Absolute lease expiry, in the same monotonic clock the
    /// kernel uses for `time_ns`. Providers MUST refuse ops with
    /// `now >= not_after` and free the slot.
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

    /// True iff the caller may exercise `perm`.
    pub fn has(&self, perm: StoragePerm) -> bool {
        (self.permissions & (perm as u16)) != 0
    }
}
