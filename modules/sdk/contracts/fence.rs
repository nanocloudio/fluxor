// Contract: fence — per-op durability and ordering advertisement.
//
// Layer: contracts (public, stable).
//
// Two providers can satisfy the same capability-surface content type
// (e.g. `file.data` or `storage.object`) while differing wildly in
// what their successful return actually guarantees:
//
//   - A local POSIX file write returns "ok" the moment the kernel
//     page cache holds the bytes — durability is none until the next
//     sync.
//   - A FAT32 driver over an SD card returns "ok" once the FAT block
//     has been flushed — local durability against a specific device.
//   - A Clustor-replicated put returns "ok" once a quorum has
//     accepted a particular log position — durability against a
//     configured cluster.
//   - A content-addressed read returns the exact bytes whose hash is
//     `digest` — durability is the hash itself, not a device.
//   - A view over a versioned object returns "ok" relative to a
//     named revision of a named source — durability is bounded by
//     the source's revision log.
//
// "Ok / errno" cannot express any of that. The `Fence` enum carries
// it: every storage op that completes successfully returns the
// strongest fence the provider actually achieved. Consumers store
// it, gossip it, or refuse to proceed until the achieved fence
// dominates the fence they require.
//
// This is the load-bearing invariant for substitution. Providers
// may share a surface name and differ in fence strength; the fence
// is what makes the substitution honest.
//
// ## Source identity is part of the fence
//
// `ReplicatedDurable`, `RevisionMonotone`, and `ViewConsistent` carry
// an explicit `source: ObjectId`. Without it, two unrelated logs at
// the same revision, or two replicated groups at the same epoch,
// would compare as dominating each other — a correctness flaw for
// substitution. `source` names the log, the replicated-state-machine
// id, or the namespace root the fence refers to.
//
// ## Wire encoding
//
// `Fence` is both a typed Rust value and a stable byte encoding so
// the kernel `provider_query` surface can return one fence value per
// op. The encoding is little-endian and prefix-tagged; `encode` and
// `decode` are the only supported entry points. `WIRE_MAX_LEN` is
// the upper bound on the encoded size of any `Fence` instance and is
// what callers size their output buffer to.
//
// Cross-references:
//   - `docs/architecture/storage_capability_surface.md` — surface
//     family, leased handles, event.log pattern.
//   - `docs/architecture/mesh.md` — Object Identity, Handle, Lease.
//   - `docs/architecture/capability_surface.md` — canonical taxonomy.
//   - `kernel_abi::query_key::LAST_FENCE` — the introspection key
//     callers use to ask a provider for the fence on a handle.

use core::cmp::Ordering;

/// Opaque cluster witness blob set by the replicating provider
/// (Clustor or equivalent). 32 bytes accommodates a SHA-256
/// commitment, a serialized lease id, or a short signature digest
/// while staying `Copy` so `Fence` can live on the stack of any
/// storage op return path.
pub type Witness = [u8; 32];

/// 128-bit object identity (matches mesh `ObjectId`). Repeated here
/// so the fence module does not pull in `foundation::mesh` types;
/// the byte layout is the same.
pub type ObjectId = [u8; 16];

/// 256-bit digest container. Holds a sha256 or sha3-256 result in
/// the leading 32 bytes. Wider hashes (sha384/sha512) are not
/// representable here — content-addressed providers that need them
/// add a separate variant rather than silently truncating.
pub type Digest32 = [u8; 32];

/// Hash algorithm identifier. Numeric so wire serializers encode it
/// as a single byte.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-256 — default for content-addressed storage.
    Sha256 = 0,
    /// SHA3-256 — for providers that elect SHA-3 over SHA-2.
    Sha3_256 = 1,
    /// BLAKE3-256 — for content-defined chunking providers.
    Blake3_256 = 2,
}

impl HashAlg {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(HashAlg::Sha256),
            1 => Some(HashAlg::Sha3_256),
            2 => Some(HashAlg::Blake3_256),
            _ => None,
        }
    }
}

/// 64-bit device identifier. Providers pick a stable id per backing
/// device (NVMe namespace UUID truncated, SD card serial, etc.). The
/// fence does not interpret this — consumers use it only to
/// disambiguate "durable on device A" from "durable on device B".
pub type DeviceId = u64;

/// Per-op durability and ordering advertisement.
///
/// A storage op that completes successfully returns the strongest
/// fence it actually achieved. "Strongest" is partial: `LocalDurable`
/// on device A is not ordered against `LocalDurable` on device B,
/// `ReplicatedDurable` against one log is not ordered against
/// `ReplicatedDurable` against another, and `ContentHashed` is
/// orthogonal to `LocalDurable` — both are meaningful, neither
/// dominates the other. See `dominates` for the partial order.
///
/// Variants are `Copy` so this type returns by value from inner
/// loops without forcing allocation on no_std targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fence {
    /// No durability guarantee. The op observed the requested state
    /// transition in volatile memory; a power loss or reset may
    /// erase it. Plain reads, in-RAM caches, and not-yet-flushed
    /// writes land here.
    Volatile,

    /// Durability against a specific local device. The bytes
    /// survived the provider's flush path on the named device — a
    /// `fsync` on a POSIX fd, a FAT32 dirty-block writeback, an
    /// NVMe sync write. Two `LocalDurable` values with different
    /// `device_id`s are not comparable.
    LocalDurable { device_id: DeviceId },

    /// Durability against a quorum-replicated cluster. The op has
    /// been accepted by enough replicas to survive any failure the
    /// cluster is configured to tolerate.
    ///
    /// - `source` identifies the replicated log / state machine the
    ///   commitment applies to. Cross-source comparisons are never
    ///   meaningful.
    /// - `commit_index` is the monotone log position *within* an
    ///   epoch. Refinement is by `commit_index`: at the same
    ///   `(source, epoch)`, `commit_index=10` dominates
    ///   `commit_index=5`. Indices are not monotone across epochs
    ///   because a reconfiguration may have rewound the log.
    /// - `epoch` is the membership / reconfiguration generation of
    ///   the replicating group. Dominance requires same epoch;
    ///   cross-epoch comparisons are not expressible by this fence
    ///   alone and require a separate reconfiguration log.
    /// - `quorum` is the size of the accepting set — informational,
    ///   not part of the dominance relation.
    /// - `witness` is the opaque commitment the cluster issues.
    ///   Same `(source, epoch, commit_index)` with mismatched
    ///   `witness` indicates a fork; `dominates` returns false on a
    ///   fork rather than treating divergent histories as ordered.
    ReplicatedDurable {
        source: ObjectId,
        commit_index: u64,
        epoch: u32,
        quorum: u8,
        witness: Witness,
    },

    /// Content-addressed integrity. The bytes returned (or written)
    /// hash to `digest` under `algorithm`. Durability is the hash
    /// itself — as long as anyone holds bytes that satisfy
    /// `(algorithm, digest)`, the fence is met. The shape CAS
    /// stores (Loam-local, Loam-distributed, content trees)
    /// advertise.
    ContentHashed {
        algorithm: HashAlg,
        digest: Digest32,
    },

    /// Monotone revision against an upstream source. `source` is
    /// the object whose revision counter is being observed
    /// (typically the event-log root); `revision` is its sequence
    /// number. Two `RevisionMonotone` results with the same
    /// `source` are totally ordered by `revision`. Event-log
    /// providers (Loam WAL, Clustor log, generic append logs) emit
    /// this once a write is committed to a particular position.
    RevisionMonotone { source: ObjectId, revision: u64 },

    /// View-consistent read against a named source. The read
    /// reflects a specific revision of `source`; subsequent reads
    /// against the same view return the same bytes for the same
    /// key. Cheaper than `RevisionMonotone` because no commit has
    /// happened — emitted by `get` / `range_get` / `list` to
    /// advertise the snapshot they observed. Views from unrelated
    /// sources never dominate each other regardless of revision.
    ViewConsistent { source: ObjectId, revision: u64 },
}

impl Fence {
    /// True iff `self` is at least as strong as `other` along the
    /// dimension `other` measures. Cross-dimension fences (e.g.
    /// `LocalDurable` vs `ContentHashed`) are incomparable —
    /// neither dominates the other, both are meaningful, and a
    /// consumer that needs guarantees along multiple dimensions
    /// accumulates fences rather than comparing them.
    ///
    /// Same-dimension dominance always requires the same identity:
    /// same `device_id` for `LocalDurable`, same `source` (and same
    /// `epoch` for `ReplicatedDurable`) for the source-tagged
    /// variants, same `(algorithm, digest)` for `ContentHashed`.
    pub fn dominates(self, other: Fence) -> bool {
        use self::Fence::*;
        match (self, other) {
            (Volatile, Volatile) => true,
            (_, Volatile) => true,
            (LocalDurable { device_id: a }, LocalDurable { device_id: b }) => a == b,
            (
                ReplicatedDurable {
                    source: sa,
                    commit_index: ca,
                    epoch: ea,
                    witness: wa,
                    ..
                },
                ReplicatedDurable {
                    source: sb,
                    commit_index: cb,
                    epoch: eb,
                    witness: wb,
                    ..
                },
            ) => {
                if sa != sb || ea != eb {
                    return false;
                }
                if ca > cb {
                    return true;
                }
                if ca == cb {
                    return wa == wb;
                }
                false
            }
            (
                ContentHashed {
                    algorithm: aa,
                    digest: da,
                },
                ContentHashed {
                    algorithm: ab,
                    digest: db,
                },
            ) => aa == ab && da == db,
            (
                RevisionMonotone {
                    source: sa,
                    revision: ra,
                },
                RevisionMonotone {
                    source: sb,
                    revision: rb,
                },
            ) => sa == sb && ra >= rb,
            (
                ViewConsistent {
                    source: sa,
                    revision: ra,
                },
                ViewConsistent {
                    source: sb,
                    revision: rb,
                },
            ) => sa == sb && ra >= rb,
            _ => false,
        }
    }

    /// Coarse ordering on the *kind* of fence, for telemetry that
    /// wants to render fence strength without interpreting the
    /// payload. Not a substitute for `dominates`.
    pub fn kind_rank(self) -> u8 {
        match self {
            Fence::Volatile => 0,
            Fence::ViewConsistent { .. } => 1,
            Fence::LocalDurable { .. } => 2,
            Fence::RevisionMonotone { .. } => 3,
            Fence::ContentHashed { .. } => 4,
            Fence::ReplicatedDurable { .. } => 5,
        }
    }
}

impl PartialOrd for Fence {
    /// `partial_cmp` returns `Some(_)` only when the two fences are
    /// on the same dimension and same identity; otherwise `None`.
    /// `dominates` is the boolean form most callers want.
    fn partial_cmp(&self, other: &Fence) -> Option<Ordering> {
        if self == other {
            Some(Ordering::Equal)
        } else if self.dominates(*other) {
            Some(Ordering::Greater)
        } else if other.dominates(*self) {
            Some(Ordering::Less)
        } else {
            None
        }
    }
}

// ─── Wire encoding ───────────────────────────────────────────────────
//
// Little-endian and prefix-tagged. First byte is the variant tag
// (`TAG_*`); remaining bytes are the variant payload. Layouts:
//
//   TAG_VOLATILE             :  1 byte  — tag only
//   TAG_LOCAL_DURABLE        :  9 bytes — tag, device_id (u64 LE)
//   TAG_REPLICATED_DURABLE   : 62 bytes — tag, source (16),
//                                         commit_index (u64 LE),
//                                         epoch (u32 LE),
//                                         quorum (u8), witness (32)
//   TAG_CONTENT_HASHED       : 34 bytes — tag, algorithm (1),
//                                         digest (32)
//   TAG_REVISION_MONOTONE    : 25 bytes — tag, source (16),
//                                         revision (u64 LE)
//   TAG_VIEW_CONSISTENT      : 25 bytes — tag, source (16),
//                                         revision (u64 LE)
//
// `WIRE_MAX_LEN` is the cap (62 — the `ReplicatedDurable` variant);
// callers size their `provider_query` output buffer to that constant
// rather than hardcoding the number.

pub const TAG_VOLATILE: u8 = 0;
pub const TAG_LOCAL_DURABLE: u8 = 1;
pub const TAG_REPLICATED_DURABLE: u8 = 2;
pub const TAG_CONTENT_HASHED: u8 = 3;
pub const TAG_REVISION_MONOTONE: u8 = 4;
pub const TAG_VIEW_CONSISTENT: u8 = 5;

/// Upper bound on the encoded byte length of any `Fence` instance.
/// Callers size their `provider_query(handle, LAST_FENCE, …)` output
/// buffer to at least this value. Dominated by `ReplicatedDurable`:
/// tag(1) + source(16) + commit_index(8) + epoch(4) + quorum(1) +
/// witness(32) = 62.
pub const WIRE_MAX_LEN: usize = 62;

/// Provider-dispatch opcode every storage / file / namespace /
/// object provider answers to return the most recent `Fence` it
/// advertised on `handle`.
///
/// The public API for consumers is
/// `provider_query(handle, kernel_abi::query_key::LAST_FENCE, …)`;
/// the kernel forwards that as `provider::provider_call(handle,
/// QUERY_OP, out, out_len)`. Routing through `provider_call` is the
/// load-bearing piece: it resolves the contract from the FD tag and
/// invokes the contract's vtable, which strips the tag before
/// re-entering the provider dispatch. PIC modules answer this
/// opcode through the same dispatch function they already export —
/// no separate query-callback ABI.
///
/// Contract:
///   - `arg` is the output buffer pointer; `arg_len` is its
///     capacity. Providers require `arg_len >= WIRE_MAX_LEN`.
///   - On success the provider writes the prefix-tagged
///     `Fence::encode` bytes into `arg` and returns the byte count.
///   - For a handle the provider does not own (closed, stale, or
///     out of range) the provider returns `ENOSYS`. `EINVAL` is
///     reserved for malformed calls (null `arg`, undersized
///     `arg_len`).
///
/// Class byte 0x00 (COMMON) is intentional — fence query is
/// cross-cutting and the contract is resolved from the handle's FD
/// tag rather than from the opcode class byte.
pub const QUERY_OP: u32 = 0x00FE;

impl Fence {
    /// Encode the fence into `buf`. Returns the number of bytes
    /// written, or `None` if `buf` is too small.
    pub fn encode(&self, buf: &mut [u8]) -> Option<usize> {
        match *self {
            Fence::Volatile => {
                if buf.is_empty() {
                    return None;
                }
                buf[0] = TAG_VOLATILE;
                Some(1)
            }
            Fence::LocalDurable { device_id } => {
                if buf.len() < 9 {
                    return None;
                }
                buf[0] = TAG_LOCAL_DURABLE;
                buf[1..9].copy_from_slice(&device_id.to_le_bytes());
                Some(9)
            }
            Fence::ReplicatedDurable {
                source,
                commit_index,
                epoch,
                quorum,
                witness,
            } => {
                if buf.len() < 62 {
                    return None;
                }
                buf[0] = TAG_REPLICATED_DURABLE;
                buf[1..17].copy_from_slice(&source);
                buf[17..25].copy_from_slice(&commit_index.to_le_bytes());
                buf[25..29].copy_from_slice(&epoch.to_le_bytes());
                buf[29] = quorum;
                buf[30..62].copy_from_slice(&witness);
                Some(62)
            }
            Fence::ContentHashed { algorithm, digest } => {
                if buf.len() < 34 {
                    return None;
                }
                buf[0] = TAG_CONTENT_HASHED;
                buf[1] = algorithm as u8;
                buf[2..34].copy_from_slice(&digest);
                Some(34)
            }
            Fence::RevisionMonotone { source, revision } => {
                if buf.len() < 25 {
                    return None;
                }
                buf[0] = TAG_REVISION_MONOTONE;
                buf[1..17].copy_from_slice(&source);
                buf[17..25].copy_from_slice(&revision.to_le_bytes());
                Some(25)
            }
            Fence::ViewConsistent { source, revision } => {
                if buf.len() < 25 {
                    return None;
                }
                buf[0] = TAG_VIEW_CONSISTENT;
                buf[1..17].copy_from_slice(&source);
                buf[17..25].copy_from_slice(&revision.to_le_bytes());
                Some(25)
            }
        }
    }

    /// Decode a `Fence` from `buf`. Returns the parsed fence and
    /// the number of bytes consumed, or `None` if the tag is
    /// unknown or the buffer is short. Unknown tags are not
    /// promoted to `Volatile` — consumers MUST treat decode failure
    /// as "no recognised fence" and refuse to proceed.
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        let tag = *buf.first()?;
        match tag {
            TAG_VOLATILE => Some((Fence::Volatile, 1)),
            TAG_LOCAL_DURABLE => {
                if buf.len() < 9 {
                    return None;
                }
                let mut id_b = [0u8; 8];
                id_b.copy_from_slice(&buf[1..9]);
                Some((
                    Fence::LocalDurable {
                        device_id: u64::from_le_bytes(id_b),
                    },
                    9,
                ))
            }
            TAG_REPLICATED_DURABLE => {
                if buf.len() < 62 {
                    return None;
                }
                let mut source = [0u8; 16];
                source.copy_from_slice(&buf[1..17]);
                let mut ci_b = [0u8; 8];
                ci_b.copy_from_slice(&buf[17..25]);
                let mut ep_b = [0u8; 4];
                ep_b.copy_from_slice(&buf[25..29]);
                let quorum = buf[29];
                let mut witness = [0u8; 32];
                witness.copy_from_slice(&buf[30..62]);
                Some((
                    Fence::ReplicatedDurable {
                        source,
                        commit_index: u64::from_le_bytes(ci_b),
                        epoch: u32::from_le_bytes(ep_b),
                        quorum,
                        witness,
                    },
                    62,
                ))
            }
            TAG_CONTENT_HASHED => {
                if buf.len() < 34 {
                    return None;
                }
                let algorithm = HashAlg::from_u8(buf[1])?;
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&buf[2..34]);
                Some((Fence::ContentHashed { algorithm, digest }, 34))
            }
            TAG_REVISION_MONOTONE => {
                if buf.len() < 25 {
                    return None;
                }
                let mut source = [0u8; 16];
                source.copy_from_slice(&buf[1..17]);
                let mut rev_b = [0u8; 8];
                rev_b.copy_from_slice(&buf[17..25]);
                Some((
                    Fence::RevisionMonotone {
                        source,
                        revision: u64::from_le_bytes(rev_b),
                    },
                    25,
                ))
            }
            TAG_VIEW_CONSISTENT => {
                if buf.len() < 25 {
                    return None;
                }
                let mut source = [0u8; 16];
                source.copy_from_slice(&buf[1..17]);
                let mut rev_b = [0u8; 8];
                rev_b.copy_from_slice(&buf[17..25]);
                Some((
                    Fence::ViewConsistent {
                        source,
                        revision: u64::from_le_bytes(rev_b),
                    },
                    25,
                ))
            }
            _ => None,
        }
    }
}
