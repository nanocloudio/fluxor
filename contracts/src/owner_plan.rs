//! The owner plan: which owner holds which module and edge ranges, which
//! owners are draining out, and what each owner is granted. The
//! composer encodes it, the kernel decodes and applies it; this is the one
//! codec both link.
//!
//! ```text
//! header   magic "FLXP" | generation u64
//! section  tag u32 | len u32 | count u32 | records[count]      (len = 4 + records)
//! digest   SHA-256 over every byte before it
//! ```
//!
//! Every field is little-endian. The three sections `ASGN`, `RVOK` and `GRNT`
//! each appear exactly once, in any order; an empty section has count 0. An
//! unknown, repeated or missing section, a length that disagrees with its
//! count, or any byte between the last section and the digest refuses the
//! plan. Records:
//!
//! ```text
//! ASGN  owner_uid [16] | slot u16 | generation u32 | module_base u16
//!       | module_count u16 | edge_base u16 | edge_count u16
//!       | state_cap u32 | buffer_cap u32                          (38 B)
//! RVOK  an ASGN record | grace_secs u16 | deadline_unix u64       (48 B)
//! GRNT  slot u16 | generation u32 | kind u16 | len u16 | bytes[len]   (10 B + len)
//! ```
//!
//! A grant is opaque here and to the kernel, which hands an owner's grants
//! to the module serving that owner's lanes (`OWNER_GRANTS`); its `kind`
//! and bytes are defined by the contract that module serves
//! (`net_proto::grant`).
//!
//! The crate links no hash: the caller passes the SHA-256 it already has to
//! [`decode`] and [`encode`]. Decoding allocates nothing; a [`Plan`] reads
//! its records from the bytes it verified. Whether a plan fits the owner
//! table it is applied to (slots, overlaps, rollback) is the applier's check,
//! not the codec's.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// `"FLXP"` read as a little-endian u32.
pub const MAGIC: u32 = u32::from_le_bytes(*b"FLXP");

/// Bytes of the plan header.
pub const HEADER_LEN: usize = 12;

/// Bytes of a section's `tag | len | count` head.
pub const SECTION_HEAD_LEN: usize = 12;

/// Bytes of the trailing digest.
pub const DIGEST_LEN: usize = 32;

/// Section tags: four ASCII bytes, read as a little-endian u32.
pub mod tag {
    /// Owner placements.
    pub const ASSIGNMENTS: u32 = u32::from_le_bytes(*b"ASGN");
    /// Owners draining out.
    pub const REVOCATIONS: u32 = u32::from_le_bytes(*b"RVOK");
    /// Per-owner grants.
    pub const GRANTS: u32 = u32::from_le_bytes(*b"GRNT");

    /// Every section a plan carries, each exactly once.
    pub const ALL: [u32; 3] = [ASSIGNMENTS, REVOCATIONS, GRANTS];
}

/// Bytes of one assignment record.
pub const ASSIGNMENT_LEN: usize = 38;
/// Bytes of one revocation record.
pub const REVOCATION_LEN: usize = ASSIGNMENT_LEN + 10;
/// Bytes of a grant record before its bytes.
pub const GRANT_HEAD: usize = 10;

/// The most bytes one grant carries.
pub const MAX_GRANT_BYTES: usize = 255;

/// The most grants a plan carries: one per `(protocol, port)` a node can
/// grant, tcp and udp, nonzero ports.
pub const MAX_GRANTS: usize = 2 * u16::MAX as usize;

/// One owner placement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Assignment {
    pub owner_uid: [u8; 16],
    pub slot: u16,
    pub generation: u32,
    pub module_base: u16,
    pub module_count: u16,
    pub edge_base: u16,
    pub edge_count: u16,
    pub state_cap: u32,
    pub buffer_cap: u32,
}

/// A departing owner's last assignment and its drain window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Revocation {
    pub assignment: Assignment,
    pub grace_secs: u16,
    pub deadline_unix: u64,
}

/// A grant to owner `(slot, generation)`: `kind` and its bytes, opaque here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Grant<'a> {
    pub slot: u16,
    pub generation: u32,
    pub kind: u16,
    pub bytes: &'a [u8],
}

/// The grant records in `section`, in order. The decoder has walked them
/// already, so a short tail cannot occur; it ends the walk.
fn grant_records(section: &[u8]) -> impl Iterator<Item = Grant<'_>> + Clone + '_ {
    let mut at = 0usize;
    core::iter::from_fn(move || {
        let len = le16(section, at + 8) as usize;
        let body = section.get(at + GRANT_HEAD..at + GRANT_HEAD + len)?;
        let g = Grant {
            slot: le16(section, at),
            generation: le32(section, at + 2),
            kind: le16(section, at + 6),
            bytes: body,
        };
        at += GRANT_HEAD + len;
        Some(g)
    })
}

/// The bytes `count` grant records take at the head of `records`, or `None`
/// when they run past it or one carries more than [`MAX_GRANT_BYTES`].
fn grants_len(records: &[u8], count: usize) -> Option<usize> {
    let mut at = 0usize;
    for _ in 0..count {
        if records.len() < at + GRANT_HEAD {
            return None;
        }
        let len = le16(records, at + 8) as usize;
        if len > MAX_GRANT_BYTES {
            return None;
        }
        at += GRANT_HEAD + len;
        if at > records.len() {
            return None;
        }
    }
    Some(at)
}

/// Why a plan was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    BadMagic {
        found: u32,
    },
    /// The bytes end inside the header, a section or the digest.
    Truncated,
    UnknownSection {
        tag: u32,
        offset: usize,
    },
    DuplicateSection {
        tag: u32,
        offset: usize,
    },
    MissingSection {
        tag: u32,
    },
    /// A section's length disagrees with its count.
    LengthMismatch {
        tag: u32,
    },
    /// A section holds more records than the plan's limit.
    TooMany {
        tag: u32,
        count: usize,
        max: usize,
    },
    DigestMismatch,
}

impl PlanError {
    /// A short name for the refusal, for a log line that carries no
    /// formatting machinery (a microcontroller kernel).
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match *self {
            Self::BadMagic { .. } => "magic",
            Self::Truncated => "truncated",
            Self::UnknownSection { .. } => "unknown section",
            Self::DuplicateSection { .. } => "repeated section",
            Self::MissingSection { .. } => "missing section",
            Self::LengthMismatch { .. } => "length disagrees with count",
            Self::TooMany { .. } => "too many records",
            Self::DigestMismatch => "digest mismatch",
        }
    }
}

impl core::fmt::Display for PlanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let n = |t: u32| t.to_le_bytes().map(char::from);
        match *self {
            Self::BadMagic { found } => write!(f, "bad plan magic {found:#010x}"),
            Self::Truncated => write!(f, "plan truncated"),
            Self::UnknownSection { tag, offset } => {
                write!(f, "unknown plan section {tag:#010x} at {offset}")
            }
            Self::DuplicateSection { tag, offset } => {
                let c = n(tag);
                write!(
                    f,
                    "plan section {}{}{}{} repeated at {offset}",
                    c[0], c[1], c[2], c[3]
                )
            }
            Self::MissingSection { tag } => {
                let c = n(tag);
                write!(f, "plan has no {}{}{}{} section", c[0], c[1], c[2], c[3])
            }
            Self::LengthMismatch { tag } => {
                let c = n(tag);
                write!(
                    f,
                    "plan section {}{}{}{} length disagrees with its count",
                    c[0], c[1], c[2], c[3]
                )
            }
            Self::TooMany { tag, count, max } => {
                let c = n(tag);
                write!(
                    f,
                    "plan section {}{}{}{} holds {count} records, limit {max}",
                    c[0], c[1], c[2], c[3]
                )
            }
            Self::DigestMismatch => write!(f, "plan digest mismatch"),
        }
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(field(b, at))
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(field(b, at))
}

/// The `N` bytes at `at`, zeros past the end: every read is of a blob the
/// decoder has bounded already, and none can panic (a module links these).
fn field<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    for (o, v) in out.iter_mut().zip(b.iter().skip(at)) {
        *o = *v;
    }
    out
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(field(b, at))
}

/// A decoded, digest-verified plan.
#[derive(Clone, Copy, Debug)]
pub struct Plan<'a> {
    pub generation: u64,
    /// The SHA-256 the plan carries, verified at decode.
    pub digest: [u8; 32],
    assignments: &'a [u8],
    revocations: &'a [u8],
    grants: &'a [u8],
}

impl<'a> Plan<'a> {
    /// The assignments, in plan order.
    pub fn assignments(&self) -> impl ExactSizeIterator<Item = Assignment> + Clone + 'a {
        crate::records::<ASSIGNMENT_LEN>(self.assignments).map(|r| read_assignment(r))
    }

    /// The revocations, in plan order.
    pub fn revocations(&self) -> impl ExactSizeIterator<Item = Revocation> + Clone + 'a {
        crate::records::<REVOCATION_LEN>(self.revocations).map(|r| Revocation {
            assignment: read_assignment(&r[..ASSIGNMENT_LEN]),
            grace_secs: le16(r, ASSIGNMENT_LEN),
            deadline_unix: le64(r, ASSIGNMENT_LEN + 2),
        })
    }

    /// The grants, in plan order.
    pub fn grants(&self) -> impl Iterator<Item = Grant<'a>> + Clone + 'a {
        grant_records(self.grants)
    }

    /// Owner `(slot, generation)`'s grants as `[kind u16][len u16][bytes]`
    /// records, written into `out` from 0; the bytes they take, which may
    /// exceed `out` (then only the records that fit are written whole).
    pub fn owner_grants(&self, slot: u16, generation: u32, out: &mut [u8]) -> usize {
        let mut need = 0usize;
        for g in self.grants() {
            if g.slot != slot || g.generation != generation {
                continue;
            }
            let end = need + 4 + g.bytes.len();
            if let Some(d) = out.get_mut(need..end) {
                let k = g.kind.to_le_bytes();
                let l = (g.bytes.len() as u16).to_le_bytes();
                for (d, v) in d.iter_mut().zip(k.iter().chain(&l).chain(g.bytes)) {
                    *d = *v;
                }
            }
            need = end;
        }
        need
    }
}

fn read_assignment(r: &[u8]) -> Assignment {
    let mut owner_uid = [0u8; 16];
    owner_uid.copy_from_slice(&r[0..16]);
    Assignment {
        owner_uid,
        slot: le16(r, 16),
        generation: le32(r, 18),
        module_base: le16(r, 22),
        module_count: le16(r, 24),
        edge_base: le16(r, 26),
        edge_count: le16(r, 28),
        state_cap: le32(r, 30),
        buffer_cap: le32(r, 34),
    }
}

/// Decode and verify a plan. `max_assignments` bounds the assignment and
/// revocation sections (the owner table's size); `sha256` hashes the bytes
/// the digest covers.
///
/// # Errors
/// The first thing that makes the plan unusable; see [`PlanError`].
pub fn decode(
    bytes: &[u8],
    max_assignments: usize,
    sha256: impl FnOnce(&[u8]) -> [u8; 32],
) -> Result<Plan<'_>, PlanError> {
    if bytes.len() < HEADER_LEN + DIGEST_LEN {
        return Err(PlanError::Truncated);
    }
    let magic = le32(bytes, 0);
    if magic != MAGIC {
        return Err(PlanError::BadMagic { found: magic });
    }
    let body_end = bytes.len() - DIGEST_LEN;
    let mut found: [Option<&[u8]>; tag::ALL.len()] = [None; tag::ALL.len()];
    let mut off = HEADER_LEN;
    while off < body_end {
        if body_end - off < SECTION_HEAD_LEN {
            return Err(PlanError::Truncated);
        }
        let t = le32(bytes, off);
        let len = le32(bytes, off + 4) as usize;
        let count = le32(bytes, off + 8) as usize;
        let Some(slot) = tag::ALL.iter().position(|&k| k == t) else {
            return Err(PlanError::UnknownSection {
                tag: t,
                offset: off,
            });
        };
        if found[slot].is_some() {
            return Err(PlanError::DuplicateSection {
                tag: t,
                offset: off,
            });
        }
        let max = match t {
            tag::ASSIGNMENTS | tag::REVOCATIONS => max_assignments,
            _ => MAX_GRANTS,
        };
        if count > max {
            return Err(PlanError::TooMany { tag: t, count, max });
        }
        let start = off + SECTION_HEAD_LEN;
        let end = off + 8 + len;
        if len < 4 || end > body_end {
            return Err(PlanError::Truncated);
        }
        let records_len = match t {
            tag::ASSIGNMENTS => Some(count * ASSIGNMENT_LEN),
            tag::REVOCATIONS => Some(count * REVOCATION_LEN),
            _ => grants_len(&bytes[start..end], count),
        };
        if records_len != Some(len - 4) {
            return Err(PlanError::LengthMismatch { tag: t });
        }
        found[slot] = Some(&bytes[start..end]);
        off = end;
    }
    let [assignments, revocations, grants] = found;
    let assignments = assignments.ok_or(PlanError::MissingSection {
        tag: tag::ASSIGNMENTS,
    })?;
    let revocations = revocations.ok_or(PlanError::MissingSection {
        tag: tag::REVOCATIONS,
    })?;
    let grants = grants.ok_or(PlanError::MissingSection { tag: tag::GRANTS })?;

    let computed = sha256(&bytes[..body_end]);
    if computed[..] != bytes[body_end..] {
        return Err(PlanError::DigestMismatch);
    }
    Ok(Plan {
        generation: le64(bytes, 4),
        digest: computed,
        assignments,
        revocations,
        grants,
    })
}

/// What [`encode`] builds a plan from.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlanSpec<'a> {
    pub generation: u64,
    pub assignments: &'a [Assignment],
    pub revocations: &'a [Revocation],
    pub grants: &'a [Grant<'a>],
}

#[cfg(feature = "alloc")]
fn push_assignment(out: &mut Vec<u8>, a: &Assignment) {
    out.extend_from_slice(&a.owner_uid);
    out.extend_from_slice(&a.slot.to_le_bytes());
    out.extend_from_slice(&a.generation.to_le_bytes());
    out.extend_from_slice(&a.module_base.to_le_bytes());
    out.extend_from_slice(&a.module_count.to_le_bytes());
    out.extend_from_slice(&a.edge_base.to_le_bytes());
    out.extend_from_slice(&a.edge_count.to_le_bytes());
    out.extend_from_slice(&a.state_cap.to_le_bytes());
    out.extend_from_slice(&a.buffer_cap.to_le_bytes());
}

#[cfg(feature = "alloc")]
fn push_section<T>(
    out: &mut Vec<u8>,
    t: u32,
    rec_len: usize,
    records: &[T],
    max: usize,
    mut push: impl FnMut(&mut Vec<u8>, &T),
) -> Result<(), PlanError> {
    if records.len() > max {
        return Err(PlanError::TooMany {
            tag: t,
            count: records.len(),
            max,
        });
    }
    let count = u32::try_from(records.len()).map_err(|_| PlanError::LengthMismatch { tag: t })?;
    let len = u32::try_from(4 + records.len() * rec_len)
        .map_err(|_| PlanError::LengthMismatch { tag: t })?;
    out.extend_from_slice(&t.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    for r in records {
        push(out, r);
    }
    Ok(())
}

#[cfg(feature = "alloc")]
fn push_grants(out: &mut Vec<u8>, grants: &[Grant<'_>]) -> Result<(), PlanError> {
    let t = tag::GRANTS;
    if grants.len() > MAX_GRANTS {
        return Err(PlanError::TooMany {
            tag: t,
            count: grants.len(),
            max: MAX_GRANTS,
        });
    }
    if grants.iter().any(|g| g.bytes.len() > MAX_GRANT_BYTES) {
        return Err(PlanError::LengthMismatch { tag: t });
    }
    let bytes: usize = grants.iter().map(|g| GRANT_HEAD + g.bytes.len()).sum();
    let count = u32::try_from(grants.len()).map_err(|_| PlanError::LengthMismatch { tag: t })?;
    let len = u32::try_from(4 + bytes).map_err(|_| PlanError::LengthMismatch { tag: t })?;
    out.extend_from_slice(&t.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    for g in grants {
        out.extend_from_slice(&g.slot.to_le_bytes());
        out.extend_from_slice(&g.generation.to_le_bytes());
        out.extend_from_slice(&g.kind.to_le_bytes());
        out.extend_from_slice(&(g.bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(g.bytes);
    }
    Ok(())
}

/// Encode a plan: header, `ASGN`, `RVOK`, `GRNT`, then the digest `sha256`
/// returns over all of it.
///
/// # Errors
/// [`PlanError::TooMany`] when a section is over its limit, the same limit
/// [`decode`] applies.
#[cfg(feature = "alloc")]
pub fn encode(
    spec: &PlanSpec<'_>,
    max_assignments: usize,
    sha256: impl FnOnce(&[u8]) -> [u8; 32],
) -> Result<Vec<u8>, PlanError> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&spec.generation.to_le_bytes());
    push_section(
        &mut out,
        tag::ASSIGNMENTS,
        ASSIGNMENT_LEN,
        spec.assignments,
        max_assignments,
        push_assignment,
    )?;
    push_section(
        &mut out,
        tag::REVOCATIONS,
        REVOCATION_LEN,
        spec.revocations,
        max_assignments,
        |o, r| {
            push_assignment(o, &r.assignment);
            o.extend_from_slice(&r.grace_secs.to_le_bytes());
            o.extend_from_slice(&r.deadline_unix.to_le_bytes());
        },
    )?;
    push_grants(&mut out, spec.grants)?;
    let digest = sha256(&out);
    out.extend_from_slice(&digest);
    Ok(out)
}
