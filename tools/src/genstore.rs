//! Durable graph-generation store: A/B generation pointer, two-phase commit,
//! boot selection with automatic rollback, and a content-addressed blob store
//! with restartable GC.
//!
//! The logic here is backend-agnostic: it runs over a small [`Storage`] trait so
//! it can be exhaustively tested with [`MemStorage`] in-memory, while the real
//! device backend (Pi 5 eMMC/NVMe through the kernel's block-storage provider,
//! or a host filesystem)
//! implements the same trait. Power-loss safety is the central property: a crash
//! at any write/commit boundary recovers either the previous committed
//! generation or the new one, never a mixture.
//!
//! Layout (keys in the backing store):
//!   * `ptr.a`, `ptr.b` — two redundant generation-pointer records. The live
//!     committed generation is the valid (CRC-ok) record with the highest epoch.
//!     The two are written alternately so a torn write never destroys the other.
//!   * `gen.<id>` — a generation slot header (state, digests, boot attempts).
//!   * `cas.<sha256hex>` — content-addressed immutable blobs, shared between
//!     generations and reference-counted by slot references.

use std::collections::{BTreeMap, BTreeSet};

/// On-storage wire records (pointer records, generation headers) —
/// path-mounted from `modules/sdk/wire/genstore_wire.rs` so the host store and
/// the device-side Pi 5 backend share one codec by construction (the same
/// lockstep discipline as `wire.rs` / the plan codec pair).
#[path = "../../modules/sdk/wire/genstore_wire.rs"]
pub mod genstore_wire;
pub use genstore_wire::GenState;
use genstore_wire::{GenHeaderView, PointerRecord};

// ============================================================================
// Storage backend
// ============================================================================

/// A flat key→bytes durable store. Keys are short ASCII names (see module docs).
pub trait Storage {
    /// Read `key`. `Ok(None)` means the key is genuinely absent; `Err` means the
    /// read itself failed (EIO, permissions, …). Callers MUST distinguish the
    /// two: treating an I/O error as "absent" would let a transient fault look
    /// like empty state and silently drop live workloads.
    fn read(&self, key: &str) -> std::io::Result<Option<Vec<u8>>>;
    /// Durably write `bytes` under `key`. MUST return an error if the bytes did
    /// not reach stable storage — callers rely on this to fail closed rather
    /// than report a commit that never persisted.
    fn write(&mut self, key: &str, bytes: &[u8]) -> std::io::Result<()>;
    fn delete(&mut self, key: &str);
    fn keys(&self) -> Vec<String>;
}

/// In-memory backend for tests.
#[derive(Default)]
pub struct MemStorage {
    map: BTreeMap<String, Vec<u8>>,
}

impl Storage for MemStorage {
    fn read(&self, key: &str) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.map.get(key).cloned())
    }
    fn write(&mut self, key: &str, bytes: &[u8]) -> std::io::Result<()> {
        self.map.insert(key.to_string(), bytes.to_vec());
        Ok(())
    }
    fn delete(&mut self, key: &str) {
        self.map.remove(key);
    }
    fn keys(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }
}

/// Directory-backed store: one file per key, durable across process restarts.
/// This is the Linux host / node-agent backend; the Pi 5 eMMC/NVMe backend
/// implements the same trait over the kernel's block-storage provider calls.
///
/// Writes go through temp-file + rename so a crash mid-write can never leave a
/// torn file under the real key — combined with the A/B pointer records above,
/// this preserves the store's power-loss contract on a journaling filesystem.
pub struct FsStorage {
    root: std::path::PathBuf,
}

impl FsStorage {
    /// Open (creating if needed) a store rooted at `root`.
    pub fn open(root: impl Into<std::path::PathBuf>) -> std::io::Result<FsStorage> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(FsStorage { root })
    }
}

impl Storage for FsStorage {
    fn read(&self, key: &str) -> std::io::Result<Option<Vec<u8>>> {
        match std::fs::read(self.root.join(key)) {
            Ok(bytes) => Ok(Some(bytes)),
            // A genuinely-missing key is `Ok(None)`; every other error (EIO,
            // permission, …) propagates so a fault can never be mistaken for
            // "not present" and silently drop persisted state.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn write(&mut self, key: &str, bytes: &[u8]) -> std::io::Result<()> {
        let tmp = self.root.join(format!("{key}.tmp"));
        let dst = self.root.join(key);
        // Durability: temp write + fsync(file) + atomic rename + fsync(dir). Any
        // step failing is surfaced so the caller does not report a persisted
        // commit that isn't. The parent-directory fsync makes the rename (the new
        // directory entry) itself durable — without it a power loss after the
        // data fsync can still lose the rename on some filesystems.
        std::fs::write(&tmp, bytes)?;
        std::fs::File::open(&tmp)?.sync_all()?;
        std::fs::rename(&tmp, &dst)?;
        std::fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    fn delete(&mut self, key: &str) {
        let _ = std::fs::remove_file(self.root.join(key));
    }
    fn keys(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&self.root) {
            for e in rd.flatten() {
                if let Some(name) = e.file_name().to_str() {
                    if !name.ends_with(".tmp") {
                        out.push(name.to_string());
                    }
                }
            }
        }
        out.sort();
        out
    }
}

// ============================================================================
// Generation pointer (A/B, epoch-selected, two-phase commit)
// ============================================================================

const PTR_A: &str = genstore_wire::PTR_A_KEY;
const PTR_B: &str = genstore_wire::PTR_B_KEY;

/// A generation slot header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Generation {
    pub id: u64,
    pub state: GenState,
    pub plan_digest: [u8; 32],
    /// ABI wire-surface digest of the substrate this generation was built
    /// against (`crate::hash::abi_surface_digest`). Boot selection on a
    /// device accepts the generation only on digest equality — identity,
    /// not version windows.
    pub abi_surface: [u8; 32],
    /// Content digests this generation references (kept alive in the CAS).
    pub artifacts: Vec<[u8; 32]>,
    pub boot_attempts: u8,
}

/// Boot-attempt threshold past which a generation is declared `Bad` and the
/// store rolls back to the most recent older committed generation. A boot
/// attempt is recorded BEFORE the generation is handed out and cleared only by
/// a successful commit, so a generation that wedges the device on every boot
/// runs out of attempts instead of wedging it forever.
pub const MAX_BOOT_ATTEMPTS: u8 = 3;

/// The durable graph-generation store.
pub struct GenStore<S: Storage> {
    pub storage: S,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    NoCommittedGeneration,
    GenerationMissing,
    DigestVerifyFailed,
    /// A durable write failed — the operation did not persist and must not be
    /// reported as committed.
    WriteFailed,
    /// Persisted state exists but could not be decoded — treated as a hard error
    /// rather than silently reset to empty (which would drop live workloads).
    CorruptState,
    /// A read of persisted state failed at the I/O layer (EIO, permissions, …).
    /// Distinct from "absent": a fault must never be mistaken for empty state,
    /// which would drop live workloads on the next reconcile.
    StorageIo,
}

impl<S: Storage> GenStore<S> {
    pub fn new(storage: S) -> Self {
        GenStore { storage }
    }

    /// Read where a fault and an absent key are equivalent: the A/B pointer
    /// redundancy tolerates one record being unreadable, and gen/artifact reads
    /// that come back empty already fail closed via `GenerationMissing`. Distinct
    /// from the node-agent's desired/slot-gens reads, which must tell an I/O
    /// error apart from "absent" to avoid dropping live pods (they call the
    /// `Storage::read` `Result` directly).
    fn read_tolerant(&self, key: &str) -> Option<Vec<u8>> {
        self.storage.read(key).ok().flatten()
    }

    fn gen_key(id: u64) -> String {
        format!("gen.{id}")
    }
    fn cas_key(digest: &[u8; 32]) -> String {
        let mut s = String::from("cas.");
        for b in digest {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// The live committed pointer = the valid record with the highest epoch.
    /// `None` before the first commit (or if both records are corrupt).
    fn live_pointer(&self) -> Option<PointerRecord> {
        let a = self
            .read_tolerant(PTR_A)
            .and_then(|b| PointerRecord::decode(&b));
        let b = self
            .read_tolerant(PTR_B)
            .and_then(|b| PointerRecord::decode(&b));
        match (a, b) {
            (Some(a), Some(b)) => Some(if a.epoch >= b.epoch { a } else { b }),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    /// Which pointer slot to write next: the one NOT holding the live record, so
    /// a torn write can never destroy the currently-authoritative pointer.
    fn next_pointer_slot(&self) -> &'static str {
        let a = self
            .read_tolerant(PTR_A)
            .and_then(|b| PointerRecord::decode(&b));
        let b = self
            .read_tolerant(PTR_B)
            .and_then(|b| PointerRecord::decode(&b));
        match (a, b) {
            (Some(a), Some(b)) => {
                if a.epoch >= b.epoch {
                    PTR_B
                } else {
                    PTR_A
                }
            }
            (Some(_), None) => PTR_B,
            _ => PTR_A,
        }
    }

    fn read_gen(&self, id: u64) -> Option<Generation> {
        self.read_tolerant(&Self::gen_key(id))
            .and_then(|b| decode_gen(&b))
    }

    fn write_gen(&mut self, g: &Generation) -> Result<(), StoreError> {
        self.storage
            .write(&Self::gen_key(g.id), &encode_gen(g))
            .map_err(|_| StoreError::WriteFailed)
    }

    /// The currently committed generation, if any.
    pub fn committed(&self) -> Option<Generation> {
        let p = self.live_pointer()?;
        self.read_gen(p.committed_gen)
    }

    /// Read a content-addressed artifact (e.g. the plan blob) by its digest.
    pub fn read_artifact(&self, digest: &[u8; 32]) -> Option<Vec<u8>> {
        self.read_tolerant(&Self::cas_key(digest))
    }

    /// Staging half of the two-phase generation swap: write the candidate
    /// generation and its artifacts without touching the committed pointer, so a
    /// crash here leaves the live generation untouched. The plan blob's sha256 is the
    /// plan_digest.
    pub fn stage(
        &mut self,
        id: u64,
        plan_digest: [u8; 32],
        artifacts: &[([u8; 32], Vec<u8>)],
    ) -> Result<(), StoreError> {
        for (digest, bytes) in artifacts {
            self.storage
                .write(&Self::cas_key(digest), bytes)
                .map_err(|_| StoreError::WriteFailed)?;
        }
        let g = Generation {
            id,
            state: GenState::Staging,
            plan_digest,
            // Pin the generation to the substrate surface this build of the
            // tools was compiled against — the agent and the kernel it
            // deploys move in lockstep in this repo, so the tools' own
            // canonical surface IS the target substrate's.
            abi_surface: crate::hash::abi_surface_digest(),
            artifacts: artifacts.iter().map(|(d, _)| *d).collect(),
            boot_attempts: 0,
        };
        self.write_gen(&g)
    }

    /// Verify the staged generation: re-read every artifact FROM STORAGE and
    /// check its content digest, then mark the generation `Candidate` — the
    /// state the commit step requires. Fails closed if any artifact is missing
    /// or corrupt, so only a generation proven readable can ever be committed.
    pub fn verify_and_mark_candidate(&mut self, id: u64) -> Result<(), StoreError> {
        let mut g = self.read_gen(id).ok_or(StoreError::GenerationMissing)?;
        for digest in &g.artifacts {
            let bytes = self
                .read_tolerant(&Self::cas_key(digest))
                .ok_or(StoreError::DigestVerifyFailed)?;
            if &sha256(&bytes) != digest {
                return Err(StoreError::DigestVerifyFailed);
            }
        }
        g.state = GenState::Candidate;
        self.write_gen(&g)?;
        Ok(())
    }

    /// Commit half of the two-phase generation swap: atomically flip the committed
    /// pointer to `id` by writing a higher-epoch record into the non-live
    /// pointer slot. This single write IS the commit. The previous
    /// committed generation is retained (for rollback) until GC'd. A crash before
    /// this write leaves the prior generation committed; after it, the new one.
    pub fn commit(&mut self, id: u64) -> Result<(), StoreError> {
        let mut g = self.read_gen(id).ok_or(StoreError::GenerationMissing)?;
        let next_epoch = self.live_pointer().map(|p| p.epoch + 1).unwrap_or(1);
        g.state = GenState::Committed;
        g.boot_attempts = 0;
        self.write_gen(&g)?;
        let rec = PointerRecord {
            epoch: next_epoch,
            committed_gen: id,
        };
        let slot = self.next_pointer_slot();
        // The pointer flip is the commit: if it does not persist, the previous
        // generation stays committed — report the failure, don't claim success.
        self.storage
            .write(slot, &rec.encode())
            .map_err(|_| StoreError::WriteFailed)?;
        Ok(())
    }

    /// Boot selection: return the committed generation, recording a boot attempt.
    /// If a generation exceeds `MAX_BOOT_ATTEMPTS` it is marked `Bad` and the
    /// store rolls back to the most recent older committed generation.
    /// Returns the generation to boot.
    pub fn select_for_boot(&mut self) -> Result<Generation, StoreError> {
        self.select_for_boot_on(&crate::hash::abi_surface_digest())
    }

    /// Boot selection against an explicit substrate surface digest (`own` is
    /// the running kernel's digest). Two rules decide which committed
    /// generation boots, both failing closed:
    ///
    /// - ABI compatibility: a generation is bootable only when its ABI-surface
    ///   pin equals `own`. An incompatible one is skipped without mutation —
    ///   it remains valid on the kernel it targets, so marking it `Bad` (and
    ///   thus GC-eligible) would destroy the rollback path when that kernel is
    ///   flashed back. Selection falls through to the newest committed
    ///   generation whose pin matches. (A record in the unpinned layout decodes
    ///   to an all-zero pin, which equals no real kernel's digest: readable for
    ///   desired-state continuity, never bootable.)
    /// - Boot health: a compatible generation that exhausts its boot attempts
    ///   is a genuine defect — marked `Bad`, and the store rolls back.
    pub fn select_for_boot_on(&mut self, own: &[u8; 32]) -> Result<Generation, StoreError> {
        let p = self
            .live_pointer()
            .ok_or(StoreError::NoCommittedGeneration)?;
        let mut g = self
            .read_gen(p.committed_gen)
            .ok_or(StoreError::GenerationMissing)?;
        if g.abi_surface != *own {
            return self.select_compatible_committed(own);
        }
        if g.boot_attempts >= MAX_BOOT_ATTEMPTS {
            g.state = GenState::Bad;
            self.write_gen(&g)?;
            return self.rollback_from_on(g.id, own);
        }
        g.boot_attempts += 1;
        self.write_gen(&g)?;
        Ok(g)
    }

    /// Select the newest `Committed` generation whose ABI-surface pin equals
    /// `own`, without mutating any incompatible generation's state (they
    /// remain valid for the kernel they target). Fails closed when none is
    /// compatible. This is the ABI-mismatch path: non-destructive, so a
    /// later flash back to a matching kernel still finds its generation.
    fn select_compatible_committed(&mut self, own: &[u8; 32]) -> Result<Generation, StoreError> {
        let mut best: Option<Generation> = None;
        for k in self.storage.keys() {
            if let Some(idstr) = k.strip_prefix("gen.") {
                if let Ok(id) = idstr.parse::<u64>() {
                    if let Some(g) = self.read_gen(id) {
                        if g.state == GenState::Committed
                            && g.abi_surface == *own
                            && best.as_ref().map(|b| g.id > b.id).unwrap_or(true)
                        {
                            best = Some(g);
                        }
                    }
                }
            }
        }
        let mut g = best.ok_or(StoreError::NoCommittedGeneration)?;
        // Point the committed record at the selected generation so the boot
        // actually runs it (the live pointer may reference an incompatible
        // one). Its own boot-attempt accounting still applies.
        if g.boot_attempts >= MAX_BOOT_ATTEMPTS {
            g.state = GenState::Bad;
            self.write_gen(&g)?;
            return self.rollback_from_on(g.id, own);
        }
        let next_epoch = self.live_pointer().map(|p| p.epoch + 1).unwrap_or(1);
        let rec = PointerRecord {
            epoch: next_epoch,
            committed_gen: g.id,
        };
        let slot = self.next_pointer_slot();
        self.storage
            .write(slot, &rec.encode())
            .map_err(|_| StoreError::WriteFailed)?;
        g.boot_attempts += 1;
        self.write_gen(&g)?;
        Ok(g)
    }

    /// Mark the current boot successful (clears boot attempts on the committed
    /// generation) — the caller invokes this once the new graph is healthy.
    pub fn mark_boot_ok(&mut self) -> Result<(), StoreError> {
        if let Some(p) = self.live_pointer() {
            if let Some(mut g) = self.read_gen(p.committed_gen) {
                g.boot_attempts = 0;
                self.write_gen(&g)?;
            }
        }
        Ok(())
    }

    /// Roll back to the newest committed generation older than `failed_id`,
    /// flipping the pointer to it. Used by automatic rollback.
    /// Roll back to the newest older committed generation whose ABI-surface
    /// pin matches `own` — rolling back onto an incompatible generation would
    /// just fail the same check on the next selection.
    fn rollback_from_on(
        &mut self,
        failed_id: u64,
        own: &[u8; 32],
    ) -> Result<Generation, StoreError> {
        let mut best: Option<Generation> = None;
        for k in self.storage.keys() {
            if let Some(idstr) = k.strip_prefix("gen.") {
                if let Ok(id) = idstr.parse::<u64>() {
                    if id >= failed_id {
                        continue;
                    }
                    if let Some(g) = self.read_gen(id) {
                        if g.state == GenState::Committed
                            && g.abi_surface == *own
                            && best.as_ref().map(|b| g.id > b.id).unwrap_or(true)
                        {
                            best = Some(g);
                        }
                    }
                }
            }
        }
        let g = best.ok_or(StoreError::NoCommittedGeneration)?;
        let next_epoch = self.live_pointer().map(|p| p.epoch + 1).unwrap_or(1);
        let rec = PointerRecord {
            epoch: next_epoch,
            committed_gen: g.id,
        };
        let slot = self.next_pointer_slot();
        self.storage
            .write(slot, &rec.encode())
            .map_err(|_| StoreError::WriteFailed)?;
        Ok(g)
    }

    /// Garbage-collect CAS blobs no live generation references. A blob is kept
    /// while any non-`Bad` generation references it. Restartable (it derives the
    /// keep-set fresh each run) and never touches a referenced blob.
    ///
    /// Fail-closed on unreadable state: a `gen.*` record that cannot be read or
    /// decoded aborts the sweep entirely (returns 0). Its artifact references
    /// are unknown, so excluding just that record from the keep-set would let
    /// GC delete blobs a live-but-undecodable generation still needs — the one
    /// unrecoverable outcome. An operator repairs or deletes the corrupt
    /// record; GC never guesses.
    pub fn gc(&mut self) -> usize {
        let mut keep: BTreeSet<String> = BTreeSet::new();
        for k in self.storage.keys() {
            if k.starts_with("gen.") {
                match self.read_tolerant(&k).and_then(|b| decode_gen(&b)) {
                    Some(g) => {
                        if g.state != GenState::Bad {
                            for d in &g.artifacts {
                                keep.insert(Self::cas_key(d));
                            }
                        }
                    }
                    None => return 0,
                }
            }
        }
        let mut removed = 0;
        for k in self.storage.keys() {
            if k.starts_with("cas.") && !keep.contains(&k) {
                self.storage.delete(&k);
                removed += 1;
            }
        }
        removed
    }
}

// ── Generation header codec ─────────────────────────────────────────────────

fn encode_gen(g: &Generation) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&genstore_wire::GEN_MAGIC.to_be_bytes());
    buf.extend_from_slice(&g.id.to_be_bytes());
    buf.push(g.state.to_u8());
    buf.push(g.boot_attempts);
    buf.extend_from_slice(&g.plan_digest);
    buf.extend_from_slice(&g.abi_surface);
    buf.extend_from_slice(&(g.artifacts.len() as u32).to_be_bytes());
    for d in &g.artifacts {
        buf.extend_from_slice(d);
    }
    buf
}

/// Decode through the shared zero-copy view, then materialize the owned
/// host form — so the host reads exactly what a device backend would.
///
/// Two narrower record variants are also accepted, so a store holding them
/// stays READABLE and reconciliation continues from the true current
/// generation instead of restarting at 1 and overwriting live state: the
/// magicless pinned variant, then the shorter unpinned one. Read ≠ bootable:
/// a record whose pin doesn't equal the running surface — the unpinned
/// variant's all-zero pin included — fails boot selection outright.
fn decode_gen(b: &[u8]) -> Option<Generation> {
    if let Some(view) = GenHeaderView::parse(b) {
        let artifacts = (0..view.artifact_count())
            .map(|i| view.artifact(i))
            .collect::<Option<Vec<_>>>()?;
        return Some(Generation {
            id: view.id(),
            state: view.state(),
            plan_digest: view.plan_digest(),
            abi_surface: view.abi_surface(),
            artifacts,
            boot_attempts: view.boot_attempts(),
        });
    }
    decode_gen_interim(b).or_else(|| decode_gen_legacy(b))
}

/// The magicless pinned record variant — it carries the ABI-surface pin but no
/// leading GEN_MAGIC discriminator: `id:u64 | state | boot_attempts |
/// plan_digest:[32] | abi_surface:[32] | count:u32 | artifacts…` (78-byte
/// fixed header, exact length). Its length classes overlap with the 46-byte
/// `legacy` variant (78 + 32m == 46 + 32(m+1)), so with no magic to tell them
/// apart this one is tried FIRST; a mis-read is then possible only when a
/// `legacy` record's first artifact digest happens to end in exactly the bytes
/// of a self-consistent count (~2^-32). Records carrying the magic are
/// unambiguous and never reach either fallback.
fn decode_gen_interim(b: &[u8]) -> Option<Generation> {
    const INTERIM_FIXED: usize = 8 + 1 + 1 + 32 + 32 + 4;
    if b.len() < INTERIM_FIXED {
        return None;
    }
    let id = u64::from_be_bytes(b[0..8].try_into().ok()?);
    let state = GenState::from_u8(b[8])?;
    let boot_attempts = b[9];
    let mut plan_digest = [0u8; 32];
    plan_digest.copy_from_slice(&b[10..42]);
    let mut abi_surface = [0u8; 32];
    abi_surface.copy_from_slice(&b[42..74]);
    let n = u32::from_be_bytes(b[74..78].try_into().ok()?) as usize;
    if b.len() != INTERIM_FIXED.checked_add(n.checked_mul(32)?)? {
        return None;
    }
    let mut artifacts = Vec::with_capacity(n);
    for i in 0..n {
        let off = INTERIM_FIXED + i * 32;
        let mut d = [0u8; 32];
        d.copy_from_slice(&b[off..off + 32]);
        artifacts.push(d);
    }
    Some(Generation {
        id,
        state,
        plan_digest,
        abi_surface,
        artifacts,
        boot_attempts,
    })
}

/// The `legacy` record variant: the shortest of the three, carrying NO
/// ABI-surface pin — `id:u64 | state:u8 | boot_attempts:u8 |
/// plan_digest:[u8;32] | artifact_count:u32 | artifacts…` (46-byte fixed
/// header). Read-only: `encode_gen` always writes the magicked pinned form.
/// Exact length required. Having no pin, it decodes to an all-zero one, which
/// FAILS boot selection against any real kernel digest — its readability
/// exists for desired-state continuity alone.
fn decode_gen_legacy(b: &[u8]) -> Option<Generation> {
    const LEGACY_FIXED: usize = 8 + 1 + 1 + 32 + 4;
    if b.len() < LEGACY_FIXED {
        return None;
    }
    let id = u64::from_be_bytes(b[0..8].try_into().ok()?);
    let state = GenState::from_u8(b[8])?;
    let boot_attempts = b[9];
    let mut plan_digest = [0u8; 32];
    plan_digest.copy_from_slice(&b[10..42]);
    let n = u32::from_be_bytes(b[42..46].try_into().ok()?) as usize;
    if b.len() != LEGACY_FIXED.checked_add(n.checked_mul(32)?)? {
        return None;
    }
    let mut artifacts = Vec::with_capacity(n);
    for i in 0..n {
        let off = LEGACY_FIXED + i * 32;
        let mut d = [0u8; 32];
        d.copy_from_slice(&b[off..off + 32]);
        artifacts.push(d);
    }
    Some(Generation {
        id,
        state,
        plan_digest,
        // No pin in this variant: the all-zero sentinel, which matches no
        // real kernel digest and so is never bootable.
        abi_surface: [0u8; 32],
        artifacts,
        boot_attempts,
    })
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(tag: u8) -> ([u8; 32], Vec<u8>) {
        let bytes = vec![tag; 64];
        (sha256(&bytes), bytes)
    }

    /// Storage whose writes always fail — used to prove commit fails closed.
    #[derive(Default)]
    struct FailingStorage {
        inner: MemStorage,
    }
    impl Storage for FailingStorage {
        fn read(&self, key: &str) -> std::io::Result<Option<Vec<u8>>> {
            self.inner.read(key)
        }
        fn write(&mut self, _key: &str, _bytes: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::other("disk full"))
        }
        fn delete(&mut self, key: &str) {
            self.inner.delete(key);
        }
        fn keys(&self) -> Vec<String> {
            self.inner.keys()
        }
    }

    #[test]
    fn write_failure_makes_stage_and_commit_fail_closed() {
        let mut s = GenStore::new(FailingStorage::default());
        // stage must surface the failed artifact/gen write, not silently succeed.
        assert_eq!(
            s.stage(1, [1u8; 32], &[art(1)]),
            Err(StoreError::WriteFailed)
        );
        // commit on a store where the generation was never written fails (the
        // generation is missing); crucially it never returns Ok while the write
        // did not persist.
        assert!(s.commit(1).is_err());
        // Nothing became committed.
        assert!(s.committed().is_none());
    }

    fn stage_commit(s: &mut GenStore<MemStorage>, id: u64, arts: &[([u8; 32], Vec<u8>)]) {
        s.stage(id, [id as u8; 32], arts).unwrap();
        s.verify_and_mark_candidate(id).unwrap();
        s.commit(id).unwrap();
    }

    #[test]
    fn commit_then_boot_selects_committed() {
        let mut s = GenStore::new(MemStorage::default());
        assert_eq!(s.committed(), None);
        let a = art(1);
        stage_commit(&mut s, 1, std::slice::from_ref(&a));
        let g = s.committed().unwrap();
        assert_eq!(g.id, 1);
        assert_eq!(g.state, GenState::Committed);
        assert_eq!(s.select_for_boot().unwrap().id, 1);
    }

    #[test]
    fn commit_increments_epoch_and_alternates_slots() {
        let mut s = GenStore::new(MemStorage::default());
        stage_commit(&mut s, 1, &[art(1)]);
        stage_commit(&mut s, 2, &[art(2)]);
        assert_eq!(s.committed().unwrap().id, 2);
        // both pointer slots are now written (alternated)
        assert!(s.storage.read(PTR_A).unwrap().is_some());
        assert!(s.storage.read(PTR_B).unwrap().is_some());
    }

    #[test]
    fn crash_before_pointer_flip_keeps_prior_generation() {
        let mut s = GenStore::new(MemStorage::default());
        stage_commit(&mut s, 1, &[art(1)]);
        // Stage + candidate gen 2 but DON'T commit (simulate power loss before
        // the pointer flip).
        let a2 = art(2);
        s.stage(2, [2; 32], &[a2]).unwrap();
        s.verify_and_mark_candidate(2).unwrap();
        // boot still selects the committed gen 1.
        assert_eq!(s.committed().unwrap().id, 1);
        assert_eq!(s.select_for_boot().unwrap().id, 1);
    }

    #[test]
    fn corrupt_pointer_record_is_ignored() {
        let mut s = GenStore::new(MemStorage::default());
        stage_commit(&mut s, 1, &[art(1)]);
        stage_commit(&mut s, 2, &[art(2)]);
        // Corrupt whichever slot holds the highest epoch (gen 2); the other
        // valid record (gen 1) must take over rather than yielding nothing.
        let hi = if PointerRecord::decode(&s.storage.read(PTR_A).unwrap().unwrap())
            .unwrap()
            .epoch
            >= PointerRecord::decode(&s.storage.read(PTR_B).unwrap().unwrap())
                .unwrap()
                .epoch
        {
            PTR_A
        } else {
            PTR_B
        };
        s.storage.write(hi, &[0xFFu8; 24]).unwrap();
        assert_eq!(s.committed().unwrap().id, 1);
    }

    #[test]
    fn boot_attempt_threshold_rolls_back() {
        let mut s = GenStore::new(MemStorage::default());
        stage_commit(&mut s, 1, &[art(1)]);
        stage_commit(&mut s, 2, &[art(2)]);
        // gen 2 fails to boot MAX_BOOT_ATTEMPTS times.
        for _ in 0..MAX_BOOT_ATTEMPTS {
            let g = s.select_for_boot().unwrap();
            assert_eq!(g.id, 2);
        }
        // next boot: gen 2 marked Bad, rolled back to gen 1.
        let g = s.select_for_boot().unwrap();
        assert_eq!(g.id, 1);
        assert_eq!(s.committed().unwrap().id, 1);
    }

    #[test]
    fn mark_boot_ok_resets_attempts() {
        let mut s = GenStore::new(MemStorage::default());
        stage_commit(&mut s, 1, &[art(1)]);
        s.select_for_boot().unwrap();
        s.select_for_boot().unwrap();
        s.mark_boot_ok().unwrap();
        // attempts reset → can boot many more times without rollback
        for _ in 0..MAX_BOOT_ATTEMPTS {
            assert_eq!(s.select_for_boot().unwrap().id, 1);
            s.mark_boot_ok().unwrap();
        }
    }

    #[test]
    fn gc_keeps_referenced_and_shared_blobs() {
        let mut s = GenStore::new(MemStorage::default());
        let shared = art(7); // referenced by both generations
        let only1 = art(1);
        let only2 = art(2);
        stage_commit(&mut s, 1, &[shared.clone(), only1.clone()]);
        stage_commit(&mut s, 2, &[shared.clone(), only2.clone()]);

        // Both committed → all three blobs referenced, GC removes nothing.
        assert_eq!(s.gc(), 0);
        assert!(s.read_artifact(&shared.0).is_some());

        // Mark gen 1 Bad → only1 becomes unreferenced; shared stays (gen 2).
        let mut g1 = s.read_gen(1).unwrap();
        g1.state = GenState::Bad;
        s.write_gen(&g1).unwrap();
        assert_eq!(s.gc(), 1);
        assert!(s.read_artifact(&only1.0).is_none());
        assert!(s.read_artifact(&shared.0).is_some());
        assert!(s.read_artifact(&only2.0).is_some());
    }

    #[test]
    fn gc_is_restartable_idempotent() {
        let mut s = GenStore::new(MemStorage::default());
        stage_commit(&mut s, 1, &[art(1)]);
        let mut g = s.read_gen(1).unwrap();
        g.state = GenState::Bad;
        s.write_gen(&g).unwrap();
        let first = s.gc();
        assert!(first >= 1);
        // second run removes nothing (idempotent / restartable)
        assert_eq!(s.gc(), 0);
    }

    /// Wire-codec lockstep: the shared `genstore_wire` records must survive
    /// corruption checks and in-place mutation exactly as the device backend
    /// will use them.
    #[test]
    fn wire_records_roundtrip_and_reject_corruption() {
        use genstore_wire::*;

        let rec = PointerRecord {
            epoch: 7,
            committed_gen: 42,
        };
        let mut bytes = rec.encode();
        assert_eq!(PointerRecord::decode(&bytes), Some(rec));
        // CRC bit-flip rejected (torn write).
        bytes[5] ^= 0x01;
        assert_eq!(PointerRecord::decode(&bytes), None);
        // Wrong length rejected.
        assert_eq!(PointerRecord::decode(&rec.encode()[..23]), None);

        let g = Generation {
            id: 3,
            state: GenState::Committed,
            plan_digest: [0xAB; 32],
            abi_surface: [0xCD; 32],
            artifacts: vec![[1u8; 32], [2u8; 32]],
            boot_attempts: 1,
        };
        let mut enc = encode_gen(&g);
        let view = GenHeaderView::parse(&enc).expect("valid record");
        assert_eq!(view.id(), 3);
        assert_eq!(view.state(), GenState::Committed);
        assert_eq!(view.boot_attempts(), 1);
        assert_eq!(view.plan_digest(), [0xAB; 32]);
        assert_eq!(view.abi_surface(), [0xCD; 32]);
        assert_eq!(view.artifact_count(), 2);
        assert_eq!(view.artifact(1), Some([2u8; 32]));
        assert_eq!(view.artifact(2), None);

        // Device-side in-place mutation reads back through the host decoder.
        assert!(set_boot_attempts_in_place(&mut enc, 2));
        assert!(set_state_in_place(&mut enc, GenState::Bad));
        let back = decode_gen(&enc).expect("still decodable");
        assert_eq!(back.boot_attempts, 2);
        assert_eq!(back.state, GenState::Bad);

        // Truncated artifact list rejected.
        let short = &enc[..enc.len() - 1];
        assert!(GenHeaderView::parse(short).is_none());
        // Unknown state byte rejected.
        enc[GEN_STATE_OFFSET] = 9;
        assert!(GenHeaderView::parse(&enc).is_none());
    }

    /// GC must abort (delete nothing) when any generation record is
    /// unreadable — its artifact references are unknown, and sweeping
    /// around it could delete blobs a live generation still needs.
    #[test]
    fn gc_aborts_on_undecodable_generation_record() {
        let mut s = GenStore::new(MemStorage::default());
        let a1 = art(1);
        stage_commit(&mut s, 1, std::slice::from_ref(&a1));
        // A second, corrupt generation record (e.g. written by a different
        // record layout) alongside an orphaned blob.
        s.storage.write("gen.2", b"garbage-record").unwrap();
        let orphan = art(9);
        s.storage
            .write(&GenStore::<MemStorage>::cas_key(&orphan.0), &orphan.1)
            .unwrap();

        assert_eq!(s.gc(), 0, "sweep must abort, not guess");
        assert!(s.read_artifact(&orphan.0).is_some(), "nothing deleted");

        // Repairing (removing) the corrupt record re-enables GC.
        s.storage.delete("gen.2");
        assert_eq!(s.gc(), 1);
        assert!(s.read_artifact(&orphan.0).is_none());
        assert!(s.read_artifact(&a1.0).is_some());
    }

    /// Boot selection enforces the ABI-surface pin: a committed generation
    /// pinned to a different substrate is skipped NON-destructively (its
    /// state and boot-attempts untouched, so a flash back to its kernel
    /// still boots it) while selection falls back to the newest compatible
    /// generation.
    #[test]
    fn boot_selection_skips_incompatible_abi_pin_without_marking_bad() {
        let mut s = GenStore::new(MemStorage::default());
        stage_commit(&mut s, 1, &[art(1)]);
        stage_commit(&mut s, 2, &[art(2)]);
        let own = crate::hash::abi_surface_digest();

        // Matching pin: gen 2 selected normally.
        assert_eq!(s.select_for_boot_on(&own).unwrap().id, 2);

        // Rewrite gen 2's pin to a DIFFERENT surface (as if committed for
        // another kernel), and reset its boot_attempts so we can prove they
        // stay untouched.
        let mut g2 = s.read_gen(2).unwrap();
        g2.abi_surface = [0x5A; 32];
        g2.boot_attempts = 0;
        s.write_gen(&g2).unwrap();

        // Selection falls back to gen 1 — and gen 2 is untouched: still
        // Committed (GC keeps its artifacts) with boot_attempts unmoved, so
        // flashing kernel 0x5A back boots gen 2.
        let selected = s.select_for_boot_on(&own).expect("falls back");
        assert_eq!(selected.id, 1);
        let g2_after = s.read_gen(2).unwrap();
        assert_eq!(
            g2_after.state,
            GenState::Committed,
            "incompatible != defective"
        );
        assert_eq!(g2_after.boot_attempts, 0, "not charged a boot attempt");
        // GC must retain gen 2's artifact (rollback path preserved).
        assert_eq!(s.gc(), 0);
        assert!(s.read_artifact(&art(2).0).is_some());

        // The incompatible kernel later boots and gets gen 2 back.
        assert_eq!(s.select_for_boot_on(&[0x5A; 32]).unwrap().id, 2);

        // No compatible generation for a THIRD kernel → fail closed, and
        // nothing was marked Bad.
        assert!(s.select_for_boot_on(&[0x77; 32]).is_err());
        assert_eq!(s.read_gen(1).unwrap().state, GenState::Committed);
        assert_eq!(s.read_gen(2).unwrap().state, GenState::Committed);
    }

    /// A store holding unpinned `legacy` records must stay READABLE (so
    /// reconciliation continues from the existing generation instead of
    /// restarting at 1 and overwriting) — but NOT bootable: an unattested
    /// generation fails the pin check like any mismatch, and selection fails
    /// closed until a re-staged, pinned generation exists.
    #[test]
    fn legacy_generation_records_readable_but_not_bootable() {
        // Hand-encode the unpinned `legacy` variant.
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&7u64.to_be_bytes()); // id
        legacy.push(GenState::Committed.to_u8());
        legacy.push(1); // boot_attempts
        legacy.extend_from_slice(&[0xAB; 32]); // plan_digest
        legacy.extend_from_slice(&2u32.to_be_bytes()); // artifact_count
        legacy.extend_from_slice(&[0x01; 32]);
        legacy.extend_from_slice(&[0x02; 32]);

        let g = decode_gen(&legacy).expect("legacy variant decodes");
        assert_eq!(g.id, 7);
        assert_eq!(g.state, GenState::Committed);
        assert_eq!(g.plan_digest, [0xAB; 32]);
        assert_eq!(g.artifacts, vec![[0x01; 32], [0x02; 32]]);
        assert_eq!(g.abi_surface, [0u8; 32], "legacy pin sentinel");

        // A committed `legacy` generation reads back, but cannot be booted.
        let mut s = GenStore::new(MemStorage::default());
        s.storage.write("gen.7", &legacy).unwrap();
        let ptr = genstore_wire::PointerRecord {
            epoch: 1,
            committed_gen: 7,
        };
        s.storage.write(PTR_A, &ptr.encode()).unwrap();
        let own = crate::hash::abi_surface_digest();
        // Not bootable: the zero pin matches no real kernel, so selection
        // fails closed — but non-destructively: the record stays Committed
        // and readable (desired-state continuity), never marked Bad.
        assert!(s.select_for_boot_on(&own).is_err());
        assert_eq!(s.read_gen(7).unwrap().state, GenState::Committed);

        // Truncated/inflated legacy bytes are rejected (exact length).
        assert!(decode_gen(&legacy[..legacy.len() - 1]).is_none());
    }

    /// Records in the magicless pinned variant must decode with their pin
    /// INTACT — unlike the unpinned `legacy` variant, they carry a real
    /// surface digest, so they stay readable and, when that pin matches the
    /// running kernel, bootable.
    #[test]
    fn interim_magicless_pinned_records_decode() {
        let pin = [0x77u8; 32];
        let mut interim = Vec::new();
        interim.extend_from_slice(&9u64.to_be_bytes());
        interim.push(GenState::Committed.to_u8());
        interim.push(0); // boot_attempts
        interim.extend_from_slice(&[0xAB; 32]); // plan_digest
        interim.extend_from_slice(&pin); // abi_surface
        interim.extend_from_slice(&1u32.to_be_bytes());
        interim.extend_from_slice(&[0x01; 32]);

        let g = decode_gen(&interim).expect("interim layout decodes");
        assert_eq!(g.id, 9);
        assert_eq!(g.abi_surface, pin, "pin preserved");
        assert_eq!(g.artifacts, vec![[0x01; 32]]);
        // Wrong length rejected.
        assert!(decode_gen(&interim[..interim.len() - 1]).is_none());
    }
}
