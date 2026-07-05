//! Durable graph-generation store: A/B generation pointer, two-phase commit,
//! boot selection with automatic rollback, and a content-addressed blob store
//! with restartable GC (rfc_k8s.md §12.4, §13).
//!
//! The logic here is backend-agnostic: it runs over a small [`Storage`] trait so
//! it can be exhaustively tested with [`MemStorage`] in-memory, while the real
//! device backend (CM5 eMMC/NVMe via `rfc_storage_io`, or a host filesystem)
//! implements the same trait. Power-loss safety is the central property: a crash
//! at any write/commit boundary recovers either the previous committed
//! generation or the new one, never a mixture (§12.4).
//!
//! Layout (keys in the backing store):
//!   * `ptr.a`, `ptr.b` — two redundant generation-pointer records. The live
//!     committed generation is the valid (CRC-ok) record with the highest epoch.
//!     The two are written alternately so a torn write never destroys the other.
//!   * `gen.<id>` — a generation slot header (state, digests, boot attempts).
//!   * `cas.<sha256hex>` — content-addressed immutable blobs, shared between
//!     generations and reference-counted by slot references.

use std::collections::{BTreeMap, BTreeSet};

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
/// This is the Linux host / node-agent backend; the CM5 eMMC/NVMe backend
/// implements the same trait over `rfc_storage_io` primitives.
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
// CRC32 (IEEE) — small inline impl for pointer-record integrity
// ============================================================================

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ============================================================================
// Generation pointer (A/B, epoch-selected, two-phase commit)
// ============================================================================

const PTR_A: &str = "ptr.a";
const PTR_B: &str = "ptr.b";
const PTR_MAGIC: u32 = 0x4750_5452; // "GPTR"

/// A generation-pointer record: which generation is committed, under a
/// monotonic epoch, integrity-checked with a CRC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PointerRecord {
    epoch: u64,
    committed_gen: u64,
}

impl PointerRecord {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&PTR_MAGIC.to_be_bytes());
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        buf.extend_from_slice(&self.committed_gen.to_be_bytes());
        let crc = crc32(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    fn decode(bytes: &[u8]) -> Option<PointerRecord> {
        if bytes.len() != 24 {
            return None;
        }
        if u32::from_be_bytes(bytes[0..4].try_into().ok()?) != PTR_MAGIC {
            return None;
        }
        let stored_crc = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
        if crc32(&bytes[0..20]) != stored_crc {
            return None;
        }
        Some(PointerRecord {
            epoch: u64::from_be_bytes(bytes[4..12].try_into().ok()?),
            committed_gen: u64::from_be_bytes(bytes[12..20].try_into().ok()?),
        })
    }
}

/// Lifecycle state of a generation slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenState {
    Staging,
    Candidate,
    Committed,
    Bad,
}

/// A generation slot header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Generation {
    pub id: u64,
    pub state: GenState,
    pub plan_digest: [u8; 32],
    /// Content digests this generation references (kept alive in the CAS).
    pub artifacts: Vec<[u8; 32]>,
    pub boot_attempts: u8,
}

/// Boot-attempt threshold past which a generation is declared `Bad` and the
/// store rolls back to the previous committed generation (rfc_k8s.md §13.3).
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

    /// Phase 1: stage a candidate generation and its artifacts without changing
    /// the committed pointer. The plan blob's sha256 is the plan_digest.
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
            artifacts: artifacts.iter().map(|(d, _)| *d).collect(),
            boot_attempts: 0,
        };
        self.write_gen(&g)
    }

    /// Phase 2 prep: re-read every artifact and verify its content digest, then
    /// mark the generation `Candidate`. Fails closed if any artifact is missing
    /// or corrupt.
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

    /// Phase 2 commit: atomically flip the committed pointer to `id` by writing a
    /// higher-epoch record into the non-live pointer slot. The previous
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
    /// store rolls back to the most recent older committed generation
    /// (rfc_k8s.md §13.3). Returns the generation to boot.
    pub fn select_for_boot(&mut self) -> Result<Generation, StoreError> {
        let p = self
            .live_pointer()
            .ok_or(StoreError::NoCommittedGeneration)?;
        let mut g = self
            .read_gen(p.committed_gen)
            .ok_or(StoreError::GenerationMissing)?;
        if g.boot_attempts >= MAX_BOOT_ATTEMPTS {
            // Mark bad and roll back to the newest older committed generation.
            g.state = GenState::Bad;
            self.write_gen(&g)?;
            return self.rollback_from(g.id);
        }
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
    fn rollback_from(&mut self, failed_id: u64) -> Result<Generation, StoreError> {
        let mut best: Option<Generation> = None;
        for k in self.storage.keys() {
            if let Some(idstr) = k.strip_prefix("gen.") {
                if let Ok(id) = idstr.parse::<u64>() {
                    if id >= failed_id {
                        continue;
                    }
                    if let Some(g) = self.read_gen(id) {
                        if g.state == GenState::Committed
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
    pub fn gc(&mut self) -> usize {
        let mut keep: BTreeSet<String> = BTreeSet::new();
        for k in self.storage.keys() {
            if k.starts_with("gen.") {
                if let Some(g) = self.read_tolerant(&k).and_then(|b| decode_gen(&b)) {
                    if g.state != GenState::Bad {
                        for d in &g.artifacts {
                            keep.insert(Self::cas_key(d));
                        }
                    }
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
    buf.extend_from_slice(&g.id.to_be_bytes());
    buf.push(match g.state {
        GenState::Staging => 0,
        GenState::Candidate => 1,
        GenState::Committed => 2,
        GenState::Bad => 3,
    });
    buf.push(g.boot_attempts);
    buf.extend_from_slice(&g.plan_digest);
    buf.extend_from_slice(&(g.artifacts.len() as u32).to_be_bytes());
    for d in &g.artifacts {
        buf.extend_from_slice(d);
    }
    buf
}

fn decode_gen(b: &[u8]) -> Option<Generation> {
    if b.len() < 8 + 1 + 1 + 32 + 4 {
        return None;
    }
    let id = u64::from_be_bytes(b[0..8].try_into().ok()?);
    let state = match b[8] {
        0 => GenState::Staging,
        1 => GenState::Candidate,
        2 => GenState::Committed,
        3 => GenState::Bad,
        _ => return None,
    };
    let boot_attempts = b[9];
    let mut plan_digest = [0u8; 32];
    plan_digest.copy_from_slice(&b[10..42]);
    let n = u32::from_be_bytes(b[42..46].try_into().ok()?) as usize;
    let mut artifacts = Vec::with_capacity(n);
    let mut off = 46;
    for _ in 0..n {
        if off + 32 > b.len() {
            return None;
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(&b[off..off + 32]);
        artifacts.push(d);
        off += 32;
    }
    Some(Generation {
        id,
        state,
        plan_digest,
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
}
