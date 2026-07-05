//! Node-agent reconcile → stage → commit orchestration (rfc_k8s.md §6.7, §11,
//! §12), tying together composition, the binary plan codec, and the durable
//! generation store.
//!
//! `reconcile_and_commit` is the trusted host-side step that turns a desired
//! device state into a durably committed graph generation: compose the
//! deterministic plan, encode it to the bounded binary form the kernel consumes,
//! stage it (plan blob in the content-addressed store), verify, and atomically
//! commit. `load_committed_plan` reads it back — the same bytes a device fetches
//! to apply at boot. This is the real delivery path the `FLUXOR_PLAN` /
//! `test-plan` stand-ins emulate.

use sha2::{Digest, Sha256};

use crate::compose::{
    compose, decode_plan, encode_plan, ComposeError, CompositionPlan, DesiredPhase,
    DeviceDesiredState, NodeCapacity, OwnerSnapshot, PodDesired,
};
use crate::genstore::{GenStore, Storage, StoreError};

/// Why a reconcile failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentError {
    Compose(ComposeError),
    Store(StoreError),
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Compose the candidate plan for `desired`, encode it, and durably commit it as
/// generation `gen_id` in `store`. Returns the composed plan. Deterministic in
/// `(desired, cap, prior)`; the committed generation's plan blob lives in the
/// content-addressed store keyed by its sha256.
pub fn reconcile_and_commit<S: Storage>(
    store: &mut GenStore<S>,
    desired: &DeviceDesiredState,
    cap: &NodeCapacity,
    prior: &OwnerSnapshot,
    gen_id: u64,
) -> Result<CompositionPlan, AgentError> {
    let plan = stage_candidate(store, desired, cap, prior, gen_id)?;
    store.commit(gen_id).map_err(AgentError::Store)?;
    Ok(plan)
}

/// Compose + stage + verify a candidate generation WITHOUT committing (the
/// pointer is not flipped). Split out from `reconcile_and_commit` so the node
/// agent can order its own bookkeeping writes before the final commit — the
/// commit must be the last durable write so it never becomes visible ahead of a
/// failed bookkeeping write.
fn stage_candidate<S: Storage>(
    store: &mut GenStore<S>,
    desired: &DeviceDesiredState,
    cap: &NodeCapacity,
    prior: &OwnerSnapshot,
    gen_id: u64,
) -> Result<CompositionPlan, AgentError> {
    let plan = compose(desired, cap, prior).map_err(AgentError::Compose)?;
    let blob = encode_plan(&plan);
    let blob_digest = sha256(&blob);
    store
        .stage(gen_id, blob_digest, &[(blob_digest, blob)])
        .map_err(AgentError::Store)?;
    store
        .verify_and_mark_candidate(gen_id)
        .map_err(AgentError::Store)?;
    Ok(plan)
}

/// Load and decode the plan from the currently committed generation — the bytes
/// a device fetches to apply at boot. `None` if nothing is committed or the blob
/// is missing/undecodable.
pub fn load_committed_plan<S: Storage>(store: &GenStore<S>) -> Option<CompositionPlan> {
    let g = store.committed()?;
    let blob = store.read_artifact(&g.plan_digest)?;
    decode_plan(&blob).ok()
}

/// Publish the committed generation's plan blob to `path` (temp + atomic
/// rename), for a kernel that stages its plan from a file — the Linux runtime's
/// `FLUXOR_PLAN` delivery. Returns the number of bytes published, or `None`
/// when nothing is committed.
pub fn publish_committed_plan<S: Storage>(
    store: &GenStore<S>,
    path: &std::path::Path,
) -> std::io::Result<Option<usize>> {
    let Some(g) = store.committed() else {
        return Ok(None);
    };
    let Some(blob) = store.read_artifact(&g.plan_digest) else {
        return Ok(None);
    };
    let tmp = path.with_extension("plan.tmp");
    // Durability mirrors FsStorage::write: temp write + fsync(file) + atomic
    // rename + fsync(parent dir). Without the parent-dir fsync a power loss
    // after the data fsync can still lose the rename (the new directory entry),
    // so a command that reported success could publish nothing.
    std::fs::write(&tmp, &blob)?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        // An empty parent means the CWD; skip rather than open "".
        if !parent.as_os_str().is_empty() {
            std::fs::File::open(parent)?.sync_all()?;
        }
    }
    Ok(Some(blob.len()))
}

/// Key under which the node's desired pod set persists in the store.
const DESIRED_KEY: &str = "desired.pods";
/// Key holding the per-slot high-water owner generation. Slot generations must
/// survive a slot going empty (rfc_k8s.md §11: reuse always issues a strictly
/// higher generation, so a deleted pod's stale handles can never match), and
/// the committed plan only records currently-occupied slots.
const SLOT_GENS_KEY: &str = "slot.generations";

fn load_slot_gens<S: Storage>(store: &GenStore<S>) -> Result<Vec<u32>, StoreError> {
    // Absent → first run (empty). Present but undecodable → hard error: silently
    // resetting the slot high-water would let a reused slot get a lower
    // generation, defeating the stale-handle guard. An I/O fault is likewise a
    // hard error — never "absent" — so a transient read failure cannot masquerade
    // as an empty high-water table.
    match store
        .storage
        .read(SLOT_GENS_KEY)
        .map_err(|_| StoreError::StorageIo)?
    {
        None => Ok(Vec::new()),
        Some(b) => serde_json::from_slice(&b).map_err(|_| StoreError::CorruptState),
    }
}

fn save_slot_gens<S: Storage>(store: &mut GenStore<S>, gens: &[u32]) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec(gens).map_err(|_| StoreError::WriteFailed)?;
    store
        .storage
        .write(SLOT_GENS_KEY, &bytes)
        .map_err(|_| StoreError::WriteFailed)
}

fn load_desired<S: Storage>(store: &GenStore<S>) -> Result<Vec<PodDesired>, StoreError> {
    // Absent → first run (empty desired set). Present but undecodable → hard
    // error: silently treating corrupt state as an empty set would drop every
    // live pod on the next reconcile. An I/O fault is a hard error too — a
    // transient read failure must never look like "no pods desired".
    match store
        .storage
        .read(DESIRED_KEY)
        .map_err(|_| StoreError::StorageIo)?
    {
        None => Ok(Vec::new()),
        Some(b) => serde_json::from_slice(&b).map_err(|_| StoreError::CorruptState),
    }
}

fn save_desired<S: Storage>(
    store: &mut GenStore<S>,
    pods: &[PodDesired],
) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec(pods).map_err(|_| StoreError::WriteFailed)?;
    store
        .storage
        .write(DESIRED_KEY, &bytes)
        .map_err(|_| StoreError::WriteFailed)
}

/// Owner snapshot derived from the committed plan: the plan IS the record of
/// which pod holds which slot at which generation (rfc_k8s.md §11 input), so
/// recomposition keeps resident pods' slots/generations stable.
fn snapshot_from_committed<S: Storage>(
    store: &GenStore<S>,
    max_owners: u16,
) -> Result<OwnerSnapshot, StoreError> {
    let mut snap = OwnerSnapshot::empty(max_owners);
    // Generations: high-water table (survives slots going empty)...
    for (i, gen) in load_slot_gens(store)?.into_iter().enumerate() {
        if let Some(slot) = snap.slots.get_mut(i) {
            slot.generation = gen;
        }
    }
    // ...occupancy: the committed plan.
    if let Some(plan) = load_committed_plan(store) {
        for a in &plan.assignments {
            if let Some(slot) = snap.slots.get_mut(a.slot as usize) {
                slot.occupant = Some(a.pod_uid);
                slot.generation = slot.generation.max(a.generation);
            }
        }
    }
    Ok(snap)
}

/// Upsert `pod` into the node's persisted desired state and recompose ALL
/// running pods into the next generation (rfc_k8s.md §6.3: one device, one
/// composed graph). Resident pods keep their slots/generations via the
/// committed-plan snapshot. Returns the committed plan and its generation id.
pub fn upsert_pod_and_commit<S: Storage>(
    store: &mut GenStore<S>,
    pod: PodDesired,
    cap: &NodeCapacity,
) -> Result<(CompositionPlan, u64), AgentError> {
    let mut pods = load_desired(store).map_err(AgentError::Store)?;
    pods.retain(|p| p.pod_uid != pod.pod_uid);
    pods.push(pod);
    recompose(store, pods, cap)
}

/// Remove a pod from the desired state and recompose the remainder.
pub fn remove_pod_and_commit<S: Storage>(
    store: &mut GenStore<S>,
    pod_uid: [u8; 16],
    cap: &NodeCapacity,
) -> Result<(CompositionPlan, u64), AgentError> {
    let mut pods = load_desired(store).map_err(AgentError::Store)?;
    pods.retain(|p| p.pod_uid != pod_uid);
    recompose(store, pods, cap)
}

fn recompose<S: Storage>(
    store: &mut GenStore<S>,
    pods: Vec<PodDesired>,
    cap: &NodeCapacity,
) -> Result<(CompositionPlan, u64), AgentError> {
    let gen_id = store.committed().map(|g| g.id + 1).unwrap_or(1);
    let running: Vec<PodDesired> = pods
        .iter()
        .filter(|p| p.desired_phase == DesiredPhase::Running)
        .cloned()
        .collect();
    let desired = DeviceDesiredState {
        generation: gen_id,
        system_revision: 1,
        pods: running,
    };
    let prior = snapshot_from_committed(store, cap.max_owners).map_err(AgentError::Store)?;
    // Stage + verify the candidate WITHOUT committing yet.
    let plan = stage_candidate(store, &desired, cap, &prior, gen_id)?;
    // Persist the node bookkeeping (desired set + slot high-water generations)
    // BEFORE the commit. The commit (pointer flip) is the LAST durable write, so
    // a bookkeeping failure leaves nothing committed and the caller's error is
    // consistent with the unchanged prior generation — never "error returned but
    // a new generation is already live".
    save_desired(store, &pods).map_err(AgentError::Store)?;
    let mut gens = load_slot_gens(store).map_err(AgentError::Store)?;
    for a in &plan.assignments {
        let idx = a.slot as usize;
        if gens.len() <= idx {
            gens.resize(idx + 1, 0);
        }
        gens[idx] = gens[idx].max(a.generation);
    }
    save_slot_gens(store, &gens).map_err(AgentError::Store)?;
    store.commit(gen_id).map_err(AgentError::Store)?;
    Ok((plan, gen_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose::{DesiredPhase, PodDesired, ResourceProfile};
    use crate::genstore::MemStorage;

    fn uid(n: u8) -> [u8; 16] {
        let mut u = [0u8; 16];
        u[0] = n;
        u
    }

    fn pod(n: u8, modules: u16) -> PodDesired {
        PodDesired {
            pod_uid: uid(n),
            namespace: "default".into(),
            name: format!("pod-{n}"),
            workload_digest: [n; 32],
            config_generation: 1,
            desired_phase: DesiredPhase::Running,
            profile: ResourceProfile {
                modules,
                edges: 0,
                state_bytes: 4096,
                buffer_bytes: 2048,
                endpoints: 1,
                domains: 1,
            },
        }
    }

    fn cap() -> NodeCapacity {
        NodeCapacity {
            max_owners: 16,
            max_modules: 128,
            max_edges: 256,
            state_bytes: 1 << 20,
            buffer_bytes: 1 << 20,
            max_endpoints: 64,
            max_domains: 4,
        }
    }

    fn desired(pods: Vec<PodDesired>) -> DeviceDesiredState {
        DeviceDesiredState {
            generation: 1,
            system_revision: 1,
            pods,
        }
    }

    #[test]
    fn reconcile_commits_and_round_trips_the_plan() {
        let mut store = GenStore::new(MemStorage::default());
        let ds = desired(vec![pod(1, 4), pod(2, 8)]);

        let plan = reconcile_and_commit(&mut store, &ds, &cap(), &OwnerSnapshot::empty(16), 1)
            .expect("reconcile");

        // A committed generation now exists, and the plan reloaded from the
        // store is byte-for-byte the composed plan (incl. caps from the profile).
        let loaded = load_committed_plan(&store).expect("load");
        assert_eq!(loaded, plan);
        assert_eq!(loaded.assignments.len(), 2);
        assert_eq!(loaded.assignments[0].state_cap, 4096);
        assert_eq!(loaded.assignments[0].buffer_cap, 2048);
    }

    #[test]
    fn second_reconcile_supersedes_first() {
        let mut store = GenStore::new(MemStorage::default());
        reconcile_and_commit(
            &mut store,
            &desired(vec![pod(1, 4)]),
            &cap(),
            &OwnerSnapshot::empty(16),
            1,
        )
        .unwrap();
        let plan2 = reconcile_and_commit(
            &mut store,
            &desired(vec![pod(1, 4), pod(3, 2)]),
            &cap(),
            &OwnerSnapshot::empty(16),
            2,
        )
        .unwrap();

        assert_eq!(store.committed().unwrap().id, 2);
        assert_eq!(load_committed_plan(&store).unwrap(), plan2);
        assert_eq!(plan2.assignments.len(), 2);
    }

    #[test]
    fn fs_store_survives_reopen_and_publishes_plan() {
        use crate::genstore::FsStorage;
        let dir = std::env::temp_dir().join(format!("fluxor-genstore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // Commit into a directory-backed store...
        let plan = {
            let mut store = GenStore::new(FsStorage::open(&dir).unwrap());
            reconcile_and_commit(
                &mut store,
                &desired(vec![pod(1, 4)]),
                &cap(),
                &OwnerSnapshot::empty(16),
                1,
            )
            .unwrap()
        }; // store dropped — simulate process exit

        // ...reopen (fresh process) and the committed generation survives.
        let store = GenStore::new(FsStorage::open(&dir).unwrap());
        assert_eq!(store.committed().unwrap().id, 1);
        assert_eq!(load_committed_plan(&store).unwrap(), plan);

        // Publish for FLUXOR_PLAN delivery: the file's bytes decode to the
        // exact committed plan.
        let out = dir.join("current.plan");
        let n = publish_committed_plan(&store, &out).unwrap().unwrap();
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(bytes.len(), n);
        assert_eq!(decode_plan(&bytes).unwrap(), plan);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upsert_recompose_keeps_resident_slots_stable() {
        let mut store = GenStore::new(MemStorage::default());
        // Pod A alone → slot 1, gen 1.
        let (p1, g1) = upsert_pod_and_commit(&mut store, pod(1, 4), &cap()).unwrap();
        assert_eq!(g1, 1);
        assert_eq!(p1.assignments[0].slot, 1);

        // Add pod B → BOTH pods in gen 2; A keeps slot 1 + owner generation.
        let (p2, g2) = upsert_pod_and_commit(&mut store, pod(2, 8), &cap()).unwrap();
        assert_eq!(g2, 2);
        assert_eq!(p2.assignments.len(), 2, "co-resident recompose");
        let a = p2.assignments.iter().find(|a| a.pod_uid == uid(1)).unwrap();
        let b = p2.assignments.iter().find(|a| a.pod_uid == uid(2)).unwrap();
        assert_eq!(
            (a.slot, a.generation),
            (p1.assignments[0].slot, p1.assignments[0].generation),
            "resident pod's slot/generation stable across recompose"
        );
        assert_eq!(b.slot, 2);

        // Remove A → gen 3 holds only B, still in slot 2.
        let (p3, g3) = remove_pod_and_commit(&mut store, uid(1), &cap()).unwrap();
        assert_eq!(g3, 3);
        assert_eq!(p3.assignments.len(), 1);
        assert_eq!(p3.assignments[0].slot, 2);

        // Re-add a pod → reuses slot 1 with a bumped owner generation (stale
        // handles from the removed pod can never match).
        let (p4, _) = upsert_pod_and_commit(&mut store, pod(3, 2), &cap()).unwrap();
        let c = p4.assignments.iter().find(|a| a.pod_uid == uid(3)).unwrap();
        assert_eq!(c.slot, 1);
        assert!(c.generation > a.generation);
    }

    #[test]
    fn capacity_overflow_propagates_without_committing() {
        let mut store = GenStore::new(MemStorage::default());
        // One pod needing more modules than the node has.
        let ds = desired(vec![pod(1, 200)]);
        let r = reconcile_and_commit(&mut store, &ds, &cap(), &OwnerSnapshot::empty(16), 1);
        assert!(matches!(
            r,
            Err(AgentError::Compose(ComposeError::ModulesExceeded))
        ));
        // nothing committed
        assert!(store.committed().is_none());
        assert!(load_committed_plan(&store).is_none());
    }

    #[test]
    fn corrupt_desired_state_is_a_hard_error() {
        let mut store = GenStore::new(MemStorage::default());
        // Commit a live pod so persisted desired state exists.
        upsert_pod_and_commit(&mut store, pod(1, 4), &cap()).unwrap();
        // Corrupt the persisted desired set.
        store.storage.write(DESIRED_KEY, b"not json").unwrap();
        // The next reconcile must ERROR — not silently drop the live pod by
        // treating corrupt state as an empty desired set.
        let r = upsert_pod_and_commit(&mut store, pod(2, 8), &cap());
        assert!(matches!(
            r,
            Err(AgentError::Store(StoreError::CorruptState))
        ));
        // The previously committed generation is untouched.
        assert_eq!(store.committed().unwrap().id, 1);
    }

    /// Storage that injects a fault on one specific key — a failed write and/or
    /// a failed read — to test commit ordering and read-fault handling.
    struct KeyFailStorage {
        inner: MemStorage,
        fail_write_key: Option<String>,
        fail_read_key: Option<String>,
    }
    impl KeyFailStorage {
        fn fail_write(key: &str) -> Self {
            KeyFailStorage {
                inner: MemStorage::default(),
                fail_write_key: Some(key.to_string()),
                fail_read_key: None,
            }
        }
    }
    impl Storage for KeyFailStorage {
        fn read(&self, key: &str) -> std::io::Result<Option<Vec<u8>>> {
            if self.fail_read_key.as_deref() == Some(key) {
                return Err(std::io::Error::other("injected read failure"));
            }
            self.inner.read(key)
        }
        fn write(&mut self, key: &str, bytes: &[u8]) -> std::io::Result<()> {
            if self.fail_write_key.as_deref() == Some(key) {
                Err(std::io::Error::other("injected write failure"))
            } else {
                self.inner.write(key, bytes)
            }
        }
        fn delete(&mut self, key: &str) {
            self.inner.delete(key);
        }
        fn keys(&self) -> Vec<String> {
            self.inner.keys()
        }
    }

    #[test]
    fn bookkeeping_write_failure_leaves_nothing_committed() {
        // The pointer flip (commit) is the LAST durable write. A bookkeeping
        // write (desired set) that fails BEFORE it must leave the store with no
        // new committed generation — never "error returned but generation live".
        let mut store = GenStore::new(KeyFailStorage::fail_write(DESIRED_KEY));
        let r = upsert_pod_and_commit(&mut store, pod(1, 4), &cap());
        assert!(matches!(r, Err(AgentError::Store(StoreError::WriteFailed))));
        assert!(
            store.committed().is_none(),
            "no generation committed when a pre-commit write failed"
        );
    }

    #[test]
    fn commit_write_failure_leaves_prior_generation_live() {
        // Failure DURING the commit itself (the pointer flip), not before it.
        // `recompose` stages + writes bookkeeping, then flips the pointer last;
        // if that flip fails the store must stay on the PRIOR committed
        // generation — never report success, never advance the pointer.
        let mut store = GenStore::new(KeyFailStorage::fail_write("ptr.a"));
        // No pointer exists yet, so the first commit targets ptr.a → it fails.
        let r = upsert_pod_and_commit(&mut store, pod(1, 4), &cap());
        assert!(matches!(r, Err(AgentError::Store(StoreError::WriteFailed))));
        assert!(
            store.committed().is_none(),
            "a failed pointer flip must leave nothing committed"
        );
    }

    #[test]
    fn read_fault_on_desired_state_is_not_treated_as_empty() {
        // A committed pod exists; a transient I/O fault reading the desired set
        // must be a hard error, NOT an empty set (which would drop the pod).
        let mut store = GenStore::new(KeyFailStorage {
            inner: MemStorage::default(),
            fail_write_key: None,
            fail_read_key: None,
        });
        upsert_pod_and_commit(&mut store, pod(1, 4), &cap()).unwrap();
        // Now make reads of the desired set fault.
        store.storage.fail_read_key = Some(DESIRED_KEY.to_string());
        let r = upsert_pod_and_commit(&mut store, pod(2, 8), &cap());
        assert!(matches!(r, Err(AgentError::Store(StoreError::StorageIo))));
        // The prior generation is untouched — the resident pod is not dropped.
        assert_eq!(store.committed().unwrap().id, 1);
    }
}
