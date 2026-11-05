//! The agent protocol's semantics: one request and its answer between a
//! controller and a target's node agent. The records are
//! `modules/sdk/contracts/agent.rs`; the rules are
//! `docs/architecture/agent_protocol.md`.
//!
//! [`handle`] takes a record and the peer its transport vouches for and answers
//! a [`Reply`]. It is the only place the rules live: the local socket, stdio and
//! a runtime's mutual-TLS channel differ only in where the peer comes from.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use sha2::{Digest, Sha256};

use crate::compose::{DesiredPhase, NodeCapacity, WorkloadDesired};
use crate::genstore::{FsStorage, GenStore, Storage, StoreError};
use crate::hash::hex;
use crate::node_agent::{
    load_committed_plan, load_desired, node_status_with_runtime, publish_committed_plan,
    record_publish_path, remove_workload_and_commit, resolve_bundle, upsert_workload_and_commit,
    AgentError, RuntimePhase, WorkloadStatus,
};

/// The wire contract, `include!`d verbatim from the module SDK so a controller,
/// an agent and a module compile the same bytes.
pub mod wire {
    #![allow(dead_code, reason = "tools use a subset of the contract")]
    include!("../../modules/sdk/contracts/agent.rs");
}

use wire::{op, phase, result, DecodeError, Request, Response};

/// Key of the fence a target holds: `[epoch:u64 LE][seq:u64 LE]`.
const FENCE_KEY: &str = "agent.fence";
/// Key of the idempotency records.
const IDEMPOTENCY_KEY: &str = "agent.idempotency";
/// File serialising every writer of a store: `flock`ed for one request.
const LOCK_FILE: &str = "agent.lock";
/// Requests remembered per target; past it the oldest record goes.
pub const IDEMPOTENCY_MAX: usize = 256;
/// Domain of the activation digest.
const ACTIVATION_DOMAIN: &[u8] = b"fluxor.agent.activation\0";

/// The peer a transport vouches for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    /// The agent's own Unix socket: access to the socket is the authorization.
    Local,
    /// A key fingerprint the transport verified.
    Verified([u8; 32]),
}

/// What a target's agent is configured with.
#[derive(Clone, Debug)]
pub struct AgentContext {
    /// The target's key fingerprint.
    pub target_id: [u8; 32],
    /// Key fingerprints of the controllers of this target.
    pub controllers: Vec<[u8; 32]>,
    /// The target descriptor; its sha256 is the descriptor revision.
    pub descriptor: PathBuf,
    /// Holds `<bundle digest hex>/{workload.json,resources.json,graph.yaml}`.
    pub bundles: PathBuf,
    /// Where the committed plan is published for the runtime.
    pub publish: PathBuf,
    /// The limits admission checks against.
    pub capacity: NodeCapacity,
    /// Drain window, in seconds, of a REMOVE. 0 revokes immediately.
    pub remove_grace: u16,
}

/// A response, owned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub result: u8,
    pub target_id: [u8; 32],
    pub workload_uid: [u8; 16],
    pub descriptor_revision: [u8; 32],
    pub idempotency_id: [u8; 16],
    pub fence_epoch: u64,
    pub fence_seq: u64,
    pub observed_activation_digest: [u8; 32],
    pub desired_bundle_digest: [u8; 32],
    pub phase: u8,
    pub generation: u64,
    pub diag: Vec<u8>,
}

impl Reply {
    fn new(target_id: [u8; 32]) -> Self {
        Reply {
            result: result::OK,
            target_id,
            workload_uid: [0; 16],
            descriptor_revision: [0; 32],
            idempotency_id: [0; 16],
            fence_epoch: 0,
            fence_seq: 0,
            observed_activation_digest: [0; 32],
            desired_bundle_digest: [0; 32],
            phase: phase::ABSENT,
            generation: 0,
            diag: Vec::new(),
        }
    }

    fn with_diag(mut self, result: u8, diag: impl AsRef<str>) -> Self {
        self.result = result;
        self.diag = bounded_diag(diag.as_ref());
        self
    }

    /// The record for this reply.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; wire::RESPONSE_FIXED_LEN + self.diag.len()];
        let n = self.as_response().encode(&mut out).unwrap_or(0);
        out.truncate(n);
        out
    }

    fn as_response(&self) -> Response<'_> {
        Response {
            result: self.result,
            target_id: self.target_id,
            workload_uid: self.workload_uid,
            descriptor_revision: self.descriptor_revision,
            idempotency_id: self.idempotency_id,
            fence_epoch: self.fence_epoch,
            fence_seq: self.fence_seq,
            observed_activation_digest: self.observed_activation_digest,
            desired_bundle_digest: self.desired_bundle_digest,
            phase: self.phase,
            generation: self.generation,
            diag: &self.diag,
        }
    }

    /// Read a reply from its record.
    pub fn decode(record: &[u8]) -> Result<Reply, DecodeError> {
        let r = Response::decode(record)?;
        Ok(Reply {
            result: r.result,
            target_id: r.target_id,
            workload_uid: r.workload_uid,
            descriptor_revision: r.descriptor_revision,
            idempotency_id: r.idempotency_id,
            fence_epoch: r.fence_epoch,
            fence_seq: r.fence_seq,
            observed_activation_digest: r.observed_activation_digest,
            desired_bundle_digest: r.desired_bundle_digest,
            phase: r.phase,
            generation: r.generation,
            diag: r.diag.to_vec(),
        })
    }

    /// The reply as the JSON a controller verb prints.
    #[must_use]
    pub fn to_json(&self, verified_peer: Option<&[u8; 32]>) -> serde_json::Value {
        serde_json::json!({
            "result": result_name(self.result),
            "target_id": hex(&self.target_id),
            "verified_peer": verified_peer.map(|p| hex(p)),
            "workload_uid": hex(&self.workload_uid),
            "descriptor_revision": hex(&self.descriptor_revision),
            "idempotency_id": hex(&self.idempotency_id),
            "fence_epoch": self.fence_epoch,
            "fence_seq": self.fence_seq,
            "observed_activation_digest": hex(&self.observed_activation_digest),
            "desired_bundle_digest": hex(&self.desired_bundle_digest),
            "phase": phase_name(self.phase),
            "generation": self.generation,
            "diag": String::from_utf8_lossy(&self.diag),
        })
    }
}

/// A diagnostic cut to what a record holds, on a character boundary. The cut
/// loses text, never the refusal the result states.
fn bounded_diag(diag: &str) -> Vec<u8> {
    let mut end = diag.len().min(wire::DIAG_MAX);
    while !diag.is_char_boundary(end) {
        end -= 1;
    }
    diag.as_bytes()[..end].to_vec()
}

/// A result's name.
#[must_use]
pub fn result_name(r: u8) -> &'static str {
    match r {
        result::OK => "OK",
        result::REFUSED_FENCED => "REFUSED_FENCED",
        result::REFUSED_UNAUTHORIZED => "REFUSED_UNAUTHORIZED",
        result::REFUSED_DESCRIPTOR => "REFUSED_DESCRIPTOR",
        result::REFUSED_CONFLICT => "REFUSED_CONFLICT",
        result::BUNDLE_MISSING => "BUNDLE_MISSING",
        result::REFUSED_ADMISSION => "REFUSED_ADMISSION",
        result::BAD_REQUEST => "BAD_REQUEST",
        result::FAULT => "FAULT",
        _ => "UNKNOWN",
    }
}

/// A phase's name.
#[must_use]
pub fn phase_name(p: u8) -> &'static str {
    match p {
        phase::ABSENT => "ABSENT",
        phase::COMMITTED => "COMMITTED",
        phase::ACTIVATING => "ACTIVATING",
        phase::RUNNING => "RUNNING",
        phase::UNREADY => "UNREADY",
        phase::DRAINING => "DRAINING",
        phase::TERMINATED => "TERMINATED",
        _ => "UNKNOWN",
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Parse `N` bytes of hex, dashes allowed.
pub fn parse_hex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    let cleaned: Vec<u8> = text.bytes().filter(|c| *c != b'-').collect();
    if cleaned.len() != N * 2 || !cleaned.iter().all(u8::is_ascii_hexdigit) {
        return Err(format!("'{text}' is not {} hex characters", N * 2));
    }
    let nibble = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = nibble(cleaned[i * 2]) << 4 | nibble(cleaned[i * 2 + 1]);
    }
    Ok(out)
}

/// The revision of a target descriptor: the sha256 of the file.
pub fn descriptor_revision(path: &Path) -> io::Result<[u8; 32]> {
    Ok(sha256(&std::fs::read(path)?))
}

/// The activation digest of a workload, over what a live runtime reported:
///
/// ```text
/// sha256("fluxor.agent.activation\0" || workload_uid || workload_digest
///        || applied_plan_digest || slot:u16 LE || owner_generation:u32 LE)
/// ```
#[must_use]
pub fn activation_digest(
    workload_uid: &[u8; 16],
    workload_digest: &[u8; 32],
    applied_plan_digest: &[u8; 32],
    slot: u16,
    owner_generation: u32,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ACTIVATION_DOMAIN);
    h.update(workload_uid);
    h.update(workload_digest);
    h.update(applied_plan_digest);
    h.update(slot.to_le_bytes());
    h.update(owner_generation.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// One remembered request: what it was, and the generation its commit was to
/// be. `response` is absent while the commit's outcome is unrecorded.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct IdempotencyRecord {
    workload_uid: String,
    idempotency_id: String,
    request_digest: String,
    generation: u64,
    #[serde(default)]
    response: Option<String>,
}

impl IdempotencyRecord {
    fn is_for(&self, uid: &[u8; 16], id: &[u8; 16]) -> bool {
        self.workload_uid == hex(uid) && self.idempotency_id == hex(id)
    }
}

fn load_fence<S: Storage>(store: &GenStore<S>) -> Result<(u64, u64), String> {
    let bytes = store
        .storage
        .read(FENCE_KEY)
        .map_err(|e| format!("read fence: {e}"))?;
    let Some(bytes) = bytes else {
        return Ok((0, 0));
    };
    match (bytes.get(0..8), bytes.get(8..16), bytes.len()) {
        (Some(e), Some(s), 16) => {
            let mut epoch = [0u8; 8];
            let mut seq = [0u8; 8];
            epoch.copy_from_slice(e);
            seq.copy_from_slice(s);
            Ok((u64::from_le_bytes(epoch), u64::from_le_bytes(seq)))
        }
        _ => Err("the held fence is corrupt".to_string()),
    }
}

fn save_fence<S: Storage>(store: &mut GenStore<S>, fence: (u64, u64)) -> Result<(), String> {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&fence.0.to_le_bytes());
    bytes[8..].copy_from_slice(&fence.1.to_le_bytes());
    store
        .storage
        .write(FENCE_KEY, &bytes)
        .map_err(|e| format!("write fence: {e}"))
}

fn load_records<S: Storage>(store: &GenStore<S>) -> Result<Vec<IdempotencyRecord>, String> {
    match store
        .storage
        .read(IDEMPOTENCY_KEY)
        .map_err(|e| format!("read idempotency records: {e}"))?
    {
        None => Ok(Vec::new()),
        Some(b) => serde_json::from_slice(&b)
            .map_err(|e| format!("the idempotency records are corrupt: {e}")),
    }
}

/// Replace the record of `rec`'s key with `rec`, newest last, keeping the
/// newest [`IDEMPOTENCY_MAX`].
fn save_record<S: Storage>(store: &mut GenStore<S>, rec: IdempotencyRecord) -> Result<(), String> {
    let mut records = load_records(store)?;
    records.retain(|r| {
        !(r.workload_uid == rec.workload_uid && r.idempotency_id == rec.idempotency_id)
    });
    records.push(rec);
    if records.len() > IDEMPOTENCY_MAX {
        let excess = records.len() - IDEMPOTENCY_MAX;
        records.drain(..excess);
    }
    let bytes =
        serde_json::to_vec(&records).map_err(|e| format!("encode idempotency records: {e}"))?;
    store
        .storage
        .write(IDEMPOTENCY_KEY, &bytes)
        .map_err(|e| format!("write idempotency records: {e}"))
}

fn forget_record<S: Storage>(
    store: &mut GenStore<S>,
    uid: &[u8; 16],
    id: &[u8; 16],
) -> Result<(), String> {
    let mut records = load_records(store)?;
    records.retain(|r| !r.is_for(uid, id));
    let bytes =
        serde_json::to_vec(&records).map_err(|e| format!("encode idempotency records: {e}"))?;
    store
        .storage
        .write(IDEMPOTENCY_KEY, &bytes)
        .map_err(|e| format!("write idempotency records: {e}"))
}

/// Answer one request record from `peer`. Every outcome is a [`Reply`]; the
/// reply is what the store now says, never what was hoped.
pub fn handle<S: Storage>(
    record: &[u8],
    peer: Peer,
    ctx: &AgentContext,
    store: &mut GenStore<S>,
) -> Reply {
    let mut reply = Reply::new(ctx.target_id);
    let decoded = Request::decode(record);
    if let Ok(req) = &decoded {
        reply.workload_uid = req.workload_uid;
        reply.idempotency_id = req.idempotency_id;
    }
    // Before anything is read: a peer that is not a controller learns only the
    // identity its handshake already showed it.
    let authorized = match peer {
        Peer::Local => true,
        Peer::Verified(fp) => fp != [0; 32] && ctx.controllers.contains(&fp),
    };
    if !authorized {
        return reply.with_diag(
            result::REFUSED_UNAUTHORIZED,
            "the peer is not a controller of this target",
        );
    }
    let req = match decoded {
        Ok(req) => req,
        Err(e) => {
            if let Ok((epoch, seq)) = load_fence(store) {
                reply.fence_epoch = epoch;
                reply.fence_seq = seq;
            }
            return reply.with_diag(result::BAD_REQUEST, format!("{e:?}"));
        }
    };
    let held = load_fence(store);
    match answer(&req, ctx, store, reply.clone()) {
        Ok(r) => r,
        Err(fault) => {
            let mut r = reply;
            if let Ok((epoch, seq)) = load_fence(store).or(held) {
                r.fence_epoch = epoch;
                r.fence_seq = seq;
            }
            r.with_diag(result::FAULT, fault)
        }
    }
}

/// `Err` is a fault of the target's own state; a refusal is an `Ok` reply.
fn answer<S: Storage>(
    req: &Request,
    ctx: &AgentContext,
    store: &mut GenStore<S>,
    mut reply: Reply,
) -> Result<Reply, String> {
    let held = load_fence(store)?;
    let asked = (req.fence_epoch, req.fence_seq);
    if asked < held {
        reply.fence_epoch = held.0;
        reply.fence_seq = held.1;
        return Ok(reply.with_diag(
            result::REFUSED_FENCED,
            format!(
                "fence ({}, {}) is below the held ({}, {})",
                asked.0, asked.1, held.0, held.1
            ),
        ));
    }
    if asked > held {
        save_fence(store, asked)?;
    }
    let fence = asked.max(held);
    reply.fence_epoch = fence.0;
    reply.fence_seq = fence.1;
    let revision = descriptor_revision(&ctx.descriptor)
        .map_err(|e| format!("read descriptor {}: {e}", ctx.descriptor.display()))?;
    reply.descriptor_revision = revision;

    match req.op {
        op::OBSERVE => {
            observe(req.workload_uid, store, &mut reply)?;
            Ok(reply)
        }
        op::APPLY | op::REMOVE => mutate(req, ctx, store, reply, &revision),
        // `Request::decode` admits no other value.
        _ => Ok(reply.with_diag(result::BAD_REQUEST, "unknown op")),
    }
}

fn mutate<S: Storage>(
    req: &Request,
    ctx: &AgentContext,
    store: &mut GenStore<S>,
    mut reply: Reply,
    revision: &[u8; 32],
) -> Result<Reply, String> {
    if req.workload_uid == [0; 16] {
        return Ok(reply.with_diag(result::BAD_REQUEST, "workload_uid is zero"));
    }
    if req.idempotency_id == [0; 16] {
        return Ok(reply.with_diag(result::BAD_REQUEST, "idempotency_id is zero"));
    }
    if req.op == op::APPLY && req.desired_bundle_digest == [0; 32] {
        return Ok(reply.with_diag(result::BAD_REQUEST, "desired_bundle_digest is zero"));
    }

    // Before the descriptor is looked at: a request already done is answered
    // with what it did, whatever has changed since.
    let mut request_bytes = [0u8; wire::REQUEST_LEN];
    let request_len = req.encode(&mut request_bytes).unwrap_or(0);
    let request_digest = hex(&sha256(&request_bytes[..request_len]));
    let records = load_records(store)?;
    let existing = records
        .iter()
        .find(|r| r.is_for(&req.workload_uid, &req.idempotency_id));
    let mut already_committed = false;
    if let Some(rec) = existing {
        if rec.request_digest != request_digest {
            return Ok(reply.with_diag(
                result::REFUSED_CONFLICT,
                "this idempotency_id was used by a different request",
            ));
        }
        if let Some(recorded) = &rec.response {
            return replay(recorded);
        }
        // The last attempt got as far as this record and no further. Whether
        // its commit landed is in the store.
        already_committed =
            store.committed().is_some_and(|g| g.id >= rec.generation) && desired_is(store, req)?;
    }

    if !already_committed {
        if req.op == op::APPLY && req.descriptor_revision != *revision {
            return Ok(reply.with_diag(
                result::REFUSED_DESCRIPTOR,
                format!(
                    "descriptor revision {} is not the target's {}",
                    hex(&req.descriptor_revision),
                    hex(revision)
                ),
            ));
        }
        let workload = if req.op == op::APPLY {
            match admit(req, ctx) {
                Ok(w) => Some(w),
                Err(refusal) => {
                    observe(req.workload_uid, store, &mut reply)?;
                    return Ok(reply.with_diag(refusal.0, refusal.1));
                }
            }
        } else {
            if !present(store, &req.workload_uid)? {
                // Already gone: nothing to commit, and no generation to rebuild
                // the other workloads for.
                observe(req.workload_uid, store, &mut reply)?;
                return Ok(reply);
            }
            None
        };

        let next = store.committed().map_or(1, |g| g.id + 1);
        save_record(
            store,
            IdempotencyRecord {
                workload_uid: hex(&req.workload_uid),
                idempotency_id: hex(&req.idempotency_id),
                request_digest: request_digest.clone(),
                generation: next,
                response: None,
            },
        )?;
        let outcome = match workload {
            Some(w) => upsert_workload_and_commit(store, w, &ctx.capacity),
            None => {
                remove_workload_and_commit(store, req.workload_uid, ctx.remove_grace, &ctx.capacity)
            }
        };
        match outcome {
            Ok(_) => {}
            Err(AgentError::Compose(e)) => {
                forget_record(store, &req.workload_uid, &req.idempotency_id)?;
                observe(req.workload_uid, store, &mut reply)?;
                return Ok(reply.with_diag(result::REFUSED_ADMISSION, format!("{e:?}")));
            }
            Err(AgentError::Store(e)) => return Err(store_fault(e)),
        }
    }

    publish_committed_plan(store, &ctx.publish)
        .map_err(|e| format!("publish {}: {e}", ctx.publish.display()))?;
    record_publish_path(store, &ctx.publish).map_err(store_fault)?;
    observe(req.workload_uid, store, &mut reply)?;
    let generation = reply.generation;
    save_record(
        store,
        IdempotencyRecord {
            workload_uid: hex(&req.workload_uid),
            idempotency_id: hex(&req.idempotency_id),
            request_digest,
            generation,
            response: Some(hex(&reply.encode())),
        },
    )?;
    Ok(reply)
}

fn replay(recorded: &str) -> Result<Reply, String> {
    let bytes = (0..recorded.len() / 2)
        .map(|i| u8::from_str_radix(recorded.get(i * 2..i * 2 + 2).unwrap_or(""), 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| format!("the recorded response is corrupt: {e}"))?;
    Reply::decode(&bytes).map_err(|e| format!("the recorded response is corrupt: {e:?}"))
}

fn store_fault(e: StoreError) -> String {
    format!("generation store: {e:?}")
}

/// Does the desired set already say what `req` asks?
fn desired_is<S: Storage>(store: &GenStore<S>, req: &Request) -> Result<bool, String> {
    let desired = load_desired(store).map_err(store_fault)?;
    let row = desired.iter().find(|w| w.workload_uid == req.workload_uid);
    Ok(if req.op == op::APPLY {
        row.is_some_and(|w| w.workload_digest == req.desired_bundle_digest)
    } else {
        row.is_none()
    })
}

/// Is the workload in the desired set or the committed plan?
fn present<S: Storage>(store: &GenStore<S>, uid: &[u8; 16]) -> Result<bool, String> {
    let desired = load_desired(store).map_err(store_fault)?;
    if desired.iter().any(|w| w.workload_uid == *uid) {
        return Ok(true);
    }
    Ok(load_committed_plan(store)
        .is_some_and(|p| p.assignments.iter().any(|a| a.workload_uid == *uid)))
}

/// Resolve the desired bundle by digest and put it through admission: the
/// workload to commit, or the result and diagnostic that refuse it.
fn admit(req: &Request, ctx: &AgentContext) -> Result<WorkloadDesired, (u8, String)> {
    let dir = ctx.bundles.join(hex(&req.desired_bundle_digest));
    let manifest = match std::fs::read(dir.join("workload.json")) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err((
                result::BUNDLE_MISSING,
                format!("no bundle at {}", dir.display()),
            ));
        }
        Err(e) => {
            return Err((
                result::REFUSED_ADMISSION,
                format!("bundle {}: workload.json: {e}", dir.display()),
            ));
        }
    };
    let actual = sha256(&manifest);
    if actual != req.desired_bundle_digest {
        return Err((
            result::REFUSED_ADMISSION,
            format!(
                "bundle {}: workload.json hashes to {}",
                dir.display(),
                hex(&actual)
            ),
        ));
    }
    let bundle = resolve_bundle(&dir).map_err(|d| (result::REFUSED_ADMISSION, d))?;
    Ok(WorkloadDesired {
        workload_uid: req.workload_uid,
        namespace: "default".to_string(),
        name: bundle.name,
        workload_digest: bundle.workload_digest,
        config_generation: 0,
        desired_phase: DesiredPhase::Running,
        profile: bundle.profile,
        exports: bundle.exports,
    })
}

/// Fill `reply` with what the target observes of the workload. The activation
/// digest stays zero unless a live runtime reports exactly the committed plan
/// and the workload's owner running under it.
fn observe<S: Storage>(
    uid: [u8; 16],
    store: &GenStore<S>,
    reply: &mut Reply,
) -> Result<(), String> {
    let status = node_status_with_runtime(store).map_err(store_fault)?;
    let desired = load_desired(store).map_err(store_fault)?;
    let workload_digest = desired
        .iter()
        .find(|w| w.workload_uid == uid)
        .map(|w| w.workload_digest);
    let uid_hex = hex(&uid);
    let row = status
        .workloads
        .iter()
        .find(|w| w.workload_uid_hex == uid_hex);

    reply.generation = status.generation.unwrap_or(0);
    reply.desired_bundle_digest = workload_digest.unwrap_or([0; 32]);
    reply.phase = row.map_or(phase::ABSENT, phase_of);
    reply.observed_activation_digest = [0; 32];

    let committed_plan = load_committed_plan(store).map(|p| hex(&p.plan_digest));
    if let (Some(row), Some(digest), Some(plan_hex), Some(reported)) = (
        row,
        workload_digest,
        committed_plan,
        status.runtime_plan_digest.as_deref(),
    ) {
        let active = row.committed
            && reported == plan_hex
            && matches!(reply.phase, phase::RUNNING | phase::UNREADY);
        if let (true, Some(slot), Some(generation), Ok(plan)) = (
            active,
            row.slot,
            row.owner_generation,
            parse_hex::<32>(reported),
        ) {
            reply.observed_activation_digest =
                activation_digest(&uid, &digest, &plan, slot, generation);
        }
    }
    Ok(())
}

fn phase_of(row: &WorkloadStatus) -> u8 {
    let Some(rt) = row.runtime.as_ref() else {
        return if row.committed {
            phase::COMMITTED
        } else {
            phase::ABSENT
        };
    };
    if rt.owner_state.as_deref() == Some("Draining") {
        return phase::DRAINING;
    }
    match rt.phase {
        RuntimePhase::Activating => phase::ACTIVATING,
        RuntimePhase::Running if rt.ready => phase::RUNNING,
        RuntimePhase::Running => phase::UNREADY,
        RuntimePhase::Terminated => phase::TERMINATED,
    }
}

/// Holds every other writer of a store out for its lifetime.
pub struct StoreLock {
    file: std::fs::File,
}

impl StoreLock {
    /// Wait for the store's lock, creating the store if it is not there.
    pub fn acquire(store_dir: &Path) -> io::Result<StoreLock> {
        use std::os::fd::AsRawFd;
        std::fs::create_dir_all(store_dir)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(store_dir.join(LOCK_FILE))?;
        loop {
            // SAFETY: the fd is valid for the call; flock takes no pointers.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(StoreLock { file });
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: the fd is valid for the call; flock takes no pointers.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// [`handle`] over the store at `store_dir`, under its lock and from its
/// durable state alone.
pub fn handle_in_dir(record: &[u8], peer: Peer, ctx: &AgentContext, store_dir: &Path) -> Reply {
    let opened = StoreLock::acquire(store_dir)
        .and_then(|lock| FsStorage::open(store_dir).map(|storage| (lock, storage)));
    match opened {
        Ok((_lock, storage)) => handle(record, peer, ctx, &mut GenStore::new(storage)),
        Err(e) => Reply::new(ctx.target_id).with_diag(result::FAULT, format!("open store: {e}")),
    }
}

/// One frame off a stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    /// A whole record and the peer ahead of it.
    Record([u8; 32], Vec<u8>),
    /// A record over [`wire::AGENT_RECORD_MAX`], read past and not kept.
    Oversize([u8; 32]),
    /// The stream ended at a frame boundary.
    End,
}

/// Read one frame. A stream that ends inside a frame is an error.
pub fn read_frame(r: &mut impl Read) -> io::Result<Frame> {
    let mut header = [0u8; wire::FRAME_HEADER_LEN];
    let mut have = 0;
    while have < header.len() {
        match r.read(&mut header[have..]) {
            Ok(0) if have == 0 => return Ok(Frame::End),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => have += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let Some((peer, len)) = wire::decode_frame_header(&header) else {
        return Err(io::ErrorKind::InvalidData.into());
    };
    if len as usize > wire::AGENT_RECORD_MAX {
        let skipped = io::copy(&mut r.by_ref().take(u64::from(len)), &mut io::sink())?;
        if skipped != u64::from(len) {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        return Ok(Frame::Oversize(peer));
    }
    let mut record = vec![0u8; len as usize];
    r.read_exact(&mut record)?;
    Ok(Frame::Record(peer, record))
}

/// Write one frame, whole.
pub fn write_frame(w: &mut impl Write, peer: &[u8; 32], record: &[u8]) -> io::Result<()> {
    let mut frame = vec![0u8; wire::FRAME_HEADER_LEN];
    if wire::encode_frame_header(peer, record.len(), &mut frame).is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "record over the protocol's maximum",
        ));
    }
    frame.extend_from_slice(record);
    w.write_all(&frame)?;
    w.flush()
}

/// Where a frame's peer comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerSource {
    /// The agent's own Unix socket: whatever the client sends, the peer is
    /// [`Peer::Local`].
    Local,
    /// A transport that stamps the peer it verified. All zero names nobody.
    Stamped,
}

/// Serve frames until the stream ends at a boundary, answering each to the peer
/// it came from.
pub fn serve_stream(
    r: &mut impl Read,
    w: &mut impl Write,
    source: PeerSource,
    ctx: &AgentContext,
    store_dir: &Path,
) -> io::Result<()> {
    let peer_of = |fp: [u8; 32]| match source {
        PeerSource::Local => Peer::Local,
        PeerSource::Stamped => Peer::Verified(fp),
    };
    loop {
        let (fp, reply) = match read_frame(r)? {
            Frame::End => return Ok(()),
            Frame::Record(fp, record) => (fp, handle_in_dir(&record, peer_of(fp), ctx, store_dir)),
            Frame::Oversize(fp) => (
                fp,
                Reply::new(ctx.target_id)
                    .with_diag(result::BAD_REQUEST, "record over the protocol's maximum"),
            ),
        };
        write_frame(w, &fp, &reply.encode())?;
    }
}

/// Start a `fluxor-linux` that carries frames on its stdin and stdout: the
/// graph's `cli_in` and `cli_out` wired to the agent channel. It ends with this
/// process. It is told nothing of a plan: a transport's graph is the node's
/// connection to its controllers, and it must not rebuild when a workload
/// changes.
pub fn spawn_transport(
    runtime: &Path,
    config: &Path,
    modules: &Path,
    log: Stdio,
) -> io::Result<Child> {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new(runtime);
    cmd.arg("--config")
        .arg(config)
        .arg("--modules")
        .arg(modules)
        .env_remove("FLUXOR_PLAN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(log);
    // SAFETY: prctl is async-signal-safe and touches no memory of this process.
    unsafe {
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// Read frames off `r` on a thread of their own, so a caller can bound its wait.
pub fn frame_reader(
    mut r: impl Read + Send + 'static,
) -> std::sync::mpsc::Receiver<io::Result<Frame>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || loop {
        let frame = read_frame(&mut r);
        let last = !matches!(frame, Ok(Frame::Record(..) | Frame::Oversize(_)));
        if tx.send(frame).is_err() || last {
            return;
        }
    });
    rx
}

/// How a controller's call went wrong before it had an answer it may use.
#[derive(Debug, PartialEq, Eq)]
pub enum CallError {
    /// The transport ended, or no answer came in time.
    Transport(String),
    /// The record is not a response.
    Malformed(String),
    /// The target states another identity than the one its transport verified,
    /// or than the one the controller expects.
    TargetMismatch {
        stated: [u8; 32],
        verified: [u8; 32],
    },
    /// The response answers another request.
    WrongRequest,
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Transport(e) => write!(f, "transport: {e}"),
            CallError::Malformed(e) => write!(f, "malformed response: {e}"),
            CallError::TargetMismatch { stated, verified } => write!(
                f,
                "target identity mismatch: the response states {}, the expected or verified \
                 identity is {}",
                hex(stated),
                hex(verified)
            ),
            CallError::WrongRequest => write!(f, "the response answers another request"),
        }
    }
}

/// Take a controller's answer from one received frame. The response is used
/// only if it answers `req` and its `target_id` is the identity that matters:
/// the fingerprint the transport stamped on the frame when the transport
/// `verified` one, and `expected`, the identity the controller was told to reach.
pub fn accept_response(
    stamped: &[u8; 32],
    record: &[u8],
    req: &Request,
    verified: bool,
    expected: Option<&[u8; 32]>,
) -> Result<Reply, CallError> {
    let reply = Reply::decode(record).map_err(|e| CallError::Malformed(format!("{e:?}")))?;
    if verified && reply.target_id != *stamped {
        return Err(CallError::TargetMismatch {
            stated: reply.target_id,
            verified: *stamped,
        });
    }
    if let Some(want) = expected {
        if reply.target_id != *want {
            return Err(CallError::TargetMismatch {
                stated: reply.target_id,
                verified: *want,
            });
        }
    }
    // A malformed request cannot be echoed, so a BAD_REQUEST names none.
    if reply.result != result::BAD_REQUEST
        && (reply.workload_uid != req.workload_uid || reply.idempotency_id != req.idempotency_id)
    {
        return Err(CallError::WrongRequest);
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::wire::*;

    fn request() -> Request {
        Request {
            op: op::APPLY,
            flags: 0,
            workload_uid: [1; 16],
            desired_bundle_digest: [2; 32],
            descriptor_revision: [3; 32],
            idempotency_id: [4; 16],
            fence_epoch: 5,
            fence_seq: 6,
        }
    }

    fn response(diag: &[u8]) -> Response<'_> {
        Response {
            result: result::OK,
            target_id: [1; 32],
            workload_uid: [2; 16],
            descriptor_revision: [3; 32],
            idempotency_id: [4; 16],
            fence_epoch: 5,
            fence_seq: 6,
            observed_activation_digest: [7; 32],
            desired_bundle_digest: [8; 32],
            phase: phase::RUNNING,
            generation: 9,
            diag,
        }
    }

    #[test]
    fn request_round_trips_little_endian() {
        let mut buf = [0u8; REQUEST_LEN];
        assert_eq!(request().encode(&mut buf), Some(REQUEST_LEN));
        assert_eq!(buf[0], op::APPLY);
        assert_eq!(&buf[98..106], &5u64.to_le_bytes());
        assert_eq!(&buf[106..114], &6u64.to_le_bytes());
        assert_eq!(Request::decode(&buf), Ok(request()));
    }

    #[test]
    fn request_encode_never_overruns() {
        for n in 0..REQUEST_LEN {
            let mut buf = vec![0u8; n];
            assert_eq!(request().encode(&mut buf), None, "buffer of {n}");
        }
    }

    #[test]
    fn request_decode_holds_every_bound() {
        let mut buf = [0u8; REQUEST_LEN + 1];
        request().encode(&mut buf).unwrap();
        for n in 0..REQUEST_LEN {
            assert_eq!(Request::decode(&buf[..n]), Err(DecodeError::Truncated));
        }
        assert_eq!(Request::decode(&buf), Err(DecodeError::TrailingBytes));

        let mut bad = [0u8; REQUEST_LEN];
        request().encode(&mut bad).unwrap();
        bad[0] = 0;
        assert_eq!(Request::decode(&bad), Err(DecodeError::BadOp));
        bad[0] = op::OBSERVE + 1;
        assert_eq!(Request::decode(&bad), Err(DecodeError::BadOp));
        bad[0] = op::APPLY;
        bad[1] = 1;
        assert_eq!(Request::decode(&bad), Err(DecodeError::BadFlags));
        bad[1] = 0;
        bad[0] = op::OBSERVE;
        assert_eq!(Request::decode(&bad), Err(DecodeError::UnexpectedDigest));
        bad[0] = op::REMOVE;
        assert_eq!(Request::decode(&bad), Err(DecodeError::UnexpectedDigest));
    }

    #[test]
    fn response_round_trips_and_is_exact() {
        let diag = b"no linux implementation";
        let mut buf = [0u8; RESPONSE_FIXED_LEN + 64];
        let n = response(diag).encode(&mut buf).unwrap();
        assert_eq!(n, RESPONSE_FIXED_LEN + diag.len());
        assert_eq!(Response::decode(&buf[..n]), Ok(response(diag)));
        for short in 0..n {
            assert_eq!(
                Response::decode(&buf[..short]),
                Err(DecodeError::Truncated),
                "{short}"
            );
        }
        assert_eq!(
            Response::decode(&buf[..n + 1]),
            Err(DecodeError::TrailingBytes)
        );
    }

    #[test]
    fn response_refuses_what_it_does_not_define() {
        let mut buf = [0u8; RESPONSE_FIXED_LEN];
        let n = response(b"").encode(&mut buf).unwrap();
        let mut bad = buf;
        bad[0] = result::LAST + 1;
        assert_eq!(Response::decode(&bad[..n]), Err(DecodeError::BadResult));
        let mut bad = buf;
        bad[177] = phase::LAST + 1;
        assert_eq!(Response::decode(&bad[..n]), Err(DecodeError::BadPhase));
        let mut bad = buf;
        bad[186..188].copy_from_slice(&((DIAG_MAX + 1) as u16).to_le_bytes());
        assert_eq!(Response::decode(&bad[..n]), Err(DecodeError::DiagTooLong));
    }

    #[test]
    fn the_largest_diagnostic_fits_the_record_and_one_more_does_not() {
        let diag = vec![b'x'; DIAG_MAX];
        let mut buf = vec![0u8; AGENT_RECORD_MAX + 1];
        let n = response(&diag).encode(&mut buf).unwrap();
        assert_eq!(n, AGENT_RECORD_MAX);
        assert_eq!(Response::decode(&buf[..n]).unwrap().diag.len(), DIAG_MAX);
        let over = vec![b'x'; DIAG_MAX + 1];
        assert_eq!(response(&over).encode(&mut buf), None);
    }

    #[test]
    fn a_frame_header_is_peer_then_length() {
        let mut h = [0u8; FRAME_HEADER_LEN];
        assert_eq!(
            encode_frame_header(&[9; PEER_LEN], 300, &mut h),
            Some(FRAME_HEADER_LEN)
        );
        assert_eq!(&h[..32], &[9; 32]);
        assert_eq!(&h[32..], &300u32.to_le_bytes());
        assert_eq!(decode_frame_header(&h), Some(([9; 32], 300)));
        assert_eq!(decode_frame_header(&h[..35]), None);
        assert_eq!(
            encode_frame_header(&[0; PEER_LEN], AGENT_RECORD_MAX + 1, &mut h),
            None
        );
    }

    #[test]
    fn the_channel_table_states_the_record_and_its_length_field() {
        assert_eq!(
            CHANNEL_TABLE,
            format!("OctetStream:len32:{}", AGENT_RECORD_MAX + 4)
        );
    }
}
