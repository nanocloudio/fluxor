//! `fluxor agent` — the narrow local protocol a host orchestrator (nanocloud's
//! `FluxorGraphWorkloadRuntime`) drives instead of linking fluxor-tools as a
//! library (rfc_k8s.md §18.3 / Q12: "a neutral OCI execution library **or a
//! narrow local service protocol**"). One verb for now:
//!
//! `fluxor agent commit` — reconcile a single-pod desired state into a durable
//! generation store and publish the committed plan blob for the Linux
//! runtime's `FLUXOR_PLAN` staging. Prints the workload handle
//! (`fluxor://<pod-uid-hex>/<generation>`) on stdout for the caller to track.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::error::{Error, Result};
use fluxor_tools::compose::{DesiredPhase, NodeCapacity, PodDesired, ResourceProfile};
use fluxor_tools::genstore::{FsStorage, GenStore};
use fluxor_tools::node_agent::{
    publish_committed_plan, remove_pod_and_commit, upsert_pod_and_commit,
};
use fluxor_tools::workload::{
    parse_manifest, parse_resource_profile, select_implementation, validate,
};

#[derive(Args, Debug)]
pub struct AgentArgs {
    #[command(subcommand)]
    pub command: AgentCommand,
}

#[derive(Subcommand, Debug)]
pub enum AgentCommand {
    /// Upsert a pod into the node's desired state, recompose all resident
    /// pods into the next generation, and publish the plan blob.
    Commit(CommitArgs),
    /// Remove a pod from the desired state, recompose, and publish.
    Remove(RemoveArgs),
}

#[derive(Args, Debug)]
pub struct RemoveArgs {
    #[arg(long)]
    pub store: PathBuf,
    #[arg(long)]
    pub publish: PathBuf,
    /// Pod UID as 32 hex chars (dashes allowed).
    #[arg(long)]
    pub pod_uid: String,
}

#[derive(Args, Debug)]
pub struct CommitArgs {
    /// Generation-store directory (created if absent).
    #[arg(long)]
    pub store: PathBuf,
    /// Path to publish the committed plan blob to (FLUXOR_PLAN target).
    #[arg(long)]
    pub publish: PathBuf,
    /// Pod UID as 32 hex chars (Kubernetes UID with dashes stripped).
    #[arg(long)]
    pub pod_uid: String,
    #[arg(long, default_value = "default")]
    pub namespace: String,
    #[arg(long)]
    pub name: String,
    /// Signed resource profile: module count.
    #[arg(long, default_value_t = 1)]
    pub modules: u16,
    /// Signed resource profile: edge count.
    #[arg(long, default_value_t = 0)]
    pub edges: u16,
    /// Signed resource profile: state-byte cap.
    #[arg(long, default_value_t = 0)]
    pub state_bytes: u32,
    /// Signed resource profile: buffer-byte cap.
    #[arg(long, default_value_t = 0)]
    pub buffer_bytes: u32,
    /// Workload bundle directory: validates `workload.json`, selects
    /// the linux implementation, and takes the resource profile from
    /// `resources.json` — overriding the explicit profile flags above.
    #[arg(long)]
    pub bundle: Option<PathBuf>,
}

/// Raw sha256 of `bytes`.
fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// `sha256:<hex>` of `bytes` (the manifest's digest spelling).
fn sha256_ref(bytes: &[u8]) -> String {
    let mut s = String::from("sha256:");
    for b in sha256_bytes(bytes) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Verify an on-disk artifact's content hashes to the manifest's pinned digest.
/// A bundle whose artifact bytes don't match the declared digest is rejected —
/// modified artifacts must never be admitted.
fn verify_artifact(bytes: &[u8], declared: &str, what: &str) -> Result<()> {
    let actual = sha256_ref(bytes);
    if actual != declared {
        return Err(Error::Config(format!(
            "bundle {what}: content digest mismatch (manifest pins {declared}, artifact is {actual})"
        )));
    }
    Ok(())
}

/// Validate a bundle dir and extract the pod's resource profile + workload
/// digest from it. Admission-gates the manifest: a bundle that fails
/// validation, lacks a linux implementation, or whose artifacts don't match the
/// manifest's pinned digests is rejected before anything is committed.
///
/// This is the local-orchestrator trust model (rfc_k8s.md §18.3): the manifest
/// arrives from the trusted local host, and the artifacts (`resources.json`,
/// `graph.yaml`) are verified against the digests it pins — a modified artifact
/// fails. (Verifying a *signature over the manifest itself* is the untrusted-
/// source path and requires the bundle to carry a signature; the format does
/// not yet, so that layer is out of scope here.)
fn resolve_bundle(dir: &std::path::Path) -> Result<(ResourceProfile, [u8; 32])> {
    let manifest_json = std::fs::read_to_string(dir.join("workload.json"))
        .map_err(|e| Error::Config(format!("bundle {}: workload.json: {e}", dir.display())))?;
    let manifest = parse_manifest(&manifest_json).map_err(Error::Config)?;
    let report = validate(&manifest);
    if !report.is_ok() {
        return Err(Error::Config(format!(
            "bundle '{}' failed validation: {}",
            manifest.name,
            report.errors.join("; ")
        )));
    }
    let imp = select_implementation(&manifest, "linux", "aarch64", 1).ok_or_else(|| {
        Error::Config(format!(
            "bundle '{}' has no linux/aarch64/abi-1 implementation",
            manifest.name
        ))
    })?;

    // Verify the bundle's artifacts against the digests the manifest pins.
    let resources_json = std::fs::read(dir.join("resources.json"))
        .map_err(|e| Error::Config(format!("bundle {}: resources.json: {e}", dir.display())))?;
    verify_artifact(&resources_json, &imp.resources.digest, "resources.json")?;
    let graph_yaml = std::fs::read(dir.join("graph.yaml"))
        .map_err(|e| Error::Config(format!("bundle {}: graph.yaml: {e}", dir.display())))?;
    verify_artifact(&graph_yaml, &imp.graph.digest, "graph.yaml")?;

    let doc =
        parse_resource_profile(&String::from_utf8(resources_json).map_err(|e| {
            Error::Config(format!("bundle {}: resources.json: {e}", dir.display()))
        })?)
        .map_err(Error::Config)?;

    // The workload digest identifies the (verified) workload: the sha256 of its
    // manifest, recorded on the pod so the committed generation is tied to a
    // specific workload rather than a zeroed placeholder.
    let workload_digest = sha256_bytes(manifest_json.as_bytes());
    Ok((doc.to_compose(), workload_digest))
}

fn parse_pod_uid(hex: &str) -> Result<[u8; 16]> {
    let cleaned: String = hex.chars().filter(|c| *c != '-').collect();
    if cleaned.len() != 32 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Config(format!(
            "--pod-uid must be 32 hex chars (got '{hex}')"
        )));
    }
    let mut uid = [0u8; 16];
    for (i, byte) in uid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
            .map_err(|e| Error::Config(format!("--pod-uid: {e}")))?;
    }
    Ok(uid)
}

/// Node capacity facts for the Linux host profile (matches
/// `modules/sdk/config.rs` `profile_host`). A future verb can read these from
/// the running kernel instead of mirroring the profile.
fn linux_capacity() -> NodeCapacity {
    NodeCapacity {
        max_owners: 64,
        max_modules: 128,
        max_edges: 128,
        state_bytes: 64 * 1024 * 1024,
        buffer_bytes: 8 * 1024 * 1024,
        max_endpoints: 64,
        max_domains: 4,
    }
}

pub fn dispatch(args: AgentArgs) -> Result<()> {
    match args.command {
        AgentCommand::Commit(c) => commit(c),
        AgentCommand::Remove(r) => remove(r),
    }
}

fn remove(r: RemoveArgs) -> Result<()> {
    let pod_uid = parse_pod_uid(&r.pod_uid)?;
    let storage = FsStorage::open(&r.store)
        .map_err(|e| Error::Config(format!("open store {}: {e}", r.store.display())))?;
    let mut store = GenStore::new(storage);
    let (plan, gen) = remove_pod_and_commit(&mut store, pod_uid, &linux_capacity())
        .map_err(|e| Error::Config(format!("remove/recompose failed: {e:?}")))?;
    publish_committed_plan(&store, &r.publish)
        .map_err(|e| Error::Config(format!("publish failed: {e}")))?;
    println!("gen {} pods {}", gen, plan.assignments.len());
    Ok(())
}

fn commit(c: CommitArgs) -> Result<()> {
    let pod_uid = parse_pod_uid(&c.pod_uid)?;
    let (profile, workload_digest) = match &c.bundle {
        Some(dir) => resolve_bundle(dir)?,
        None => (
            ResourceProfile {
                modules: c.modules,
                edges: c.edges,
                state_bytes: c.state_bytes,
                buffer_bytes: c.buffer_bytes,
                endpoints: 0,
                domains: 1,
            },
            // No bundle → ad-hoc profile, no workload identity to pin.
            [0u8; 32],
        ),
    };
    let pod = PodDesired {
        pod_uid,
        namespace: c.namespace.clone(),
        name: c.name.clone(),
        workload_digest,
        config_generation: 0,
        desired_phase: DesiredPhase::Running,
        profile,
    };

    let storage = FsStorage::open(&c.store)
        .map_err(|e| Error::Config(format!("open store {}: {e}", c.store.display())))?;
    let mut store = GenStore::new(storage);
    let (_plan, gen) = upsert_pod_and_commit(&mut store, pod, &linux_capacity())
        .map_err(|e| Error::Config(format!("reconcile/commit failed: {e:?}")))?;
    publish_committed_plan(&store, &c.publish)
        .map_err(|e| Error::Config(format!("publish failed: {e}")))?
        .ok_or_else(|| Error::Config("no committed generation after commit".into()))?;

    // The workload handle the orchestrator tracks (rfc_k8s.md §7.2).
    println!(
        "fluxor://{}/{}",
        c.pod_uid.chars().filter(|c| *c != '-').collect::<String>(),
        gen
    );
    Ok(())
}
