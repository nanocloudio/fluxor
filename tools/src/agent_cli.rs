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
use fluxor_tools::compose::{
    capacity_for_profile, DesiredPhase, NodeCapacity, PodDesired, ResourceProfile,
};
use fluxor_tools::genstore::{FsStorage, GenStore};
use fluxor_tools::node_agent::{
    node_status_with_runtime, publish_committed_plan, record_publish_path, remove_pod_and_commit,
    upsert_pod_and_commit, PodRuntimeStatus, RuntimePhase,
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
    /// Report the node's committed generation and per-pod status
    /// (owner-tagged: pod UID + owner slot + generation, rfc_k8s.md §17.2).
    Status(StatusArgs),
    /// Stream an owner's per-owner log ring (rfc_owner_drain_and_logs.md §4.5).
    Logs(LogsArgs),
    /// Read or set the node policy composition consults on every commit/remove
    /// (rfc_endpoint_lease.md §5.2): today the reserved-port set.
    Policy(PolicyArgs),
}

#[derive(Args, Debug)]
pub struct PolicyArgs {
    /// Generation-store directory (created if absent).
    #[arg(long)]
    pub store: PathBuf,
    /// Replace the reserved-port set: comma-separated host ports no owner
    /// export may claim (e.g. "6443,53"). An empty string clears the set.
    /// Omitted → that field of the policy is left unchanged.
    #[arg(long)]
    pub reserved_ports: Option<String>,
    /// The node substrate's platform-module prefix (platform stacks prepend
    /// their modules): pod module ranges are placed past compiled indices
    /// [0, N). Omitted → unchanged.
    #[arg(long)]
    pub system_modules: Option<u16>,
}

#[derive(Args, Debug)]
pub struct LogsArgs {
    /// Generation-store directory (used to locate the runtime's `logs/` sidecar).
    #[arg(long)]
    pub store: PathBuf,
    /// Owner UID: 32 hex chars (dashes allowed) or the literal `system` for
    /// owner-0 / platform records.
    #[arg(long, visible_alias = "pod-uid")]
    pub owner_uid: String,
    /// Only records at or after this Unix-millisecond timestamp.
    #[arg(long)]
    pub since: Option<u64>,
    /// Only the last N records.
    #[arg(long)]
    pub tail: Option<usize>,
    /// Stream the live tail: after printing the filtered records, keep polling
    /// the ring (~4×/s, the writer flushes every ~100 ms) and print new records
    /// as they land. Runs until killed or stdout closes (broken pipe).
    #[arg(long, short = 'f')]
    pub follow: bool,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Generation-store directory.
    #[arg(long)]
    pub store: PathBuf,
    /// Machine-readable JSON output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct RemoveArgs {
    #[arg(long)]
    pub store: PathBuf,
    #[arg(long)]
    pub publish: PathBuf,
    /// Owner UID as 32 hex chars (dashes allowed).
    #[arg(long, visible_alias = "owner-uid")]
    pub pod_uid: String,
    /// Grace window in seconds: the owner drains (admission closed, in-flight
    /// work runs, readiness withdrawn) and is revoked at quiescence or this
    /// deadline, whichever comes first (rfc_owner_drain_and_logs.md §3.1).
    /// 0 = revoke immediately.
    #[arg(long, default_value_t = 0)]
    pub grace: u16,
    /// Target capacity profile (linux | pi5 | bcm2712) — sets the kernel
    /// limits admission checks against.
    #[arg(long, default_value = "linux")]
    pub profile: String,
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
    /// Target capacity profile (linux | pi5 | bcm2712) — sets the kernel
    /// limits admission checks against.
    #[arg(long, default_value = "linux")]
    pub profile: String,
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
fn resolve_bundle(
    dir: &std::path::Path,
) -> Result<(
    ResourceProfile,
    [u8; 32],
    Vec<fluxor_tools::compose::ExportDecl>,
)> {
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
    // Declared exports travel with the desired pod so `agent status` can join
    // them against the runtime's bound report (rfc_endpoint_lease.md §4.3).
    let exports = manifest
        .contract
        .exports
        .iter()
        .map(|e| fluxor_tools::compose::ExportDecl {
            protocol: e.protocol.clone(),
            port: e.port,
        })
        .collect();
    Ok((doc.to_compose(), workload_digest, exports))
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

/// Capacity for the named target profile, from the kernel-mirroring table in
/// `compose` (drift-guarded against the kernel sources there). Unknown
/// profiles are a hard admission error, never a silent linux fallback.
fn capacity(profile: &str) -> Result<NodeCapacity> {
    capacity_for_profile(profile).ok_or_else(|| {
        Error::Config(format!(
            "unknown capacity profile '{profile}' (known: linux, pi5, bcm2712)"
        ))
    })
}

pub fn dispatch(args: AgentArgs) -> Result<()> {
    match args.command {
        AgentCommand::Commit(c) => commit(c),
        AgentCommand::Remove(r) => remove(r),
        AgentCommand::Status(s) => status(s),
        AgentCommand::Logs(l) => logs(l),
        AgentCommand::Policy(p) => policy(p),
    }
}

/// `agent policy` — set-and-forget node policy. Setting does NOT recompose:
/// the new reserved set applies from the next commit/remove (a retroactive
/// sweep of already-granted leases is a revocation decision that belongs to
/// the orchestrator, not a side effect of writing policy). Always prints the
/// effective policy as JSON so callers can verify what composition will use.
fn policy(a: PolicyArgs) -> Result<()> {
    use fluxor_tools::node_agent::{load_node_policy, save_node_policy};

    let storage = FsStorage::open(&a.store)
        .map_err(|e| Error::Config(format!("open store {}: {e}", a.store.display())))?;
    let mut store = GenStore::new(storage);

    // Field-wise upsert: load the current policy, apply only the fields
    // given, persist iff something was given. Omitting every flag is a pure
    // read.
    let mut effective = load_node_policy(&store)
        .map_err(|e| Error::Config(format!("load policy failed: {e:?}")))?;
    let mut dirty = false;
    if let Some(spec) = a.reserved_ports {
        let mut ports = Vec::new();
        for tok in spec.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            let port: u16 = tok.parse().map_err(|_| {
                Error::Config(format!("--reserved-ports: '{tok}' is not a port (0-65535)"))
            })?;
            if !ports.contains(&port) {
                ports.push(port);
            }
        }
        ports.sort_unstable();
        effective.reserved_ports = ports;
        dirty = true;
    }
    if let Some(n) = a.system_modules {
        effective.system_modules = n;
        dirty = true;
    }
    if dirty {
        save_node_policy(&mut store, &effective)
            .map_err(|e| Error::Config(format!("save policy failed: {e:?}")))?;
    }
    println!(
        "{}",
        serde_json::to_string(&effective).map_err(|e| Error::Config(e.to_string()))?
    );
    Ok(())
}

fn logs(a: LogsArgs) -> Result<()> {
    use fluxor_tools::agent_logs::{
        apply_filter, parse_owner_uid, read_owner_records, FollowCursor, LineRenderer, LogFilter,
    };
    use fluxor_tools::node_agent::published_sidecar_dir;
    use std::io::Write as _;

    let uid = parse_owner_uid(&a.owner_uid).ok_or_else(|| {
        Error::Config(format!(
            "invalid --owner-uid '{}' (want 32 hex chars or 'system')",
            a.owner_uid
        ))
    })?;

    let storage = FsStorage::open(&a.store)
        .map_err(|e| Error::Config(format!("open store {}: {e}", a.store.display())))?;
    let store = GenStore::new(storage);

    // The ring directory sits beside owner_status.json, under `logs/`. If
    // nothing has been published yet there is nothing to show; follow mode
    // keeps polling for the publish to appear (a node whose first commit is
    // still in flight).
    let resolve_logs_dir =
        |store: &GenStore<FsStorage>| published_sidecar_dir(store).map(|s| s.join("logs"));
    let logs_dir = match resolve_logs_dir(&store) {
        Some(dir) => Some(dir),
        None if a.follow => None,
        None => return Ok(()),
    };

    // Emit lines and stop cleanly when the consumer hangs up: a follow stream's
    // normal end is the reader (kubectl / an HTTP client) closing the pipe.
    let emit = |lines: &[String]| -> bool {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for line in lines {
            if writeln!(out, "{line}").is_err() {
                return false;
            }
        }
        out.flush().is_ok()
    };

    let records = logs_dir
        .as_deref()
        .map(|dir| read_owner_records(dir, &uid))
        .unwrap_or_default();
    let filtered = apply_filter(
        &records,
        &LogFilter {
            since_ms: a.since,
            tail: a.tail,
        },
    );
    let mut renderer = LineRenderer::new();
    if !emit(&renderer.render(&filtered)) {
        return Ok(());
    }
    if !a.follow {
        return Ok(());
    }

    // Follow: poll the ring files (~4×/s; the writer flushes every ~100 ms) and
    // stream records past what was already printed. Each poll re-reads the full
    // retained snapshot; a torn mid-write read yields fewer valid records and
    // the next poll catches up (per-record CRC guards partial writes). Eviction
    // between polls surfaces as the renderer's LogsTruncated marker.
    let mut logs_dir = logs_dir;
    let mut cursor = FollowCursor::at_end_of(&records);
    loop {
        std::thread::sleep(std::time::Duration::from_millis(250));
        if logs_dir.is_none() {
            logs_dir = resolve_logs_dir(&store);
        }
        let Some(dir) = logs_dir.as_deref() else {
            continue; // nothing published yet; keep waiting
        };
        let snapshot = read_owner_records(dir, &uid);
        let fresh = cursor.take_new(&snapshot);
        if fresh.is_empty() {
            continue;
        }
        if !emit(&renderer.render(&fresh)) {
            return Ok(()); // consumer hung up
        }
    }
}

fn status(a: StatusArgs) -> Result<()> {
    let storage = FsStorage::open(&a.store)
        .map_err(|e| Error::Config(format!("open store {}: {e}", a.store.display())))?;
    let store = GenStore::new(storage);
    let st = node_status_with_runtime(&store)
        .map_err(|e| Error::Config(format!("status failed: {e:?}")))?;
    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&st).map_err(|e| Error::Config(e.to_string()))?
        );
        return Ok(());
    }
    match st.generation {
        Some(g) => println!("generation {g}"),
        None => println!("generation - (nothing committed)"),
    }
    match &st.committed_abi_surface {
        Some(pin) if *pin != st.abi_surface => println!(
            "abi-surface {} (WARNING: committed generation pinned to {} — \
             restage before rolling the substrate)",
            st.abi_surface, pin
        ),
        _ => println!("abi-surface {}", st.abi_surface),
    }
    println!(
        "{:<32} {:<16} {:<10} {:<8} {:<5} {:<5} {:<8} {:<6} {:<24}",
        "POD-UID", "NAME", "NAMESPACE", "PHASE", "SLOT", "GEN", "MODULES", "EDGES", "RUNTIME"
    );
    for p in &st.pods {
        let dash = || "-".to_string();
        println!(
            "{:<32} {:<16} {:<10} {:<8} {:<5} {:<5} {:<8} {:<6} {:<24}",
            p.pod_uid_hex,
            p.name,
            p.namespace,
            format!("{:?}", p.desired_phase),
            p.slot.map(|v| v.to_string()).unwrap_or_else(dash),
            p.owner_generation
                .map(|v| v.to_string())
                .unwrap_or_else(dash),
            p.modules.map(|v| v.to_string()).unwrap_or_else(dash),
            p.edges.map(|v| v.to_string()).unwrap_or_else(dash),
            runtime_column(p.runtime.as_ref()),
        );
    }
    Ok(())
}

/// Human-readable summary of the live runtime state for the table output
/// ("-" when the runtime isn't up; the JSON form carries the full object).
fn runtime_column(rt: Option<&PodRuntimeStatus>) -> String {
    let Some(rt) = rt else {
        return "-".to_string();
    };
    match rt.phase {
        RuntimePhase::Running if rt.ready => format!("Running(ready) x{}", rt.restart_count),
        RuntimePhase::Running => format!("Running(unready) x{}", rt.restart_count),
        RuntimePhase::Activating => "Activating".to_string(),
        RuntimePhase::Terminated => match &rt.terminated {
            Some(t) => format!("Terminated({:?}, exit {})", t.reason, t.exit_code),
            None => "Terminated".to_string(),
        },
    }
}

fn remove(r: RemoveArgs) -> Result<()> {
    let pod_uid = parse_pod_uid(&r.pod_uid)?;
    let storage = FsStorage::open(&r.store)
        .map_err(|e| Error::Config(format!("open store {}: {e}", r.store.display())))?;
    let mut store = GenStore::new(storage);
    let cap = capacity(&r.profile)?;
    let (plan, gen) = remove_pod_and_commit(&mut store, pod_uid, r.grace, &cap)
        .map_err(|e| Error::Config(format!("remove/recompose failed: {e:?}")))?;
    publish_committed_plan(&store, &r.publish)
        .map_err(|e| Error::Config(format!("publish failed: {e}")))?;
    // Best-effort: status still works without it, just without live state.
    let _ = record_publish_path(&mut store, &r.publish);
    println!("gen {} pods {}", gen, plan.assignments.len());
    Ok(())
}

fn commit(c: CommitArgs) -> Result<()> {
    let pod_uid = parse_pod_uid(&c.pod_uid)?;
    let (profile, workload_digest, exports) = match &c.bundle {
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
            Vec::new(),
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
        exports,
    };

    let storage = FsStorage::open(&c.store)
        .map_err(|e| Error::Config(format!("open store {}: {e}", c.store.display())))?;
    let mut store = GenStore::new(storage);
    let cap = capacity(&c.profile)?;
    let (_plan, gen) = upsert_pod_and_commit(&mut store, pod, &cap)
        .map_err(|e| Error::Config(format!("reconcile/commit failed: {e:?}")))?;
    publish_committed_plan(&store, &c.publish)
        .map_err(|e| Error::Config(format!("publish failed: {e}")))?
        .ok_or_else(|| Error::Config("no committed generation after commit".into()))?;
    // Remember the publish location so `agent status` can find the runtime's
    // owner_status.json beside it. Best-effort: status still works without
    // it, just without live state.
    let _ = record_publish_path(&mut store, &c.publish);

    // The workload handle the orchestrator tracks (rfc_k8s.md §7.2).
    println!(
        "fluxor://{}/{}",
        c.pod_uid.chars().filter(|c| *c != '-').collect::<String>(),
        gen
    );
    Ok(())
}
