//! `fluxor agent` — the narrow local protocol a host orchestrator (nanocloud's
//! `FluxorGraphWorkloadRuntime`) drives instead of linking fluxor-tools as a
//! library. The orchestrator talks to fluxor over a narrow local command
//! protocol — process boundary, stable argv and stdout — rather than embedding
//! fluxor's composition code or a general OCI execution library in its own
//! address space.
//!
//! `fluxor agent commit` — reconcile a single-workload desired state into a durable
//! generation store and publish the committed plan blob for the Linux
//! runtime's `FLUXOR_PLAN` staging. Prints the workload handle
//! (`fluxor://<workload-uid-hex>/<generation>`) on stdout for the caller to track.
//!
//! `fluxor agent serve` and `fluxor agent call` — the agent protocol
//! (`docs/architecture/agent_protocol.md`): the two ends of one request and its
//! answer, over the agent's Unix socket, stdio, or a runtime's mutual-TLS
//! channel. `commit` and `remove` stay beside them because their argv says more
//! than the protocol does and they answer in their own stdout: a name, a
//! namespace, a resource profile or a bundle path, a per-call grace. They share
//! the protocol's store lock.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use clap::{Args, Subcommand};

use crate::error::{Error, Result};
use fluxor_tools::agent_protocol::wire::{self, op, result, Request};
use fluxor_tools::agent_protocol::{
    accept_response, descriptor_revision, frame_reader, parse_hex, result_name, serve_stream,
    spawn_transport, write_frame, AgentContext, Frame, PeerSource, StoreLock,
};
use fluxor_tools::compose::{
    capacity_for_profile, DesiredPhase, NodeCapacity, ResourceProfile, WorkloadDesired,
};
use fluxor_tools::genstore::{FsStorage, GenStore};
use fluxor_tools::node_agent::{
    node_status_with_runtime, publish_committed_plan, record_publish_path,
    remove_workload_and_commit, resolve_bundle, upsert_workload_and_commit, RuntimePhase,
    WorkloadRuntimeStatus,
};

#[derive(Args, Debug)]
pub struct AgentArgs {
    #[command(subcommand)]
    pub command: AgentCommand,
}

#[derive(Subcommand, Debug)]
pub enum AgentCommand {
    /// Upsert a workload into the node's desired state, recompose all resident
    /// workloads into the next generation, and publish the plan blob.
    Commit(CommitArgs),
    /// Remove a workload from the desired state, recompose, and publish.
    Remove(RemoveArgs),
    /// Report the node's committed generation and per-workload status
    /// (owner-tagged by the full join key: workload UID + owner slot + generation).
    Status(StatusArgs),
    /// Stream an owner's per-owner log ring.
    Logs(LogsArgs),
    /// Read or set the node policy composition consults on every commit/remove
    /// — node-scoped, never per-workload: today the reserved-port set.
    Policy(PolicyArgs),
    /// Answer agent-protocol requests for this target until the transport ends.
    Serve(ServeArgs),
    /// Send one agent-protocol request and print its answer as JSON. Exits
    /// non-zero unless the result is OK.
    Call(CallArgs),
}

#[derive(Args, Debug)]
pub struct ServeArgs {
    /// Generation-store directory (created if absent).
    #[arg(long)]
    pub store: PathBuf,
    /// Path to publish the committed plan blob to (FLUXOR_PLAN target).
    #[arg(long)]
    pub publish: PathBuf,
    /// Directory of bundles, one per `<workload digest hex>/`.
    #[arg(long)]
    pub bundles: PathBuf,
    /// The target descriptor; its sha256 is the descriptor revision.
    #[arg(long)]
    pub descriptor: PathBuf,
    /// This target's key fingerprint: 64 hex chars.
    #[arg(long)]
    pub target_id: String,
    /// A controller's key fingerprint: 64 hex chars. Repeatable.
    #[arg(long = "controller")]
    pub controllers: Vec<String>,
    /// Target capacity profile (linux | pi5 | bcm2712) — sets the kernel
    /// limits admission checks against.
    #[arg(long, default_value = "linux")]
    pub profile: String,
    /// Drain window of a REMOVE, in seconds. 0 revokes immediately.
    #[arg(long, default_value_t = 0)]
    pub remove_grace: u16,
    #[command(flatten)]
    pub transport: TransportArgs,
    /// Serve frames on stdin and stdout, the peer in each frame being the one
    /// its parent vouches for.
    #[arg(long)]
    pub stdio: bool,
}

/// The two transports a controller and an agent share.
#[derive(Args, Debug)]
pub struct TransportArgs {
    /// The agent's Unix socket. Access to it is the authorization: the peer is
    /// local whatever a client sends.
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// A fluxor-linux to carry frames over mutual TLS.
    #[arg(long)]
    pub runtime: Option<PathBuf>,
    /// The runtime's built graph (includes the `agent_listen` or `agent_dial` stack).
    #[arg(long, requires = "runtime")]
    pub config: Option<PathBuf>,
    /// The runtime's module table. Default: `modules.bin` beside `--config`.
    #[arg(long, requires = "runtime")]
    pub modules: Option<PathBuf>,
    /// Where the runtime's log goes. Default: `serve` inherits stderr, `call`
    /// discards it.
    #[arg(long, requires = "runtime")]
    pub runtime_log: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct CallArgs {
    #[command(flatten)]
    pub transport: TransportArgs,
    /// apply | remove | observe.
    #[arg(long)]
    pub op: String,
    /// Workload UID as 32 hex chars (dashes allowed). Default for `observe`:
    /// none, which reports the target alone.
    #[arg(long)]
    pub workload_uid: Option<String>,
    /// `apply`: the desired bundle's workload digest, 64 hex chars.
    #[arg(long)]
    pub bundle_digest: Option<String>,
    /// `apply`: the target descriptor revision this was validated against, 64
    /// hex chars.
    #[arg(long)]
    pub descriptor_revision: Option<String>,
    /// `apply` and `remove`: this request's identity, 32 hex chars. Send the
    /// same identity to retry it.
    #[arg(long)]
    pub idempotency_id: Option<String>,
    #[arg(long, default_value_t = 0)]
    pub fence_epoch: u64,
    #[arg(long, default_value_t = 0)]
    pub fence_seq: u64,
    /// The target's key fingerprint this call must reach, 64 hex chars. On a
    /// runtime transport the response's `target_id` is held to the fingerprint
    /// the channel verified whether or not this is given.
    #[arg(long)]
    pub target_id: Option<String>,
    /// How long to wait for the session and the answer.
    #[arg(long, default_value_t = 30_000)]
    pub timeout_ms: u64,
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
    /// their modules): workload module ranges are placed past compiled indices
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
    #[arg(long)]
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
    /// Workload UID as 32 hex chars (dashes allowed).
    #[arg(long)]
    pub workload_uid: String,
    /// Grace window in seconds: the owner drains (admission closed, in-flight
    /// work runs, readiness withdrawn) and is revoked at quiescence or this
    /// deadline, whichever comes first. 0 = revoke immediately.
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
    /// Workload UID as 32 hex chars (dashes allowed).
    #[arg(long)]
    pub workload_uid: String,
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

fn parse_workload_uid(hex: &str) -> Result<[u8; 16]> {
    let cleaned: String = hex.chars().filter(|c| *c != '-').collect();
    if cleaned.len() != 32 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Config(format!(
            "--workload-uid must be 32 hex chars (got '{hex}')"
        )));
    }
    let mut uid = [0u8; 16];
    for (i, byte) in uid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
            .map_err(|e| Error::Config(format!("--workload-uid: {e}")))?;
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
        AgentCommand::Serve(s) => serve(s),
        AgentCommand::Call(c) => call(c),
    }
}

fn hex_arg<const N: usize>(flag: &str, text: &str) -> Result<[u8; N]> {
    parse_hex::<N>(text).map_err(|e| Error::Config(format!("--{flag}: {e}")))
}

/// The runtime's module table: as given, or `modules.bin` beside its config.
fn transport_files(t: &TransportArgs) -> Result<Option<(&Path, &Path, PathBuf)>> {
    let Some(runtime) = t.runtime.as_deref() else {
        return Ok(None);
    };
    let config = t
        .config
        .as_deref()
        .ok_or_else(|| Error::Config("--runtime needs --config".into()))?;
    let modules = t.modules.clone().unwrap_or_else(|| {
        config
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("modules.bin")
    });
    Ok(Some((runtime, config, modules)))
}

fn runtime_log(t: &TransportArgs, default: Stdio) -> Result<Stdio> {
    match t.runtime_log.as_deref() {
        Some(path) => Ok(Stdio::from(std::fs::File::create(path)?)),
        None => Ok(default),
    }
}

fn serve(s: ServeArgs) -> Result<()> {
    let target_id = hex_arg::<32>("target-id", &s.target_id)?;
    if target_id == [0; 32] {
        return Err(Error::Config("--target-id: names no key".into()));
    }
    let mut controllers = Vec::with_capacity(s.controllers.len());
    for c in &s.controllers {
        let fp = hex_arg::<32>("controller", c)?;
        if fp == [0; 32] {
            return Err(Error::Config("--controller: names no key".into()));
        }
        controllers.push(fp);
    }
    let ctx = AgentContext {
        target_id,
        controllers,
        descriptor: s.descriptor.clone(),
        bundles: s.bundles.clone(),
        publish: s.publish.clone(),
        capacity: capacity(&s.profile)?,
        remove_grace: s.remove_grace,
    };
    // A descriptor the agent cannot read is a mistake of this invocation, not
    // something to answer every request about.
    descriptor_revision(&ctx.descriptor)
        .map_err(|e| Error::Config(format!("--descriptor {}: {e}", ctx.descriptor.display())))?;
    let transports = usize::from(s.transport.socket.is_some())
        + usize::from(s.transport.runtime.is_some())
        + usize::from(s.stdio);
    if transports != 1 {
        return Err(Error::Config(
            "exactly one of --socket, --stdio, --runtime is needed".into(),
        ));
    }
    if let Some(path) = s.transport.socket.as_deref() {
        return serve_socket(path, &ctx, &s.store);
    }
    if s.stdio {
        let mut r = std::io::stdin().lock();
        let mut w = std::io::stdout().lock();
        serve_stream(&mut r, &mut w, PeerSource::Stamped, &ctx, &s.store)?;
        return Ok(());
    }
    let (runtime, config, modules) =
        transport_files(&s.transport)?.ok_or_else(|| Error::Config("no transport".into()))?;
    let log = runtime_log(&s.transport, Stdio::inherit())?;
    let mut child = spawn_transport(runtime, config, &modules, log)
        .map_err(|e| Error::Config(format!("start {}: {e}", runtime.display())))?;
    let mut w = child
        .stdin
        .take()
        .ok_or_else(|| Error::Config("the runtime has no stdin".into()))?;
    let mut r = child
        .stdout
        .take()
        .ok_or_else(|| Error::Config("the runtime has no stdout".into()))?;
    let served = serve_stream(&mut r, &mut w, PeerSource::Stamped, &ctx, &s.store);
    let _ = child.kill();
    let status = child.wait()?;
    served?;
    Err(Error::Config(format!(
        "the transport runtime ended: {status}"
    )))
}

/// Bind the agent's socket, reachable by its owner alone: access to it is the
/// authorization. A socket something still answers on is left alone.
fn bind_socket(path: &Path) -> Result<UnixListener> {
    if path.exists() {
        if UnixStream::connect(path).is_ok() {
            return Err(Error::Config(format!(
                "{} is being served already",
                path.display()
            )));
        }
        std::fs::remove_file(path)?;
    }
    // SAFETY: umask takes no pointers. This runs before the process has any
    // other thread, and is put back straight after the bind.
    let old = unsafe { libc::umask(0o177) };
    let bound = UnixListener::bind(path);
    // SAFETY: as above.
    unsafe { libc::umask(old) };
    bound.map_err(|e| Error::Config(format!("bind {}: {e}", path.display())))
}

fn serve_socket(path: &Path, ctx: &AgentContext, store: &Path) -> Result<()> {
    let listener = bind_socket(path)?;
    std::thread::scope(|scope| {
        for conn in listener.incoming() {
            let mut conn = conn?;
            scope.spawn(move || {
                let Ok(mut reader) = conn.try_clone() else {
                    return;
                };
                let served = serve_stream(&mut reader, &mut conn, PeerSource::Local, ctx, store);
                if let Err(e) = served {
                    eprintln!("agent: a local client's connection ended: {e}");
                }
            });
        }
        Ok(())
    })
}

/// The request `c` describes.
fn call_request(c: &CallArgs) -> Result<Request> {
    let opcode = match c.op.as_str() {
        "apply" => op::APPLY,
        "remove" => op::REMOVE,
        "observe" => op::OBSERVE,
        other => {
            return Err(Error::Config(format!(
                "--op: '{other}' is not apply, remove or observe"
            )))
        }
    };
    let workload_uid = match c.workload_uid.as_deref() {
        Some(u) => hex_arg::<16>("workload-uid", u)?,
        None if opcode == op::OBSERVE => [0; 16],
        None => return Err(Error::Config("--workload-uid is needed".into())),
    };
    let desired_bundle_digest = match (c.bundle_digest.as_deref(), opcode) {
        (Some(d), op::APPLY) => hex_arg::<32>("bundle-digest", d)?,
        (None, op::APPLY) => return Err(Error::Config("apply needs --bundle-digest".into())),
        (Some(_), _) => return Err(Error::Config("--bundle-digest is for apply".into())),
        (None, _) => [0; 32],
    };
    let descriptor_revision = match (c.descriptor_revision.as_deref(), opcode) {
        (Some(d), _) => hex_arg::<32>("descriptor-revision", d)?,
        (None, op::APPLY) => return Err(Error::Config("apply needs --descriptor-revision".into())),
        (None, _) => [0; 32],
    };
    let idempotency_id = match (c.idempotency_id.as_deref(), opcode) {
        (Some(i), _) => hex_arg::<16>("idempotency-id", i)?,
        (None, op::OBSERVE) => [0; 16],
        (None, _) => return Err(Error::Config("--idempotency-id is needed".into())),
    };
    Ok(Request {
        op: opcode,
        flags: 0,
        workload_uid,
        desired_bundle_digest,
        descriptor_revision,
        idempotency_id,
        fence_epoch: c.fence_epoch,
        fence_seq: c.fence_seq,
    })
}

fn call(c: CallArgs) -> Result<()> {
    let req = call_request(&c)?;
    let expected = c
        .target_id
        .as_deref()
        .map(|t| hex_arg::<32>("target-id", t))
        .transpose()?;
    let mut record = [0u8; wire::REQUEST_LEN];
    let len = req
        .encode(&mut record)
        .ok_or_else(|| Error::Config("the request does not encode".into()))?;
    let timeout = Duration::from_millis(c.timeout_ms);

    if c.transport.socket.is_some() == c.transport.runtime.is_some() {
        return Err(Error::Config(
            "exactly one of --socket, --runtime is needed".into(),
        ));
    }
    let (frame, verified) = if let Some(path) = c.transport.socket.as_deref() {
        let mut conn = UnixStream::connect(path)
            .map_err(|e| Error::Config(format!("connect {}: {e}", path.display())))?;
        write_frame(&mut conn, &[0; 32], &record[..len])?;
        (first_frame(frame_reader(conn.try_clone()?), timeout), false)
    } else {
        let (runtime, config, modules) =
            transport_files(&c.transport)?.ok_or_else(|| Error::Config("no transport".into()))?;
        let log = runtime_log(&c.transport, Stdio::null())?;
        let mut child = spawn_transport(runtime, config, &modules, log)
            .map_err(|e| Error::Config(format!("start {}: {e}", runtime.display())))?;
        let mut w = child
            .stdin
            .take()
            .ok_or_else(|| Error::Config("the runtime has no stdin".into()))?;
        let r = child
            .stdout
            .take()
            .ok_or_else(|| Error::Config("the runtime has no stdout".into()))?;
        // All-zero prefix: the channel's one session, whichever peer it binds.
        write_frame(&mut w, &[0; 32], &record[..len])?;
        let frame = first_frame(frame_reader(r), timeout);
        let _ = child.kill();
        let _ = child.wait();
        (frame, true)
    };
    let (stamped, response) = frame?;
    let reply = accept_response(&stamped, &response, &req, verified, expected.as_ref())
        .map_err(|e| Error::Config(e.to_string()))?;
    let verified_peer = verified.then_some(&stamped);
    println!(
        "{}",
        serde_json::to_string_pretty(&reply.to_json(verified_peer))
            .map_err(|e| Error::Config(e.to_string()))?
    );
    if reply.result != result::OK {
        return Err(Error::Config(format!(
            "the target answered {}: {}",
            result_name(reply.result),
            String::from_utf8_lossy(&reply.diag)
        )));
    }
    Ok(())
}

/// The one frame a call waits for, within `timeout`.
fn first_frame(
    frames: std::sync::mpsc::Receiver<std::io::Result<Frame>>,
    timeout: Duration,
) -> Result<([u8; 32], Vec<u8>)> {
    match frames.recv_timeout(timeout) {
        Ok(Ok(Frame::Record(peer, record))) => Ok((peer, record)),
        Ok(Ok(Frame::Oversize(_))) => Err(Error::Config(
            "the answer is over the protocol's maximum".into(),
        )),
        Ok(Ok(Frame::End)) => Err(Error::Config("the transport ended with no answer".into())),
        Ok(Err(e)) => Err(Error::Config(format!("the transport failed: {e}"))),
        Err(_) => Err(Error::Config(format!(
            "no answer within {} ms: no session, or the channel refused it",
            timeout.as_millis()
        ))),
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
        "WORKLOAD-UID", "NAME", "NAMESPACE", "PHASE", "SLOT", "GEN", "MODULES", "EDGES", "RUNTIME"
    );
    for p in &st.workloads {
        let dash = || "-".to_string();
        println!(
            "{:<32} {:<16} {:<10} {:<8} {:<5} {:<5} {:<8} {:<6} {:<24}",
            p.workload_uid_hex,
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
fn runtime_column(rt: Option<&WorkloadRuntimeStatus>) -> String {
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
    let workload_uid = parse_workload_uid(&r.workload_uid)?;
    let _lock = StoreLock::acquire(&r.store)
        .map_err(|e| Error::Config(format!("lock store {}: {e}", r.store.display())))?;
    let storage = FsStorage::open(&r.store)
        .map_err(|e| Error::Config(format!("open store {}: {e}", r.store.display())))?;
    let mut store = GenStore::new(storage);
    let cap = capacity(&r.profile)?;
    let (plan, gen) = remove_workload_and_commit(&mut store, workload_uid, r.grace, &cap)
        .map_err(|e| Error::Config(format!("remove/recompose failed: {e:?}")))?;
    publish_committed_plan(&store, &r.publish)
        .map_err(|e| Error::Config(format!("publish failed: {e}")))?;
    // Best-effort: status still works without it, just without live state.
    let _ = record_publish_path(&mut store, &r.publish);
    println!("gen {} workloads {}", gen, plan.assignments.len());
    Ok(())
}

fn commit(c: CommitArgs) -> Result<()> {
    let workload_uid = parse_workload_uid(&c.workload_uid)?;
    let (profile, workload_digest, exports) = match &c.bundle {
        Some(dir) => {
            let b = resolve_bundle(dir).map_err(Error::Config)?;
            (b.profile, b.workload_digest, b.exports)
        }
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
    let workload = WorkloadDesired {
        workload_uid,
        namespace: c.namespace.clone(),
        name: c.name.clone(),
        workload_digest,
        config_generation: 0,
        desired_phase: DesiredPhase::Running,
        profile,
        exports,
    };

    let _lock = StoreLock::acquire(&c.store)
        .map_err(|e| Error::Config(format!("lock store {}: {e}", c.store.display())))?;
    let storage = FsStorage::open(&c.store)
        .map_err(|e| Error::Config(format!("open store {}: {e}", c.store.display())))?;
    let mut store = GenStore::new(storage);
    let cap = capacity(&c.profile)?;
    let (_plan, gen) = upsert_workload_and_commit(&mut store, workload, &cap)
        .map_err(|e| Error::Config(format!("reconcile/commit failed: {e:?}")))?;
    publish_committed_plan(&store, &c.publish)
        .map_err(|e| Error::Config(format!("publish failed: {e}")))?
        .ok_or_else(|| Error::Config("no committed generation after commit".into()))?;
    // Remember the publish location so `agent status` can find the runtime's
    // owner_status.json beside it. Best-effort: status still works without
    // it, just without live state.
    let _ = record_publish_path(&mut store, &c.publish);

    // The workload handle the orchestrator tracks: `fluxor://<uid-hex>/<gen>`.
    println!(
        "fluxor://{}/{}",
        c.workload_uid
            .chars()
            .filter(|c| *c != '-')
            .collect::<String>(),
        gen
    );
    Ok(())
}
