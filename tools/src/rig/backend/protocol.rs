//! Wire-format types for the rig-backend subprocess protocol.
//!
//! See `docs/architecture/rig-backend-protocol.md` for the normative spec.
//! This module is the Rust-side serde representation.
//!
//! Two message shapes:
//!
//!   * **Actuator** (one-shot, e.g. `power-<name> cycle`): the core
//!     writes one JSON object to the backend's stdin, closes it, and reads
//!     one JSON object from stdout on successful exit.
//!
//!   * **Transport** (streaming, e.g. `console-serial attach`): the core
//!     writes one JSON object to the backend's stdin and closes it, then
//!     reads newline-delimited JSON events from stdout until the backend
//!     exits (on its own or on SIGTERM). Byte payloads are base64-encoded.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ── Shared ─────────────────────────────────────────────────────────────────

/// Data passed to every backend. `binding` is the profile section the
/// capability selected (secrets already resolved); `context` gives the
/// backend enough metadata to identify the run it's serving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendInvocation {
    pub binding: BTreeMap<String, BindingValue>,
    pub context: BackendContext,
    /// Only populated for deploy actuators (`stage`). Describes the
    /// artifact the backend should place in its target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactRef>,
    /// Arguments of the verb itself, when it takes any: `hold` receives
    /// `{"minutes": N}`. Absent for a verb that takes none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<serde_json::Value>,
    /// The `[relay.<name>]` binding when the backend runs through a relay
    /// (the binding said `relay = "<name>"`). Filled in at spawn, from
    /// the resolved backend, so no builder of an invocation needs to know.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<BTreeMap<String, BindingValue>>,
}

/// Why a backend is being called: the lifecycle of a scenario (`run`),
/// the steps that put the rig back (`teardown`), or an operator's
/// `fluxor rig power …` (`adhoc`). A backend that behaves differently at
/// the end of a run from in the middle of one (a `power off` that also
/// stops a helper machine only when the run is over) reads this rather
/// than guessing from the verb.
pub const PHASE_RUN: &str = "run";
pub const PHASE_TEARDOWN: &str = "teardown";
pub const PHASE_ADHOC: &str = "adhoc";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendContext {
    pub rig_id: String,
    pub lab: String,
    pub run_id: String,
    pub run_dir: String,
    pub scenario_name: String,
    pub board: String,
    pub effective_timeout_ms: u64,
    /// One of [`PHASE_RUN`], [`PHASE_TEARDOWN`], [`PHASE_ADHOC`]; absent
    /// means `run`.
    #[serde(default = "phase_run")]
    pub phase: String,
    /// The rig's own directory, `0700`, kept across runs and serialised by
    /// the rig lock: where this rig's backends leave what the next step
    /// needs (the image a deploy made, the machine a power step started).
    #[serde(default)]
    pub state_dir: String,
}

fn phase_run() -> String {
    PHASE_RUN.to_string()
}

/// JSON-friendly view of a resolved profile field. Strings have already
/// had `${env:…}` / `${file:…}` indirections substituted by the time they
/// reach the backend — backends never see the indirection syntax.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BindingValue {
    // Order matters for `#[serde(untagged)]`: serde tries variants in
    // declaration order, so `Int` must precede `Float` — otherwise a JSON
    // literal like `5` deserializes as `Float(5.0)` instead of `Int(5)`.
    String(String),
    Bool(bool),
    Int(i64),
    Float(f64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactRef {
    /// Single file. `path` is absolute.
    File { path: String },
    /// Multi-file bundle rooted at `path` (absolute directory).
    Bundle { path: String },
}

// ── Actuator result ────────────────────────────────────────────────────────

/// Shape of the JSON object a successful actuator writes on stdout.
/// The exit code is authoritative for success; `ok: false` on a zero
/// exit is still read as a failure, so a backend that forgot its exit
/// status cannot pass by accident.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActuatorReport {
    #[serde(default = "bool_true")]
    pub ok: bool,
    #[serde(default)]
    pub info: Option<String>,
    /// Optional structured detail the backend wants saved with the run
    /// record. Copied verbatim into the run's `manifest.json`.
    #[serde(default)]
    pub detail: Option<serde_json::Value>,
}

fn bool_true() -> bool {
    true
}

/// Exit status a backend uses for a verb it does not implement. The
/// orchestrator tolerates it for the optional verbs (`diagnose`,
/// `unstage`, `hold`, `sweep`) and for any transport, and treats it as a
/// failure for a switching verb or `stage`.
pub const EXIT_UNSUPPORTED_VERB: i32 = 64;

// ── Transport events ───────────────────────────────────────────────────────

/// Shape of one line of NDJSON on a transport backend's stdout.
///
/// `kind` drives decoding:
///   * `"bytes"`  — raw transport bytes, base64 in `data`
///   * `"boot"`   — what follows comes from a target started for this run
///   * `"fetch"`  — a deploy-side fetch happened (netboot/TFTP etc.)
///   * `"dhcp"`   — informational DHCP activity
///   * `"error"`  — backend surfaced a non-fatal error
///   * `"note"`   — free-form human-readable diagnostic
///   * `"ready"`  — backend setup completed; observation is live
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransportEvent {
    /// Raw bytes from the transport. `data` is base64-encoded so the line
    /// is plain JSON and logs stay `cat`-safe.
    Bytes {
        data: String,
    },
    /// The transport can show that the bytes after this point come from a
    /// target started for this run: it reopened a device after a reset, or
    /// it connected to a machine that did not exist before the run's power
    /// step. A first open of a device that was already running is never a
    /// boot — the old image is still talking.
    Boot,
    /// A deploy-adjacent fetch event.
    Fetch {
        filename: String,
        #[serde(default)]
        client_ip: Option<String>,
    },
    Dhcp,
    Error {
        message: String,
    },
    Note {
        message: String,
    },
    /// Sent once, after setup, so the orchestrator knows the transport is
    /// live. The orchestrator stages and powers nothing until every
    /// transport has sent it or exited, up to a bound; a backend that never
    /// sends it costs the run that bound.
    Ready,
}
