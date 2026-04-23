//! Wire-format types for the rig-backend subprocess protocol.
//!
//! See `docs/architecture/rig-backend-protocol.md` for the normative spec.
//! This module is the Rust-side serde representation.
//!
//! Two message shapes:
//!
//!   * **Actuator** (one-shot, e.g. `power-kasa_local cycle`): the core
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendContext {
    pub rig_id: String,
    pub lab: String,
    pub run_id: String,
    pub run_dir: String,
    pub scenario_name: String,
    pub board: String,
    pub effective_timeout_ms: u64,
}

/// JSON-friendly view of a resolved profile field. Strings have already
/// had `${env:…}` / `${file:…}` / `${keychain:…}` indirections substituted
/// by the time they reach the backend — backends never see the
/// indirection syntax.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BindingValue {
    String(String),
    Int(i64),
    Bool(bool),
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
/// Fields beyond `ok` are advisory; the core treats nonzero exit as
/// failure regardless of what's on stdout.
#[derive(Debug, Clone, Default, Deserialize)]
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

// ── Transport events ───────────────────────────────────────────────────────

/// Shape of one line of NDJSON on a transport backend's stdout.
///
/// `kind` drives decoding:
///   * `"bytes"`  — raw transport bytes, base64 in `data`
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
    /// live. Optional — backends that set up synchronously may skip it.
    Ready,
}
