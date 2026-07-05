//! Fluxor workload-bundle manifest: parse, validate, target-select, and extract
//! the resource footprint (rfc_k8s.md §8, §9, §19.1).
//!
//! The manifest (`application/vnd.nanocloud.fluxor.workload.v1+json`) separates a
//! portable **contract** (typed imports/exports, config schema, health/lifecycle
//! signals, update policy) from per-target **implementations** (graph, modules,
//! resource profile, optional OCI-backed external nodes, and the bindings that
//! wire the contract to that implementation's graph).
//!
//! Validation enforces the §9 rules: every required import, export, and
//! health signal is bound exactly once in each implementation; OCI-backed
//! external-node ports correspond to a declared export and the image is
//! digest-pinned; every digest field is well-formed. The resource footprint that
//! feeds the scheduler reservation (`compose::ResourceProfile`) is extracted from
//! the implementation's signed resource profile, never trusted from handwriting.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::compose::{PodUid, ResourceProfile};

// ============================================================================
// Manifest types (rfc_k8s.md §9 shape)
// ============================================================================

/// A `sha256:<hex>` content reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestRef {
    pub digest: String,
}

impl DigestRef {
    /// True when the digest is a well-formed `sha256:<64 lowercase hex>`.
    pub fn is_well_formed(&self) -> bool {
        is_sha256(&self.digest)
    }
}

/// A typed capability the workload imports from the system substrate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Import {
    pub name: String,
    pub contract: String,
    pub version: u32,
}

/// A named network endpoint the workload exports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Export {
    pub name: String,
    pub protocol: String,
    pub port: u16,
}

/// Aggregate health/lifecycle signal names declared by the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    pub readiness: String,
    pub liveness: String,
}

/// Update/drain policy. `state_policy` is `preserve-compatible` | `discard`
/// (rfc_k8s.md §12.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePolicy {
    pub drain_timeout_ms: u32,
    pub state_policy: String,
}

/// The portable, target-independent workload contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Contract {
    #[serde(default)]
    pub imports: Vec<Import>,
    #[serde(default)]
    pub exports: Vec<Export>,
    pub config_schema: DigestRef,
    pub health: Health,
    pub update: UpdatePolicy,
}

/// Target selector for one implementation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub family: String,
    pub architecture: String,
    pub fluxor_abi: u32,
}

/// A module referenced by an implementation graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleRef {
    pub name: String,
    pub digest: String,
}

/// One bridge between an OCI-backed node's proxy port and a container endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceBinding {
    pub proxy_port: String,
    pub kind: String,
    pub container_port: u16,
}

/// A Linux OCI-backed graph node (rfc_k8s.md §6.8, §9). `execution_class` is
/// `external-hosted`; `image` must be digest-pinned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalNode {
    pub module: String,
    pub executor: String,
    pub execution_class: String,
    pub image: String,
    #[serde(default)]
    pub interface_bindings: Vec<InterfaceBinding>,
}

/// Wiring of the contract onto an implementation's graph. Keys are contract
/// names (imports/exports) or signal names (health); values are graph targets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bindings {
    #[serde(default)]
    pub imports: BTreeMap<String, String>,
    #[serde(default)]
    pub exports: BTreeMap<String, String>,
    #[serde(default)]
    pub health: BTreeMap<String, String>,
}

/// One target-specific implementation of the workload contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Implementation {
    pub target: Target,
    pub graph: DigestRef,
    #[serde(default)]
    pub modules: Vec<ModuleRef>,
    pub resources: DigestRef,
    #[serde(default)]
    pub external_nodes: Vec<ExternalNode>,
    pub bindings: Bindings,
}

/// A parsed workload bundle manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadManifest {
    pub schema_version: u32,
    pub name: String,
    pub version: String,
    pub contract: Contract,
    #[serde(default)]
    pub implementations: Vec<Implementation>,
}

/// The resource-footprint document referenced by an implementation's
/// `resources` digest (`application/vnd.nanocloud.fluxor.resources.v1+json`).
/// Generated/measured by the build tool, never handwritten (rfc_k8s.md §9).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceProfileDoc {
    pub modules: u16,
    pub edges: u16,
    pub state_bytes: u32,
    pub buffer_bytes: u32,
    #[serde(default)]
    pub endpoints: u16,
    #[serde(default)]
    pub domains: u8,
    /// Per-module state-schema digests used for change classification (§12.2).
    #[serde(default)]
    pub state_schemas: BTreeMap<String, String>,
}

impl ResourceProfileDoc {
    /// Project to the scheduler-reservation footprint consumed by `compose`.
    pub fn to_compose(&self) -> ResourceProfile {
        ResourceProfile {
            modules: self.modules,
            edges: self.edges,
            state_bytes: self.state_bytes,
            buffer_bytes: self.buffer_bytes,
            endpoints: self.endpoints,
            domains: self.domains,
        }
    }
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse a workload manifest from JSON bytes.
pub fn parse_manifest(json: &str) -> Result<WorkloadManifest, String> {
    serde_json::from_str(json).map_err(|e| format!("manifest parse error: {e}"))
}

/// Parse a resource-profile document from JSON bytes.
pub fn parse_resource_profile(json: &str) -> Result<ResourceProfileDoc, String> {
    serde_json::from_str(json).map_err(|e| format!("resource profile parse error: {e}"))
}

// ============================================================================
// Validation
// ============================================================================

/// Outcome of validating a manifest: a list of human-readable problems, each
/// naming the offending field path (rfc_k8s.md §7.1 "exact field paths").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidationReport {
    pub errors: Vec<String>,
}

impl ValidationReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
    fn push(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
    }
}

fn is_sha256(s: &str) -> bool {
    match s.strip_prefix("sha256:") {
        Some(hex) => hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

/// An OCI image reference is digest-pinned when it carries an `@sha256:<hex>`.
fn is_digest_pinned_image(image: &str) -> bool {
    match image.split_once('@') {
        Some((_, digest)) => is_sha256(digest),
        None => false,
    }
}

/// Validate a manifest against the §9 contract rules. Returns a report; empty
/// `errors` means valid.
pub fn validate(m: &WorkloadManifest) -> ValidationReport {
    let mut r = ValidationReport::default();

    if m.schema_version != 1 {
        r.push(format!(
            "schemaVersion: unsupported value {} (expected 1)",
            m.schema_version
        ));
    }
    if m.name.trim().is_empty() {
        r.push("name: must not be empty");
    }
    if !m.contract.config_schema.is_well_formed() {
        r.push("contract.configSchema.digest: not a sha256: digest");
    }
    if m.contract.health.readiness.trim().is_empty() {
        r.push("contract.health.readiness: must not be empty");
    }
    if m.contract.health.liveness.trim().is_empty() {
        r.push("contract.health.liveness: must not be empty");
    }
    match m.contract.update.state_policy.as_str() {
        "preserve-compatible" | "discard" => {}
        other => r.push(format!(
            "contract.update.statePolicy: unsupported '{other}' (preserve-compatible | discard)"
        )),
    }
    if m.implementations.is_empty() {
        r.push("implementations: at least one is required");
    }

    for (i, imp) in m.implementations.iter().enumerate() {
        validate_implementation(m, imp, i, &mut r);
    }
    r
}

fn validate_implementation(
    m: &WorkloadManifest,
    imp: &Implementation,
    idx: usize,
    r: &mut ValidationReport,
) {
    let p = format!("implementations[{idx}]");

    if !imp.graph.is_well_formed() {
        r.push(format!("{p}.graph.digest: not a sha256: digest"));
    }
    if !imp.resources.is_well_formed() {
        r.push(format!("{p}.resources.digest: not a sha256: digest"));
    }
    for (j, md) in imp.modules.iter().enumerate() {
        if !is_sha256(&md.digest) {
            r.push(format!(
                "{p}.modules[{j}] ({}): digest not sha256:",
                md.name
            ));
        }
    }

    // Every required import bound exactly once.
    for imp_decl in &m.contract.imports {
        if !imp.bindings.imports.contains_key(&imp_decl.name) {
            r.push(format!(
                "{p}.bindings.imports: missing binding for required import '{}'",
                imp_decl.name
            ));
        }
    }
    for key in imp.bindings.imports.keys() {
        if !m.contract.imports.iter().any(|i| &i.name == key) {
            r.push(format!(
                "{p}.bindings.imports: '{key}' does not match any contract import"
            ));
        }
    }

    // Every export bound exactly once.
    for exp in &m.contract.exports {
        if !imp.bindings.exports.contains_key(&exp.name) {
            r.push(format!(
                "{p}.bindings.exports: missing binding for export '{}'",
                exp.name
            ));
        }
    }
    for key in imp.bindings.exports.keys() {
        if !m.contract.exports.iter().any(|e| &e.name == key) {
            r.push(format!(
                "{p}.bindings.exports: '{key}' does not match any contract export"
            ));
        }
    }

    // Both health signals bound.
    for sig in [&m.contract.health.readiness, &m.contract.health.liveness] {
        if !imp.bindings.health.contains_key(sig) {
            r.push(format!(
                "{p}.bindings.health: missing binding for health signal '{sig}'"
            ));
        }
    }

    // External nodes: digest-pinned image, external-hosted class, and every
    // interface binding's proxy port must be a declared contract export.
    for (k, en) in imp.external_nodes.iter().enumerate() {
        let ep = format!("{p}.externalNodes[{k}] ({})", en.module);
        if en.execution_class != "external-hosted" {
            r.push(format!(
                "{ep}.executionClass: must be 'external-hosted', got '{}'",
                en.execution_class
            ));
        }
        if !is_digest_pinned_image(&en.image) {
            r.push(format!(
                "{ep}.image: must be digest-pinned (…@sha256:<hex>), got '{}'",
                en.image
            ));
        }
        for (b, ib) in en.interface_bindings.iter().enumerate() {
            if !m.contract.exports.iter().any(|e| e.name == ib.proxy_port) {
                r.push(format!(
                    "{ep}.interfaceBindings[{b}].proxyPort: '{}' is not a declared contract export",
                    ib.proxy_port
                ));
            }
            match ib.kind.as_str() {
                "tcp" | "udp" | "unix" | "stdio" => {}
                other => r.push(format!(
                    "{ep}.interfaceBindings[{b}].kind: unsupported bridge kind '{other}'"
                )),
            }
        }
    }
}

// ============================================================================
// Target selection (rfc_k8s.md §8)
// ============================================================================

/// Select the implementation matching `(family, architecture, fluxor_abi)`.
pub fn select_implementation<'a>(
    m: &'a WorkloadManifest,
    family: &str,
    architecture: &str,
    fluxor_abi: u32,
) -> Option<&'a Implementation> {
    m.implementations.iter().find(|imp| {
        imp.target.family == family
            && imp.target.architecture == architecture
            && imp.target.fluxor_abi == fluxor_abi
    })
}

// ============================================================================
// Deterministic subgraph namespacing (rfc_k8s.md §10.2)
// ============================================================================

/// Qualify a pod-local module name into its globally-unique composed-graph name
/// `pod/<namespace>/<pod-uid-hex>/<module>`. Deterministic and collision-free
/// across pods (the Pod UID disambiguates), so two pods can declare a module of
/// the same local name without clashing in the composed device graph.
pub fn qualify_module(namespace: &str, pod_uid: &PodUid, module: &str) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(32);
    for b in pod_uid {
        let _ = write!(hex, "{b:02x}");
    }
    format!("pod/{namespace}/{hex}/{module}")
}

/// Qualify every module in an implementation, in manifest-declaration order
/// (deterministic — the order feeds the composition layout).
pub fn qualify_implementation_modules(
    namespace: &str,
    pod_uid: &PodUid,
    imp: &Implementation,
) -> Vec<String> {
    imp.modules
        .iter()
        .map(|m| qualify_module(namespace, pod_uid, &m.name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Quantum-shaped bundle mirroring rfc_k8s.md §9 (digests truncated to
    /// valid 64-hex form; the linux impl carries an OCI-backed broker node).
    fn quantum_manifest_json() -> String {
        let d = format!("sha256:{}", "ab".repeat(32)); // 64 hex
        format!(
            r#"{{
  "schemaVersion": 1,
  "name": "quantum",
  "version": "1.0.0",
  "contract": {{
    "imports": [
      {{ "name": "network", "contract": "network.ethernet", "version": 1 }},
      {{ "name": "keyVault", "contract": "key.vault", "version": 1 }}
    ],
    "exports": [ {{ "name": "mqtt", "protocol": "tcp", "port": 1883 }} ],
    "configSchema": {{ "digest": "{d}" }},
    "health": {{ "readiness": "quantum.ready", "liveness": "quantum.progress" }},
    "update": {{ "drainTimeoutMs": 30000, "statePolicy": "preserve-compatible" }}
  }},
  "implementations": [
    {{
      "target": {{ "family": "bcm2712", "architecture": "aarch64", "fluxorAbi": 1 }},
      "graph": {{ "digest": "{d}" }},
      "modules": [ {{ "name": "protocol_router", "digest": "{d}" }} ],
      "resources": {{ "digest": "{d}" }},
      "bindings": {{
        "imports": {{ "network": "platform.net0", "keyVault": "platform.keys" }},
        "exports": {{ "mqtt": "protocol_router.mqtt" }},
        "health": {{ "quantum.ready": "protocol_router.ready", "quantum.progress": "protocol_router.progress" }}
      }}
    }},
    {{
      "target": {{ "family": "linux", "architecture": "aarch64", "fluxorAbi": 1 }},
      "graph": {{ "digest": "{d}" }},
      "modules": [ {{ "name": "protocol_router", "digest": "{d}" }} ],
      "resources": {{ "digest": "{d}" }},
      "externalNodes": [
        {{
          "module": "broker",
          "executor": "linux.oci",
          "executionClass": "external-hosted",
          "image": "registry.example/broker@{d}",
          "interfaceBindings": [ {{ "proxyPort": "mqtt", "kind": "tcp", "containerPort": 1883 }} ]
        }}
      ],
      "bindings": {{
        "imports": {{ "network": "platform.net0", "keyVault": "platform.keys" }},
        "exports": {{ "mqtt": "broker.mqtt" }},
        "health": {{ "quantum.ready": "broker.ready", "quantum.progress": "broker.progress" }}
      }}
    }}
  ]
}}"#
        )
    }

    #[test]
    fn quantum_bundle_parses_and_validates() {
        let m = parse_manifest(&quantum_manifest_json()).expect("parse");
        assert_eq!(m.name, "quantum");
        assert_eq!(m.implementations.len(), 2);
        let report = validate(&m);
        assert!(report.is_ok(), "expected valid, got {:?}", report.errors);
    }

    #[test]
    fn round_trips_through_json() {
        let m = parse_manifest(&quantum_manifest_json()).unwrap();
        let json = serde_json::to_string(&m).unwrap();
        let m2 = parse_manifest(&json).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn target_selection_picks_the_right_impl() {
        let m = parse_manifest(&quantum_manifest_json()).unwrap();
        let bcm = select_implementation(&m, "bcm2712", "aarch64", 1).unwrap();
        assert!(bcm.external_nodes.is_empty());
        let linux = select_implementation(&m, "linux", "aarch64", 1).unwrap();
        assert_eq!(linux.external_nodes.len(), 1);
        assert!(select_implementation(&m, "rp2350", "thumbv8m", 1).is_none());
    }

    #[test]
    fn missing_import_binding_is_rejected_with_path() {
        let mut m = parse_manifest(&quantum_manifest_json()).unwrap();
        m.implementations[0].bindings.imports.remove("keyVault");
        let report = validate(&m);
        assert!(!report.is_ok());
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("implementations[0].bindings.imports") && e.contains("keyVault")));
    }

    #[test]
    fn unpinned_external_image_is_rejected() {
        let mut m = parse_manifest(&quantum_manifest_json()).unwrap();
        m.implementations[1].external_nodes[0].image = "registry.example/broker:latest".into();
        let report = validate(&m);
        assert!(report.errors.iter().any(|e| e.contains("digest-pinned")));
    }

    #[test]
    fn external_proxy_port_must_be_declared_export() {
        let mut m = parse_manifest(&quantum_manifest_json()).unwrap();
        m.implementations[1].external_nodes[0].interface_bindings[0].proxy_port = "amqp".into();
        let report = validate(&m);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("proxyPort") && e.contains("amqp")));
    }

    #[test]
    fn bad_state_policy_and_digest_rejected() {
        let mut m = parse_manifest(&quantum_manifest_json()).unwrap();
        m.contract.update.state_policy = "yolo".into();
        m.contract.config_schema.digest = "notadigest".into();
        let report = validate(&m);
        assert!(report.errors.iter().any(|e| e.contains("statePolicy")));
        assert!(report.errors.iter().any(|e| e.contains("configSchema")));
    }

    #[test]
    fn resource_profile_extracts_to_compose() {
        let json = r#"{
            "modules": 12, "edges": 18, "stateBytes": 262144, "bufferBytes": 65536,
            "endpoints": 3, "domains": 1,
            "stateSchemas": { "protocol_router": "sha256:00" }
        }"#;
        let doc = parse_resource_profile(json).expect("parse");
        let rp = doc.to_compose();
        assert_eq!(rp.modules, 12);
        assert_eq!(rp.edges, 18);
        assert_eq!(rp.state_bytes, 262144);
        assert_eq!(rp.buffer_bytes, 65536);
        assert_eq!(rp.endpoints, 3);
        assert_eq!(rp.domains, 1);
    }

    #[test]
    fn module_namespacing_is_deterministic_and_collision_free() {
        let mut uid_a = [0u8; 16];
        uid_a[0] = 0xab;
        let uid_b = [0xcdu8; 16];

        let n1 = qualify_module("default", &uid_a, "protocol_router");
        let n2 = qualify_module("default", &uid_a, "protocol_router");
        assert_eq!(n1, n2, "deterministic");
        assert!(n1.starts_with("pod/default/ab"));
        assert!(n1.ends_with("/protocol_router"));

        // same local name, different pods → distinct qualified names
        let other = qualify_module("default", &uid_b, "protocol_router");
        assert_ne!(n1, other);

        let m = parse_manifest(&quantum_manifest_json()).unwrap();
        let qualified = qualify_implementation_modules("ns", &uid_a, &m.implementations[0]);
        assert_eq!(qualified.len(), 1);
        assert_eq!(
            qualified[0],
            qualify_module("ns", &uid_a, "protocol_router")
        );
    }
}
