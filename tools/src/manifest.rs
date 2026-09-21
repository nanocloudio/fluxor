//! Module manifest: structured metadata for composition, validation, and integrity.
//!
//! The manifest is a required section in every `.fmod` file (ABI v2+).
//! It describes ports, resource claims, dependencies, and an optional integrity hash.

#![allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]

use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::hash::fnv1a_hash;

/// The module tiers, in tier-table order
/// (standards/fluxor-modules.md §0.1). A module lives in exactly one
/// of these directories; the tier is its ownership/portability
/// statement, never its delivery (`builtin = true` is a manifest key).
///
/// This is the ONE list. Every consumer — the builder, manifest
/// source-tree lookup, config module search roots, scenario
/// validation, module tests — walks these and only these, so a tier
/// that resolves is a tier that builds and is tested. There is no
/// flat `modules/<name>/` entry: §0.1's table has none, so neither
/// does this. A project with a flat layout has no resolvable modules
/// until it moves them into tiers.
///
/// `modules/common/` holds shared sources rather than modules; it
/// carries no `manifest.toml`, and every consumer keys discovery off
/// manifest presence, so listing it here is inert until a sibling
/// project puts a real module there.
pub const MODULE_TIERS: &[&str] = &[
    "modules/foundation",
    "modules/drivers",
    "modules/platform/linux",
    "modules/platform/wasm",
    "modules/platform/qemu",
    "modules/fixtures",
    "modules/app",
    "modules/common",
];

/// Manifest section magic: "FXMF"
pub const MANIFEST_MAGIC: u32 = 0x464D5846;

/// Manifest format version. Kept at v1 by policy — the kernel and
/// tools always ship together, so additive wire-format extensions
/// ride within v1 rather than bumping the integer. The current
/// layout is:
///
/// - 16-byte header (magic, version, port/resource/dependency
///   counts, module_version, hardware_targets, state_size_hint,
///   flags, fine-grained permissions byte).
/// - Port records (4 bytes each): `[direction, content_type, flags,
///   index]`. Byte 3 is the resolved per-direction `PortSpec.index`,
///   matching what the config compiler wires against.
/// - Resource records (4 bytes each).
/// - Dependency records (8 bytes each).
/// - Optional 32-byte SHA-256 integrity hash (flags bit 0).
/// - Optional `[ed25519_signature: 64B][signer_pubkey_fingerprint:
///   32B]` block (flags bit 1). The signature covers the integrity
///   hash, not the full module bytes.
pub const MANIFEST_VERSION: u8 = 1;

/// Manifest header size (fixed portion before variable sections)
pub const MANIFEST_HEADER_SIZE: usize = 17;

/// Signature block size (ed25519 signature + signer fingerprint).
pub const SIGNATURE_BLOCK_SIZE: usize = 96;

// Content-type wire-byte table lives in `fluxor-contracts` so sibling
// projects authoring module manifests can depend on it without pulling
// in the rest of the host-side tooling. Re-exported here to preserve
// the long-standing `tools::manifest::CONTENT_TYPES` import path.
pub use fluxor_contracts::CONTENT_TYPES;

fn content_type_from_str(s: &str) -> Result<u8> {
    if let Some(idx) = CONTENT_TYPES
        .iter()
        .position(|&t| t.eq_ignore_ascii_case(s))
    {
        return Ok(idx as u8);
    }
    // Levenshtein "did you mean" hint — content_type typos in port
    // declarations are common (e.g. `content_type: "AudioSAMPLE"` vs
    // `"AudioSample"`). Case-insensitive match would have caught the
    // capitalisation difference; the closest_match catches actual
    // misspellings (`"AudioSamle"` → `"AudioSample"`). The helper
    // lives in `crate::text_distance` so it's reachable from both
    // the binary and library compilation contexts of this file.
    let candidates: Vec<String> = CONTENT_TYPES.iter().map(|s| s.to_string()).collect();
    let suggestion = crate::text_distance::closest_match(s, &candidates, 3);
    Err(Error::Module(match suggestion {
        Some(hint) => format!("unknown content type: '{s}'. Did you mean '{hint}'?"),
        None => format!("unknown content type: '{s}'"),
    }))
}

// ── Contract name → u8 mapping (matches provider::contract constants) ───────
//
// The manifest's `requires_contract` field names a contract by its layer
// name. Module-facing names mirror the layer boundaries documented in
// `docs/architecture/abi_layers.md`:
//   - HAL hardware contracts: "gpio", "spi", "i2c", "pio", "uart", "adc", "pwm"
//   - Stable module contracts: "fs" (plus kernel-provided channel/timer/buffer/event, implicit)
//   - Platform transport contracts: "platform_nic_ring", "platform_dma",
//     "platform_dma_fd", "pcie_device" (raw register-level surfaces gated
//     by `platform_raw`)
//
// Permission names ("internal", "flash_raw", "platform_raw", etc.) are not
// contracts and belong in the top-level `permissions = [...]` list — they
// are rejected here with a schema-error pointing at the correct section.

/// Width of the public contract-id space. A contract id is a bit position
/// in the fmod header's `required_caps` (u64 at `reserved[6..14]`) and the
/// index of the kernel's vtable registry, so this mirrors
/// `MAX_CONTRACTS` in `src/kernel/module/provider.rs`; the two are checked
/// against each other by `tools/tests/contract_id_inventory.rs`.
pub const CONTRACT_ID_SPACE: usize = 64;

/// Positions consumed in the `required_caps` space, counting the four
/// reserved ids and excluding the kernel-internal dispatch bucket (0x0C).
/// Registered in `docs/architecture/limit_register.md`.
pub const CONTRACT_ID_POSITIONS_ASSIGNED: usize = 29;

/// Parse a contract name from `[[resources]].requires_contract`. Only
/// public contract names are accepted here — `"internal"` and specific
/// permission names like `"flash_raw"` or `"platform_raw"` are **not**
/// contracts and must be declared under the top-level `permissions = [...]`
/// list instead.
///
/// An id outside [`CONTRACT_ID_SPACE`] is unrepresentable in the header
/// mask and unregisterable as a vtable, and is refused by
/// [`Manifest::required_caps_mask`].
pub fn contract_id_from_name(s: &str) -> Result<u8> {
    match s.to_ascii_lowercase().as_str() {
        "gpio" => Ok(0x01),
        "spi" => Ok(0x02),
        "i2c" => Ok(0x03),
        "pio" => Ok(0x04),
        "channel" => Ok(0x05),
        "timer" => Ok(0x06),
        "platform_nic_ring" => Ok(0x07),
        "platform_dma" => Ok(0x08),
        "fs" => Ok(0x09),
        "buffer" => Ok(0x0A),
        "event" => Ok(0x0B),
        "uart" => Ok(0x0D),
        "adc" => Ok(0x0E),
        "pwm" => Ok(0x0F),
        "platform_dma_fd" => Ok(0x11),
        "pcie_device" => Ok(0x12),
        // Storage capability surfaces (see
        // docs/architecture/storage_capability_surface.md). Both are
        // module-providable contracts; class bytes match the kernel
        // `provider::contract::STORAGE_*` constants.
        "storage.namespace" => Ok(0x13),
        "storage.object" => Ok(0x14),
        // USB host controller binding (scaffold). Allocated so
        // foundation modules can name the contract today; the kernel
        // vtable is not yet implemented and `provider_open` against
        // it returns ENOSYS until a host-controller driver lands.
        "usb_host" => Ok(0x15),
        // Host process executor (the impure boundary). Host-linux only; a node
        // without the `proc` grant ENOSYS-denies.
        "proc" => Ok(0x16),
        // "keyspace" (0x17) is not accepted here — the keyspace surface
        // lives in lattice; the ID stays reserved.
        // "oci" (0x18) / "netfilter" (0x19) are not accepted — host
        // isolation is declared as "workload" (0x1A); their mechanism is
        // that contract's Linux backend. The IDs stay reserved.
        // Platform-neutral isolated-workload surface (workload). Host-linux;
        // class byte matches provider::contract::WORKLOAD. Also requires the
        // platform_raw permission.
        "workload" => Ok(0x1A),
        // The platform's verdict on a certificate chain. A module naming it
        // is saying it will ASK rather than verify, which is the only thing
        // this contract lets it do: no anchors cross it.
        "trust" => Ok(0x1D),
        // Anything that looks like a permission name is a manifest
        // schema error — those go in `permissions = [...]`, not
        // `[[resources]]`.
        "internal" | "system" | "reconfigure" | "flash_raw" | "backing_provider"
        | "platform_raw" | "monitor" | "bridge" => Err(Error::Module(format!(
            "`{s}` is a permission, not a contract. Declare it in the \
                 top-level `permissions = [\"{s}\", ...]` list, not under \
                 `[[resources]]`. See docs/architecture/abi_layers.md."
        ))),
        _ => Err(Error::Module(format!(
            "unknown contract name: {s} — expected one of: gpio, spi, i2c, pio, \
             uart, adc, pwm, fs, storage.namespace, storage.object, usb_host, \
             platform_nic_ring, platform_dma, platform_dma_fd, \
             pcie_device, trust (see docs/architecture/abi_layers.md)"
        ))),
    }
}

pub fn contract_name_to_str(class: u8) -> &'static str {
    // Must round-trip with `contract_id_from_name`: every id that
    // `_from_name` accepts MUST be present here, and the returned
    // name MUST be one that `_from_name` round-trips back to the
    // same id. The drift-guard test in
    // `tools/tests/contract_id_round_trip.rs` enforces both
    // directions.
    match class {
        0x01 => "gpio",
        0x02 => "spi",
        0x03 => "i2c",
        0x04 => "pio",
        0x05 => "channel",
        0x06 => "timer",
        0x07 => "platform_nic_ring",
        0x08 => "platform_dma",
        0x09 => "fs",
        0x0A => "buffer",
        0x0B => "event",
        0x0C => "internal",
        0x0D => "uart",
        0x0E => "adc",
        0x0F => "pwm",
        0x11 => "platform_dma_fd",
        0x12 => "pcie_device",
        // Storage capability surfaces — kept in sync with
        // `provider::contract::STORAGE_{NAMESPACE,OBJECT}` (kernel)
        // and `contract_id_from_name` (this file). Without these rows
        // an error quoting bit 0x13/0x14 of a required-caps mask would
        // render the byte as "unknown".
        0x13 => "storage.namespace",
        0x14 => "storage.object",
        0x15 => "usb_host",
        0x16 => "proc",
        0x1A => "workload",
        _ => "unknown",
    }
}

// Canonical capability registry lives in `fluxor-contracts` so sibling
// projects authoring module manifests share one source of truth (the same
// reason `CONTENT_TYPES` lives there). Re-exported here for manifest
// validation and the presentation-group checks.
pub use fluxor_contracts::vocabulary::CAPABILITY_NAMES;
use fluxor_contracts::vocabulary::{PROVIDER_CONTRACTS, PROVIDER_SURFACES};

/// Validate capability names against the whitelist and canonicalize each
/// entry to its lowercase form in place. Downstream consumers — the
/// presentation-group validator, telemetry, doc dumps — can then use
/// exact string comparison instead of paying for case-insensitive
/// matching at every callsite.
fn validate_capability_names(caps: &mut [String]) -> Result<()> {
    for c in caps {
        *c = canonical_capability(c, "capability")?;
    }
    Ok(())
}

/// Resolve one capability string to its canonical lowercase spelling, or
/// fail with a did-you-mean. `field` names the manifest key being checked
/// so the error points at `capabilities` or `requires_capability` rather
/// than at "a capability" in the abstract.
fn canonical_capability(name: &str, field: &str) -> Result<String> {
    match CAPABILITY_NAMES
        .iter()
        .find(|n| n.eq_ignore_ascii_case(name))
    {
        Some(canonical) => Ok((*canonical).to_string()),
        None => {
            let candidates: Vec<String> = CAPABILITY_NAMES.iter().map(|s| s.to_string()).collect();
            let did_you_mean = crate::text_distance::closest_match(name, &candidates, 3)
                .map(|s| format!(" Did you mean `{s}`?"))
                .unwrap_or_default();
            Err(Error::Module(format!(
                "unknown {field} `{name}`.{did_you_mean} Expected one of: {}.",
                CAPABILITY_NAMES.join(", "),
            )))
        }
    }
}

/// Validate a `[capability_facts]` table: every capability it names must be
/// one this module declares or requires (or a parent of one), every fact
/// must be admitted by that capability's schema, and every value must be
/// admitted by that fact.
///
/// Declaring facts for a capability the module neither carries nor needs is
/// an error rather than a no-op: it is always a mistake, and a silently
/// ignored `ack = "durable"` is exactly the kind of unchecked promise the
/// registry exists to prevent.
/// Flatten `[capability_facts]` TOML values to strings.
///
/// A numeric fact reads naturally unquoted (`max_payload = 4096`) and a
/// string fact quoted (`ack = "durable"`); both arrive here as raw TOML and
/// leave as strings, so the schema check downstream has one shape to reason
/// about. Any other TOML type is a manifest error rather than a coercion —
/// `ack = true` is a mistake, not a boolean fact.
fn normalise_capability_facts(
    raw: Option<
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, toml::Value>>,
    >,
) -> Result<std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>> {
    let mut out: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>> =
        std::collections::BTreeMap::new();
    for (capability, table) in raw.unwrap_or_default() {
        let mut flat = std::collections::BTreeMap::new();
        for (fact, value) in table {
            let text = match value {
                toml::Value::String(s) => s,
                toml::Value::Integer(i) => {
                    if i < 0 {
                        return Err(Error::Module(format!(
                            "fact `{fact}` on capability `{capability}` is negative ({i}); \
                             capability facts are non-negative."
                        )));
                    }
                    i.to_string()
                }
                other => {
                    return Err(Error::Module(format!(
                        "fact `{fact}` on capability `{capability}` must be a string or an \
                         integer, got a {}.",
                        other.type_str(),
                    )))
                }
            };
            flat.insert(fact, text);
        }
        out.insert(capability, flat);
    }
    Ok(out)
}

fn validate_capability_facts(
    facts: &std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    declared: &[String],
    required: &[String],
) -> Result<()> {
    use fluxor_contracts::vocabulary::{capability_and_parents, fact_is_numeric, facts_for};

    for (capability, table) in facts {
        let canonical = canonical_capability(capability, "capability_facts capability")?;
        // Facts belong to either side of the surface. A PROVIDER states the
        // terms it offers (`capabilities`); a CONSUMER states the terms it
        // needs — what it sends, so a provider's ceiling can be checked
        // against it — and names the capability on a port's
        // `requires_capability` rather than providing it.
        // The key may be the capability itself or a PARENT of it, since
        // sibling roles share the parent's schema rather than repeating it.
        let covered = declared
            .iter()
            .chain(required.iter())
            .any(|name| capability_and_parents(name).any(|probe| probe == canonical));
        if !covered {
            return Err(Error::Module(format!(
                "[capability_facts.\"{canonical}\"] declares facts for a capability this \
                 module neither lists in `capabilities = [...]` nor names in any port's \
                 `requires_capability`."
            )));
        }
        let Some(schema) = facts_for(&canonical) else {
            return Err(Error::Module(format!(
                "capability `{canonical}` carries no facts, so \
                 [capability_facts.\"{canonical}\"] has nothing to declare."
            )));
        };
        for (fact, value) in table {
            let Some((_, admitted)) = schema.iter().find(|(n, _)| n == fact) else {
                let candidates: Vec<String> =
                    schema.iter().map(|(n, _)| (*n).to_string()).collect();
                let did_you_mean = crate::text_distance::closest_match(fact, &candidates, 3)
                    .map(|s| format!(" Did you mean `{s}`?"))
                    .unwrap_or_default();
                return Err(Error::Module(format!(
                    "unknown fact `{fact}` on capability `{canonical}`.{did_you_mean} \
                     Expected one of: {}.",
                    candidates.join(", "),
                )));
            };
            if fact_is_numeric(&canonical, fact) {
                if value.parse::<u32>().is_err() {
                    return Err(Error::Module(format!(
                        "fact `{fact}` on capability `{canonical}` takes a u32, got `{value}`."
                    )));
                }
            } else if !admitted.iter().any(|a| a == value) {
                return Err(Error::Module(format!(
                    "value `{value}` is not admitted for fact `{fact}` on capability \
                     `{canonical}`. Expected one of: {}.",
                    admitted.join(", "),
                )));
            }
        }
    }
    Ok(())
}

/// Validate `[[requires_when]]` entries: the capability must be one a
/// target provides (`TARGET_CAPABILITIES`), spelled canonically, and the
/// parameter and value must be named. Whether the parameter exists is the
/// composer's to check, against the module's schema, when the module is
/// placed.
fn validate_requires_when(entries: Vec<TomlRequiresWhen>) -> Result<Vec<RequiresWhen>> {
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let capability = canonical_capability(&e.capability, "requires_when capability")?;
        if !crate::target_facts::is_target_capability(&capability) {
            return Err(Error::Module(format!(
                "[[requires_when]] names `{capability}`, which a module provides and a port \
                 requires (`requires_capability`); only a TARGET-provided capability may be \
                 required conditionally. Expected one of: {}.",
                fluxor_contracts::vocabulary::TARGET_CAPABILITIES.join(", "),
            )));
        }
        if e.when.is_empty() {
            return Err(Error::Module(format!(
                "[[requires_when]] for `{capability}` has an empty `when`; an unconditional \
                 requirement belongs in `[requires]`"
            )));
        }
        let mut when = Vec::with_capacity(e.when.len());
        for (param, values) in e.when {
            let values = match values {
                TomlWhenValues::One(v) => vec![v],
                TomlWhenValues::Any(vs) => vs,
            };
            if param.trim().is_empty()
                || values.is_empty()
                || values.iter().any(|v| v.trim().is_empty())
            {
                return Err(Error::Module(format!(
                    "[[requires_when]] for `{capability}`: every `when` condition needs a \
                     parameter name and at least one value"
                )));
            }
            when.push((param, values));
        }
        out.push(RequiresWhen { capability, when });
    }
    Ok(out)
}

/// Validate `provides = [..]` entries against the providable vocabulary
/// (service/contract names in `PROVIDER_CONTRACTS` plus the storage
/// **surface** family in `PROVIDER_SURFACES`). Like capabilities, `provides`
/// is resolved by exact string match downstream — the config resolver wires
/// consumers to providers by name — so an unwhitelisted typo would silently
/// never resolve. Fail it at parse instead, with a did-you-mean.
fn validate_provides_names(provides: &[String]) -> Result<()> {
    for p in provides {
        let known = PROVIDER_CONTRACTS
            .iter()
            .chain(PROVIDER_SURFACES.iter())
            .any(|n| n.eq_ignore_ascii_case(p));
        if !known {
            let candidates: Vec<String> = PROVIDER_CONTRACTS
                .iter()
                .chain(PROVIDER_SURFACES.iter())
                .map(|s| s.to_string())
                .collect();
            let did_you_mean = crate::text_distance::closest_match(p, &candidates, 3)
                .map(|s| format!(" Did you mean `{s}`?"))
                .unwrap_or_default();
            return Err(Error::Module(format!(
                "unknown provided surface/service `{p}`.{did_you_mean} Expected one of: {}.",
                candidates.join(", "),
            )));
        }
    }
    Ok(())
}

fn access_mode_from_str(s: &str) -> Result<u8> {
    match s.to_ascii_lowercase().as_str() {
        "read" => Ok(0),
        "write" => Ok(1),
        "exclusive" => Ok(2),
        "chain" => Ok(3),
        _ => {
            let valid = ["read", "write", "exclusive", "chain"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>();
            let did_you_mean = crate::text_distance::closest_match(s, &valid, 3)
                .map(|h| format!(" Did you mean '{h}'?"))
                .unwrap_or_default();
            Err(Error::Module(format!(
                "unknown access mode: '{s}'.{did_you_mean} Expected: read, write, exclusive, chain."
            )))
        }
    }
}

fn access_mode_to_str(mode: u8) -> &'static str {
    match mode {
        0 => "read",
        1 => "write",
        2 => "exclusive",
        3 => "chain",
        _ => "unknown",
    }
}

fn direction_from_str(s: &str) -> Result<u8> {
    match s.to_ascii_lowercase().as_str() {
        "input" | "in" => Ok(0),
        "output" | "out" => Ok(1),
        "ctrl" | "ctrl_input" => Ok(2),
        "ctrl_output" => Ok(3),
        _ => {
            let valid = ["input", "output", "ctrl", "ctrl_output"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>();
            let did_you_mean = crate::text_distance::closest_match(s, &valid, 3)
                .map(|h| format!(" Did you mean '{h}'?"))
                .unwrap_or_default();
            Err(Error::Module(format!(
                "unknown port direction: '{s}'.{did_you_mean} Expected: input, output, ctrl, ctrl_output."
            )))
        }
    }
}

pub fn direction_to_str(d: u8) -> &'static str {
    match d {
        0 => "input",
        1 => "output",
        2 => "ctrl",
        3 => "ctrl_output",
        _ => "unknown",
    }
}

pub fn content_type_to_str(ct: u8) -> &'static str {
    CONTENT_TYPES.get(ct as usize).copied().unwrap_or("Unknown")
}

// ── Semver encoding ─────────────────────────────────────────────────────────

/// Encode semver (major, minor, patch) into a u16: major<<10 | minor<<5 | patch.
/// Supports major 0-63, minor 0-31, patch 0-31.
pub fn encode_semver(major: u8, minor: u8, patch: u8) -> u16 {
    ((major as u16 & 0x3F) << 10) | ((minor as u16 & 0x1F) << 5) | (patch as u16 & 0x1F)
}

/// Decode u16 semver back to (major, minor, patch).
pub fn decode_semver(v: u16) -> (u8, u8, u8) {
    let major = ((v >> 10) & 0x3F) as u8;
    let minor = ((v >> 5) & 0x1F) as u8;
    let patch = (v & 0x1F) as u8;
    (major, minor, patch)
}

fn parse_semver(s: &str) -> Result<(u8, u8, u8)> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Module(format!("invalid semver: {s}")));
    }
    let major: u8 = parts[0]
        .parse()
        .map_err(|_| Error::Module(format!("invalid semver major: {s}")))?;
    let minor: u8 = parts[1]
        .parse()
        .map_err(|_| Error::Module(format!("invalid semver minor: {s}")))?;
    let patch: u8 = parts[2]
        .parse()
        .map_err(|_| Error::Module(format!("invalid semver patch: {s}")))?;
    Ok((major, minor, patch))
}

// ── Hardware target mapping ─────────────────────────────────────────────────

fn hardware_targets_from_list(targets: &[String]) -> u16 {
    let mut mask = 0u16;
    for t in targets {
        match t.to_ascii_lowercase().as_str() {
            "rp2350" => mask |= 0x01,
            "rp2040" => mask |= 0x02,
            "bcm2712" => mask |= 0x04,
            "wasm" => mask |= 0x08,
            "linux" => mask |= 0x10,
            _ => {} // ignore unknown targets
        }
    }
    mask
}

// ── Core types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PortSpec {
    pub direction: u8,
    pub content_type: u8,
    pub flags: u8,
    /// Human-readable port name (tooling-only, not serialized to binary).
    pub name: Option<String>,
    /// Explicit port index within its direction group (default: sequential).
    pub index: u8,
    /// Requested channel ring capacity in bytes (0 = kernel default).
    /// Serialized in the flag-bit-5 port-capacity section so capacity
    /// is knowable statically — including for wasm payloads, whose
    /// packed export tables are empty.
    pub buffer_size: u32,
    /// Largest single `channel_write` this port issues (0 = undeclared).
    /// `channel_write` is all-or-nothing: a record larger than the ring
    /// can NEVER succeed, so the loader refuses at graph load any wiring
    /// where `max_record` exceeds the granted ring.
    pub max_record: u32,
    /// Fastest rate class this port's step logic is engineered for.
    /// Tools-side only (not serialized): wiring a faster-class edge
    /// into the port fails `fluxor build` instead of stalling at
    /// runtime. `None` = undeclared = unchecked.
    pub rate_class_max: Option<fluxor_contracts::RateClass>,
    /// This port's own default rate class, taking priority over the
    /// generic `CONTENT_RATE_CLASS` default for its `content_type`
    /// when resolving an unwired edge's class. Tools-side only (not
    /// serialized). A content type like `NetProto` spans wildly
    /// different real traffic shapes across modules (RTP media vs.
    /// DNS lookups vs. HTTP admin loopback) — a module whose default
    /// diverges from the generic content-type default declares it
    /// here once, instead of every consuming config repeating a
    /// per-edge `rate:` override. `None` = fall back to the
    /// content-type default (see `resolve_edge_rate_class`).
    pub rate_class_default: Option<fluxor_contracts::RateClass>,
    /// The capability the module wired to this port must declare.
    ///
    /// Tools-side only (not serialized). This is the CONSUMER half of the
    /// capability registry, and it lives on the port rather than on the
    /// module for a reason: a capability requirement is satisfied by the
    /// peer on an EDGE, not by some module being present somewhere in the
    /// graph. A module-level requirement would pass a config that wired
    /// this port to entirely the wrong provider.
    ///
    /// Matching is the same parent/child prefix rule the graph validator
    /// already uses for `capabilities`, so a port requiring `request` is
    /// satisfied by a `request.http` provider but not the reverse.
    /// `None` = undeclared = unchecked.
    pub requires_capability: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResourceClaim {
    pub device_class: u8,
    pub access_mode: u8,
    /// Hardware instance index (0xFF = any/unspecified).
    /// Used to distinguish e.g. PIO0 vs PIO1 for conflict checks.
    pub instance: u8,
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name_hash: u32,
    pub min_version: u16,
}

/// FMP command vocabulary: what messages a module accepts and/or emits.
/// Used by the config tool for wiring validation (not serialized to binary).
#[derive(Debug, Clone, Default)]
pub struct CommandVocabulary {
    pub accepts: Vec<String>,
    pub emits: Vec<String>,
}

/// A named feature-set variant declared by a `[[variant]]` table in the
/// source `manifest.toml`. Tools-side only — never serialized to the
/// binary manifest. Each variant drives one rustc invocation (`--cfg
/// feature="…"` per entry in `features`) producing one prebuilt `.fmod`;
/// the default variant emits the unsuffixed `<module>.fmod`, non-default
/// variants emit `<module>-<name>.fmod`. The variant suffix exists only
/// in the filename — the embedded fmod name (and therefore the FXMT
/// `name_hash` graphs bind against) stays the base module type.
#[derive(Debug, Clone)]
pub struct VariantDecl {
    pub name: String,
    /// Cargo-style feature names mapped 1:1 to `--cfg feature="<name>"`.
    pub features: Vec<String>,
    /// Exactly one variant per module must set this; it names which
    /// feature set the plain `<module>.fmod` filename carries.
    pub default: bool,
    /// Ports absent from this variant. Applied by `apply_variant` to the
    /// manifest that gets EMBEDDED in the variant's fmod: omitted ports
    /// are removed from the port table, retained ports keep their
    /// already-resolved indices (omission leaves holes, never shifts —
    /// module code addresses ports positionally).
    pub omit_ports: Vec<String>,
    /// Provider capabilities absent from this artifact.
    pub omit_capabilities: Vec<String>,
}

/// Fine-grained module permissions. Each category gates a specific
/// subset of 0x0Cxx orchestration / platform opcodes; a module that
/// needs only one surface does not implicitly get the others.
///
/// Serialised as a little-endian u16 bitmap into the manifest binary at
/// offset 15 (bytes 15..17). Widened from u8 once the low 8 bits filled
/// (DMA took bit 7); `observe` is bit 8. Not part of the module header's
/// flags byte.
#[derive(Debug, Clone, Copy, Default)]
pub struct ManifestPermissions {
    pub bits: u16,
}

/// Permission category bits. Keep in sync with the kernel's
/// `permission` module in `src/kernel/module/syscalls.rs`.
pub mod permission {
    pub const RECONFIGURE: u16 = 1 << 0; // graph slot commit, boot counter, FMP routing
    pub const FLASH_RAW: u16 = 1 << 1; // flash ERASE / PROGRAM
    pub const BACKING_PROVIDER: u16 = 1 << 2; // paged-arena / backing-provider registration
    pub const PLATFORM_RAW: u16 = 1 << 3; // MMIO/DMA/PCIe/SMMU/NIC, raw peripheral register bridges
    pub const MONITOR: u16 = 1 << 4; // fault monitor BIND/WAIT/ACK/REPORT/RAISE
    pub const BRIDGE: u16 = 1 << 5; // cross-domain / cross-core dispatch
    pub const PCIE_DEVICE: u16 = 1 << 6; // kernel-mediated PCIe device bind/config/BAR/MSI
    pub const DMA: u16 = 1 << 7; // DMA-arena buffer alloc + cache maintenance
    pub const OBSERVE: u16 = 1 << 8; // read-only telemetry-ring drain (TLM_SUBSCRIBE/DRAIN/STATS)
    pub const USB_HOST: u16 = 1 << 9; // kernel-mediated USB host controller bind + transfers

    pub fn from_name(s: &str) -> Option<u16> {
        match s {
            "reconfigure" => Some(RECONFIGURE),
            "flash_raw" => Some(FLASH_RAW),
            "backing_provider" => Some(BACKING_PROVIDER),
            "platform_raw" => Some(PLATFORM_RAW),
            "monitor" => Some(MONITOR),
            "bridge" => Some(BRIDGE),
            "pcie_device" => Some(PCIE_DEVICE),
            "dma" => Some(DMA),
            "observe" => Some(OBSERVE),
            "usb_host" => Some(USB_HOST),
            _ => None,
        }
    }

    pub fn names(bits: u16) -> Vec<&'static str> {
        let mut out = Vec::new();
        if bits & RECONFIGURE != 0 {
            out.push("reconfigure");
        }
        if bits & FLASH_RAW != 0 {
            out.push("flash_raw");
        }
        if bits & BACKING_PROVIDER != 0 {
            out.push("backing_provider");
        }
        if bits & PLATFORM_RAW != 0 {
            out.push("platform_raw");
        }
        if bits & MONITOR != 0 {
            out.push("monitor");
        }
        if bits & BRIDGE != 0 {
            out.push("bridge");
        }
        if bits & PCIE_DEVICE != 0 {
            out.push("pcie_device");
        }
        if bits & DMA != 0 {
            out.push("dma");
        }
        if bits & OBSERVE != 0 {
            out.push("observe");
        }
        if bits & USB_HOST != 0 {
            out.push("usb_host");
        }
        out
    }
}

/// Lowest tag a built-in `[[params]]` entry may claim. Tags below this
/// belong to the TLV framing and to fixed low-numbered fields, so a
/// parameter must not occupy them.
pub const PARAM_TAG_MIN: u8 = 10;

/// Highest tag a built-in `[[params]]` entry may claim. 0xF0..=0xFF are
/// reserved for protection/policy metadata (0xFD voice-preset blobs,
/// 0xFE TLV magic, 0xFF terminator among them).
pub const PARAM_TAG_MAX: u8 = 0xEF;

/// Param type categories declared in `[[params]]`. Matches the wire
/// types used by the runtime TLV packer in `tools/src/schema.rs`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ManifestParamType {
    U8,
    U16,
    U32,
    Str,
    Enum,
}

/// A single `[[params]]` entry from a built-in's `manifest.toml`.
/// Defaults are stored as 32-bit unsigned integers when numeric, or as
/// a string for `str`/`enum`.
#[derive(Debug, Clone)]
pub struct ManifestParam {
    /// TLV tag — declared explicitly by the manifest (`tag = N`) and
    /// permanent once a built-in ships. The tag, not the declaration
    /// position, is the wire identity of the parameter, so entries may
    /// be reordered or inserted without changing any encoding.
    /// Legal range is [`PARAM_TAG_MIN`]..=[`PARAM_TAG_MAX`]; tags below
    /// the minimum belong to the TLV framing and 0xF0..=0xFF are
    /// reserved for protection/policy metadata.
    pub tag: u8,
    pub name: String,
    pub ptype: ManifestParamType,
    /// Numeric default for U8/U16/U32; ignored for Str/Enum.
    pub default_num: u32,
    /// String default for Str; enum-name default for Enum.
    pub default_str: String,
    /// Enum: list of (name, value) mappings. Values are u8.
    pub enum_values: Vec<(String, u8)>,
    /// Optional inclusive range for numeric params: [min, max].
    pub range: Option<(u32, u32)>,
    /// When true, the YAML must specify this param — build fails if
    /// missing. Equivalent to "no safe default exists." Set on params
    /// like `host_asset_source.path` where falling back to a default
    /// would silently misconfigure the graph.
    pub required: bool,
}

/// How a module's notion of time relates to the scheduler tick — governs
/// whether it tolerates the adaptive-tick variable cadence. Declared in the
/// manifest as `timer_class = "..."`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimerClass {
    /// No `timer_class` declared (field absent, or the module has no manifest).
    /// The SAFE default: an unattested module is
    /// assumed step-counted, so mechanism (b) (variable cadence, bit 1) is
    /// BLOCKED on any domain hosting it until it POSITIVELY attests
    /// `wall_clock` or `agnostic`. Mechanism (a)-only domains still admit it
    /// (idle-relax alone doesn't warp a running module; the liveness and
    /// replicated-clock gates cover (a)'s hazards by module type). This
    /// is distinct from an EXPLICIT `agnostic` — the absence of a declaration is
    /// not an attestation.
    #[default]
    Unattested,
    /// Cadence-independent — a pure data transform whose output is a function of
    /// its inputs, not of *when* it runs. Safe under any cadence. An EXPLICIT
    /// declaration that the author has reasoned about cadence (a positive
    /// attestation, unlike `Unattested`).
    Agnostic,
    /// Reads real wall-clock time (`dev_millis`/`dev_micros`) for its timing, so
    /// a variable cadence only changes *when* it samples, never its correctness.
    /// Safe under adaptive tick.
    WallClock,
    /// Counts scheduler ticks/passes as a time proxy — its sense of time warps
    /// when the cadence varies (a relaxed tick stretches its timers). UNSAFE on
    /// an adaptive domain; the validator rejects it.
    TickCounted,
    /// Needs a fixed-cadence WCET guarantee (a control loop / hard-real-time
    /// step). UNSAFE on a mechanism-(b) (variable-cadence) domain UNLESS the
    /// domain re-validates its WCET/budget schedulability at `tick_min_us`
    /// (see `guaranteed_wcet_revalidated`).
    Guaranteed,
    /// Advances an externally committed / replicated logical clock (e.g.
    /// `ttl_scheduler`, `lease_manager`): it reads wall-clock `dev_millis` so
    /// it does NOT silently rescale under a variable cadence, but its expiry
    /// semantics must agree across replicas. Mechanism (b) MUST NOT change the
    /// replicated-tick *emission rate* unless all replicas agree, and
    /// mechanism (a) idle must not stall the tick emitter. The validator
    /// applies the dedicated replicated-clock gate rather than the generic
    /// step-counted gate.
    ReplicatedClock,
}

impl TimerClass {
    /// Parse the manifest string; unknown values are an error so a typo can't
    /// silently downgrade to the lenient default. `unattested` is NOT a writable
    /// value — it is the implicit default for an absent declaration only.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "agnostic" => Some(Self::Agnostic),
            "wall_clock" => Some(Self::WallClock),
            "tick_counted" => Some(Self::TickCounted),
            "guaranteed" => Some(Self::Guaranteed),
            "replicated_clock" => Some(Self::ReplicatedClock),
            _ => None,
        }
    }
    /// True when the class cannot tolerate a variable scheduler cadence — used
    /// for the mechanism-(a)-only lenient gate (only the two hard-unsafe classes
    /// are rejected; `Unattested`/`Agnostic`/`WallClock` are admitted on (a)).
    /// `ReplicatedClock` is NOT here: it reads wall-clock time, so idle-relax
    /// alone doesn't warp it — its (a) hazard (idle stalling the tick emitter)
    /// is handled by the dedicated replicated-clock gate, not this lenient one.
    pub fn forbids_adaptive(self) -> bool {
        matches!(self, Self::TickCounted | Self::Guaranteed)
    }
    /// True only for a POSITIVE attestation that the module tolerates a
    /// variable cadence. Required for every admitted module on a mechanism-(b)
    /// domain: `Unattested` (absent declaration) does NOT qualify — that is
    /// the fail-closed default. `ReplicatedClock` qualifies for the
    /// *per-module rescale* concern (it reads wall-clock time), but the
    /// cross-replica emission-rate hazard is gated separately by the
    /// replicated-clock gate.
    pub fn tolerates_variable_cadence(self) -> bool {
        matches!(
            self,
            Self::WallClock | Self::Agnostic | Self::ReplicatedClock
        )
    }
    /// A replicated/committed logical clock whose cross-replica agreement the
    /// adaptive cadence must not break.
    pub fn is_replicated_clock(self) -> bool {
        matches!(self, Self::ReplicatedClock)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unattested => "unattested",
            Self::Agnostic => "agnostic",
            Self::WallClock => "wall_clock",
            Self::TickCounted => "tick_counted",
            Self::Guaranteed => "guaranteed",
            Self::ReplicatedClock => "replicated_clock",
        }
    }
}

/// Which kind of execution claim a module's `[execution]` facts make
/// Declared in the manifest as
/// `profile = "..."`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionProfile {
    /// The numbers rest on an auditable execution model: every code path a
    /// step can take is bounded and the derivation is on file at
    /// `evidence`. Only a bare-metal target can honour a bound claim.
    AnalyticalBound,
    /// The numbers are observed maxima under a stated workload on a stated
    /// host. A percentile, not a guarantee; what Linux always publishes.
    MeasuredEnvelope,
}

impl ExecutionProfile {
    /// The manifest and config spellings.
    pub const NAMES: [&'static str; 2] = ["analytical_bound", "measured_envelope"];

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "analytical_bound" => Some(Self::AnalyticalBound),
            "measured_envelope" => Some(Self::MeasuredEnvelope),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AnalyticalBound => "analytical_bound",
            Self::MeasuredEnvelope => "measured_envelope",
        }
    }
}

/// A module's `[execution]` facts — the two universal timing declarations
/// of the envelope and the profile they are made under.
/// TOML-only, never serialized to the binary manifest: the facts are what
/// the composer admits a graph against, and a binary-loaded manifest makes
/// no timing claim at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEnvelope {
    /// Exclusive local CPU time of one `module_step`, in microseconds, on
    /// the profile's stated host. Synchronous provider dispatches the step
    /// makes are NOT inside this number — they are charged separately by
    /// `max_dispatch_us` and the dispatch count, so a provider shared by
    /// several callers is accounted once.
    pub max_step_us: u32,
    /// Bounded cost of one synchronous provider dispatch the module makes,
    /// in microseconds.
    pub max_dispatch_us: u32,
    pub profile: ExecutionProfile,
    /// Where the numbers come from: the gate that measures them or the
    /// derivation that bounds them. Required for `analytical_bound`.
    pub evidence: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub module_version: u16,
    pub hardware_targets: u16,
    pub state_size_hint: u16,
    pub ports: Vec<PortSpec>,
    pub resources: Vec<ResourceClaim>,
    pub permissions: ManifestPermissions,
    pub dependencies: Vec<Dependency>,
    pub integrity_hash: Option<[u8; 32]>,
    /// ABI wire-surface digest of the SDK/kernel tree this module was
    /// PACKED against (`hash::abi_surface_digest`, flag bit 4 + trailing
    /// 32-byte block in the binary). Packaging (slot-image, mktable,
    /// combine) rejects a module whose attestation differs from the
    /// current surface — a stale `.fmod` built before an ABI renumbering
    /// cannot ride into a new image. `None` on a module packed without an
    /// attestation (accepted, unverifiable).
    pub abi_surface: Option<[u8; 32]>,
    /// Ed25519 signature over the integrity hash. Set by the `fluxor sign`
    /// subcommand; absent on unsigned (v1) manifests.
    pub signature: Option<[u8; 64]>,
    /// SHA-256 fingerprint of the signer's Ed25519 public key. Loader
    /// matches this against OTP/provisioned pubkey to accept/reject.
    pub signer_fp: Option<[u8; 32]>,
    /// FMP command vocabulary (parsed from TOML, not in binary format)
    pub commands: CommandVocabulary,
    /// Services this module provides to others (parsed from TOML, not in
    /// binary format). Used by the config resolver to wire dependencies by
    /// service name (e.g. `pwm_rp` provides `"pwm"`).
    pub provides: Vec<String>,
    /// Terms on which this module offers each capability it declares
    /// (parsed from TOML, not serialized to the binary `.fmod`). Keyed by
    /// capability name; see `fluxor_contracts::vocabulary::CAPABILITY_FACTS`.
    pub capability_facts:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    /// Role/surface capabilities this module declares (parsed from TOML,
    /// not serialized to the binary `.fmod`). The whitelist lives in
    /// `CAPABILITY_NAMES`; the config validator consults this field to
    /// enforce presentation-group rules. See
    /// `docs/architecture/av_capability_surface.md`.
    pub capabilities: Vec<String>,
    /// Build-time observability declarations from the `[observability]` table
    /// (parsed from TOML, not serialized to the binary `.fmod`). Consulted by
    /// `fluxor lint observability`. See `standards/observability.md` §6.
    pub observability: Observability,
    /// Module is built into the kernel (no .fmod file needed).
    /// Used by platform-specific modules like linux_net.
    pub builtin: bool,
    /// `[[variant]]` feature-set variants. Parsed from TOML, tools-side
    /// only, never serialized to binary — the binary manifest a variant
    /// fmod embeds is the already-filtered port table, not the variant
    /// declaration.
    pub variants: Vec<VariantDecl>,
    /// `[capacities]` — module-scope capacity declarations, already
    /// resolved for the silicon this manifest was loaded for (same
    /// flat-or-per-silicon form as a port's `buffer_size`). These size a
    /// buffer the MODULE owns but the build tooling must agree on, so the
    /// manifest is the single place the bound is written and the tool
    /// reads it instead of hard-coding a second copy. TOML-only, never
    /// serialized to the binary manifest.
    pub capacities: std::collections::BTreeMap<String, u32>,
    /// Module attests that its `module_step` / `module_isr_init` /
    /// `module_isr_entry` exports are safe to invoke from an ISR
    /// context: no heap allocation, no `provider_call`, no
    /// `channel_read`/`channel_write`, bounded execution within the
    /// declared `isr_budget_cycles`. The author owns this claim; the
    /// tool does not statically verify it. The flag is mandatory for
    /// admission into a Tier 1b (`domain_exec_mode == 2`) or Tier 2
    /// (`domain_exec_mode == 4`) domain — modules without it are
    /// rejected at build time. The runtime backstop is the EACCES check
    /// the scheduler applies to every syscall an ISR-tier module is
    /// barred from making.
    pub isr_safe: bool,
    /// Module attests that it can resume after an arbitrary fault, and is
    /// therefore eligible for `fault_policy: restart`. That policy releases
    /// every provider handle the module owned, flushes every connected
    /// input / output / control channel, and resumes the **same** state
    /// allocation — it does not zero state and does not re-run
    /// `module_new`. The attestation asserts all four of:
    ///   * no invariant is carried across `module_step` boundaries — every
    ///     externally visible transition completes within one step or is
    ///     safely abandonable inside one;
    ///   * losing every provider handle without notification is tolerable;
    ///   * discarding everything in flight on every channel loses at most
    ///     work the module's own protocol layer already treats as loss;
    ///   * any counter or rate state that resumes part-updated affects
    ///     behaviour only within its own bounded window.
    ///
    /// The author owns this claim; the tool does not statically verify it.
    /// Absent ⇒ `false`, and the config validator refuses the policy.
    /// TOML-only, never serialized to the binary manifest: the policy it
    /// gates is itself a compose-time choice.
    pub resume_after_fault: bool,
    /// Module opts into the **Tier 1c pre-pass drain slot**. Pre-tick
    /// modules run cooperatively at the *start* of every scheduler
    /// pass for their domain, before the regular `domain_exec_order`
    /// rotation. Use for latency-critical drains that need to run
    /// every tick regardless of `exec_order` position (canonical
    /// case: NIC RX/TX). The module retains the full cooperative API
    /// (heap + `provider_call` + `channel_read`/`write`); the only
    /// new contract is a shared combined cycle budget across all
    /// pre-tick modules in a domain (kernel default
    /// `MAX_PRE_TICK_BUDGET_US = 5`).
    pub pre_tick_drain: bool,
    /// Hardware-feature requirements declared by the module.
    /// Validated against the resolved target's silicon capability
    /// matrix at config time by `check_target_capabilities`. Default
    /// `TomlRequires::default()` (all-false) means "no specific
    /// requirements," which satisfies every silicon.
    pub requires: TomlRequires,
    /// Conditional target-capability requirements (`[[requires_when]]`).
    /// TOML-only, never serialized; evaluated at compose against the
    /// resolved target's facts (`target_facts::TargetFacts`).
    pub requires_when: Vec<RequiresWhen>,
    /// `[build] wasm_opt_level = "0"|"1"|"2"|"3"|"s"|"z"` — per-module
    /// rustc `opt-level` for the wasm target. TOML-only, never
    /// serialized to the binary. `None` keeps the build default.
    pub wasm_opt_level: Option<String>,
    /// `[build] opt_level = "0"|"1"|"2"|"3"|"s"|"z"` — per-module rustc
    /// `opt-level` for a native target. TOML-only, never serialized.
    /// `None` keeps the build default.
    ///
    /// The loader admits a bounded amount of code per module, and a module
    /// that links a whole engine can reach it. Building that one for size
    /// where the default builds for speed is the alternative to making every
    /// module slower, or to leaving the one that is nearly over with no room.
    pub opt_level: Option<String>,
    /// Built-in parameter declarations from `[[params]]` (toml-only).
    /// `.fmod` modules carry their schema embedded in the binary; built-ins
    /// declare it here so the config tool can validate YAML and pack TLV.
    pub params: Vec<ManifestParam>,
    /// How the module's timekeeping relates to the scheduler tick. Default
    /// `Unattested` (no declaration). The
    /// config validator rejects `TickCounted`/`Guaranteed` on any adaptive
    /// domain, and on a mechanism-(b) domain requires a POSITIVE attestation
    /// (`wall_clock` or `agnostic`) — `Unattested` is fail-closed for (b).
    pub timer_class: TimerClass,
    /// Coarse-step period in scheduler ticks (module ABI header byte 1,
    /// loader.rs:846). 0 = step every tick (default). N>0 = step every N
    /// ticks; the scheduler counts TICKS, so the wall-clock period is
    /// `step_period_ticks × domain_tick_us` — which a variable cadence WARPS.
    /// The adaptive validator therefore errors when a `step_period_ticks != 0`
    /// module is on a mechanism-(b) domain unless it attests `wall_clock`.
    /// Wired into header byte 1 by `pack_fmod`/`pack_fmod_wasm`.
    pub step_period_ticks: u8,
    /// `[execution]` — the module's step and dispatch cost facts and the
    /// profile they hold under. `None` when the module declares nothing;
    /// the composer's `validate_execution_profile` treats an undeclared
    /// module as one that can be part of no envelope claim.
    pub execution: Option<ExecutionEnvelope>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            module_version: encode_semver(0, 1, 0),
            hardware_targets: 0x01, // RP2350 by default
            state_size_hint: 0,
            ports: Vec::new(),
            resources: Vec::new(),
            permissions: ManifestPermissions::default(),
            dependencies: Vec::new(),
            integrity_hash: None,
            abi_surface: None,
            signature: None,
            signer_fp: None,
            commands: CommandVocabulary::default(),
            provides: Vec::new(),
            capability_facts: std::collections::BTreeMap::new(),
            capabilities: Vec::new(),
            observability: Observability::default(),
            builtin: false,
            variants: Vec::new(),
            capacities: std::collections::BTreeMap::new(),
            isr_safe: false,
            resume_after_fault: false,
            pre_tick_drain: false,
            requires: TomlRequires::default(),
            requires_when: Vec::new(),
            wasm_opt_level: None,
            opt_level: None,
            params: Vec::new(),
            timer_class: TimerClass::Unattested,
            step_period_ticks: 0,
            execution: None,
        }
    }
}

/// Build-time observability declarations from the `[observability]` manifest
/// table — the instrument names a module emits, and an optional opt-out reason.
/// Parsed from TOML, not serialized to the binary `.fmod`. Instrument-name
/// resolution and the baseline contract are enforced by
/// `fluxor lint observability`; see `standards/observability.md`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observability {
    /// Metric instrument names this module emits (interned per module at build).
    pub metrics: Vec<String>,
    /// Span names this module emits.
    pub spans: Vec<String>,
    /// When set, the module opts out of the instrumentation contract with a
    /// stated reason (data-moving modules only).
    pub exempt: Option<String>,
    /// Per-instrument metadata (`[[observability.instrument]]`): kind,
    /// declared histogram bounds, and declared dimension domains. Optional
    /// per instrument — a name in `metrics` with no row here is a plain
    /// dimensionless counter, which is what a name with no row declares
    /// implicitly.
    pub instruments: Vec<InstrumentDecl>,
}

/// One `[[observability.instrument]]` row: build-time metadata for a name in
/// the `metrics` list. Bounds and dimension domains are id-table metadata —
/// they ship to consumers out-of-band and never ride a sample record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstrumentDecl {
    /// Must match a name in `metrics`; the wire id stays that name's position.
    pub name: String,
    pub kind: InstrumentKind,
    /// Histogram bucket upper bounds in µs, strictly ascending. Length is
    /// fixed by kind: 7 for `histogram` (8 buckets), 15 for `histogram16`
    /// (16 buckets, the last implicit `+Inf`). Empty for scalar kinds.
    pub bounds_us: Vec<u64>,
    /// Declared dimension keys, in composite-index order: `dim_id =
    /// ((i0·s1)+i1)·s2+…` over the domain sizes.
    pub dimensions: Vec<DimensionDecl>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstrumentKind {
    Counter,
    UpDown,
    Histogram,
    Histogram16,
}

impl InstrumentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            InstrumentKind::Counter => "counter",
            InstrumentKind::UpDown => "updown",
            InstrumentKind::Histogram => "histogram",
            InstrumentKind::Histogram16 => "histogram16",
        }
    }

    /// Declared-bound count this kind requires (buckets − 1), 0 for scalars.
    pub fn bound_count(self) -> usize {
        match self {
            InstrumentKind::Histogram => 7,
            InstrumentKind::Histogram16 => 15,
            _ => 0,
        }
    }
}

/// One dimension key with its bounded value domain. The product of an
/// instrument's domain sizes is capped at 65534 (`DIM_MAX_PRODUCT`) so the
/// composite index always fits the record's u16 with `0xFFFF` left for
/// `__other__`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DimensionDecl {
    /// Attribute key — OTel semconv or `fluxor.*` (standards/observability.md
    /// §5; vocabulary enforced by `fluxor lint observability`).
    pub key: String,
    pub domain: DimDomain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DimDomain {
    /// Values `0..max` pass through as the component index.
    Numeric { max: u32 },
    /// Declared value set; the component index is the declared position. A
    /// value outside the set folds to `__other__` at the emitter.
    Enum { values: Vec<String> },
}

impl DimDomain {
    pub fn size(&self) -> u32 {
        match self {
            DimDomain::Numeric { max } => *max,
            DimDomain::Enum { values } => values.len() as u32,
        }
    }
}

/// Ceiling on the product of one instrument's declared domain sizes — mirror
/// of `contracts/telemetry.rs::DIM_MAX_PRODUCT`, which keeps every composite
/// index below the reserved `__other__` (`0xFFFF`).
pub const DIM_MAX_PRODUCT: u32 = 65534;

/// Convert one TOML instrument row into the typed declaration, rejecting
/// unknown kinds/domains and domain/field mismatches at parse.
fn convert_instrument(t: TomlInstrument) -> Result<InstrumentDecl> {
    let ctx = |msg: String| Error::Module(format!("observability instrument '{}': {msg}", t.name));
    let kind = match t.kind.as_str() {
        "counter" => InstrumentKind::Counter,
        "updown" => InstrumentKind::UpDown,
        "histogram" => InstrumentKind::Histogram,
        "histogram16" => InstrumentKind::Histogram16,
        other => {
            return Err(ctx(format!(
                "unknown kind '{other}' (counter | updown | histogram | histogram16)"
            )))
        }
    };
    let mut dimensions = Vec::new();
    for d in t.dimension.unwrap_or_default() {
        let domain = match d.domain.as_str() {
            "numeric" => {
                if d.values.is_some() {
                    return Err(ctx(format!(
                        "dimension '{}': `values` belongs to domain = \"enum\"",
                        d.key
                    )));
                }
                DimDomain::Numeric {
                    max: d.max.ok_or_else(|| {
                        ctx(format!(
                            "dimension '{}': numeric domain requires `max`",
                            d.key
                        ))
                    })?,
                }
            }
            "enum" => {
                if d.max.is_some() {
                    return Err(ctx(format!(
                        "dimension '{}': `max` belongs to domain = \"numeric\"",
                        d.key
                    )));
                }
                DimDomain::Enum {
                    values: d.values.ok_or_else(|| {
                        ctx(format!(
                            "dimension '{}': enum domain requires `values`",
                            d.key
                        ))
                    })?,
                }
            }
            other => {
                return Err(ctx(format!(
                    "dimension '{}': unknown domain '{other}' (numeric | enum)",
                    d.key
                )))
            }
        };
        dimensions.push(DimensionDecl { key: d.key, domain });
    }
    Ok(InstrumentDecl {
        name: t.name,
        kind,
        bounds_us: t.bounds_us,
        dimensions,
    })
}

/// Structural validation for `[[observability.instrument]]` rows.
/// Vocabulary (semconv keys) is the lint's job; everything shape-shaped
/// fails here, at manifest load.
fn validate_instruments(obs: &Observability) -> Result<()> {
    let mut seen: Vec<&str> = Vec::new();
    for inst in &obs.instruments {
        let ctx =
            |msg: String| Error::Module(format!("observability instrument '{}': {msg}", inst.name));
        if !obs.metrics.iter().any(|m| m == &inst.name) {
            return Err(ctx(
                "not in the `metrics` list — the wire id is the name's position there, \
                 so a metadata row without a metrics entry has no id to describe"
                    .to_string(),
            ));
        }
        if seen.contains(&inst.name.as_str()) {
            return Err(ctx("declared twice".into()));
        }
        seen.push(&inst.name);
        let want = inst.kind.bound_count();
        if inst.bounds_us.len() != want {
            return Err(ctx(format!(
                "kind '{}' requires exactly {} `bounds_us` entries (buckets − 1), got {}",
                inst.kind.as_str(),
                want,
                inst.bounds_us.len()
            )));
        }
        if inst.bounds_us.windows(2).any(|w| w[0] >= w[1]) {
            return Err(ctx("`bounds_us` must be strictly ascending".into()));
        }
        let mut product: u64 = 1;
        for d in &inst.dimensions {
            let sz = d.domain.size();
            if sz == 0 {
                return Err(ctx(format!("dimension '{}' has an empty domain", d.key)));
            }
            match &d.domain {
                DimDomain::Enum { values } => {
                    let mut vs: Vec<&str> = values.iter().map(String::as_str).collect();
                    vs.sort_unstable();
                    if vs.windows(2).any(|w| w[0] == w[1]) {
                        return Err(ctx(format!("dimension '{}' repeats a value", d.key)));
                    }
                }
                DimDomain::Numeric { .. } => {}
            }
            product = product.saturating_mul(sz as u64);
        }
        if product > DIM_MAX_PRODUCT as u64 {
            return Err(ctx(format!(
                "declared dimension domains multiply to {product} series, over the                  {DIM_MAX_PRODUCT} the composite u16 index can carry;                  shrink a domain — cardinality is a declared resource bound"
            )));
        }
    }
    Ok(())
}

/// NEON / aarch64 intrinsic substrings that signal an
/// ISR-unsafe import. A Tier 1b/Tier 2 module (`isr_safe = true`,
/// `domain_exec_mode == 2 or 4`) hard-preempts the cooperative tier,
/// and the ISR is documented as scalar-only. If a module accidentally
/// pulls in a NEON intrinsic, restoring its NEON state on ISR
/// completion is the caller's job — and nothing in the runtime saves
/// the NEON file. A Tier 1b ISR that clobbers NEON would corrupt the
/// preempted cooperative thread's vector regs.
///
/// The substrings below cover the canonical NEON paths in `core::arch`:
///   * `core::arch::aarch64` — the `arm_neon` module re-exports
///   * `arm_neon::` — direct import of the intrinsic module
///   * `vqaddq_`, `vld1q_`, `vst1q_`, `vmlaq_`, etc. — common intrinsic
///     prefixes (`v[name][q]_[type]`). The `vld1q_`/`vst1q_` plus
///     `vqaddq_` triplet covers ~95% of real NEON use without a wide
///     false-positive surface.
const NEON_IMPORT_MARKERS: &[&str] = &[
    "core::arch::aarch64",
    "arm_neon::",
    "::vld1q_",
    "::vst1q_",
    "::vqaddq_",
    "::vaddq_",
    "::vmulq_",
    "::vmlaq_",
];

/// Scan a module source tree for NEON / aarch64 SIMD imports.
/// Returns `Ok(())` if no markers found, `Err` listing the offending
/// files otherwise. Designed to be called from the build path when
/// `manifest.isr_safe == true` so a module that claims ISR safety
/// can't quietly pull in NEON intrinsics.
///
/// The check is **substring-based and source-static** — it parses
/// `.rs` files under `src_root` and looks for the marker strings
/// in `NEON_IMPORT_MARKERS`. Inside a string literal or comment that
/// happens to mention the marker, the check will false-positive;
/// fix the source comment or split the literal in those cases. The
/// alternative (full Rust parsing) costs ~100× more for the same
/// signal.
pub fn check_isr_safe_no_neon(src_root: &Path) -> Result<()> {
    if !src_root.exists() {
        return Ok(());
    }
    let mut offenders: Vec<String> = Vec::new();
    walk_rs(src_root, &mut |path, source| {
        for marker in NEON_IMPORT_MARKERS {
            if source.contains(marker) {
                offenders.push(format!(
                    "{}: contains `{}` (NEON-marker substring)",
                    path.display(),
                    marker,
                ));
                break;
            }
        }
    });
    if offenders.is_empty() {
        Ok(())
    } else {
        Err(Error::Module(format!(
            "ISR-tier module declares `isr_safe = true` but its source imports NEON / \
             aarch64 SIMD intrinsics. Tier 1b/Tier 2 ISRs are scalar-only by contract \
             — NEON registers are not preserved across an ISR. Offending files:\n  {}",
            offenders.join("\n  "),
        )))
    }
}

/// Scan a module source tree for an actual `module_isr_entry` **export**
/// — the IRQ-context entry point a Tier 2 (IRQ-owned) module must
/// provide. Returns `Ok(())` if any `.rs` file under `src_root` defines
/// the symbol with an exportable signature, `Err` otherwise. Used by the
/// Tier 2 admission validator so a module placed in an `isr_owned`
/// domain that forgot to export `module_isr_entry` fails the graph build
/// rather than failing registration on the rig.
///
/// **The packer's ELF symbol table is the authoritative source of
/// truth** — it sets the `.fmod` isr_module header bit only when the
/// linked symbol is actually present, and the kernel loader fail-closes
/// at runtime (`isr_entry_fn = None` → admission refused, never
/// dispatches the cooperative `module_step` from IRQ context). This
/// source-static check is the *early, build-time mirror* of that gate;
/// its job is to catch the common mistake at validation time instead of
/// on the rig.
///
/// To avoid the false-admits a bare substring match would allow (the
/// name in a comment / string / a plain `fn module_isr_entry` with no
/// `#[no_mangle]`, which the linker would NOT export), the match
/// requires the real export shape on one logical declaration: a
/// `#[no_mangle]` / `#[unsafe(no_mangle)]` attribute on the signature
/// line or within the few preceding attribute lines, AND an
/// `extern "C" fn module_isr_entry` signature on that line.
///
/// `//` line comments are stripped before matching. Residual gaps the
/// source scan cannot see (a `#[cfg(...)]`-disabled definition, a
/// block-comment-spanned signature) are caught by the authoritative
/// packer/loader gate described above — the same tradeoff
/// `check_isr_safe_no_neon` carries.
pub fn check_module_exports_isr_entry(src_root: &Path) -> Result<()> {
    if !src_root.exists() {
        return Err(Error::Module(format!(
            "source tree {} does not exist — cannot verify the \
             `module_isr_entry` export",
            src_root.display(),
        )));
    }
    let mut found = false;
    walk_rs(src_root, &mut |_path, source| {
        if source_exports_isr_entry(source) {
            found = true;
        }
    });
    if found {
        Ok(())
    } else {
        Err(Error::Module(
            "its source tree exports no `module_isr_entry` — expected a \
             `#[no_mangle] pub extern \"C\" fn module_isr_entry(...)` \
             definition (a bare `fn module_isr_entry` without `#[no_mangle]` \
             would not be linked as an export)"
                .to_string(),
        ))
    }
}

/// Source-static test for a real `module_isr_entry` export in one `.rs`
/// file's text. See `check_module_exports_isr_entry` for the contract;
/// factored out so it is unit-testable in isolation.
///
/// Models Rust attribute attachment: a `#[no_mangle]` attribute attaches
/// to the *next item*. We carry a `pending_no_mangle` flag set by an
/// attribute line and cleared by the next code (item) line, so an
/// intervening `fn` consumes the attribute and a later bare
/// `fn module_isr_entry` does not steal it.
fn source_exports_isr_entry(source: &str) -> bool {
    let mut pending_no_mangle = false;
    for raw in source.lines() {
        // Strip a `//` line comment (conservative: only removes text, so
        // it can never manufacture a match). `///` / `//!` doc lines
        // collapse to empty and are treated as blank.
        let line = match raw.find("//") {
            Some(i) => &raw[..i],
            None => raw,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let has_no_mangle = line.contains("no_mangle");
        // The real export shape: `extern "C" fn module_isr_entry` with a
        // `no_mangle` attribute on this line or on a preceding attribute
        // line that hasn't been consumed by another item yet.
        if line.contains("extern \"C\"")
            && line.contains("fn module_isr_entry")
            && (has_no_mangle || pending_no_mangle)
        {
            return true;
        }
        if trimmed.starts_with("#[") || trimmed.starts_with("#![") {
            // Attribute line — accumulate `no_mangle`, leave any pending
            // flag from a sibling attribute (`#[cfg]` between
            // `#[no_mangle]` and the fn) intact.
            pending_no_mangle |= has_no_mangle;
        } else {
            // A code/item line consumes the pending attribute (it
            // attached to *this* item, whatever it was).
            pending_no_mangle = false;
        }
    }
    false
}

/// Walk `.rs` files under `root`, invoking `f(path, source)` for each.
/// Best-effort; unreadable files are skipped silently. Pure
/// directory traversal — no Cargo metadata, no symlink chasing.
fn walk_rs<F: FnMut(&Path, &str)>(root: &Path, f: &mut F) {
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, f);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            if let Ok(source) = std::fs::read_to_string(&path) {
                f(&path, &source);
            }
        }
    }
}

impl Manifest {
    /// Compute the required_caps bitmask from resource claims. Each
    /// declared contract id sets the corresponding bit in a u64; contract
    /// ids must fall in 0..63 to be expressible, the same range the kernel
    /// registers a vtable for (`MAX_CONTRACTS`). Non-contract permissions
    /// live in `self.permissions` and are serialised separately into
    /// manifest binary byte 15.
    pub fn required_caps_mask(&self) -> Result<u64> {
        let mut mask = 0u64;
        for r in &self.resources {
            if (r.device_class as usize) < CONTRACT_ID_SPACE {
                mask |= 1u64 << r.device_class;
            } else {
                return Err(Error::Module(format!(
                    "requires_contract {} (0x{:02x}) is outside the required_caps u64 range (bits 0..63).",
                    contract_name_to_str(r.device_class),
                    r.device_class,
                )));
            }
        }
        Ok(mask)
    }

    /// Look up a port by name. Returns (direction, index, content_type).
    pub fn find_port_by_name(&self, name: &str) -> Option<(u8, u8, u8)> {
        self.ports.iter().find_map(|p| {
            p.name
                .as_deref()
                .filter(|n| *n == name)
                .map(|_| (p.direction, p.index, p.content_type))
        })
    }

    /// Look up a port by direction and index. Returns content_type if found.
    /// Full port record by direction + resolved index.
    pub fn find_port_spec(&self, direction: u8, index: u8) -> Option<&PortSpec> {
        self.ports
            .iter()
            .find(|p| p.direction == direction && p.index == index)
    }

    pub fn find_port(&self, direction: u8, index: u8) -> Option<u8> {
        self.ports.iter().find_map(|p| {
            if p.direction == direction && p.index == index {
                Some(p.content_type)
            } else {
                None
            }
        })
    }

    /// Look up a module's source-tree manifest by type name. Returns
    /// `Ok(None)` if nothing matches; `Err` only on a parse failure of
    /// an existing file. Results are cached for the lifetime of the
    /// process — each module type is parsed at most once per
    /// invocation, including negative lookups.
    ///
    /// Search paths are the tier list (`MODULE_TIERS`), covering both
    /// PIC modules and kernel-resident built-ins (under
    /// `modules/platform/<platform>/<name>/`). See
    /// `docs/architecture/abi_layers.md` for what each tree is for.
    pub fn from_source_tree(module_type: &str) -> Result<Option<Self>> {
        static CACHE: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<String, Option<Manifest>>>,
        > = std::sync::OnceLock::new();
        let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
        if let Some(hit) = cache.lock().unwrap().get(module_type) {
            return Ok(hit.clone());
        }
        // Per-root manifest layouts, targeting a fluxor source tree
        // (modules/ at the root). Downstream projects reach these via
        // the install-root / sibling-checkout search roots below — the
        // published `fluxor-abi` source artifact ships `modules/sdk/**`
        // only, no per-platform manifests.
        const SOURCE_TREE_DIRS: &[&str] = MODULE_TIERS;

        // Search roots are walked in order:
        //   1. Project root (CWD-relative discovery via marker walk, or
        //      `$FLUXOR_PROJECT_ROOT` override).
        //   2. Install root (`$FLUXOR_INSTALL_ROOT` or exe-prefix
        //      derivation). Downstream consumers point this at a
        //      sibling fluxor checkout so builtin modules resolve
        //      without requiring a fully-synced registry.
        //   3. Bare CWD as the final fallback so existing call sites
        //      that ran from fluxor's repo root continue to work.
        //
        // Per root, source-tree layouts are checked first so a
        // colocated fluxor checkout wins over a synced SDK copy
        // (the source is newer than the published artefact during
        // active development).
        let mut search_roots: Vec<std::path::PathBuf> = Vec::new();
        let project = crate::project::root();
        search_roots.push(project.clone());
        if let Some(install) = crate::project::install_root() {
            if !search_roots.contains(&install.path) {
                search_roots.push(install.path);
            }
        }
        let cwd = std::env::current_dir().unwrap_or_default();
        if !search_roots.contains(&cwd) {
            search_roots.push(cwd);
        }
        // Sibling checkouts last, so an in-tree module always wins a name
        // clash. See `workspace::member_roots` for why this is a dev
        // convenience and not a resolution path anything shippable may rely on.
        for member in crate::workspace::member_roots(&project) {
            if !search_roots.contains(member) {
                search_roots.push(member.clone());
            }
        }

        let mut found: Option<Manifest> = None;
        'outer: for root in &search_roots {
            for dir in SOURCE_TREE_DIRS {
                let p = root.join(dir).join(module_type).join("manifest.toml");
                if p.exists() {
                    let m = Manifest::from_toml(&p)?;
                    found = Some(m);
                    break 'outer;
                }
            }
        }
        cache
            .lock()
            .unwrap()
            .insert(module_type.to_string(), found.clone());
        Ok(found)
    }

    /// Parse manifest from a TOML file.
    pub fn from_toml(path: &Path) -> Result<Self> {
        Self::from_toml_for_target(path, None)
    }

    /// Specialize this manifest to a named `[[variant]]`: ports listed
    /// in the variant's `omit_ports` are removed from the port table.
    /// Retained ports keep their already-resolved indices — omission
    /// leaves holes, never shifts, because module code addresses ports
    /// positionally. The filtered manifest is what gets embedded in the
    /// variant's fmod, making the artifact's advertised port surface
    /// honest.
    pub fn apply_variant(&mut self, variant: &str) -> Result<()> {
        let Some(decl) = self.variants.iter().find(|v| v.name == variant) else {
            let known: Vec<&str> = self.variants.iter().map(|v| v.name.as_str()).collect();
            return Err(Error::Module(if known.is_empty() {
                format!(
                    "variant '{variant}' requested but the manifest declares no [[variant]] table"
                )
            } else {
                format!(
                    "unknown variant '{variant}' — declared: {}",
                    known.join(", ")
                )
            }));
        };
        let omit = decl.omit_ports.clone();
        let omitted_caps = decl.omit_capabilities.clone();
        self.capabilities.retain(|c| !omitted_caps.contains(c));
        self.capability_facts
            .retain(|c, _| !omitted_caps.contains(c));
        self.ports.retain(|p| {
            p.name
                .as_deref()
                .is_none_or(|n| !omit.iter().any(|o| o == n))
        });
        Ok(())
    }

    /// Target-aware TOML load: per-target capacity tables resolve
    /// against `silicon` (falling back to their `default` key). A
    /// `None` silicon resolves `default` only.
    pub fn from_toml_for_target(path: &Path, silicon: Option<&str>) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Module(format!("cannot read {}: {}", path.display(), e)))?;
        // Name the manifest in every diagnostic: the module identity lives in
        // the path, not in the TOML, so a bare parse error would otherwise
        // leave the reader guessing which of ~40 manifests failed.
        Self::from_toml_str_for_target(&content, silicon)
            .map_err(|e| Error::Module(format!("{}: {e}", path.display())))
    }

    /// Parse a manifest from in-memory TOML bytes (already read), sharing
    /// every rule with `from_toml_for_target`. Lets callers resolve a
    /// manifest that never sits on disk — notably the `manifest.toml`
    /// layer of a pinned `[[artifact]]` module entry, which is fetched from
    /// the OCI store rather than a source tree.
    pub fn from_toml_str_for_target(content: &str, silicon: Option<&str>) -> Result<Self> {
        let toml_val: TomlManifest = toml::from_str(content)
            .map_err(|e| Error::Module(format!("invalid manifest TOML: {e}")))?;

        let (major, minor, patch) = parse_semver(&toml_val.version)?;
        let module_version = encode_semver(major, minor, patch);

        let hardware_target_names: Vec<String> = toml_val.hardware_targets.unwrap_or_default();
        let hardware_targets = if hardware_target_names.is_empty() {
            0x01
        } else {
            hardware_targets_from_list(&hardware_target_names)
        };

        let state_size_hint = toml_val.state_size_hint.unwrap_or(0);

        let mut ports = Vec::new();
        let mut port_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        // Track next auto-index per direction: [input, output, ctrl]
        let mut next_index = [0u8; 4];
        for p in toml_val.ports.unwrap_or_default() {
            let direction = direction_from_str(&p.direction)?;
            let content_type = content_type_from_str(&p.content_type)?;
            let mut flags = 0u8;
            if p.required.unwrap_or(false) {
                flags |= 0x01;
            }
            if p.framed.unwrap_or(false) {
                flags |= 0x02;
            }

            // Validate port name
            if let Some(ref name) = p.name {
                if name == "in" || name == "out" || name == "ctrl" {
                    return Err(Error::Module(format!(
                        "port name '{name}' is a reserved word"
                    )));
                }
                if !port_names.insert(name.clone()) {
                    return Err(Error::Module(format!("duplicate port name '{name}'")));
                }
            }

            // Resolve port index
            let dir_idx = direction as usize;
            let index = if let Some(idx) = p.index {
                // Explicit index — advance auto-index past it
                if idx >= next_index[dir_idx] {
                    next_index[dir_idx] = idx + 1;
                }
                idx
            } else {
                let idx = next_index[dir_idx];
                next_index[dir_idx] = idx + 1;
                idx
            };

            ports.push(PortSpec {
                direction,
                content_type,
                flags,
                name: p.name,
                index,
                buffer_size: match &p.buffer_size {
                    Some(v) => v.resolve(silicon, "buffer_size")?,
                    None => 0,
                },
                max_record: match &p.max_record {
                    Some(v) => v.resolve(silicon, "max_record")?,
                    None => 0,
                },
                rate_class_max: match &p.rate_class_max {
                    Some(r) => {
                        Some(fluxor_contracts::RateClass::from_str_opt(r).ok_or_else(|| {
                            Error::Module(format!(
                                "unknown rate_class_max '{r}' \
                                 (control | transaction | audio | video | bulk)"
                            ))
                        })?)
                    }
                    None => None,
                },
                rate_class_default: match &p.rate_class_default {
                    Some(r) => {
                        Some(fluxor_contracts::RateClass::from_str_opt(r).ok_or_else(|| {
                            Error::Module(format!(
                                "unknown rate_class_default '{r}' \
                                 (control | transaction | audio | video | bulk)"
                            ))
                        })?)
                    }
                    None => None,
                },
                requires_capability: match &p.requires_capability {
                    Some(c) => Some(canonical_capability(c, "requires_capability")?),
                    None => None,
                },
            });
        }

        let mut resources = Vec::new();
        for r in toml_val.resources.unwrap_or_default() {
            let cid = contract_id_from_name(&r.device_class)?;
            let access_mode = access_mode_from_str(&r.access)?;
            let instance = r.instance.unwrap_or(0xFF);
            resources.push(ResourceClaim {
                device_class: cid,
                access_mode,
                instance,
            });
        }

        let mut permissions = ManifestPermissions::default();
        for name in toml_val.permissions.unwrap_or_default() {
            match permission::from_name(&name) {
                Some(bit) => permissions.bits |= bit,
                None => {
                    return Err(Error::Module(format!(
                        "unknown permission: {name} — expected one of: reconfigure, \
                         flash_raw, backing_provider, platform_raw, monitor, bridge \
                         (see docs/architecture/abi_layers.md)",
                    )));
                }
            }
        }

        let mut dependencies = Vec::new();
        for d in toml_val.dependencies.unwrap_or_default() {
            let name_hash = fnv1a_hash(d.name.as_bytes());
            let min_version = if let Some(v) = d.min_version {
                let (maj, min, pat) = parse_semver(&v)?;
                encode_semver(maj, min, pat)
            } else {
                0
            };
            dependencies.push(Dependency {
                name_hash,
                min_version,
            });
        }

        let commands = if let Some(cmds) = toml_val.commands {
            CommandVocabulary {
                accepts: cmds.accepts.unwrap_or_default(),
                emits: cmds.emits.unwrap_or_default(),
            }
        } else {
            CommandVocabulary::default()
        };

        let provides = toml_val.provides.unwrap_or_default();
        validate_provides_names(&provides)?;
        let mut capabilities = toml_val.capabilities.unwrap_or_default();
        validate_capability_names(&mut capabilities)?;
        let capability_facts = normalise_capability_facts(toml_val.capability_facts)?;
        let required_caps: Vec<String> = ports
            .iter()
            .filter_map(|p| p.requires_capability.clone())
            .collect();
        validate_capability_facts(&capability_facts, &capabilities, &required_caps)?;
        let requires_when = validate_requires_when(toml_val.requires_when.unwrap_or_default())?;

        let observability = match toml_val.observability {
            None => Observability::default(),
            Some(o) => {
                let mut instruments = Vec::new();
                for i in o.instrument.unwrap_or_default() {
                    instruments.push(convert_instrument(i)?);
                }
                let obs = Observability {
                    metrics: o.metrics,
                    spans: o.spans,
                    exempt: o.exempt,
                    instruments,
                };
                validate_instruments(&obs)?;
                obs
            }
        };

        let builtin = toml_val.builtin.unwrap_or(false);

        let raw_params = toml_val.params.unwrap_or_default();
        // `[[params]]` belongs to built-ins. PIC (`.fmod`) modules carry
        // their schema in the binary via the `define_params!` macro;
        // declaring it again in the manifest would create two sources
        // of truth for the same wire layout.
        if !builtin && !raw_params.is_empty() {
            return Err(Error::Module(format!(
                "[[params]] is only valid on built-in modules (`builtin = true`). \
                 PIC modules embed their schema via `define_params!`. \
                 Got {} param(s) on a non-builtin manifest.",
                raw_params.len(),
            )));
        }

        let mut params: Vec<ManifestParam> = Vec::new();
        for p in raw_params {
            // The tag is the parameter's wire identity, so it is declared,
            // never derived from declaration position: reordering or
            // inserting an entry must not re-point a shipped encoding.
            let tag = p.tag.ok_or_else(|| {
                Error::Module(format!(
                    "param '{}': missing `tag = N`. Built-in parameter tags \
                     are explicit and permanent — pick an unused value in \
                     {PARAM_TAG_MIN}..={PARAM_TAG_MAX} and never reuse a \
                     retired one.",
                    p.name,
                ))
            })?;
            if !(PARAM_TAG_MIN..=PARAM_TAG_MAX).contains(&tag) {
                return Err(Error::Module(format!(
                    "param '{}': tag {tag} out of range \
                     ({PARAM_TAG_MIN}..={PARAM_TAG_MAX}). Tags below \
                     {PARAM_TAG_MIN} belong to the TLV framing and \
                     0xF0..=0xFF are reserved for protection metadata.",
                    p.name,
                )));
            }
            if let Some(prev) = params.iter().find(|q: &&ManifestParam| q.tag == tag) {
                return Err(Error::Module(format!(
                    "param '{}': tag {tag} is already claimed by param '{}'. \
                     Each built-in parameter needs its own tag — two entries \
                     sharing one tag collide on the wire.",
                    p.name, prev.name,
                )));
            }
            let ptype = match p.ptype.as_str() {
                "u8" => ManifestParamType::U8,
                "u16" => ManifestParamType::U16,
                "u32" => ManifestParamType::U32,
                "str" | "string" => ManifestParamType::Str,
                "enum" => ManifestParamType::Enum,
                other => {
                    return Err(Error::Module(format!(
                        "param '{}': unknown type '{}' (expected: u8, u16, u32, str, enum)",
                        p.name, other,
                    )));
                }
            };

            // Enum: values list is required; each name maps to its index.
            let mut enum_values: Vec<(String, u8)> = Vec::new();
            if ptype == ManifestParamType::Enum {
                let vals = p.values.as_ref().ok_or_else(|| {
                    Error::Module(format!(
                        "param '{}': enum requires `values = [...]`",
                        p.name
                    ))
                })?;
                if vals.is_empty() || vals.len() > 256 {
                    return Err(Error::Module(format!(
                        "param '{}': enum needs 1..=256 values",
                        p.name
                    )));
                }
                for (j, v) in vals.iter().enumerate() {
                    enum_values.push((v.clone(), j as u8));
                }
            } else if p.values.is_some() {
                return Err(Error::Module(format!(
                    "param '{}': `values` only applies to type='enum'",
                    p.name
                )));
            }

            // Resolve default. Numeric types accept integers; str/enum
            // accept strings (enum default must be one of `values`).
            let mut default_num: u32 = 0;
            let mut default_str = String::new();
            match (&ptype, p.default.as_ref()) {
                (
                    ManifestParamType::U8 | ManifestParamType::U16 | ManifestParamType::U32,
                    Some(v),
                ) => {
                    let n = v.as_integer().ok_or_else(|| {
                        Error::Module(format!("param '{}': default must be an integer", p.name))
                    })?;
                    if n < 0 {
                        return Err(Error::Module(format!(
                            "param '{}': default must be non-negative",
                            p.name
                        )));
                    }
                    default_num = n as u32;
                }
                (ManifestParamType::Str, Some(v)) => {
                    let s = v.as_str().ok_or_else(|| {
                        Error::Module(format!("param '{}': default must be a string", p.name))
                    })?;
                    default_str = s.to_string();
                }
                (ManifestParamType::Enum, Some(v)) => {
                    let s = v.as_str().ok_or_else(|| {
                        Error::Module(format!(
                            "param '{}': default must be one of {:?}",
                            p.name,
                            enum_values.iter().map(|(n, _)| n).collect::<Vec<_>>(),
                        ))
                    })?;
                    let (_, val) = enum_values.iter().find(|(n, _)| n == s).ok_or_else(|| {
                        Error::Module(format!(
                            "param '{}': default '{}' is not in values {:?}",
                            p.name,
                            s,
                            enum_values.iter().map(|(n, _)| n).collect::<Vec<_>>(),
                        ))
                    })?;
                    default_num = *val as u32;
                    default_str = s.to_string();
                }
                (_, None) => {} // no default — zero / empty
            }

            // Validate range bounds.
            let range = if let Some([min, max]) = p.range {
                if matches!(ptype, ManifestParamType::Str | ManifestParamType::Enum) {
                    return Err(Error::Module(format!(
                        "param '{}': `range` only applies to numeric types",
                        p.name
                    )));
                }
                if min > max {
                    return Err(Error::Module(format!(
                        "param '{}': range min ({}) > max ({})",
                        p.name, min, max
                    )));
                }
                Some((min, max))
            } else {
                None
            };

            // A `required` param must not also carry a `default` — that
            // would be contradictory. Catch the schema error early.
            if p.required && p.default.is_some() {
                return Err(Error::Module(format!(
                    "param '{}': `required = true` and `default` are mutually exclusive",
                    p.name
                )));
            }

            params.push(ManifestParam {
                tag,
                name: p.name,
                ptype,
                default_num,
                default_str,
                enum_values,
                range,
                required: p.required,
            });
        }

        let timer_class = match toml_val.timer_class.as_deref() {
            // Absent ⇒ Unattested (fail-closed on mechanism (b); see TimerClass).
            None => TimerClass::Unattested,
            Some(s) => TimerClass::from_str_opt(s).ok_or_else(|| {
                Error::Module(format!(
                    "manifest timer_class=\"{s}\" is invalid; expected one of \
                     agnostic | wall_clock | tick_counted | guaranteed"
                ))
            })?,
        };

        // step_period_ticks is the module ABI header byte 1 (0..=255). Range-check
        // here so an out-of-byte value is a clear manifest error, not a silent
        // truncation when wired into the header by pack_fmod.
        let step_period_ticks = match toml_val.step_period_ticks {
            None => 0u8,
            Some(n) if n <= u8::MAX as u64 => n as u8,
            Some(n) => {
                return Err(Error::Module(format!(
                    "manifest step_period_ticks={n} out of range; the ABI field is \
                     a single byte (0..=255). 0 = every tick."
                )));
            }
        };

        let execution = match toml_val.execution {
            None => None,
            Some(e) => Some(e.validate(&hardware_target_names)?),
        };

        // `[[variant]]` table. Validated here so a malformed table fails
        // the build loudly rather than surfacing as a missing artifact at
        // packaging.
        let mut variants: Vec<VariantDecl> = Vec::new();
        if let Some(raw_variants) = toml_val.variant {
            let port_names: std::collections::BTreeSet<&str> =
                ports.iter().filter_map(|p| p.name.as_deref()).collect();
            let mut default_count = 0usize;
            let mut seen = std::collections::BTreeSet::new();
            for v in &raw_variants {
                if v.name.is_empty()
                    || !v
                        .name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    return Err(Error::Module(format!(
                        "variant name '{}' invalid — ascii alphanumeric/underscore only \
                         (it becomes part of the artifact filename)",
                        v.name
                    )));
                }
                if !seen.insert(v.name.as_str()) {
                    return Err(Error::Module(format!(
                        "duplicate variant name '{}'",
                        v.name
                    )));
                }
                if v.features.is_none() {
                    return Err(Error::Module(format!(
                        "variant '{}' declares no features — a variant is a feature \
                         set; write `features = []` explicitly for a deliberate \
                         base-surface-only variant",
                        v.name
                    )));
                }
                if v.default {
                    default_count += 1;
                }
                for capability in &v.omit_capabilities {
                    if !capabilities.contains(capability) {
                        return Err(Error::Module(format!(
                            "variant '{}' omits unknown capability '{}'",
                            v.name, capability
                        )));
                    }
                }
                for op in &v.omit_ports {
                    if !port_names.contains(op.as_str()) {
                        return Err(Error::Module(format!(
                            "variant '{}' omits unknown port '{}' — declared ports: {}",
                            v.name,
                            op,
                            port_names.iter().copied().collect::<Vec<_>>().join(", ")
                        )));
                    }
                }
            }
            if default_count != 1 {
                return Err(Error::Module(format!(
                    "a [[variant]] table needs exactly one `default = true` entry \
                     (found {default_count}) — the default names which feature set \
                     the unsuffixed <module>.fmod carries"
                )));
            }
            variants = raw_variants
                .into_iter()
                .map(|v| VariantDecl {
                    name: v.name,
                    features: v.features.unwrap_or_default(),
                    default: v.default,
                    omit_ports: v.omit_ports,
                    omit_capabilities: v.omit_capabilities,
                })
                .collect();
        }

        // Module-scope capacities resolve against the same silicon the port
        // capacities do, so one manifest read yields every bound the build
        // needs for this target.
        let mut capacities = std::collections::BTreeMap::new();
        for (name, value) in toml_val.capacities.unwrap_or_default() {
            let resolved = value.resolve(silicon, &format!("capacities.{name}"))?;
            capacities.insert(name, resolved);
        }

        let build = toml_val.build.unwrap_or_default();
        let wasm_opt_level = build.wasm_opt_level;
        let opt_level = build.opt_level;
        for level in [&wasm_opt_level, &opt_level].into_iter().flatten() {
            validate_wasm_opt_level(level)?;
        }

        Ok(Manifest {
            module_version,
            hardware_targets,
            state_size_hint,
            ports,
            resources,
            permissions,
            dependencies,
            integrity_hash: None, // set later by caller
            abi_surface: None,    // set by pack (attests the packing tree)
            signature: None,
            signer_fp: None,
            commands,
            provides,
            capability_facts,
            capabilities,
            observability,
            builtin,
            variants,
            capacities,
            isr_safe: toml_val.isr_safe,
            resume_after_fault: toml_val.resume_after_fault,
            pre_tick_drain: toml_val.pre_tick_drain,
            requires: toml_val.requires,
            requires_when,
            wasm_opt_level,
            opt_level,
            params,
            timer_class,
            step_period_ticks,
            execution,
        })
    }

    /// Serialize manifest to binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let has_integrity = self.integrity_hash.is_some();
        let has_signature = self.signature.is_some() && self.signer_fp.is_some();
        // Signature requires integrity (signature is over the hash).
        let has_signature = has_signature && has_integrity;
        let has_abi_surface = self.abi_surface.is_some();
        // Port-capacity section (flag bit 5): 8 bytes per port
        // [buffer_size u32 LE][max_record u32 LE], emitted directly
        // after the dependency records so it sits INSIDE the signed
        // envelope region ([15..hash_offset]) — ring capacities are
        // load-bearing metadata (a tampered max_record wedges a graph).
        let has_port_capacity = self
            .ports
            .iter()
            .any(|p| p.buffer_size != 0 || p.max_record != 0);
        let var_size = self.ports.len() * 4
            + self.resources.len() * 4
            + self.dependencies.len() * 8
            + if has_port_capacity {
                self.ports.len() * 8
            } else {
                0
            }
            + if has_integrity { 32 } else { 0 }
            + if has_signature {
                SIGNATURE_BLOCK_SIZE
            } else {
                0
            }
            + if has_abi_surface { 32 } else { 0 };
        let total = MANIFEST_HEADER_SIZE + var_size;
        let mut buf = Vec::with_capacity(total);

        // Header (16 bytes). Signed and unsigned manifests share the
        // same port-record layout; signature presence is signalled by
        // flag bit 1 (byte 14), not by a version split.
        buf.extend_from_slice(&MANIFEST_MAGIC.to_le_bytes());
        buf.push(MANIFEST_VERSION);
        buf.push(self.ports.len() as u8);
        buf.push(self.resources.len() as u8);
        buf.push(self.dependencies.len() as u8);
        buf.extend_from_slice(&self.module_version.to_le_bytes());
        buf.extend_from_slice(&self.hardware_targets.to_le_bytes());
        buf.extend_from_slice(&self.state_size_hint.to_le_bytes());
        // byte 14: bit 0 = has_integrity, bit 1 = has_signature,
        //          bit 2 = isr_safe (author attestation; the
        //                  **build-time** `validate_isr_tier_admission`
        //                  in `tools/src/config.rs` is the live gate
        //                  for this flag. Tier 1b and Tier 2 admission
        //                  are both live (Tier 2 additionally requires
        //                  an `irq:` field + a `module_isr_entry`
        //                  export — see `check_module_exports_isr_entry`
        //                  and the loader's `isr_entry_fn`). The kernel-side
        //                  `Manifest::from_bytes` round-trips the
        //                  bit through `LoadedModule.manifest`, but
        //                  the loader does NOT currently re-check it
        //                  at instantiation — the runtime gate today
        //                  is the EACCES check on every gated
        //                  syscall (`scheduler::deny_isr_tier_syscall`).
        //                  A loader-side defense-in-depth check that
        //                  mirrors the build-time one would still be
        //                  worth adding for hand-rolled binaries.
        //          bit 3 = pre_tick_drain (Tier 1c opt-in).
        //                  Read by `prepare_graph` to populate
        //                  `domain_pre_tick_order` and exclude the
        //                  module from `domain_exec_order`.
        //          bits 4-7: reserved (0).
        let flags = (if has_integrity { 1 } else { 0 })
            | (if has_signature { 2 } else { 0 })
            | (if self.isr_safe { 4 } else { 0 })
            | (if self.pre_tick_drain { 8 } else { 0 })
            | (if has_abi_surface { 0x10 } else { 0 })
            | (if has_port_capacity { 0x20 } else { 0 });
        buf.push(flags);
        // byte 15: fine-grained permissions bitmap (see `permission::*`).
        // The kernel reads this byte directly at module instantiation.
        buf.extend_from_slice(&self.permissions.bits.to_le_bytes());

        // Ports (4 bytes each: direction, content_type, flags, index).
        // Byte 3 is the per-direction port index (0..15) the TOML
        // resolver computed in `parse_toml` — manifests may pin
        // explicit indices via `index = N`, so the binary must carry
        // the resolved value rather than re-derive it from source
        // order on the read side.
        for p in &self.ports {
            buf.push(p.direction);
            buf.push(p.content_type);
            buf.push(p.flags);
            buf.push(p.index);
        }

        // Resources (4 bytes each)
        for r in &self.resources {
            buf.push(r.device_class);
            buf.push(r.access_mode);
            buf.push(r.instance);
            buf.push(0);
        }

        // Dependencies (8 bytes each)
        for d in &self.dependencies {
            buf.extend_from_slice(&d.name_hash.to_le_bytes());
            buf.extend_from_slice(&d.min_version.to_le_bytes());
            buf.push(0);
            buf.push(0);
        }

        // Port-capacity section (flag bit 5): one 8-byte entry per port,
        // in port-record order.
        if has_port_capacity {
            for p in &self.ports {
                buf.extend_from_slice(&p.buffer_size.to_le_bytes());
                buf.extend_from_slice(&p.max_record.to_le_bytes());
            }
        }

        // Integrity hash (32 bytes)
        if let Some(hash) = &self.integrity_hash {
            buf.extend_from_slice(hash);
        }

        // Signature block (64 B sig + 32 B signer fingerprint). Only emitted
        // when both present *and* the integrity hash is set (signature is
        // over that hash).
        if has_signature {
            buf.extend_from_slice(self.signature.as_ref().unwrap());
            buf.extend_from_slice(self.signer_fp.as_ref().unwrap());
        }

        // ABI-surface attestation (32 bytes), LAST — appended after every
        // block the kernel computes offsets over, so the loader's
        // integrity/signature offset math is untouched.
        if let Some(d) = &self.abi_surface {
            buf.extend_from_slice(d);
        }

        debug_assert_eq!(buf.len(), total);
        buf
    }

    /// Deserialize manifest from binary.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < MANIFEST_HEADER_SIZE {
            return Err(Error::Module(format!(
                "manifest too small: {} bytes",
                data.len()
            )));
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != MANIFEST_MAGIC {
            return Err(Error::Module(format!(
                "invalid manifest magic: 0x{magic:08x}"
            )));
        }

        let version = data[4];
        if version != MANIFEST_VERSION {
            return Err(Error::Module(format!(
                "unsupported manifest version: {version}"
            )));
        }

        let port_count = data[5] as usize;
        let resource_count = data[6] as usize;
        let dependency_count = data[7] as usize;
        let module_version = u16::from_le_bytes([data[8], data[9]]);
        let hardware_targets = u16::from_le_bytes([data[10], data[11]]);
        let state_size_hint = u16::from_le_bytes([data[12], data[13]]);
        let flags = data[14];
        let has_integrity = (flags & 0x01) != 0;
        let has_signature = (flags & 0x02) != 0;
        let isr_safe = (flags & 0x04) != 0;
        let pre_tick_drain = (flags & 0x08) != 0;
        let has_abi_surface = (flags & 0x10) != 0;
        let has_port_capacity = (flags & 0x20) != 0;
        let permissions_bits = u16::from_le_bytes([data[15], data[16]]); // fine-grained permissions bitmap (bytes 15..17)

        let expected_size = MANIFEST_HEADER_SIZE
            + port_count * 4
            + resource_count * 4
            + dependency_count * 8
            + if has_port_capacity { port_count * 8 } else { 0 }
            + if has_integrity { 32 } else { 0 }
            + if has_signature {
                SIGNATURE_BLOCK_SIZE
            } else {
                0
            }
            + if has_abi_surface { 32 } else { 0 };

        // EXACT size, not a lower bound: the serializer emits exact sizes,
        // so slack is at best corruption and at worst a substitution attack
        // (a second attestation appended past the canonical offset, aimed at
        // a verifier that reads from the other end). Both this parser and
        // the kernel verifier reject slack.
        if data.len() != expected_size {
            return Err(Error::Module(format!(
                "manifest size mismatch: {} bytes, layout requires exactly {}",
                data.len(),
                expected_size
            )));
        }

        let mut offset = MANIFEST_HEADER_SIZE;

        let mut ports = Vec::with_capacity(port_count);
        for _ in 0..port_count {
            ports.push(PortSpec {
                direction: data[offset],
                content_type: data[offset + 1],
                flags: data[offset + 2],
                name: None,
                index: data[offset + 3],
                buffer_size: 0,
                max_record: 0,
                rate_class_max: None,
                rate_class_default: None,
                requires_capability: None,
            });
            offset += 4;
        }

        let mut resources = Vec::with_capacity(resource_count);
        for _ in 0..resource_count {
            resources.push(ResourceClaim {
                device_class: data[offset],
                access_mode: data[offset + 1],
                instance: data[offset + 2],
            });
            offset += 4;
        }

        let mut dependencies = Vec::with_capacity(dependency_count);
        for _ in 0..dependency_count {
            let name_hash = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let min_version = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
            dependencies.push(Dependency {
                name_hash,
                min_version,
            });
            offset += 8;
        }

        // Port-capacity section (flag bit 5), in port-record order.
        if has_port_capacity {
            for port in ports.iter_mut() {
                port.buffer_size = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                port.max_record = u32::from_le_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                offset += 8;
            }
        }

        let integrity_hash = if has_integrity {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            Some(hash)
        } else {
            None
        };

        let (signature, signer_fp) = if has_signature {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&data[offset..offset + 64]);
            offset += 64;
            let mut fp = [0u8; 32];
            fp.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            (Some(sig), Some(fp))
        } else {
            (None, None)
        };

        let abi_surface = if has_abi_surface {
            let mut d = [0u8; 32];
            d.copy_from_slice(&data[offset..offset + 32]);
            Some(d)
        } else {
            None
        };

        Ok(Manifest {
            module_version,
            hardware_targets,
            state_size_hint,
            ports,
            resources,
            permissions: ManifestPermissions {
                bits: permissions_bits,
            },
            dependencies,
            integrity_hash,
            abi_surface,
            signature,
            signer_fp,
            commands: CommandVocabulary::default(),
            provides: Vec::new(), // not serialized in binary format
            capability_facts: std::collections::BTreeMap::new(), // not serialized
            capabilities: Vec::new(), // not serialized in binary format
            observability: Observability::default(), // not serialized in binary format
            builtin: false,
            variants: Vec::new(), // toml-only, not serialized
            capacities: std::collections::BTreeMap::new(), // toml-only, not serialized
            isr_safe,
            // Author attestation, TOML-only: a binary-loaded manifest makes
            // no claim, so `fault_policy: restart` is refused (fail-closed).
            resume_after_fault: false,
            pre_tick_drain,
            // `requires` is a TOML-only field — modules carry their
            // binary manifest stripped of the requires block (it's a
            // build-time concern, not a runtime one). Round-tripping
            // through the binary loses it; that's intentional.
            requires: TomlRequires::default(),
            requires_when: Vec::new(), // toml-only, not serialized
            wasm_opt_level: None,      // toml-only, not serialized
            opt_level: None,           // toml-only, not serialized
            params: Vec::new(),        // toml-only, not serialized
            // timer_class is a TOML-only build-time concern (drives the config
            // validator's adaptive-tick gate); not serialized into the binary, so
            // a binary-loaded manifest is Unattested (fail-closed) by default.
            timer_class: TimerClass::Unattested,
            // step_period_ticks lives in the module ABI HEADER (byte 1), not the
            // manifest binary parsed here; a manifest-only load defaults to 0.
            step_period_ticks: 0,
            // Timing facts are compose-time evidence, TOML-only: a
            // binary-loaded manifest claims no envelope.
            execution: None,
        })
    }

    /// Display manifest contents for info/debug output.
    pub fn display(&self) -> String {
        let (major, minor, patch) = decode_semver(self.module_version);
        let mut lines = vec![
            format!("  version: {}.{}.{}", major, minor, patch),
            format!("  hardware_targets: 0x{:04x}", self.hardware_targets),
            match self.required_caps_mask() {
                Ok(m) => format!("  required_caps: 0x{m:016x}"),
                Err(e) => format!("  required_caps: <error: {e}>"),
            },
        ];
        if self.state_size_hint > 0 {
            lines.push(format!("  state_size_hint: {} bytes", self.state_size_hint));
        }
        if !self.ports.is_empty() {
            lines.push("  ports:".into());
            for p in &self.ports {
                let req = if p.flags & 0x01 != 0 {
                    " (required)"
                } else {
                    ""
                };
                let name_str = p.name.as_deref().unwrap_or("-");
                lines.push(format!(
                    "    {}[{}] {} ({}){}",
                    direction_to_str(p.direction),
                    p.index,
                    name_str,
                    content_type_to_str(p.content_type),
                    req,
                ));
            }
        }
        if !self.resources.is_empty() {
            lines.push("  resources:".into());
            for r in &self.resources {
                if r.instance != 0xFF {
                    lines.push(format!(
                        "    {}[{}] ({})",
                        contract_name_to_str(r.device_class),
                        r.instance,
                        access_mode_to_str(r.access_mode),
                    ));
                } else {
                    lines.push(format!(
                        "    {} ({})",
                        contract_name_to_str(r.device_class),
                        access_mode_to_str(r.access_mode),
                    ));
                }
            }
        }
        if self.permissions.bits != 0 {
            lines.push(format!(
                "  permissions: [{}]",
                permission::names(self.permissions.bits).join(", ")
            ));
        }
        if !self.dependencies.is_empty() {
            lines.push("  dependencies:".into());
            for d in &self.dependencies {
                let (maj, min, pat) = decode_semver(d.min_version);
                lines.push(format!(
                    "    hash=0x{:08x} min={}.{}.{}",
                    d.name_hash, maj, min, pat,
                ));
            }
        }
        if !self.commands.accepts.is_empty() || !self.commands.emits.is_empty() {
            lines.push("  commands:".into());
            if !self.commands.accepts.is_empty() {
                lines.push(format!(
                    "    accepts: [{}]",
                    self.commands.accepts.join(", ")
                ));
            }
            if !self.commands.emits.is_empty() {
                lines.push(format!("    emits: [{}]", self.commands.emits.join(", ")));
            }
        }
        if let Some(hash) = &self.integrity_hash {
            let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
            lines.push(format!("  integrity: sha256:{hex}"));
        }
        lines.join("\n")
    }
}

/// Compute SHA-256 integrity hash over code and data sections.
pub fn compute_integrity(code: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(code);
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ── TOML deserialization structs ────────────────────────────────────────────

// deny_unknown_fields: a typo'd key in a [[variant]] row (`omit_port`,
// `feature`) silently ignored would ship a variant with the wrong port
// surface or feature set — reject loudly instead.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlVariant {
    name: String,
    /// `Option` so a FORGOTTEN `features` key stays an error while an
    /// explicit `features = []` declares a legitimate base-surface-only
    /// variant (e.g. `otel-min`: the fxtl path with no OTLP encoder).
    features: Option<Vec<String>>,
    #[serde(default)]
    default: bool,
    #[serde(default)]
    omit_ports: Vec<String>,
    #[serde(default)]
    omit_capabilities: Vec<String>,
}

#[derive(Deserialize, Default)]
struct TomlObservability {
    #[serde(default)]
    metrics: Vec<String>,
    #[serde(default)]
    spans: Vec<String>,
    exempt: Option<String>,
    /// `[[observability.instrument]]` metadata rows.
    instrument: Option<Vec<TomlInstrument>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlInstrument {
    name: String,
    kind: String,
    #[serde(default)]
    bounds_us: Vec<u64>,
    /// `[[observability.instrument.dimension]]` rows, composite-index order.
    dimension: Option<Vec<TomlDimension>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlDimension {
    key: String,
    domain: String,
    /// `domain = "numeric"`: values are 0..max.
    max: Option<u32>,
    /// `domain = "enum"`: the declared value set, index = declared position.
    values: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct TomlManifest {
    version: String,
    hardware_targets: Option<Vec<String>>,
    state_size_hint: Option<u16>,
    ports: Option<Vec<TomlPort>>,
    resources: Option<Vec<TomlResource>>,
    /// Top-level `permissions = ["reconfigure", "flash_raw", …]` list —
    /// fine-grained non-contract permission categories. Distinct from
    /// `[[resources]]` (which is for public contract access).
    permissions: Option<Vec<String>>,
    dependencies: Option<Vec<TomlDependency>>,
    commands: Option<TomlCommands>,
    provides: Option<Vec<String>>,
    /// Role/surface capability strings. Whitelisted by
    /// `CAPABILITY_NAMES`; validated and canonicalized at parse time.
    capabilities: Option<Vec<String>>,
    /// `[observability]` table — instrument names this module emits.
    observability: Option<TomlObservability>,
    /// Module is built into the kernel (no .fmod file needed).
    builtin: Option<bool>,
    /// `[[variant]]` feature-set variants.
    variant: Option<Vec<TomlVariant>>,
    /// `[capacities]` table — module-scope capacity declarations, each a
    /// flat number or a per-silicon table exactly like a port's
    /// `buffer_size`. Use it for a bound the module compiles in AND the
    /// build tooling has to respect, so the two can't drift.
    capacities: Option<std::collections::BTreeMap<String, CapacityValue>>,
    /// `[capability_facts."<capability>"]` tables — the terms on which this
    /// module offers a capability it declares (`ack`, `ordering`,
    /// `max_payload`, …). Schema and admitted values live in
    /// `fluxor_contracts::vocabulary::CAPABILITY_FACTS`.
    /// Values are read as raw TOML so a numeric fact may be written
    /// naturally (`max_payload = 4096`) or as a string (`"4096"`); both
    /// normalise to the same stored form.
    capability_facts:
        Option<std::collections::BTreeMap<String, std::collections::BTreeMap<String, toml::Value>>>,
    /// Author attests ISR-safety. Required for Tier 1b/2 admission.
    /// See `Manifest::isr_safe` for the contract.
    #[serde(default)]
    isr_safe: bool,
    /// Author attests the module can resume after an arbitrary fault.
    /// Required for `fault_policy: restart`. See
    /// `Manifest::resume_after_fault` for the contract.
    #[serde(default)]
    resume_after_fault: bool,
    /// Author opts the module into the Tier 1c pre-pass drain slot.
    /// See `Manifest::pre_tick_drain` for the contract.
    #[serde(default)]
    pre_tick_drain: bool,
    /// Hardware-feature requirements. Validated at config time
    /// against the resolved target's capability matrix. A module that
    /// declares `requires.fpu = true` is rejected from a target without
    /// FPU support (RP2040). Default-all-false means "no specific
    /// requirements," which satisfies every silicon.
    #[serde(default)]
    requires: TomlRequires,
    /// `[[requires_when]]` — a target-provided capability this module needs
    /// only under one of its own parameter values. See `RequiresWhen`.
    requires_when: Option<Vec<TomlRequiresWhen>>,
    /// `[[params]]` declarations — built-in modules only. PIC modules
    /// embed schema in their .fmod and these are ignored.
    params: Option<Vec<TomlParam>>,
    /// `timer_class = "agnostic"|"wall_clock"|"tick_counted"|"guaranteed"` —
    /// how the module's timekeeping relates to the scheduler tick. Absent ⇒
    /// `Unattested` (fail-closed on mechanism (b)). See `TimerClass`.
    timer_class: Option<String>,
    /// `step_period_ticks = N` — coarse-step period: run this module every N
    /// scheduler ticks (0/absent = every tick). Wired into ABI header byte 1.
    /// A non-zero value is tick-counted, so the adaptive validator blocks it
    /// on a mechanism-(b) domain unless `timer_class = "wall_clock"`.
    #[serde(default)]
    step_period_ticks: Option<u64>,
    /// `[build]` table — per-module build knobs.
    build: Option<TomlBuild>,
    /// `[execution]` table — step / dispatch cost facts and their profile.
    /// See `ExecutionEnvelope`.
    execution: Option<TomlExecution>,
}

/// `[execution]` manifest table as written. Every field is optional at the
/// TOML layer so the validator, not serde, names what is missing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlExecution {
    max_step_us: Option<u64>,
    max_dispatch_us: Option<u64>,
    profile: Option<String>,
    evidence: Option<String>,
}

impl TomlExecution {
    /// Check the block against its contract and the step budget of every
    /// silicon the module targets (`target_facts::TargetFacts::step_budget_us`).
    fn validate(self, hardware_targets: &[String]) -> Result<ExecutionEnvelope> {
        let err = |msg: String| Error::Module(format!("manifest [execution]: {msg}"));
        let positive = |name: &str, v: Option<u64>| -> Result<u32> {
            match v {
                None => Err(err(format!("required field `{name}` missing"))),
                Some(0) => Err(err(format!(
                    "`{name}` must be greater than 0 — a zero-cost step is not a fact"
                ))),
                Some(n) => {
                    u32::try_from(n).map_err(|_| err(format!("`{name}` = {n} does not fit a u32")))
                }
            }
        };
        let max_step_us = positive("max_step_us", self.max_step_us)?;
        let max_dispatch_us = positive("max_dispatch_us", self.max_dispatch_us)?;
        let profile = match self.profile.as_deref() {
            None => return Err(err("required field `profile` missing".into())),
            Some(p) => ExecutionProfile::from_str_opt(p).ok_or_else(|| {
                err(format!(
                    "profile=\"{p}\" is invalid; expected one of {}",
                    ExecutionProfile::NAMES.join(" | ")
                ))
            })?,
        };
        let evidence = self.evidence.filter(|e| !e.trim().is_empty());
        if profile == ExecutionProfile::AnalyticalBound && evidence.is_none() {
            return Err(err(
                "profile = \"analytical_bound\" requires `evidence` naming the reviewed \
                 derivation; a bound nobody can audit is a measurement, so declare \
                 `measured_envelope` instead"
                    .into(),
            ));
        }
        for silicon in hardware_targets {
            let budget = crate::target_facts::TargetFacts::for_silicon(silicon).step_budget_us;
            if max_step_us > budget {
                return Err(err(format!(
                    "max_step_us = {max_step_us} exceeds the {budget} us step budget of \
                     hardware target `{silicon}`; a step that cannot fit one scheduler \
                     pass there has no envelope on that silicon"
                )));
            }
        }
        Ok(ExecutionEnvelope {
            max_step_us,
            max_dispatch_us,
            profile,
            evidence,
        })
    }
}

/// `[build]` manifest table: per-module build configuration.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TomlBuild {
    /// rustc `opt-level` for the wasm target (`"0"`–`"3"`, `"s"`,
    /// `"z"`). Absent keeps the build default.
    wasm_opt_level: Option<String>,
    /// rustc `opt-level` for a native target. Absent keeps the default.
    opt_level: Option<String>,
}

/// The accepted `wasm_opt_level` values — rustc's `opt-level` set.
pub const WASM_OPT_LEVELS: [&str; 6] = ["0", "1", "2", "3", "s", "z"];

/// Validate a `[build] wasm_opt_level` value against rustc's
/// `opt-level` set. Shared by the manifest parse and module-build
/// discovery so both reject a typo with the same message.
pub fn validate_wasm_opt_level(level: &str) -> Result<()> {
    if WASM_OPT_LEVELS.contains(&level) {
        return Ok(());
    }
    Err(Error::Module(format!(
        "invalid [build] wasm_opt_level '{level}' — expected one of {}",
        WASM_OPT_LEVELS.join(", ")
    )))
}

/// Hardware-feature requirements declared by a module in its
/// One `[[requires_when]]` entry as written in TOML.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct TomlRequiresWhen {
    capability: String,
    /// `when = { param = "value", other = ["a", "b"] }` — every parameter
    /// must match one of its listed values.
    when: std::collections::BTreeMap<String, TomlWhenValues>,
}

/// A `when` value: one admitted value or a list of them.
#[derive(Deserialize, Clone, Debug)]
#[serde(untagged)]
enum TomlWhenValues {
    One(String),
    Any(Vec<String>),
}

/// A conditional requirement on a TARGET-provided capability
/// (`vocabulary::TARGET_CAPABILITIES`): when every condition in `when`
/// holds for this module instance, the target must provide `capability`.
///
/// This is how a module binds a POSTURE to a platform fact. `tls` checks
/// certificate lifetimes against the kernel's trusted clock only when it
/// validates a chain (`peer_auth` is a CA profile) under `clock_policy =
/// require`, and then fails closed without one; on a target with no clock
/// the honest configuration is `unchecked`, and the wrong one should be
/// refused at compose rather than at the first handshake. A static
/// `[requires]` cannot say that: the same module on the same target is
/// fine as a plain server, or under the other clock value.
///
/// Each condition is a parameter and the values that satisfy it — enum
/// names or numbers, compared against the resolved value, with the schema
/// default standing in when the graph does not set the parameter. All
/// conditions must hold. TOML-only, never serialized — like `[requires]`,
/// a compose-time concern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequiresWhen {
    pub capability: String,
    /// `(param, admitted values)`, ordered by parameter name — a TOML
    /// inline table has no declaration order worth preserving.
    pub when: Vec<(String, Vec<String>)>,
}

/// `[requires]` TOML section. Used by `check_target_capabilities` to
/// reject the module at config time if the resolved target lacks
/// the requested capability — catches a class of "module pulls in
/// soft-float on a target without FPU and silently runs 100× slower"
/// bugs before they ship.
#[derive(Deserialize, Default, Clone, Copy, Debug)]
#[serde(default)]
pub struct TomlRequires {
    /// Hardware floating-point unit. Modules using `f32`/`f64` math
    /// on a target without FPU fall back to soft-float helpers in
    /// `compiler-builtins`, which are 50–100× slower than scalar
    /// integer ops. Declare `requires.fpu = true` to be rejected
    /// from such targets at build time.
    pub fpu: bool,
    /// Advanced SIMD (NEON on aarch64). Modules that use
    /// `core::arch::aarch64` intrinsics must declare this; the build
    /// then rejects placement on Cortex-M / WASM targets where the
    /// intrinsics simply don't exist (link error or panic at runtime).
    pub neon: bool,
    /// Memory-management unit with page-table isolation. Modules that
    /// rely on paged arenas declare this; the
    /// build rejects placement on Cortex-M / Cortex-A targets without
    /// an MMU (RP2350 has an MPU but not an MMU).
    pub mmu: bool,
}

/// Target hardware-capability matrix used by
/// `check_target_capabilities`. Constructed from a target's silicon
/// id; tracks the three boolean caps that modules can demand. Built
/// here rather than read from `TargetDescriptor` to keep this lint
/// portable across the tools crate's internal types (avoids a
/// circular dependency in tools/src/config.rs).
#[derive(Clone, Copy, Debug)]
pub struct TargetCapabilities {
    pub fpu: bool,
    pub neon: bool,
    pub mmu: bool,
}

impl TargetCapabilities {
    /// Resolve capabilities for a silicon or host id. Conservative —
    /// unknown names return all-false so a manifest's `requires.fpu =
    /// true` will reject placement until the name is added here.
    ///
    /// Board names must be resolved to silicon through the `targets/`
    /// registry BEFORE this call (`TargetDescriptor::module_silicon()`);
    /// this table deliberately carries no board rows.
    pub fn for_silicon(name: &str) -> Self {
        // Silicon and host tokens only — board names resolve through the
        // `targets/` registry BEFORE reaching this table (callers pass
        // `TargetDescriptor::module_silicon()`). No alias rows: the
        // registry is the single board→silicon mapping
        // (standards/target_consolidation.md §3).
        match name {
            // Cortex-M0+, no FPU, no SIMD, no MMU.
            "rp2040" => Self {
                fpu: false,
                neon: false,
                mmu: false,
            },
            // Cortex-M33 with FPv5-SP single-precision FPU, no SIMD,
            // MPU but not MMU.
            "rp2350" => Self {
                fpu: true,
                neon: false,
                mmu: false,
            },
            // Cortex-A76 quad-core, full FP/NEON, full MMU.
            "bcm2712" => Self {
                fpu: true,
                neon: true,
                mmu: true,
            },
            // Hosted: always all-yes (running on the dev machine).
            "linux" => Self {
                fpu: true,
                neon: true,
                mmu: true,
            },
            // WASM: no NEON in the portable target; FPU yes via
            // wasm-mvp; no MMU (linear memory only).
            "wasm" => Self {
                fpu: true,
                neon: false,
                mmu: false,
            },
            // Unknown — fail closed.
            _ => Self {
                fpu: false,
                neon: false,
                mmu: false,
            },
        }
    }
}

/// Confirm that the module's declared hardware-feature
/// requirements are satisfied by the target's capabilities. Returns
/// `Ok(())` if compatible, `Err` listing every mismatched capability
/// otherwise.
///
/// Designed to be called from the config-validation path against the
/// resolved per-module target after `parse_modules_from_config`. The
/// resulting error message is operator-facing (cites silicon id and
/// the missing caps).
pub fn check_target_capabilities(manifest_requires: TomlRequires, silicon: &str) -> Result<()> {
    let caps = TargetCapabilities::for_silicon(silicon);
    let mut missing: Vec<&str> = Vec::new();
    if manifest_requires.fpu && !caps.fpu {
        missing.push("fpu");
    }
    if manifest_requires.neon && !caps.neon {
        missing.push("neon");
    }
    if manifest_requires.mmu && !caps.mmu {
        missing.push("mmu");
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(Error::Module(format!(
            "module's `[requires]` declares {} but silicon `{}` does not provide them. \
             Either place this module on a target with those caps, or drop the requirement \
             if the module does not need it.",
            missing.join(", "),
            silicon,
        )))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlParam {
    name: String,
    /// `tag = N` — the permanent TLV tag for this parameter. Required on
    /// every built-in entry; see `ManifestParam::tag`.
    tag: Option<u8>,
    /// One of: u8, u16, u32, str, enum
    #[serde(rename = "type")]
    ptype: String,
    /// TOML may parse the default as int, string, or enum-name; capture
    /// raw and resolve in `Manifest::from_toml`.
    default: Option<toml::Value>,
    /// Required for `type = "enum"`: list of legal value names. Each maps
    /// to its index (0..len-1) on the wire.
    values: Option<Vec<String>>,
    /// Optional inclusive `[min, max]` for numeric types.
    range: Option<[u32; 2]>,
    /// `required = true` makes YAML omission a build error. Implies no
    /// safe default exists for this param — falling back would
    /// silently misconfigure the graph.
    #[serde(default)]
    required: bool,
}

/// A capacity value in port TOML: either flat (`buffer_size = 4096`)
/// or per-target (`buffer_size = { default = 2048, bcm2712 = 16384 }`),
/// resolved at pack time — the packer knows which silicon it is
/// packing for. Keys are silicon ids (`rp2040`, `rp2350`, `bcm2712`,
/// `wasm`) plus `default`; unknown keys are rejected so a typo can't
/// silently fall back to `default`.
#[derive(Deserialize)]
#[serde(untagged)]
enum CapacityValue {
    Flat(u32),
    PerTarget(std::collections::BTreeMap<String, u32>),
}

const CAPACITY_TARGET_KEYS: &[&str] = &["default", "rp2040", "rp2350", "bcm2712", "wasm"];

impl CapacityValue {
    fn resolve(&self, silicon: Option<&str>, field: &str) -> Result<u32> {
        match self {
            CapacityValue::Flat(v) => Ok(*v),
            CapacityValue::PerTarget(map) => {
                for k in map.keys() {
                    if !CAPACITY_TARGET_KEYS.contains(&k.as_str()) {
                        return Err(Error::Module(format!(
                            "unknown target '{k}' in per-target `{field}` \
                             (known: {CAPACITY_TARGET_KEYS:?})"
                        )));
                    }
                }
                if let Some(sil) = silicon {
                    if let Some(v) = map.get(sil) {
                        return Ok(*v);
                    }
                }
                map.get("default").copied().ok_or_else(|| {
                    Error::Module(format!(
                        "per-target `{field}` has no entry for target {:?} and no `default`",
                        silicon.unwrap_or("<none>")
                    ))
                })
            }
        }
    }
}

#[derive(Deserialize)]
struct TomlPort {
    direction: String,
    content_type: String,
    required: Option<bool>,
    /// This port carries whole RECORDS, not a byte stream. A framed edge must
    /// be in mailbox mode (`buffer_group` on the wiring entry) or the default
    /// byte FIFO will fragment records under pressure — silently, and only
    /// under load. Declaring it lets the graph build enforce it.
    framed: Option<bool>,
    name: Option<String>,
    index: Option<u8>,
    buffer_size: Option<CapacityValue>,
    max_record: Option<CapacityValue>,
    rate_class_max: Option<String>,
    rate_class_default: Option<String>,
    /// Capability the peer wired to this port must declare. See
    /// [`PortSpec::requires_capability`].
    requires_capability: Option<String>,
}

#[derive(Deserialize)]
struct TomlResource {
    /// Public contract this module needs access to. Values: one of
    /// gpio, spi, i2c, pio, uart, adc, pwm, fs. Non-contract
    /// permissions go in the top-level `permissions = [...]` list.
    #[serde(rename = "requires_contract")]
    device_class: String,
    access: String,
    instance: Option<u8>,
}

#[derive(Deserialize)]
struct TomlDependency {
    name: String,
    min_version: Option<String>,
}

#[derive(Deserialize)]
struct TomlCommands {
    accepts: Option<Vec<String>>,
    emits: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `[build] wasm_opt_level` parses into the manifest, absent means
    /// `None` (build default), and a value outside rustc's `opt-level`
    /// set is rejected at parse time.
    #[test]
    fn build_wasm_opt_level_parses_and_validates() {
        let with = "version = \"0.1.0\"\n\n[build]\nwasm_opt_level = \"z\"\n";
        let m = Manifest::from_toml_str_for_target(with, None).expect("parse");
        assert_eq!(m.wasm_opt_level.as_deref(), Some("z"));

        for level in WASM_OPT_LEVELS {
            let toml = format!("version = \"0.1.0\"\n\n[build]\nwasm_opt_level = \"{level}\"\n");
            let m = Manifest::from_toml_str_for_target(&toml, None).expect("parse");
            assert_eq!(m.wasm_opt_level.as_deref(), Some(level));
        }

        let without = "version = \"0.1.0\"\n";
        let m = Manifest::from_toml_str_for_target(without, None).expect("parse");
        assert_eq!(m.wasm_opt_level, None);

        let bad = "version = \"0.1.0\"\n\n[build]\nwasm_opt_level = \"fast\"\n";
        let err = Manifest::from_toml_str_for_target(bad, None).unwrap_err();
        assert!(err.to_string().contains("wasm_opt_level"), "{err}");
    }

    #[test]
    fn semver_roundtrip() {
        let v = encode_semver(1, 2, 3);
        assert_eq!(decode_semver(v), (1, 2, 3));
    }

    /// Port-capacity section (flag bit 5): round-trips through the
    /// binary form, sits inside the signed region (before the
    /// integrity hash), and absent capacities emit no section.
    #[test]
    fn port_capacity_roundtrip() {
        let mut m = Manifest::default();
        m.ports.push(PortSpec {
            direction: 0,
            content_type: 3,
            flags: 1,
            name: None,
            index: 0,
            buffer_size: 65536,
            max_record: 0,
            rate_class_max: None,
            rate_class_default: None,
            requires_capability: None,
        });
        m.ports.push(PortSpec {
            direction: 1,
            content_type: 5,
            flags: 0,
            name: None,
            index: 0,
            buffer_size: 1048576,
            max_record: 16384,
            rate_class_max: None,
            rate_class_default: None,
            requires_capability: None,
        });
        let bytes = m.to_bytes();
        assert_eq!(bytes[14] & 0x20, 0x20, "capacity flag set");
        // Section sits after the header + port records (17 + 2*4 = 25),
        // before any hash.
        assert_eq!(&bytes[25..29], &65536u32.to_le_bytes());
        assert_eq!(&bytes[33..37], &1048576u32.to_le_bytes());
        assert_eq!(&bytes[37..41], &16384u32.to_le_bytes());
        let back = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(back.ports[0].buffer_size, 65536);
        assert_eq!(back.ports[0].max_record, 0);
        assert_eq!(back.ports[1].buffer_size, 1048576);
        assert_eq!(back.ports[1].max_record, 16384);

        // No capacities → no section, no flag set.
        let mut plain = Manifest::default();
        plain.ports.push(PortSpec {
            direction: 0,
            content_type: 3,
            flags: 1,
            name: None,
            index: 0,
            buffer_size: 0,
            max_record: 0,
            rate_class_max: None,
            rate_class_default: None,
            requires_capability: None,
        });
        let pb = plain.to_bytes();
        assert_eq!(pb[14] & 0x20, 0);
        assert_eq!(pb.len(), 17 + 4);
        assert!(Manifest::from_bytes(&pb).is_ok());
    }

    #[test]
    fn check_module_exports_isr_entry_finds_definition() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(
            src.join("lib.rs"),
            "#[no_mangle]\npub extern \"C\" fn module_isr_entry(_s: *mut u8) -> i32 { 0 }\n",
        )
        .expect("write");
        check_module_exports_isr_entry(dir.path())
            .expect("source defining module_isr_entry must pass");
    }

    #[test]
    fn check_module_exports_isr_entry_rejects_missing_definition() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        // Only a cooperative step — no ISR entry.
        std::fs::write(
            src.join("lib.rs"),
            "fn module_step(_s: *mut u8) -> i32 { 0 }\n",
        )
        .expect("write");
        let err = check_module_exports_isr_entry(dir.path())
            .expect_err("source without module_isr_entry must be rejected");
        assert!(
            format!("{err}").contains("module_isr_entry"),
            "diagnostic must name the missing export, got: {err}"
        );
    }

    #[test]
    fn check_module_exports_isr_entry_rejects_missing_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does_not_exist");
        check_module_exports_isr_entry(&missing)
            .expect_err("nonexistent source tree must be rejected");
    }

    #[test]
    fn source_exports_isr_entry_accepts_real_shapes() {
        // Attribute on its own line, with #[cfg] in between.
        assert!(source_exports_isr_entry(
            "#[no_mangle]\n#[cfg(feature = \"x\")]\npub extern \"C\" fn module_isr_entry(_s: *mut u8) -> i32 { 0 }\n"
        ));
        // Attribute and signature on the same line.
        assert!(source_exports_isr_entry(
            "#[no_mangle] pub unsafe extern \"C\" fn module_isr_entry(s: *mut u8) -> i32 { 0 }\n"
        ));
        // Rust-2024 unsafe(no_mangle) form.
        assert!(source_exports_isr_entry(
            "#[unsafe(no_mangle)]\npub extern \"C\" fn module_isr_entry(_s: *mut u8) -> i32 { 0 }\n"
        ));
    }

    #[test]
    fn source_exports_isr_entry_rejects_false_positives() {
        // Bare fn with no #[no_mangle] — the linker would NOT export it.
        assert!(!source_exports_isr_entry(
            "pub extern \"C\" fn module_isr_entry(_s: *mut u8) -> i32 { 0 }\n"
        ));
        // Not extern "C" — also not the export ABI.
        assert!(!source_exports_isr_entry(
            "#[no_mangle]\nfn module_isr_entry(_s: *mut u8) -> i32 { 0 }\n"
        ));
        // Name only in a line comment.
        assert!(!source_exports_isr_entry(
            "// TODO: add extern \"C\" fn module_isr_entry later\n#[no_mangle]\n"
        ));
        // Name only in a doc comment.
        assert!(!source_exports_isr_entry(
            "/// calls extern \"C\" fn module_isr_entry from the ISR\nfn other() {}\n"
        ));
        // The #[no_mangle] attaches to an intervening fn, NOT to the
        // bare module_isr_entry that follows.
        assert!(!source_exports_isr_entry(
            "#[no_mangle]\npub extern \"C\" fn other_export() -> i32 { 0 }\n\
             pub extern \"C\" fn module_isr_entry(_s: *mut u8) -> i32 { 0 }\n"
        ));
    }

    #[test]
    fn empty_manifest_roundtrip() {
        let m = Manifest::default();
        let bytes = m.to_bytes();
        assert_eq!(bytes.len(), MANIFEST_HEADER_SIZE);
        let m2 = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(m2.module_version, m.module_version);
        assert!(m2.ports.is_empty());
        assert!(m2.resources.is_empty());
        assert!(m2.dependencies.is_empty());
        assert!(m2.integrity_hash.is_none());
    }

    #[test]
    fn manifest_with_integrity_roundtrip() {
        let mut m = Manifest::default();
        m.ports.push(PortSpec {
            direction: 0,
            content_type: 3,
            flags: 1,
            name: None,
            index: 0,
            buffer_size: 0,
            max_record: 0,
            rate_class_max: None,
            rate_class_default: None,
            requires_capability: None,
        });
        m.resources.push(ResourceClaim {
            device_class: 0x04,
            access_mode: 2,
            instance: 0xFF,
        });
        m.dependencies.push(Dependency {
            name_hash: 0x12345678,
            min_version: encode_semver(1, 0, 0),
        });
        m.integrity_hash = Some([0xAB; 32]);

        let bytes = m.to_bytes();
        let m2 = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(m2.ports.len(), 1);
        assert_eq!(m2.ports[0].content_type, 3);
        assert_eq!(m2.resources.len(), 1);
        assert_eq!(m2.resources[0].device_class, 0x04);
        assert_eq!(m2.dependencies.len(), 1);
        assert_eq!(m2.dependencies[0].name_hash, 0x12345678);
        assert_eq!(m2.integrity_hash.unwrap(), [0xAB; 32]);
    }

    #[test]
    fn required_caps_mask() {
        let mut m = Manifest::default();
        m.resources.push(ResourceClaim {
            device_class: 0x01,
            access_mode: 0,
            instance: 0xFF,
        }); // GPIO
        m.resources.push(ResourceClaim {
            device_class: 0x04,
            access_mode: 2,
            instance: 0xFF,
        }); // PIO
        m.resources.push(ResourceClaim {
            device_class: 0x3F,
            access_mode: 0,
            instance: 0xFF,
        }); // highest representable position
        assert_eq!(
            m.required_caps_mask().unwrap(),
            (1u64 << 1) | (1u64 << 4) | (1u64 << 0x3F)
        );
    }

    #[test]
    fn required_caps_mask_refuses_an_id_outside_the_space() {
        let mut m = Manifest::default();
        m.resources.push(ResourceClaim {
            device_class: CONTRACT_ID_SPACE as u8,
            access_mode: 0,
            instance: 0xFF,
        });
        assert!(m.required_caps_mask().is_err());
    }

    fn parse_toml(src: &str) -> Result<Manifest> {
        // RAII scratch dir; cleaned when this function returns. The
        // path passed to `from_toml` is only borrowed during the
        // synchronous parse, so the TempDir can drop right after.
        let tmp = tempfile::Builder::new()
            .prefix("fluxor-manifest-test-")
            .tempdir()
            .unwrap();
        let path = tmp.path().join("manifest.toml");
        std::fs::write(&path, src).unwrap();
        Manifest::from_toml(&path)
    }

    // ── [[variant]] table ─────────────────────

    const VARIANT_MANIFEST: &str = r#"
version = "1.0.0"

[[ports]]
name = "encoded"
direction = "input"
content_type = "OctetStream"

[[ports]]
name = "audio"
direction = "output"
content_type = "AudioSample"

[[ports]]
name = "pixels"
direction = "output"
content_type = "VideoRaster"

[[variant]]
name = "audio"
features = ["wav", "mp3"]
omit_ports = ["pixels"]

[[variant]]
name = "full"
features = ["wav", "mp3", "image"]
default = true
"#;

    /// apply_variant filters omitted ports from the embedded manifest
    /// while retained ports keep their already-resolved indices —
    /// omission leaves holes, never shifts (module code addresses
    /// ports positionally).
    #[test]
    fn variant_apply_filters_ports_and_keeps_indices() {
        let mut m = parse_toml(VARIANT_MANIFEST).expect("parse");
        assert_eq!(m.variants.len(), 2);
        assert_eq!(m.ports.len(), 3);

        m.apply_variant("audio").expect("apply");
        assert_eq!(m.ports.len(), 2);
        assert!(m.ports.iter().all(|p| p.name.as_deref() != Some("pixels")));
        // audio output keeps out[0]; the omitted pixels out[1] leaves a hole.
        let audio = m
            .ports
            .iter()
            .find(|p| p.name.as_deref() == Some("audio"))
            .expect("audio port");
        assert_eq!(audio.index, 0);

        // The default variant omits nothing.
        let mut full = parse_toml(VARIANT_MANIFEST).expect("parse");
        full.apply_variant("full").expect("apply full");
        assert_eq!(full.ports.len(), 3);
    }

    /// Index stability across a hole: omitting an EARLIER output port
    /// must not renumber a later one.
    #[test]
    fn variant_omission_leaves_index_holes() {
        let src = r#"
version = "1.0.0"

[[ports]]
name = "first_out"
direction = "output"
content_type = "OctetStream"

[[ports]]
name = "second_out"
direction = "output"
content_type = "OctetStream"

[[variant]]
name = "trimmed"
features = ["a"]
omit_ports = ["first_out"]

[[variant]]
name = "full"
features = ["a", "b"]
default = true
"#;
        let mut m = parse_toml(src).expect("parse");
        m.apply_variant("trimmed").expect("apply");
        assert_eq!(m.ports.len(), 1);
        // second_out keeps out[1] even though out[0] is gone.
        assert_eq!(m.ports[0].name.as_deref(), Some("second_out"));
        assert_eq!(m.ports[0].index, 1);
    }

    #[test]
    fn variant_unknown_name_is_an_error() {
        let mut m = parse_toml(VARIANT_MANIFEST).expect("parse");
        let err = m.apply_variant("nope").unwrap_err().to_string();
        assert!(err.contains("unknown variant"), "got: {err}");
        assert!(err.contains("audio"), "should list declared names: {err}");
    }

    #[test]
    fn variant_table_needs_exactly_one_default() {
        let src = VARIANT_MANIFEST.replace("default = true", "");
        let err = parse_toml(&src).unwrap_err().to_string();
        assert!(err.contains("exactly one `default = true`"), "got: {err}");
    }

    #[test]
    fn variant_omit_unknown_port_is_an_error() {
        let src = VARIANT_MANIFEST.replace("omit_ports = [\"pixels\"]", "omit_ports = [\"nope\"]");
        let err = parse_toml(&src).unwrap_err().to_string();
        assert!(err.contains("omits unknown port"), "got: {err}");
    }

    #[test]
    fn variant_missing_features_key_is_an_error() {
        let src = VARIANT_MANIFEST.replace("features = [\"wav\", \"mp3\"]\n", "");
        let err = parse_toml(&src).unwrap_err().to_string();
        assert!(err.contains("declares no features"), "got: {err}");
    }

    /// An EXPLICIT `features = []` is a deliberate base-surface-only variant
    /// (otel-min: the fxtl path with no OTLP encoder in flash) — allowed,
    /// unlike a forgotten `features` key.
    #[test]
    fn variant_explicit_empty_features_is_allowed() {
        let src = VARIANT_MANIFEST.replace("features = [\"wav\", \"mp3\"]", "features = []");
        parse_toml(&src).expect("explicit empty feature set parses");
    }

    /// A typo'd key in a [[variant]] row must fail parsing, not be
    /// silently ignored (a dropped `omit_ports` would ship a variant
    /// advertising ports it doesn't carry).
    #[test]
    fn variant_unknown_key_is_an_error() {
        let src = VARIANT_MANIFEST.replace("omit_ports = [\"pixels\"]", "omit_port = [\"pixels\"]");
        assert!(
            parse_toml(&src).is_err(),
            "unknown [[variant]] key must fail parsing"
        );
    }

    #[test]
    fn rejects_params_on_non_builtin_manifest() {
        let src = r#"
version = "1.0.0"
hardware_targets = ["linux"]

[[ports]]
name = "stream"
direction = "output"
content_type = "OctetStream"

[[params]]
name = "x"
tag = 10
type = "u32"
default = 1
"#;
        let err = parse_toml(src).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("[[params]] is only valid on built-in modules"),
            "unexpected message: {msg}",
        );
    }

    #[test]
    fn accepts_params_on_builtin_manifest() {
        let src = r#"
version = "1.0.0"
hardware_targets = ["linux"]
builtin = true

[[ports]]
name = "stream"
direction = "output"
content_type = "OctetStream"

[[params]]
name = "width"
tag = 10
type = "u32"
default = 480
range = [1, 4096]

[[params]]
name = "scale_mode"
tag = 11
type = "enum"
values = ["fit", "stretch"]
default = "fit"

[[params]]
name = "path"
tag = 12
type = "str"
required = true
"#;
        let m = parse_toml(src).expect("parse");
        assert!(m.builtin);
        assert_eq!(m.params.len(), 3);
        // Tags come from the manifest, not from declaration position.
        assert_eq!(m.params[0].tag, 10);
        assert_eq!(m.params[1].tag, 11);
        assert_eq!(m.params[2].tag, 12);
        // Range honored.
        assert_eq!(m.params[0].range, Some((1, 4096)));
        // Enum value table.
        assert_eq!(m.params[1].enum_values.len(), 2);
        assert_eq!(m.params[1].enum_values[0].1, 0); // fit -> 0
        assert_eq!(m.params[1].enum_values[1].1, 1); // stretch -> 1
        assert_eq!(m.params[1].default_num, 0); // fit
                                                // required honored.
        assert!(m.params[2].required);
        assert!(!m.params[0].required);
    }

    #[test]
    fn rejects_required_with_default() {
        let src = r#"
version = "1.0.0"
builtin = true

[[params]]
name = "path"
tag = 10
type = "str"
default = "/tmp/foo"
required = true
"#;
        let err = parse_toml(src).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("mutually exclusive"), "unexpected: {msg}");
    }

    /// The ABI-surface attestation block must round-trip through the binary
    /// codec, coexist with integrity+signature blocks (it is appended LAST,
    /// so the kernel's offset math over earlier blocks is untouched), and
    /// stay optional for a manifest that carries no attestation.
    #[test]
    fn abi_surface_attestation_round_trips() {
        let mut m = Manifest {
            integrity_hash: Some([0x11; 32]),
            signature: Some([0x22; 64]),
            signer_fp: Some([0x33; 32]),
            abi_surface: Some([0x44; 32]),
            ..Manifest::default()
        };
        let bytes = m.to_bytes();
        let back = Manifest::from_bytes(&bytes).expect("decode");
        assert_eq!(back.abi_surface, Some([0x44; 32]));
        assert_eq!(back.integrity_hash, Some([0x11; 32]));
        assert_eq!(back.signature, Some([0x22; 64]));
        assert_eq!(back.signer_fp, Some([0x33; 32]));

        // A manifest with no attestation round-trips as None.
        m.abi_surface = None;
        let back = Manifest::from_bytes(&m.to_bytes()).expect("decode legacy");
        assert_eq!(back.abi_surface, None);

        // Truncating the attestation block is rejected.
        m.abi_surface = Some([0x44; 32]);
        let bytes = m.to_bytes();
        assert!(Manifest::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    /// Module-scope `[capacities]` resolve per silicon like port capacities do,
    /// fall back to `default` for an unlisted silicon, and reject an unknown
    /// silicon key so a typo can't silently hand back `default`.
    #[test]
    fn module_capacities_resolve_per_silicon() {
        const TOML: &str = r#"
version = "1.0.0"
hardware_targets = ["bcm2712", "rp2350"]

[capacities]
idtable = { default = 2048, bcm2712 = 4096 }
scratch = 512
"#;
        let big = Manifest::from_toml_str_for_target(TOML, Some("bcm2712")).expect("bcm2712");
        assert_eq!(big.capacities["idtable"], 4096);
        assert_eq!(big.capacities["scratch"], 512);

        let small = Manifest::from_toml_str_for_target(TOML, Some("rp2350")).expect("rp2350");
        assert_eq!(small.capacities["idtable"], 2048);

        let none = Manifest::from_toml_str_for_target(TOML, None).expect("no silicon");
        assert_eq!(none.capacities["idtable"], 2048);

        let typo = "version = \"1.0.0\"\n[capacities]\nidtable = { default = 1, bcm2711 = 2 }\n";
        let err = Manifest::from_toml_str_for_target(typo, Some("bcm2712"))
            .expect_err("unknown silicon key is rejected")
            .to_string();
        assert!(
            err.contains("capacities.idtable"),
            "error should name the offending capacity: {err}"
        );
    }

    // ── Built-in parameter schema lock ──────────────────────────────────
    //
    // A built-in's configuration reaches the platform as a TLV blob keyed
    // by tag, so the `(name, type, tag)` tuple of every `[[params]]` entry
    // is a wire contract: rename a parameter and a config stops resolving,
    // change its type and the value is decoded as something else, move its
    // tag and a deployed encoding starts meaning a different field.
    //
    // `RELEASED_LAYOUT` pins that tuple for every shipped built-in.
    // Changing a released parameter means changing this table in the same
    // commit — an explicit, reviewable edit rather than a side effect of
    // editing a manifest.

    /// The built-in manifest trees, relative to the repository root.
    const BUILTIN_TREES: [&str; 2] = ["modules/platform/linux", "modules/platform/wasm"];

    /// Every released built-in parameter: `(module, name, type, tag)`.
    ///
    /// Adding a parameter adds a row. Removing one removes its row — and
    /// retires its tag permanently, because a deployed config may still
    /// carry it. Editing a row is a migration and needs to be justified as
    /// one.
    const RELEASED_LAYOUT: &[(&str, &str, &str, u8)] = &[
        ("host_asset_index", "paths", "str", 10),
        ("host_asset_source", "path", "str", 10),
        ("host_image_codec", "width", "u32", 10),
        ("host_image_codec", "height", "u32", 11),
        ("host_image_codec", "scale_mode", "enum", 12),
        ("host_image_codec", "max_bytes", "u32", 13),
        ("linux_alsa_midi", "mode", "enum", 10),
        ("linux_alsa_midi", "port_filter", "str", 11),
        ("linux_alsa_midi", "client_name", "str", 12),
        ("linux_audio", "mode", "enum", 10),
        ("linux_audio", "path", "str", 11),
        ("linux_audio", "sample_rate", "u32", 12),
        ("linux_audio", "channels", "u8", 13),
        ("linux_display", "mode", "enum", 10),
        ("linux_display", "path", "str", 11),
        ("linux_display", "width", "u32", 12),
        ("linux_display", "height", "u32", 13),
        ("linux_display", "scale", "u32", 14),
        ("linux_display", "header", "u32", 15),
        // Memory budgets are a deployment decision, not an adapter fact: an
        // adapter will let a graph allocate until the host dies, so the
        // ceiling admission enforces is configured rather than discovered.
        ("linux_gpu", "resident_mb", "u32", 10),
        ("linux_gpu", "staging_kb", "u32", 11),
        ("linux_net", "max_conns", "u32", 10),
        ("linux_net", "write_buf_kib", "u32", 11),
        ("linux_net", "listen_backlog", "u32", 12),
        ("linux_pointer", "path", "str", 10),
        ("linux_pointer", "width", "u32", 11),
        ("linux_pointer", "height", "u32", 12),
        ("linux_pointer", "x_max", "u32", 13),
        ("linux_pointer", "y_max", "u32", 14),
        ("linux_surface_traits", "width", "u32", 10),
        ("linux_surface_traits", "height", "u32", 11),
        ("host_browser_fetch", "url", "str", 10),
        ("wasm_browser_audio", "sample_rate", "u32", 10),
        ("wasm_browser_audio", "channels", "u8", 11),
        ("wasm_browser_audio", "lead_ms", "u8", 12),
        ("wasm_browser_canvas", "width", "u16", 10),
        ("wasm_browser_canvas", "height", "u16", 11),
        ("wasm_browser_canvas", "header", "u16", 12),
        ("wasm_browser_display_capture", "width", "u16", 10),
        ("wasm_browser_display_capture", "height", "u16", 11),
        ("wasm_browser_display_capture", "header", "u16", 12),
        ("wasm_browser_gpu", "width", "u16", 10),
        ("wasm_browser_gpu", "height", "u16", 11),
        ("wasm_browser_image_codec", "width", "u16", 10),
        ("wasm_browser_image_codec", "height", "u16", 11),
        ("wasm_browser_image_codec", "max_bytes", "u32", 12),
        ("wasm_browser_midi_in", "port_filter", "str", 10),
        ("wasm_browser_midi_in", "sysex", "enum", 11),
        ("wasm_browser_midi_out", "port_filter", "str", 10),
        ("wasm_browser_video_codec", "width", "u16", 10),
        ("wasm_browser_video_codec", "height", "u16", 11),
        ("wasm_browser_video_codec", "max_frame_bytes", "u32", 12),
        ("wasm_browser_http", "origin", "str", 10),
        ("wasm_browser_http", "surface_status", "u8", 11),
        ("wasm_browser_websocket", "url", "str", 10),
        ("wasm_browser_ws", "origin", "str", 10),
        ("wasm_browser_ws_source", "url", "str", 10),
    ];

    fn repo_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("tools/ has a parent")
            .to_path_buf()
    }

    fn param_type_name(t: ManifestParamType) -> &'static str {
        match t {
            ManifestParamType::U8 => "u8",
            ManifestParamType::U16 => "u16",
            ManifestParamType::U32 => "u32",
            ManifestParamType::Str => "str",
            ManifestParamType::Enum => "enum",
        }
    }

    /// Load every built-in manifest that declares `[[params]]`, in tree
    /// then directory order, as `(module, name, type, tag)` rows.
    fn actual_builtin_layout() -> Vec<(String, String, &'static str, u8)> {
        let root = repo_root();
        let mut rows = Vec::new();
        for tree in BUILTIN_TREES {
            let dir = root.join(tree);
            let mut modules: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
                .filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .filter(|p| p.join("manifest.toml").exists())
                .collect();
            modules.sort();
            for module in modules {
                let name = module
                    .file_name()
                    .expect("module directory has a name")
                    .to_string_lossy()
                    .into_owned();
                let manifest = Manifest::from_toml(&module.join("manifest.toml"))
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                for p in &manifest.params {
                    rows.push((
                        name.clone(),
                        p.name.clone(),
                        param_type_name(p.ptype),
                        p.tag,
                    ));
                }
            }
        }
        rows
    }

    #[test]
    fn released_builtin_parameters_match_the_pinned_schema() {
        let expected: Vec<(String, String, &str, u8)> = RELEASED_LAYOUT
            .iter()
            .map(|(m, n, t, g)| ((*m).to_string(), (*n).to_string(), *t, *g))
            .collect();

        // Compare as sorted sets: the tag, not the declaration position,
        // is the identity, so a reordered manifest must NOT register as a
        // change.
        let mut a = actual_builtin_layout();
        let mut e = expected;
        a.sort();
        e.sort();
        assert_eq!(
            a, e,
            "built-in parameter schema drifted.\n\
             Each row is (module, name, type, tag) and is a wire contract: a\n\
             rename, a type change, or a tag reassignment changes what a\n\
             deployed config means. If the change is intended, migrate it\n\
             deliberately and update RELEASED_LAYOUT in the same commit.",
        );
    }

    #[test]
    fn every_builtin_tag_is_unique_and_in_range() {
        let mut seen: Vec<(String, u8)> = Vec::new();
        for (module, name, _, tag) in actual_builtin_layout() {
            assert!(
                (PARAM_TAG_MIN..=PARAM_TAG_MAX).contains(&tag),
                "{module}.{name}: tag {tag} outside {PARAM_TAG_MIN}..={PARAM_TAG_MAX}",
            );
            let key = (module.clone(), tag);
            assert!(
                !seen.contains(&key),
                "{module}.{name}: tag {tag} used twice in one module",
            );
            seen.push(key);
        }
    }

    fn builtin_with_params(params: &str) -> String {
        format!("version = \"1.0.0\"\nbuiltin = true\n{params}")
    }

    fn builtin_param_parse_err(params: &str) -> String {
        let src = builtin_with_params(params);
        let err =
            Manifest::from_toml_str_for_target(&src, None).expect_err("expected a manifest error");
        format!("{err}")
    }

    /// The defect the declared tag exists to prevent: with
    /// position-derived tags, inserting `mode` ahead of `height` moved
    /// `height`'s wire meaning onto the next field. With declared tags it
    /// cannot.
    #[test]
    fn a_reordered_or_extended_params_table_leaves_released_tags_alone() {
        let before = builtin_with_params(
            "[[params]]\nname = \"width\"\ntag = 10\ntype = \"u32\"\n\n\
             [[params]]\nname = \"height\"\ntag = 11\ntype = \"u32\"\n",
        );
        let after = builtin_with_params(
            "[[params]]\nname = \"width\"\ntag = 10\ntype = \"u32\"\n\n\
             [[params]]\nname = \"mode\"\ntag = 12\ntype = \"u8\"\n\n\
             [[params]]\nname = \"height\"\ntag = 11\ntype = \"u32\"\n",
        );
        let tag_of = |src: &str, want: &str| {
            Manifest::from_toml_str_for_target(src, None)
                .expect("parse")
                .params
                .iter()
                .find(|p| p.name == want)
                .expect("param present")
                .tag
        };
        assert_eq!(tag_of(&before, "height"), 11);
        assert_eq!(tag_of(&after, "height"), 11);
        assert_eq!(tag_of(&after, "width"), 10);
    }

    #[test]
    fn a_missing_builtin_tag_is_rejected() {
        let msg = builtin_param_parse_err("[[params]]\nname = \"width\"\ntype = \"u32\"\n");
        assert!(
            msg.contains("param 'width'") && msg.contains("missing `tag = N`"),
            "unexpected message: {msg}",
        );
    }

    #[test]
    fn a_duplicate_builtin_tag_is_rejected() {
        let msg = builtin_param_parse_err(
            "[[params]]\nname = \"width\"\ntag = 10\ntype = \"u32\"\n\n\
             [[params]]\nname = \"height\"\ntag = 10\ntype = \"u32\"\n",
        );
        assert!(
            msg.contains("param 'height'") && msg.contains("already claimed by param 'width'"),
            "unexpected message: {msg}",
        );
    }

    #[test]
    fn a_reserved_or_out_of_range_builtin_tag_is_rejected() {
        for tag in [0u16, 9, 0xF0, 0xFE, 0xFF] {
            let msg = builtin_param_parse_err(&format!(
                "[[params]]\nname = \"width\"\ntag = {tag}\ntype = \"u32\"\n"
            ));
            assert!(
                msg.contains("param 'width'") && msg.contains("out of range"),
                "tag {tag}: unexpected message: {msg}",
            );
        }
    }

    #[test]
    fn a_builtin_tag_beyond_a_byte_is_rejected() {
        let msg =
            builtin_param_parse_err("[[params]]\nname = \"width\"\ntag = 256\ntype = \"u32\"\n");
        assert!(
            msg.contains("invalid manifest TOML"),
            "unexpected message: {msg}",
        );
    }

    /// `build.rs` generates the tag constants the platform matches on from
    /// these same manifests, so a second, hand-typed copy of a tag number
    /// cannot exist to drift. Catch one being reintroduced.
    #[test]
    fn no_platform_source_hand_writes_a_param_tag() {
        let root = repo_root().join("src/platform");
        let mut offenders = Vec::new();
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir)
                .expect("read src/platform")
                .flatten()
            {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("read source");
                for (n, line) in text.lines().enumerate() {
                    let trimmed = line.trim();
                    let Some(rest) = trimmed.strip_prefix("const ") else {
                        continue;
                    };
                    if !rest.contains("_TAG_") {
                        continue;
                    }
                    let Some((_, value)) = rest.split_once('=') else {
                        continue;
                    };
                    let value = value.trim().trim_end_matches(';');
                    if value
                        .parse::<u8>()
                        .is_ok_and(|v| (PARAM_TAG_MIN..=PARAM_TAG_MAX).contains(&v))
                    {
                        offenders.push(format!("{}:{}: {trimmed}", path.display(), n + 1));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "hand-written parameter tag constant(s) in src/platform — take the \
             value from `platform::builtin_param_tags`, which build.rs generates \
             from the manifests:\n{}",
            offenders.join("\n"),
        );
    }

    // ── [[observability.instrument]] rows ───────────────────

    fn obs_manifest(extra: &str) -> String {
        format!(
            "version = \"1.0.0\"\ntype = \"Transformer\"\nentry = \"mod.rs\"\n\
             hardware_targets = [\"bcm2712\"]\n\n[observability]\n\
             metrics = [\"requests_total\", \"lag\", \"latency_us\"]\n{extra}"
        )
    }

    #[test]
    fn instrument_rows_parse_with_dimensions_and_bounds() {
        let src = obs_manifest(
            "[[observability.instrument]]\nname = \"lag\"\nkind = \"updown\"\n\
             [[observability.instrument.dimension]]\nkey = \"messaging.destination.partition.id\"\n\
             domain = \"numeric\"\nmax = 64\n\
             [[observability.instrument.dimension]]\nkey = \"messaging.consumer.group.name\"\n\
             domain = \"enum\"\nvalues = [\"ingest\", \"audit\"]\n",
        );
        let m = Manifest::from_toml_str_for_target(&src, None).expect("parses");
        let inst = &m.observability.instruments[0];
        assert_eq!(inst.kind, InstrumentKind::UpDown);
        assert_eq!(inst.dimensions.len(), 2);
        assert_eq!(inst.dimensions[0].domain.size(), 64);
        assert_eq!(inst.dimensions[1].domain.size(), 2);
    }

    #[test]
    fn instrument_domain_product_over_the_u16_ceiling_is_rejected() {
        // 64 × 1024 = 65536 > 65534 (DIM_MAX_PRODUCT): the composite index
        // could not carry it, so the manifest must refuse at build.
        let src = obs_manifest(
            "[[observability.instrument]]\nname = \"lag\"\nkind = \"updown\"\n\
             [[observability.instrument.dimension]]\nkey = \"messaging.destination.partition.id\"\n\
             domain = \"numeric\"\nmax = 64\n\
             [[observability.instrument.dimension]]\nkey = \"messaging.consumer.group.name\"\n\
             domain = \"numeric\"\nmax = 1024\n",
        );
        let err = Manifest::from_toml_str_for_target(&src, None).expect_err("must refuse");
        assert!(err.to_string().contains("65534"), "{err}");
    }

    #[test]
    fn histogram16_requires_exactly_15_ascending_bounds() {
        let short = obs_manifest(
            "[[observability.instrument]]\nname = \"latency_us\"\nkind = \"histogram16\"\n\
             bounds_us = [1, 2, 3]\n",
        );
        let err = Manifest::from_toml_str_for_target(&short, None).expect_err("must refuse");
        assert!(err.to_string().contains("15"), "{err}");

        let unsorted = obs_manifest(
            "[[observability.instrument]]\nname = \"latency_us\"\nkind = \"histogram16\"\n\
             bounds_us = [250, 500, 400, 2500, 5000, 10000, 25000, 50000, 100000, 250000, 500000, 1000000, 2500000, 5000000, 10000000]\n",
        );
        let err = Manifest::from_toml_str_for_target(&unsorted, None).expect_err("must refuse");
        assert!(err.to_string().contains("ascending"), "{err}");
    }

    #[test]
    fn instrument_row_must_name_a_declared_metric() {
        let src = obs_manifest(
            "[[observability.instrument]]\nname = \"not_a_metric\"\nkind = \"counter\"\n",
        );
        let err = Manifest::from_toml_str_for_target(&src, None).expect_err("must refuse");
        assert!(err.to_string().contains("metrics"), "{err}");
    }
}
