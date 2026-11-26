//! Per-target facts about what the PLATFORM provides, as opposed to what a
//! module declares: the calendar-time source its HAL can vouch for, the
//! sealing key it can derive from, the custody a key vault can reach there,
//! and the step budget its scheduler grants a module.
//!
//! These are properties of the kernel build and the silicon, so no manifest
//! carries them and no graph wires them. The composer answers them from this
//! table, and a manifest binds to them through `[[requires_when]]` — a
//! module that needs a trustworthy clock only under one of its own
//! parameter values says so and is refused at compose on a target that
//! cannot back it, rather than at its first handshake.
//!
//! Every value here mirrors the kernel source cited beside it, every fact
//! value is one `CAPABILITY_FACTS` admits for its capability, and the silicon
//! keys are those of `manifest::TargetCapabilities::for_runtime` — board names
//! resolve through the `targets/` registry before reaching here.

use fluxor_contracts::vocabulary::TARGET_CAPABILITIES;

use crate::error::{Error, Result};
use crate::manifest::{ExecutionProfile, Manifest};

/// Vault key suites, `crates/fluxor-abi/src/contracts/key_vault.rs::suite`.
pub mod vault_suite {
    pub const P256: u16 = 1;
    pub const ED25519: u16 = 2;
    pub const ML_DSA_44: u16 = 4;
    pub const ML_DSA_65: u16 = 5;
    pub const ML_DSA_87: u16 = 6;
    /// A 32-byte ChaCha20-Poly1305 sealing key: no public half, signs
    /// nothing, and what a resumption ticket is sealed under.
    pub const AEAD_KEY: u16 = 8;
    /// RSA keys by modulus width, signing RSASSA-PSS-SHA256.
    pub const RSA_2048: u16 = 10;
    pub const RSA_3072: u16 = 11;
    pub const RSA_4096: u16 = 12;
}

/// Vault custody values, `crates/fluxor-abi/src/contracts/key_vault.rs::custody`.
pub mod vault_custody {
    pub const SOFTWARE: u8 = 0;
    pub const DEVICE_HW: u8 = 2;
}

/// Suites every `key_vault` build holds. `AEAD_KEY` needs no polynomial
/// scratch, so the smallest build carries it, and a resumption ticket cannot
/// be sealed without it.
const SUITES_BASE: &[u16] = &[
    vault_suite::P256,
    vault_suite::ED25519,
    vault_suite::AEAD_KEY,
];
/// What the `ml_dsa` feature of `key_vault` adds.
const SUITES_ML_DSA: &[u16] = &[
    vault_suite::ML_DSA_44,
    vault_suite::ML_DSA_65,
    vault_suite::ML_DSA_87,
];
/// What the `rsa` feature of `key_vault` adds.
const SUITES_RSA: &[u16] = &[
    vault_suite::RSA_2048,
    vault_suite::RSA_3072,
    vault_suite::RSA_4096,
];

/// The suites a `key_vault` build with `features` holds
/// (`modules/foundation/key_vault/manifest.toml`'s `[[variant]]`s): the base
/// set, plus ML-DSA with `ml_dsa` and RSA with `rsa`. Which suites a graph
/// can use is a fact of the vault variant it composes, not of the target.
pub fn key_vault_suites(features: &[String]) -> Vec<u16> {
    let mut suites = SUITES_BASE.to_vec();
    if features.iter().any(|f| f == "ml_dsa") {
        suites.extend_from_slice(SUITES_ML_DSA);
    }
    if features.iter().any(|f| f == "rsa") {
        suites.extend_from_slice(SUITES_RSA);
    }
    suites
}

/// Where a target's sealing key comes from (`hal::seal_provenance`), which
/// `SEAL_KEY_DERIVE` answers from.
pub mod seal_provenance {
    /// Read from the device's own one-time-programmable fuses.
    pub const DEVICE_UNIQUE: &str = "device_unique";
    /// Supplied by the host (`FLUXOR_SEAL_KEY`), readable to whoever
    /// administers it.
    pub const HOST_READABLE: &str = "host_readable";
}

/// The ip module's published ceilings on a target
/// (`crates/fluxor-abi/src/config.rs::ip`, per arch profile).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetCeilings {
    /// Locally terminated TCP connections (`MAX_TCP_CONNS`).
    pub tcp_connections: u32,
    /// Datagram endpoints (`MAX_DG_ENDPOINTS`; the u8 `ep_id` window).
    pub datagram_endpoints: u32,
    /// Local addresses, primary included (`MAX_LOCAL_ADDRS`).
    pub local_addresses: u32,
    /// Packets the profile sizes the decision seam for (`MAX_PACKET_HOLD`,
    /// the figure a graph turning the seam on declares as `ip`'s
    /// `packet_holds`).
    pub packet_hold: u32,
}

/// The aarch64 host profile: linux and the bcm2712 boards.
const NET_HOST: NetCeilings = NetCeilings {
    tcp_connections: 65536,
    datagram_endpoints: 256,
    local_addresses: 4096,
    packet_hold: 32,
};
/// The wasm32 profile.
const NET_WASM: NetCeilings = NetCeilings {
    tcp_connections: 256,
    datagram_endpoints: 256,
    local_addresses: 8,
    packet_hold: 8,
};
/// The embedded (RP-class) profile.
const NET_EMBEDDED: NetCeilings = NetCeilings {
    tcp_connections: 8,
    datagram_endpoints: 8,
    local_addresses: 8,
    packet_hold: 4,
};

/// The CPU time one cooperative `module_step` may take on a target, in
/// microseconds: the scheduler's per-domain pass budget at the default tick
/// (`src/kernel/exec/scheduler/mod.rs::DEFAULT_TICK_US`, which
/// `setup.rs` installs as `domain_budget_us_limit` when a config names no
/// tick). A module's `[execution] max_step_us` is admitted against this
/// for every silicon it targets; a step that cannot fit one default pass
/// on its slowest silicon has no honest envelope there. Every silicon
/// runs the same default tick, so every row carries the same value; the
/// per-row shape is what lets a slower part publish a smaller budget.
pub const STEP_BUDGET_DEFAULT_TICK_US: u32 = 1000;

/// What one target's platform provides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetFacts {
    /// `time.wall` `source`: the strongest source class the HAL can report
    /// `TRUSTED` for, or `None` when the target has no calendar clock the
    /// kernel would ever vouch for.
    pub time_wall_source: Option<&'static str>,
    /// Whether a `trust` provider is registered on this target — the
    /// platform's own verifier, which `trust = "system"` asks. Only the
    /// Linux host carries one; bare metal and wasm hold no public root set
    /// and a graph asking for one there is refused at compose rather than
    /// discovering it at the first handshake.
    pub trust_system: bool,
    /// Where the platform's sealing key comes from
    /// ([`seal_provenance`]), or `None` when the platform has none
    /// (`SEAL_KEY_DERIVE` answers `ENOSYS`): a `key_vault` there cannot
    /// seal its records under it (`seal = hardware`).
    pub seal_provenance: Option<&'static str>,
    /// The highest custody a key vault can report here: the custody
    /// `SealProvenance::DeviceUnique` raises it to where the platform reads
    /// a device-unique sealing key, `SOFTWARE` everywhere else.
    pub vault_custody_ceiling: u8,
    /// The ip module's ceilings on this target — what a composition
    /// claiming a connection or address count is admitted against.
    pub net: NetCeilings,
    /// Exclusive CPU time one `module_step` may declare on this target
    /// (`[execution] max_step_us`), in microseconds.
    pub step_budget_us: u32,
    /// The platform's NIC driver answers the transmit-drain query
    /// (`net::identity::tx_drain`), so a `fence.enforceable` fence from
    /// the ip module reports `cutoff = "wire"` rather than the ring
    /// hand-off. True only where a Fluxor driver owns the transmit ring;
    /// a hosted stack's wire belongs to its host kernel.
    pub nic_tx_drain: bool,
    /// `counter.cycles` `clock` and `counter.icache` `scope`: what the
    /// target's counters count, from its `[counters]` table. Filled by
    /// [`TargetFacts::for_target`]; a row answered by name alone
    /// ([`TargetFacts::for_runtime`]) has read no target file and carries
    /// neither.
    pub counters: crate::target::CounterFacts,
}

/// A row that has read no target file.
const NO_COUNTERS: crate::target::CounterFacts = crate::target::CounterFacts {
    cycles: None,
    icache: None,
};

impl TargetFacts {
    /// Facts for a loaded target: its runtime's row, and what its own file
    /// declares.
    pub fn for_target(target: &crate::target::TargetDescriptor) -> Self {
        Self {
            counters: target.counters,
            ..Self::for_runtime(target.runtime())
        }
    }

    /// Facts for a runtime id. Unknown names answer the weakest
    /// row — no clock, no sealing key, software custody — so a requirement on an
    /// unregistered target fails closed.
    pub fn for_runtime(name: &str) -> Self {
        match name {
            // Hosted on an operating system that runs a time protocol:
            // `adjtimex(2)` says whether the clock is disciplined.
            "linux" => Self {
                time_wall_source: Some("network_sync"),
                trust_system: true,
                seal_provenance: Some(seal_provenance::HOST_READABLE),
                vault_custody_ceiling: vault_custody::SOFTWARE,
                net: NET_HOST,
                step_budget_us: STEP_BUDGET_DEFAULT_TICK_US,
                nic_tx_drain: false,
                counters: NO_COUNTERS,
            },
            // Bare metal with no RTC: the kernel vouches for wall time once
            // a time-sync module (`sntp`) anchors it from a quorum of
            // servers. An OTP-read device-unique sealing key when
            // provisioned; the rp1_gem driver owns the transmit ring and
            // reports it drained.
            "bcm2712" => Self {
                time_wall_source: Some("network_sync"),
                trust_system: false,
                seal_provenance: Some(seal_provenance::DEVICE_UNIQUE),
                vault_custody_ceiling: vault_custody::DEVICE_HW,
                net: NET_HOST,
                step_budget_us: STEP_BUDGET_DEFAULT_TICK_US,
                nic_tx_drain: true,
                counters: NO_COUNTERS,
            },
            // Bare metal on firmware that hands the wall clock over once, at
            // handoff, and no sealing key — a cloud guest is offered none —
            // so the vault stays software. No Fluxor driver owns a transmit
            // ring, so none reports one drained.
            "uefi" => Self {
                time_wall_source: Some("network_sync"),
                trust_system: false,
                seal_provenance: None,
                vault_custody_ceiling: vault_custody::SOFTWARE,
                net: NET_HOST,
                step_budget_us: STEP_BUDGET_DEFAULT_TICK_US,
                nic_tx_drain: false,
                counters: NO_COUNTERS,
            },
            // No RTC, but the kernel vouches for wall time once `sntp`
            // anchors it, as on bcm2712; an OTP seal key when provisioned (`rp_otp_seal`, unproven on
            // hardware).
            "rp2350" => Self {
                time_wall_source: Some("network_sync"),
                trust_system: false,
                seal_provenance: Some(seal_provenance::DEVICE_UNIQUE),
                vault_custody_ceiling: vault_custody::DEVICE_HW,
                net: NET_EMBEDDED,
                step_budget_us: STEP_BUDGET_DEFAULT_TICK_US,
                nic_tx_drain: false,
                counters: NO_COUNTERS,
            },
            // No RTC and no `sntp` build, no OTP and so no sealing key.
            "rp2040" => Self {
                time_wall_source: None,
                trust_system: false,
                seal_provenance: None,
                vault_custody_ceiling: vault_custody::SOFTWARE,
                net: NET_EMBEDDED,
                step_budget_us: STEP_BUDGET_DEFAULT_TICK_US,
                nic_tx_drain: false,
                counters: NO_COUNTERS,
            },
            // The browser host offers no synchronisation evidence.
            "wasm" => Self {
                time_wall_source: None,
                trust_system: false,
                seal_provenance: None,
                vault_custody_ceiling: vault_custody::SOFTWARE,
                net: NET_WASM,
                step_budget_us: STEP_BUDGET_DEFAULT_TICK_US,
                nic_tx_drain: false,
                counters: NO_COUNTERS,
            },
            _ => Self {
                time_wall_source: None,
                trust_system: false,
                seal_provenance: None,
                vault_custody_ceiling: vault_custody::SOFTWARE,
                net: NET_EMBEDDED,
                step_budget_us: STEP_BUDGET_DEFAULT_TICK_US,
                nic_tx_drain: false,
                counters: NO_COUNTERS,
            },
        }
    }

    /// The value of `fact` under target-provided `capability`, or `None`
    /// when this target does not provide the capability. Facts are the
    /// ones `CAPABILITY_FACTS` admits for the capability.
    pub fn fact(&self, capability: &str, fact: &str) -> Option<&'static str> {
        match (capability, fact) {
            ("time.wall", "source") => self.time_wall_source,
            ("counter.cycles", "clock") => self.counters.cycles,
            ("counter.icache", "scope") => self.counters.icache,
            _ => None,
        }
    }

    /// The `cutoff` the ip module's `fence.enforceable` reaches on this
    /// target: `wire` where the NIC driver drains on request, the
    /// manifest's own `ring_handoff` elsewhere.
    pub fn ip_fence_cutoff(&self) -> &'static str {
        if self.nic_tx_drain {
            "wire"
        } else {
            "ring_handoff"
        }
    }

    /// Whether Fluxor owns the whole transport state machine on this
    /// target — the condition under which a stream or mux anchor may
    /// claim continuity across a host loss. A hosted stack's TCP lives in
    /// the host kernel and cannot be checkpointed.
    pub fn owns_transport(silicon: &str) -> bool {
        !matches!(silicon, "linux" | "wasm")
    }

    /// Whether this target provides `capability` at all: a target-provided
    /// capability is present exactly when its defining fact has a value.
    pub fn provides(&self, capability: &str) -> bool {
        // `trust.system` carries no facts: a platform verifier either
        // answers or it does not, and there is nothing further to describe
        // about one. It is therefore a bare boolean rather than a
        // fact-defined capability.
        if capability == "trust.system" {
            return self.trust_system;
        }
        let defining_fact = match capability {
            "time.wall" => "source",
            "counter.cycles" => "clock",
            "counter.icache" => "scope",
            _ => return false,
        };
        self.fact(capability, defining_fact).is_some()
    }
}

/// True when `capability` is one a TARGET answers rather than a module.
pub fn is_target_capability(capability: &str) -> bool {
    TARGET_CAPABILITIES.contains(&capability)
}

/// How one `when` condition resolved against a placed instance. The
/// composer resolves it through the module's parameter schema; this module
/// only judges the outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamResolution {
    /// The module carries no parameter schema to resolve against.
    NoSchema,
    /// The schema declares no such parameter, or none of the listed values.
    Undeclared,
    /// Whether the effective value is one of the condition's values.
    Matches(bool),
}

/// One `[[requires_when]]` entry against one placed module instance,
/// `resolutions` being one outcome per `when` condition in order.
///
/// Refuses when every condition holds and the target does not provide the
/// capability, or provides it with a fact the entry does not accept — and refuses when any condition cannot be resolved at all,
/// since a requirement nobody can evaluate is not one that has been met.
///
/// `active` is one outcome per `active_when_params` name: whether the
/// instance sets it non-empty (`None`, a param the schema does not
/// declare). The entry holds when its `when` does and, naming any, one of
/// them is set.
pub fn check_requires_when(
    resolutions: &[ParamResolution],
    active: &[Option<bool>],
    rw: &crate::manifest::RequiresWhen,
    facts: &TargetFacts,
    runtime: &str,
) -> Result<()> {
    if let Some((param, _)) = rw
        .active_when_params
        .iter()
        .zip(active)
        .find(|(_, a)| a.is_none())
    {
        return Err(Error::Config(format!(
            "`[[requires_when]]` names parameter `{param}` in `active_when_params`, which the \
             module's schema does not declare"
        )));
    }
    let mut triggered = rw.active_when_params.is_empty() || active.contains(&Some(true));
    for ((param, values), resolution) in rw.when.iter().zip(resolutions) {
        match resolution {
            ParamResolution::NoSchema => {
                return Err(Error::Config(format!(
                    "`[[requires_when]]` names parameter `{param}` but the module carries no \
                     parameter schema to resolve it against"
                )));
            }
            ParamResolution::Undeclared => {
                return Err(Error::Config(format!(
                    "`[[requires_when]]` names parameter `{param}` = {}, which the module's \
                     schema does not declare",
                    values.join(" | ")
                )));
            }
            ParamResolution::Matches(m) => triggered &= *m,
        }
    }
    if resolutions.len() != rw.when.len() {
        return Err(Error::Config(
            "`[[requires_when]]` conditions were not all resolved".to_string(),
        ));
    }
    if triggered && !facts.provides(&rw.capability) {
        let mut posture: Vec<String> = rw
            .when
            .iter()
            .map(|(p, v)| format!("`{p}` = {}", v.join(" | ")))
            .collect();
        if !rw.active_when_params.is_empty() {
            posture.push(format!("`{}` set", rw.active_when_params.join("` or `")));
        }
        let params: Vec<&str> = rw
            .when
            .iter()
            .map(|(p, _)| p.as_str())
            .chain(rw.active_when_params.iter().map(String::as_str))
            .collect();
        return Err(Error::Config(format!(
            "{} requires target capability `{}`, which runtime `{}` does not provide. Either \
             place this module on a target that does, or choose a value of {} that does not \
             need it.",
            posture.join(" with "),
            rw.capability,
            runtime,
            params.join(" / "),
        )));
    }
    if triggered {
        for (fact, wanted) in &rw.facts {
            let has = facts.fact(&rw.capability, fact);
            if !has.is_some_and(|v| wanted.iter().any(|w| w == v)) {
                return Err(Error::Config(format!(
                    "requires target capability `{}` with `{fact}` = {}, but runtime `{}` \
                     provides `{fact}` = {}. Place this module on a target whose `{}` is \
                     what it needs.",
                    rw.capability,
                    wanted.join(" | "),
                    runtime,
                    has.unwrap_or("none"),
                    rw.capability,
                )));
            }
        }
    }
    Ok(())
}

/// Admit the graph's execution-envelope claim
/// against what its modules declare.
///
/// The top-level block names the profile the whole graph claims:
///
/// ```yaml
/// execution:
///   profile: analytical_bound | measured_envelope
/// ```
///
/// A graph claims nothing without it. With it, the claim is only as good as
/// its weakest member, so admission is per instantiated module:
///
///   * `analytical_bound` — every module must carry `[execution]` with
///     `profile = "analytical_bound"`, and the target must be bare metal.
///     A hosted runtime's tail belongs to the host scheduler, not to the
///     module, so Linux and wasm publish the measured profile only; a graph
///     resolved against no known target cannot show the evidence either.
///   * `measured_envelope` — every module must carry `[execution]` at all.
///     A measured module beside an unmeasured one is an envelope with a
///     hole in it, whichever profile the measured one holds.
///
/// The refusal names every offending module so one pass fixes the graph.
///
/// What is admitted here is the presence and kind of each module's claim.
/// The lane arithmetic — summing the admitted quanta and dispatch costs of
/// a scheduler round, composing a service curve with an arrival envelope,
/// and checking each edge's backlog and deadline — is a separate mechanism
/// with its own evidence requirements, and a graph that passes here holds
/// no derived latency bound.
pub fn admit_execution_profile<S: std::hash::BuildHasher>(
    config: &serde_json::Value,
    module_names: &[String],
    manifests: &std::collections::HashMap<String, Manifest, S>,
    target: Option<&str>,
) -> Result<()> {
    let Some(block) = config.get("execution") else {
        return Ok(());
    };
    let Some(profile) = block.get("profile") else {
        return Ok(());
    };
    let profile_str = profile
        .as_str()
        .ok_or_else(|| Error::Config("execution.profile must be a string".into()))?;
    let claimed = ExecutionProfile::from_str_opt(profile_str).ok_or_else(|| {
        Error::Config(format!(
            "execution.profile = \"{profile_str}\" is invalid; expected one of {}",
            ExecutionProfile::NAMES.join(" | ")
        ))
    })?;

    let hosted = matches!(target, Some("linux") | Some("wasm"));
    if claimed == ExecutionProfile::AnalyticalBound {
        match target {
            None => {
                return Err(Error::Config(
                    "execution.profile = \"analytical_bound\" needs a resolved target: the \
                     bound is a claim about one silicon's scheduling, and none is named"
                        .into(),
                ));
            }
            Some(t) if hosted => {
                return Err(Error::Config(format!(
                    "execution.profile = \"analytical_bound\" is not admissible on `{t}`: a \
                     hosted runtime's latency tail belongs to the host scheduler, so the \
                     honest profile there is \"measured_envelope\""
                )));
            }
            Some(_) => {}
        }
    }

    let mut undeclared: Vec<&str> = Vec::new();
    let mut measured_only: Vec<&str> = Vec::new();
    for name in module_names {
        match manifests.get(name).and_then(|m| m.execution.as_ref()) {
            None => undeclared.push(name),
            Some(e)
                if claimed == ExecutionProfile::AnalyticalBound
                    && e.profile != ExecutionProfile::AnalyticalBound =>
            {
                measured_only.push(name)
            }
            Some(_) => {}
        }
    }
    if !undeclared.is_empty() {
        return Err(Error::Config(format!(
            "execution.profile = \"{profile_str}\" claims an envelope for the whole graph, \
             but {} declare(s) no [execution] facts; a module with no facts cannot be part \
             of the claim. Measure it (`max_step_us`, `max_dispatch_us`, `profile`, \
             `evidence` in its manifest.toml) or drop the claim.",
            undeclared
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    if !measured_only.is_empty() {
        return Err(Error::Config(format!(
            "execution.profile = \"analytical_bound\" claims a hard bound, but {} carry \
             only a measured envelope (`profile = \"measured_envelope\"`); the graph's \
             honest profile is \"measured_envelope\" until every module is bounded.",
            measured_only
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(())
}
