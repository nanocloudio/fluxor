//! Per-target facts about what the PLATFORM provides, as opposed to what a
//! module declares: the calendar-time source its HAL can vouch for, the key
//! suites its vault holds, the custody tier its vault can reach, and the
//! step budget its scheduler grants a module.
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
//! keys are those of `manifest::TargetCapabilities::for_silicon` — board names
//! resolve through the `targets/` registry before reaching here.

use fluxor_contracts::vocabulary::TARGET_CAPABILITIES;

use crate::error::{Error, Result};
use crate::manifest::{ExecutionProfile, Manifest};

/// Vault key suites, `modules/sdk/contracts/key_vault.rs::suite`.
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

/// Vault custody tiers, `modules/sdk/contracts/key_vault.rs::tier`.
pub mod vault_tier {
    pub const SOFTWARE: u8 = 0;
    pub const DEVICE_HW: u8 = 2;
}

/// Suites every kernel vault holds. `AEAD_KEY` is here because it is
/// ungated in `src/kernel/security/key_vault.rs` — unlike the ML-DSA
/// suites it needs no polynomial scratch, so the smallest part carries it
/// — and a resumption ticket cannot be sealed without it.
const SUITES_BASE: &[u16] = &[
    vault_suite::P256,
    vault_suite::ED25519,
    vault_suite::AEAD_KEY,
];
/// Suites a kernel built with the `pq-vault` and `rsa-vault` features
/// adds. The two are enabled together: both are a question of kernel
/// static RAM, and every target with room for one has room for the other.
const SUITES_PQ: &[u16] = &[
    vault_suite::P256,
    vault_suite::ED25519,
    vault_suite::AEAD_KEY,
    vault_suite::ML_DSA_44,
    vault_suite::ML_DSA_65,
    vault_suite::ML_DSA_87,
    vault_suite::RSA_2048,
    vault_suite::RSA_3072,
    vault_suite::RSA_4096,
];

/// The ip module's published ceilings on a target
/// (`modules/sdk/abi/config.rs::ip`, per arch profile).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetCeilings {
    /// Locally terminated TCP connections (`MAX_TCP_CONNS`).
    pub tcp_connections: u32,
    /// Datagram endpoints (`MAX_DG_ENDPOINTS`; the u8 `ep_id` window).
    pub datagram_endpoints: u32,
    /// Local addresses, primary included (`MAX_LOCAL_ADDRS`).
    pub local_addresses: u32,
    /// Packets the decision seam may hold (`MAX_PACKET_HOLD`).
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
    tcp_connections: 16,
    datagram_endpoints: 16,
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
    /// Key suites the kernel vault holds on this target.
    pub vault_suites: &'static [u16],
    /// The highest custody tier the kernel vault can report here: the tier
    /// `SealProvenance::DeviceUnique` raises it to where the platform reads
    /// a device-unique sealing key, `SOFTWARE` everywhere else.
    pub vault_tier_ceiling: u8,
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
}

impl TargetFacts {
    /// Facts for a silicon or host id. Unknown names answer the weakest
    /// row — no clock, base suites, software tier — so a requirement on an
    /// unregistered target fails closed.
    pub fn for_silicon(name: &str) -> Self {
        match name {
            // Hosted on an operating system that runs a time protocol:
            // `adjtimex(2)` says whether the clock is disciplined.
            "linux" => Self {
                time_wall_source: Some("network_sync"),
                vault_suites: SUITES_PQ,
                vault_tier_ceiling: vault_tier::SOFTWARE,
                net: NET_HOST,
                step_budget_us: STEP_BUDGET_DEFAULT_TICK_US,
                nic_tx_drain: false,
            },
            // Bare metal with no RTC and no time source; an OTP-read
            // device-unique sealing key when provisioned; the rp1_gem
            // driver owns the transmit ring and reports it drained.
            "bcm2712" => Self {
                time_wall_source: None,
                vault_suites: SUITES_PQ,
                vault_tier_ceiling: vault_tier::DEVICE_HW,
                net: NET_HOST,
                step_budget_us: STEP_BUDGET_DEFAULT_TICK_US,
                nic_tx_drain: true,
            },
            // No RTC, no room for the ML-DSA scratch, no sealing.
            "rp2040" | "rp2350" => Self {
                time_wall_source: None,
                vault_suites: SUITES_BASE,
                vault_tier_ceiling: vault_tier::SOFTWARE,
                net: NET_EMBEDDED,
                step_budget_us: STEP_BUDGET_DEFAULT_TICK_US,
                nic_tx_drain: false,
            },
            // The browser host offers no synchronisation evidence.
            "wasm" => Self {
                time_wall_source: None,
                vault_suites: SUITES_PQ,
                vault_tier_ceiling: vault_tier::SOFTWARE,
                net: NET_WASM,
                step_budget_us: STEP_BUDGET_DEFAULT_TICK_US,
                nic_tx_drain: false,
            },
            _ => Self {
                time_wall_source: None,
                vault_suites: SUITES_BASE,
                vault_tier_ceiling: vault_tier::SOFTWARE,
                net: NET_EMBEDDED,
                step_budget_us: STEP_BUDGET_DEFAULT_TICK_US,
                nic_tx_drain: false,
            },
        }
    }

    /// The value of `fact` under target-provided `capability`, or `None`
    /// when this target does not provide the capability. Facts are the
    /// ones `CAPABILITY_FACTS` admits for the capability.
    pub fn fact(&self, capability: &str, fact: &str) -> Option<&'static str> {
        match (capability, fact) {
            ("time.wall", "source") => self.time_wall_source,
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
        let defining_fact = match capability {
            "time.wall" => "source",
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
/// capability — and refuses when any condition cannot be resolved at all,
/// since a requirement nobody can evaluate is not one that has been met.
pub fn check_requires_when(
    resolutions: &[ParamResolution],
    rw: &crate::manifest::RequiresWhen,
    facts: &TargetFacts,
    silicon: &str,
) -> Result<()> {
    let mut triggered = true;
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
        let posture: Vec<String> = rw
            .when
            .iter()
            .map(|(p, v)| format!("`{p}` = {}", v.join(" | ")))
            .collect();
        let params: Vec<&str> = rw.when.iter().map(|(p, _)| p.as_str()).collect();
        return Err(Error::Config(format!(
            "{} requires target capability `{}`, which silicon `{}` does not provide. Either \
             place this module on a target that does, or choose a value of {} that does not \
             need it.",
            posture.join(" with "),
            rw.capability,
            silicon,
            params.join(" / "),
        )));
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
