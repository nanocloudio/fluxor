//! Per-target facts about what the PLATFORM provides, as opposed to what a
//! module declares: the calendar-time source its HAL can vouch for, the key
//! suites its vault holds, and the custody tier its vault can reach.
//!
//! These are properties of the kernel build and the silicon, so no manifest
//! carries them and no graph wires them. The composer answers them from this
//! table, and a manifest binds to them through `[[requires_when]]` — a
//! module that needs a trustworthy clock only under one of its own
//! parameter values says so and is refused at compose on a target that
//! cannot back it, rather than at its first handshake.
//!
//! Values mirror kernel source and are pinned against it by
//! `target_facts_mirror_kernel_sources` in `tools/tests/target_facts.rs`;
//! every fact value is admitted by `CAPABILITY_FACTS` and pinned by the same
//! test. Silicon keys match `manifest::TargetCapabilities::for_silicon` —
//! board names resolve through the `targets/` registry before reaching here.

use fluxor_contracts::vocabulary::TARGET_CAPABILITIES;

use crate::error::{Error, Result};

/// Vault key suites, `modules/sdk/contracts/key_vault.rs::suite`.
pub mod vault_suite {
    pub const P256: u16 = 1;
    pub const ED25519: u16 = 2;
    pub const ML_DSA_44: u16 = 4;
    pub const ML_DSA_65: u16 = 5;
    pub const ML_DSA_87: u16 = 6;
}

/// Vault custody tiers, `modules/sdk/contracts/key_vault.rs::tier`.
pub mod vault_tier {
    pub const SOFTWARE: u8 = 0;
    pub const DEVICE_HW: u8 = 2;
}

/// Suites every kernel vault holds.
const SUITES_BASE: &[u16] = &[vault_suite::P256, vault_suite::ED25519];
/// Suites a kernel built with the `pq-vault` feature adds.
const SUITES_PQ: &[u16] = &[
    vault_suite::P256,
    vault_suite::ED25519,
    vault_suite::ML_DSA_44,
    vault_suite::ML_DSA_65,
    vault_suite::ML_DSA_87,
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
            },
            // Bare metal with no RTC and no time source; an OTP-read
            // device-unique sealing key when provisioned.
            "bcm2712" => Self {
                time_wall_source: None,
                vault_suites: SUITES_PQ,
                vault_tier_ceiling: vault_tier::DEVICE_HW,
                net: NET_HOST,
            },
            // No RTC, no room for the ML-DSA scratch, no sealing.
            "rp2040" | "rp2350" => Self {
                time_wall_source: None,
                vault_suites: SUITES_BASE,
                vault_tier_ceiling: vault_tier::SOFTWARE,
                net: NET_EMBEDDED,
            },
            // The browser host offers no synchronisation evidence.
            "wasm" => Self {
                time_wall_source: None,
                vault_suites: SUITES_PQ,
                vault_tier_ceiling: vault_tier::SOFTWARE,
                net: NET_WASM,
            },
            _ => Self {
                time_wall_source: None,
                vault_suites: SUITES_BASE,
                vault_tier_ceiling: vault_tier::SOFTWARE,
                net: NET_EMBEDDED,
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
