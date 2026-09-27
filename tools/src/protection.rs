//! Protection levels: what a graph asks for, and what a target gives.
//!
//! One resolution serves the validator, the stack and state admission, and
//! the config builder, so the level the composer admits is the level the
//! kernel is told to enforce.
//!
//! A requested level is a floor. A target provides the weakest level it
//! implements that is at least the one asked for, and refuses a request above
//! everything it implements. `none` and `guarded` are implemented everywhere:
//! every kernel steps every module under the step guard. `contained` and
//! `isolated` are implemented where a backend is compiled in, which the
//! target publishes as `[isolation] levels`.

use serde_json::Value;

/// A protection level, ordered from weakest. The discriminant is the wire
/// value of config tag 0xF5; `>= Contained` means the module is gated
/// (unprivileged, reaching the kernel only through the gateway).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    None = 0,
    Guarded = 1,
    Contained = 2,
    Isolated = 3,
}

impl Level {
    pub const ALL: [Level; 4] = [
        Level::None,
        Level::Guarded,
        Level::Contained,
        Level::Isolated,
    ];

    pub fn parse(s: &str) -> Option<Level> {
        match s {
            "none" => Some(Level::None),
            "guarded" => Some(Level::Guarded),
            "contained" => Some(Level::Contained),
            "isolated" => Some(Level::Isolated),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Level::None => "none",
            Level::Guarded => "guarded",
            Level::Contained => "contained",
            Level::Isolated => "isolated",
        }
    }

    /// Whether a module at this level is unprivileged behind the gateway.
    pub fn is_gated(self) -> bool {
        self >= Level::Contained
    }
}

/// A module's trust tier, the default source of its protection level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Platform = 0,
    Verified = 1,
    Community = 2,
    Unsigned = 3,
}

impl Tier {
    pub fn parse(s: &str) -> Option<Tier> {
        match s {
            "platform" => Some(Tier::Platform),
            "verified" => Some(Tier::Verified),
            "community" => Some(Tier::Community),
            "unsigned" => Some(Tier::Unsigned),
            _ => None,
        }
    }

    /// The level a tier implies when the graph names none.
    pub fn default_level(self) -> Level {
        match self {
            Tier::Platform => Level::None,
            Tier::Verified => Level::Guarded,
            Tier::Community | Tier::Unsigned => Level::Isolated,
        }
    }
}

/// Where a requested level came from, for the message that refuses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Module,
    Graph,
    Tier(Tier),
}

/// One module's resolved protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolution {
    pub tier: Tier,
    pub requested: Level,
    pub source: Source,
    /// What the target provides: the weakest implemented level at or above
    /// `requested`.
    pub provided: Level,
}

fn graph_str<'a>(config: &'a Value, key: &str) -> Option<&'a str> {
    config.get(key).and_then(|v| v.as_str()).or_else(|| {
        config
            .get("graph")
            .and_then(|g| g.get(key))
            .and_then(|v| v.as_str())
    })
}

/// The tier and requested level for `module`, before admission. An
/// unrecognised string is an error, not a default.
pub fn requested(module: &Value, config: &Value) -> Result<(Tier, Level, Source), String> {
    let tier_str = module
        .get("trust_tier")
        .and_then(|v| v.as_str())
        .or_else(|| graph_str(config, "default_trust_tier"))
        .unwrap_or("platform");
    let tier = Tier::parse(tier_str).ok_or_else(|| {
        format!(
            "invalid trust_tier '{tier_str}' (expected platform, verified, community or unsigned)"
        )
    })?;
    let (explicit, source) = match module.get("protection").and_then(|v| v.as_str()) {
        Some(p) => (Some(p), Source::Module),
        None => (graph_str(config, "protection"), Source::Graph),
    };
    match explicit {
        Some(p) => {
            let level = Level::parse(p).ok_or_else(|| {
                format!("invalid protection '{p}' (expected none, guarded, contained or isolated)")
            })?;
            Ok((tier, level, source))
        }
        None => Ok((tier, tier.default_level(), Source::Tier(tier))),
    }
}

/// The level a target provides for `requested`, given the gated levels it
/// implements, or `None` if it implements nothing at or above it.
pub fn provided(requested: Level, implemented: &[Level]) -> Option<Level> {
    Level::ALL
        .into_iter()
        .find(|&l| l >= requested && (l <= Level::Guarded || implemented.contains(&l)))
}

/// Resolve `module` against a target that implements `implemented`.
pub fn resolve(
    module: &Value,
    config: &Value,
    implemented: &[Level],
) -> Result<Resolution, String> {
    let (tier, requested, source) = requested(module, config)?;
    let provided = provided(requested, implemented).ok_or_else(|| {
        let what = match source {
            Source::Module => "asks for".to_string(),
            Source::Graph => "takes the graph's".to_string(),
            Source::Tier(t) => format!("is trust_tier {t:?}, which implies"),
        };
        let has = if implemented.is_empty() {
            "none and guarded only".to_string()
        } else {
            let mut v: Vec<&str> = vec!["none", "guarded"];
            v.extend(implemented.iter().map(|l| l.name()));
            v.join(", ")
        };
        format!(
            "{what} protection: {}, which this target does not implement (it has {has}). \
             Set `protection:` explicitly to a level it has — a recorded downgrade — or \
             deploy to a target that isolates.",
            requested.name()
        )
    })?;
    Ok(Resolution {
        tier,
        requested,
        source,
        provided,
    })
}

/// The module type names a module entry refers to (`name`, or `type` when it
/// instantiates another type), paired with the entry.
pub fn module_entries(config: &Value) -> Vec<(String, &Value)> {
    match config.get("modules") {
        Some(Value::Array(list)) => list
            .iter()
            .filter_map(|m| {
                let name = m
                    .as_str()
                    .or_else(|| m.get("name").and_then(|n| n.as_str()))?;
                let ty = m.get("type").and_then(|t| t.as_str()).unwrap_or(name);
                Some((ty.to_string(), m))
            })
            .collect(),
        Some(Value::Object(map)) => map
            .iter()
            .map(|(name, m)| {
                let ty = m.get("type").and_then(|t| t.as_str()).unwrap_or(name);
                (ty.to_string(), m)
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Params a gated module's `module_new` receives are copied onto its own
/// stack; this is what the composer budgets for them.
pub const PARAMS_BUDGET: u64 = 256;

/// The private region (stack, state, heap) a gated module gets on an MPU
/// target: what the loader allocates, and so what the state arena is charged.
pub fn private_region_bytes(
    stack: u64,
    state: u64,
    arena: u64,
    frame: u64,
    model: fluxor_contracts::isolation::RegionModel,
) -> u64 {
    let stack = stack.next_multiple_of(8) + frame + PARAMS_BUDGET + 64;
    let state = (state + 4).next_multiple_of(8);
    let total = stack + state + arena.next_multiple_of(8);
    fluxor_contracts::isolation::private_region_shape(total, model).0
}

/// Whether an isolated module's code, which the packer starts on a 4 KiB
/// boundary, can be drawn as one region under `model`. Checked at the
/// worst-case base: page-aligned and nothing more.
pub fn code_plannable(code: u64, model: fluxor_contracts::isolation::RegionModel) -> bool {
    use fluxor_contracts::isolation::{region_plan, Access, Span};
    let len = fluxor_contracts::isolation::private_region_shape(code.max(1), model).0;
    region_plan(
        &[Span {
            base: 0x1000_1000,
            len,
            access: Access::ReadExec,
        }],
        model,
    )
    .is_ok()
}

/// One gated module as admission sees it.
pub struct Gated<'a> {
    pub name: &'a str,
    pub level: Level,
    /// The manifest's permission bits.
    pub permissions: u16,
    /// Contracts the module provides.
    pub provides: &'a [String],
    /// Bytes of code, for the isolated code-region check.
    pub code: u64,
}

/// Permission bits that reach past the gateway, and their manifest names.
pub const BEYOND_GATEWAY: &[(u16, &str)] = &[
    (crate::manifest::permission::RECONFIGURE, "reconfigure"),
    (crate::manifest::permission::FLASH_RAW, "flash_raw"),
    (
        crate::manifest::permission::BACKING_PROVIDER,
        "backing_provider",
    ),
    (crate::manifest::permission::PLATFORM_RAW, "platform_raw"),
    (crate::manifest::permission::MONITOR, "monitor"),
    (crate::manifest::permission::BRIDGE, "bridge"),
    (crate::manifest::permission::PCIE_DEVICE, "pcie_device"),
    (crate::manifest::permission::DMA, "dma"),
    (crate::manifest::permission::USB_HOST, "usb_host"),
];

/// Why a graph's gated modules cannot be admitted on a target with
/// `isolated_slots` slots (0 = no limit stated); empty when they can.
///
/// Refused: more isolated modules than there are slots; a gated module
/// holding any permission that reaches past the gateway; a gated module that
/// provides a contract, since other modules' calls into it would run its code
/// privileged.
pub fn gated_refusals(
    gated: &[Gated<'_>],
    isolated_slots: u32,
    target: &str,
    model: Option<fluxor_contracts::isolation::RegionModel>,
) -> Vec<String> {
    let mut out = Vec::new();
    // An isolated module on an MPU target reads and executes only its own
    // code, as one region; a model that cannot draw it is refused here, and
    // `contained` — which gives it all of flash — is the level that fits.
    if let Some(m) = model.filter(|m| !matches!(m, fluxor_contracts::isolation::RegionModel::Pages))
    {
        for g in gated.iter().filter(|g| g.level == Level::Isolated) {
            if !code_plannable(g.code, m) {
                out.push(format!(
                    "{} is isolated but its {} B of code cannot be drawn as one region on \
                     {target} at page alignment; use `protection: contained`, which gives it \
                     all of flash to read and execute",
                    g.name, g.code
                ));
            }
        }
    }
    let isolated = gated.iter().filter(|g| g.level == Level::Isolated).count();
    if isolated_slots > 0 && isolated > isolated_slots as usize {
        out.push(format!(
            "{isolated} modules are isolated but {target} isolates at most {isolated_slots} \
             at once ([isolation] isolated_slots)"
        ));
    }
    for g in gated {
        let held: Vec<&str> = BEYOND_GATEWAY
            .iter()
            .filter(|(bit, _)| g.permissions & bit != 0)
            .map(|(_, name)| *name)
            .collect();
        if !held.is_empty() {
            out.push(format!(
                "{} is {} but holds permission(s) {}, which reach past the gateway",
                g.name,
                g.level.name(),
                held.join(", ")
            ));
        }
        if !g.provides.is_empty() {
            out.push(format!(
                "{} is {} but provides {}; other modules' calls would run its code privileged",
                g.name,
                g.level.name(),
                g.provides.join(", ")
            ));
        }
    }
    out
}

/// The peripheral block a module's `device_window: <name>` names, resolved
/// against the target's grantable blocks: (base, size). `Ok(None)` when the
/// module asks for none.
pub fn device_window(
    module: &Value,
    ranges: &[(String, u64, u32)],
) -> Result<Option<(u64, u32)>, String> {
    let Some(w) = module.get("device_window") else {
        return Ok(None);
    };
    let name = w
        .as_str()
        .ok_or("device_window names a peripheral block, e.g. `device_window: pwm`")?;
    let found = ranges
        .iter()
        .find(|(n, _, _)| n == name)
        .map(|&(_, b, z)| (b, z));
    match found {
        Some(r) => Ok(Some(r)),
        None => {
            let known: Vec<&str> = ranges.iter().map(|(n, _, _)| n.as_str()).collect();
            Err(format!(
                "device_window '{name}' is not a block the target grants ([isolation] \
                 device_ranges: {})",
                if known.is_empty() {
                    "none".to_string()
                } else {
                    known.join(", ")
                }
            ))
        }
    }
}

/// Why a resolved device window cannot be granted, or `None`: the target
/// maps windows, the module is gated, and the model draws the window exactly.
pub fn window_refusal(
    window: (u64, u32),
    level: Level,
    device_windows: bool,
    model: Option<fluxor_contracts::isolation::RegionModel>,
) -> Option<String> {
    use fluxor_contracts::isolation::{region_plan, Access, Span};
    let (base, size) = (window.0, window.1 as u64);
    if !level.is_gated() {
        return Some(format!(
            "a device window is a grant to a gated module; at protection {} the module \
             already reaches every register",
            level.name()
        ));
    }
    if !device_windows {
        return Some("the target does not map device windows ([isolation] device_windows)".into());
    }
    let model = model?;
    let span = Span {
        base,
        len: size,
        access: Access::Device,
    };
    region_plan(&[span], model).err().map(|e| {
        format!("window 0x{base:x}+0x{size:x} cannot be drawn exactly as one region ({e:?})")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_request_is_a_floor() {
        use Level::{Contained, Guarded, Isolated};
        assert_eq!(provided(Contained, &[Isolated]), Some(Isolated));
        assert_eq!(provided(Contained, &[Contained, Isolated]), Some(Contained));
        assert_eq!(provided(Isolated, &[Contained]), Option::None);
        assert_eq!(provided(Guarded, &[]), Some(Guarded));
        assert_eq!(provided(Level::None, &[Isolated]), Some(Level::None));
    }

    #[test]
    fn module_beats_graph_beats_tier() {
        let cfg = json!({"protection": "guarded", "default_trust_tier": "community"});
        let m = json!({"name": "x", "protection": "contained"});
        assert_eq!(requested(&m, &cfg).unwrap().1, Level::Contained);
        let m = json!({"name": "x"});
        assert_eq!(requested(&m, &cfg).unwrap().1, Level::Guarded);
        let cfg = json!({"default_trust_tier": "community"});
        let (tier, level, _) = requested(&m, &cfg).unwrap();
        assert_eq!((tier, level), (Tier::Community, Level::Isolated));
    }

    #[test]
    fn the_default_tier_is_honoured_under_graph() {
        let cfg = json!({"graph": {"default_trust_tier": "verified"}});
        let m = json!({"name": "x"});
        assert_eq!(requested(&m, &cfg).unwrap().1, Level::Guarded);
    }

    #[test]
    fn unknown_strings_are_errors() {
        let cfg = json!({});
        assert!(requested(&json!({"name": "x", "protection": "sandboxed"}), &cfg).is_err());
        assert!(requested(&json!({"name": "x", "trust_tier": "trusted"}), &cfg).is_err());
    }

    #[test]
    fn isolated_modules_are_admitted_against_the_slots() {
        let none: Vec<String> = Vec::new();
        let g = |name| Gated {
            name,
            level: Level::Isolated,
            permissions: 0,
            provides: &none,
            code: 1024,
        };
        assert!(gated_refusals(&[g("a"), g("b")], 2, "bcm2712", None).is_empty());
        let r = gated_refusals(&[g("a"), g("b"), g("c")], 2, "bcm2712", None);
        assert_eq!(r.len(), 1);
        assert!(
            r[0].contains("3 modules are isolated but bcm2712 isolates at most 2"),
            "{r:?}"
        );
        // Contained modules take no isolated slot.
        let c = Gated {
            name: "c",
            level: Level::Contained,
            permissions: 0,
            provides: &none,
            code: 1024,
        };
        assert!(gated_refusals(&[g("a"), g("b"), c], 2, "x", None).is_empty());
    }

    #[test]
    fn a_gated_module_holds_no_permission_past_the_gateway() {
        let none: Vec<String> = Vec::new();
        let raw = Gated {
            name: "drv",
            level: Level::Isolated,
            permissions: crate::manifest::permission::PLATFORM_RAW
                | crate::manifest::permission::DMA,
            provides: &none,
            code: 1024,
        };
        let r = gated_refusals(&[raw], 0, "x", None);
        assert!(r[0].contains("platform_raw, dma"), "{r:?}");
        let observe = Gated {
            name: "obs",
            level: Level::Isolated,
            permissions: crate::manifest::permission::OBSERVE,
            provides: &none,
            code: 1024,
        };
        assert!(
            gated_refusals(&[observe], 0, "x", None).is_empty(),
            "OBSERVE is read-only"
        );
    }

    #[test]
    fn a_gated_module_provides_no_contract() {
        let provides = vec!["storage.object".to_string()];
        let p = Gated {
            name: "fs",
            level: Level::Contained,
            permissions: 0,
            provides: &provides,
            code: 1024,
        };
        let r = gated_refusals(&[p], 0, "x", None);
        assert!(r[0].contains("provides storage.object"), "{r:?}");
    }

    #[test]
    fn large_code_is_isolated_on_pmsav8_and_contained_on_pmsav7() {
        use fluxor_contracts::isolation::RegionModel;
        let v7 = RegionModel::Pmsav7 { regions: 8 };
        let v8 = RegionModel::Pmsav8 { regions: 8 };
        assert!(
            code_plannable(4096, v7),
            "a page of code at a page boundary"
        );
        assert!(
            !code_plannable(40 * 1024, v7),
            "needs a 64 KiB-aligned region"
        );
        assert!(code_plannable(40 * 1024, v8));
        let none: Vec<String> = Vec::new();
        let big = Gated {
            name: "ip",
            level: Level::Isolated,
            permissions: 0,
            provides: &none,
            code: 40 * 1024,
        };
        let r = gated_refusals(&[big], 0, "rp2040", Some(v7));
        assert!(r[0].contains("use `protection: contained`"), "{r:?}");
        let big = Gated {
            name: "ip",
            level: Level::Contained,
            permissions: 0,
            provides: &none,
            code: 40 * 1024,
        };
        assert!(gated_refusals(&[big], 0, "rp2040", Some(v7)).is_empty());
    }

    #[test]
    fn a_shortfall_names_the_levels_the_target_has() {
        let cfg = json!({});
        let m = json!({"name": "x", "trust_tier": "community"});
        let e = resolve(&m, &cfg, &[Level::Contained]).unwrap_err();
        assert!(e.contains("none, guarded, contained"), "{e}");
        let r = resolve(
            &json!({"name": "x", "trust_tier": "community", "protection": "contained"}),
            &cfg,
            &[Level::Contained],
        )
        .unwrap();
        assert_eq!(r.provided, Level::Contained);
    }

    #[test]
    fn a_device_window_names_a_block_the_target_grants() {
        let ranges = vec![("sysinfo".to_string(), 0x4000_0000u64, 0x4000u32)];
        let m = json!({"name": "d", "device_window": "sysinfo"});
        assert_eq!(device_window(&m, &ranges), Ok(Some((0x4000_0000, 0x4000))));
        assert_eq!(device_window(&json!({"name": "d"}), &ranges), Ok(None));
        let e = device_window(&json!({"device_window": "timer"}), &ranges).unwrap_err();
        assert!(e.contains("sysinfo"), "names what the target grants: {e}");
        assert!(device_window(&json!({"device_window": {"base": 0}}), &ranges).is_err());
    }

    #[test]
    fn a_device_window_is_refused_unless_gated_mapped_and_drawable() {
        use fluxor_contracts::isolation::RegionModel;
        let v7 = Some(RegionModel::Pmsav7 { regions: 8 });
        let w = (0x4000_0000, 0x4000);
        assert_eq!(window_refusal(w, Level::Isolated, true, v7), None);
        assert_eq!(window_refusal(w, Level::Contained, true, v7), None);
        assert!(window_refusal(w, Level::Guarded, true, v7).is_some());
        assert!(window_refusal(w, Level::Isolated, false, v7).is_some());
        // 16 bytes off every boundary a 256-byte region's eighths fall on.
        assert!(window_refusal((0x4000_0010, 0x100), Level::Isolated, true, v7).is_some());
    }
}
