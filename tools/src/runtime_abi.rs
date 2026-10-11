//! Runtimes and module ABIs: the one table every consumer reads.
//!
//! A **runtime** is where a module runs — bare-metal silicon, or fluxor
//! hosted as a process — and decides which contracts and providers exist.
//! Module manifests name runtimes in `hardware_targets`; a graph's
//! `target:` resolves to one.
//!
//! A **module ABI** is the bytes a module compiles to: an instruction set
//! and a CPU-feature floor, "this and above". It names the artefact shelf
//! (`target/fluxor/<abi>/modules`), the store tag and the `fluxor.lock`
//! pin. Runtimes that share an ABI share module bytes: the hosted Linux
//! runtime on aarch64 runs the very `.fmod`s bare-metal Pi 5 runs.
//!
//! Build, `modules build --all`, publish, capability facts, the scenario
//! validator and graph composition all answer "which modules belong where"
//! from [`RUNTIMES`]; nothing else maps one to the other. The kernel loader
//! checks the same runtime bits from the signed manifest.

/// One runtime: its manifest token, its bit in a module manifest's
/// runtime mask, and the module ABIs it can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Runtime {
    pub id: &'static str,
    /// Bit in the signed manifest's `hardware_targets` mask.
    pub bit: u16,
    /// Module ABIs this runtime loads, the one it builds by default first.
    pub abis: &'static [&'static str],
}

/// Every runtime. A runtime whose ABIs are not yet buildable is still
/// listed, so its name and manifest bit are fixed once.
pub const RUNTIMES: &[Runtime] = &[
    Runtime {
        id: "rp2350",
        bit: crate::wire::runtime_bit::RP2350,
        abis: &["thumbv8m"],
    },
    Runtime {
        id: "rp2040",
        bit: crate::wire::runtime_bit::RP2040,
        abis: &["thumbv6m"],
    },
    Runtime {
        id: "bcm2712",
        bit: crate::wire::runtime_bit::BCM2712,
        abis: &["aarch64"],
    },
    Runtime {
        id: "wasm",
        bit: crate::wire::runtime_bit::WASM,
        abis: &["wasm32"],
    },
    Runtime {
        id: "linux",
        bit: crate::wire::runtime_bit::LINUX,
        abis: &["aarch64", "x86_64"],
    },
    Runtime {
        id: "macos",
        bit: crate::wire::runtime_bit::MACOS,
        abis: &["aarch64", "x86_64"],
    },
    Runtime {
        id: "windows",
        bit: crate::wire::runtime_bit::WINDOWS,
        abis: &["aarch64", "x86_64"],
    },
    Runtime {
        id: "esp32",
        bit: crate::wire::runtime_bit::ESP32,
        abis: &["xtensa-lx6"],
    },
];

/// One module ABI and the floor its artefacts assume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Abi {
    pub id: &'static str,
    /// What a CPU must offer to run these modules, in words.
    pub floor: &'static str,
    /// Whether `fluxor modules build` can produce it yet.
    pub buildable: bool,
}

/// Every module ABI.
pub const ABIS: &[Abi] = &[
    Abi {
        id: "thumbv6m",
        floor: "ARMv6-M (Cortex-M0+)",
        buildable: true,
    },
    Abi {
        id: "thumbv8m",
        floor: "ARMv8-M Mainline with single-precision FPU (Cortex-M33)",
        buildable: true,
    },
    Abi {
        id: "aarch64",
        floor: "ARMv8.0-A with AES, SHA2 and NEON",
        buildable: true,
    },
    Abi {
        id: "x86_64",
        floor: "x86-64-v3 with AES-NI and PCLMULQDQ",
        buildable: false,
    },
    Abi {
        id: "wasm32",
        floor: "WebAssembly 1.0 (MVP)",
        buildable: true,
    },
    Abi {
        id: "xtensa-lx6",
        floor: "Xtensa LX6 with single-precision FPU (ESP32)",
        buildable: false,
    },
];

pub fn runtime(id: &str) -> Option<&'static Runtime> {
    RUNTIMES.iter().find(|r| r.id == id)
}

pub fn abi(id: &str) -> Option<&'static Abi> {
    ABIS.iter().find(|a| a.id == id)
}

/// The manifest runtime mask for a list of `hardware_targets` tokens.
/// Unknown tokens contribute nothing; [`unknown_runtimes`] names them.
pub fn runtime_mask(tokens: &[String]) -> u16 {
    tokens
        .iter()
        .filter_map(|t| runtime(&t.to_ascii_lowercase()))
        .fold(0, |m, r| m | r.bit)
}

/// The tokens in `tokens` that name no runtime.
pub fn unknown_runtimes(tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .filter(|t| runtime(&t.to_ascii_lowercase()).is_none())
        .cloned()
        .collect()
}

/// The runtimes a manifest mask names.
pub fn runtimes_in(mask: u16) -> impl Iterator<Item = &'static Runtime> {
    RUNTIMES.iter().filter(move |r| mask & r.bit != 0)
}

/// Whether a module whose manifest names `tokens` belongs on the `abi`
/// shelf: some runtime it names loads that ABI. A module naming no
/// runtime is portable and belongs everywhere.
pub fn module_on_abi(tokens: &[String], abi: &str) -> bool {
    if tokens.is_empty() {
        return true;
    }
    tokens
        .iter()
        .filter_map(|t| runtime(&t.to_ascii_lowercase()))
        .any(|r| r.abis.contains(&abi))
}

/// Why a module whose signed runtime mask is `mask` may not be placed
/// under `runtime_id`, or `None` when it may. Sharing a module ABI shares
/// bytes, not contracts, so only the runtime's own bit admits it.
pub fn placement_refusal(module: &str, mask: u16, runtime_id: &str) -> Option<String> {
    let rt = runtime(runtime_id)?;
    if mask & rt.bit != 0 {
        return None;
    }
    let names: Vec<&str> = runtimes_in(mask).map(|r| r.id).collect();
    Some(format!(
        "{module} runs on {} but this graph's runtime is `{runtime_id}`; add \
         `{runtime_id}` to its `hardware_targets` only if it really runs there",
        if names.is_empty() {
            "no runtime".to_string()
        } else {
            names.join(", ")
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn every_runtime_names_known_abis_and_a_unique_bit() {
        let mut bits = 0u16;
        for r in RUNTIMES {
            assert_eq!(bits & r.bit, 0, "{} reuses a bit", r.id);
            assert_eq!(r.bit.count_ones(), 1, "{} bit", r.id);
            bits |= r.bit;
            for a in r.abis {
                assert!(abi(a).is_some(), "{} names unknown ABI {a}", r.id);
            }
        }
    }

    #[test]
    fn a_linux_only_module_belongs_on_the_aarch64_shelf_but_not_on_bare_metal() {
        let linux = s(&["linux"]);
        assert!(module_on_abi(&linux, "aarch64"));
        assert!(!module_on_abi(&linux, "thumbv8m"));
        let mask = runtime_mask(&linux);
        assert_ne!(mask & runtime("linux").unwrap().bit, 0);
        assert_eq!(mask & runtime("bcm2712").unwrap().bit, 0);
    }

    #[test]
    fn placement_admits_only_the_runtimes_a_module_names() {
        let hosted = runtime_mask(&s(&["linux"]));
        assert!(placement_refusal("drain_probe", hosted, "linux").is_none());
        let why = placement_refusal("drain_probe", hosted, "bcm2712").expect("refused");
        assert!(
            why.contains("runs on linux") && why.contains("`bcm2712`"),
            "{why}"
        );
        let bare = runtime_mask(&s(&["bcm2712"]));
        assert!(placement_refusal("nvme", bare, "linux").is_some());
        // An unknown runtime is not this check's to judge.
        assert!(placement_refusal("x", bare, "nonesuch").is_none());
    }

    #[test]
    fn a_bare_metal_module_shares_the_shelf_but_not_the_hosted_runtime() {
        let pi = s(&["bcm2712"]);
        assert!(module_on_abi(&pi, "aarch64"));
        assert_eq!(runtime_mask(&pi) & runtime("linux").unwrap().bit, 0);
        assert_eq!(runtime_mask(&s(&["rp2350", "bcm2712", "linux"])), 0x15);
        assert_eq!(unknown_runtimes(&s(&["esp32s9", "linux"])), s(&["esp32s9"]));
    }
}
