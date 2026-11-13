//! `fluxor_abi`, the module ABI this build targets, for a cargo build.
//!
//! `config::profile_embedded` picks connection ceilings and `TARGET_CLASS`
//! by it: the RP parts differ by 3.75x in SRAM and `target_arch` cannot tell
//! thumbv6m from thumbv8m. The module build passes the value to rustc
//! itself; a cargo build (the kernel, the tools) takes it from the target,
//! so the kernel and the modules it loads read the same profile. Hosted
//! targets set no value: their profiles are selected by `target_arch`.

fn main() {
    println!(
        "cargo::rustc-check-cfg=cfg(fluxor_abi, values(\"thumbv6m\", \"thumbv8m\", \"aarch64\", \"x86_64\", \"wasm32\", \"xtensa-lx6\"))"
    );
    let target = std::env::var("TARGET").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let abi = if target.starts_with("thumbv6m") {
        Some("thumbv6m")
    } else if target.starts_with("thumbv8m") {
        Some("thumbv8m")
    } else if target.starts_with("aarch64") && (os == "none" || os == "uefi") {
        Some("aarch64")
    } else {
        None
    };
    if let Some(abi) = abi {
        println!("cargo::rustc-cfg=fluxor_abi=\"{abi}\"");
    }
}
