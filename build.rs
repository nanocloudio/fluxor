//! Build script for fluxor
//!
//! Provides the target-specific memory.x linker script.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());

    // Select linker script based on chip feature
    let linker_script = if env::var("CARGO_FEATURE_CHIP_RP2040").is_ok() {
        include_bytes!("memory-rp2040.x") as &[u8]
    } else {
        include_bytes!("memory-rp2350.x") as &[u8]
    };

    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(linker_script)
        .unwrap();

    println!("cargo:rustc-link-search={}", out.display());

    println!("cargo:rerun-if-changed=memory-rp2350.x");
    println!("cargo:rerun-if-changed=memory-rp2040.x");
    println!("cargo:rerun-if-changed=build.rs");
}
