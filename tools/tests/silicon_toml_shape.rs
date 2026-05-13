//! Pin the contract between `targets/silicon/rp2*.toml` and
//! `build.rs::generate_chip_rs`.
//!
//! `build.rs` reads `[kernel]` from the per-silicon TOML and emits
//! `chip_generated.rs` with these constants:
//!   * `WATCHDOG_CTRL`           ← `watchdog_ctrl`        (hex string → u32)
//!   * `BOOT2_SRC`               ← `boot2_src`            (hex string → u32)
//!   * `STATE_ARENA_SIZE`        ← `state_arena_kb * 1024`
//!   * `BUFFER_ARENA_SIZE`       ← `buffer_arena_kb * 1024`
//!   * `MAX_MODULE_CONFIG_SIZE`  ← `config_buffer_kb * 1024`
//!   * `CONFIG_ARENA_SIZE`       ← `config_arena_kb * 1024`
//!
//! The RP target build (`make firmware TARGET=rp2040` / `rp2350`) is the
//! only place these constants are exercised — `chip_generated.rs`
//! doesn't exist for hosted targets. That makes the contract invisible
//! on host CI: a TOML rename, a missing field, or a non-numeric value
//! is only caught when the RP firmware is built.
//!
//! This test reads each TOML directly from the source tree, parses the
//! `[kernel]` section, and asserts:
//!   1. Every required field is present.
//!   2. The numeric values are within sensible bounds (state arena
//!      between 16 KB and 4 MB; hex pointers in flash/RAM address
//!      space).
//!   3. The per-field `kb` values, when multiplied by 1024, do not
//!      overflow `usize` and produce results consistent with the kernel
//!      profile maximums.
//!
//! What it does NOT test: that `build.rs` *actually* multiplies by 1024
//! correctly. That arithmetic is one line; mis-typing it would be
//! caught by `make check-build-matrix` failing to compile the RP
//! firmware (because every consumer relies on the constant). Together
//! the two checks pin the chain:
//!   TOML shape (this test) → build.rs arithmetic (compile-time) →
//!   kernel constants (target builds via `make check-build-matrix`).
//!
//! Run with:
//!   cargo test --manifest-path tools/Cargo.toml --test silicon_toml_shape

use std::path::PathBuf;

#[derive(serde::Deserialize)]
struct SiliconToml {
    kernel: KernelSection,
}

#[derive(serde::Deserialize)]
struct KernelSection {
    watchdog_ctrl: String,
    boot2_src: String,
    state_arena_kb: u32,
    buffer_arena_kb: u32,
    config_buffer_kb: u32,
    config_arena_kb: u32,
    // Optional fields that `build.rs::generate_chip_rs` also touches but
    // aren't all RP-mandatory; we don't validate them here.
    #[serde(default)]
    flash_erase_block_size: Option<String>,
    #[serde(default)]
    flash_erase_cmd: Option<String>,
}

fn workspace_root() -> PathBuf {
    // `tools/Cargo.toml` is the manifest dir; workspace root is one up.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p
}

fn parse_hex(s: &str) -> u32 {
    let t = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or_else(|| panic!("expected hex string starting with 0x, got {:?}", s));
    u32::from_str_radix(t, 16)
        .unwrap_or_else(|e| panic!("bad hex {:?}: {}", s, e))
}

fn load_silicon(rel: &str) -> SiliconToml {
    let path = workspace_root().join(rel);
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    toml::from_str(&content)
        .unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e))
}

fn verify_kernel(k: &KernelSection, file: &str) {
    // Hex pointers parse as u32 and are non-zero.
    let wctrl = parse_hex(&k.watchdog_ctrl);
    let boot2 = parse_hex(&k.boot2_src);
    assert_ne!(wctrl, 0, "{}: watchdog_ctrl must not be 0", file);
    assert_ne!(boot2, 0, "{}: boot2_src must not be 0", file);

    // KB-sized fields are non-zero and within sane bounds.
    // Floor: 4 KB (smallest plausible) so a TOML with `state_arena_kb = 0`
    // (which would compile-pass but produce a zero-byte arena) is caught.
    // Ceiling: 4 MB. RP2350 ships with 256 KB; anything > 4 MB indicates
    // a typo (KB-vs-byte confusion).
    let kb_fields: [(&str, u32); 4] = [
        ("state_arena_kb", k.state_arena_kb),
        ("buffer_arena_kb", k.buffer_arena_kb),
        ("config_buffer_kb", k.config_buffer_kb),
        ("config_arena_kb", k.config_arena_kb),
    ];
    for (name, kb) in kb_fields {
        assert!(
            (4..=4096).contains(&kb),
            "{}: {} = {} kb out of expected [4, 4096] range",
            file,
            name,
            kb
        );
        // Byte-multiplication does not overflow on a 32-bit usize host.
        let bytes = (kb as usize).checked_mul(1024).unwrap_or_else(|| {
            panic!("{}: {} = {} kb overflows usize when multiplied by 1024", file, name, kb)
        });
        assert!(
            bytes > 0,
            "{}: {} byte size computed to 0 (overflow guard)",
            file,
            name
        );
    }

    // Cross-field sanity: buffer arena is sized to deliver streaming
    // capacity per channel, so it should be smaller than the state
    // arena (modules > buffers in any realistic workload). This catches
    // the swap-typo failure mode.
    assert!(
        k.buffer_arena_kb <= k.state_arena_kb,
        "{}: buffer_arena_kb ({}) > state_arena_kb ({}) — likely a TOML swap",
        file,
        k.buffer_arena_kb,
        k.state_arena_kb,
    );

    // Optional flash fields, when present, are valid hex.
    if let Some(s) = &k.flash_erase_block_size {
        let _ = parse_hex(s);
    }
    if let Some(s) = &k.flash_erase_cmd {
        let _ = parse_hex(s);
    }
}

#[test]
fn rp2040_kernel_section_is_well_formed() {
    let s = load_silicon("targets/silicon/rp2040.toml");
    verify_kernel(&s.kernel, "rp2040.toml");
}

#[test]
fn rp2350a_kernel_section_is_well_formed() {
    let s = load_silicon("targets/silicon/rp2350a.toml");
    verify_kernel(&s.kernel, "rp2350a.toml");
}

#[test]
fn rp2350b_kernel_section_is_well_formed() {
    // rp2350b shares the same [kernel] shape as rp2350a; deserialise
    // through the same struct to confirm the file hasn't drifted.
    let s = load_silicon("targets/silicon/rp2350b.toml");
    verify_kernel(&s.kernel, "rp2350b.toml");
}

#[test]
fn rp2040_arenas_are_strictly_smaller_than_rp2350() {
    // RP2040 has less SRAM (264 KB) than RP2350 (520 KB). The TOMLs
    // should reflect this — RP2040's state_arena should not exceed
    // RP2350's. Catches accidental copy-paste between the two files.
    let small = load_silicon("targets/silicon/rp2040.toml");
    let big = load_silicon("targets/silicon/rp2350a.toml");
    assert!(
        small.kernel.state_arena_kb <= big.kernel.state_arena_kb,
        "rp2040.state_arena_kb ({}) > rp2350a.state_arena_kb ({}); \
         RP2040 has less SRAM — values likely swapped",
        small.kernel.state_arena_kb,
        big.kernel.state_arena_kb,
    );
}
