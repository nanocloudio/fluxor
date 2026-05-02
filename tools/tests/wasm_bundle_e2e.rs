//! End-to-end integration test for the WASM bundle pipeline.
//!
//! Exercises the full chain: a YAML config with `target: wasm` →
//! module table assembly from `target/wasm/modules/` → config.bin
//! emission → kernel `firmware.wasm` placeholder rewrite → final
//! self-contained `<config>.wasm` artifact.
//!
//! Skipped when the prerequisites aren't built (`firmware.wasm`
//! and/or `target/wasm/modules/`) — running this test from a
//! fresh tree would require building the wasm kernel and modules
//! first.

use std::path::PathBuf;
use std::process::Command;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn fluxor_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fluxor"))
}

fn skip_if_unconfigured() -> Option<&'static str> {
    if !fluxor_binary().exists() {
        return Some("fluxor binary missing");
    }
    let firmware = project_root().join("target/wasm/firmware.wasm");
    if !firmware.exists() {
        return Some("target/wasm/firmware.wasm missing — run `make firmware TARGET=wasm`");
    }
    let modules = project_root().join("target/wasm/modules");
    if !modules.exists() {
        return Some("target/wasm/modules missing — run `make modules TARGET=wasm`");
    }
    None
}

#[test]
fn wasm_bundle_round_trip() {
    if let Some(reason) = skip_if_unconfigured() {
        eprintln!("skip: {reason}");
        return;
    }

    // Empty-modules config — exercises the bundle pipeline without
    // committing to a specific module set.
    let yaml = r#"
target: wasm
modules: []
wiring: []
"#;
    let tmp_dir = std::env::temp_dir().join("fluxor_wasm_bundle_e2e");
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let yaml_path = tmp_dir.join("empty.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();

    let status = Command::new(fluxor_binary())
        .current_dir(project_root())
        .arg("build")
        .arg(&yaml_path)
        .status()
        .expect("invoking fluxor build");
    assert!(status.success(), "fluxor build failed");

    let out = project_root().join("target/wasm/wasm/empty.wasm");
    assert!(out.exists(), "bundle did not produce {}", out.display());

    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(&bytes[..4], b"\0asm", "output is not a wasm binary");

    // Locate the modules-blob magic and verify the header looks
    // sensible after rewrite.
    let modules_magic = b"FLUXOR_MOD_BLOB\0";
    let m_off = bytes
        .windows(modules_magic.len())
        .position(|w| w == modules_magic)
        .expect("modules blob magic not found in bundled wasm");
    let m_capacity = u32::from_le_bytes(bytes[m_off + 16..m_off + 20].try_into().unwrap());
    let m_used = u32::from_le_bytes(bytes[m_off + 20..m_off + 24].try_into().unwrap());
    assert!(m_capacity > 0, "modules blob has zero capacity");
    assert!(
        m_used <= m_capacity,
        "modules used {} > capacity {}",
        m_used,
        m_capacity
    );

    // The empty-modules config produces a 16-byte module-table
    // header (no entries, no payload). Verify exactly that.
    assert_eq!(m_used, 16, "empty config should emit 16-byte modules.bin");

    // Module table magic at the start of the modules blob (FXMT).
    let table_off = m_off + 32;
    assert_eq!(
        &bytes[table_off..table_off + 4],
        b"FXMT",
        "modules.bin doesn't start with FXMT magic"
    );

    // Config blob has used_len matching the emitted config.bin size.
    let config_magic = b"FLUXOR_CFG_BLOB\0";
    let c_off = bytes
        .windows(config_magic.len())
        .position(|w| w == config_magic)
        .expect("config blob magic not found in bundled wasm");
    let c_used = u32::from_le_bytes(bytes[c_off + 20..c_off + 24].try_into().unwrap());
    assert!(c_used > 0, "config blob is empty (config.bin size = 0)");
}

#[test]
fn wasm_bundle_with_one_module() {
    if let Some(reason) = skip_if_unconfigured() {
        eprintln!("skip: {reason}");
        return;
    }

    // Verify a config that names `format` (a small pure-compute
    // foundation module) actually carries the wasm-payload .fmod
    // through to the bundled output, with the wasm-payload flag set
    // on its FXMD header.
    let yaml = r#"
target: wasm
modules:
  - name: format
    input_rate: 8000
    output_rate: 44100
    input_bits: 16
    input_channels: 1
wiring: []
"#;
    let tmp_dir = std::env::temp_dir().join("fluxor_wasm_bundle_e2e");
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let yaml_path = tmp_dir.join("one_mod.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();

    let status = Command::new(fluxor_binary())
        .current_dir(project_root())
        .arg("build")
        .arg(&yaml_path)
        .status()
        .expect("invoking fluxor build");
    assert!(status.success(), "fluxor build failed");

    let out = project_root().join("target/wasm/wasm/one_mod.wasm");
    let bytes = std::fs::read(&out).unwrap();

    // Find the modules blob, then walk into it to find the format
    // module's .fmod entry. Expect: FXMT table magic, count >= 1,
    // first .fmod has FXMD magic and wasm-payload flag set.
    let m_off = bytes
        .windows(16)
        .position(|w| w == b"FLUXOR_MOD_BLOB\0")
        .unwrap();
    let modules_bin = &bytes[m_off + 32..];
    assert_eq!(&modules_bin[..4], b"FXMT", "FXMT magic");
    let count = modules_bin[5];
    assert!(count >= 1, "expected at least one module in table");

    // First entry is at offset 16 (after the 16-byte table header).
    let entry = &modules_bin[16..32];
    let mod_offset = u32::from_le_bytes(entry[4..8].try_into().unwrap()) as usize;
    let fmod = &modules_bin[mod_offset..];
    assert_eq!(&fmod[..4], b"FXMD", "FXMD magic");
    let flags_byte = fmod[60];
    assert_eq!(
        flags_byte & 0x20,
        0x20,
        "wasm-payload flag (bit 5) not set on bundled module"
    );

    // Code starts at offset 72 (FXMD header size). Verify it begins
    // with the wasm magic.
    let code = &fmod[72..76];
    assert_eq!(code, b"\0asm", "module code section doesn't start with wasm magic");
}
