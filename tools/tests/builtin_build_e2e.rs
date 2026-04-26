//! End-to-end build-pipeline tests for built-in modules.
//!
//! Drive the actual `fluxor` binary against generated YAML configs,
//! exercising the full chain: stack expansion → manifest lookup →
//! schema synthesis → validation (unknown-key, range, required) →
//! TLV packing → config.bin emission.
//!
//! Layout-drift tests (`builtin_param_layout.rs`) cover the schema in
//! isolation; these tests exercise the build pipeline as the user
//! sees it. They do *not* run `fluxor-linux` — that requires runtime
//! infrastructure (a built `fluxor-linux`, a populated bcm2712 modules
//! dir, and possibly hardware).
//!
//! Tests are skipped if `target/bcm2712/modules/` is missing — the tool
//! pulls .fmod files from there and we can't fail useful tests on a
//! fresh tree.

use std::path::PathBuf;
use std::process::Command;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn fluxor_binary() -> PathBuf {
    // Cargo sets `CARGO_BIN_EXE_<name>` for every `[[bin]]` in the same
    // crate when integration tests are compiled, so this always points
    // at the binary built from the code under test.
    PathBuf::from(env!("CARGO_BIN_EXE_fluxor"))
}

fn modules_dir() -> PathBuf {
    project_root().join("target/bcm2712/modules")
}

fn skip_if_unconfigured() -> bool {
    if !fluxor_binary().exists() {
        eprintln!("skip: fluxor binary not at {}", fluxor_binary().display());
        return true;
    }
    if !modules_dir().exists() {
        eprintln!(
            "skip: bcm2712 modules not at {} — run `make modules TARGET=bcm2712`",
            modules_dir().display()
        );
        return true;
    }
    false
}

fn write_yaml(name: &str, body: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let p = std::env::temp_dir().join(format!(
        "fluxor-e2e-{}-{}-{}.yaml",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed),
        name,
    ));
    std::fs::write(&p, body).unwrap();
    p
}

/// Run `fluxor build <yaml>` and capture stderr+stdout.
fn run_build(yaml: &PathBuf) -> (bool, String) {
    let out = Command::new(fluxor_binary())
        .arg("build")
        .arg(yaml)
        .current_dir(project_root())
        .output()
        .unwrap_or_else(|e| panic!("spawn fluxor: {}", e));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), combined)
}

#[test]
fn jpeg_display_clean_build() {
    if skip_if_unconfigured() {
        return;
    }
    let yaml = write_yaml(
        "valid",
        r#"
target: linux
modules:
  - name: asset
    type: host_asset_source
    path: assets/test.jpg
  - name: codec
    type: host_image_codec
    width: 480
    height: 480
    scale_mode: fit
  - name: display
    type: linux_display
    mode: file
    path: ./target/host-display/clean.ppm
    width: 480
    height: 480
wiring:
  - from: asset.stream
    to: codec.encoded
  - from: codec.pixels
    to: display.pixels
"#,
    );
    let (ok, out) = run_build(&yaml);
    assert!(ok, "expected clean build, got error:\n{out}");
}

#[test]
fn typo_in_param_rejected_with_did_you_mean_hint() {
    if skip_if_unconfigured() {
        return;
    }
    let yaml = write_yaml(
        "typo",
        r#"
target: linux
modules:
  - name: asset
    type: host_asset_source
    path: assets/test.jpg
  - name: codec
    type: host_image_codec
    widht: 320
    scale_mode: fit
wiring:
  - from: asset.stream
    to: codec.encoded
"#,
    );
    let (ok, out) = run_build(&yaml);
    assert!(!ok, "expected build failure, got success:\n{out}");
    assert!(
        out.contains("unknown param 'widht'") && out.contains("did you mean 'width'"),
        "expected typo + hint, got:\n{out}",
    );
}

#[test]
fn out_of_range_param_rejected_with_bounds() {
    if skip_if_unconfigured() {
        return;
    }
    let yaml = write_yaml(
        "range",
        r#"
target: linux
modules:
  - name: asset
    type: host_asset_source
    path: assets/test.jpg
  - name: codec
    type: host_image_codec
    width: 8000
    scale_mode: fit
wiring:
  - from: asset.stream
    to: codec.encoded
"#,
    );
    let (ok, out) = run_build(&yaml);
    assert!(!ok, "expected build failure, got success:\n{out}");
    assert!(
        out.contains("param 'width'=8000 is outside [1, 4096]"),
        "expected range error with bounds, got:\n{out}",
    );
}

#[test]
fn missing_required_param_rejected() {
    if skip_if_unconfigured() {
        return;
    }
    // `host_asset_source.path` is `required = true` with no default,
    // so omitting it must fail the build with a missing-required error.
    let yaml = write_yaml(
        "missing_required",
        r#"
target: linux
modules:
  - name: asset
    type: host_asset_source
wiring: []
"#,
    );
    let (ok, out) = run_build(&yaml);
    assert!(!ok, "expected build failure, got success:\n{out}");
    assert!(
        out.contains("required param 'path' is missing from YAML"),
        "expected missing-required error, got:\n{out}",
    );
}

#[test]
fn transparent_params_wrapper_works() {
    if skip_if_unconfigured() {
        return;
    }
    // `params: { ... }` is a transparent grouping container — its
    // inner keys map to schema params with no prefix.
    let yaml = write_yaml(
        "params_wrapper",
        r#"
target: linux
modules:
  - name: asset
    type: host_asset_source
    params:
      path: assets/test.jpg
  - name: codec
    type: host_image_codec
    params:
      width: 320
      height: 240
      scale_mode: stretch
wiring:
  - from: asset.stream
    to: codec.encoded
"#,
    );
    let (ok, out) = run_build(&yaml);
    assert!(ok, "expected clean build with params wrapper, got:\n{out}");
}

#[test]
fn defaults_propagate_when_yaml_omits_param() {
    if skip_if_unconfigured() {
        return;
    }
    // host_image_codec has no required params (other than its
    // type/name); omitting all of width/height/scale_mode/max_bytes
    // should succeed because the manifest declares defaults.
    let yaml = write_yaml(
        "defaults",
        r#"
target: linux
modules:
  - name: asset
    type: host_asset_source
    path: assets/test.jpg
  - name: codec
    type: host_image_codec
wiring:
  - from: asset.stream
    to: codec.encoded
"#,
    );
    let (ok, out) = run_build(&yaml);
    assert!(ok, "expected clean build with all defaults, got:\n{out}");
}
