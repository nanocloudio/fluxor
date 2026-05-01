//! Validator tests for the `presentation_groups` YAML block.
//!
//! Drives `fluxor validate` against synthetic YAML to cover
//! `tools/src/config.rs::validate_presentation_groups`, the
//! `cmd_validate` config-relative module-search hook, and manifest
//! capability case-handling. Tests run on Linux only and skip when the
//! bcm2712 module tree is missing (same convention as
//! `builtin_build_e2e.rs`).

use std::path::{Path, PathBuf};
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
        "fluxor-pg-{}-{}-{}.yaml",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed),
        name,
    ));
    std::fs::write(&p, body).unwrap();
    p
}

fn run_validate(yaml: &Path) -> (bool, String) {
    let out = Command::new(fluxor_binary())
        .arg("validate")
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

/// Minimal Pico 2 W graph used as the baseline payload for the
/// `presentation_groups` tests below. `i2s_pio` is the audio sink
/// (declares `presentation.clock`), `synth` is not.
const PICO_BASE: &str = r#"
target: pico2w

modules:
  - name: pio_rp
  - name: i2s_pio
    data_pin: 28
    clock_base: 26
    sample_rate: 8000
  - name: synth
    sample_rate: 8000
    waveform: sine

wiring:
  - from: synth.audio
    to: i2s_pio.audio
"#;

fn pico_with_pg(pg_block: &str) -> String {
    format!("{}\n{}", PICO_BASE, pg_block)
}

#[test]
fn solo_speaker_group_validates() {
    if skip_if_unconfigured() {
        return;
    }
    let yaml = write_yaml(
        "solo_ok",
        &pico_with_pg(
            r#"
presentation_groups:
  - id: speaker
    clock_authority: i2s_pio
    members: [i2s_pio]
    cutover_policy: boundary_cut
    continuity_policy: drain
"#,
        ),
    );
    let (ok, out) = run_validate(&yaml);
    assert!(ok, "expected solo group to validate, got:\n{out}");
}

#[test]
fn missing_clock_authority_field_rejected() {
    if skip_if_unconfigured() {
        return;
    }
    let yaml = write_yaml(
        "missing_authority",
        &pico_with_pg(
            r#"
presentation_groups:
  - id: speaker
    members: [i2s_pio]
"#,
        ),
    );
    let (ok, out) = run_validate(&yaml);
    assert!(!ok, "expected validation failure, got success:\n{out}");
    assert!(
        out.contains("required field `clock_authority` missing"),
        "expected missing-authority error, got:\n{out}"
    );
}

#[test]
fn clock_authority_without_capability_rejected() {
    if skip_if_unconfigured() {
        return;
    }
    // `synth` does not declare `presentation.clock`, so naming it as
    // the clock authority must fail with a pointer at the manifest.
    let yaml = write_yaml(
        "synth_authority",
        &pico_with_pg(
            r#"
presentation_groups:
  - id: bad
    clock_authority: synth
    members: [synth, i2s_pio]
"#,
        ),
    );
    let (ok, out) = run_validate(&yaml);
    assert!(!ok, "expected validation failure, got success:\n{out}");
    assert!(
        out.contains("does not declare capability `presentation.clock`"),
        "expected presentation.clock-missing error, got:\n{out}"
    );
}

#[test]
fn clock_authority_must_be_a_member() {
    if skip_if_unconfigured() {
        return;
    }
    let yaml = write_yaml(
        "auth_not_in_members",
        &pico_with_pg(
            r#"
presentation_groups:
  - id: bad
    clock_authority: i2s_pio
    members: [synth]
"#,
        ),
    );
    let (ok, out) = run_validate(&yaml);
    assert!(!ok, "expected validation failure, got success:\n{out}");
    assert!(
        out.contains("is not in members"),
        "expected not-in-members error, got:\n{out}"
    );
}

#[test]
fn non_string_member_rejected_with_index() {
    if skip_if_unconfigured() {
        return;
    }
    let yaml = write_yaml(
        "bad_member_type",
        &pico_with_pg(
            r#"
presentation_groups:
  - id: speaker
    clock_authority: i2s_pio
    members: [i2s_pio, 123]
"#,
        ),
    );
    let (ok, out) = run_validate(&yaml);
    assert!(!ok, "expected validation failure, got success:\n{out}");
    assert!(
        out.contains("members[1] must be a string"),
        "expected indexed type error, got:\n{out}"
    );
    assert!(
        out.contains("got number"),
        "expected observed-type hint, got:\n{out}"
    );
}

#[test]
fn invalid_cutover_policy_rejected() {
    if skip_if_unconfigured() {
        return;
    }
    let yaml = write_yaml(
        "bad_cutover",
        &pico_with_pg(
            r#"
presentation_groups:
  - id: speaker
    clock_authority: i2s_pio
    members: [i2s_pio]
    cutover_policy: hot_swap
"#,
        ),
    );
    let (ok, out) = run_validate(&yaml);
    assert!(!ok, "expected validation failure, got success:\n{out}");
    assert!(
        out.contains("cutover_policy `hot_swap` is invalid"),
        "expected invalid-cutover error, got:\n{out}"
    );
}

#[test]
fn protected_without_capability_rejected() {
    if skip_if_unconfigured() {
        return;
    }
    // i2s_pio declares audio.sample but not audio.protected_out, so a
    // group that demands a protected path must reject it.
    let yaml = write_yaml(
        "protected_no_cap",
        &pico_with_pg(
            r#"
presentation_groups:
  - id: speaker
    clock_authority: i2s_pio
    members: [i2s_pio]
    protected: true
"#,
        ),
    );
    let (ok, out) = run_validate(&yaml);
    assert!(!ok, "expected validation failure, got success:\n{out}");
    assert!(
        out.contains("does not declare `audio.protected_out`"),
        "expected protected-cap error, got:\n{out}"
    );
}

#[test]
fn duplicate_group_ids_rejected() {
    if skip_if_unconfigured() {
        return;
    }
    let yaml = write_yaml(
        "dup_ids",
        &pico_with_pg(
            r#"
presentation_groups:
  - id: speaker
    clock_authority: i2s_pio
    members: [i2s_pio]
  - id: speaker
    clock_authority: i2s_pio
    members: [i2s_pio]
"#,
        ),
    );
    let (ok, out) = run_validate(&yaml);
    assert!(!ok, "expected validation failure, got success:\n{out}");
    assert!(
        out.contains("duplicate id `speaker`"),
        "expected duplicate-id error, got:\n{out}"
    );
}

#[test]
fn budget_implausibly_large_rejected() {
    if skip_if_unconfigured() {
        return;
    }
    let yaml = write_yaml(
        "big_budget",
        &pico_with_pg(
            r#"
presentation_groups:
  - id: speaker
    clock_authority: i2s_pio
    members: [i2s_pio]
    latency_budget_ms: 99999
"#,
        ),
    );
    let (ok, out) = run_validate(&yaml);
    assert!(!ok, "expected validation failure, got success:\n{out}");
    assert!(
        out.contains("latency_budget_ms"),
        "expected latency-budget error, got:\n{out}"
    );
}

/// Two host_display sinks in one group with `multihead: true`. Both
/// linux_display manifests declare `display.scanout` — the validator
/// must accept the group.
#[test]
fn multihead_with_two_display_scanout_validates() {
    if skip_if_unconfigured() {
        return;
    }
    let yaml = write_yaml(
        "multihead_ok",
        r#"
target: linux

modules:
  - name: head1
    type: linux_display
    mode: file
    path: ./target/host-display/h1_%04d.ppm
    width: 64
    height: 64

  - name: head2
    type: linux_display
    mode: file
    path: ./target/host-display/h2_%04d.ppm
    width: 64
    height: 64

  - name: source
    type: host_image_codec
    width: 64
    height: 64

  - name: asset
    type: host_asset_source
    path: assets/test.jpg

wiring:
  - from: asset.stream
    to: source.encoded
  - from: source.pixels
    to: head1.pixels
  - from: source.pixels
    to: head2.pixels
    force: true

presentation_groups:
  - id: video_wall
    clock_authority: head1
    members: [head1, head2]
    multihead: true
"#,
    );
    let (ok, out) = run_validate(&yaml);
    assert!(ok, "expected multihead group to validate, got:\n{out}");
}

/// `multihead: true` requires ≥2 `display.scanout` members; a single
/// scanout sink alongside an audio sink must fail.
#[test]
fn multihead_with_single_display_scanout_rejected() {
    if skip_if_unconfigured() {
        return;
    }
    let yaml = write_yaml(
        "multihead_fail",
        r#"
target: linux

modules:
  - name: head1
    type: linux_display
    mode: file
    path: ./target/host-display/h_%04d.ppm
    width: 64
    height: 64

  - name: speaker
    type: linux_audio
    mode: null
    path: ""
    sample_rate: 48000
    channels: 2

  - name: source
    type: host_image_codec
    width: 64
    height: 64

  - name: asset
    type: host_asset_source
    path: assets/test.jpg

  - name: synth
    type: synth
    sample_rate: 48000
    waveform: sine

wiring:
  - from: asset.stream
    to: source.encoded
  - from: source.pixels
    to: head1.pixels
  - from: synth.audio
    to: speaker.audio

presentation_groups:
  - id: bad_wall
    clock_authority: head1
    members: [head1, speaker]
    multihead: true
"#,
    );
    let (ok, out) = run_validate(&yaml);
    assert!(
        !ok,
        "expected multihead-violation to fail, got success:\n{out}"
    );
    assert!(
        out.contains("only 1 member(s) declare `display.scanout`"),
        "expected multihead-count error, got:\n{out}"
    );
}

/// `cmd_validate` should resolve project-local manifests via the
/// config-relative `<config-parent>/../modules` search path the same
/// way `cmd_build` does. Construct a tiny project tree under TMP, drop a
/// builtin manifest with `presentation.clock` into it, and confirm
/// `fluxor validate` finds it.
#[test]
fn fluxor_validate_resolves_config_relative_modules() {
    if skip_if_unconfigured() {
        return;
    }
    let proj = std::env::temp_dir().join(format!("fluxor-pg-localmod-{}", std::process::id()));
    let mod_dir = proj.join("modules").join("local_clock");
    std::fs::create_dir_all(&mod_dir).unwrap();
    std::fs::write(
        mod_dir.join("manifest.toml"),
        r#"version = "1.0.0"
hardware_targets = ["linux"]
builtin = true
capabilities = ["audio.sample", "presentation.clock"]

[[ports]]
name = "audio"
direction = "input"
content_type = "AudioSample"
required = true
"#,
    )
    .unwrap();

    let config_dir = proj.join("configs");
    std::fs::create_dir_all(&config_dir).unwrap();
    let yaml = config_dir.join("proj.yaml");
    std::fs::write(
        &yaml,
        r#"target: linux

modules:
  - name: synth
    type: synth
    sample_rate: 48000
    waveform: sine
  - name: sink
    type: local_clock

wiring:
  - from: synth.audio
    to: sink.audio
    force: true

presentation_groups:
  - id: local
    clock_authority: sink
    members: [sink]
"#,
    )
    .unwrap();

    let (ok, out) = run_validate(&yaml);
    assert!(
        ok,
        "expected validate to find /tmp project-local manifest, got:\n{out}"
    );
}

/// Manifest capability names must accept any-case input (e.g.
/// `Presentation.Clock`) and canonicalize to lowercase so the
/// downstream presentation-group validator's exact-string compare
/// still recognises them. Constructs a project-local manifest with a
/// mixed-case capability and confirms a group naming it as
/// clock_authority validates clean.
#[test]
fn capability_names_are_case_insensitive_at_parse() {
    if skip_if_unconfigured() {
        return;
    }
    let proj = std::env::temp_dir().join(format!("fluxor-pg-mixedcase-{}", std::process::id()));
    let mod_dir = proj.join("modules").join("mixed_case_clock");
    std::fs::create_dir_all(&mod_dir).unwrap();
    std::fs::write(
        mod_dir.join("manifest.toml"),
        r#"version = "1.0.0"
hardware_targets = ["linux"]
builtin = true
capabilities = ["Audio.Sample", "Presentation.Clock"]

[[ports]]
name = "audio"
direction = "input"
content_type = "AudioSample"
required = true
"#,
    )
    .unwrap();

    let config_dir = proj.join("configs");
    std::fs::create_dir_all(&config_dir).unwrap();
    let yaml = config_dir.join("proj.yaml");
    std::fs::write(
        &yaml,
        r#"target: linux

modules:
  - name: synth
    type: synth
    sample_rate: 48000
    waveform: sine
  - name: sink
    type: mixed_case_clock

wiring:
  - from: synth.audio
    to: sink.audio
    force: true

presentation_groups:
  - id: speaker
    clock_authority: sink
    members: [sink]
"#,
    )
    .unwrap();

    let (ok, out) = run_validate(&yaml);
    assert!(
        ok,
        "expected mixed-case capability to validate, got:\n{out}"
    );
}
