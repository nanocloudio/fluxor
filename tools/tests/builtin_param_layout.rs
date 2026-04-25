//! Layout-drift tests for built-in module `[[params]]`.
//!
//! Each built-in's kernel-side step function reads TLV by hardcoded tag
//! constants (e.g. `IMG_TAG_WIDTH = 10`). The tag is determined by the
//! param's declaration order in `manifest.toml` (first param = 10,
//! second = 11, …). Reordering a `[[params]]` entry shifts the tags
//! silently and the kernel routes values to the wrong fields.
//!
//! These tests pin the expected param order per built-in. If a manifest
//! changes and these assertions trip, update the matching tag constants
//! in the corresponding `src/platform/linux/<name>.rs` together.
//!
//! Tests are independent of the kernel binary — they read the same
//! `manifest.toml` files the runtime ships, so contradictions surface
//! at `cargo test` time instead of as silent runtime corruption.

use std::path::PathBuf;

fn project_root() -> PathBuf {
    // tests/ lives under tools/, project root is two levels up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load(name: &str) -> fluxor_tools::manifest::Manifest {
    // Built-in manifests live under `modules/builtin/{linux,host}/`
    // depending on whether they bind to Linux APIs (winit/CPAL/libc)
    // or are host-OS-agnostic pure-Rust (std + crates that work on
    // any host, including future wasm).
    let candidates = [
        project_root()
            .join("modules/builtin/linux")
            .join(name)
            .join("manifest.toml"),
        project_root()
            .join("modules/builtin/host")
            .join(name)
            .join("manifest.toml"),
    ];
    for p in &candidates {
        if p.exists() {
            return fluxor_tools::manifest::Manifest::from_toml(p)
                .unwrap_or_else(|e| panic!("parse {}: {}", p.display(), e));
        }
    }
    panic!(
        "no manifest found for '{}' under modules/builtin/{{linux,host}}/",
        name
    );
}

/// Assert that a manifest's `[[params]]` declarations match an expected
/// list of `(tag, name)`. Tags must start at 10 in declaration order
/// (the auto-assignment scheme in `Manifest::from_toml`).
fn assert_layout(name: &str, expected: &[(u8, &str)]) {
    let m = load(name);
    let actual: Vec<(u8, &str)> = m.params.iter().map(|p| (p.tag, p.name.as_str())).collect();
    assert_eq!(
        actual.len(),
        expected.len(),
        "{}: param count mismatch — manifest has {}, test expects {}. \
         If you added/removed a [[params]] entry, update both this test \
         and the matching tag constants in src/platform/linux/{}.rs.",
        name,
        actual.len(),
        expected.len(),
        name,
    );
    for (i, (exp, act)) in expected.iter().zip(actual.iter()).enumerate() {
        assert_eq!(
            exp, act,
            "{}: param {} drifted — manifest says {:?}, test expects {:?}. \
             If you reordered [[params]], update src/platform/linux/{}.rs \
             tag constants to match.",
            name, i, act, exp, name,
        );
    }
}

#[test]
fn host_asset_source_layout() {
    // Pinned: src/platform/linux/host_asset_source.rs::ASSET_TAG_PATH
    assert_layout("host_asset_source", &[(10, "path")]);
}

#[test]
fn linux_display_layout() {
    // Pinned: src/platform/linux/linux_display.rs::DISPLAY_TAG_*
    assert_layout(
        "linux_display",
        &[
            (10, "mode"),
            (11, "path"),
            (12, "width"),
            (13, "height"),
            (14, "scale"),
        ],
    );
}

#[test]
fn linux_audio_layout() {
    // Pinned: src/platform/linux/linux_audio.rs::AUDIO_TAG_*
    assert_layout(
        "linux_audio",
        &[
            (10, "mode"),
            (11, "path"),
            (12, "sample_rate"),
            (13, "channels"),
        ],
    );
}

#[test]
fn host_image_codec_layout() {
    // Pinned: src/platform/linux/host_image_codec.rs::IMG_TAG_*
    assert_layout(
        "host_image_codec",
        &[
            (10, "width"),
            (11, "height"),
            (12, "scale_mode"),
            (13, "max_bytes"),
        ],
    );
}

#[test]
fn linux_display_mode_enum() {
    // Pinned: src/platform/linux/linux_display.rs::DISPLAY_MODE_*
    let m = load("linux_display");
    let mode = m.params.iter().find(|p| p.name == "mode").expect("mode");
    let names: Vec<&str> = mode.enum_values.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        vec!["file", "null", "window"],
        "linux_display.mode enum drifted. Update DISPLAY_MODE_FILE / \
         DISPLAY_MODE_NULL / DISPLAY_MODE_WINDOW constants in \
         src/platform/linux/linux_display.rs."
    );
    let vals: Vec<u8> = mode.enum_values.iter().map(|(_, v)| *v).collect();
    assert_eq!(vals, vec![0, 1, 2]);
}

#[test]
fn linux_audio_mode_enum() {
    // Pinned: src/platform/linux/linux_audio.rs::AUDIO_MODE_*
    let m = load("linux_audio");
    let mode = m.params.iter().find(|p| p.name == "mode").expect("mode");
    let names: Vec<&str> = mode.enum_values.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        vec!["wav", "raw", "null", "playback"],
        "linux_audio.mode enum drifted. Update AUDIO_MODE_* constants in \
         src/platform/linux/linux_audio.rs."
    );
    let vals: Vec<u8> = mode.enum_values.iter().map(|(_, v)| *v).collect();
    assert_eq!(vals, vec![0, 1, 2, 3]);
}

#[test]
fn host_image_codec_scale_mode_enum() {
    // Pinned: src/platform/linux/host_image_codec.rs::IMG_SCALE_MODE_*
    let m = load("host_image_codec");
    let s = m
        .params
        .iter()
        .find(|p| p.name == "scale_mode")
        .expect("scale_mode");
    let names: Vec<&str> = s.enum_values.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        vec!["fit", "stretch"],
        "host_image_codec.scale_mode enum drifted. Update \
         IMG_SCALE_MODE_FIT / IMG_SCALE_MODE_STRETCH constants in \
         src/platform/linux/host_image_codec.rs."
    );
    let vals: Vec<u8> = s.enum_values.iter().map(|(_, v)| *v).collect();
    assert_eq!(vals, vec![0, 1]);
}
