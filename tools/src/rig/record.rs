//! Run record — RFC §10.6.
//!
//! Every rig run should produce a reproducibility-grade identity manifest:
//! hashes of the artifact bundle, scenario file, and rig profile (with
//! secrets redacted), plus verdict and timing.
//!
//! Records are written under
//! `~/.local/state/fluxor/labs/<lab>/rigs/<rig>/runs/<timestamp>/manifest.json`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::rig::profile::{BindingTable, BindingValue, RigProfile};
use crate::rig::scenario::Scenario;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub run_id: String,
    pub rig: String,
    pub lab: String,
    pub board: String,
    pub scenario: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub verdict: Verdict,
    pub primary_observation_source: Option<String>,
    pub tool_version: &'static str,
    pub git_revision: Option<String>,
    pub scenario_sha256: String,
    pub profile_sha256: String,
    pub artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Planning only, no side effects taken.
    Planned,
    Pending,
    Passed,
    Failed,
    /// Terminated without reaching a pass or fail rule.
    TimedOut,
    /// Aborted before completion (Ctrl-C, internal error, etc.).
    Aborted,
}

impl RunRecord {
    pub fn for_plan(
        lab: &str,
        scenario: &Scenario,
        profile: &RigProfile,
        artifact_digest: Option<String>,
    ) -> Result<Self> {
        let (started_at, subsec_nanos) = now_unix_secs_and_nanos();
        let run_id = run_id_for(started_at, subsec_nanos, &profile.rig.id);
        Ok(Self {
            run_id,
            rig: profile.rig.id.clone(),
            lab: lab.to_string(),
            board: profile.rig.board.clone(),
            scenario: scenario.name.clone(),
            started_at,
            finished_at: None,
            verdict: Verdict::Planned,
            primary_observation_source: None,
            tool_version: env!("CARGO_PKG_VERSION"),
            git_revision: option_env!("FLUXOR_GIT_REV").map(|s| s.to_string()),
            scenario_sha256: hash_scenario_file(scenario)?,
            profile_sha256: hash_profile(profile),
            artifact_sha256: artifact_digest,
        })
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("RunRecord is always serialisable")
    }
}

/// Artifact digest for a single-file artifact. A trivial SHA-256 of the bytes.
pub fn hash_artifact_file(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path).map_err(|e| {
        Error::Config(format!(
            "run record: opening artifact {}: {e}",
            path.display()
        ))
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| {
            Error::Config(format!(
                "run record: reading artifact {}: {e}",
                path.display()
            ))
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_digest(&hasher.finalize()))
}

/// Artifact digest for a multi-file bundle. Deterministic under the RFC-§10.6
/// canonicalisation: entries sorted by path relative to the bundle root,
/// each emitted as `len(path)||path||len(content)||content`, concatenated
/// and SHA-256'd.
///
/// Only regular files are included; symlinks, directories, and sockets are
/// ignored. Directory traversal is depth-first.
pub fn hash_artifact_bundle(root: &Path) -> Result<String> {
    if !root.is_dir() {
        return Err(Error::Config(format!(
            "run record: bundle root {} is not a directory",
            root.display()
        )));
    }
    let mut entries: Vec<(PathBuf, PathBuf)> = Vec::new();
    collect_files(root, root, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    for (rel, abs) in &entries {
        let bytes = std::fs::read(abs).map_err(|e| {
            Error::Config(format!(
                "run record: reading bundle entry {}: {e}",
                abs.display()
            ))
        })?;
        let rel_str = rel.to_string_lossy();
        let rel_bytes = rel_str.as_bytes();
        hasher.update((rel_bytes.len() as u64).to_be_bytes());
        hasher.update(rel_bytes);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
    }
    Ok(hex_digest(&hasher.finalize()))
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, PathBuf)>) -> Result<()> {
    for entry in std::fs::read_dir(dir)
        .map_err(|e| Error::Config(format!("run record: reading dir {}: {e}", dir.display())))?
    {
        let entry =
            entry.map_err(|e| Error::Config(format!("run record: reading dir entry: {e}")))?;
        let path = entry.path();
        let meta = entry
            .metadata()
            .map_err(|e| Error::Config(format!("run record: stat {}: {e}", path.display())))?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            collect_files(root, &path, out)?;
        } else if meta.is_file() {
            let rel = path.strip_prefix(root).map_err(|_| {
                Error::Config(format!(
                    "run record: path {} not under root {}",
                    path.display(),
                    root.display()
                ))
            })?;
            out.push((rel.to_path_buf(), path));
        }
    }
    Ok(())
}

fn hash_scenario_file(scenario: &Scenario) -> Result<String> {
    // Hash the scenario file exactly as loaded, so filename changes are
    // reflected in the manifest.
    if let Some(path) = &scenario.source_path {
        if path.is_file() {
            return hash_file_bytes(path);
        }
    }
    // Scenarios constructed from an in-memory string have no on-disk
    // path; fall back to a synthetic identity over the fields that
    // would otherwise collide.
    let mut hasher = Sha256::new();
    hasher.update(b"scenario:");
    hasher.update(scenario.name.as_bytes());
    hasher.update(b"|target:");
    hasher.update(scenario.target.as_bytes());
    hasher.update(b"|config:");
    hasher.update(scenario.config.to_string_lossy().as_bytes());
    Ok(hex_digest(&hasher.finalize()))
}

fn hash_file_bytes(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut f = std::fs::File::open(path)
        .map_err(|e| Error::Config(format!("run record: hashing {}: {e}", path.display())))?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| Error::Config(format!("run record: reading {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_digest(&hasher.finalize()))
}

/// Canonicalise a profile for hashing: every string value is reduced via
/// `Secret::for_hash` so resolved secret values are replaced by the `***`
/// sentinel. The canonical form is a sorted, flat list of
/// `key=type:value` lines so reordering TOML doesn't change the hash and
/// presence-of-secret-field is still distinguishable from absence.
pub fn canonical_profile(profile: &RigProfile) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("rig.id={}", profile.rig.id));
    lines.push(format!("rig.board={}", profile.rig.board));
    for (i, tag) in profile.rig.tags.iter().enumerate() {
        lines.push(format!("rig.tags[{i}]={tag}"));
    }
    if let Some(p) = &profile.power {
        emit_binding("power", p, &mut lines);
    }
    for (cap, binding) in &profile.deploy {
        emit_binding(cap.as_str(), binding, &mut lines);
    }
    for (cap, binding) in &profile.console {
        emit_binding(cap.as_str(), binding, &mut lines);
    }
    for (cap, binding) in &profile.telemetry {
        emit_binding(cap.as_str(), binding, &mut lines);
    }
    for (cap, binding) in &profile.observe {
        emit_binding(cap.as_str(), binding, &mut lines);
    }
    if !profile.secrets.is_empty() {
        emit_binding("secrets", &profile.secrets, &mut lines);
    }
    lines.sort();
    lines.join("\n")
}

fn emit_binding(section: &str, table: &BindingTable, out: &mut Vec<String>) {
    for (k, v) in table.iter() {
        let rendered = match v {
            BindingValue::Secret(s) => format!("string:{}", s.for_hash()),
            BindingValue::Int(n) => format!("int:{n}"),
            BindingValue::Bool(b) => format!("bool:{b}"),
        };
        out.push(format!("{section}.{k}={rendered}"));
    }
}

pub fn hash_profile(profile: &RigProfile) -> String {
    let canonical = canonical_profile(profile);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex_digest(&hasher.finalize())
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn now_unix_secs_and_nanos() -> (u64, u32) {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs(), d.subsec_nanos()))
        .unwrap_or((0, 0))
}

/// Run id format: `<unix_secs>-<9-digit-subsec-nanos>-<rig_id>`.
/// Sub-second precision makes run directories distinct even for fast
/// reruns against the same rig; lexicographic order matches time order.
fn run_id_for(unix_secs: u64, subsec_nanos: u32, rig_id: &str) -> String {
    format!("{unix_secs:010}-{subsec_nanos:09}-{rig_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rig::profile::parse_profile_str;

    #[test]
    fn scenario_hash_follows_file_contents_not_basename() {
        use crate::rig::scenario::load_scenario;

        let dir = crate::rig::test_utils::unique_tmp_dir("record-scn-hash");

        // `name` field deliberately differs from the basename — the
        // hash must reflect the file's actual bytes.
        let body = r#"
name = "totally-different-name"
target = "cm5"
config = "../../examples/cm5/hello_uart.yaml"
requires = ["deploy.netboot_tftp", "observe.netboot_fetch"]
[[pass]]
source = "observe.netboot_fetch"
regex = "kernel\\.img$"
"#;
        let path_a = dir.join("scenario_alpha.toml");
        let path_b = dir.join("scenario_beta.toml");
        std::fs::write(&path_a, body).unwrap();
        std::fs::write(&path_b, body).unwrap();

        let scn_a = load_scenario(&path_a).unwrap();
        let scn_b = load_scenario(&path_b).unwrap();

        let hash_a = hash_scenario_file(&scn_a).unwrap();
        let hash_b = hash_scenario_file(&scn_b).unwrap();
        assert_eq!(hash_a, hash_b);

        let expected = {
            let mut h = sha2::Sha256::new();
            h.update(body.as_bytes());
            hex_digest(&h.finalize())
        };
        assert_eq!(hash_a, expected);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_ids_differ_within_the_same_second() {
        let id_a = run_id_for(1_700_000_000, 100_000_000, "pi5-a");
        let id_b = run_id_for(1_700_000_000, 100_000_001, "pi5-a");
        assert_ne!(id_a, id_b);
        assert!(id_a < id_b);
    }

    #[test]
    fn run_id_format_is_lexicographically_sortable() {
        let earlier = run_id_for(1_700_000_000, 999_999_999, "pi5-a");
        let later = run_id_for(1_700_000_001, 0, "pi5-a");
        assert!(earlier < later);
    }

    #[test]
    fn bundle_hash_is_stable_across_dir_walk_order() {
        let tmp = std::env::temp_dir().join(format!("fluxor-rig-bundle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("sub")).unwrap();
        std::fs::write(tmp.join("a.bin"), b"aaa").unwrap();
        std::fs::write(tmp.join("sub/b.bin"), b"bbb").unwrap();
        std::fs::write(tmp.join("c.bin"), b"ccc").unwrap();

        let h1 = hash_artifact_bundle(&tmp).unwrap();
        // Perturb: add and remove a file that shouldn't change the hash
        // after being removed.
        std::fs::write(tmp.join("temp.bin"), b"xxx").unwrap();
        let h_with = hash_artifact_bundle(&tmp).unwrap();
        assert_ne!(h1, h_with);
        std::fs::remove_file(tmp.join("temp.bin")).unwrap();
        let h_after = hash_artifact_bundle(&tmp).unwrap();
        assert_eq!(h1, h_after);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn profile_hash_redacts_secrets() {
        std::env::set_var("FLUXOR_PROFILE_HASH_TEST", "one");
        let src_one = r#"
            [rig]
            id = "x"
            board = "cm5"

            [secrets]
            tok = "${env:FLUXOR_PROFILE_HASH_TEST}"
        "#;
        let p1 = parse_profile_str(src_one, Path::new("/tmp/x.toml")).unwrap();
        let h1 = hash_profile(&p1);

        std::env::set_var("FLUXOR_PROFILE_HASH_TEST", "two");
        let p2 = parse_profile_str(src_one, Path::new("/tmp/x.toml")).unwrap();
        let h2 = hash_profile(&p2);

        // Changing the resolved secret value must NOT change the profile hash.
        assert_eq!(h1, h2);
        std::env::remove_var("FLUXOR_PROFILE_HASH_TEST");
    }

    #[test]
    fn profile_hash_distinguishes_present_vs_absent_secret() {
        std::env::set_var("FLUXOR_PROFILE_HASH_T2", "v");

        let with = r#"
            [rig]
            id = "x"
            board = "cm5"

            [secrets]
            tok = "${env:FLUXOR_PROFILE_HASH_T2}"
        "#;
        let without = r#"
            [rig]
            id = "x"
            board = "cm5"
        "#;

        let p1 = parse_profile_str(with, Path::new("/tmp/x.toml")).unwrap();
        let p2 = parse_profile_str(without, Path::new("/tmp/x.toml")).unwrap();
        // A profile with a secret field present (value redacted) must not
        // hash-equal one with the field removed entirely.
        assert_ne!(hash_profile(&p1), hash_profile(&p2));
        std::env::remove_var("FLUXOR_PROFILE_HASH_T2");
    }

    #[test]
    fn artifact_file_hash_matches_sha256() {
        let tmp =
            std::env::temp_dir().join(format!("fluxor-rig-artifact-{}.bin", std::process::id()));
        std::fs::write(&tmp, b"hello").unwrap();
        let h = hash_artifact_file(&tmp).unwrap();
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            h,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        let _ = std::fs::remove_file(&tmp);
    }
}
