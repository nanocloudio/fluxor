//! Project build descriptor — maps a board id to the command that
//! produces its artifact and the path to the artifact on disk.
//!
//! RFC §15.2. Build knowledge only: serial paths, smart-plug identities,
//! TFTP roots, and rig-lock state live in the private rig profile under
//! `~/.config/fluxor/labs/`.
//!
//! The descriptor can live in either of two places, looked up in order
//! from the scenario's location:
//!
//!   1. `<user-config>/fluxor/projects/<project-name>/rig.toml` where
//!      `<user-config>` is `$XDG_CONFIG_HOME` (falling back to
//!      `$HOME/.config`) and `<project-name>` is the basename of the
//!      nearest `.git` root walking upward. Build commands run from the
//!      `.git` root.
//!   2. An in-tree `.fluxor-rig.toml` at a project root, walking
//!      upward from the scenario file. Build commands run from the
//!      descriptor's directory.
//!
//! Output paths are anchored to the build's working directory.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};

/// Filename for an in-tree descriptor.
pub const PROJECT_DESCRIPTOR: &str = ".fluxor-rig.toml";

/// Fully resolved project descriptor. `project_root` is the directory
/// the build command runs in and the anchor for relative output paths.
#[derive(Debug, Clone)]
pub struct ProjectDescriptor {
    pub project_root: PathBuf,
    /// Board id → build recipe.
    pub builds: HashMap<String, BuildRecipe>,
}

#[derive(Debug, Clone)]
pub struct BuildRecipe {
    /// argv of the build command (no shell interpretation).
    pub command: Vec<String>,
    /// Exactly one of `artifact` or `artifact_bundle_dir` is set.
    pub output: BuildOutput,
}

#[derive(Debug, Clone)]
pub enum BuildOutput {
    /// Single-file artifact (e.g. a UF2). Absolute path.
    File(PathBuf),
    /// Multi-file artifact bundle (e.g. CM5 boot bundle). Absolute path
    /// to the directory; the deploy adapter decides what to do with its
    /// contents based on the board's artifact class.
    Bundle(PathBuf),
}

impl ProjectDescriptor {
    /// Locate the descriptor for the project containing `start`.
    /// Returns `Ok(None)` when neither a user-config descriptor nor an
    /// in-tree `.fluxor-rig.toml` applies.
    pub fn discover(start: &Path) -> Result<Option<Self>> {
        if let Some(project_root) = find_git_root(start) {
            if let Some(name) = project_root.file_name().and_then(|s| s.to_str()) {
                if let Some(cfg) = user_config_descriptor_path(name) {
                    if cfg.is_file() {
                        return Self::load_for_project(&cfg, &project_root).map(Some);
                    }
                }
            }
        }
        if let Some(in_tree) = find_in_tree_descriptor(start) {
            return Self::load(&in_tree).map(Some);
        }
        Ok(None)
    }

    /// Load an in-tree descriptor. `project_root` is the descriptor's
    /// parent directory.
    pub fn load(path: &Path) -> Result<Self> {
        let root = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        Self::load_for_project(path, &root)
    }

    /// Load a descriptor while letting the caller specify the
    /// `project_root` that build commands run against. Used when the
    /// descriptor lives in user config but the build targets a
    /// separate source tree.
    pub fn load_for_project(path: &Path, project_root: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            Error::Config(format!(
                "rig: reading project descriptor {}: {}",
                path.display(),
                e
            ))
        })?;
        parse_project_str(&raw, project_root, &path.display().to_string())
    }

    pub fn recipe(&self, board_id: &str) -> Option<&BuildRecipe> {
        self.builds.get(board_id)
    }
}

/// Walk upward from `start` looking for a directory containing `.git`.
/// The first match is the project root.
fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut cursor = start.canonicalize().unwrap_or_else(|_| start.to_path_buf());
    if cursor.is_file() {
        cursor.pop();
    }
    loop {
        if cursor.join(".git").exists() {
            return Some(cursor);
        }
        if !cursor.pop() {
            return None;
        }
    }
}

/// Walk upward from `start` looking for an in-tree descriptor.
fn find_in_tree_descriptor(start: &Path) -> Option<PathBuf> {
    let mut cursor = start.canonicalize().unwrap_or_else(|_| start.to_path_buf());
    if cursor.is_file() {
        cursor.pop();
    }
    loop {
        let candidate = cursor.join(PROJECT_DESCRIPTOR);
        if candidate.is_file() {
            return Some(candidate);
        }
        if !cursor.pop() {
            return None;
        }
    }
}

fn user_config_descriptor_path(project_name: &str) -> Option<PathBuf> {
    let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|s| !s.is_empty()) {
        Some(PathBuf::from(xdg))
    } else {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config"))
    };
    base.map(|b| {
        b.join("fluxor")
            .join("projects")
            .join(project_name)
            .join("rig.toml")
    })
}

// ── TOML deserialization ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ProjectFile {
    #[serde(default)]
    build: HashMap<String, BuildToml>,
}

#[derive(Deserialize)]
struct BuildToml {
    command: Vec<String>,
    artifact: Option<String>,
    artifact_bundle_dir: Option<String>,
}

pub fn parse_project_str(raw: &str, project_root: &Path, ctx: &str) -> Result<ProjectDescriptor> {
    let f: ProjectFile = toml::from_str(raw)?;
    let mut builds = HashMap::with_capacity(f.build.len());
    for (board_id, b) in f.build {
        if b.command.is_empty() {
            return Err(Error::Config(format!(
                "{ctx}: [build.{board_id}].command is empty"
            )));
        }
        let output = match (b.artifact, b.artifact_bundle_dir) {
            (Some(_), Some(_)) => {
                return Err(Error::Config(format!(
                    "{ctx}: [build.{board_id}] has both 'artifact' and 'artifact_bundle_dir' \
                     — pick exactly one"
                )));
            }
            (Some(p), None) => BuildOutput::File(resolve(project_root, &p)),
            (None, Some(p)) => BuildOutput::Bundle(resolve(project_root, &p)),
            (None, None) => {
                return Err(Error::Config(format!(
                    "{ctx}: [build.{board_id}] must set one of 'artifact' or \
                     'artifact_bundle_dir'"
                )));
            }
        };
        builds.insert(
            board_id,
            BuildRecipe {
                command: b.command,
                output,
            },
        );
    }
    Ok(ProjectDescriptor {
        project_root: project_root.to_path_buf(),
        builds,
    })
}

fn resolve(root: &Path, p: &str) -> PathBuf {
    let pb = PathBuf::from(p);
    if pb.is_absolute() {
        pb
    } else {
        root.join(pb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_artifact_shapes() {
        let src = r#"
            [build.cm5]
            command = ["make", "firmware", "TARGET=cm5"]
            artifact_bundle_dir = "target/cm5/bundle"

            [build.pico2w]
            command = ["cargo", "build", "--release"]
            artifact = "target/thumbv8m.main-none-eabihf/release/firmware.uf2"
        "#;
        let p =
            parse_project_str(src, Path::new("/home/me/proj"), "proj/.fluxor-rig.toml").unwrap();
        assert_eq!(p.builds.len(), 2);

        let cm5 = p.recipe("cm5").unwrap();
        assert_eq!(cm5.command, vec!["make", "firmware", "TARGET=cm5"]);
        match &cm5.output {
            BuildOutput::Bundle(path) => {
                assert_eq!(path, &PathBuf::from("/home/me/proj/target/cm5/bundle"));
            }
            _ => panic!("expected bundle"),
        }

        let pico = p.recipe("pico2w").unwrap();
        match &pico.output {
            BuildOutput::File(path) => {
                assert!(path.ends_with("firmware.uf2"));
                assert!(path.is_absolute());
            }
            _ => panic!("expected file"),
        }
    }

    #[test]
    fn absolute_output_path_preserved() {
        let src = r#"
            [build.cm5]
            command = ["make"]
            artifact_bundle_dir = "/srv/fluxor/cm5-out"
        "#;
        let p = parse_project_str(src, Path::new("/proj"), "p").unwrap();
        match &p.recipe("cm5").unwrap().output {
            BuildOutput::Bundle(path) => assert_eq!(path, &PathBuf::from("/srv/fluxor/cm5-out")),
            _ => panic!(),
        }
    }

    #[test]
    fn empty_command_rejected() {
        let src = r#"
            [build.cm5]
            command = []
            artifact = "x.uf2"
        "#;
        assert!(parse_project_str(src, Path::new("/"), "p").is_err());
    }

    #[test]
    fn both_outputs_rejected() {
        let src = r#"
            [build.cm5]
            command = ["a"]
            artifact = "a.uf2"
            artifact_bundle_dir = "b"
        "#;
        assert!(parse_project_str(src, Path::new("/"), "p").is_err());
    }

    #[test]
    fn no_output_rejected() {
        let src = r#"
            [build.cm5]
            command = ["a"]
        "#;
        assert!(parse_project_str(src, Path::new("/"), "p").is_err());
    }

    #[test]
    fn load_for_project_uses_caller_supplied_root() {
        let tmp = crate::rig::test_utils::unique_tmp_dir("project-descriptor");
        let descriptor = tmp.join("rig.toml");
        std::fs::write(
            &descriptor,
            r#"
                [build.cm5]
                command = ["make"]
                artifact_bundle_dir = "target/out"
            "#,
        )
        .unwrap();

        let elsewhere = crate::rig::test_utils::unique_tmp_dir("project-source");
        let p = ProjectDescriptor::load_for_project(&descriptor, &elsewhere).unwrap();

        assert_eq!(p.project_root, elsewhere);
        match &p.recipe("cm5").unwrap().output {
            BuildOutput::Bundle(path) => {
                assert_eq!(path, &elsewhere.join("target").join("out"));
            }
            _ => panic!(),
        }

        std::fs::remove_dir_all(&tmp).ok();
        std::fs::remove_dir_all(&elsewhere).ok();
    }
}
