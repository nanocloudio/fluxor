//! `fluxor workspace` — live-workspace detection and surface.
//!
//! A user-local `~/.fluxor/workspace.toml` lists project checkouts
//! the CLI should treat as live source rather than registry
//! artefacts. `fluxor sync` prefers a workspace member's locally-
//! built fmods / runtime binaries over the registry copy when both
//! exist; CI's lockfile-consistency check skips with an advisory
//! rather than failing.
//!
//! Source crates (`fluxor-abi`, `fluxor-sdk`) still resolve through
//! the registry — workspace mode doesn't yet bypass `make publish`
//! for SDK source edits.
//!
//! This module is the detection + inspection surface. The override
//! semantics live in the consuming commands (`publish` /
//! `sync` / `ci`).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Resolve `~/.fluxor/workspace.toml`. `$FLUXOR_WORKSPACE` overrides
/// the default location — primarily for tests.
pub fn workspace_file_path() -> Result<PathBuf> {
    if let Some(v) = std::env::var_os("FLUXOR_WORKSPACE") {
        return Ok(PathBuf::from(v));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| {
        Error::Config(
            "cannot resolve workspace file: neither $HOME nor $FLUXOR_WORKSPACE is set".into(),
        )
    })?;
    Ok(PathBuf::from(home).join(".fluxor").join("workspace.toml"))
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Workspace {
    #[serde(default)]
    pub workspace: WorkspaceSection,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WorkspaceSection {
    /// Absolute paths to live project checkouts.
    #[serde(default)]
    pub members: Vec<PathBuf>,
}

/// Load `~/.fluxor/workspace.toml` if it exists. Returns `Ok(None)`
/// when the file is absent — that's the normal "pinned-mode only"
/// state, not an error.
pub fn load_workspace() -> Result<Option<Workspace>> {
    let path = workspace_file_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path)
        .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
    let ws: Workspace = toml::from_str(&text)
        .map_err(|e| Error::Config(format!("parse {}: {e}", path.display())))?;
    Ok(Some(ws))
}

#[derive(Debug, Clone)]
pub struct MemberStatus {
    pub path: PathBuf,
    pub exists: bool,
    /// `true` iff `path/fluxor.toml` exists. Members that point at
    /// non-fluxor checkouts are kept (a developer may be juggling
    /// adjacent repos) but flagged.
    pub has_fluxor_toml: bool,
    pub is_absolute: bool,
}

impl MemberStatus {
    fn evaluate(path: &Path) -> Self {
        let exists = path.exists();
        let has_fluxor_toml = path.join("fluxor.toml").exists();
        let is_absolute = path.is_absolute();
        MemberStatus {
            path: path.to_path_buf(),
            exists,
            has_fluxor_toml,
            is_absolute,
        }
    }
}

/// Return the workspace member containing `cwd`, if any. Match is by
/// canonical-path prefix.
pub fn current_member(ws: &Workspace, cwd: &Path) -> Option<PathBuf> {
    let cwd_canon = cwd.canonicalize().ok()?;
    for member in &ws.workspace.members {
        let Ok(member_canon) = member.canonicalize() else {
            continue;
        };
        if cwd_canon.starts_with(&member_canon) {
            return Some(member_canon);
        }
    }
    None
}

/// One-line advisory describing the live-mode state. Build / publish
/// commands print this once per invocation so users know when
/// registry resolution is being bypassed.
pub fn advisory(ws: &Workspace, cwd: &Path) -> Option<String> {
    let active = current_member(ws, cwd)?;
    let live_count = ws
        .workspace
        .members
        .iter()
        .filter(|m| m.canonicalize().is_ok())
        .count();
    Some(format!(
        "workspace mode active: {} member{} live, current project = {}",
        live_count,
        if live_count == 1 { "" } else { "s" },
        active.display(),
    ))
}

// ── CLI ───────────────────────────────────────────────────────────────

pub fn cmd_workspace_status(json: bool) -> Result<()> {
    let path = workspace_file_path()?;
    let ws = load_workspace()?;
    let cwd = std::env::current_dir()?;

    if json {
        #[derive(Serialize)]
        struct StatusOutput<'a> {
            workspace_file: &'a Path,
            present: bool,
            members: Vec<MemberStatusJson>,
            cwd: &'a Path,
            active_member: Option<PathBuf>,
        }
        #[derive(Serialize)]
        struct MemberStatusJson {
            path: PathBuf,
            exists: bool,
            has_fluxor_toml: bool,
            is_absolute: bool,
        }
        let members: Vec<MemberStatusJson> = ws
            .as_ref()
            .map(|w| {
                w.workspace
                    .members
                    .iter()
                    .map(|m| {
                        let s = MemberStatus::evaluate(m);
                        MemberStatusJson {
                            path: s.path,
                            exists: s.exists,
                            has_fluxor_toml: s.has_fluxor_toml,
                            is_absolute: s.is_absolute,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let active = ws.as_ref().and_then(|w| current_member(w, &cwd));
        let out = StatusOutput {
            workspace_file: &path,
            present: ws.is_some(),
            members,
            cwd: &cwd,
            active_member: active,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("workspace file: {}", path.display());
    let Some(ws) = ws else {
        println!("status:         not present (pinned-mode only)");
        return Ok(());
    };
    println!(
        "status:         present, {} member(s)",
        ws.workspace.members.len()
    );
    println!("cwd:            {}", cwd.display());

    let active = current_member(&ws, &cwd);
    match &active {
        Some(m) => println!("mode:           LIVE (current member: {})", m.display()),
        None => println!("mode:           pinned (cwd outside every workspace member)"),
    }

    println!();
    if ws.workspace.members.is_empty() {
        println!("members: (none)");
        return Ok(());
    }
    println!("members:");
    for member in &ws.workspace.members {
        let s = MemberStatus::evaluate(member);
        let mut tags: Vec<&str> = Vec::new();
        if !s.is_absolute {
            tags.push("not-absolute");
        }
        if !s.exists {
            tags.push("missing");
        } else if !s.has_fluxor_toml {
            tags.push("no-fluxor.toml");
        }
        let tag_str = if tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", tags.join(", "))
        };
        let active_marker = match &active {
            Some(a) if member.canonicalize().ok().as_ref() == Some(a) => " *",
            _ => "  ",
        };
        println!("  {}{}{}", active_marker, member.display(), tag_str);
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_workspace_section() {
        let text = "[workspace]\nmembers = []\n";
        let ws: Workspace = toml::from_str(text).unwrap();
        assert!(ws.workspace.members.is_empty());
    }

    #[test]
    fn parse_workspace_with_members() {
        let text = r#"
            [workspace]
            members = [
              "/srv/code/fluxor",
              "/srv/code/projectA",
            ]
        "#;
        let ws: Workspace = toml::from_str(text).unwrap();
        assert_eq!(ws.workspace.members.len(), 2);
        assert_eq!(ws.workspace.members[0], PathBuf::from("/srv/code/fluxor"));
    }

    #[test]
    fn current_member_finds_cwd_under_member() {
        let tmp = std::env::temp_dir().join("fluxor_workspace_test_a");
        let nested = tmp.join("nested/dir");
        let _ = fs::create_dir_all(&nested);
        let ws = Workspace {
            workspace: WorkspaceSection {
                members: vec![tmp.clone()],
            },
        };
        let found = current_member(&ws, &nested);
        assert_eq!(found, tmp.canonicalize().ok());
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn current_member_returns_none_when_outside() {
        let tmp = std::env::temp_dir().join("fluxor_workspace_test_b");
        let _ = fs::create_dir_all(&tmp);
        let other = std::env::temp_dir().join("fluxor_workspace_test_b_other");
        let _ = fs::create_dir_all(&other);
        let ws = Workspace {
            workspace: WorkspaceSection {
                members: vec![tmp.clone()],
            },
        };
        let found = current_member(&ws, &other);
        assert!(found.is_none());
        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(&other);
    }
}
