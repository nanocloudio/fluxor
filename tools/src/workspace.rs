//! `fluxor workspace` — the live-policy surface.
//!
//! A user-local `~/.fluxor/workspace.toml` lists project checkouts
//! whose artifacts are LIVE: `fluxor sync` write-through-resolves a
//! member's `:latest` store tags into the lockfile instead of
//! replaying pins verbatim, and `fluxor workspace publish`
//! republishes every member whose input digests drifted from its
//! published artifacts. Membership is the whole live/pinned
//! distinction — a policy question, never a file format or mode.
//!
//! This module owns the file (load, save, `add`/`rm`, `status`); the
//! resolution semantics live in `store_sync`.

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

/// Canonicalised workspace-member roots, excluding the current project.
///
/// Module lookup consults these last, so a graph can name a module owned by a
/// sibling checkout (wave's `http`, say) and still resolve its manifest for
/// validation. This mirrors sync's live-member policy, where a member's
/// checkout state (its `:latest` store tags) wins over replayed pins.
///
/// The workspace file is user-local and gitignored, so this is a developer
/// convenience only — never a build dependency. Fluxor must not require its
/// downstreams to be checked out, and anything that only resolves through this
/// path will not resolve on a clean clone or in CI.
///
/// Cached for the process lifetime: `standard_module_dirs` runs per module
/// lookup, and re-reading plus re-parsing the file for every module in a graph
/// is pure waste. A malformed or unreadable file yields an empty list — a
/// broken dev-local convenience must not fail an otherwise valid build.
pub fn member_roots(project: &Path) -> &'static [PathBuf] {
    static ROOTS: std::sync::OnceLock<Vec<PathBuf>> = std::sync::OnceLock::new();
    let all = ROOTS.get_or_init(|| match load_workspace() {
        Ok(Some(ws)) => ws
            .workspace
            .members
            .into_iter()
            .map(|m| m.canonicalize().unwrap_or(m))
            .collect(),
        _ => Vec::new(),
    });
    // `project` is not part of the cache key: within one invocation the project
    // root is fixed, and filtering here keeps the cached vector reusable.
    if all.iter().any(|m| m == project) {
        // Rare enough (one allocation per process) to leak deliberately rather
        // than thread a lifetime through every caller.
        static FILTERED: std::sync::OnceLock<Vec<PathBuf>> = std::sync::OnceLock::new();
        return FILTERED.get_or_init(|| all.iter().filter(|m| *m != project).cloned().collect());
    }
    all
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

/// Write `~/.fluxor/workspace.toml` (atomic replace; parent dir
/// created if needed).
pub fn save_workspace(ws: &Workspace) -> Result<PathBuf> {
    let path = workspace_file_path()?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)
            .map_err(|e| Error::Config(format!("create {}: {e}", dir.display())))?;
    }
    let body = toml::to_string_pretty(ws)
        .map_err(|e| Error::Config(format!("serialise workspace: {e}")))?;
    let tmp = path.with_extension(format!("toml.tmp.{}", std::process::id()));
    fs::write(&tmp, body).map_err(|e| Error::Config(format!("write {}: {e}", tmp.display())))?;
    if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(Error::Config(format!("rename to {}: {e}", path.display())));
    }
    Ok(path)
}

// ── CLI ───────────────────────────────────────────────────────────────

/// `fluxor workspace add <path>` — append a member (canonicalised;
/// creates the workspace file when absent; idempotent on re-add).
pub fn cmd_workspace_add(path: &Path) -> Result<()> {
    let member = path
        .canonicalize()
        .map_err(|e| Error::Config(format!("cannot resolve {}: {e}", path.display())))?;
    if !member.join("fluxor.toml").exists() {
        eprintln!(
            "note: {} has no fluxor.toml — added anyway, but it will never \
             resolve as a live project",
            member.display()
        );
    }
    let mut ws = load_workspace()?.unwrap_or(Workspace {
        workspace: WorkspaceSection::default(),
    });
    if ws.workspace.members.contains(&member) {
        println!("already a member: {}", member.display());
        return Ok(());
    }
    ws.workspace.members.push(member.clone());
    let file = save_workspace(&ws)?;
    println!("added {} to {}", member.display(), file.display());
    Ok(())
}

/// `fluxor workspace rm <path>` — remove a member. Errors when the
/// workspace file is absent or the path isn't listed.
pub fn cmd_workspace_rm(path: &Path) -> Result<()> {
    let Some(mut ws) = load_workspace()? else {
        return Err(Error::Config(format!(
            "no workspace file at {} — nothing to remove",
            workspace_file_path()?.display()
        )));
    };
    // Match either the literal entry or its canonical form, so `rm`
    // accepts the same spelling `add` recorded or a relative path to it.
    let canon = path.canonicalize().ok();
    let before = ws.workspace.members.len();
    ws.workspace
        .members
        .retain(|m| m != path && Some(m) != canon.as_ref());
    if ws.workspace.members.len() == before {
        return Err(Error::Config(format!(
            "{} is not a workspace member",
            path.display()
        )));
    }
    let file = save_workspace(&ws)?;
    println!("removed {} from {}", path.display(), file.display());
    Ok(())
}

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
