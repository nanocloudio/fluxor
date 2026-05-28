//! `fluxor sync` — install lockfile-resolved fmods into the local
//! build tree.
//!
//! The symmetric half of `fluxor publish fmod`: where publishing
//! writes `<name>.fmod` into `~/.fluxor/registry/fmod/<project>/<target>/
//! <name>/<version>.fmod`, sync reads the project's `fluxor.lock`
//! and copies every `[[fmod]]` entry into
//! `<project_root>/target/fluxor/<target>/modules/<name>.fmod` —
//! where the existing build / flash / run tooling expects to find
//! foundation fmods.
//!
//! Hash verification is mandatory: every destination file's
//! SHA-256 must match the lockfile's recorded `hash` field. This
//! catches registry tampering, partial publishes, and the case
//! where `fluxor.lock` was committed against one registry state but
//! the developer's machine has a different one.
//!
//! Workspace mode is detected and surfaced via advisory: when the
//! upstream lives as a live workspace member, sync *prefers* the
//! member's locally-built `target/` artefacts as an override.
//! Anything the member hasn't built locally falls through to the
//! lockfile's registry copy (hash-verified). This matches RFC §5's
//! "availability ≠ wiring" stance — the lockfile records what's
//! available; the live build is an optional iteration override, not
//! a prerequisite. A summary advisory names every workspace member
//! that fell back so developers know which local builds are missing.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::hash::file_sha256_prefixed;
use crate::lockfile;
use crate::project;
use crate::registry;
use crate::workspace;

pub fn cmd_sync(project_root: Option<&Path>, dry_run: bool) -> Result<()> {
    let pr = project_root
        .map(PathBuf::from)
        .unwrap_or_else(project::root);

    let lock = lockfile::read(&pr)?.ok_or_else(|| {
        Error::Config(format!(
            "{} not found — run `fluxor update` first",
            lockfile::lockfile_path(&pr).display()
        ))
    })?;

    if lock.fmods.is_empty() && lock.runtimes.is_empty() && lock.crates.is_empty() {
        println!("lockfile records no artefacts; nothing to sync.");
        return Ok(());
    }

    // Workspace mode: build a project → checkout-path map for the
    // live members. Fmods from those projects are sourced from the
    // member's `target/fluxor/<target>/modules/<name>.fmod` instead
    // of the registry. Lockfile hashes don't apply because the live
    // source is authoritative.
    let workspace_members = workspace_member_map();
    if let Ok(Some(ws)) = workspace::load_workspace() {
        if let Some(msg) = workspace::advisory(&ws, &pr) {
            println!("note: {msg}");
            println!(
                "      live workspace members will source fmods from their own target/ trees, bypassing the registry."
            );
            println!();
        }
    }

    let registry_root = registry::registry_root()?;

    let mut copied = 0usize;
    let mut copied_live = 0usize;
    let mut skipped_same = 0usize;
    let mut errors: Vec<String> = Vec::new();
    // (project, target) → count of fmods/runtimes that fell back to
    // the registry because the workspace member had no local build.
    // Aggregated to one summary line per (project, target) so a
    // freshly-cloned upstream doesn't generate dozens of identical
    // notes during a routine sync.
    let mut fallback_counts: BTreeMap<(String, String), usize> = BTreeMap::new();

    // Collision detection: the destination layout is flat
    // (`target/fluxor/<target>/modules/<name>.fmod`), so two
    // dependencies publishing the same `(target, name)` pair would
    // silently overwrite each other. Track every fmod we've written
    // this run and refuse a different-source / different-content
    // write to the same destination. Once the build resolver
    // supports yaml `dep::name` references, callers can disambiguate
    // explicitly; until then, sync surfaces the collision as a hard
    // error.
    let mut written_fmods: BTreeMap<PathBuf, (String, String)> = BTreeMap::new(); // dest -> (project, hash)

    for entry in &lock.fmods {
        // Resolve fmod source: live workspace member's local build
        // wins if present, otherwise fall back to the registry copy
        // recorded in the lockfile (hash-verified). A live workspace
        // member that hasn't built a particular fmod locally is fine
        // — that fmod just resolves from the registry like any
        // non-member dep. Iteration is opt-in per-artefact, not
        // all-or-nothing.
        //
        // Live layouts: `fluxor modules build` (no --out) writes to
        // `target/fluxor/<silicon>/modules/`; `make modules-all`
        // (`--out target`) writes to `target/<silicon>/modules/`.
        // Sync accepts either; the registry-shaped layout wins when
        // both exist.
        let live_src_opt = workspace_members
            .get(&entry.project)
            .and_then(|member_path| {
                let canonical = member_path
                    .join("target")
                    .join("fluxor")
                    .join(&entry.target)
                    .join("modules")
                    .join(format!("{}.fmod", entry.name));
                let flat = member_path
                    .join("target")
                    .join(&entry.target)
                    .join("modules")
                    .join(format!("{}.fmod", entry.name));
                if canonical.exists() {
                    Some(canonical)
                } else if flat.exists() {
                    Some(flat)
                } else {
                    None
                }
            });

        let (src, mode_label, expect_hash) = if let Some(live_src) = live_src_opt {
            (live_src, "live", None)
        } else {
            if workspace_members.contains_key(&entry.project) {
                *fallback_counts
                    .entry((entry.project.clone(), entry.target.clone()))
                    .or_insert(0) += 1;
            }
            let reg_src = registry_root.join(&entry.source);
            if !reg_src.exists() {
                errors.push(format!(
                    "source missing: {} (lockfile entry {}::{}/{})",
                    reg_src.display(),
                    entry.project,
                    entry.target,
                    entry.name,
                ));
                continue;
            }
            (reg_src, "registry", Some(entry.hash.as_str()))
        };

        // Hash verification only when sourcing from the registry —
        // live members are the authoritative source and may
        // legitimately diverge from the lockfile entry.
        let actual_hash = file_sha256_prefixed(&src)?;
        if let Some(want) = expect_hash {
            if actual_hash != want {
                errors.push(format!(
                    "hash mismatch on {} — lockfile says {} but file is {}",
                    src.display(),
                    want,
                    actual_hash,
                ));
                continue;
            }
        }

        let dest_dir = pr
            .join("target")
            .join("fluxor")
            .join(&entry.target)
            .join("modules");
        let dest = dest_dir.join(format!("{}.fmod", entry.name));

        // Cross-project collision: did an earlier iteration in this
        // sync already write this destination from a different
        // project? Same project + same hash is fine (idempotent —
        // multiple lockfile entries can point at the same file via
        // path/git overrides, etc.). Different content is a hard
        // error.
        if let Some((prev_project, prev_hash)) = written_fmods.get(&dest) {
            if prev_hash != &actual_hash {
                errors.push(format!(
                    "fmod name collision on `{}` for target `{}`: \
                     project `{}` and project `{}` both publish this module with different content. \
                     Rename one or use the yaml `dep::name` reference form to disambiguate.",
                    entry.name, entry.target, prev_project, entry.project
                ));
                continue;
            }
        }

        // Idempotency: if the destination already matches what
        // we're about to copy, nothing to do.
        if dest.exists() {
            let dest_hash = file_sha256_prefixed(&dest)?;
            if dest_hash == actual_hash {
                skipped_same += 1;
                written_fmods.insert(dest.clone(), (entry.project.clone(), actual_hash.clone()));
                continue;
            }
        }

        if dry_run {
            println!(
                "would copy [{}] {} → {} ({} bytes)",
                mode_label,
                src.display(),
                dest.display(),
                fs::metadata(&src).map(|m| m.len()).unwrap_or(0),
            );
            written_fmods.insert(dest.clone(), (entry.project.clone(), actual_hash.clone()));
            continue;
        }

        fs::create_dir_all(&dest_dir)?;
        fs::copy(&src, &dest)?;
        written_fmods.insert(dest.clone(), (entry.project.clone(), actual_hash.clone()));
        match mode_label {
            "live" => copied_live += 1,
            _ => copied += 1,
        }
    }

    // Source crates — extract each `.crate` tarball into
    // `<project>/target/fluxor/<crate-name>/`. PIC modules in
    // downstream projects reach into this stable path via
    // `#[path]` to consume the bundled `sdk/` subtree (which the
    // upstream crate ships via symlink-deref at package time).
    for entry in &lock.crates {
        // Skip path / git overrides — those don't go through the
        // registry-extract path.
        if entry.source.starts_with("path:") || entry.source.starts_with("git:") {
            continue;
        }

        let src = registry_root.join(&entry.source);
        if !src.exists() {
            errors.push(format!(
                "source crate missing: {} (lockfile entry {} {})",
                src.display(),
                entry.name,
                entry.version,
            ));
            continue;
        }

        let actual_hash = file_sha256_prefixed(&src)?;
        if actual_hash != entry.hash {
            errors.push(format!(
                "hash mismatch on {} — lockfile says {} but file is {}",
                src.display(),
                entry.hash,
                actual_hash,
            ));
            continue;
        }

        let crate_root_dir = pr.join("target").join("fluxor");
        let dest_dir = crate_root_dir.join(&entry.name);

        // Idempotency: stamp the dest with the resolved version
        // and skip if it matches.
        let stamp_path = dest_dir.join(".fluxor-sync-stamp");
        if stamp_path.exists() {
            if let Ok(stamp) = fs::read_to_string(&stamp_path) {
                if stamp.trim() == entry.hash {
                    skipped_same += 1;
                    continue;
                }
            }
        }

        if dry_run {
            println!(
                "would extract {} → {} ({} bytes)",
                src.display(),
                dest_dir.display(),
                fs::metadata(&src).map(|m| m.len()).unwrap_or(0),
            );
            continue;
        }

        // Extract into a sibling temp dir then atomic-rename. The
        // `.crate` tarball's root entry is `<name>-<version>/`; we
        // pull that up to a stable `<name>/`. Defensive tar flags:
        //   --no-same-owner / --no-same-permissions  — never honour
        //     owner/mode bits from the archive
        //   --no-overwrite-dir                       — refuse to
        //     replace an existing directory's metadata
        //   -P is intentionally NOT passed, so tar strips absolute /
        //     traversal paths by default.
        fs::create_dir_all(&crate_root_dir)?;
        let tmp_extract = crate_root_dir.join(format!(".tmp-{}-{}", entry.name, entry.version));
        cleanup_or_warn(&tmp_extract, &mut errors);
        fs::create_dir_all(&tmp_extract)?;
        let status = std::process::Command::new("tar")
            .args(["-xzf"])
            .arg(&src)
            .args([
                "--no-same-owner",
                "--no-same-permissions",
                "--no-overwrite-dir",
                "-C",
            ])
            .arg(&tmp_extract)
            .status()
            .map_err(|e| Error::Config(format!("spawn tar: {e}")))?;
        if !status.success() {
            errors.push(format!(
                "tar extract failed for {} (exit {status})",
                src.display()
            ));
            cleanup_or_warn(&tmp_extract, &mut errors);
            continue;
        }

        // Require exactly one top-level directory in the extracted
        // tree. A well-formed `.crate` tarball always ships its
        // contents under `<name>-<version>/`; multiple top-level
        // entries indicate either tampering or a foreign tarball
        // shape we don't support.
        let entries: Vec<fs::DirEntry> = fs::read_dir(&tmp_extract)?
            .filter_map(std::result::Result::ok)
            .collect();
        let inner = match entries.as_slice() {
            [only] => only.path(),
            [] => {
                errors.push(format!("{} extracted to an empty directory", src.display()));
                cleanup_or_warn(&tmp_extract, &mut errors);
                continue;
            }
            _ => {
                errors.push(format!(
                    "{} extracted to {} top-level entries; expected exactly one `<name>-<version>/` directory",
                    src.display(),
                    entries.len(),
                ));
                cleanup_or_warn(&tmp_extract, &mut errors);
                continue;
            }
        };

        if dest_dir.exists() {
            fs::remove_dir_all(&dest_dir)?;
        }
        fs::rename(&inner, &dest_dir)?;
        cleanup_or_warn(&tmp_extract, &mut errors);

        // Write the stamp so subsequent syncs are O(1) when
        // unchanged.
        fs::write(&stamp_path, &entry.hash)?;
        copied += 1;
    }

    // Runtime binaries — same live-override / registry-fallback
    // shape as fmods above. Live source is `<member>/target/
    // <host-target>/release/<name>`; absent that, the lockfile's
    // registry copy resolves.
    for entry in &lock.runtimes {
        let live_src_opt = workspace_members
            .get(&entry.project)
            .and_then(|member_path| {
                let live_src = member_path
                    .join("target")
                    .join(&entry.host_target)
                    .join("release")
                    .join(&entry.name);
                if live_src.exists() {
                    Some(live_src)
                } else {
                    None
                }
            });

        let (src, mode_label, expect_hash) = if let Some(live_src) = live_src_opt {
            (live_src, "live", None)
        } else {
            if workspace_members.contains_key(&entry.project) {
                *fallback_counts
                    .entry((entry.project.clone(), entry.host_target.clone()))
                    .or_insert(0) += 1;
            }
            let reg_src = registry_root.join(&entry.source);
            if !reg_src.exists() {
                errors.push(format!(
                    "runtime source missing: {} (lockfile entry {}::{}/{})",
                    reg_src.display(),
                    entry.project,
                    entry.host_target,
                    entry.name,
                ));
                continue;
            }
            (reg_src, "registry", Some(entry.hash.as_str()))
        };

        let actual_hash = file_sha256_prefixed(&src)?;
        if let Some(want) = expect_hash {
            if actual_hash != want {
                errors.push(format!(
                    "hash mismatch on {} — lockfile says {} but file is {}",
                    src.display(),
                    want,
                    actual_hash,
                ));
                continue;
            }
        }

        let dest_dir = pr.join("target").join(&entry.host_target).join("release");
        let dest = dest_dir.join(&entry.name);

        if dest.exists() {
            let dest_hash = file_sha256_prefixed(&dest)?;
            if dest_hash == actual_hash {
                skipped_same += 1;
                continue;
            }
        }

        if dry_run {
            println!(
                "would copy [{}] {} → {} ({} bytes)",
                mode_label,
                src.display(),
                dest.display(),
                fs::metadata(&src).map(|m| m.len()).unwrap_or(0),
            );
            continue;
        }

        fs::create_dir_all(&dest_dir)?;
        fs::copy(&src, &dest)?;
        // Ensure executable bit on the destination — the .crate / fs::copy
        // chain *should* preserve mode but cheap defence-in-depth.
        let mut perms = fs::metadata(&dest)?.permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        fs::set_permissions(&dest, perms)?;
        match mode_label {
            "live" => copied_live += 1,
            _ => copied += 1,
        }
    }

    for line in &errors {
        eprintln!("error: {line}");
    }

    // One-line advisory per (workspace-member, target) that lacked
    // local builds. Aggregated so a freshly-cloned upstream doesn't
    // produce dozens of noisy lines — most of the time the developer
    // just hasn't built anything yet, and that's fine.
    for ((project, target), count) in &fallback_counts {
        println!(
            "note: workspace member `{project}` had no local build for {count} artefact(s) ({target}); used registry copies (lockfile-pinned)"
        );
    }

    let total_entries = lock.fmods.len() + lock.runtimes.len() + lock.crates.len();
    if dry_run {
        println!(
            "\ndry-run: {} entries; {} would copy, {} already in place, {} errors.",
            total_entries,
            total_entries - skipped_same - errors.len(),
            skipped_same,
            errors.len(),
        );
    } else {
        println!(
            "sync: copied {copied} (registry) + {copied_live} (live), {skipped_same} already in place, {} errors.",
            errors.len()
        );
    }

    if !errors.is_empty() {
        return Err(Error::Config(format!(
            "{} artefact(s) failed to sync — see errors above",
            errors.len()
        )));
    }
    Ok(())
}

/// Remove a directory if present. The expected failure modes are
/// "not there yet" (first-run before the temp dir is created) and
/// "still there after a crashed extract" (which we want to delete).
/// Errors that aren't `NotFound` are surfaced via `errors` so they
/// don't accumulate orphan `.tmp-*` dirs silently.
fn cleanup_or_warn(path: &Path, errors: &mut Vec<String>) {
    match fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => errors.push(format!(
            "could not clean up temp extract at {}: {e}",
            path.display(),
        )),
    }
}

/// Build a map from `[project].name` to the workspace member's
/// checkout path. Members whose `fluxor.toml` is missing or has no
/// `[project].name` are silently dropped — they're not live for
/// any project-name-keyed lookup.
fn workspace_member_map() -> BTreeMap<String, PathBuf> {
    let mut out: BTreeMap<String, PathBuf> = BTreeMap::new();
    let Ok(Some(ws)) = workspace::load_workspace() else {
        return out;
    };
    for member in &ws.workspace.members {
        let Ok(canon) = member.canonicalize() else {
            continue;
        };
        let Ok(Some(identity)) = project::project_identity(&canon) else {
            continue;
        };
        out.insert(identity.name, canon);
    }
    out
}
