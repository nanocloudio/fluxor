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
//! Hash verification is mandatory for registry-sourced artefacts:
//! every destination file's SHA-256 must match the lockfile's
//! recorded `hash` field. This catches registry tampering, partial
//! publishes, and the case where `fluxor.lock` was committed against
//! one registry state but the developer's machine has a different
//! one.
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
//!
//! **Live-sourced destinations are symlinks, not copies** — for all
//! three artefact kinds (fmods, runtime binaries, and `[[crate]]`
//! source-crate directories). A copy, however freshly taken, is only
//! ever accurate as of the moment sync ran, which quietly defeats the
//! point of a *live* workspace member: every subsequent upstream
//! rebuild would need another `fluxor sync` to be seen downstream.
//! A symlink needs no further sync, ever — the live artefact's next
//! rebuild (or, for `[[crate]]`, the live source's next edit) is
//! visible immediately. Registry-sourced destinations are still
//! plain copies, hash-verified against the lockfile, since a
//! registry artefact is an immutable pinned version, not something
//! that changes out from under the copy.
//!
//! `[[crate]]` entries need one extra step because `LockedCrate`
//! carries no `project` field (unlike `[[fmod]]`/`[[runtime]]`): the
//! owning workspace member is inferred from the `<project>-*`
//! crate-naming rule (standards/dependencies.md §9), and the symlink
//! points directly at that member's crate source directory rather
//! than at a build output.

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

    run_sync(&pr, &lock, dry_run, false)
}

/// Re-create every lockfile-recorded destination that is missing —
/// the implicit half of `fluxor sync`, run by build/run pre-flights
/// so `cargo clean` (which wipes the staged `target/` tree) doesn't
/// demand a manual re-sync the lockfile + workspace config already
/// fully determine. Strictly re-executes the recorded
/// materialization: never resolves versions, never touches
/// `fluxor.lock`, and fails exactly where `fluxor sync` would
/// (missing registry artefact, hash mismatch). No-op when the
/// project has no lockfile or every destination is present.
pub fn ensure_materialized(project_root: &Path) -> Result<()> {
    let Some(lock) = lockfile::read(project_root)? else {
        return Ok(());
    };
    if lock.fmods.is_empty() && lock.runtimes.is_empty() && lock.crates.is_empty() {
        return Ok(());
    }
    if all_destinations_present(project_root, &lock) {
        return Ok(());
    }
    eprintln!(
        "note: staged artefacts missing from target/ — re-materializing from fluxor.lock \
         (run `fluxor sync` for the full report)"
    );
    run_sync(project_root, &lock, false, true)
}

/// True when every lockfile-recorded destination exists (a broken
/// symlink counts as missing). Content staleness is deliberately not
/// checked — refreshing a stale registry copy is `fluxor sync`'s
/// job; the implicit path only fills holes.
fn all_destinations_present(pr: &Path, lock: &lockfile::LockFile) -> bool {
    for entry in &lock.fmods {
        let dest = pr
            .join("target")
            .join("fluxor")
            .join(&entry.target)
            .join("modules")
            .join(format!("{}.fmod", entry.name));
        if fs::metadata(&dest).is_err() {
            return false;
        }
    }
    for entry in &lock.crates {
        if entry.source.starts_with("path:") || entry.source.starts_with("git:") {
            continue;
        }
        if fs::metadata(pr.join("target").join("fluxor").join(&entry.name)).is_err() {
            return false;
        }
    }
    for entry in &lock.runtimes {
        let dest = pr
            .join("target")
            .join(&entry.host_target)
            .join("release")
            .join(&entry.name);
        if fs::metadata(&dest).is_err() {
            return false;
        }
    }
    true
}

/// The materialization body shared by `cmd_sync` (verbose) and
/// `ensure_materialized` (quiet). `quiet` suppresses the advisory /
/// fallback / summary chatter; errors always surface either way.
fn hex12(d: &[u8; 32]) -> String {
    d.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// Why an `.fmod` cannot be loaded by the current runtime, or `""` if it can.
///
/// Two rejections, both meaning "staging this can only fail later":
///   * it does not parse as a module at all (a snapshot built against a
///     different manifest layout reads as a size mismatch), so no consumer
///     can load it;
///   * it attests an ABI surface that is not the current one.
///
/// An artefact carrying no attestation is left alone: that is a separate,
/// pack-time concern with its own diagnosis.
fn unloadable(path: &Path) -> String {
    match crate::modules::ModuleInfo::from_file(path) {
        Err(e) => format!("does not parse as a module ({e})"),
        Ok(info) => match info.manifest.abi_surface {
            Some(embedded) if embedded != crate::hash::abi_surface_digest() => format!(
                "attests ABI surface {}, current is {}",
                hex12(&embedded),
                hex12(&crate::hash::abi_surface_digest())
            ),
            _ => String::new(),
        },
    }
}

fn run_sync(pr: &Path, lock: &lockfile::LockFile, dry_run: bool, quiet: bool) -> Result<()> {
    if lock.fmods.is_empty() && lock.runtimes.is_empty() && lock.crates.is_empty() {
        if !quiet {
            println!("lockfile records no artefacts; nothing to sync.");
        }
        return Ok(());
    }

    // Workspace mode: build a project → checkout-path map for the
    // live members. Fmods from those projects are sourced from the
    // member's `target/fluxor/<target>/modules/<name>.fmod` instead
    // of the registry. Lockfile hashes don't apply because the live
    // source is authoritative.
    let workspace_members = workspace_member_map();
    if !quiet {
        if let Ok(Some(ws)) = workspace::load_workspace() {
            if let Some(msg) = workspace::advisory(&ws, pr) {
                println!("note: {msg}");
                println!(
                    "      live workspace members will source fmods from their own target/ trees, bypassing the registry."
                );
                println!();
            }
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
        // `target/fluxor/<silicon>/modules/`; `fluxor modules build
        // --all --out target` writes to `target/<silicon>/modules/`.
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

        // Idempotency:
        // - live: dest is already a symlink pointing at `src` — done,
        //   permanently. This is what makes live mode actually live:
        //   an upstream rebuild needs no re-sync, ever, because the
        //   destination was never a snapshot to begin with.
        // - registry: dest's content already matches what we'd copy.
        let mut already_current = if mode_label == "live" {
            fs::read_link(&dest).map(|t| t == src).unwrap_or(false)
        } else {
            dest.exists() && file_sha256_prefixed(&dest)? == actual_hash
        };
        // ABI-surface freshness, the same invalidation trigger
        // `modules_build::is_up_to_date` applies to modules a project
        // builds itself — extended here to modules it STAGES. Content
        // equality with the source says the copy is faithful, not that
        // it is loadable: after an ABI-surface change every artefact
        // built before it is dead on arrival, and a registry snapshot
        // stays dead until upstream rebuilds AND republishes. Without
        // this check `sync` reports "already in place", the stale file
        // survives, and the failure surfaces much later as a confusing
        // "built against a different ABI surface" at graph-build time.
        // Re-copying cannot fix a stale SOURCE, so say so precisely
        // instead of silently staging it.
        if already_current && !unloadable(&dest).is_empty() {
            already_current = false;
        }
        // An unloadable source is reported but still staged. Refusing to stage
        // it would trade a precise load-time error for a missing-file one, and
        // an ABI-surface change makes every not-yet-rebuilt snapshot unloadable
        // at once — a hard failure there blocks every consumer on an upstream
        // rebuild. Warning keeps the diagnosis without holding the tree
        // hostage.
        if !dry_run && !quiet {
            let why = unloadable(&src);
            if !why.is_empty() {
                eprintln!(
                    "warning: {} {why} — rebuild it upstream with `fluxor modules build`{}",
                    src.display(),
                    if mode_label == "registry" {
                        " and republish with `fluxor publish`. If the module no longer exists \
                         upstream this registry snapshot is an orphan: delete it and re-run \
                         `fluxor update` so consumers stop carrying it"
                    } else {
                        ""
                    },
                );
            }
        }
        if already_current {
            skipped_same += 1;
            written_fmods.insert(dest.clone(), (entry.project.clone(), actual_hash.clone()));
            continue;
        }

        if dry_run {
            println!(
                "would {} [{}] {} → {} ({} bytes)",
                if mode_label == "live" {
                    "symlink"
                } else {
                    "copy"
                },
                mode_label,
                src.display(),
                dest.display(),
                fs::metadata(&src).map(|m| m.len()).unwrap_or(0),
            );
            written_fmods.insert(dest.clone(), (entry.project.clone(), actual_hash.clone()));
            continue;
        }

        fs::create_dir_all(&dest_dir)?;
        if mode_label == "live" {
            // Clear whatever's at `dest` (a stale registry copy, or a
            // symlink pointing at a since-moved live artefact) before
            // relinking. `dest` is always a plain file or symlink
            // here, never a directory.
            match fs::symlink_metadata(&dest) {
                Ok(_) => fs::remove_file(&dest)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    errors.push(format!(
                        "could not inspect {} before relinking: {e}",
                        dest.display()
                    ));
                    continue;
                }
            }
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&src, &dest)?;
            }
            #[cfg(not(unix))]
            {
                errors.push(format!(
                    "live-fmod symlinking isn't implemented on this platform (needed {} → {})",
                    dest.display(),
                    src.display(),
                ));
                continue;
            }
        } else {
            // Clear `dest` first — for the same reason the `live` arm above
            // does, but the consequence here is far worse than a stale link.
            //
            // A tree previously synced in `live` mode carries `dest` as a
            // symlink back to `src` (the producing project's
            // `target/fluxor/<silicon>/modules/<name>.fmod`). `fs::copy`
            // follows the destination symlink and opens it
            // `.write(true).truncate(true)`, so it truncates `src`, reads
            // 0 bytes from it, and writes those 0 bytes back — destroying
            // the artefact it was asked to copy. `std::fs::copy` has no
            // same-file guard, unlike coreutils `cp`, so this is silent, and
            // the consumer cannot repair it because the destroyed originals
            // live in the producing checkout.
            //
            // Removing `dest` makes the copy write a fresh file, leaving
            // `src` untouched whether or not a stale live-link is present.
            if let Err(e) = copy_replacing(&src, &dest) {
                errors.push(format!(
                    "could not copy {} -> {}: {e}",
                    src.display(),
                    dest.display()
                ));
                continue;
            }
        }
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
    //
    // Live-override: unlike `[[fmod]]`/`[[runtime]]`, `LockedCrate`
    // carries no `project` field (a crate is identified by
    // name+version+hash alone), so the owning workspace member is
    // inferred from the `<project>-*` naming rule
    // (standards/dependencies.md §9) — the longest workspace-member
    // project name `entry.name` starts with, followed by a hyphen.
    //
    // When a live member owns the crate, the destination is a
    // SYMLINK straight to that member's own crate source directory —
    // not a copy. A copy (even a freshly-repackaged one) is only ever
    // accurate as of the moment sync ran — a "sync again after every
    // upstream edit" requirement that quietly defeats the point of a
    // *live* workspace member. A symlink, once created, needs no further
    // sync ever — the live checkout's own edits are visible
    // downstream immediately, the same instant `#[path]`-including
    // module source is compiled. This intentionally skips the
    // publish-time `include = [...]` curation (see e.g.
    // `crates/clustor-common/Cargo.toml`'s comment on that allowlist)
    // — consistent with the existing live-mode trust boundary for
    // fmods/runtimes ("hash verification is skipped — the live
    // source is authoritative"), just applied one layer earlier.
    for entry in &lock.crates {
        // Skip path / git overrides — those don't go through the
        // registry-extract path.
        if entry.source.starts_with("path:") || entry.source.starts_with("git:") {
            continue;
        }

        let live_owner = workspace_members
            .keys()
            .filter(|project| entry.name.starts_with(&format!("{project}-")))
            .max_by_key(|project| project.len());

        if let Some(project) = live_owner {
            let member_path = workspace_members[project].clone();
            sync_live_crate(
                pr,
                &member_path,
                project,
                entry,
                dry_run,
                &mut skipped_same,
                &mut copied_live,
                &mut errors,
            )?;
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

        // Idempotency — same live-symlink-vs-registry-hash split as
        // the fmod loop above; see its comment for the rationale.
        let already_current = if mode_label == "live" {
            fs::read_link(&dest).map(|t| t == src).unwrap_or(false)
        } else {
            dest.exists() && file_sha256_prefixed(&dest)? == actual_hash
        };
        if already_current {
            skipped_same += 1;
            continue;
        }

        if dry_run {
            println!(
                "would {} [{}] {} → {} ({} bytes)",
                if mode_label == "live" {
                    "symlink"
                } else {
                    "copy"
                },
                mode_label,
                src.display(),
                dest.display(),
                fs::metadata(&src).map(|m| m.len()).unwrap_or(0),
            );
            continue;
        }

        fs::create_dir_all(&dest_dir)?;
        if mode_label == "live" {
            match fs::symlink_metadata(&dest) {
                Ok(_) => fs::remove_file(&dest)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    errors.push(format!(
                        "could not inspect {} before relinking: {e}",
                        dest.display()
                    ));
                    continue;
                }
            }
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&src, &dest)?;
            }
            #[cfg(not(unix))]
            {
                errors.push(format!(
                    "live-runtime symlinking isn't implemented on this platform (needed {} → {})",
                    dest.display(),
                    src.display(),
                ));
                continue;
            }
            // No chmod: the live binary already has its correct
            // executable bit from whatever built it (`cargo build`),
            // and a symlink's own mode is meaningless on Linux — the
            // target's permissions are what a caller actually sees.
        } else {
            fs::copy(&src, &dest)?;
            // Ensure executable bit on the destination — the .crate / fs::copy
            // chain *should* preserve mode but cheap defence-in-depth.
            let mut perms = fs::metadata(&dest)?.permissions();
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o755);
            fs::set_permissions(&dest, perms)?;
        }
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
    if !quiet {
        for ((project, target), count) in &fallback_counts {
            println!(
                "note: workspace member `{project}` had no local build for {count} artefact(s) ({target}); used registry copies (lockfile-pinned)"
            );
        }
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
    } else if !quiet {
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

/// Resolve `target/fluxor/<entry.name>` to a symlink at the live
/// workspace member's own crate source directory, creating or
/// repairing it as needed. This is the live-mode counterpart to the
/// registry tar-extraction below it — see the crate loop's doc
/// comment for why a symlink (not a copy, not even a freshly
/// re-packaged one) is what actually delivers on "live": once
/// created, it never goes stale, so this function only does real
/// work the first time or when something has changed the target.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors the counters/errors threaded through every loop in this file; a struct would be one-call overhead for no reuse"
)]
fn sync_live_crate(
    pr: &Path,
    member_path: &Path,
    project: &str,
    entry: &crate::lockfile::LockedCrate,
    dry_run: bool,
    skipped_same: &mut usize,
    copied_live: &mut usize,
    errors: &mut Vec<String>,
) -> Result<()> {
    let live_src_dir = match crate::publish::locate_member_manifest(member_path, &entry.name) {
        Ok(manifest_path) => manifest_path
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| {
                Error::Config(format!(
                    "workspace member `{project}` manifest {} has no parent directory",
                    manifest_path.display()
                ))
            }),
        Err(e) => Err(e),
    };
    let live_src_dir = match live_src_dir {
        Ok(dir) => dir,
        Err(e) => {
            errors.push(format!(
                "could not locate live source for crate `{}` in workspace member `{project}`: {e}",
                entry.name,
            ));
            return Ok(());
        }
    };

    let crate_root_dir = pr.join("target").join("fluxor");
    let dest_dir = crate_root_dir.join(&entry.name);

    // Idempotency: already a symlink pointing at the right place?
    // Nothing to do — this is the common case on every sync after
    // the first.
    if let Ok(existing_target) = fs::read_link(&dest_dir) {
        if existing_target == live_src_dir {
            *skipped_same += 1;
            return Ok(());
        }
    }

    if dry_run {
        println!(
            "would symlink [live] {} → {}",
            dest_dir.display(),
            live_src_dir.display(),
        );
        return Ok(());
    }

    // Clear whatever's there: a stale symlink (wrong target), a
    // stale directory (a registry-extracted copy from before this
    // member was live), or nothing at all.
    match fs::symlink_metadata(&dest_dir) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            fs::remove_dir_all(&dest_dir)?;
        }
        Ok(_) => fs::remove_file(&dest_dir)?, // existing symlink, wrong target
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            errors.push(format!(
                "could not inspect {} before relinking: {e}",
                dest_dir.display()
            ));
            return Ok(());
        }
    }

    fs::create_dir_all(&crate_root_dir)?;
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&live_src_dir, &dest_dir)?;
    }
    #[cfg(not(unix))]
    {
        errors.push(format!(
            "live-crate symlinking isn't implemented on this platform \
             (needed {} → {})",
            dest_dir.display(),
            live_src_dir.display(),
        ));
        return Ok(());
    }

    *copied_live += 1;
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

/// Copy `src` over `dest`, removing `dest` first.
///
/// The removal is the whole point. See the call site for the full account:
/// when `dest` is a symlink back to `src` — which is exactly what a previous
/// `live`-mode sync leaves behind — a bare `fs::copy` follows the destination
/// link, truncates `src`, and then copies the resulting 0 bytes over itself.
/// Rust's `std::fs::copy` has no same-file guard, so it destroys the artefact
/// silently and reports success.
fn copy_replacing(src: &Path, dest: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(dest) {
        Ok(_) => fs::remove_file(dest)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    fs::copy(src, dest).map(|_| ())
}

#[cfg(test)]
mod copy_replacing_tests {
    use super::copy_replacing;
    use std::fs;

    /// A downstream project synced in `live` mode holds `dest` as a symlink
    /// to the producing project's real artefact; a later non-live sync must
    /// not destroy it.
    #[test]
    fn copy_over_symlink_pointing_at_source_preserves_source() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("ip.fmod");
        let dest_dir = tmp.path().join("consumer");
        fs::create_dir_all(&dest_dir).unwrap();
        let dest = dest_dir.join("ip.fmod");

        fs::write(&src, b"real module bytes").unwrap();
        std::os::unix::fs::symlink(&src, &dest).unwrap();

        copy_replacing(&src, &dest).unwrap();

        assert_eq!(
            fs::read(&src).unwrap(),
            b"real module bytes",
            "source artefact was destroyed by the copy"
        );
        assert_eq!(fs::read(&dest).unwrap(), b"real module bytes");
        assert!(
            !fs::symlink_metadata(&dest)
                .unwrap()
                .file_type()
                .is_symlink(),
            "dest should be a real file after a non-live sync, not a link"
        );
    }

    /// A bare `fs::copy` in the same situation destroys the source — this is
    /// the behaviour `copy_replacing` exists to prevent, pinned so nobody
    /// "simplifies" the removal away.
    #[test]
    fn bare_fs_copy_would_destroy_the_source() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("ip.fmod");
        let dest = tmp.path().join("link.fmod");
        fs::write(&src, b"real module bytes").unwrap();
        std::os::unix::fs::symlink(&src, &dest).unwrap();

        let _ = fs::copy(&src, &dest);
        assert!(
            fs::read(&src).unwrap().is_empty(),
            "if this ever stops truncating, std::fs::copy grew a same-file \
             guard and copy_replacing's removal could be revisited"
        );
    }
}
