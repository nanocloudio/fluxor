//! `fluxor publish` — registry-publication CLI.
//!
//! Each verb packages a project artefact and writes it into the local
//! registry at `~/.fluxor/registry/`.
//!
//! Versioning rules:
//! - **Canonical publish** (no `--local`): refuses to overwrite an
//!   existing `(name, version)` and refuses to publish if the
//!   resolved version is the dev default (`0.0.0-dev`).
//! - **Local publish** (`--local`): appends `-local.<content-hash>`
//!   to every artefact name so re-publishing after edits produces a
//!   new file rather than overwriting. Consumers pick the newest
//!   hash automatically.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cargo_index;
use crate::error::{Error, Result};
use crate::hash::file_sha256_short;
use crate::project::{self, ProjectIdentity, DEV_VERSION};
use crate::project_meta;
use crate::registry;
use crate::workspace;

// ── Common helpers ────────────────────────────────────────────────────

fn resolve_project_root(opt: Option<&Path>) -> PathBuf {
    opt.map(PathBuf::from).unwrap_or_else(project::root)
}

/// Refresh the project-meta file at the registry. Called from every
/// canonical-publish path so the meta tracks the latest published
/// state of the project's `[project]` + `[dependencies]` tables.
fn refresh_project_meta(project_root: &Path) -> Result<()> {
    let registry_root = registry::registry_root()?;
    let meta = project_meta::from_project_root(project_root)?;
    let _ = project_meta::write_meta(&registry_root, &meta)?;
    Ok(())
}

/// One-line stderr advisory when publish runs from inside a live
/// workspace member. The artifact still publishes normally — the
/// advisory just informs the developer that workspace-aware
/// consumers will continue using the live source path until they
/// leave the workspace.
fn announce_workspace_mode_if_active(project_root: &Path) {
    let Ok(Some(ws)) = workspace::load_workspace() else {
        return;
    };
    let Some(msg) = workspace::advisory(&ws, project_root) else {
        return;
    };
    eprintln!("note: {msg}");
    eprintln!(
        "      published artefact still lands in the registry, but workspace-aware consumers"
    );
    eprintln!("      will resolve to the live source path until they leave the workspace.");
}

fn require_project_identity(project_root: &Path) -> Result<ProjectIdentity> {
    let identity = project::project_identity(project_root)
        .map_err(Error::Config)?
        .ok_or_else(|| {
            Error::Config(format!(
                "no [project] table in {}/fluxor.toml — publish requires `[project].name`",
                project_root.display()
            ))
        })?;
    Ok(identity)
}

fn reject_dev_version_for_canonical(identity: &ProjectIdentity, local: bool) -> Result<()> {
    if !local && identity.version == DEV_VERSION {
        return Err(Error::Config(format!(
            "canonical publish refuses `[project].version = \"{DEV_VERSION}\"` — \
             set a real version in fluxor.toml, or pass --local."
        )));
    }
    Ok(())
}

fn content_hash(path: &Path) -> Result<String> {
    file_sha256_short(path)
}

/// Build the destination filename: `<stem>.<ext>` or
/// `<stem>-local.<hash>.<ext>`.
fn target_filename(stem: &str, ext: &str, hash: Option<&str>) -> String {
    match hash {
        Some(h) => format!("{stem}-local.{h}.{ext}"),
        None => format!("{stem}.{ext}"),
    }
}

/// What `install_crate_artefact` (and the analogous runtime install)
/// did. Callers branch on this so a byte-identical re-publish stays
/// idempotent — the cargo-index `append_entry` step refuses to add a
/// duplicate `(name, version)`, so on `SkippedIdempotent` we have to
/// skip the index step too.
enum InstallOutcome {
    /// The destination didn't exist and we wrote it.
    Written(PathBuf),
    /// The destination existed with byte-identical content; no-op.
    SkippedIdempotent(PathBuf),
}

impl InstallOutcome {
    fn path(&self) -> &Path {
        match self {
            InstallOutcome::Written(p) | InstallOutcome::SkippedIdempotent(p) => p,
        }
    }
}

/// Copy `src` into the registry's `cargo/` shelf. Byte-identical
/// re-publishes are an idempotent no-op (matches the per-fmod
/// behaviour of `cmd_publish_fmod`). A canonical re-publish with
/// different bytes at the same version is still a hard error —
/// `(name, version)` identifies one immutable artefact in the
/// registry, and the operator needs to know they should bump the
/// version.
fn install_crate_artefact(
    src: &Path,
    crate_name: &str,
    version: &str,
    local: bool,
) -> Result<InstallOutcome> {
    let root = registry::registry_root()?;
    registry::ensure_layout(&root)?;
    let cargo_dir = root.join("cargo");

    let stem = format!("{crate_name}-{version}");
    let hash = if local {
        Some(content_hash(src)?)
    } else {
        None
    };
    let filename = target_filename(&stem, "crate", hash.as_deref());
    let dest = cargo_dir.join(&filename);

    if !local && dest.exists() {
        let existing_hash = content_hash(&dest)?;
        let new_hash = content_hash(src)?;
        if existing_hash == new_hash {
            return Ok(InstallOutcome::SkippedIdempotent(dest));
        }
        return Err(Error::Config(format!(
            "canonical {} already exists with different content; \
             bump [package].version or pass --local",
            dest.display()
        )));
    }

    fs::copy(src, &dest)?;
    Ok(InstallOutcome::Written(dest))
}

fn run_cargo_package(project_root: &Path, package: &str) -> Result<PathBuf> {
    let status = Command::new("cargo")
        .arg("package")
        .arg("--no-verify")
        .arg("--allow-dirty")
        .arg("--package")
        .arg(package)
        .arg("--target-dir")
        .arg(project_root.join("target"))
        .current_dir(project_root)
        .status()
        .map_err(|e| Error::Config(format!("failed to spawn cargo package: {e}")))?;
    if !status.success() {
        return Err(Error::Config(format!(
            "cargo package -p {package} exited with status {status}"
        )));
    }

    // Read the package's actual version from its Cargo.toml — the
    // emitted artefact is `<name>-<version>.crate` and that's what we
    // copy into the registry.
    let manifest = read_crate_manifest(project_root, package)?;
    let crate_path = project_root
        .join("target")
        .join("package")
        .join(format!("{}-{}.crate", package, manifest.version));
    if !crate_path.exists() {
        return Err(Error::Config(format!(
            "expected packaged artefact at {} but it is missing",
            crate_path.display()
        )));
    }
    Ok(crate_path)
}

struct CrateManifest {
    version: String,
}

/// Resolution-ready view of one workspace member's `Cargo.toml`.
struct MemberManifest {
    path: PathBuf,
    name: String,
    version: String,
}

/// Walk the workspace root's `Cargo.toml` and return every member's
/// resolved `(path, name, version)`. Members declaring
/// `version.workspace = true` (the standard cargo workspace-
/// inheritance form) get the root's `[workspace.package].version`
/// substituted. Members whose Cargo.toml is missing the
/// `[package]` table — e.g. virtual sub-workspaces — are skipped
/// silently; the publisher only cares about publishable members.
fn enumerate_workspace_members(project_root: &Path) -> Result<Vec<MemberManifest>> {
    #[derive(serde::Deserialize)]
    struct RootManifest {
        workspace: Option<WorkspaceSection>,
    }
    #[derive(serde::Deserialize)]
    struct WorkspaceSection {
        #[serde(default)]
        members: Vec<String>,
        #[serde(default)]
        package: Option<WorkspacePackage>,
    }
    #[derive(serde::Deserialize)]
    struct WorkspacePackage {
        #[serde(default)]
        version: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct MemberRoot {
        package: Option<MemberPackage>,
    }
    #[derive(serde::Deserialize)]
    struct MemberPackage {
        name: String,
        #[serde(default)]
        version: Option<VersionField>,
    }
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum VersionField {
        Literal(String),
        Inherited(WorkspaceInherit),
    }
    #[derive(serde::Deserialize)]
    struct WorkspaceInherit {
        #[serde(default)]
        workspace: bool,
    }

    let root_path = project_root.join("Cargo.toml");
    let root_text = fs::read_to_string(&root_path)
        .map_err(|e| Error::Config(format!("read {}: {e}", root_path.display())))?;
    let root_parsed: RootManifest = toml::from_str(&root_text)
        .map_err(|e| Error::Config(format!("parse {}: {e}", root_path.display())))?;
    let workspace_version = root_parsed
        .workspace
        .as_ref()
        .and_then(|w| w.package.as_ref())
        .and_then(|p| p.version.clone());
    let members = root_parsed.workspace.map(|w| w.members).unwrap_or_default();

    let mut out = Vec::new();
    for member in &members {
        let manifest_path = project_root.join(member).join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }
        let text = fs::read_to_string(&manifest_path)
            .map_err(|e| Error::Config(format!("read {}: {e}", manifest_path.display())))?;
        let parsed: MemberRoot = match toml::from_str(&text) {
            Ok(p) => p,
            Err(_) => continue, // virtual workspace or other non-publishable layout
        };
        let Some(pkg) = parsed.package else {
            continue;
        };
        let resolved_version = match pkg.version {
            Some(VersionField::Literal(v)) => v,
            Some(VersionField::Inherited(WorkspaceInherit { workspace: true })) => {
                let Some(ref ws_version) = workspace_version else {
                    return Err(Error::Config(format!(
                        "{} declares `version.workspace = true` but the workspace root \
                         has no `[workspace.package].version` to inherit from",
                        manifest_path.display()
                    )));
                };
                ws_version.clone()
            }
            Some(VersionField::Inherited(WorkspaceInherit { workspace: false })) | None => {
                // `version` omitted entirely is unusual but not our problem to
                // diagnose — this enumerator just skips such members.
                continue;
            }
        };
        out.push(MemberManifest {
            path: manifest_path,
            name: pkg.name,
            version: resolved_version,
        });
    }
    Ok(out)
}

fn read_crate_manifest(project_root: &Path, package: &str) -> Result<CrateManifest> {
    for member in enumerate_workspace_members(project_root)? {
        if member.name == package {
            return Ok(CrateManifest {
                version: member.version,
            });
        }
    }
    Err(Error::Config(format!(
        "could not locate Cargo.toml for package {package} \
         (searched workspace members from {})",
        project_root.join("Cargo.toml").display()
    )))
}

// ── Verb implementations ──────────────────────────────────────────────

pub fn cmd_publish_abi(local: bool, project_root: Option<&Path>) -> Result<()> {
    publish_workspace_crate("fluxor-abi", local, project_root)
}

pub fn cmd_publish_sdk(local: bool, project_root: Option<&Path>) -> Result<()> {
    publish_workspace_crate("fluxor-sdk", local, project_root)
}

pub fn cmd_publish_common(local: bool, project_root: Option<&Path>) -> Result<()> {
    let pr = resolve_project_root(project_root);
    let identity = require_project_identity(&pr)?;
    publish_workspace_crate(&format!("{}-common", identity.name), local, project_root)
}

fn publish_workspace_crate(package: &str, local: bool, project_root: Option<&Path>) -> Result<()> {
    let pr = resolve_project_root(project_root);
    let identity = require_project_identity(&pr)?;
    reject_dev_version_for_canonical(&identity, local)?;
    announce_workspace_mode_if_active(&pr);

    let manifest = read_crate_manifest(&pr, package)?;

    // Single source of truth: `[package].version` in every workspace
    // member crate must match `[project].version` in fluxor.toml.
    // The transitive resolver looks up project-meta at
    // `projects/<dep>/<resolved-crate-version>.toml` (lockfile.rs);
    // project-meta is written at `<dep>/<[project].version>.toml`
    // (project_meta.rs). Keeping the two numbers identical is what
    // makes transitive resolution find the meta file. Canonical
    // publish refuses to publish a mismatched crate; `--local`
    // accepts (locals are content-hashed and aren't indexed).
    if !local && manifest.version != identity.version {
        return Err(Error::Config(format!(
            "version mismatch: crate `{}` is at {} but [project].version is {} — \
             keep [package].version aligned with [project].version (single source of truth) \
             or pass --local for a content-hashed snapshot",
            package, manifest.version, identity.version,
        )));
    }

    println!(
        "packaging {} v{} from {}",
        package,
        manifest.version,
        pr.display()
    );
    let crate_path = run_cargo_package(&pr, package)?;

    let outcome = install_crate_artefact(&crate_path, package, &manifest.version, local)?;
    let dest = outcome.path().to_path_buf();
    match &outcome {
        InstallOutcome::Written(_) => {
            println!("published {} → {}", package, dest.display());
        }
        InstallOutcome::SkippedIdempotent(_) => {
            println!(
                "skipped {} → {} (already published, byte-identical)",
                package,
                dest.display()
            );
        }
    }

    // Canonical publish updates the cargo git-index so downstream
    // projects can resolve the crate by name. Local publishes are
    // throwaway content-hashed artefacts and never enter the index.
    // Idempotent skips don't re-index either — the index already
    // records this `(name, version)` from the prior write.
    if !local && matches!(outcome, InstallOutcome::Written(_)) {
        let manifest_path = locate_member_manifest(&pr, package)?;
        let deps = cargo_index::extract_deps(&manifest_path)?;
        let cksum = cargo_index::sha256_hex(&dest)?;
        let entry = cargo_index::IndexEntry {
            name: package,
            vers: &manifest.version,
            deps,
            cksum,
            features: serde_json::Map::new(),
            yanked: false,
        };
        let registry_root = registry::registry_root()?;
        let idx_path = cargo_index::append_entry(&registry_root, &entry)?;
        println!(
            "indexed {} {} → {}",
            package,
            manifest.version,
            idx_path.display()
        );
        refresh_project_meta(&pr)?;
    }

    Ok(())
}

/// Locate the workspace member's source Cargo.toml for the given
/// package. Reused by `publish_workspace_crate` to feed dep
/// extraction into the cargo-index writer.
fn locate_member_manifest(project_root: &Path, package: &str) -> Result<PathBuf> {
    for member in enumerate_workspace_members(project_root)? {
        if member.name == package {
            return Ok(member.path);
        }
    }
    Err(Error::Config(format!(
        "could not locate workspace-member manifest for {package}"
    )))
}

/// One module owned by this project: tier-relative module name and
/// the version declared in its `manifest.toml`.
struct OwnedModule {
    name: String,
    version: String,
}

/// Enumerate every module this project owns by walking the local
/// `modules/{foundation,app,drivers}/*/manifest.toml` tree. The
/// returned list is what the publisher considers republishable —
/// fmods present in `target/` whose name doesn't appear here belong
/// to some other project (synced upstream artefacts) and must not
/// be re-published under this project's namespace. Modules without
/// a `version` field in their manifest are reported as errors so
/// the operator notices the manifest is incomplete.
fn list_owned_modules(project_root: &Path) -> Result<Vec<OwnedModule>> {
    #[derive(serde::Deserialize)]
    struct ModuleManifest {
        version: Option<String>,
    }
    let tiers = ["foundation", "app", "drivers"];
    let mut out = Vec::new();
    for tier in tiers {
        let tier_dir = project_root.join("modules").join(tier);
        if !tier_dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&tier_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let manifest_path = entry.path().join("manifest.toml");
            if !manifest_path.exists() {
                continue;
            }
            let text = fs::read_to_string(&manifest_path)
                .map_err(|e| Error::Config(format!("read {}: {e}", manifest_path.display())))?;
            let parsed: ModuleManifest = toml::from_str(&text)
                .map_err(|e| Error::Config(format!("parse {}: {e}", manifest_path.display())))?;
            let Some(version) = parsed.version else {
                return Err(Error::Config(format!(
                    "{} has no `version` field — every publishable module \
                     manifest must declare one",
                    manifest_path.display()
                )));
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            out.push(OwnedModule { name, version });
        }
    }
    Ok(out)
}

pub fn cmd_publish_fmod(
    target: Option<&str>,
    module: Option<&str>,
    local: bool,
    project_root: Option<&Path>,
) -> Result<()> {
    let pr = resolve_project_root(project_root);
    let identity = require_project_identity(&pr)?;
    // identity.version is *not* what gates canonical fmod publish —
    // each fmod uses its own manifest version. The project-version
    // guard here exists so a `publish --local` run catches a missing
    // `[project].name` early; per-fmod versions are re-evaluated below.
    reject_dev_version_for_canonical(&identity, true)?;
    announce_workspace_mode_if_active(&pr);

    let root = registry::registry_root()?;
    registry::ensure_layout(&root)?;

    // Drive from the project's own manifest tree, not the target/
    // shelf. The target tree contains every fmod that ever passed
    // through `make sync`, including synced upstream artefacts —
    // republishing those under this project's namespace would
    // misattribute them. The manifest tree is the canonical list of
    // what this project owns; only modules with a local manifest get
    // considered.
    let mut owned = list_owned_modules(&pr)?;
    if let Some(m) = module {
        owned.retain(|o| o.name == m);
        if owned.is_empty() {
            return Err(Error::Config(format!(
                "no module manifest at modules/{{foundation,app,drivers}}/{m}/manifest.toml"
            )));
        }
    }
    if owned.is_empty() {
        // No owned modules at all — fluxor publish (no subcommand)
        // routes here best-effort, so emit a soft message and exit
        // cleanly. A project with zero modules just has nothing to
        // publish at this tier.
        println!("no owned modules to publish (modules/{{foundation,app,drivers}}/*/manifest.toml is empty).");
        return Ok(());
    }

    let target_root_under_fluxor = pr.join("target").join("fluxor");
    let target_root_bare = pr.join("target");
    let candidate_roots = [&target_root_under_fluxor, &target_root_bare];

    let targets_to_walk: Vec<String> = match target {
        Some(t) => vec![t.to_string()],
        None => list_built_targets(&candidate_roots)?,
    };

    if targets_to_walk.is_empty() {
        return Err(Error::Config(
            "no built fmods under target/fluxor/* or target/* — run `make modules-all` first"
                .to_string(),
        ));
    }

    let mut published: Vec<PathBuf> = Vec::new();
    let mut skipped_idempotent = 0usize;
    let mut errors: Vec<String> = Vec::new();
    for target_name in &targets_to_walk {
        for owned_module in &owned {
            if !local && owned_module.version == project::DEV_VERSION {
                errors.push(format!(
                    "skip {}: canonical publish refuses module version `{}`",
                    owned_module.name,
                    project::DEV_VERSION
                ));
                continue;
            }
            // Find the built fmod for this (target, module). Either
            // layout is acceptable; the first one that exists wins.
            let src = candidate_roots
                .iter()
                .map(|r| {
                    r.join(target_name)
                        .join("modules")
                        .join(format!("{}.fmod", owned_module.name))
                })
                .find(|p| p.exists());
            let Some(src) = src else {
                // Module is owned but not built for this target.
                // Silent skip — not every owned module targets
                // every silicon (e.g. a host-only app module skipped
                // for rp2040), and the operator already controls the
                // build set via `make modules` / `make modules-all`.
                continue;
            };

            let dest_dir = root
                .join("fmod")
                .join(&identity.name)
                .join(target_name)
                .join(&owned_module.name);
            fs::create_dir_all(&dest_dir)?;
            let hash = if local {
                Some(content_hash(&src)?)
            } else {
                None
            };
            let dest_filename = target_filename(&owned_module.version, "fmod", hash.as_deref());
            let dest = dest_dir.join(&dest_filename);
            if !local && dest.exists() {
                // Idempotent skip on byte-identical re-publish; hard
                // error on diverging content at the same version.
                // The registry promise is that `(name, version)`
                // identifies one immutable artefact. Module
                // versions are independent of `[project].version`,
                // so any publish cycle commonly re-encounters every
                // already-published fmod unchanged.
                let existing_hash = content_hash(&dest)?;
                let new_hash = content_hash(&src)?;
                if existing_hash == new_hash {
                    skipped_idempotent += 1;
                    continue;
                }
                errors.push(format!(
                    "{} already exists with different content — bump module version in modules/<tier>/{}/manifest.toml",
                    dest.display(),
                    owned_module.name,
                ));
                continue;
            }
            fs::copy(&src, &dest)?;
            published.push(dest);
        }
    }

    let real_failure = !errors.is_empty();
    for line in &errors {
        eprintln!("warning: {line}");
    }
    if published.is_empty() && skipped_idempotent == 0 {
        // Truly nothing happened — neither published nor skipped.
        // Likely the operator hasn't built owned modules for any of
        // the discovered targets yet.
        return Err(Error::Config(
            "no fmods were published — run `make modules-all` first".into(),
        ));
    }
    if real_failure {
        return Err(Error::Config(format!(
            "{} fmod(s) failed to publish — see warnings above",
            errors.len()
        )));
    }
    if !published.is_empty() {
        println!("published {} fmod(s):", published.len());
        for p in &published {
            println!("  {}", p.display());
        }
    }
    if skipped_idempotent > 0 {
        println!("skipped {skipped_idempotent} fmod(s) already at the same content (idempotent).");
    }
    if !local {
        refresh_project_meta(&pr)?;
    }
    Ok(())
}

fn list_built_targets(roots: &[&PathBuf]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let modules = entry.path().join("modules");
            if !modules.exists() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    Ok(out)
}

/// Detect the host target triple — used by `publish runtime`'s
/// `--host-target` default. We read it from rustc's print output
/// since cargo doesn't surface it via env at runtime.
fn detect_host_target() -> Result<String> {
    let out = std::process::Command::new("rustc")
        .args(["-Vv"])
        .output()
        .map_err(|e| Error::Config(format!("spawn rustc -Vv: {e}")))?;
    if !out.status.success() {
        return Err(Error::Config(format!(
            "rustc -Vv failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("host: ") {
            return Ok(rest.trim().to_string());
        }
    }
    Err(Error::Config("rustc -Vv output had no `host:` line".into()))
}

pub fn cmd_publish_runtime(
    binary: &str,
    host_target: Option<&str>,
    local: bool,
    project_root: Option<&Path>,
) -> Result<()> {
    let pr = resolve_project_root(project_root);
    let identity = require_project_identity(&pr)?;
    reject_dev_version_for_canonical(&identity, local)?;
    announce_workspace_mode_if_active(&pr);

    let host_target = match host_target {
        Some(s) => s.to_string(),
        None => detect_host_target()?,
    };

    let src = pr
        .join("target")
        .join(&host_target)
        .join("release")
        .join(binary);
    if !src.exists() {
        return Err(Error::Config(format!(
            "runtime binary not found at {} — build it first \
             (e.g. `cargo build -p <pkg> --target {} --release --bin {}`)",
            src.display(),
            host_target,
            binary,
        )));
    }

    let root = registry::registry_root()?;
    registry::ensure_layout(&root)?;
    let bin_root = root.join("bin");
    fs::create_dir_all(&bin_root)?;
    let dest_dir = bin_root
        .join(&identity.name)
        .join(&host_target)
        .join(binary);
    fs::create_dir_all(&dest_dir)?;

    let hash = if local {
        Some(content_hash(&src)?)
    } else {
        None
    };
    let dest_filename = match &hash {
        Some(h) => format!("{}-local.{}", identity.version, h),
        None => identity.version.clone(),
    };
    let dest = dest_dir.join(&dest_filename);

    if !local && dest.exists() {
        // Byte-identical re-publish is an idempotent no-op (matches
        // the per-fmod and per-crate behaviour). Different content
        // at the same version stays a hard error so the operator
        // bumps the version.
        let existing_hash = content_hash(&dest)?;
        let new_hash = content_hash(&src)?;
        if existing_hash == new_hash {
            println!(
                "skipped runtime {} ({}/{}) → {} (already published, byte-identical)",
                binary,
                identity.name,
                host_target,
                dest.display(),
            );
            return Ok(());
        }
        return Err(Error::Config(format!(
            "canonical {} already exists with different content; \
             bump [project].version or pass --local",
            dest.display()
        )));
    }

    fs::copy(&src, &dest)?;
    // Preserve executable bit (cargo emits chmod 755 binaries; fs::copy
    // preserves mode on Linux, but be explicit for safety).
    let mut perms = fs::metadata(&dest)?.permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    fs::set_permissions(&dest, perms)?;

    println!(
        "published runtime {} ({}/{}) → {}",
        binary,
        identity.name,
        host_target,
        dest.display(),
    );
    if !local {
        refresh_project_meta(&pr)?;
    }
    Ok(())
}

/// Does the project at `project_root` own a workspace member with
/// the given package name? Used by `cmd_publish_all` to gate the
/// abi / sdk subcommands so a downstream consumer doesn't try to
/// republish fluxor-owned crates under its own namespace.
fn project_owns_workspace_crate(project_root: &Path, package: &str) -> bool {
    enumerate_workspace_members(project_root)
        .map(|members| members.iter().any(|m| m.name == package))
        .unwrap_or(false)
}

/// Publish every applicable tier in one sweep. `local=false`
/// performs canonical publishing (refuses dev versions, idempotent-
/// skips byte-identical re-publishes, writes cargo-index entries
/// and project-meta files); `local=true` writes content-hashed
/// `-local.<sha>` snapshots that never enter the cargo index. The
/// bare `fluxor publish` (no subcommand) routes here, honouring
/// the top-level `--local` flag.
///
/// Each tier is gated by what this project actually owns:
///
/// - `abi`/`sdk` run only when `fluxor-abi`/`fluxor-sdk` are
///   workspace members of THIS project (i.e. when running from
///   fluxor's own checkout). Downstream consumers skip silently
///   instead of trying to republish fluxor-owned crates under
///   their own name.
/// - `common` runs only when `<project>-common` is a workspace
///   member.
/// - `fmod` always runs — the publisher walks the project's local
///   manifest tree, so synced upstream fmods are correctly
///   ignored.
/// - `runtime` runs only for binaries explicitly listed in
///   `fluxor.toml::[project].runtimes`. The previous "publish
///   anything in target/<host>/release/" heuristic
///   misclassified synced upstream binaries as owned.
///
/// Failure of an applicable tier is non-fatal as long as some
/// other tier produced an artefact (or skipped idempotently); the
/// command only fails when nothing was published, skipped, or
/// silently bypassed.
pub fn cmd_publish_all(local: bool, project_root: Option<&Path>) -> Result<()> {
    let pr = resolve_project_root(project_root);
    let identity = require_project_identity(&pr)?;

    type PublishFn = fn(bool, Option<&Path>) -> Result<()>;
    let candidate_tiers: &[(&str, &str, PublishFn)] = &[
        ("abi", "fluxor-abi", cmd_publish_abi),
        ("sdk", "fluxor-sdk", cmd_publish_sdk),
    ];

    let mut any_succeeded = false;
    let mut soft_failures: Vec<String> = Vec::new();

    // abi / sdk only when this project owns the workspace member.
    for (label, package, f) in candidate_tiers {
        if !project_owns_workspace_crate(&pr, package) {
            continue;
        }
        match f(local, Some(&pr)) {
            Ok(()) => any_succeeded = true,
            Err(e) => soft_failures.push(format!("{label}: {e}")),
        }
    }

    // common only when `<project>-common` is a workspace member.
    let common_package = format!("{}-common", identity.name);
    if project_owns_workspace_crate(&pr, &common_package) {
        match cmd_publish_common(local, Some(&pr)) {
            Ok(()) => any_succeeded = true,
            Err(e) => soft_failures.push(format!("common: {e}")),
        }
    }

    // fmods — owned modules only (driven by local manifest tree).
    match cmd_publish_fmod(None, None, local, Some(&pr)) {
        Ok(()) => any_succeeded = true,
        Err(e) => soft_failures.push(format!("fmod: {e}")),
    }

    // Runtime binaries — explicit opt-in via `[project].runtimes`.
    // Without an entry there, the publish sweep doesn't go anywhere
    // near the target tree's `release/` directory; a binary synced
    // from upstream into the consumer's tree (e.g. fluxor-linux)
    // doesn't get republished under the consumer's namespace.
    if !identity.runtimes.is_empty() {
        let host_target = match detect_host_target() {
            Ok(t) => t,
            Err(e) => {
                soft_failures.push(format!("runtime host-target detect: {e}"));
                String::new()
            }
        };
        if !host_target.is_empty() {
            for binary in &identity.runtimes {
                let conventional = pr
                    .join("target")
                    .join(&host_target)
                    .join("release")
                    .join(binary);
                if !conventional.exists() {
                    soft_failures.push(format!(
                        "runtime {binary}: declared in [project].runtimes but \
                         {} doesn't exist — build it first",
                        conventional.display()
                    ));
                    continue;
                }
                match cmd_publish_runtime(binary, Some(&host_target), local, Some(&pr)) {
                    Ok(()) => any_succeeded = true,
                    Err(e) => soft_failures.push(format!("runtime {binary}: {e}")),
                }
            }
        }
    }

    for s in &soft_failures {
        eprintln!("note: {s}");
    }
    if !any_succeeded {
        let kind = if local { "publish --local" } else { "publish" };
        return Err(Error::Config(format!(
            "{kind}: nothing was published; see notes above"
        )));
    }
    Ok(())
}
