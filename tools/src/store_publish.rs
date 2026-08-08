//! Store publish — the single store-write path behind `fluxor
//! publish`: every artifact kind (source trees, fmods, runtimes, the
//! CLI) staged under one publish transaction and committed in one
//! locked index swap, each annotated with the epoch, its
//! token-canonical input digest, provenance, source rev, and — when
//! the last green `fluxor ci` covered the same inputs — the ci
//! digest. Lib-only (the store engine layering): the bin reaches it
//! via `fluxor_tools::store_publish`, mirroring `store_cli`.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::publish::{detect_host_target, require_project_identity};

use crate::oci_store::{ArtifactMeta, OciStore, Prepared};
use std::collections::BTreeMap;

/// Walk a directory into sorted `(rel_path, bytes)` pairs, skipping
/// VCS/build residue. The optional `prefix` maps the tree under a path
/// prefix in the artifact (e.g. `modules/sdk/**` shipped as `sdk/**`,
/// preserving the extraction contract
/// `target/fluxor/fluxor-abi/sdk/abi.rs`). The walked trees are real
/// directories — no symlink dereference is needed. The result
/// satisfies `canonical_tar`'s ordering contract and reproduces the
/// shape `fluxor sync` extracts.
fn collect_tree(root: &Path, prefix: Option<&str>) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).map_err(Error::Io)? {
            let entry = entry.map_err(Error::Io)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == ".git" || name == "target" || name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            let md = std::fs::metadata(&path).map_err(Error::Io)?;
            if md.is_dir() {
                stack.push(path);
            } else if md.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .map_err(|_| Error::Config(format!("walk escaped root: {}", path.display())))?
                    .to_string_lossy()
                    .replace('\\', "/");
                let rel = match prefix {
                    Some(p) => format!("{p}/{rel}"),
                    None => rel,
                };
                out.push((rel, std::fs::read(&path).map_err(Error::Io)?));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Token-canonical input digest over a file set: `.rs` files hash by
/// their canonicalized token stream (comment/format churn is
/// digest-neutral, same property as the srcpin), everything else by
/// raw bytes; each entry folds its path so renames move the digest.
fn input_digest_hex(files: &[(String, Vec<u8>)]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for (path, bytes) in files {
        h.update(path.as_bytes());
        h.update([0u8]);
        if path.ends_with(".rs") {
            if let Ok(text) = std::str::from_utf8(bytes) {
                h.update(crate::hash::canonicalize_source(text).as_bytes());
            } else {
                h.update(bytes);
            }
        } else {
            h.update(bytes);
        }
        h.update([0xFFu8]);
    }
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Where `fluxor ci` records the input digests it went green on:
/// `target/fluxor/.ci-green.toml` (`name = "hex"` lines). Publish
/// annotates `ci-digest` only for artifacts whose current input digest
/// appears here — information, never a gate.
pub fn ci_green_stamp_path(project_root: &Path) -> PathBuf {
    project_root.join("target/fluxor/.ci-green.toml")
}

fn read_ci_stamp(project_root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Ok(text) = std::fs::read_to_string(ci_green_stamp_path(project_root)) {
        for line in text.lines() {
            if let Some((k, v)) = line.split_once('=') {
                out.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
            }
        }
    }
    out
}

/// Source-artifact candidates for a project, as
/// `(name, dir, tar prefix)`. Fluxor publishes `fluxor-abi` =
/// `modules/sdk/**` under a `sdk/` prefix (extraction to
/// `target/fluxor/fluxor-abi/` preserves the `#[path]` mount contract
/// `target/fluxor/fluxor-abi/sdk/abi.rs`) and `fluxor-contracts` =
/// `contracts/src/**` under `src/`. A sibling publishes
/// `modules/common/**` as `<project>-common`, unprefixed. No crate
/// facades ship — consumers mount staged source, never cargo-link.
fn source_candidates(
    pr: &Path,
    project_name: &str,
) -> Vec<(String, PathBuf, Option<&'static str>)> {
    if project_name == "fluxor" {
        [
            ("fluxor-abi", pr.join("modules/sdk"), Some("sdk")),
            ("fluxor-contracts", pr.join("contracts/src"), Some("src")),
        ]
        .into_iter()
        .filter(|(_, d, _)| d.is_dir())
        .map(|(n, d, p)| (n.to_string(), d, p))
        .collect()
    } else {
        let common = pr.join("modules/common");
        if common.is_dir() {
            vec![(format!("{project_name}-common"), common, None)]
        } else {
            Vec::new()
        }
    }
}

/// Per-artifact input digests for everything the project publishes —
/// the shared walk behind publish annotation and the ci green stamp
/// (`fluxor ci` writes exactly this map on a green run; publish
/// annotates `ci-digest` where current digests match it).
pub fn project_input_digests(pr: &Path) -> Result<BTreeMap<String, String>> {
    let identity = require_project_identity(pr)?;
    let epoch_hex: String = crate::hash::abi_surface_digest()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut out = BTreeMap::new();
    for (name, dir, prefix) in source_candidates(pr, &identity.name) {
        out.insert(name, input_digest_hex(&collect_tree(&dir, prefix)?));
    }
    // Roots a module's out-of-dir source references may resolve
    // within: this project plus every workspace-member checkout.
    let mut ref_roots: Vec<PathBuf> = vec![pr.to_path_buf()];
    if let Ok(Some(ws)) = crate::workspace::load_workspace() {
        ref_roots.extend(ws.workspace.members.iter().cloned());
    }
    for m in crate::modules_build::list(pr)? {
        let Some(dir) = m.manifest.parent() else {
            continue;
        };
        let mut files = collect_tree(dir, None)?;
        // Sources reached via `#[path]`/`include!` OUTSIDE the module
        // directory are build inputs too — without them an edit to a
        // shared `#[path]`-mounted file leaves the digest (and thus
        // publish/ci staleness) unmoved while the artifact changes.
        for extra in crate::modules_build::transitive_source_refs(dir, &ref_roots) {
            let label = ref_roots
                .iter()
                .filter_map(|r| {
                    let root = r.canonicalize().ok()?;
                    let rel = extra.strip_prefix(&root).ok()?;
                    Some((root.components().count(), root, rel.to_path_buf()))
                })
                .max_by_key(|(depth, _, _)| *depth)
                .map(|(_, root, rel)| {
                    let base = root
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    format!("extern:{base}/{}", rel.to_string_lossy().replace('\\', "/"))
                })
                .unwrap_or_else(|| format!("extern:{}", extra.to_string_lossy()));
            if let Ok(bytes) = std::fs::read(&extra) {
                files.push((label, bytes));
            }
        }
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let mut hex = input_digest_hex(&files);
        hex.push_str(&epoch_hex[..16]);
        out.insert(m.name, hex);
    }
    Ok(out)
}

/// The whole-project publish onto the store. Returns the committed tag
/// names. `only` filters kinds: empty = everything publishable.
pub fn publish_project_to_store(
    project_root: &Path,
    only: &[&str],
    verbose: bool,
) -> Result<Vec<String>> {
    let pr = project_root.to_path_buf();
    let identity = require_project_identity(&pr)?;
    let epoch_hex: String = crate::hash::abi_surface_digest()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let rev = crate::oci_store::git_source_rev(&pr);
    let ci_stamp = read_ci_stamp(&pr);
    let input_digests = project_input_digests(&pr)?;
    let want = |k: &str| only.is_empty() || only.contains(&k);

    let store = OciStore::open(crate::oci_store::store_root()?)?;
    let txn = store.begin_publish()?;
    let mut prepared: Vec<Prepared> = Vec::new();

    let meta_for = |name: &str, input_hex: Option<&str>, ci: &BTreeMap<String, String>| {
        let ci_hex = input_hex
            .and_then(|d| ci.get(name).filter(|s| s.as_str() == d))
            .cloned();
        (input_hex.map(str::to_string), ci_hex)
    };

    // Source trees: fluxor publishes `fluxor-abi` (modules/sdk/** under
    // `sdk/`) and `fluxor-contracts` (contracts/src/** under `src/`);
    // siblings publish modules/common/** as `<name>-common`.
    if want("source") {
        for (name, dir, prefix) in source_candidates(&pr, &identity.name) {
            let files = collect_tree(&dir, prefix)?;
            let input_hex = input_digests
                .get(&name)
                .cloned()
                .unwrap_or_else(|| input_digest_hex(&files));
            let (input, ci) = meta_for(&name, Some(&input_hex), &ci_stamp);
            let meta = ArtifactMeta {
                project: &identity.name,
                provenance: "local-build",
                source_rev: rev.as_deref(),
                abi_surface_hex: &epoch_hex,
                input_digest_hex: input.as_deref(),
                ci_digest_hex: ci.as_deref(),
            };
            prepared.push(store.prepare_source(&name, &identity.version, &files, &meta)?);
            if verbose {
                println!("prepared source {name} ({} files)", files.len());
            }
        }
    }

    // fmods: every built artifact across every configured target shelf.
    if want("fmod") {
        // Ownership map: only fmods whose module directory lives in
        // this project's own tree are published; synced upstream
        // copies in the same shelf are not ours.
        let owned: BTreeMap<String, PathBuf> = crate::modules_build::list(&pr)?
            .into_iter()
            .filter_map(|m| m.manifest.parent().map(|d| (m.name, d.to_path_buf())))
            .collect();
        let shelf_root = pr.join("target/fluxor");
        if shelf_root.is_dir() {
            for target_dir in std::fs::read_dir(&shelf_root).map_err(Error::Io)? {
                let target_dir = target_dir.map_err(Error::Io)?.path();
                let target = target_dir
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                let modules_dir = target_dir.join("modules");
                if !modules_dir.is_dir() {
                    continue;
                }
                let mut fmods: Vec<PathBuf> = std::fs::read_dir(&modules_dir)
                    .map_err(Error::Io)?
                    .filter_map(std::result::Result::ok)
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|e| e == "fmod"))
                    .collect();
                fmods.sort();
                for fmod in fmods {
                    let name = fmod
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let Some(src_dir) = owned.get(&name) else {
                        continue;
                    };
                    let bytes = std::fs::read(&fmod).map_err(Error::Io)?;
                    let Some(input_hex) = input_digests.get(&name).cloned() else {
                        continue;
                    };
                    let (input, ci) = meta_for(&name, Some(&input_hex), &ci_stamp);
                    let manifest_toml = std::fs::read_to_string(src_dir.join("manifest.toml")).ok();
                    let meta = ArtifactMeta {
                        project: &identity.name,
                        provenance: "local-build",
                        source_rev: rev.as_deref(),
                        abi_surface_hex: &epoch_hex,
                        input_digest_hex: input.as_deref(),
                        ci_digest_hex: ci.as_deref(),
                    };
                    prepared.push(store.prepare_module(
                        &name,
                        &target,
                        &identity.version,
                        &bytes,
                        manifest_toml.as_deref(),
                        &meta,
                    )?);
                }
            }
        }
    }

    // Runtimes: `[project].runtimes` binaries, plus — for fluxor — the
    // CLI itself (Decision 8: the CLI is a runtime artifact).
    if want("runtime") {
        let mut names = identity.runtimes.clone();
        if identity.name == "fluxor" && !names.iter().any(|n| n == "fluxor") {
            names.push("fluxor".to_string());
        }
        let triple = detect_host_target()?;
        for name in names {
            let bin = pr.join("target").join(&triple).join("release").join(&name);
            if !bin.is_file() {
                if verbose {
                    println!("runtime {name}: not built at {} — skipped", bin.display());
                }
                continue;
            }
            let bytes = std::fs::read(&bin).map_err(Error::Io)?;
            let meta = ArtifactMeta {
                project: &identity.name,
                provenance: "local-build",
                source_rev: rev.as_deref(),
                abi_surface_hex: &epoch_hex,
                // The binary layer digest is the input digest for a
                // runtime — a separate tree hash would say less.
                input_digest_hex: None,
                ci_digest_hex: None,
            };
            prepared.push(store.prepare_runtime(
                &name,
                &identity.version,
                &triple,
                &bytes,
                &meta,
            )?);
        }
    }

    // A project with no publishable artifacts still gets its project
    // index: `<name>/meta:latest` over an empty child set. Vacuous
    // truth — downstream consumers (the ci live-staleness gate, sync)
    // read the index to answer "is anything stale?", and for a
    // zero-artifact project the honest answer is "no", not "unknown".
    if prepared.is_empty() {
        println!("published empty project index (no artifacts)");
    }

    let deps = crate::project::dependencies(&pr)
        .unwrap_or_default()
        .iter()
        .map(|d| d.name.clone())
        .collect::<Vec<_>>()
        .join(",");
    let committed = store.commit_publish(
        &txn,
        &identity.name,
        &identity.version,
        prepared,
        if deps.is_empty() { None } else { Some(&deps) },
    )?;
    Ok(committed
        .iter()
        .filter_map(|d| d.annotations.get(crate::oci_store::ANN_REF_NAME).cloned())
        .collect())
}

/// Record a green `fluxor ci` run: the per-artifact input digests the
/// gate just covered, written to `target/fluxor/.ci-green.toml`.
pub fn write_ci_green_stamp(project_root: &Path) -> Result<PathBuf> {
    let digests = project_input_digests(project_root)?;
    let path = ci_green_stamp_path(project_root);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(Error::Io)?;
    }
    let mut text = String::from(
        "# Written by `fluxor ci` on a green run: artifact name -> input digest.\n\
         # `fluxor publish` annotates io.fluxor.ci-digest where these match.\n",
    );
    for (name, hex) in &digests {
        text.push_str(&format!("{name} = \"{hex}\"\n"));
    }
    std::fs::write(&path, text).map_err(Error::Io)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::publish_project_to_store;

    /// GAP: transitive `#[path]`/`include!` staleness. A module whose
    /// sources reach a file OUTSIDE the module directory must fold
    /// that file into its input digest — an edit there is a real input
    /// change, and the publish/ci staleness machinery keys on this
    /// digest.
    #[test]
    fn transitively_included_file_outside_module_dir_moves_the_digest() {
        let scratch = tempfile::tempdir().unwrap();
        let pr = scratch.path().join("proj");
        let mod_dir = pr.join("modules/app/demo");
        std::fs::create_dir_all(&mod_dir).unwrap();
        std::fs::create_dir_all(pr.join("shared")).unwrap();
        std::fs::write(
            pr.join("fluxor.toml"),
            "[project]\nname = \"testproj\"\nversion = \"0.0.1\"\n",
        )
        .unwrap();
        std::fs::write(mod_dir.join("manifest.toml"), "version = \"0.1.0\"\n").unwrap();
        std::fs::write(
            mod_dir.join("mod.rs"),
            "#[path = \"../../../shared/core.rs\"]\nmod core;\n",
        )
        .unwrap();
        std::fs::write(pr.join("shared/core.rs"), "pub fn v() -> u32 { 1 }\n").unwrap();

        // No workspace file: roots = the project only.
        let _env = crate::oci_store::test_env_lock();
        std::env::set_var("FLUXOR_WORKSPACE", scratch.path().join("no-workspace.toml"));
        let before = super::project_input_digests(&pr).unwrap();
        std::fs::write(pr.join("shared/core.rs"), "pub fn v() -> u32 { 2 }\n").unwrap();
        let after = super::project_input_digests(&pr).unwrap();
        std::env::remove_var("FLUXOR_WORKSPACE");

        let d0 = before.get("demo").expect("module digest present");
        let d1 = after.get("demo").expect("module digest present");
        assert_ne!(
            d0, d1,
            "an edit to a #[path]-mounted file outside the module dir must move the digest"
        );
    }

    /// GAP: a zero-artifact project still publishes its (empty)
    /// project index, so `<name>/meta:latest` resolves and the ci
    /// live-staleness phase can answer "vacuously fresh" instead of
    /// hard-failing on a missing index.
    #[test]
    fn zero_artifact_project_publishes_empty_index() {
        let scratch = tempfile::tempdir().unwrap();
        let pr = scratch.path().join("proj");
        std::fs::create_dir_all(&pr).unwrap();
        std::fs::write(
            pr.join("fluxor.toml"),
            "[project]\nname = \"emptyproj\"\nversion = \"0.0.1\"\n",
        )
        .unwrap();

        let store_dir = scratch.path().join("store");
        let _env = crate::oci_store::test_env_lock();
        std::env::set_var("FLUXOR_STORE", &store_dir);
        let tags = publish_project_to_store(&pr, &[], false).unwrap();
        let store = crate::oci_store::OciStore::open(&store_dir).unwrap();
        let desc = store.resolve("emptyproj/meta:latest").unwrap();
        let bytes = store.read_blob(&desc.digest).unwrap();
        std::env::remove_var("FLUXOR_STORE");

        assert!(
            tags.iter().any(|t| t == "emptyproj/meta:latest"),
            "project index missing: {tags:?}"
        );
        let idx: crate::oci_store::ImageIndex = serde_json::from_slice(&bytes).unwrap();
        assert!(idx.manifests.is_empty(), "index children should be empty");
    }

    /// End-to-end over a scratch project + scratch store: a sibling
    /// with a `modules/common` tree publishes one source artifact,
    /// tagged `:ver` + `:latest`, plus its project index — all in one
    /// commit. Exercises canonical_tar → prepare_source →
    /// commit_publish → sweep wiring hermetically.
    #[test]
    fn sibling_common_tree_publishes_source_and_index() {
        let scratch = tempfile::tempdir().unwrap();
        let pr = scratch.path().join("proj");
        std::fs::create_dir_all(pr.join("modules/common")).unwrap();
        std::fs::write(
            pr.join("fluxor.toml"),
            "[project]\nname = \"testproj\"\nversion = \"0.0.1\"\n",
        )
        .unwrap();
        std::fs::write(
            pr.join("modules/common/core.rs"),
            "pub fn forty_two() -> u32 { 42 }\n",
        )
        .unwrap();

        let store_dir = scratch.path().join("store");
        // Env var routes store_root(); env is process-global, so hold
        // the shared env lock while it is set.
        let _env = crate::oci_store::test_env_lock();
        std::env::set_var("FLUXOR_STORE", &store_dir);
        let tags = publish_project_to_store(&pr, &["source"], false).unwrap();
        std::env::remove_var("FLUXOR_STORE");

        assert!(
            tags.iter()
                .any(|t| t == "testproj/src/testproj-common:0.0.1"),
            "canonical tag missing: {tags:?}"
        );
        assert!(
            tags.iter()
                .any(|t| t == "testproj/src/testproj-common:latest"),
            ":latest tag missing: {tags:?}"
        );
        assert!(
            tags.iter().any(|t| t == "testproj/meta:latest"),
            "project index missing: {tags:?}"
        );

        // The store on disk is a valid OCI layout with the tar blob.
        let store = crate::oci_store::OciStore::open(&store_dir).unwrap();
        let desc = store
            .resolve("testproj/src/testproj-common:latest")
            .unwrap();
        let manifest = store.read_manifest(&desc).unwrap();
        assert_eq!(
            manifest
                .annotations
                .get(crate::oci_store::ANN_KIND)
                .map(String::as_str),
            Some("source")
        );
        assert!(manifest
            .annotations
            .contains_key(crate::oci_store::ANN_ABI_SURFACE));
        assert!(manifest
            .annotations
            .contains_key(crate::oci_store::ANN_INPUT_DIGEST));
        let tar = store.read_blob(&manifest.layers[0].digest).unwrap();
        assert_eq!(&tar[257..262], b"ustar");
    }

    /// Fluxor's source artifacts follow the decided convention:
    /// `fluxor-abi` = modules/sdk/** under a `sdk/` tar prefix (so
    /// extraction to `target/fluxor/fluxor-abi/` preserves the mount
    /// contract `…/fluxor-abi/sdk/abi.rs`), `fluxor-contracts` =
    /// contracts/src/** under `src/`, and no `fluxor-sdk` crate-facade
    /// artifact ships.
    #[test]
    fn fluxor_publishes_abi_and_contracts_with_path_prefixes() {
        let scratch = tempfile::tempdir().unwrap();
        let pr = scratch.path().join("fluxor");
        std::fs::create_dir_all(pr.join("modules/sdk")).unwrap();
        std::fs::create_dir_all(pr.join("contracts/src")).unwrap();
        std::fs::write(
            pr.join("fluxor.toml"),
            "[project]\nname = \"fluxor\"\nversion = \"0.0.1\"\n",
        )
        .unwrap();
        std::fs::write(pr.join("modules/sdk/abi.rs"), "pub struct SyscallTable;\n").unwrap();
        std::fs::write(pr.join("contracts/src/lib.rs"), "pub mod contracts {}\n").unwrap();

        let store_dir = scratch.path().join("store");
        let _env = crate::oci_store::test_env_lock();
        std::env::set_var("FLUXOR_STORE", &store_dir);
        let tags = publish_project_to_store(&pr, &["source"], false).unwrap();
        std::env::remove_var("FLUXOR_STORE");

        assert!(
            tags.iter().any(|t| t == "fluxor/src/fluxor-abi:latest"),
            "{tags:?}"
        );
        assert!(
            tags.iter()
                .any(|t| t == "fluxor/src/fluxor-contracts:latest"),
            "{tags:?}"
        );
        assert!(
            !tags.iter().any(|t| t.contains("fluxor-sdk")),
            "the fluxor-sdk artifact was dropped: {tags:?}"
        );

        let store = crate::oci_store::OciStore::open(&store_dir).unwrap();
        let first_entry_name = |reference: &str| {
            let desc = store.resolve(reference).unwrap();
            let manifest = store.read_manifest(&desc).unwrap();
            let tar = store.read_blob(&manifest.layers[0].digest).unwrap();
            std::str::from_utf8(&tar[0..100])
                .unwrap()
                .trim_end_matches('\0')
                .to_string()
        };
        assert_eq!(
            first_entry_name("fluxor/src/fluxor-abi:latest"),
            "sdk/abi.rs"
        );
        assert_eq!(
            first_entry_name("fluxor/src/fluxor-contracts:latest"),
            "src/lib.rs"
        );
    }
}
