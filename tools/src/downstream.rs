//! The `downstream-conformance` CI phase: do this fluxor's consumers still
//! build against it?
//!
//! # The failure this exists to end
//!
//! Every other CI phase in this ecosystem is single-project, so a change to
//! a fluxor surface can leave a consumer unable to compile while fluxor's
//! own suite stays green — and the breakage waits until somebody happens to
//! build that consumer.
//!
//! The cost is not carelessness; it is the ordinary price of a correct
//! change. Reshaping an API for a good reason breaks its callers exactly as
//! thoroughly as deleting one by accident, and the person best placed to fix
//! either is whoever is already holding the change. That is why the gate
//! lives in the repo doing the changing rather than in the repos absorbing
//! it: a break is cheapest at the moment it is made and most expensive after
//! something has been built on it.
//!
//! # Why it checks the SYNCED surface first, and refuses rather than guessing
//!
//! A downstream cannot build against an UNPUBLISHED fluxor: it resolves the
//! SDK through the artefact store, so "against the working tree" and
//! "published, then synced" are the same state reached two ways. That is not
//! a limitation to work around — publishing IS how a change reaches a
//! consumer.
//!
//! So the phase compares each consumer's synced `ABI_SURFACE_DIGEST` with
//! this tree's, and when they differ it says so and stops instead of
//! building. Building anyway would compile the consumer against the PREVIOUS
//! fluxor and report green — the single most misleading thing this phase
//! could do, because it would answer the question it was asked while
//! measuring something else.
//!
//! # Why build-only
//!
//! This is `E1a`, the regression floor: every consumer builds against one
//! fluxor pin. Running each consumer's whole `fluxor ci` here would multiply
//! this suite's runtime by the number of consumers and duplicate what those
//! repos already run. What only fluxor can check is the compile edge, and
//! that is what this checks.

use std::path::{Path, PathBuf};
use std::process::Command;

/// One consumer to check, and where it lives.
pub struct Consumer {
    pub name: String,
    pub path: PathBuf,
}

/// Read `[ci.downstream]` — `projects` and an optional `root` (default `..`,
/// the sibling-checkout layout every repo here uses).
///
/// `None` when the table is absent: a project that declares no consumers has
/// none, and the phase is omitted rather than perpetually skipped.
pub fn configured(project_root: &Path) -> Option<Vec<Consumer>> {
    let raw = std::fs::read_to_string(project_root.join("fluxor.toml")).ok()?;
    let doc: toml::Value = toml::from_str(&raw).ok()?;
    let table = doc.get("ci")?.get("downstream")?;
    let projects = table.get("projects")?.as_array()?;
    let root = table
        .get("root")
        .and_then(|r| r.as_str())
        .unwrap_or("..")
        .to_string();
    let base = project_root.join(root);
    Some(
        projects
            .iter()
            .filter_map(|p| p.as_str())
            .map(|name| Consumer {
                name: name.to_string(),
                path: base.join(name),
            })
            .collect(),
    )
}

/// The `ABI_SURFACE_DIGEST` bytes a synced SDK carries, as they appear in
/// the generated source.
///
/// Parsed out of the file rather than compiled in, because the whole point
/// is to read what ANOTHER checkout was synced with — a value this binary
/// by definition does not hold.
fn synced_digest(consumer: &Path) -> Option<String> {
    let path = consumer.join("target/fluxor/fluxor-abi/sdk/abi_surface_srcpin.rs");
    let text = std::fs::read_to_string(path).ok()?;
    let at = text.find("pub const ABI_SURFACE_DIGEST")?;
    // The `[` of the ARRAY LITERAL, not the one in the type `[u8; 32]` that
    // precedes it — the first `[` after the name is the type's, and taking
    // it yields "u8; 32" and a silent `None` that reads as "no synced SDK".
    let eq = text[at..].find('=')?;
    let open = text[at + eq..].find('[')?;
    let start = at + eq + open;
    let close = text[start..].find(']')?;
    let body = &text[start + 1..start + close];
    let mut out = String::new();
    for tok in body.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        let v: u8 = if let Some(hex) = tok.strip_prefix("0x") {
            u8::from_str_radix(hex, 16).ok()?
        } else {
            tok.parse().ok()?
        };
        out.push_str(&format!("{v:02x}"));
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Does this consumer take fluxor as a SOURCE dependency?
///
/// `fluxor = "0.0.1"` does; `fluxor = { abi = 1 }` is a wire-ABI pin and
/// does not — it says which ABI the project targets, not that it compiles
/// against the SDK sources. Only the first materialises
/// `target/fluxor/fluxor-abi/sdk/`, which is the thing this gate reads.
fn depends_on_sdk(consumer: &Path) -> bool {
    let Ok(raw) = std::fs::read_to_string(consumer.join("fluxor.toml")) else {
        return false;
    };
    let Ok(doc) = toml::from_str::<toml::Value>(&raw) else {
        return false;
    };
    doc.get("dependencies")
        .and_then(|d| d.get("fluxor"))
        .is_some_and(|f| f.as_str().is_some())
}

/// Run the phase. `self_invoke` builds a `Command` that re-runs this CLI.
pub fn check(
    project_root: &Path,
    consumers: &[Consumer],
    self_invoke: impl Fn() -> Command,
) -> std::result::Result<(), String> {
    let plan = crate::abi_pin::compute(project_root).map_err(|e| e.to_string())?;
    let ours = plan.digest_hex.to_lowercase();

    let mut problems = Vec::new();
    let mut checked = 0usize;

    for c in consumers {
        // An absent checkout is not a failure. Most people have some of the
        // sibling repos and not all of them, and a gate that demanded the
        // full set would be one everybody learned to skip.
        if !c.path.join("fluxor.toml").exists() {
            continue;
        }
        let Some(theirs) = synced_digest(&c.path) else {
            // No materialised SDK. Which of two things that means is
            // decided by the consumer's own manifest, and getting it wrong
            // in either direction is bad: a project that DOES depend on the
            // SDK and has not synced is exactly what this gate is for, and
            // one that does not is not this gate's business at all.
            //
            // `fluxor = { abi = N }` is a wire-ABI PIN, not a source
            // dependency — truffle carries one and materialises no SDK. Only
            // a version-string dependency pulls the SDK sources in.
            if depends_on_sdk(&c.path) {
                problems.push(format!(
                    "{}: depends on the fluxor SDK but has not materialised it \
                     (run `fluxor sync` there)",
                    c.name
                ));
            }
            continue;
        };
        if theirs.to_lowercase() != ours {
            problems.push(format!(
                "{}: synced against ABI surface {}…, this tree is {}… — \
                 publish this fluxor and `fluxor sync` there, then re-run. \
                 Building now would compile it against the PREVIOUS fluxor \
                 and report green.",
                c.name,
                &theirs[..theirs.len().min(12)],
                &ours[..ours.len().min(12)]
            ));
            continue;
        }
        let out = self_invoke()
            .arg("modules")
            .arg("build")
            .arg("--all")
            .current_dir(&c.path)
            .output()
            .map_err(|e| format!("{}: could not run the build: {e}", c.name))?;
        checked += 1;
        if !out.status.success() {
            let text = String::from_utf8_lossy(&out.stderr);
            let tail: Vec<&str> = text.lines().rev().take(6).collect();
            let tail: Vec<&str> = tail.into_iter().rev().collect();
            problems.push(format!(
                "{}: modules build failed\n    {}",
                c.name,
                tail.join("\n    ")
            ));
        }
    }

    if problems.is_empty() {
        // Zero consumers present is reported as a pass, not silently: a
        // developer with no sibling checkouts should see that the gate found
        // nothing to gate rather than believe it checked something.
        if checked == 0 {
            return Err("no consumer checkouts found — nothing was checked".to_string());
        }
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}
