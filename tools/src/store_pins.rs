//! The store's pin ledger: which checkouts on this machine are holding
//! which store digests.
//!
//! The store's garbage collector needs to know what is live. Index tags
//! answer that for anything currently tagged, but a `fluxor.lock`
//! deliberately pins a digest so it STOPS moving with the tag — so pins
//! are a root class of their own, and one the store cannot see by
//! looking at itself.
//!
//! Workspace membership is the wrong question twice over. It means
//! "this project participates in epoch and currency checks", which is
//! unrelated to whether anybody is holding a digest; and
//! `workspace.toml` is a hand-maintained list of absolute paths on one
//! machine, so a second clone, a worktree or a consumer nobody added is
//! unprotected by construction. A sweep that took membership for
//! liveness would delete a manifest whose only holder is a checkout it
//! cannot see, and a rebuild yields a different digest, so the artifact
//! is gone rather than re-derivable.
//!
//! A root that holds only while some other checkout happens to pin the
//! same digest is also no root at all: it survives for reasons it has
//! no part in and no way to audit, and vanishes the moment that other
//! checkout advances its own pins — correct, unremarkable, unannounced.
//!
//! So the ledger records a fact rather than a list. Every checkout that
//! writes a lockfile or resolves a pin registers itself here, and the
//! root set is what actually happened rather than who was invited. One
//! file per checkout, named by the hash of its canonical path, written
//! atomically: two sessions registering
//! different checkouts never touch the same file, and two registering
//! the SAME checkout are already serialized by the lockfile guard.
//!
//! Offline-first: nothing here touches the network.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Ledger directory inside the store root.
pub fn ledger_dir(store_root: &Path) -> PathBuf {
    store_root.join("pins")
}

/// One checkout's registration.
#[derive(Debug, Clone)]
pub struct LedgerEntry {
    /// Canonical path of the checkout holding the pins.
    pub checkout: PathBuf,
    /// RFC 3339 timestamp of the last registration.
    pub updated: String,
    /// Every `sha256:` digest the checkout's lockfile pinned.
    pub digests: BTreeSet<String>,
    /// Ledger file this entry was read from.
    pub path: PathBuf,
}

impl LedgerEntry {
    /// Short label for reports: the checkout's directory name.
    pub fn label(&self) -> String {
        self.checkout
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| self.checkout.to_string_lossy().to_string())
    }

    /// Whether the checkout is still on disk. A missing one is reported,
    /// never silently dropped: a repo can be temporarily unmounted, and
    /// forgetting its pins on that basis is how artifacts get deleted.
    pub fn present(&self) -> bool {
        self.checkout.is_dir()
    }
}

/// Ledger file for `checkout`, named by the hash of its canonical path
/// so the name is stable, filesystem-safe and free of separators.
fn entry_path(store_root: &Path, checkout: &Path) -> PathBuf {
    let canonical = checkout
        .canonicalize()
        .unwrap_or_else(|_| checkout.to_path_buf());
    let hex = crate::oci_store::sha256_hex_prefixed(canonical.to_string_lossy().as_bytes());
    let hex = hex.strip_prefix("sha256:").unwrap_or(&hex).to_string();
    ledger_dir(store_root).join(format!("{hex}.toml"))
}

/// Every `sha256:<hex>` digest appearing in `text`. Shared by the
/// ledger writer and the legacy member-lockfile scan, so both admit
/// exactly the same digests from exactly the same file.
pub fn digests_in(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = text;
    while let Some(pos) = rest.find("sha256:") {
        let hex: String = rest[pos + 7..]
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect();
        if hex.len() == 64 {
            out.insert(format!("sha256:{hex}"));
        }
        rest = &rest[pos + 7..];
    }
    out
}

/// Register `digests` as held by `checkout`.
///
/// Idempotent and cheap: a registration that would not change the file
/// is skipped, so the build-time resolver can call it on every
/// invocation without writing anything. Never fails the caller —
/// registration is a liveness improvement, and a store whose ledger
/// directory cannot be written is not a reason to fail a build. It
/// degrades to the behaviour that existed before the ledger.
pub fn register(store_root: &Path, checkout: &Path, digests: &BTreeSet<String>) {
    let _ = try_register(store_root, checkout, digests);
}

fn try_register(store_root: &Path, checkout: &Path, digests: &BTreeSet<String>) -> Result<()> {
    // Never bring a store into being by registering against it. An
    // `$FLUXOR_STORE` that does not exist yet must stay untouched, or
    // the next `OciStore::open` finds a non-empty directory that is not
    // a store and rightly refuses to initialize over it.
    if !store_root.join("oci-layout").exists() {
        return Ok(());
    }
    let canonical = checkout
        .canonicalize()
        .unwrap_or_else(|_| checkout.to_path_buf());
    let path = entry_path(store_root, checkout);
    let mut body = String::new();
    body.push_str("# fluxor store pin ledger — generated, one file per checkout.\n");
    body.push_str("# Registered by `fluxor update`, `fluxor store pin` and pin resolution.\n");
    body.push_str("# Every digest listed here is a garbage-collection root.\n\n");
    body.push_str(&format!("checkout = \"{}\"\n", canonical.display()));
    body.push_str("digests = [\n");
    for d in digests {
        body.push_str(&format!("    \"{d}\",\n"));
    }
    body.push_str("]\n");

    // Compare on everything but the timestamp, so an unchanged pin set
    // rewrites nothing and the ledger's mtime stays meaningful.
    if let Ok(existing) = fs::read_to_string(&path) {
        if strip_timestamp(&existing) == body {
            return Ok(());
        }
    }
    fs::create_dir_all(ledger_dir(store_root))?;
    let stamped = format!("updated = \"{}\"\n{body}", now_rfc3339());
    write_atomic(&path, stamped.as_bytes())
}

fn strip_timestamp(text: &str) -> String {
    text.lines()
        .filter(|l| !l.starts_with("updated = "))
        .map(|l| format!("{l}\n"))
        .collect()
}

/// Read every ledger entry. A file that cannot be read or parsed is a
/// hard error: the caller is the sweep, whose whole contract is to fail
/// closed rather than assume a checkout holds nothing.
pub fn entries(store_root: &Path) -> Result<Vec<LedgerEntry>> {
    let dir = ledger_dir(store_root);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)?
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .collect();
    files.sort();
    for path in files {
        let text = fs::read_to_string(&path).map_err(|e| {
            Error::Config(format!(
                "pin ledger entry {} unreadable ({e}) — sweep skipped (fail-closed)",
                path.display()
            ))
        })?;
        let mut checkout = PathBuf::new();
        let mut updated = String::new();
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("checkout = ") {
                checkout = PathBuf::from(v.trim().trim_matches('"'));
            } else if let Some(v) = line.strip_prefix("updated = ") {
                updated = v.trim().trim_matches('"').to_string();
            }
        }
        if checkout.as_os_str().is_empty() {
            return Err(Error::Config(format!(
                "pin ledger entry {} names no checkout — refusing to sweep against a \
                 ledger it cannot interpret",
                path.display()
            )));
        }
        out.push(LedgerEntry {
            checkout,
            updated,
            digests: digests_in(&text),
            path,
        });
    }
    Ok(out)
}

/// Read `checkout`'s `fluxor.lock` and register its pins. This is what
/// `fluxor store adopt` runs, and what bootstraps a checkout that has
/// not resolved anything since the ledger existed.
pub fn adopt(store_root: &Path, checkout: &Path) -> Result<usize> {
    let lock = checkout.join("fluxor.lock");
    if !lock.is_file() {
        return Err(Error::Config(format!(
            "{} holds no fluxor.lock — nothing to adopt",
            checkout.display()
        )));
    }
    let text = fs::read_to_string(&lock)?;
    // The `[catalog]` stamp is a digest over the catalog FILES, not a
    // store blob, so admitting it would register a root that can never
    // be reached — count and register only `[[artifact]]` pins.
    let digests = artifact_digests(&text);
    let n = digests.len();
    try_register(store_root, checkout, &digests)?;
    Ok(n)
}

/// `sha256:` digests from the `[[artifact]]` entries of a lockfile,
/// excluding the `[catalog]` stamp.
pub fn artifact_digests(lock_text: &str) -> BTreeSet<String> {
    let body = match lock_text.find("\n[catalog]") {
        Some(pos) => &lock_text[..pos],
        None => lock_text,
    };
    digests_in(body)
}

/// Who holds each digest, for the displacement report and `fsck`.
#[derive(Debug, Clone, Default)]
pub struct Holders {
    /// Digest → checkout labels holding it, in ledger order.
    pub by_digest: BTreeMap<String, Vec<String>>,
    /// Checkout label → canonical path.
    pub paths: BTreeMap<String, PathBuf>,
    /// Labels of checkouts that are workspace members.
    pub members: BTreeSet<String>,
}

impl Holders {
    /// Whether any WORKSPACE MEMBER holds `digest`. Retained because it
    /// is the exact predicate the old root set used, and the reports
    /// need to say when the answer has become "none".
    pub fn any_member(&self, digest: &str) -> bool {
        self.by_digest
            .get(digest)
            .is_some_and(|hs| hs.iter().any(|h| self.members.contains(h)))
    }

    /// Holders of `digest` other than `exclude` (the publishing
    /// checkout), which is what makes a displacement somebody else's
    /// problem rather than the publisher's own.
    pub fn others(&self, digest: &str, exclude: &Path) -> Vec<String> {
        let exclude = exclude.canonicalize().unwrap_or_else(|_| exclude.into());
        self.by_digest
            .get(digest)
            .map(|hs| {
                hs.iter()
                    .filter(|h| self.paths.get(*h) != Some(&exclude))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Build the holder map from the ledger, marking which checkouts are
/// workspace members. Member lockfiles are read directly as well as
/// through the ledger, so a member that has never registered is still
/// counted — the ledger ADDS roots, it never removes one that the old
/// root set had.
pub fn holders(store_root: &Path) -> Result<Holders> {
    let mut h = Holders::default();
    let mut member_paths: BTreeSet<PathBuf> = BTreeSet::new();
    if let Ok(Some(ws)) = crate::workspace::load_workspace() {
        for m in &ws.workspace.members {
            member_paths.insert(m.canonicalize().unwrap_or_else(|_| m.clone()));
        }
    }

    let mut add = |label: String, path: PathBuf, digests: BTreeSet<String>, member: bool| {
        if member {
            h.members.insert(label.clone());
        }
        h.paths.insert(label.clone(), path);
        for d in digests {
            let slot = h.by_digest.entry(d).or_default();
            if !slot.contains(&label) {
                slot.push(label.clone());
            }
        }
    };

    for entry in entries(store_root)? {
        let canonical = entry.checkout.clone();
        let member = member_paths.contains(&canonical);
        add(entry.label(), canonical, entry.digests, member);
    }
    for path in member_paths {
        let lock = path.join("fluxor.lock");
        if !lock.exists() {
            continue;
        }
        let text = fs::read_to_string(&lock).map_err(|e| {
            Error::Config(format!(
                "member lockfile {} unreadable ({e}) — sweep skipped (fail-closed)",
                lock.display()
            ))
        })?;
        let label = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string_lossy().to_string());
        add(label, path, artifact_digests(&text), true);
    }
    Ok(h)
}

/// Every digest any checkout holds — the sweep's pin root class.
pub fn root_digests(store_root: &Path) -> Result<BTreeSet<String>> {
    Ok(holders(store_root)?.by_digest.into_keys().collect())
}

/// Drop ledger entries whose checkout is no longer on disk. Only ever
/// run from `fluxor store gc --forget-missing`, never automatically:
/// an unmounted repo is indistinguishable from a deleted one, and
/// guessing wrong is how a pin stops being a root.
pub fn forget_missing(store_root: &Path) -> Result<Vec<PathBuf>> {
    let mut dropped = Vec::new();
    for entry in entries(store_root)? {
        if !entry.present() {
            fs::remove_file(&entry.path)?;
            dropped.push(entry.checkout);
        }
    }
    Ok(dropped)
}

fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Civil date from a Unix timestamp (Howard Hinnant's algorithm) —
    // the ledger stamps a human-readable time without a date crate.
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&tmp, bytes)?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Registration writes into a real store, never into a directory
    /// that merely has the store's path: creating `pins/` beside a store
    /// that does not exist yet leaves a non-empty directory the next
    /// `OciStore::open` rightly refuses to initialize over.
    #[test]
    fn registering_against_a_nonexistent_store_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let checkout = dir.path().join("outsider");
        fs::create_dir_all(&checkout).unwrap();
        register(&store, &checkout, &BTreeSet::new());
        assert!(!store.exists(), "no store, no ledger");
    }

    #[test]
    fn a_registration_round_trips_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::oci_store::OciStore::open(dir.path().join("store")).unwrap();
        let store = store.root().to_path_buf();
        let checkout = dir.path().join("outsider");
        fs::create_dir_all(&checkout).unwrap();
        let digests: BTreeSet<String> = ["sha256:".to_string() + &"a".repeat(64)]
            .into_iter()
            .collect();

        register(&store, &checkout, &digests);
        let first = entries(&store).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].digests, digests);
        assert_eq!(first[0].label(), "outsider");
        let stamp = first[0].updated.clone();

        // An unchanged registration rewrites nothing, so the timestamp
        // still describes when the pin set last MOVED.
        register(&store, &checkout, &digests);
        assert_eq!(entries(&store).unwrap()[0].updated, stamp);
    }

    #[test]
    fn the_catalog_stamp_is_not_a_pin() {
        let lock = "[[artifact]]\ndigest = \"sha256:\
                    1111111111111111111111111111111111111111111111111111111111111111\"\n\
                    \n[catalog]\ndigest = \"sha256:\
                    2222222222222222222222222222222222222222222222222222222222222222\"\n";
        let d = artifact_digests(lock);
        assert_eq!(d.len(), 1, "the catalog stamp is not a store blob: {d:?}");
        assert!(d.iter().next().unwrap().ends_with("111"));
    }

    #[test]
    fn a_ledger_entry_that_names_no_checkout_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        fs::create_dir_all(ledger_dir(&store)).unwrap();
        // (`entries` reads the ledger directly; no store needed to prove
        // it refuses an entry it cannot interpret.)
        fs::write(ledger_dir(&store).join("bogus.toml"), "digests = []\n").unwrap();
        assert!(entries(&store).is_err());
    }
}
