//! Store maintenance: `fluxor store fsck`.
//!
//! The store has one destructive verb (`gc`), one migration verb
//! (`restamp`) and one question: is everything anybody pins still here?
//! Without a way to ask it, a missing artifact is discovered one at a
//! time, by a build that can no longer resolve a module — so `fsck`
//! asks it of the whole store at once.
//!
//! `fsck` is read-only and takes no store lock. It snapshots
//! `index.json` once and works from that, so it is safe to run while
//! other sessions publish into the same store: a publish landing
//! mid-run shows up as a blob the snapshot did not expect, never as
//! corruption. `--repair` restores quarantined blobs; nothing here ever
//! deletes.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::error::Result;
use crate::oci_store::OciStore;
use crate::store_pins;

/// One pinned digest's health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinHealth {
    /// The manifest and everything it references are present.
    Resolvable,
    /// Present only in quarantine; any read restores it. Reported so an
    /// operator can see the sweep guessed wrong, not because anything
    /// is broken.
    Quarantined,
    /// The manifest resolves through a restamp alias.
    Aliased(String),
    /// The manifest is present but a blob it references is not.
    Dangling(String),
    /// Gone. A rebuild yields a different digest, so this is a loss, not
    /// a repair job — and saying so plainly is the point.
    Dead,
}

impl PinHealth {
    pub fn label(&self) -> String {
        match self {
            PinHealth::Resolvable => "ok".into(),
            PinHealth::Quarantined => "quarantined (healed on read)".into(),
            PinHealth::Aliased(d) => format!("via restamp alias {}", short(d)),
            PinHealth::Dangling(d) => format!("DANGLING: layer {} missing", short(d)),
            PinHealth::Dead => "DEAD: manifest not in store".into(),
        }
    }

    pub fn is_fault(&self) -> bool {
        matches!(self, PinHealth::Dangling(_) | PinHealth::Dead)
    }
}

/// One checkout's pins, as `fsck` found them.
#[derive(Debug)]
pub struct CheckoutReport {
    pub label: String,
    pub checkout: PathBuf,
    pub present: bool,
    pub member: bool,
    pub total: usize,
    /// Only the entries worth printing: faults and quarantine hits.
    pub notable: Vec<(String, PinHealth)>,
    /// Digests this checkout is the ONLY holder of.
    pub sole: usize,
    /// Digests no workspace member holds.
    pub unmembered: usize,
}

/// The whole check.
#[derive(Debug, Default)]
pub struct FsckReport {
    pub checkouts: Vec<CheckoutReport>,
    /// Index descriptors whose manifest or closure could not be read.
    pub index_faults: Vec<String>,
    /// Manifests still carrying provenance annotations — they will keep
    /// churning until `fluxor store restamp` runs.
    pub unrestamped: usize,
    pub blobs_total: usize,
    pub blobs_live: usize,
    pub reclaimable: u64,
    pub quarantined: usize,
    pub ledger_missing: Vec<PathBuf>,
    pub repaired: Vec<String>,
}

fn short(digest: &str) -> String {
    digest
        .strip_prefix("sha256:")
        .unwrap_or(digest)
        .chars()
        .take(12)
        .collect()
}

/// Check every pin every checkout holds, and the store's own integrity.
pub fn fsck(store: &OciStore, repair: bool) -> Result<FsckReport> {
    let mut report = FsckReport::default();
    let index = store.read_index()?;
    let holders = store_pins::holders(store.root())?;

    // 1. Index integrity, and how much of the store still predates the
    //    restamp.
    for d in &index.manifests {
        match store.read_manifest(d) {
            Ok(m) => {
                if m.annotations.contains_key(crate::oci_store::ANN_PROVENANCE)
                    || m.annotations.contains_key(crate::oci_store::ANN_SOURCE_REV)
                {
                    report.unrestamped += 1;
                }
                for l in m.layers.iter().chain(std::iter::once(&m.config)) {
                    if !store.has_blob(&l.digest) {
                        report.index_faults.push(format!(
                            "{} references missing blob {}",
                            short(&d.digest),
                            short(&l.digest)
                        ));
                    }
                }
            }
            // An index child is an OCI index, not a manifest; the
            // closure walk below covers it.
            Err(_) if d.media_type == crate::oci_store::MT_OCI_INDEX => {}
            Err(e) => report
                .index_faults
                .push(format!("{}: {e}", short(&d.digest))),
        }
    }

    // 2. Pin health, per checkout.
    let mut hold_count: BTreeMap<String, usize> = BTreeMap::new();
    for (digest, hs) in &holders.by_digest {
        hold_count.insert(digest.clone(), hs.len());
    }
    for entry in store_pins::entries(store.root())? {
        if !entry.present() {
            report.ledger_missing.push(entry.checkout.clone());
        }
        let label = entry.label();
        let mut c = CheckoutReport {
            member: holders.members.contains(&label),
            label,
            checkout: entry.checkout.clone(),
            present: entry.present(),
            total: entry.digests.len(),
            notable: Vec::new(),
            sole: 0,
            unmembered: 0,
        };
        for digest in &entry.digests {
            if hold_count.get(digest).copied().unwrap_or(0) == 1 {
                c.sole += 1;
            }
            if !holders.any_member(digest) {
                c.unmembered += 1;
            }
            let quarantined = store.is_quarantined(digest);
            if quarantined && repair {
                // `blob_path` heals as a side effect of being asked.
                let _ = store.blob_path(digest);
                report.repaired.push(digest.clone());
            }
            let health = health_of(store, digest, quarantined && !repair);
            if health.is_fault() || matches!(health, PinHealth::Quarantined) {
                c.notable.push((digest.clone(), health));
            }
        }
        report.checkouts.push(c);
    }

    // 3. Reclaimable bytes — the figure that says whether the collector
    //    is keeping up, which for a displacement-triggered sweep it
    //    never is.
    let (live, damaged) = store.live_closure()?;
    for d in damaged {
        report
            .index_faults
            .push(format!("{}: present but unreadable", short(&d)));
    }
    let blobs = store.root().join("blobs").join("sha256");
    if blobs.is_dir() {
        for entry in std::fs::read_dir(&blobs)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.len() != 64 {
                continue;
            }
            report.blobs_total += 1;
            if live.contains(&format!("sha256:{name}")) {
                report.blobs_live += 1;
            } else {
                report.reclaimable += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    let q = store.quarantine_dir();
    if q.is_dir() {
        report.quarantined = std::fs::read_dir(&q)?
            .filter_map(std::result::Result::ok)
            .count();
    }
    Ok(report)
}

fn health_of(store: &OciStore, digest: &str, quarantined: bool) -> PinHealth {
    if quarantined {
        return PinHealth::Quarantined;
    }
    let resolved = store.resolve_pin(digest);
    let Ok(bytes) = store.read_blob(&resolved) else {
        return PinHealth::Dead;
    };
    if let Ok(m) = serde_json::from_slice::<crate::oci_store::ImageManifest>(&bytes) {
        for l in m.layers.iter().chain(std::iter::once(&m.config)) {
            if !store.has_blob(&l.digest) {
                return PinHealth::Dangling(l.digest.clone());
            }
        }
    }
    if resolved != digest {
        return PinHealth::Aliased(resolved);
    }
    PinHealth::Resolvable
}

/// Render the report. One block per checkout, faults named with the
/// reference and the holders, then the store-wide totals.
pub fn render(report: &FsckReport) -> String {
    let mut s = String::new();
    s.push_str("pins, by checkout\n");
    for c in &report.checkouts {
        let faults = c.notable.iter().filter(|(_, h)| h.is_fault()).count();
        s.push_str(&format!(
            "  {:<24} {:<11} {:>4} pins   {:>3} sole-held   {:>3} unmembered{}\n",
            c.label,
            if c.member { "member" } else { "non-member" },
            c.total,
            c.sole,
            c.unmembered,
            if c.present {
                String::new()
            } else {
                format!("   [checkout missing: {}]", c.checkout.display())
            }
        ));
        for (digest, health) in &c.notable {
            s.push_str(&format!("      {}  {}\n", short(digest), health.label()));
        }
        if faults > 0 {
            s.push_str(&format!(
                "      ^ {faults} unrecoverable — a rebuild mints a different digest, \
                 so these are losses, not repairs\n"
            ));
        }
    }
    if report.checkouts.is_empty() {
        s.push_str(
            "  (the ledger is empty — run `fluxor store adopt <checkout>` for each \
             checkout holding a fluxor.lock)\n",
        );
    }
    s.push_str("\nstore\n");
    s.push_str(&format!(
        "  blobs                {:>8}  ({} reachable from a root)\n",
        report.blobs_total, report.blobs_live
    ));
    s.push_str(&format!(
        "  reclaimable          {:>8.1} GiB  (`fluxor store gc` collects it)\n",
        report.reclaimable as f64 / (1u64 << 30) as f64
    ));
    s.push_str(&format!(
        "  quarantined          {:>8}  (restored automatically on read)\n",
        report.quarantined
    ));
    if report.unrestamped > 0 {
        s.push_str(&format!(
            "  un-restamped         {:>8}  manifests still carry provenance annotations \
             and will keep\n                                 churning — run `fluxor store restamp`\n",
            report.unrestamped
        ));
    }
    for fault in &report.index_faults {
        s.push_str(&format!("  INDEX FAULT  {fault}\n"));
    }
    for missing in &report.ledger_missing {
        s.push_str(&format!(
            "  ledger entry names a checkout that is not on disk: {}\n\
             \x20   (kept — an unmounted repo is not a deleted one; \
             `fluxor store gc --forget-missing` drops it)\n",
            missing.display()
        ));
    }
    if !report.repaired.is_empty() {
        s.push_str(&format!(
            "  repaired             {:>8}  blobs restored from quarantine\n",
            report.repaired.len()
        ));
    }
    s
}

/// What the store is holding, by directory.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StoreUsage {
    pub live_bytes: u64,
    pub live_count: u64,
    pub quarantined_bytes: u64,
    pub quarantined_count: u64,
}

impl StoreUsage {
    /// One line, or `None` when there is nothing worth saying.
    ///
    /// Reported rather than collected, deliberately. `gc` is the only verb
    /// that deletes, and its own doc calls it "a deliberate, whole-store pass
    /// an operator runs ... rather than a reflex on a hot path" — a store
    /// that sweeps on publish is how pins get destroyed. So this says what is
    /// there and leaves the decision where it belongs.
    #[must_use]
    pub fn report(&self, quarantine_warn_gib: f64) -> Option<String> {
        let gib = |b: u64| b as f64 / 1_073_741_824.0;
        if self.quarantined_bytes == 0 && self.live_bytes == 0 {
            return None;
        }
        let mut line = format!(
            "store: {:.1} GiB in {} blob(s)",
            gib(self.live_bytes),
            self.live_count
        );
        if self.quarantined_count > 0 {
            line.push_str(&format!(
                ", {:.1} GiB quarantined in {} blob(s)",
                gib(self.quarantined_bytes),
                self.quarantined_count
            ));
            if gib(self.quarantined_bytes) >= quarantine_warn_gib {
                line.push_str(
                    " — nothing expires quarantined bytes but `fluxor store gc`; \
                     run it when you are ready to lose them",
                );
            }
        }
        Some(line)
    }
}

/// Measure the store's two byte-holding directories.
///
/// Cheap by construction: `read_dir` plus `metadata`, no hashing and no index
/// parse, so it can sit on the publish path. Unreadable entries are skipped —
/// this is a report, and a report that fails is worse than one that is a few
/// blobs short.
#[must_use]
pub fn usage(store_root: &std::path::Path) -> StoreUsage {
    let mut u = StoreUsage::default();
    let tally = |dir: std::path::PathBuf, bytes: &mut u64, count: &mut u64| {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            if let Ok(m) = e.metadata() {
                if m.is_file() {
                    *bytes += m.len();
                    *count += 1;
                }
            }
        }
    };
    tally(
        store_root.join("blobs").join("sha256"),
        &mut u.live_bytes,
        &mut u.live_count,
    );
    tally(
        store_root.join("quarantine"),
        &mut u.quarantined_bytes,
        &mut u.quarantined_count,
    );
    u
}

#[cfg(test)]
mod usage_tests {
    use super::*;

    #[test]
    fn a_large_quarantine_says_what_clears_it() {
        let u = StoreUsage {
            live_bytes: 3_865_470_566,
            live_count: 5877,
            quarantined_bytes: 22_548_578_304,
            quarantined_count: 35_334,
        };
        let line = u.report(1.0).expect("something to report");
        assert!(line.contains("21.0 GiB quarantined"), "{line}");
        assert!(line.contains("fluxor store gc"), "{line}");
    }

    #[test]
    fn a_small_quarantine_is_stated_without_advice() {
        let u = StoreUsage {
            live_bytes: 1_073_741_824,
            live_count: 10,
            quarantined_bytes: 1024,
            quarantined_count: 1,
        };
        let line = u.report(1.0).expect("something to report");
        assert!(line.contains("quarantined"), "{line}");
        assert!(!line.contains("store gc"), "{line}");
    }

    #[test]
    fn an_empty_store_says_nothing() {
        assert_eq!(StoreUsage::default().report(1.0), None);
    }
}
