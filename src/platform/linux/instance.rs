//! Instance scoping on Linux: which runtime this is on its host, and the
//! host registry every runtime on the host shares.
//!
//! Several runtimes may share one host (one network domain, one set of
//! host-global names and tunables). Each is an **instance**, named by a
//! **tag**:
//!
//! * `FLUXOR_INSTANCE` when set (`[a-z0-9]`, 1..=32 characters);
//! * otherwise a short digest of `FLUXOR_STATE_DIR` when that is set;
//! * otherwise an ephemeral tag from the process id (`p<base36 pid>`), so a
//!   runtime started with neither still never takes another's names. Its
//!   objects are collected as soon as it is gone, like any dead tag.
//!
//! `FLUXOR_STATE_DIR` is the instance's own state directory (distinct from
//! `FLUXOR_STORE_DIR`); the runtime holds an exclusive lock in it
//! (`instance.lock`) for its life, so two runtimes never share one.
//!
//! The **host registry** lives in `/run/fluxor/` (`FLUXOR_RUN_DIR`
//! overrides it) and every change to it is made under one registry lock
//! (`registry.lock`):
//!
//! * `live/<tag>` — liveness. The running instance holds an exclusive lock
//!   on it for its whole life. The OS drops a dead process's lock, so
//!   liveness is a lock that is either held or free, never a count that
//!   leaks. A second runtime asking for a live tag gets `EBUSY`.
//! * `tags/<tag>` — what the tag holds: its claims (segment prefixes, peer
//!   prefixes, gateways, held addresses; an overlap with another live tag's
//!   claim is a conflict) and its allocations (routing table id, rule
//!   priority).
//! * `tunables/<hex key>` — each host tunable an instance changed: its
//!   value before the first change and the tags depending on it. Restored
//!   when the last live dependent is gone, and only if it now differs, so a
//!   tunable the host already had on (forwarding) is never turned off.
//!
//! **Dead-tag collection** runs on every instance start and exit: every tag
//! whose liveness lock is free is reclaimed — first the object kinds that
//! must stop acting for the dead tag at once (held addresses, guards), then
//! the rest, then its tunables, claims and allocations. An instance's start
//! also reclaims what its own previous life left behind (boot reclaim),
//! touching only objects that carry its tag. The object kinds are a table of
//! [`Reclaimer`]s, one row per kind.
//!
//! The registry's directories must be this runtime's (or root's) and
//! writable by no one else: a tunable record names a host setting the
//! runtime writes back, so a record another user planted would be a write
//! made on that user's behalf. A directory of its own the runtime makes so;
//! any other is refused (`EACCES`).
//!
//! Host-global names come from the tag (`fx<stem>w<idx>` workload links,
//! `fx<stem>g` the gateway link, `fx_<tag>_<name>` policy tables), where the
//! stem is the tag's first six characters (a link name has 15). Two live
//! tags may not share a stem; the full tag rides in the link's alias.
//!
//! Platform-internal: nothing here crosses the portable surface.

use crate::kernel::sys::errno;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Longest tag: what an alias and a policy-table name carry comfortably.
pub const TAG_MAX: usize = 32;
/// The part of the tag a link name carries: `fx` + stem + `w` + index must
/// fit IFNAMSIZ (15 characters).
pub const STEM_MAX: usize = 6;
/// Where the registry lives unless `FLUXOR_RUN_DIR` says otherwise.
pub const DEFAULT_RUN_DIR: &str = "/run/fluxor";
/// Where tunables live unless `FLUXOR_TUNABLE_DIR` says otherwise (a test
/// hook: it points the registry at a scratch tree).
pub const DEFAULT_TUNABLE_DIR: &str = "/proc/sys";
/// A link alias that marks a link as an instance's: this, then the tag.
pub const LINK_ALIAS_PREFIX: &str = "fluxor:";
/// The first routing table id handed out. Ids below are the host's own
/// (main 254, local 255, default 253, and whatever an operator numbered).
pub const TABLE_ID_FIRST: u32 = 0x4658_0000;
/// The first rule priority handed out; the range ends before the host's
/// `main` rule at [`RULE_PRIORITY_MAIN`], since an instance's rule must be
/// consulted first.
pub const RULE_PRIORITY_FIRST: u32 = 20_000;
/// The host's `main` rule priority.
pub const RULE_PRIORITY_MAIN: u32 = 32766;

// ---- tags and names ---------------------------------------------------------

/// A tag is `[a-z0-9]`, 1..=[`TAG_MAX`] characters: safe in a link name, a
/// policy-table name and a file name, and with no separator in it, so
/// `fx_<tag>_` prefixes never overlap between tags.
pub fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= TAG_MAX
        && tag
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// The part of `tag` a link name carries.
pub fn stem(tag: &str) -> &str {
    &tag[..tag.len().min(STEM_MAX)]
}

/// Name of the node-side link of workload `idx`.
pub fn workload_link_name(tag: &str, idx: usize) -> String {
    format!("fx{}w{idx}", stem(tag))
}

/// Name of the instance's gateway link.
pub fn gateway_link_name(tag: &str) -> String {
    format!("fx{}g", stem(tag))
}

/// The alias every link of the instance carries.
pub fn link_alias(tag: &str) -> String {
    format!("{LINK_ALIAS_PREFIX}{tag}")
}

/// The tag a link alias names, if it is an instance's alias.
pub fn alias_tag(alias: &str) -> Option<&str> {
    alias
        .strip_prefix(LINK_ALIAS_PREFIX)
        .filter(|t| valid_tag(t))
}

/// Whether `name` is one of the link names a tag with `stem` uses.
pub fn is_link_name_of(name: &str, stem: &str) -> bool {
    let Some(rest) = name.strip_prefix("fx").and_then(|r| r.strip_prefix(stem)) else {
        return false;
    };
    rest == "g"
        || rest
            .strip_prefix('w')
            .is_some_and(|i| !i.is_empty() && i.bytes().all(|c| c.is_ascii_digit()))
}

/// The policy-table name prefix of a tag.
pub fn policy_table_prefix(tag: &str) -> String {
    format!("fx_{tag}_")
}

/// The host name of policy table `name` for `tag`.
pub fn policy_table_name(tag: &str, name: &str) -> String {
    format!("{}{}", policy_table_prefix(tag), name.replace('-', "_"))
}

/// The default tag of a state directory: the first eight hex digits of the
/// SHA-256 of its path.
pub fn state_dir_tag(dir: &Path) -> String {
    let mut h = crate::kernel::security::crypto::sha256::Sha256::new();
    h.update(dir.as_os_str().as_encoded_bytes());
    let d = h.finalize();
    let mut s = String::with_capacity(8);
    for b in &d[..4] {
        use core::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The tag of a runtime given neither an instance nor a state directory.
pub fn ephemeral_tag(pid: u32) -> String {
    let mut digits = Vec::new();
    let mut n = pid;
    loop {
        let d = (n % 36) as u8;
        digits.push(if d < 10 { b'0' + d } else { b'a' + d - 10 });
        n /= 36;
        if n == 0 {
            break;
        }
    }
    digits.push(b'p');
    digits.reverse();
    String::from_utf8(digits).unwrap_or_default()
}

// ---- claims -----------------------------------------------------------------

/// What a claim is a claim on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClaimKind {
    Segment,
    Peer,
    Gateway,
    Held,
}

impl ClaimKind {
    fn word(self) -> &'static str {
        match self {
            ClaimKind::Segment => "segment",
            ClaimKind::Peer => "peer",
            ClaimKind::Gateway => "gateway",
            ClaimKind::Held => "held",
        }
    }
    fn from_word(w: &str) -> Option<Self> {
        Some(match w {
            "segment" => ClaimKind::Segment,
            "peer" => ClaimKind::Peer,
            "gateway" => ClaimKind::Gateway,
            "held" => ClaimKind::Held,
            _ => return None,
        })
    }
}

/// One claimed prefix: `family` 4 or 6, the address in the first 4 or 16
/// bytes of `addr` (network order), `len` bits. A gateway or a held address
/// is a full-length prefix.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Claim {
    pub kind: ClaimKind,
    pub family: u8,
    pub addr: [u8; 16],
    pub len: u8,
}

impl Claim {
    fn bits(&self) -> u8 {
        if self.family == 6 {
            128
        } else {
            32
        }
    }

    fn valid(&self) -> bool {
        (self.family == 4 || self.family == 6) && self.len <= self.bits()
    }

    /// Whether the two prefixes share an address.
    pub fn overlaps(&self, other: &Claim) -> bool {
        if self.family != other.family {
            return false;
        }
        let n = self.len.min(other.len) as usize;
        let (full, rest) = (n / 8, n % 8);
        if self.addr[..full] != other.addr[..full] {
            return false;
        }
        if rest == 0 {
            return true;
        }
        let mask = 0xFFu8 << (8 - rest);
        self.addr[full] & mask == other.addr[full] & mask
    }
}

/// A claim refused because a live tag holds an overlapping one.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Conflict {
    /// The live tag holding it.
    pub tag: String,
    /// Its claim.
    pub theirs: Claim,
    /// The claim of ours that overlaps it.
    pub ours: Claim,
}

/// Why a claim was not recorded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ClaimError {
    /// Another live tag holds an overlapping prefix (`refused(conflict)`).
    Conflict(Conflict),
    /// The registry could not be read or written, or a claim is malformed.
    Errno(i32),
}

impl ClaimError {
    /// The errno a caller that only speaks errno reports.
    pub fn errno(&self) -> i32 {
        match self {
            ClaimError::Conflict(_) => errno::EEXIST,
            ClaimError::Errno(e) => *e,
        }
    }
}

// ---- per-tag record ---------------------------------------------------------

#[derive(Default, Clone)]
struct TagRecord {
    claims: Vec<Claim>,
    table: Option<u32>,
    priority: Option<u32>,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

impl TagRecord {
    fn parse(text: &str) -> Self {
        let mut r = TagRecord::default();
        for line in text.lines() {
            let w: Vec<&str> = line.split_whitespace().collect();
            match w.as_slice() {
                ["claim", kind, fam, addr, len] => {
                    let (Some(kind), Ok(family), Some(a), Ok(len)) = (
                        ClaimKind::from_word(kind),
                        fam.parse::<u8>(),
                        unhex(addr),
                        len.parse::<u8>(),
                    ) else {
                        continue;
                    };
                    let mut addr = [0u8; 16];
                    if a.len() != 16 {
                        continue;
                    }
                    addr.clone_from_slice(&a);
                    r.claims.push(Claim {
                        kind,
                        family,
                        addr,
                        len,
                    });
                }
                ["table", id] => r.table = id.parse().ok(),
                ["priority", p] => r.priority = p.parse().ok(),
                _ => {}
            }
        }
        r
    }

    fn render(&self) -> String {
        let mut s = String::new();
        for c in &self.claims {
            s.push_str(&format!(
                "claim {} {} {} {}\n",
                c.kind.word(),
                c.family,
                hex(&c.addr),
                c.len
            ));
        }
        if let Some(t) = self.table {
            s.push_str(&format!("table {t}\n"));
        }
        if let Some(p) = self.priority {
            s.push_str(&format!("priority {p}\n"));
        }
        s
    }
}

// ---- tunable record ---------------------------------------------------------

struct TunableRecord {
    key: String,
    prior: String,
    deps: Vec<String>,
}

impl TunableRecord {
    fn parse(text: &str) -> Option<Self> {
        let mut key = None;
        let mut prior = None;
        let mut deps = Vec::new();
        for line in text.lines() {
            let mut w = line.splitn(2, ' ');
            match (w.next(), w.next()) {
                (Some("key"), Some(k)) => key = Some(k.to_string()),
                (Some("prior"), Some(v)) => {
                    prior = Some(String::from_utf8(unhex(v)?).ok()?);
                }
                (Some("dep"), Some(t)) if valid_tag(t) => deps.push(t.to_string()),
                _ => {}
            }
        }
        Some(TunableRecord {
            key: key?,
            prior: prior?,
            deps,
        })
    }

    fn render(&self) -> String {
        let mut s = format!("key {}\nprior {}\n", self.key, hex(self.prior.as_bytes()));
        for d in &self.deps {
            s.push_str(&format!("dep {d}\n"));
        }
        s
    }
}

/// A tunable key is a path under the tunable root (`net/ipv4/ip_forward`):
/// relative, no `..`, no empty part.
fn valid_tunable_key(key: &str) -> bool {
    !key.is_empty()
        && !key.starts_with('/')
        && key
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
        && !key.bytes().any(|c| c.is_ascii_whitespace() || c == 0)
}

// ---- reclaim hooks ----------------------------------------------------------

/// When a kind is reclaimed during a collection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReclaimPhase {
    /// Before anything else, for every dead tag: objects that keep acting
    /// for the dead tag (answering for its held addresses, guarding its
    /// links) must go before anything another instance might now own.
    First,
    /// Everything else the tag left on the host.
    Rest,
}

/// What a reclaimer is told about the tag it reclaims.
pub struct ReclaimCtx<'a> {
    /// The tag whose objects go.
    pub tag: &'a str,
    /// `true` when no live tag uses this tag's stem, so an object that lost
    /// its alias (a crash between creating a link and naming it) may be
    /// matched by name. `false` for boot reclaim: that touches only objects
    /// carrying the tag.
    pub by_name: bool,
    /// The routing table id the tag was allocated, if any.
    pub table: Option<u32>,
    /// The rule priority the tag was allocated, if any.
    pub priority: Option<u32>,
    /// The tag's recorded claims that no live tag holds too: what is the
    /// tag's alone to withdraw (a live runtime that took over an address
    /// keeps answering for it).
    pub claims: &'a [Claim],
}

/// One object kind's reclaim: removes every object of the kind that the
/// tag left on the host. Idempotent; `Err(errno)` keeps the tag's records
/// so a later collection retries.
pub struct Reclaimer {
    pub kind: &'static str,
    pub phase: ReclaimPhase,
    pub run: fn(&ReclaimCtx<'_>) -> Result<(), i32>,
}

/// The object kinds instances create on the host, one row each: held
/// addresses and guards first (they act for the tag: the held addresses'
/// proxy entries, routes and addresses go before anything else, so a dead
/// runtime stops answering), then rules, routes, links and policy tables.
pub const RECLAIMERS: &[Reclaimer] = &[
    Reclaimer {
        kind: "held-address",
        phase: ReclaimPhase::First,
        run: super::net_route::reclaim_held,
    },
    Reclaimer {
        kind: "route-guard",
        phase: ReclaimPhase::First,
        run: super::net_route::reclaim_guard,
    },
    Reclaimer {
        kind: "route-rule",
        phase: ReclaimPhase::Rest,
        run: super::net_route::reclaim_rule,
    },
    Reclaimer {
        kind: "route-table",
        phase: ReclaimPhase::Rest,
        run: super::net_route::reclaim_routes,
    },
    Reclaimer {
        kind: "workload-link",
        phase: ReclaimPhase::Rest,
        run: super::net_identity::reclaim_links,
    },
    Reclaimer {
        kind: "policy-table",
        phase: ReclaimPhase::Rest,
        run: super::net_policy::reclaim_tables,
    },
];

// ---- the registry -----------------------------------------------------------

fn flock(f: &File, op: i32) -> Result<(), i32> {
    loop {
        // SAFETY: flock on a descriptor `f` owns for the call.
        let rc = unsafe { libc::flock(f.as_raw_fd(), op) };
        if rc == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if e == libc::EINTR {
            continue;
        }
        return Err(if e == libc::EWOULDBLOCK {
            errno::EBUSY
        } else {
            errno::ERROR
        });
    }
}

fn io_errno(e: &std::io::Error) -> i32 {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => errno::EACCES,
        std::io::ErrorKind::NotFound => errno::ENOENT,
        _ => errno::ERROR,
    }
}

/// `EACCES` unless `dir` is a directory owned by this process's user or by
/// root, and writable by neither its group nor others. One this user owns
/// is made so (a umask may leave it group-writable); one it does not own is
/// refused.
fn private_dir(dir: &Path) -> Result<(), i32> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = fs::metadata(dir).map_err(|e| io_errno(&e))?;
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    let mut mode = m.mode();
    if m.is_dir() && m.uid() == me && mode & 0o022 != 0 {
        mode &= !0o022;
        fs::set_permissions(dir, fs::Permissions::from_mode(mode & 0o7777))
            .map_err(|e| io_errno(&e))?;
    }
    if !m.is_dir() || (m.uid() != me && m.uid() != 0) || mode & 0o022 != 0 {
        log::warn!(
            "[instance] registry directory {} is not private to this runtime",
            dir.display()
        );
        return Err(errno::EACCES);
    }
    Ok(())
}

/// Write `text` to `path` whole: a temporary, then a rename over it.
fn write_whole(path: &Path, text: &str) -> Result<(), i32> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, text).map_err(|e| io_errno(&e))?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_errno(&e)
    })
}

/// The host registry at one run directory.
#[derive(Clone)]
pub struct Registry {
    run: PathBuf,
    tunables: PathBuf,
    reclaimers: &'static [Reclaimer],
}

/// Held while the registry is changed.
struct RegistryGuard {
    _lock: File,
}

impl Registry {
    /// The registry at `run_dir`, tunables under `tunable_dir`, reclaiming
    /// with `reclaimers`. Creates the directories it needs (mode 0755), and
    /// refuses (`EACCES`) any of them that its group or others may write and
    /// that is neither root's nor this runtime's to make private.
    pub fn open(
        run_dir: &Path,
        tunable_dir: &Path,
        reclaimers: &'static [Reclaimer],
    ) -> Result<Self, i32> {
        use std::os::unix::fs::DirBuilderExt;
        for sub in ["live", "tags", "tunables"] {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(run_dir.join(sub))
                .map_err(|e| io_errno(&e))?;
        }
        for dir in [run_dir.to_path_buf()]
            .into_iter()
            .chain(["live", "tags", "tunables"].map(|s| run_dir.join(s)))
        {
            private_dir(&dir)?;
        }
        Ok(Registry {
            run: run_dir.to_path_buf(),
            tunables: tunable_dir.to_path_buf(),
            reclaimers,
        })
    }

    /// The registry the environment names: `FLUXOR_RUN_DIR` (default
    /// `/run/fluxor`), `FLUXOR_TUNABLE_DIR` (default `/proc/sys`), the
    /// standard reclaimers.
    pub fn from_env() -> Result<Self, i32> {
        let run = std::env::var("FLUXOR_RUN_DIR")
            .ok()
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| DEFAULT_RUN_DIR.into());
        let tun = std::env::var("FLUXOR_TUNABLE_DIR")
            .ok()
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| DEFAULT_TUNABLE_DIR.into());
        Self::open(Path::new(&run), Path::new(&tun), RECLAIMERS)
    }

    /// The run directory.
    pub fn run_dir(&self) -> &Path {
        &self.run
    }

    fn lock(&self) -> Result<RegistryGuard, i32> {
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.run.join("registry.lock"))
            .map_err(|e| io_errno(&e))?;
        flock(&f, libc::LOCK_EX)?;
        Ok(RegistryGuard { _lock: f })
    }

    fn live_path(&self, tag: &str) -> PathBuf {
        self.run.join("live").join(tag)
    }

    fn tag_path(&self, tag: &str) -> PathBuf {
        self.run.join("tags").join(tag)
    }

    fn read_tag(&self, tag: &str) -> TagRecord {
        fs::read_to_string(self.tag_path(tag))
            .map(|t| TagRecord::parse(&t))
            .unwrap_or_default()
    }

    fn write_tag(&self, tag: &str, r: &TagRecord) -> Result<(), i32> {
        write_whole(&self.tag_path(tag), &r.render())
    }

    fn tunable_records(&self) -> Vec<(PathBuf, TunableRecord)> {
        let Ok(dir) = fs::read_dir(self.run.join("tunables")) else {
            return Vec::new();
        };
        let mut v = Vec::new();
        for e in dir.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "tmp") {
                continue;
            }
            if let Some(r) = fs::read_to_string(&p)
                .ok()
                .and_then(|t| TunableRecord::parse(&t))
            {
                v.push((p, r));
            }
        }
        v
    }

    fn tunable_path(&self, key: &str) -> PathBuf {
        self.run.join("tunables").join(hex(key.as_bytes()))
    }

    /// Every tag the registry knows of: by liveness file, by record, or as
    /// a tunable's dependent.
    fn known_tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = Vec::new();
        for sub in ["live", "tags"] {
            if let Ok(dir) = fs::read_dir(self.run.join(sub)) {
                for e in dir.flatten() {
                    if let Some(n) = e.file_name().to_str() {
                        if valid_tag(n) && !tags.iter().any(|t| t == n) {
                            tags.push(n.to_string());
                        }
                    }
                }
            }
        }
        for (_, r) in self.tunable_records() {
            for d in r.deps {
                if !tags.contains(&d) {
                    tags.push(d);
                }
            }
        }
        tags.sort();
        tags
    }

    /// Whether `tag`'s liveness lock is held, by any process (this one
    /// included). A free lock is taken and returned, so the tag stays dead
    /// while it is reclaimed.
    fn probe(&self, tag: &str) -> Probe {
        let f = match OpenOptions::new().read(true).open(self.live_path(tag)) {
            Ok(f) => f,
            Err(_) => return Probe::Dead(None),
        };
        match flock(&f, libc::LOCK_EX | libc::LOCK_NB) {
            Ok(()) => Probe::Dead(Some(f)),
            Err(_) => Probe::Live,
        }
    }

    /// Whether `tag` is live now.
    pub fn is_live(&self, tag: &str) -> bool {
        matches!(self.probe(tag), Probe::Live)
    }

    /// Go live as `tag`: take its liveness lock (`EBUSY` while another
    /// runtime holds it, or while a live tag shares its stem), then collect
    /// every dead tag and this tag's own leftovers.
    pub fn go_live(&self, tag: &str) -> Result<Live, i32> {
        if !valid_tag(tag) {
            return Err(errno::EINVAL);
        }
        let _g = self.lock()?;
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.live_path(tag))
            .map_err(|e| io_errno(&e))?;
        flock(&f, libc::LOCK_EX | libc::LOCK_NB)?;
        for other in self.known_tags() {
            if other != tag && stem(&other) == stem(tag) && self.is_live(&other) {
                log::warn!("[instance] tag {tag} shares its name stem with live tag {other}");
                return Err(errno::EBUSY);
            }
        }
        let _ = f.set_len(0);
        let _ = (&f).write_all(format!("pid {}\n", std::process::id()).as_bytes());
        self.collect_locked(Some(tag));
        Ok(Live {
            reg: self.clone(),
            tag: tag.to_string(),
            live: Some(f),
        })
    }

    /// Collect every dead tag now. Returns the tags fully reclaimed.
    pub fn collect(&self) -> Result<Vec<String>, i32> {
        let _g = self.lock()?;
        Ok(self.collect_locked(None))
    }

    /// Collect dead tags; `own` is the tag going live, whose leftovers are
    /// reclaimed by alias only and whose liveness stays.
    fn collect_locked(&self, own: Option<&str>) -> Vec<String> {
        let mut live: Vec<String> = Vec::new();
        // (tag, its liveness lock held for the reclaim, whether it is ours)
        let mut targets: Vec<(String, Option<File>, bool)> = Vec::new();
        for t in self.known_tags() {
            if Some(t.as_str()) == own {
                live.push(t.clone());
                targets.push((t, None, true));
                continue;
            }
            match self.probe(&t) {
                Probe::Live => live.push(t),
                Probe::Dead(f) => targets.push((t, f, false)),
            }
        }
        let mut failed: Vec<String> = Vec::new();
        let live_claims: Vec<Claim> = live
            .iter()
            .filter(|l| Some(l.as_str()) != own)
            .flat_map(|l| self.read_tag(l).claims)
            .collect();
        for phase in [ReclaimPhase::First, ReclaimPhase::Rest] {
            for (t, _, mine) in &targets {
                let rec = self.read_tag(t);
                let claims: Vec<Claim> = rec
                    .claims
                    .iter()
                    .filter(|c| {
                        !live_claims
                            .iter()
                            .any(|l| l.kind == c.kind && l.overlaps(c))
                    })
                    .copied()
                    .collect();
                let ctx = ReclaimCtx {
                    tag: t,
                    by_name: !mine && !live.iter().any(|l| stem(l) == stem(t)),
                    table: rec.table,
                    priority: rec.priority,
                    claims: &claims,
                };
                for r in self.reclaimers.iter().filter(|r| r.phase == phase) {
                    if let Err(e) = (r.run)(&ctx) {
                        log::warn!("[instance] reclaim {} of tag {t} failed ({e}); retried at the next collection", r.kind);
                        if !failed.contains(t) {
                            failed.push(t.clone());
                        }
                    }
                }
            }
        }
        // Tunables: drop every dependent reclaimed above (a dead tag, or our
        // own previous life), and restore a tunable once none is left.
        let gone = |d: &String| targets.iter().any(|(t, _, _)| t == d) && !failed.contains(d);
        for (path, mut rec) in self.tunable_records() {
            let before = rec.deps.len();
            rec.deps.retain(|d| !gone(d));
            if rec.deps.is_empty() {
                self.restore(&rec);
                let _ = fs::remove_file(&path);
            } else if rec.deps.len() != before {
                let _ = write_whole(&path, &rec.render());
            }
        }
        let mut done = Vec::new();
        for (t, f, mine) in targets {
            if failed.contains(&t) {
                continue;
            }
            let _ = fs::remove_file(self.tag_path(&t));
            if !mine {
                let _ = fs::remove_file(self.live_path(&t));
                log::info!("[instance] collected dead tag {t}");
            }
            drop(f);
            done.push(t);
        }
        done
    }

    /// Put a tunable back to the value it had before any instance changed
    /// it — only if it differs now, so a value the host already had (its
    /// forwarding on) is never written over.
    fn restore(&self, rec: &TunableRecord) {
        if !valid_tunable_key(&rec.key) {
            return;
        }
        let path = self.tunables.join(&rec.key);
        let now = fs::read_to_string(&path).unwrap_or_default();
        if now.trim() == rec.prior.trim() {
            return;
        }
        match fs::write(&path, rec.prior.as_bytes()) {
            Ok(()) => log::info!("[instance] restored {} to {}", rec.key, rec.prior.trim()),
            Err(e) => log::warn!("[instance] cannot restore {}: {e}", rec.key),
        }
    }
}

enum Probe {
    Live,
    Dead(Option<File>),
}

/// A live instance: holds its tag's liveness lock until it is released or
/// the process ends.
pub struct Live {
    reg: Registry,
    tag: String,
    live: Option<File>,
}

impl Live {
    /// The tag.
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// The registry it lives in.
    pub fn registry(&self) -> &Registry {
        &self.reg
    }

    /// Replace this tag's claims of `kind` with `claims`, atomically: all
    /// recorded, or (on an overlap with any claim of another live tag, of
    /// any kind) none.
    pub fn set_claims(&self, kind: ClaimKind, claims: &[Claim]) -> Result<(), ClaimError> {
        if claims.iter().any(|c| c.kind != kind || !c.valid()) {
            return Err(ClaimError::Errno(errno::EINVAL));
        }
        let _g = self.reg.lock().map_err(ClaimError::Errno)?;
        for other in self.reg.known_tags() {
            if other == self.tag || !self.reg.is_live(&other) {
                continue;
            }
            for theirs in self.reg.read_tag(&other).claims {
                if let Some(ours) = claims.iter().find(|c| c.overlaps(&theirs)) {
                    return Err(ClaimError::Conflict(Conflict {
                        tag: other,
                        theirs,
                        ours: *ours,
                    }));
                }
            }
        }
        let mut rec = self.reg.read_tag(&self.tag);
        rec.claims.retain(|c| c.kind != kind);
        rec.claims.extend_from_slice(claims);
        self.reg
            .write_tag(&self.tag, &rec)
            .map_err(ClaimError::Errno)
    }

    /// This tag's recorded claims of `kind`.
    pub fn claims(&self, kind: ClaimKind) -> Vec<Claim> {
        self.reg
            .read_tag(&self.tag)
            .claims
            .into_iter()
            .filter(|c| c.kind == kind)
            .collect()
    }

    /// This instance's routing table id: the one recorded, or the lowest
    /// id from [`TABLE_ID_FIRST`] no other tag records.
    pub fn table_id(&self) -> Result<u32, i32> {
        self.allocate(
            |r| r.table,
            |r, v| r.table = Some(v),
            TABLE_ID_FIRST,
            u32::MAX,
        )
    }

    /// This instance's rule priority: the one recorded, or the lowest from
    /// [`RULE_PRIORITY_FIRST`] below [`RULE_PRIORITY_MAIN`] no other tag
    /// records (`ENOSPC` when none is left).
    pub fn rule_priority(&self) -> Result<u32, i32> {
        self.allocate(
            |r| r.priority,
            |r, v| r.priority = Some(v),
            RULE_PRIORITY_FIRST,
            RULE_PRIORITY_MAIN,
        )
    }

    fn allocate(
        &self,
        get: fn(&TagRecord) -> Option<u32>,
        set: fn(&mut TagRecord, u32),
        first: u32,
        end: u32,
    ) -> Result<u32, i32> {
        let _g = self.reg.lock()?;
        let mut rec = self.reg.read_tag(&self.tag);
        if let Some(v) = get(&rec) {
            return Ok(v);
        }
        // Dead tags not yet collected keep theirs: their objects may still
        // be on the host under that number.
        let taken: Vec<u32> = self
            .reg
            .known_tags()
            .iter()
            .filter(|t| **t != self.tag)
            .filter_map(|t| get(&self.reg.read_tag(t)))
            .collect();
        let v = (first..end)
            .find(|v| !taken.contains(v))
            .ok_or(errno::ENOSPC)?;
        set(&mut rec, v);
        self.reg.write_tag(&self.tag, &rec)?;
        Ok(v)
    }

    /// Set the host tunable `key` (a path under the tunable root, such as
    /// `net/ipv4/ip_forward`) to `value` and record this tag as depending on
    /// it. The first dependent records the value it had before.
    pub fn depend_tunable(&self, key: &str, value: &str) -> Result<(), i32> {
        if !valid_tunable_key(key) {
            return Err(errno::EINVAL);
        }
        let _g = self.reg.lock()?;
        let path = self.reg.tunable_path(key);
        let file = self.reg.tunables.join(key);
        let mut rec = match fs::read_to_string(&path)
            .ok()
            .and_then(|t| TunableRecord::parse(&t))
        {
            Some(r) => r,
            None => TunableRecord {
                key: key.to_string(),
                prior: fs::read_to_string(&file).map_err(|e| io_errno(&e))?,
                deps: Vec::new(),
            },
        };
        if !rec.deps.contains(&self.tag) {
            rec.deps.push(self.tag.clone());
        }
        // Recorded before the change: a crash after it still leaves the
        // record the restore needs.
        write_whole(&path, &rec.render())?;
        let now = fs::read_to_string(&file).unwrap_or_default();
        if now.trim() != value.trim() {
            fs::write(&file, value.as_bytes()).map_err(|e| io_errno(&e))?;
        }
        Ok(())
    }

    /// The value tunable `key` had before any instance changed it, if an
    /// instance has (`None`: no instance depends on it).
    pub fn tunable_prior(&self, key: &str) -> Option<String> {
        if !valid_tunable_key(key) {
            return None;
        }
        let _g = self.reg.lock().ok()?;
        fs::read_to_string(self.reg.tunable_path(key))
            .ok()
            .and_then(|t| TunableRecord::parse(&t))
            .map(|r| r.prior)
    }

    /// Stop depending on tunable `key`; restore it when no live dependent
    /// is left.
    pub fn release_tunable(&self, key: &str) -> Result<(), i32> {
        if !valid_tunable_key(key) {
            return Err(errno::EINVAL);
        }
        let _g = self.reg.lock()?;
        let path = self.reg.tunable_path(key);
        let Some(mut rec) = fs::read_to_string(&path)
            .ok()
            .and_then(|t| TunableRecord::parse(&t))
        else {
            return Ok(());
        };
        rec.deps.retain(|d| *d != self.tag);
        let any_live = rec.deps.iter().any(|d| self.reg.is_live(d));
        if !any_live {
            self.reg.restore(&rec);
            let _ = fs::remove_file(&path);
            return Ok(());
        }
        write_whole(&path, &rec.render())
    }

    /// Leave: drop the liveness lock, then collect every dead tag, this one
    /// included.
    pub fn release(mut self) {
        let Ok(_g) = self.reg.lock() else {
            return;
        };
        drop(self.live.take());
        self.reg.collect_locked(None);
    }
}

// ---- this process's instance ------------------------------------------------

struct Global {
    tag: Option<String>,
    explicit: bool,
    state_lock: Option<File>,
    live: Option<Live>,
    pid: u32,
    atexit: bool,
}

static GLOBAL: Mutex<Global> = Mutex::new(Global {
    tag: None,
    explicit: false,
    state_lock: None,
    live: None,
    pid: 0,
    atexit: false,
});

/// The tag the environment names, and whether it was named explicitly.
fn env_tag() -> Result<(String, bool), String> {
    if let Some(t) = std::env::var("FLUXOR_INSTANCE")
        .ok()
        .filter(|t| !t.is_empty())
    {
        if !valid_tag(&t) {
            return Err(format!(
                "FLUXOR_INSTANCE={t:?} is not a tag ([a-z0-9], 1..={TAG_MAX} characters)"
            ));
        }
        return Ok((t, true));
    }
    if let Some(d) = state_dir() {
        let canon = fs::canonicalize(&d).unwrap_or(d);
        return Ok((state_dir_tag(&canon), true));
    }
    Ok((ephemeral_tag(std::process::id()), false))
}

/// `FLUXOR_STATE_DIR`, when set.
pub fn state_dir() -> Option<PathBuf> {
    std::env::var("FLUXOR_STATE_DIR")
        .ok()
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
}

/// The global for this process: a forked child is not the instance, and
/// starts from nothing (its copies of the parent's descriptors close; the
/// parent's locks stay the parent's).
fn global() -> std::sync::MutexGuard<'static, Global> {
    let mut g = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
    let pid = std::process::id();
    if g.pid != pid {
        *g = Global {
            tag: None,
            explicit: false,
            state_lock: None,
            live: None,
            pid,
            atexit: g.atexit,
        };
    }
    g
}

fn ensure_tag(g: &mut Global) -> Result<String, String> {
    if let Some(t) = &g.tag {
        return Ok(t.clone());
    }
    let (t, explicit) = env_tag()?;
    g.tag = Some(t.clone());
    g.explicit = explicit;
    Ok(t)
}

extern "C" fn at_exit() {
    shutdown();
}

fn go_live(g: &mut Global) -> Result<(), i32> {
    if g.live.is_some() {
        return Ok(());
    }
    let tag = ensure_tag(g).map_err(|_| errno::EINVAL)?;
    let live = Registry::from_env()?.go_live(&tag)?;
    log::info!(
        "[instance] live as {tag} in {}",
        live.registry().run_dir().display()
    );
    g.live = Some(live);
    if !g.atexit {
        g.atexit = true;
        // SAFETY: registers a plain extern "C" fn with no captured state.
        unsafe {
            libc::atexit(at_exit);
        }
    }
    Ok(())
}

/// Runtime start: read `FLUXOR_STATE_DIR` and `FLUXOR_INSTANCE`, lock the
/// state directory, and — when the instance is named (either input set) —
/// go live now, so a second runtime for the same instance stops here.
/// A runtime named by neither goes live on first need ([`live_tag`]).
///
/// `Err` is fatal: the state directory or the tag is another runtime's, or
/// an input is malformed. A registry that cannot be opened (an
/// unprivileged runtime) is not: the runtime runs, and whatever needs the
/// registry is refused when asked.
pub fn init_from_env() -> Result<(), String> {
    let mut g = global();
    if let Some(dir) = state_dir() {
        fs::create_dir_all(&dir).map_err(|e| format!("FLUXOR_STATE_DIR {}: {e}", dir.display()))?;
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("instance.lock"))
            .map_err(|e| format!("FLUXOR_STATE_DIR {}: {e}", dir.display()))?;
        flock(&f, libc::LOCK_EX | libc::LOCK_NB).map_err(|_| {
            format!(
                "FLUXOR_STATE_DIR {} is in use by another runtime",
                dir.display()
            )
        })?;
        g.state_lock = Some(f);
    }
    let tag = ensure_tag(&mut g)?;
    if g.explicit {
        match go_live(&mut g) {
            Ok(()) => {}
            Err(e) if e == errno::EBUSY => {
                return Err(format!(
                    "instance {tag} is live in another runtime on this host (or shares its name stem with one)"
                ))
            }
            Err(e) => log::warn!(
                "[instance] {tag}: host registry unavailable ({e}); host networking will be refused"
            ),
        }
    }
    Ok(())
}

/// This runtime's tag (computed from the environment on first use).
pub fn tag() -> String {
    let mut g = global();
    ensure_tag(&mut g).unwrap_or_else(|_| ephemeral_tag(std::process::id()))
}

/// This runtime's tag, live in the host registry — going live first if it
/// is not yet. `Err(errno)` when it cannot be: an object created under a
/// tag that is not live would be collected by the next instance to start.
pub fn live_tag() -> Result<String, i32> {
    let mut g = global();
    go_live(&mut g)?;
    Ok(g.live.as_ref().map(|l| l.tag.clone()).unwrap_or_default())
}

/// Run `f` with this runtime's live instance (going live first).
pub fn with_live<R>(f: impl FnOnce(&Live) -> R) -> Result<R, i32> {
    let mut g = global();
    go_live(&mut g)?;
    match g.live.as_ref() {
        Some(l) => Ok(f(l)),
        None => Err(errno::ERROR),
    }
}

/// Runtime exit: leave the registry (collecting dead tags, this one
/// included) and release the state directory. Idempotent; a forked child
/// does nothing.
pub fn shutdown() {
    let mut g = global();
    if let Some(l) = g.live.take() {
        l.release();
    }
    g.state_lock = None;
}

/// What [`reclaim_from_env`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reclaimed {
    /// Every dead tag the registry knew of was collected; these were.
    All(Vec<String>),
    /// The named tag was dead and is collected (with every other dead tag,
    /// listed).
    Tag(String, Vec<String>),
    /// The named tag is live: another runtime holds it, so nothing of it
    /// was touched. Other dead tags were still collected.
    Live(String, Vec<String>),
    /// The named tag is dead but an object kind could not be reclaimed
    /// (logged); the next collection retries it.
    Pending(String, Vec<String>),
}

/// The reclaim command (a service manager's post-stop hook): collect every
/// dead tag in the host registry the environment names, without going
/// live. With the instance named (`FLUXOR_INSTANCE`, else the
/// `FLUXOR_STATE_DIR` digest), say whether that tag was reclaimed or is
/// still live. `Err` is a malformed tag (`EINVAL`) or a registry that
/// cannot be opened or locked.
pub fn reclaim_from_env() -> Result<Reclaimed, i32> {
    let named = match env_tag() {
        Ok((t, true)) => Some(t),
        Ok((_, false)) => None,
        Err(e) => {
            log::error!("[instance] {e}");
            return Err(errno::EINVAL);
        }
    };
    let reg = Registry::from_env()?;
    let collected = reg.collect()?;
    Ok(match named {
        None => Reclaimed::All(collected),
        Some(t) if reg.is_live(&t) => Reclaimed::Live(t, collected),
        Some(t) if reg.known_tags().contains(&t) => Reclaimed::Pending(t, collected),
        Some(t) => Reclaimed::Tag(t, collected),
    })
}
