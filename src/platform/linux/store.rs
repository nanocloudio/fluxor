//! Local versioned watchable store — the in-runtime backing for the
//! `storage.object` (0x14) and `storage.namespace` (0x13) contracts on Linux.
//!
//! A versioned watchable KV is not a bespoke contract: it decomposes into the
//! standard storage surfaces (`storage.object` CAS and LIST,
//! `storage.namespace` LIST/SUBSCRIBE, and a `RevisionMonotone` fence). This
//! module implements that decomposition: a keyed byte store with a monotone
//! revision clock, per-key revision (the CAS token / etag), prefix
//! enumeration, and a bounded change history that drives SUBSCRIBE with
//! resume-from-revision.
//!
//! The store is single-writer: the runtime hosts the control plane's modules
//! in one process and the provider serialises calls, so there is no
//! multi-process WAL and no `flock`. Durability is a plain append log
//! (`store.log`), replayed at open, whose torn tail is cut off before the
//! first append. The log is also the seam a test harness seeds through
//! between runs.

use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Log record op discriminants.
const OP_PUT: u8 = 1;
const OP_DELETE: u8 = 2;

/// One change delivered to a watcher / retained in history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub revision: u64,
    pub key: String,
    pub kind: ChangeKind,
    /// Present for Added/Modified; absent for Deleted.
    pub value: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
}

/// CAS failure — carries the current per-key revision for a retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CasConflict {
    pub current: u64,
}

/// A write outcome.
#[derive(Debug)]
pub enum WriteError {
    Conflict(CasConflict),
    Io(std::io::Error),
}

impl WriteError {
    pub fn conflict(&self) -> Option<CasConflict> {
        match self {
            WriteError::Conflict(c) => Some(*c),
            _ => None,
        }
    }
}

/// A subscriber's drain outcome: buffered changes, or `Lost` when the ring
/// overflowed / the resume point preceded retained history — the consumer must
/// relist and re-subscribe from `resume_revision`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Drain {
    Events(Vec<Change>),
    Lost { resume_revision: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WatchId(pub u64);

struct Entry {
    value: Vec<u8>,
    revision: u64,
}

struct Watch {
    prefix: String,
    ring: VecDeque<Change>,
    lost: bool,
    lost_resume: u64,
    cap: usize,
}

/// A single-writer append log — the store's durability and seed seam. No
/// `flock`: the store has one writer at a time (the runtime, or a harness
/// between runs).
/// Record: `[rev:u64 LE][op:u8][key_len:u16 LE][val_len:u32 LE][key][val]`.
struct Log {
    file: File,
    /// Length of the valid records; the next append lands here.
    len: u64,
}

/// One replayed log record: `(rev, op, key, value)`.
type LogRecord = (u64, u8, String, Vec<u8>);

impl Log {
    fn open(path: &Path) -> std::io::Result<(Self, Vec<LogRecord>)> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // Recovery open: existing records are replayed, then appended to.
            .truncate(false)
            .open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        let (records, valid) = parse_log(&data)?;
        // A crash mid-append leaves a partial record. Appending behind it
        // would let the next replay read the partial header's lengths across
        // the new record, so the tail is cut off first.
        if valid < data.len() {
            file.set_len(valid as u64)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::Start(valid as u64))?;
        Ok((
            Log {
                file,
                len: valid as u64,
            },
            records,
        ))
    }

    fn append(&mut self, rev: u64, op: u8, key: &str, value: &[u8]) -> std::io::Result<()> {
        let too_long = || std::io::Error::from(std::io::ErrorKind::InvalidInput);
        let key_len = u16::try_from(key.len()).map_err(|_| too_long())?;
        let value_len = u32::try_from(value.len()).map_err(|_| too_long())?;
        let mut buf = Vec::with_capacity(LOG_HEADER_LEN + key.len() + value.len());
        buf.extend_from_slice(&rev.to_le_bytes());
        buf.push(op);
        buf.extend_from_slice(&key_len.to_le_bytes());
        buf.extend_from_slice(&value_len.to_le_bytes());
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(value);
        let written = self
            .file
            .write_all(&buf)
            .and_then(|()| self.file.flush())
            .and_then(|()| self.file.sync_data());
        match written {
            Ok(()) => {
                self.len += buf.len() as u64;
                Ok(())
            }
            Err(e) => {
                // A refused append must not leave a partial record that the
                // next append would land behind.
                let _ = self.file.set_len(self.len);
                let _ = self.file.seek(SeekFrom::Start(self.len));
                Err(e)
            }
        }
    }
}

/// `[rev:u64][op:u8][key_len:u16][val_len:u32]`.
const LOG_HEADER_LEN: usize = 15;

/// Make `dir`'s entries durable.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Parse an append log into `(rev, op, key, value)` records and the length
/// they occupy. A partial record at the end (a crash mid-append leaves at most
/// one) ends the parse and is excluded from that length. A complete record that
/// cannot be applied — an unknown op, a key that is not UTF-8, or the empty key
/// (which no `PUT` creates and no listing can return) — is not a torn write and
/// is refused as corruption rather than silently dropped with everything
/// behind it.
fn parse_log(data: &[u8]) -> std::io::Result<(Vec<LogRecord>, usize)> {
    let corrupt =
        |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string());
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + LOG_HEADER_LEN <= data.len() {
        let rev = u64::from_le_bytes(data[p..p + 8].try_into().unwrap());
        let op = data[p + 8];
        let kl = u16::from_le_bytes(data[p + 9..p + 11].try_into().unwrap()) as usize;
        let vl = u32::from_le_bytes(data[p + 11..p + 15].try_into().unwrap()) as usize;
        let end = p + LOG_HEADER_LEN + kl + vl;
        if end > data.len() {
            break;
        }
        if op != OP_PUT && op != OP_DELETE {
            return Err(corrupt("store.log: unknown record op"));
        }
        if kl == 0 {
            return Err(corrupt("store.log: record key is empty"));
        }
        let key = std::str::from_utf8(&data[p + LOG_HEADER_LEN..p + LOG_HEADER_LEN + kl])
            .map_err(|_| corrupt("store.log: record key is not UTF-8"))?
            .to_string();
        let value = data[p + LOG_HEADER_LEN + kl..end].to_vec();
        out.push((rev, op, key, value));
        p = end;
    }
    Ok((out, p))
}

/// An in-memory versioned keyspace with an optional durable append log.
/// Single-writer per instance (the provider serialises calls) — no interior
/// mutability, no locks.
pub struct Store {
    entries: BTreeMap<String, Entry>,
    revision: u64,
    history: VecDeque<Change>,
    history_cap: usize,
    watches: BTreeMap<WatchId, Watch>,
    next_watch: u64,
    default_ring_cap: usize,
    log: Option<Log>,
}

/// What a mutating write may be made conditional on.
///
/// A real three-way choice, and not `Option<u64>`, because that shape cannot
/// hold one: it would have to encode "must not exist" as `Some(0)`, which is
/// indistinguishable from "must currently be at revision 0". A
/// compare-and-swap against a key at revision 0 and a create-only write would
/// then be the same request, and one of them always answered wrongly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Precondition {
    /// Apply unconditionally.
    Any,
    /// Apply only if the key does not exist.
    Absent,
    /// Apply only if the key exists at exactly this revision.
    Revision(u64),
}

impl Precondition {
    /// Evaluate against the key's current revision, `None` when absent.
    fn check(self, existing: Option<u64>) -> Result<(), CasConflict> {
        match self {
            Self::Any => Ok(()),
            Self::Absent => match existing {
                None => Ok(()),
                Some(current) => Err(CasConflict { current }),
            },
            Self::Revision(expect) => match existing {
                Some(current) if current == expect => Ok(()),
                other => Err(CasConflict {
                    current: other.unwrap_or(0),
                }),
            },
        }
    }
}

impl Store {
    pub fn new() -> Self {
        Self::with_limits(4096, 1024)
    }

    /// `history_cap` bounds watch-replay reach; `ring_cap` bounds a single
    /// subscriber's in-flight backlog before it is declared `Lost`.
    pub fn with_limits(history_cap: usize, ring_cap: usize) -> Self {
        Store {
            entries: BTreeMap::new(),
            revision: 0,
            history: VecDeque::new(),
            history_cap: history_cap.max(1),
            watches: BTreeMap::new(),
            next_watch: 1,
            default_ring_cap: ring_cap.max(1),
            log: None,
        }
    }

    /// Open a durable store, replaying its append log at `dir/store.log` to
    /// rebuild the map, the revision clock, and the tail of the change history.
    pub fn open(dir: &Path, history_cap: usize, ring_cap: usize) -> std::io::Result<Self> {
        let created = !dir.exists();
        std::fs::create_dir_all(dir)?;
        let mut store = Self::with_limits(history_cap, ring_cap);
        let (log, records) = Log::open(&dir.join("store.log"))?;
        // A write is acknowledged `LocalDurable` once its record is synced,
        // which holds across a power cut only if the log's directory entry
        // (and the directory's own, when it was just made) is durable too.
        sync_dir(dir)?;
        if created {
            match dir.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => sync_dir(parent)?,
                _ => sync_dir(Path::new("."))?,
            }
        }
        for (rev, op, key, value) in records {
            store.replay(rev, op, key, value);
        }
        store.log = Some(log);
        Ok(store)
    }

    /// Apply a record already durable in the log (replay at open). Sets the
    /// revision clock to max (the revision came off the log) and routes through
    /// `record`, so history retains it for future-subscriber replay.
    fn replay(&mut self, rev: u64, op: u8, key: String, value: Vec<u8>) {
        self.revision = self.revision.max(rev);
        let change = if op == OP_DELETE {
            self.entries.remove(&key);
            Change {
                revision: rev,
                key,
                kind: ChangeKind::Deleted,
                value: None,
            }
        } else {
            let existed = self.entries.contains_key(&key);
            self.entries.insert(
                key.clone(),
                Entry {
                    value: value.clone(),
                    revision: rev,
                },
            );
            Change {
                revision: rev,
                key,
                kind: if existed {
                    ChangeKind::Modified
                } else {
                    ChangeKind::Added
                },
                value: Some(value),
            }
        };
        self.record(change);
    }

    /// Whether writes to this store reach a durable log before they are
    /// acknowledged.
    ///
    /// This is what decides the fence a write reports. A store with no log
    /// is a store whose acknowledgement survives nothing, and saying so is
    /// the whole point of the fence surface — a caller that must record a
    /// revocation needs to be refused here rather than told it committed.
    #[must_use]
    pub fn is_durable(&self) -> bool {
        self.log.is_some()
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Current value + its per-key revision (the CAS token / etag source).
    pub fn get(&self, key: &str) -> Option<(&[u8], u64)> {
        self.entries
            .get(key)
            .map(|e| (e.value.as_slice(), e.revision))
    }

    fn apply_local(&mut self, rev: u64, op: u8, key: &str, value: Vec<u8>) {
        self.revision = rev;
        let change = if op == OP_DELETE {
            self.entries.remove(key);
            Change {
                revision: rev,
                key: key.to_string(),
                kind: ChangeKind::Deleted,
                value: None,
            }
        } else {
            let existed = self.entries.contains_key(key);
            self.entries.insert(
                key.to_string(),
                Entry {
                    value: value.clone(),
                    revision: rev,
                },
            );
            Change {
                revision: rev,
                key: key.to_string(),
                kind: if existed {
                    ChangeKind::Modified
                } else {
                    ChangeKind::Added
                },
                value: Some(value),
            }
        };
        self.record(change);
    }

    /// Insert or update under `precondition`. Returns the new store revision.
    /// Appends to the durable log (if any) before applying.
    pub fn put(
        &mut self,
        key: &str,
        value: Vec<u8>,
        precondition: Precondition,
    ) -> Result<u64, WriteError> {
        let existing_rev = self.entries.get(key).map(|e| e.revision);
        if let Err(conflict) = precondition.check(existing_rev) {
            return Err(WriteError::Conflict(conflict));
        }
        let rev = self.revision + 1;
        if let Some(log) = self.log.as_mut() {
            log.append(rev, OP_PUT, key, &value)
                .map_err(WriteError::Io)?;
        }
        self.apply_local(rev, OP_PUT, key, value);
        Ok(rev)
    }

    /// Remove a key under `precondition`. Returns the new revision, or
    /// `Ok(None)` for an unconditional delete of an absent key (no-op).
    pub fn delete(
        &mut self,
        key: &str,
        precondition: Precondition,
    ) -> Result<Option<u64>, WriteError> {
        let existing_rev = self.entries.get(key).map(|e| e.revision);
        if let Err(conflict) = precondition.check(existing_rev) {
            return Err(WriteError::Conflict(conflict));
        }
        if existing_rev.is_none() {
            return Ok(None);
        }
        let rev = self.revision + 1;
        if let Some(log) = self.log.as_mut() {
            log.append(rev, OP_DELETE, key, &[])
                .map_err(WriteError::Io)?;
        }
        self.apply_local(rev, OP_DELETE, key, Vec::new());
        Ok(Some(rev))
    }

    /// Key-ordered `(key, revision)` snapshot under `prefix`, plus the store
    /// revision the snapshot is consistent at — the list→watch watermark a
    /// subsequent `subscribe(prefix, watermark)` resumes from with no gap.
    pub fn list(&self, prefix: &str) -> (Vec<(String, u64)>, u64) {
        let items = self
            .entries
            .range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, e)| (k.clone(), e.revision))
            .collect();
        (items, self.revision)
    }

    /// Key-ordered `(key, size, revision)` under the byte `prefix`, starting
    /// strictly after `after` when given. A lazy walk of the map, so a page
    /// costs the entries it returns rather than the whole prefix.
    pub fn scan<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a str>,
    ) -> impl Iterator<Item = (&'a str, u64, u64)> + 'a {
        use std::ops::Bound;
        // The longest UTF-8 head of the prefix is a lower bound on every key
        // that starts with the prefix; a prefix that ends inside a code point
        // still matches the keys that complete it.
        let head = match core::str::from_utf8(prefix) {
            Ok(s) => s,
            Err(e) => core::str::from_utf8(&prefix[..e.valid_up_to()]).unwrap_or(""),
        };
        let lower = match after {
            Some(a) if a >= head => Bound::Excluded(a),
            _ => Bound::Included(head),
        };
        self.entries
            .range::<str, _>((lower, Bound::Unbounded))
            .skip_while(move |(k, _)| k.as_bytes() < prefix)
            .take_while(move |(k, _)| k.as_bytes().starts_with(prefix))
            .map(|(k, e)| (k.as_str(), e.value.len() as u64, e.revision))
    }

    /// Open a watch over `prefix`, delivering every retained change with
    /// `revision > since_revision`, then live changes. If `since_revision`
    /// precedes retained history, the watch opens already `Lost`.
    pub fn subscribe(&mut self, prefix: &str, since_revision: u64) -> WatchId {
        let id = WatchId(self.next_watch);
        self.next_watch += 1;
        let mut watch = Watch {
            prefix: prefix.to_string(),
            ring: VecDeque::new(),
            lost: false,
            lost_resume: 0,
            cap: self.default_ring_cap,
        };
        let oldest = self.history.front().map(|c| c.revision);
        let reachable = match oldest {
            None => since_revision <= self.revision,
            Some(o) => since_revision.saturating_add(1) >= o,
        };
        if !reachable {
            watch.lost = true;
            watch.lost_resume = self.revision;
        } else {
            for change in self.history.iter() {
                if change.revision > since_revision && change.key.starts_with(prefix) {
                    Self::push(&mut watch, change.clone(), self.revision);
                }
            }
        }
        self.watches.insert(id, watch);
        id
    }

    /// Drain up to `max` buffered changes (0 = all). `Lost` is sticky until
    /// drained once, then the watch resumes buffering from `resume_revision`.
    pub fn drain(&mut self, id: WatchId, max: usize) -> Option<Drain> {
        let watch = self.watches.get_mut(&id)?;
        if watch.lost {
            watch.lost = false;
            let resume = watch.lost_resume;
            watch.ring.clear();
            return Some(Drain::Lost {
                resume_revision: resume,
            });
        }
        let take = if max == 0 {
            watch.ring.len()
        } else {
            max.min(watch.ring.len())
        };
        let events = watch.ring.drain(..take).collect();
        Some(Drain::Events(events))
    }

    /// Redeliver events a `drain` took but the caller could not fit, in order.
    pub fn requeue_front(&mut self, id: WatchId, events: Vec<Change>) {
        if let Some(watch) = self.watches.get_mut(&id) {
            for ev in events.into_iter().rev() {
                watch.ring.push_front(ev);
            }
        }
    }

    pub fn unsubscribe(&mut self, id: WatchId) -> bool {
        self.watches.remove(&id).is_some()
    }

    pub fn watch_count(&self) -> usize {
        self.watches.len()
    }

    fn record(&mut self, change: Change) {
        let rev = self.revision;
        for watch in self.watches.values_mut() {
            if change.key.starts_with(&watch.prefix) {
                Self::push(watch, change.clone(), rev);
            }
        }
        self.history.push_back(change);
        while self.history.len() > self.history_cap {
            self.history.pop_front();
        }
    }

    fn push(watch: &mut Watch, change: Change, store_revision: u64) {
        if watch.lost {
            return;
        }
        if watch.ring.len() >= watch.cap {
            watch.lost = true;
            watch.lost_resume = store_revision;
            watch.ring.clear();
            return;
        }
        watch.ring.push_back(change);
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Contract wiring — back `storage.object` (0x14) and `storage.namespace` (0x13)
// on Linux with this store. Env-gated:
// when `FLUXOR_STORE_DIR` is set, the two providers route their ops here; else
// they keep their filesystem/HTTP behaviour. Provider dispatch is single
// scheduler thread (see kernel::module::provider), so the `static mut` singletons need
// no locking.
// ===========================================================================

use crate::abi::contracts::mesh::capability as cap;
use crate::abi::contracts::storage::handle::STORAGE_KEY_MAX;
use crate::abi::contracts::storage::object::precondition as obj_precondition;
use crate::abi::contracts::storage::{namespace as ns_op, object as obj_op};
use crate::abi::fence::{Fence, QUERY_OP, WIRE_MAX_LEN};
use crate::kernel::ipc::channel::channel_write;
use crate::kernel::ipc::fd::{slot_of, tag_fd, FD_TAG_STORAGE_NAMESPACE, FD_TAG_STORAGE_OBJECT};
use crate::kernel::sys::errno;

/// `CONTENT_TYPES` byte for `NamespaceChange` (`contracts/src/lib.rs`). A
/// watcher routes on this to tell a store change from anything else sharing
/// its sink, so it must be the vocabulary's byte and not a private one.
const CT_NAMESPACE_CHANGE: u8 = 0x23;
/// mesh Event header size (see `modules/foundation/mesh/mesh_types.rs`).
const EVENT_HEADER_SIZE: usize = 32;

/// A fixed 16-byte source id for this store's fences/events (ObjectId).
const STORE_SOURCE: [u8; 16] = *b"fluxor-cp-store\0";

/// Device id reported in a `LocalDurable` fence.
///
/// One store, one device: this identifies the durability domain a write
/// reached, so a caller comparing two `LocalDurable` fences can tell
/// whether they survived the same failure. There is exactly one control-
/// plane store per node, so it is a constant rather than a real device
/// number — a fabricated per-write value would make two fences from the
/// same store look like two independent domains.
const STORE_DEVICE_ID: u64 = 1;

/// One subscription per watched prefix per module. Sized as bare metal's
/// (`bcm2712/store.rs` `MAX_SUBS`): a whole control plane asks for ~95, and a
/// graph that runs here must run there.
const STORE_MAX_SUBS: usize = 256;
const STORE_MAX_READS: usize = 32;

#[derive(Clone, Copy)]
struct Sub {
    in_use: bool,
    watch: WatchId,
    sink_chan: u32,
    sequence: u32,
}
const SUB_EMPTY: Sub = Sub {
    in_use: false,
    watch: WatchId(0),
    sink_chan: 0,
    sequence: 0,
};

/// A GET-opened read slot: a value snapshot the caller drains via RANGE_GET.
struct ReadSlot {
    in_use: bool,
    value: Vec<u8>,
    revision: u64,
    /// The grant the slot was opened under, which it dies with.
    grant: Option<usize>,
}
const READ_EMPTY: ReadSlot = ReadSlot {
    in_use: false,
    value: Vec::new(),
    revision: 0,
    grant: None,
};

/// Grants presented to a guarded store at once. A presentation past it is
/// refused `ENOMEM` until one is closed; none is evicted, because an evicted
/// grant is a caller whose next operation silently starts failing.
const STORE_MAX_GRANTS: usize = 64;

/// Grant handles are store slots from here up, apart from read slots.
const GRANT_SLOT_BASE: usize = 0x1_0000;

/// A capability grant a caller presented: its scope, rights and expiry, and
/// the module occupancy it belongs to.
struct Grant {
    scope: Vec<u8>,
    permissions: u16,
    not_after: u32,
    owner: usize,
    owner_generation: u32,
}

/// The mesh roots a guarded store verifies chains against, from
/// `FLUXOR_MESH_ROOTS`. Empty: the store is unguarded.
static mut MESH_ROOTS: Vec<[u8; 32]> = Vec::new();
static mut GRANTS: Vec<Option<Grant>> = Vec::new();

struct KernelCrypto;

impl cap::CapCrypto for KernelCrypto {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut h = crate::kernel::security::crypto::sha256::Sha256::new();
        h.update(data);
        h.finalize()
    }
    fn ed25519_verify(&self, key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        crate::kernel::security::crypto::ed25519::verify(key, msg, sig)
    }
}

static mut LINUX_STORE: Option<Store> = None;
static mut LINUX_SUBS: [Sub; STORE_MAX_SUBS] = [SUB_EMPTY; STORE_MAX_SUBS];
static mut LINUX_READS: [ReadSlot; STORE_MAX_READS] = [READ_EMPTY; STORE_MAX_READS];

/// What `store_init_from_env` found: three outcomes, not two, because "no
/// store was asked for" and "a store was asked for and could not be opened"
/// must not look alike.
///
/// The first is the ordinary case for every graph that does not use the
/// control-plane store. The second leaves EVERY store-backed module in the
/// graph talking to a store that is not there, and such a module does not
/// fail: it simply never produces anything, which from outside is
/// indistinguishable from a module with nothing to do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoreInit {
    /// `FLUXOR_STORE_DIR` is unset: this node has no control-plane store, by
    /// configuration. Not an error and not worth a line.
    NotConfigured,
    /// Opened, or already open.
    Opened,
    /// `FLUXOR_STORE_DIR` was set and the store could not be opened. The
    /// caller MUST report this — see the type docs.
    Failed,
}

/// Initialise the control-plane store from `FLUXOR_STORE_DIR`, if set. Called
/// once at provider registration.
///
/// # Safety
/// Single-threaded startup only; initialises the `static mut` store singleton
/// before any provider dispatch.
pub unsafe fn store_init_from_env() -> StoreInit {
    if (*core::ptr::addr_of!(LINUX_STORE)).is_some() {
        return StoreInit::Opened;
    }
    let Ok(dir) = std::env::var("FLUXOR_STORE_DIR") else {
        return StoreInit::NotConfigured;
    };
    // Roots that do not parse fail the store rather than open it unguarded:
    // a deployment that asked for authority must not quietly run without it.
    match parse_roots(std::env::var("FLUXOR_MESH_ROOTS").ok().as_deref()) {
        Some(roots) => MESH_ROOTS = roots,
        None => return StoreInit::Failed,
    }
    match Store::open(std::path::Path::new(&dir), 65536, 4096) {
        Ok(s) => {
            LINUX_STORE = Some(s);
            StoreInit::Opened
        }
        Err(_) => StoreInit::Failed,
    }
}

/// `FLUXOR_MESH_ROOTS`: up to `cap::MAX_ROOTS` comma-separated 64-hex-digit
/// Ed25519 keys; absent is no roots. `None` when it does not parse.
fn parse_roots(v: Option<&str>) -> Option<Vec<[u8; 32]>> {
    let Some(v) = v.map(str::trim).filter(|v| !v.is_empty()) else {
        return Some(Vec::new());
    };
    let mut roots = Vec::new();
    for item in v.split(',') {
        let item = item.trim();
        if item.len() != 64 || roots.len() == cap::MAX_ROOTS {
            return None;
        }
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = u8::from_str_radix(item.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        roots.push(k);
    }
    Some(roots)
}

/// Install the mesh roots directly — the harness's way in, where the store
/// is opened without the environment.
/// # Safety
/// Single-threaded platform dispatch only.
pub unsafe fn set_mesh_roots(roots: &[[u8; 32]]) {
    MESH_ROOTS = roots.to_vec();
    (*core::ptr::addr_of_mut!(GRANTS)).clear();
}

unsafe fn guarded() -> bool {
    !(*core::ptr::addr_of!(MESH_ROOTS)).is_empty()
}

fn grant_handle(i: usize) -> i32 {
    tag_fd(FD_TAG_STORAGE_OBJECT, (GRANT_SLOT_BASE + i) as i32)
}

/// The grant `handle` names, if it is a live one the caller owns.
unsafe fn grant_of(handle: i32) -> Option<usize> {
    if handle < 0 {
        return None;
    }
    let slot = slot_of(handle) as usize;
    let i = slot.checked_sub(GRANT_SLOT_BASE)?;
    let g = (&*core::ptr::addr_of!(GRANTS)).get(i)?.as_ref()?;
    let owner = crate::kernel::exec::scheduler::caller_module_index();
    let generation = crate::kernel::exec::scheduler::module_slot_generation(owner);
    (g.owner == owner && g.owner_generation == generation).then_some(i)
}

fn trusted_clock() -> Option<cap::Clock> {
    cap::Clock::from_trusted(&crate::kernel::module::syscalls::trusted_unix_record())
}

/// Whether grant `i` is still inside its window by the trusted clock.
unsafe fn grant_live(i: usize) -> bool {
    let Some(Some(g)) = (&*core::ptr::addr_of!(GRANTS)).get(i) else {
        return false;
    };
    match trusted_clock() {
        Some(c) => c.now.saturating_add(c.uncertainty) <= g.not_after as u64,
        None => false,
    }
}

/// `PRESENT`: verify a chain over a scope and mint a grant. `arg` is the
/// caller's request buffer: its first byte receives the refusal.
unsafe fn present(arg: *mut u8, a: &[u8]) -> i32 {
    if !guarded() {
        return errno::ENOSYS;
    }
    let Some(req) = obj_op::grant::parse_present(a) else {
        return errno::EINVAL;
    };
    let Some(object) = obj_op::grant::scope_object(&KernelCrypto, req.scope) else {
        return errno::EINVAL;
    };
    let roots = &*core::ptr::addr_of!(MESH_ROOTS);
    // Verified for the scope only; each op checks its own permission.
    let verdict =
        cap::verify(&KernelCrypto, req.chain, roots, trusted_clock(), None).and_then(|g| {
            if g.object_id == object {
                Ok(g)
            } else {
                Err(cap::Refusal::ObjectMismatch)
            }
        });
    let g = match verdict {
        Ok(g) => g,
        Err(r) => {
            *arg.add(obj_op::grant::REFUSAL_AT) = r as u8;
            return errno::EACCES;
        }
    };
    let grants = &mut *core::ptr::addr_of_mut!(GRANTS);
    let i = match grants.iter().position(Option::is_none) {
        Some(i) => i,
        None if grants.len() < STORE_MAX_GRANTS => {
            grants.push(None);
            grants.len() - 1
        }
        None => return errno::ENOMEM,
    };
    let owner = crate::kernel::exec::scheduler::caller_module_index();
    grants[i] = Some(Grant {
        scope: req.scope.to_vec(),
        permissions: g.permissions,
        not_after: g.not_after,
        owner,
        owner_generation: crate::kernel::exec::scheduler::module_slot_generation(owner),
    });
    grant_handle(i)
}

/// The key (or `LIST` prefix) an op addresses, for its scope check.
fn op_key(opcode: u32, a: &[u8]) -> Option<&[u8]> {
    match opcode {
        obj_op::GET => Some(a),
        obj_op::LIST => obj_op::list::parse_request(a).map(|r| r.prefix),
        obj_op::PUT | obj_op::HEAD | obj_op::DELETE | obj_op::PUT_STREAMED_OPEN => {
            let n = u16::from_le_bytes([*a.first()?, *a.get(1)?]) as usize;
            a.get(2..2 + n)
        }
        _ => None,
    }
}

/// Admit an op on a guarded store: `Ok(Some(grant))` for an op run under a
/// grant, `Ok(None)` for one no grant covers (a read handle's own ops,
/// `CLOSE`), `Err(errno)` to refuse it.
unsafe fn admit(handle: i32, opcode: u32, a: &[u8]) -> Result<Option<usize>, i32> {
    let Some(access) = obj_op::grant::access_of(opcode) else {
        return Ok(None);
    };
    if opcode == obj_op::RANGE_GET {
        // A read handle carries the grant it was opened under.
        let idx = slot_of(handle) as usize;
        let reads = &*core::ptr::addr_of!(LINUX_READS);
        return match reads.get(idx).and_then(|r| r.grant) {
            Some(g) if grant_live(g) => Ok(None),
            _ => Err(errno::EACCES),
        };
    }
    let i = grant_of(handle).ok_or(errno::EACCES)?;
    if !grant_live(i) {
        return Err(errno::EACCES);
    }
    let Some(Some(g)) = (&*core::ptr::addr_of!(GRANTS)).get(i) else {
        return Err(errno::EACCES);
    };
    let need = access.permission();
    if g.permissions & need != need {
        return Err(errno::EACCES);
    }
    let key = op_key(opcode, a).ok_or(errno::EINVAL)?;
    if !obj_op::grant::in_scope(&g.scope, key) {
        return Err(errno::EACCES);
    }
    Ok(Some(i))
}

/// True iff the control-plane store backs the storage contracts on this node.
/// # Safety
/// Single-threaded platform dispatch only (reads the `static mut`
/// store singleton without synchronization).
pub unsafe fn store_active() -> bool {
    (*core::ptr::addr_of!(LINUX_STORE)).is_some()
}

unsafe fn store_ref() -> Option<&'static mut Store> {
    (*core::ptr::addr_of_mut!(LINUX_STORE)).as_mut()
}

// ---- etag ⇄ revision bridge (the object contract's 32-byte etag carries the
// store's u64 per-key revision in its first 8 bytes; the rest is zero). ----

fn etag_from_rev(rev: u64) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[..8].copy_from_slice(&rev.to_le_bytes());
    e
}
/// Read a `[precondition: u8][etag_len: u8][etag]` block, advancing `p`.
fn read_precondition(a: &[u8], p: &mut usize) -> Option<Precondition> {
    let &kind = a.get(*p)?;
    let &etag_len = a.get(*p + 1)?;
    *p += 2;
    let etag_len = etag_len as usize;
    if a.len() < *p + etag_len {
        return None;
    }
    let etag = &a[*p..*p + etag_len];
    *p += etag_len;
    match kind {
        obj_precondition::ANY => Some(Precondition::Any),
        obj_precondition::ABSENT => Some(Precondition::Absent),
        obj_precondition::ETAG if etag_len >= 8 => Some(Precondition::Revision(
            u64::from_le_bytes(etag[..8].try_into().unwrap()),
        )),
        // `ETAG` without a whole revision in its etag, and a kind this store
        // does not know, are malformed requests, not weaker conditions:
        // answering either as unconditional would turn a guard the caller
        // asked for into no guard at all.
        _ => None,
    }
}

/// A `[len: u16 LE][bytes]` field at the head of `a` as UTF-8, with the offset
/// just past it. `None` when the field runs past `a` or is not UTF-8: a
/// request is refused, never indexed past its end.
fn str_field(a: &[u8]) -> Option<(&str, usize)> {
    let len = get_u16(a, 0)? as usize;
    let bytes = a.get(2..2 + len)?;
    Some((core::str::from_utf8(bytes).ok()?, 2 + len))
}

/// A key a `PUT` may create. Empty is the relist sentinel's key on the change
/// stream and the "end of listing" cursor on `LIST`; longer than `STORAGE_KEY_MAX`
/// cannot be carried by either listing.
fn writable_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= STORAGE_KEY_MAX
}

/// The `LIST` cursor as a key of this store under `prefix`, or `EINVAL`. A
/// cursor is the last key a page returned, so anything else was not issued
/// here.
fn list_cursor<'a>(cursor: &'a [u8], prefix: &[u8]) -> Result<Option<&'a str>, i32> {
    if cursor.is_empty() {
        return Ok(None);
    }
    match core::str::from_utf8(cursor) {
        Ok(c) if cursor.starts_with(prefix) => Ok(Some(c)),
        _ => Err(errno::EINVAL),
    }
}

fn get_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
}
fn get_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}
fn get_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// The `[fence_out_ptr:u64][fence_out_cap:u16]` pair at `off`, or `None` —
/// the op answers `EINVAL` before acting — when it is cut short, null, or
/// smaller than `WIRE_MAX_LEN`.
fn fence_out(a: &[u8], off: usize) -> Option<(u64, u16)> {
    let ptr = get_u64(a, off)?;
    let cap = get_u16(a, off + 8)?;
    (ptr != 0 && cap as usize >= WIRE_MAX_LEN).then_some((ptr, cap))
}

/// Write an encoded fence into a caller `[fence_out_ptr:u64][fence_out_cap:u16]`.
/// A null pointer receives nothing.
unsafe fn write_fence(fence: Fence, ptr: u64, cap: u16) {
    if ptr == 0 {
        return;
    }
    let buf = core::slice::from_raw_parts_mut(ptr as *mut u8, cap as usize);
    let _ = fence.encode(buf);
}

// ---- namespace.change event push ----

/// Encode a `Change` as `[EventHeader(32)][rev:u64][kind:u8][key_len:u16][val_len:u32][key][val]`.
fn encode_event(seq: u32, ch: &Change) -> Vec<u8> {
    let key = ch.key.as_bytes();
    let val = ch.value.as_deref().unwrap_or(&[]);
    let payload_len = 8 + 1 + 2 + 4 + key.len() + val.len();
    let mut buf = vec![0u8; EVENT_HEADER_SIZE + payload_len];
    // mesh Event header (all LE): source[16], sequence[4], timestamp[8], ct[1], flags[1], length[2]
    buf[0..16].copy_from_slice(&STORE_SOURCE);
    buf[16..20].copy_from_slice(&seq.to_le_bytes());
    // timestamp left 0 (advisory)
    buf[28] = CT_NAMESPACE_CHANGE;
    buf[29] = 0;
    buf[30..32].copy_from_slice(&(payload_len as u16).to_le_bytes());
    let mut p = EVENT_HEADER_SIZE;
    buf[p..p + 8].copy_from_slice(&ch.revision.to_le_bytes());
    p += 8;
    buf[p] = match ch.kind {
        ChangeKind::Added => 0,
        ChangeKind::Modified => 1,
        ChangeKind::Deleted => 2,
    };
    p += 1;
    buf[p..p + 2].copy_from_slice(&(key.len() as u16).to_le_bytes());
    p += 2;
    buf[p..p + 4].copy_from_slice(&(val.len() as u32).to_le_bytes());
    p += 4;
    buf[p..p + key.len()].copy_from_slice(key);
    p += key.len();
    buf[p..p + val.len()].copy_from_slice(val);
    buf
}

/// Drain every active subscription and push its changes onto its sink channel.
/// Synchronous — the pump point (there is no async provider callback). On a
/// full channel (`EAGAIN`) the undelivered tail is requeued for the next pump.
/// Takes the store by `&mut` (never re-acquires the singleton) so it never
/// aliases the caller's borrow.
unsafe fn pump_subscriptions(store: &mut Store) {
    let subs = &mut *core::ptr::addr_of_mut!(LINUX_SUBS);
    for s in subs.iter_mut() {
        if !s.in_use {
            continue;
        }
        loop {
            match store.drain(s.watch, 32) {
                Some(Drain::Events(evs)) => {
                    if evs.is_empty() {
                        break;
                    }
                    let mut requeue: Vec<Change> = Vec::new();
                    let mut blocked = false;
                    for (i, ch) in evs.iter().enumerate() {
                        if blocked {
                            requeue.push(ch.clone());
                            continue;
                        }
                        let bytes = encode_event(s.sequence, ch);
                        let rc = channel_write(s.sink_chan as i32, bytes.as_ptr(), bytes.len());
                        if rc == errno::EAGAIN {
                            blocked = true;
                            requeue.push(ch.clone());
                            // remaining handled by the `blocked` branch above
                            let _ = i;
                        } else {
                            s.sequence = s.sequence.wrapping_add(1);
                        }
                    }
                    if !requeue.is_empty() {
                        store.requeue_front(s.watch, requeue);
                        break; // channel full — try again on the next pump
                    }
                }
                Some(Drain::Lost { .. }) => {
                    // A LOST is delivered as a distinguished namespace.change with
                    // kind=Deleted and an empty key (the "relist" sentinel).
                    let sentinel = Change {
                        revision: store.revision(),
                        key: String::new(),
                        kind: ChangeKind::Deleted,
                        value: None,
                    };
                    let bytes = encode_event(s.sequence, &sentinel);
                    let _ = channel_write(s.sink_chan as i32, bytes.as_ptr(), bytes.len());
                    s.sequence = s.sequence.wrapping_add(1);
                    break;
                }
                None => break,
            }
        }
    }
}

// ---- storage.object dispatch (routed here when the store is active) ----

/// Handle a `storage.object` op against the control-plane store. Returns the
/// contract's i32 (bytes/handle/0 or negative errno).
/// # Safety
/// Single-threaded platform dispatch only: touches `static mut` provider
/// state without synchronization. `arg` must be null or valid for reads
/// and writes of `arg_len` bytes for the duration of the call.
pub unsafe fn dispatch_object(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let Some(store) = store_ref() else {
        return errno::ENOSYS;
    };

    // Per-handle fence introspection for a GET-opened read slot.
    if opcode == QUERY_OP {
        if arg.is_null() || arg_len < WIRE_MAX_LEN {
            return errno::EINVAL;
        }
        let idx = slot_of(handle) as usize;
        let reads = &*core::ptr::addr_of!(LINUX_READS);
        if idx >= STORE_MAX_READS || !reads[idx].in_use {
            return errno::ENOSYS;
        }
        let buf = core::slice::from_raw_parts_mut(arg, arg_len);
        return match (Fence::ViewConsistent {
            source: STORE_SOURCE,
            revision: reads[idx].revision,
        })
        .encode(buf)
        {
            Some(n) => n as i32,
            None => errno::EINVAL,
        };
    }

    let a = if arg.is_null() {
        &[][..]
    } else {
        core::slice::from_raw_parts(arg, arg_len)
    };

    if opcode == obj_op::PRESENT {
        if arg.is_null() {
            return errno::EINVAL;
        }
        return present(arg, a);
    }
    if opcode == obj_op::CLOSE && handle >= 0 && slot_of(handle) as usize >= GRANT_SLOT_BASE {
        let Some(i) = grant_of(handle) else {
            return errno::EACCES;
        };
        (&mut *core::ptr::addr_of_mut!(GRANTS))[i] = None;
        // Read handles opened under it die with it.
        for r in (*core::ptr::addr_of_mut!(LINUX_READS)).iter_mut() {
            if r.grant == Some(i) {
                *r = READ_EMPTY;
            }
        }
        return 0;
    }
    let grant = if guarded() {
        match admit(handle, opcode, a) {
            Ok(g) => g,
            Err(e) => return e,
        }
    } else {
        None
    };

    match opcode {
        obj_op::PUT => {
            // [key_len:u16][key][ct_len:u8][ct][body_ptr:u64][body_len:u64]
            // [precondition:u8][etag_len:u8][etag]
            // [fence_out_ptr:u64][fence_out_cap:u16]
            let Some((key, mut p)) = str_field(a) else {
                return errno::EINVAL;
            };
            if !writable_key(key) {
                return errno::EINVAL;
            }
            let key = key.to_string();
            let Some(&ctl) = a.get(p) else {
                return errno::EINVAL;
            };
            p += 1 + ctl as usize; // skip content-type
            let Some(body_ptr) = get_u64(a, p) else {
                return errno::EINVAL;
            };
            let Some(body_len) = get_u64(a, p + 8) else {
                return errno::EINVAL;
            };
            p += 16;
            let Some(precondition) = read_precondition(a, &mut p) else {
                return errno::EINVAL;
            };
            let absent = precondition == Precondition::Absent;
            let Some((fence_ptr, fence_cap)) = fence_out(a, p) else {
                return errno::EINVAL;
            };

            let body = if body_len == 0 {
                Vec::new()
            } else {
                core::slice::from_raw_parts(body_ptr as *const u8, body_len as usize).to_vec()
            };
            match store.put(&key, body, precondition) {
                Ok(rev) => {
                    // `Log::append` does write_all → flush → sync_data, and
                    // it runs BEFORE `apply_local`, so a returned `Ok` means
                    // the record is on disk. That is `LocalDurable`, and
                    // it is what this reports.
                    //
                    // `RevisionMonotone` would be a statement about ORDERING
                    // — revisions go up — and says nothing about surviving a
                    // restart. A caller applying a durability policy would
                    // have to refuse a write that was in fact durable.
                    // Under-reporting is the safe direction to be wrong in,
                    // but it is still wrong, and it makes the fence unusable
                    // for the decision it exists for.
                    //
                    // With no log there is no durability to claim, and
                    // `RevisionMonotone` remains exactly right: the ordering
                    // holds, nothing else does.
                    let achieved = if store.is_durable() {
                        Fence::LocalDurable {
                            device_id: STORE_DEVICE_ID,
                        }
                    } else {
                        Fence::RevisionMonotone {
                            source: STORE_SOURCE,
                            revision: rev,
                        }
                    };
                    write_fence(achieved, fence_ptr, fence_cap);
                    pump_subscriptions(store);
                    0
                }
                // Two answers, because they ask the caller to do two
                // different things. `EEXIST`: somebody else created this key,
                // so a create-only caller has LOST. `EAGAIN`: the key moved
                // under a compare-and-swap, so re-read and retry.
                Err(WriteError::Conflict(_)) if absent => errno::EEXIST,
                Err(WriteError::Conflict(_)) => errno::EAGAIN,
                Err(WriteError::Io(_)) => errno::ERROR,
            }
        }
        obj_op::GET => {
            // arg = UTF-8 key → open a read slot, return tagged handle.
            let Ok(key) = core::str::from_utf8(a) else {
                return errno::EINVAL;
            };
            let Some((val, rev)) = store.get(key) else {
                return errno::ENXIO;
            };
            let val = val.to_vec();
            let reads = &mut *core::ptr::addr_of_mut!(LINUX_READS);
            let Some(idx) = reads.iter().position(|r| !r.in_use) else {
                return errno::ENOMEM;
            };
            reads[idx] = ReadSlot {
                in_use: true,
                value: val,
                revision: rev,
                grant,
            };
            tag_fd(FD_TAG_STORAGE_OBJECT, idx as i32)
        }
        obj_op::RANGE_GET => {
            // [offset:u64][length:u32][out_ptr:u64]
            let idx = slot_of(handle) as usize;
            let reads = &*core::ptr::addr_of!(LINUX_READS);
            if idx >= STORE_MAX_READS || !reads[idx].in_use {
                return errno::ENOSYS;
            }
            let Some(offset) = get_u64(a, 0).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            let Some(length) = get_u32(a, 8).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            let Some(out_ptr) = get_u64(a, 12) else {
                return errno::EINVAL;
            };
            let val = &reads[idx].value;
            if offset >= val.len() {
                return 0;
            }
            let end = (offset + length).min(val.len());
            let n = end - offset;
            core::ptr::copy_nonoverlapping(val[offset..end].as_ptr(), out_ptr as *mut u8, n);
            n as i32
        }
        obj_op::HEAD => {
            // [key_len:u16][key][out_ptr:u64][out_cap:u32][fence_out_ptr:u64][fence_out_cap:u16]
            let Some((key, p)) = str_field(a) else {
                return errno::EINVAL;
            };
            let out_ptr = get_u64(a, p).unwrap_or(0);
            let out_cap = get_u32(a, p + 8).unwrap_or(0) as usize;
            let Some((fptr, fcap)) = fence_out(a, p + 12) else {
                return errno::EINVAL;
            };
            let Some((val, rev)) = store.get(key) else {
                return errno::ENXIO;
            };
            // HEAD record: [size:u64][mtime:u64][content_type_len:u8][ct][etag_len:u8][etag]
            let etag = etag_from_rev(rev);
            let mut rec = Vec::new();
            rec.extend_from_slice(&(val.len() as u64).to_le_bytes());
            rec.extend_from_slice(&0u64.to_le_bytes());
            rec.push(0); // content_type_len
            rec.push(32); // etag_len
            rec.extend_from_slice(&etag);
            // The count returned is the count written: a record that does not
            // fit is refused, not reported as delivered.
            if out_ptr == 0 {
                return errno::EINVAL;
            }
            if rec.len() > out_cap {
                return errno::ENOMEM;
            }
            core::ptr::copy_nonoverlapping(rec.as_ptr(), out_ptr as *mut u8, rec.len());
            write_fence(
                Fence::ViewConsistent {
                    source: STORE_SOURCE,
                    revision: store.revision(),
                },
                fptr,
                fcap,
            );
            rec.len() as i32
        }
        obj_op::DELETE => {
            // [key_len:u16][key][precondition:u8][etag_len:u8][etag]
            //   [fence_out_ptr:u64][fence_out_cap:u16]
            let Some((key, mut p)) = str_field(a) else {
                return errno::EINVAL;
            };
            let key = key.to_string();
            let Some(precondition) = read_precondition(a, &mut p) else {
                return errno::EINVAL;
            };
            let Some((fptr, fcap)) = fence_out(a, p) else {
                return errno::EINVAL;
            };
            match store.delete(&key, precondition) {
                Ok(opt) => {
                    let rev = opt.unwrap_or_else(|| store.revision());
                    // As `PUT`: the delete is logged and fsynced before it
                    // applies, so a logged store achieved `LocalDurable`.
                    // A delete that reports weaker than it achieved is the
                    // worse half of the pair — a caller removing a grant
                    // needs to know the removal survives.
                    let achieved = if store.is_durable() {
                        Fence::LocalDurable {
                            device_id: STORE_DEVICE_ID,
                        }
                    } else {
                        Fence::RevisionMonotone {
                            source: STORE_SOURCE,
                            revision: rev,
                        }
                    };
                    write_fence(achieved, fptr, fcap);
                    pump_subscriptions(store);
                    0
                }
                Err(WriteError::Conflict(_)) => errno::EAGAIN,
                Err(WriteError::Io(_)) => errno::ERROR,
            }
        }
        obj_op::LIST => {
            let Some(req) = obj_op::list::parse_request(a) else {
                return errno::EINVAL;
            };
            let after = match list_cursor(req.cursor, req.prefix) {
                Ok(after) => after,
                Err(e) => return e,
            };
            let out = core::slice::from_raw_parts_mut(req.out_ptr as *mut u8, req.out_cap as usize);
            let mut page = obj_op::list::PageWriter::new(out, req.max_keys);
            let mut last: Option<&str> = None;
            let mut more = false;
            for (key, size, rev) in store.scan(req.prefix, after) {
                if page.is_full() {
                    more = true;
                    break;
                }
                if key.len() > STORAGE_KEY_MAX {
                    return errno::EOVERFLOW;
                }
                // mtime 0, as HEAD reports it: the store keeps no clock.
                if !page.push(key.as_bytes(), size, 0, &etag_from_rev(rev)) {
                    more = true;
                    break;
                }
                last = Some(key);
            }
            let cursor = match last {
                Some(k) if more => k.as_bytes(),
                // A page that cannot hold the next entry made no progress.
                None if more => return errno::ENOMEM,
                _ => &[],
            };
            let Some(n) = page.finish(cursor) else {
                return errno::ENOMEM;
            };
            write_fence(
                Fence::ViewConsistent {
                    source: STORE_SOURCE,
                    revision: store.revision(),
                },
                req.fence_out_ptr,
                req.fence_out_cap,
            );
            n as i32
        }
        obj_op::CLOSE => {
            let idx = slot_of(handle) as usize;
            let reads = &mut *core::ptr::addr_of_mut!(LINUX_READS);
            if idx < STORE_MAX_READS {
                reads[idx] = READ_EMPTY;
            }
            0
        }
        _ => errno::ENOSYS,
    }
}

// ---- storage.namespace dispatch (routed here when the store is active) ----

/// Handle a `storage.namespace` op against the control-plane store.
///
/// # Safety
/// Single-threaded platform dispatch only: touches `static mut` provider
/// state without synchronization. `arg` must be null or valid for reads
/// and writes of `arg_len` bytes for the duration of the call.
pub unsafe fn dispatch_namespace(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    // A guarded store is reached through `storage.object` under a grant. The
    // namespace surface has no way to carry one, so it answers nothing that
    // would list or change what a scope hides.
    if guarded() {
        return errno::EACCES;
    }
    let Some(store) = store_ref() else {
        return errno::ENOSYS;
    };

    // Per-handle fence introspection (LOOKUP/SUBSCRIBE handle): a view fence at
    // the current store revision.
    if opcode == QUERY_OP {
        if arg.is_null() || arg_len < WIRE_MAX_LEN {
            return errno::EINVAL;
        }
        let buf = core::slice::from_raw_parts_mut(arg, arg_len);
        return match (Fence::ViewConsistent {
            source: STORE_SOURCE,
            revision: store.revision(),
        })
        .encode(buf)
        {
            Some(n) => n as i32,
            None => errno::EINVAL,
        };
    }

    let a = if arg.is_null() {
        &[][..]
    } else {
        core::slice::from_raw_parts(arg, arg_len)
    };

    match opcode {
        // Versioned store: live subscriptions and windowed change reads
        // are implemented; mutation (BIND/RENAME/DELETE) flows through the
        // object surface, not this one (namespace.rs::caps).
        ns_op::CAPS => (ns_op::caps::SUBSCRIBE | ns_op::caps::CHANGES) as i32,
        ns_op::LIST => {
            let Some(req) = ns_op::list::parse_request(a) else {
                return errno::EINVAL;
            };
            let after = match list_cursor(req.cursor, req.prefix) {
                Ok(after) => after,
                Err(e) => return e,
            };
            let out = core::slice::from_raw_parts_mut(req.out_ptr as *mut u8, req.out_cap as usize);
            let mut page = ns_op::list::PageWriter::new(out);
            let mut last: Option<&str> = None;
            let mut more = false;
            for (key, _, _) in store.scan(req.prefix, after) {
                if key.len() > STORAGE_KEY_MAX {
                    return errno::EOVERFLOW;
                }
                if !page.push(key.as_bytes(), ns_op::KIND_OBJECT) {
                    more = true;
                    break;
                }
                last = Some(key);
            }
            let cursor = match last {
                Some(k) if more => k.as_bytes(),
                // A page that cannot hold the next entry made no progress.
                None if more => return errno::ENOMEM,
                _ => &[],
            };
            let Some(n) = page.finish(cursor) else {
                return errno::ENOMEM;
            };
            write_fence(
                Fence::ViewConsistent {
                    source: STORE_SOURCE,
                    revision: store.revision(),
                },
                req.fence_out_ptr,
                req.fence_out_cap,
            );
            n as i32
        }
        ns_op::SUBSCRIBE => {
            // [prefix_len:u16][prefix][sink_chan:u32][flags:u8]
            let Some((prefix, p)) = str_field(a) else {
                return errno::EINVAL;
            };
            let prefix = prefix.to_string();
            let Some(sink_chan) = get_u32(a, p) else {
                return errno::EINVAL;
            };
            let flags = *a.get(p + 4).unwrap_or(&0);
            let include_initial = flags & 0x01 != 0;

            // Live subscription from the current watermark; if the caller wants the
            // initial listing, synthesise Added events for every current entry so
            // the stream is a complete list→watch with no separate GET.
            let watermark = store.revision();
            let watch = if include_initial {
                let (items, _) = store.list(&prefix);
                let wid = store.subscribe(&prefix, watermark);
                // Feed the current state as history-shaped Added events by
                // pushing them straight to the channel ahead of the live ring.
                let subs = &mut *core::ptr::addr_of_mut!(LINUX_SUBS);
                let Some(idx) = subs.iter().position(|s| !s.in_use) else {
                    store.unsubscribe(wid);
                    return errno::ENOMEM;
                };
                subs[idx] = Sub {
                    in_use: true,
                    watch: wid,
                    sink_chan,
                    sequence: 0,
                };
                for (k, rev) in items {
                    let val = store.get(&k).map(|(v, _)| v.to_vec());
                    let ch = Change {
                        revision: rev,
                        key: k,
                        kind: ChangeKind::Added,
                        value: val,
                    };
                    let bytes = encode_event(subs[idx].sequence, &ch);
                    if channel_write(sink_chan as i32, bytes.as_ptr(), bytes.len()) <= 0 {
                        // The snapshot could not be delivered whole. Release
                        // the slot and refuse: a watcher established on a
                        // partial list believes it has seen the full state,
                        // and nothing later in the stream corrects it.
                        subs[idx].in_use = false;
                        store.unsubscribe(wid);
                        return errno::EAGAIN;
                    }
                    subs[idx].sequence = subs[idx].sequence.wrapping_add(1);
                }
                return tag_fd(FD_TAG_STORAGE_NAMESPACE, idx as i32);
            } else {
                store.subscribe(&prefix, watermark)
            };
            let subs = &mut *core::ptr::addr_of_mut!(LINUX_SUBS);
            let Some(idx) = subs.iter().position(|s| !s.in_use) else {
                store.unsubscribe(watch);
                return errno::ENOMEM;
            };
            subs[idx] = Sub {
                in_use: true,
                watch,
                sink_chan,
                sequence: 0,
            };
            tag_fd(FD_TAG_STORAGE_NAMESPACE, idx as i32)
        }
        ns_op::CHANGES => {
            // [prefix_len:u16][prefix][since:u64][out_buf:u64][out_cap:u32]
            // [fence_out_ptr:u64][fence_out_cap:u16]
            let Some((prefix, mut p)) = str_field(a) else {
                return errno::EINVAL;
            };
            let prefix = prefix.to_string();
            let since = get_u64(a, p).unwrap_or(0);
            p += 8;
            let out_buf = get_u64(a, p).unwrap_or(0);
            let out_cap = get_u32(a, p + 8).unwrap_or(0) as usize;
            let fptr = get_u64(a, p + 12).unwrap_or(0);
            let fcap = get_u16(a, p + 20).unwrap_or(0);

            // Event record: [rev:u64][kind:u8][key_len:u16][val_len:u32][key][val].
            fn push_event(body: &mut Vec<u8>, rev: u64, kind: u8, key: &str, val: &[u8]) {
                body.extend_from_slice(&rev.to_le_bytes());
                body.push(kind);
                body.extend_from_slice(&(key.len() as u16).to_le_bytes());
                body.extend_from_slice(&(val.len() as u32).to_le_bytes());
                body.extend_from_slice(key.as_bytes());
                body.extend_from_slice(val);
            }

            let mut body = Vec::new();
            let mut count: u32 = 0;
            let mut status: u8 = 0;
            let mut fence_rev = since;

            if since == 0 {
                // Full snapshot: every current entry as Added at its revision.
                let (items, wm) = store.list(&prefix);
                fence_rev = wm;
                for (k, rev) in items {
                    let val = store.get(&k).map(|(v, _)| v.to_vec()).unwrap_or_default();
                    push_event(&mut body, rev, 0, &k, &val);
                    count += 1;
                    if rev > fence_rev {
                        fence_rev = rev;
                    }
                }
            } else {
                // Incremental: resume the change history from `since`.
                let wid = store.subscribe(&prefix, since);
                match store.drain(wid, 0) {
                    Some(Drain::Events(evs)) => {
                        for ch in evs {
                            let kind = match ch.kind {
                                ChangeKind::Added => 0u8,
                                ChangeKind::Modified => 1u8,
                                ChangeKind::Deleted => 2u8,
                            };
                            let val = ch.value.unwrap_or_default();
                            push_event(&mut body, ch.revision, kind, &ch.key, &val);
                            count += 1;
                            if ch.revision > fence_rev {
                                fence_rev = ch.revision;
                            }
                        }
                    }
                    Some(Drain::Lost { resume_revision }) => {
                        status = 1;
                        fence_rev = resume_revision;
                    }
                    None => {}
                }
                store.unsubscribe(wid);
            }

            let mut buf = Vec::with_capacity(5 + body.len());
            buf.push(status);
            buf.extend_from_slice(&count.to_le_bytes());
            buf.extend_from_slice(&body);
            if out_buf != 0 && buf.len() <= out_cap {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), out_buf as *mut u8, buf.len());
            } else if out_buf != 0 {
                return errno::ENOMEM;
            }
            write_fence(
                Fence::ViewConsistent {
                    source: STORE_SOURCE,
                    revision: fence_rev,
                },
                fptr,
                fcap,
            );
            buf.len() as i32
        }
        // The store enumerates and watches; it has no per-path handle.
        ns_op::LOOKUP | ns_op::STAT => errno::ENOSYS,
        ns_op::CLOSE => {
            let idx = slot_of(handle) as usize;
            let subs = &mut *core::ptr::addr_of_mut!(LINUX_SUBS);
            if idx < STORE_MAX_SUBS && subs[idx].in_use {
                store.unsubscribe(subs[idx].watch);
                subs[idx] = SUB_EMPTY;
            }
            0
        }
        _ => errno::ENOSYS,
    }
}
