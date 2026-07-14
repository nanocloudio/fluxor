// ============================================================================
// Versioned keyspace store — the control-plane peer of the read-only
// filesystem namespace/object providers.
// ============================================================================
//
// WHY THIS EXISTS (rfc_keyspace_provider.md §0, corrected approach). Fluxor
// already carries the keyspace *surface* — `storage.namespace` (LOOKUP/LIST/
// STAT/SUBSCRIBE), `storage.object` (GET/PUT/DELETE with an `if_match` etag
// guard), and the `fence` contract (`RevisionMonotone`/`ViewConsistent`). What
// it lacks is a *provider* fit for a reconcile loop: the host namespace
// provider is read-only + `Volatile` (namespace.rs), the host object provider
// is HTTP-range read-only (object.rs), `namespace::SUBSCRIBE` (0x1305) is
// implemented nowhere, and NOTHING produces a `RevisionMonotone` fence.
//
// A reconciler needs three things those providers don't give: durable monotone
// *revisions* (so a watch can resume and a LIST anchors a subsequent SUBSCRIBE
// — the classic list→watch watermark), *conditional writes* (the `if_match`
// CAS that makes read-modify-write safe), and a *change stream* (the watch).
//
// This module is the algorithmic heart of that provider — deliberately
// backend- and dispatch-agnostic so it is identical whether the eventual
// backing is this in-memory map (tests), a shared on-disk keyspace directory,
// or a fluxor-native durable store. It is pure, `unsafe`-free, std-only:
//
//   * a monotone `u64` revision stamped on every mutation;
//   * per-key current revision, used as the CAS token (`if_match`);
//   * a bounded change history for watch replay;
//   * per-subscriber rings that drain synchronously (the `event.log`
//     ring-drain pattern — no async push mechanism required), signalling
//     `Lost` on overflow so the consumer relists exactly as at cold start.
//
// The provider dispatch wrapper (mapping `storage.object`/`storage.namespace`
// opcodes onto this, encoding `Fence::RevisionMonotone`, and binding a durable
// backend) is the deliberate next step; this core is what it is built on and
// what these tests pin down.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

// ---- Volume-projected persistence (the "Local WAL" of the event.log pattern) ----
//
// Durability is a write-ahead log projected onto a volume directory (nanocloud
// mounts a persistent volume there; fluxor only sees a path). Each mutation
// appends one length-prefixed record and `fsync`s before the op returns — so a
// completed write is `Fence::LocalDurable`, not `Volatile`. On startup the log
// is replayed to rebuild the map, the revision clock, and the tail of the
// change history (so a watch can resume across a restart). A torn trailing
// record (crash mid-append) stops replay cleanly — earlier records stand.
//
// Record: [revision:u64 LE][op:u8][key_len:u16 LE][val_len:u32 LE][key][value]
const WAL_FILE: &str = "keyspace.wal";
const WAL_OP_PUT: u8 = 1;
const WAL_OP_DELETE: u8 = 2;
const WAL_HDR: usize = 8 + 1 + 2 + 4;

/// A write error is either a CAS precondition failure (the caller retries with
/// the current revision) or a durability I/O failure (the mutation did not
/// persist and must not be treated as applied).
#[derive(Debug)]
pub enum WriteError {
    Conflict(CasConflict),
    Io(std::io::Error),
}

impl WriteError {
    /// The CAS conflict, if that is why the write failed (I/O errors return
    /// `None`). Lets callers/tests assert the precondition path cleanly.
    pub fn conflict(&self) -> Option<CasConflict> {
        match self {
            WriteError::Conflict(c) => Some(*c),
            WriteError::Io(_) => None,
        }
    }
}

/// One parsed WAL record: `(rev, op, key, value)`.
type WalRecord = (u64, u8, String, Vec<u8>);

/// The append-only log projected onto the volume directory.
/// Parse every intact record from `data`, returning the records and the byte
/// count consumed. A torn trailing record (crash mid-append) halts parsing —
/// records before it stand; `consumed` stops before the torn bytes.
fn parse_wal_records(data: &[u8]) -> (Vec<WalRecord>, usize) {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + WAL_HDR <= data.len() {
        let rev = u64::from_le_bytes(data[p..p + 8].try_into().unwrap());
        let op = data[p + 8];
        let key_len = u16::from_le_bytes(data[p + 9..p + 11].try_into().unwrap()) as usize;
        let val_len = u32::from_le_bytes(data[p + 11..p + 15].try_into().unwrap()) as usize;
        let end = p + WAL_HDR + key_len + val_len;
        if end > data.len() {
            break; // torn trailing record
        }
        let key = match std::str::from_utf8(&data[p + WAL_HDR..p + WAL_HDR + key_len]) {
            Ok(s) => s.to_string(),
            Err(_) => break,
        };
        let value = data[p + WAL_HDR + key_len..end].to_vec();
        out.push((rev, op, key, value));
        p = end;
    }
    (out, p)
}

/// The append-only log on the shared volume directory — **multi-process**.
///
/// This is the store-sharing seam: the WAL is the ONE cluster store, and more
/// than one process appends to it (nanocloud projects services/pods in; the
/// reconciler fmod writes endpoints out). Two mechanisms make that safe:
///
/// * **flock** around every append (`LOCK_EX`) and every tail-read
///   (`LOCK_SH`): appends are atomic units, and a shared-locked reader never
///   observes a half-written record from a live writer. A torn tail can only
///   come from a crashed writer; the next exclusive appender truncates it
///   (safe — it holds the lock, and recovery already treats those bytes as
///   dead).
/// * **offset tracking + tailing**: each process remembers how much of the
///   log it has consumed and, before any read or write, tails the remainder —
///   records appended by *other* processes — and applies them to its
///   in-memory view (fanning them into watch rings, so a subscriber sees
///   external writes as ordinary events). Revisions stay globally monotone
///   because an appender assigns `rev = max_seen + 1` only after tailing to
///   the end under the exclusive lock.
struct Wal {
    file: File,
    /// Bytes of the log this process has consumed (parsed into memory).
    offset: u64,
}

impl Wal {
    fn open(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(dir.join(WAL_FILE))?;
        Ok(Self { file, offset: 0 })
    }

    fn lock(&self, exclusive: bool) {
        use std::os::unix::io::AsRawFd;
        let op = if exclusive {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        };
        // SAFETY: flock on our own open fd; blocking until granted.
        unsafe {
            libc::flock(self.file.as_raw_fd(), op);
        }
    }

    fn unlock(&self) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: releasing the lock we hold on our own fd.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }

    /// Read every complete record appended since `offset` (by anyone),
    /// advancing `offset` past what parsed. Caller holds the lock.
    fn tail_locked(&mut self) -> Vec<(u64, u8, String, Vec<u8>)> {
        use std::io::{Seek, SeekFrom};
        let len = match self.file.metadata() {
            Ok(m) => m.len(),
            Err(_) => return Vec::new(),
        };
        if len <= self.offset {
            return Vec::new();
        }
        if self.file.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }
        let mut data = Vec::with_capacity((len - self.offset) as usize);
        if self.file.read_to_end(&mut data).is_err() {
            return Vec::new();
        }
        let (records, consumed) = parse_wal_records(&data);
        self.offset += consumed as u64;
        records
    }

    /// Append one record and `fsync` — durable when this returns Ok. Caller
    /// holds the EXCLUSIVE lock and has tailed to the end (so `offset` is the
    /// true end of intact records). Any bytes past `offset` are a crashed
    /// writer's torn tail — truncate them before appending over them.
    fn append_locked(&mut self, rev: u64, op: u8, key: &str, value: &[u8]) -> std::io::Result<()> {
        if let Ok(m) = self.file.metadata() {
            if m.len() > self.offset {
                self.file.set_len(self.offset)?;
            }
        }
        let kb = key.as_bytes();
        let mut buf = Vec::with_capacity(WAL_HDR + kb.len() + value.len());
        buf.extend_from_slice(&rev.to_le_bytes());
        buf.push(op);
        buf.extend_from_slice(&(kb.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
        buf.extend_from_slice(kb);
        buf.extend_from_slice(value);
        self.file.write_all(&buf)?;
        self.file.sync_data()?;
        self.offset += buf.len() as u64;
        Ok(())
    }
}

/// A single namespace change, revision-ordered on the store's monotone clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyspaceChange {
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

/// Returned when a conditional op's `if_match` revision does not equal the
/// key's current revision — carries the current revision for a retry, exactly
/// as `storage.object`'s CAS and `KS_MSG_CONFLICT` intend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CasConflict {
    pub current: u64,
}

/// A subscriber's drain outcome: either the buffered changes, or `Lost` when
/// the ring overflowed and the consumer must relist and re-subscribe from the
/// returned resume revision (the level-triggered "same path as cold start").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Drain {
    Events(Vec<KeyspaceChange>),
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
    /// Bounded ring of pending changes for this subscriber.
    ring: VecDeque<KeyspaceChange>,
    /// Set once the ring overflows; cleared when the consumer acknowledges by
    /// draining (which returns `Lost` and the resume point).
    lost: bool,
    /// The revision to resume from after a `Lost` — the store revision at the
    /// moment of overflow, so a relist + re-subscribe misses nothing.
    lost_resume: u64,
    cap: usize,
}

/// An in-memory versioned keyspace. Single-writer per store instance (the
/// provider serialises calls); no interior mutability, no locks — the caller
/// owns synchronisation, matching the provider dispatch model.
pub struct KeyspaceStore {
    entries: BTreeMap<String, Entry>,
    /// Monotone revision clock. Revision 0 means "before any mutation"; the
    /// first mutation is revision 1, so `since_revision = 0` replays everything
    /// retained.
    revision: u64,
    /// Bounded change history for watch replay (SUBSCRIBE `since` older than
    /// the oldest retained change yields `Lost` immediately).
    history: VecDeque<KeyspaceChange>,
    history_cap: usize,
    watches: BTreeMap<WatchId, Watch>,
    next_watch: u64,
    default_ring_cap: usize,
    /// The volume-projected write-ahead log; `None` for an in-memory store
    /// (tests, or a caller that persists elsewhere). When present, every
    /// mutation is `fsync`'d before it returns.
    wal: Option<Wal>,
}

impl KeyspaceStore {
    pub fn new() -> Self {
        Self::with_limits(1024, 256)
    }

    /// `history_cap` bounds watch-replay reach; `ring_cap` bounds a single
    /// subscriber's in-flight backlog before it is declared `Lost`.
    pub fn with_limits(history_cap: usize, ring_cap: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            revision: 0,
            history: VecDeque::new(),
            history_cap: history_cap.max(1),
            watches: BTreeMap::new(),
            next_watch: 1,
            default_ring_cap: ring_cap.max(1),
            wal: None,
        }
    }

    /// Recover a persistent store from its volume-projected WAL directory,
    /// replaying the log to rebuild the map, the revision clock, and the tail
    /// of the change history (bounded by `history_cap`, so a watch can resume
    /// across a restart). The log stays open for subsequent appends.
    pub fn recover(dir: &Path, history_cap: usize, ring_cap: usize) -> std::io::Result<Self> {
        let mut store = Self::with_limits(history_cap, ring_cap);
        let mut wal = Wal::open(dir)?;
        wal.lock(false);
        let records = wal.tail_locked();
        wal.unlock();
        store.wal = Some(wal);
        for (rev, op, key, value) in records {
            store.apply_external(rev, op, key, value);
        }
        Ok(store)
    }

    /// Apply one WAL record that is already durable in the log — a recover
    /// replay or another process's append discovered by tailing. Updates the
    /// map and revision clock (set-to-max, not bump: the revision came off the
    /// log) and routes the change through `record`, so live watches see
    /// external writes as ordinary events and bounded history retains them.
    fn apply_external(&mut self, rev: u64, op: u8, key: String, value: Vec<u8>) {
        self.revision = self.revision.max(rev);
        let existed = self.entries.contains_key(&key);
        let change = match op {
            WAL_OP_DELETE => {
                self.entries.remove(&key);
                KeyspaceChange {
                    revision: rev,
                    key,
                    kind: ChangeKind::Deleted,
                    value: None,
                }
            }
            _ => {
                self.entries.insert(
                    key.clone(),
                    Entry {
                        value: value.clone(),
                        revision: rev,
                    },
                );
                KeyspaceChange {
                    revision: rev,
                    key,
                    kind: if existed {
                        ChangeKind::Modified
                    } else {
                        ChangeKind::Added
                    },
                    value: Some(value),
                }
            }
        };
        self.record(change);
    }

    /// Consume records other processes appended to the shared WAL since we
    /// last looked, folding them into the in-memory view (and into watch
    /// rings). Called at the top of every read and inside every write — the
    /// store is always current-as-of-the-last-op. No-op for in-memory stores.
    fn catch_up(&mut self) {
        let records = match self.wal.as_mut() {
            Some(wal) => {
                wal.lock(false);
                let recs = wal.tail_locked();
                wal.unlock();
                recs
            }
            None => return,
        };
        for (rev, op, key, value) in records {
            self.apply_external(rev, op, key, value);
        }
    }

    /// The current store revision — the watermark a LIST advertises and a
    /// subsequent SUBSCRIBE resumes from (`fence::RevisionMonotone.revision`).
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Current value + its per-key revision (the CAS token / etag source).
    /// `&mut` because a shared-WAL store first folds in other processes'
    /// appends (`catch_up`).
    pub fn get(&mut self, key: &str) -> Option<(&[u8], u64)> {
        self.catch_up();
        self.entries
            .get(key)
            .map(|e| (e.value.as_slice(), e.revision))
    }

    /// Apply a locally-authored, already-durable change to the in-memory view.
    fn apply_local(&mut self, rev: u64, op: u8, key: &str, value: Vec<u8>) {
        self.revision = rev;
        let change = if op == WAL_OP_DELETE {
            self.entries.remove(key);
            KeyspaceChange {
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
            KeyspaceChange {
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

    /// Insert or update. `if_match`: `None` = unconditional; `Some(0)` = must
    /// not exist; `Some(r)` = current per-key revision must equal `r`. Returns
    /// the new store revision the write was stamped with.
    ///
    /// Shared-WAL stores settle everything that must be atomic — tailing other
    /// processes' appends, the CAS check, revision assignment, the append
    /// itself — under the WAL's exclusive lock, so concurrent writers in other
    /// processes cannot invalidate the precondition or collide on a revision.
    pub fn put(
        &mut self,
        key: &str,
        value: Vec<u8>,
        if_match: Option<u64>,
    ) -> Result<u64, WriteError> {
        if self.wal.is_some() {
            // Lock, then fold in everything appended before us.
            let records = {
                let wal = self.wal.as_mut().expect("checked above");
                wal.lock(true);
                wal.tail_locked()
            };
            for (rev, op, k, v) in records {
                self.apply_external(rev, op, k, v);
            }
            // CAS under the lock — the check is against the true current state.
            if let Some(expect) = if_match {
                let current = self.entries.get(key).map(|e| e.revision).unwrap_or(0);
                if current != expect {
                    self.wal.as_ref().expect("checked above").unlock();
                    return Err(WriteError::Conflict(CasConflict { current }));
                }
            }
            let rev = self.revision + 1;
            let res = self
                .wal
                .as_mut()
                .expect("checked above")
                .append_locked(rev, WAL_OP_PUT, key, &value);
            self.wal.as_ref().expect("checked above").unlock();
            res.map_err(WriteError::Io)?;
            self.apply_local(rev, WAL_OP_PUT, key, value);
            return Ok(rev);
        }

        // In-memory path (tests / callers that persist elsewhere).
        let existing_rev = self.entries.get(key).map(|e| e.revision);
        if let Some(expect) = if_match {
            let current = existing_rev.unwrap_or(0);
            if current != expect {
                return Err(WriteError::Conflict(CasConflict { current }));
            }
        }
        let rev = self.revision + 1;
        self.apply_local(rev, WAL_OP_PUT, key, value);
        Ok(rev)
    }

    /// Remove a key. `if_match` as in `put` (`Some(0)` is meaningless for
    /// delete and always conflicts unless the key is absent). Returns the new
    /// store revision, or `Ok(None)` if the key was absent (no-op, no
    /// revision spent) under an unconditional delete. Same locking discipline
    /// as `put`.
    pub fn delete(&mut self, key: &str, if_match: Option<u64>) -> Result<Option<u64>, WriteError> {
        if self.wal.is_some() {
            let records = {
                let wal = self.wal.as_mut().expect("checked above");
                wal.lock(true);
                wal.tail_locked()
            };
            for (rev, op, k, v) in records {
                self.apply_external(rev, op, k, v);
            }
            let existing_rev = self.entries.get(key).map(|e| e.revision);
            let precheck = Self::delete_precheck(if_match, existing_rev);
            match precheck {
                Err(conflict) => {
                    self.wal.as_ref().expect("checked above").unlock();
                    return Err(WriteError::Conflict(conflict));
                }
                Ok(false) => {
                    self.wal.as_ref().expect("checked above").unlock();
                    return Ok(None); // absent-key no-op
                }
                Ok(true) => {}
            }
            let rev = self.revision + 1;
            let res = self.wal.as_mut().expect("checked above").append_locked(
                rev,
                WAL_OP_DELETE,
                key,
                &[],
            );
            self.wal.as_ref().expect("checked above").unlock();
            res.map_err(WriteError::Io)?;
            self.apply_local(rev, WAL_OP_DELETE, key, Vec::new());
            return Ok(Some(rev));
        }

        let existing_rev = self.entries.get(key).map(|e| e.revision);
        match Self::delete_precheck(if_match, existing_rev) {
            Err(conflict) => return Err(WriteError::Conflict(conflict)),
            Ok(false) => return Ok(None),
            Ok(true) => {}
        }
        let rev = self.revision + 1;
        self.apply_local(rev, WAL_OP_DELETE, key, Vec::new());
        Ok(Some(rev))
    }

    /// The delete precondition: `Err` = CAS conflict; `Ok(false)` = valid
    /// no-op (key absent); `Ok(true)` = proceed to delete.
    fn delete_precheck(
        if_match: Option<u64>,
        existing_rev: Option<u64>,
    ) -> Result<bool, CasConflict> {
        match (if_match, existing_rev) {
            (Some(expect), current) => {
                let cur = current.unwrap_or(0);
                if cur != expect {
                    return Err(CasConflict { current: cur });
                }
                Ok(current.is_some())
            }
            (None, None) => Ok(false), // unconditional delete of absent key: no-op
            (None, Some(_)) => Ok(true),
        }
    }

    /// Key-ordered snapshot of entries under `prefix`, plus the store revision
    /// the snapshot is consistent at — the anchor a subsequent `subscribe`
    /// resumes from with no gap (the list→watch watermark). `&mut` for
    /// `catch_up`, as in `get`.
    pub fn list(&mut self, prefix: &str) -> (Vec<(String, u64)>, u64) {
        self.catch_up();
        let items = self
            .entries
            .range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, e)| (k.clone(), e.revision))
            .collect();
        (items, self.revision)
    }

    /// Open a watch over `prefix`, delivering every retained change with
    /// `revision > since_revision`, then live changes. If `since_revision`
    /// precedes retained history, the watch opens already `Lost` (the consumer
    /// must relist) — never a silent gap.
    pub fn subscribe(&mut self, prefix: &str, since_revision: u64) -> WatchId {
        // Fold in other processes' appends first, so `since` is judged against
        // the true current revision (and their changes land in history, not in
        // this watch's ring twice).
        self.catch_up();
        let id = WatchId(self.next_watch);
        self.next_watch += 1;
        let cap = self.default_ring_cap;
        let mut watch = Watch {
            prefix: prefix.to_string(),
            ring: VecDeque::new(),
            lost: false,
            lost_resume: 0,
            cap,
        };

        // Can we reach `since_revision` from retained history?
        let oldest = self.history.front().map(|c| c.revision);
        let reachable = match oldest {
            // History empty: reachable iff caller is already current.
            None => since_revision <= self.revision,
            // Reachable iff the caller's cursor is at or after (oldest-1),
            // i.e. the first change we retain (oldest) is the next one it needs.
            // `since` comes off the wire, so saturate rather than overflow on
            // `u64::MAX`.
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

    /// Drain up to `max` buffered changes for a watch (0 = all). `Lost` is
    /// sticky until drained: a lost watch returns `Drain::Lost` once, then
    /// resumes buffering live changes from `resume_revision`.
    pub fn drain(&mut self, id: WatchId, max: usize) -> Option<Drain> {
        // The poll path: tailing here is what makes another process's appends
        // arrive in this subscriber's ring as ordinary events.
        self.catch_up();
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

    /// Return events a `drain` took off a watch's ring back to its front, in
    /// original order. Used when a caller's out buffer could not hold the whole
    /// drained batch, so the remainder is redelivered next drain rather than
    /// lost. The count returned never exceeds what was just removed, so this
    /// cannot overflow the ring or trip its `Lost` guard.
    fn requeue_front(&mut self, id: WatchId, events: Vec<KeyspaceChange>) {
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

    // ---- internals ----

    fn record(&mut self, change: KeyspaceChange) {
        // Fan out to matching live subscribers first (they observe in the same
        // revision order the history preserves).
        let rev = self.revision;
        for watch in self.watches.values_mut() {
            if change.key.starts_with(&watch.prefix) {
                Self::push(watch, change.clone(), rev);
            }
        }
        // Then retain in the bounded history for future-subscriber replay.
        self.history.push_back(change);
        while self.history.len() > self.history_cap {
            self.history.pop_front();
        }
    }

    /// Push a change into a subscriber's ring, marking `Lost` (with the resume
    /// point) if the ring would overflow rather than silently dropping.
    fn push(watch: &mut Watch, change: KeyspaceChange, store_revision: u64) {
        if watch.lost {
            return; // already lost; awaiting the consumer's relist
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

impl Default for KeyspaceStore {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Provider wire — a dedicated keyspace surface over the versioned store.
// ============================================================================
//
// A control-plane versioned/watchable KV is an honest sibling of the existing
// read-only `storage.namespace` (fs enumeration) and `storage.object` (HTTP
// paging) providers — it shares their vocabulary (the `fence` contract, the
// tagged-handle model) but not their backing semantics, so it gets its own
// class byte rather than displacing them (the runtime routes one vtable per
// contract). This is the slice-based marshalling core; the unsafe
// `linux_keyspace_dispatch(handle, op, ptr, len)` wrapper and the kernel
// registration (contract id 0x17, an FD tag, the vtable + boot register) are
// the mechanical adapter that wraps this — kept separate so the wire logic is
// unit-testable off the FFI boundary.
//
// Fences (rfc_keyspace_provider.md §0, arch doc §2): reads advertise
// `ViewConsistent{source, revision}` (a read view at a revision); writes that
// committed + fsync'd advertise `RevisionMonotone{source, revision}` (the
// revision a watcher resumes from). `source` is the store's stable ObjectId.

use fluxor::abi::contracts::fence as ks_fence;

pub mod wire {
    /// One-shot ops (handle = -1; key travels in `arg`), class byte 0x17.
    pub const KS_PUT: u32 = 0x1701;
    pub const KS_GET: u32 = 0x1702;
    pub const KS_DELETE: u32 = 0x1703;
    pub const KS_LIST: u32 = 0x1704;
    pub const KS_SUBSCRIBE: u32 = 0x1705;
    pub const KS_DRAIN: u32 = 0x1706;
    pub const KS_UNSUBSCRIBE: u32 = 0x1707;

    /// Negative i32 status codes (errno-shaped, matching the provider ABI).
    pub const E_INVAL: i32 = -22;
    pub const E_NOENT: i32 = -2; // key absent (GET/DELETE report as status)
    pub const E_CONFLICT: i32 = -11; // CAS precondition failed; out carries current rev
    pub const E_IO: i32 = -5; // durability failure
    pub const E_NOSPC: i32 = -28; // output buffer too small
    pub const E_BADWATCH: i32 = -9; // no such watch

    /// DRAIN out-buffer tag: events vs a lost marker.
    pub const DRAIN_EVENTS: u8 = 0;
    pub const DRAIN_LOST: u8 = 1;
}

/// Stable source identity for this store's fences (`ObjectId = [u8;16]`).
const KEYSPACE_SOURCE: ks_fence::ObjectId = *b"fluxor-keyspace\0";

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn get_u16(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
}
fn get_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}
fn get_u64(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

fn encode_fence(view: bool, revision: u64, fence_out: &mut [u8]) {
    if fence_out.len() < ks_fence::WIRE_MAX_LEN {
        return;
    }
    let f = if view {
        ks_fence::Fence::ViewConsistent {
            source: KEYSPACE_SOURCE,
            revision,
        }
    } else {
        ks_fence::Fence::RevisionMonotone {
            source: KEYSPACE_SOURCE,
            revision,
        }
    };
    let _ = f.encode(fence_out);
}

impl KeyspaceStore {
    /// The slice-based provider dispatch: map one keyspace opcode onto the
    /// store, writing the result into `out` and the per-op fence into
    /// `fence_out`. Returns bytes written to `out` (>= 0), or a negative
    /// `wire::E_*` status. Pure over slices — the unsafe FFI entry wraps this.
    pub fn dispatch(
        &mut self,
        opcode: u32,
        arg: &[u8],
        out: &mut [u8],
        fence_out: &mut [u8],
    ) -> i32 {
        match opcode {
            wire::KS_PUT => self.wire_put(arg, out, fence_out),
            wire::KS_GET => self.wire_get(arg, out, fence_out),
            wire::KS_DELETE => self.wire_delete(arg, out, fence_out),
            wire::KS_LIST => self.wire_list(arg, out, fence_out),
            wire::KS_SUBSCRIBE => self.wire_subscribe(arg, out),
            wire::KS_DRAIN => self.wire_drain(arg, out),
            wire::KS_UNSUBSCRIBE => self.wire_unsubscribe(arg),
            _ => wire::E_INVAL,
        }
    }

    // PUT arg: [key_len:u16][if_match:u64][val_len:u32][key][value]
    // out on success: [new_rev:u64]; on conflict: [current_rev:u64] + E_CONFLICT
    fn wire_put(&mut self, arg: &[u8], out: &mut [u8], fence_out: &mut [u8]) -> i32 {
        let (Some(key_len), Some(if_match), Some(val_len)) =
            (get_u16(arg, 0), get_u64(arg, 2), get_u32(arg, 10))
        else {
            return wire::E_INVAL;
        };
        let (key_len, val_len) = (key_len as usize, val_len as usize);
        let key_start = 14;
        let val_start = key_start + key_len;
        if arg.len() < val_start + val_len {
            return wire::E_INVAL;
        }
        let Ok(key) = std::str::from_utf8(&arg[key_start..val_start]) else {
            return wire::E_INVAL;
        };
        let value = arg[val_start..val_start + val_len].to_vec();
        let cond = if if_match == u64::MAX {
            None
        } else {
            Some(if_match)
        };
        match self.put(key, value, cond) {
            Ok(rev) => {
                if out.len() < 8 {
                    return wire::E_NOSPC;
                }
                put_u64(out, 0, rev);
                encode_fence(false, rev, fence_out); // committed → RevisionMonotone
                8
            }
            Err(WriteError::Conflict(c)) => {
                if out.len() >= 8 {
                    put_u64(out, 0, c.current);
                }
                wire::E_CONFLICT
            }
            Err(WriteError::Io(_)) => wire::E_IO,
        }
    }

    // GET arg: [key_len:u16][key]; out: [rev:u64][value]
    fn wire_get(&mut self, arg: &[u8], out: &mut [u8], fence_out: &mut [u8]) -> i32 {
        let Some(key_len) = get_u16(arg, 0) else {
            return wire::E_INVAL;
        };
        let key_len = key_len as usize;
        if arg.len() < 2 + key_len {
            return wire::E_INVAL;
        }
        let Ok(key) = std::str::from_utf8(&arg[2..2 + key_len]) else {
            return wire::E_INVAL;
        };
        match self.get(key) {
            Some((value, rev)) => {
                let need = 8 + value.len();
                if out.len() < need {
                    return wire::E_NOSPC;
                }
                put_u64(out, 0, rev);
                out[8..need].copy_from_slice(value);
                encode_fence(true, rev, fence_out); // read view → ViewConsistent
                need as i32
            }
            None => wire::E_NOENT,
        }
    }

    // DELETE arg: [key_len:u16][if_match:u64][key]; out: [new_rev:u64] (0 = no-op)
    fn wire_delete(&mut self, arg: &[u8], out: &mut [u8], fence_out: &mut [u8]) -> i32 {
        let (Some(key_len), Some(if_match)) = (get_u16(arg, 0), get_u64(arg, 2)) else {
            return wire::E_INVAL;
        };
        let key_len = key_len as usize;
        if arg.len() < 10 + key_len {
            return wire::E_INVAL;
        }
        let Ok(key) = std::str::from_utf8(&arg[10..10 + key_len]) else {
            return wire::E_INVAL;
        };
        let cond = if if_match == u64::MAX {
            None
        } else {
            Some(if_match)
        };
        match self.delete(key, cond) {
            Ok(rev) => {
                if out.len() < 8 {
                    return wire::E_NOSPC;
                }
                let r = rev.unwrap_or(0);
                put_u64(out, 0, r);
                encode_fence(false, r, fence_out);
                8
            }
            Err(WriteError::Conflict(c)) => {
                if out.len() >= 8 {
                    put_u64(out, 0, c.current);
                }
                wire::E_CONFLICT
            }
            Err(WriteError::Io(_)) => wire::E_IO,
        }
    }

    // LIST arg: [prefix_len:u16][prefix]
    // out: [watermark:u64][count:u32] then count×[key_len:u16][rev:u64][key]
    fn wire_list(&mut self, arg: &[u8], out: &mut [u8], fence_out: &mut [u8]) -> i32 {
        let Some(prefix_len) = get_u16(arg, 0) else {
            return wire::E_INVAL;
        };
        let prefix_len = prefix_len as usize;
        if arg.len() < 2 + prefix_len {
            return wire::E_INVAL;
        }
        let Ok(prefix) = std::str::from_utf8(&arg[2..2 + prefix_len]) else {
            return wire::E_INVAL;
        };
        let (items, watermark) = self.list(prefix);
        if out.len() < 12 {
            return wire::E_NOSPC;
        }
        put_u64(out, 0, watermark);
        let mut w = 12;
        let mut count = 0u32;
        for (key, rev) in &items {
            let kb = key.as_bytes();
            let need = 2 + 8 + kb.len();
            if w + need > out.len() {
                return wire::E_NOSPC; // caller sizes from a prior watermark-only list or retries larger
            }
            put_u16(out, w, kb.len() as u16);
            put_u64(out, w + 2, *rev);
            out[w + 10..w + 10 + kb.len()].copy_from_slice(kb);
            w += need;
            count += 1;
        }
        put_u32(out, 8, count);
        encode_fence(true, watermark, fence_out);
        w as i32
    }

    // SUBSCRIBE arg: [since_rev:u64][prefix_len:u16][prefix]; out: [watch_id:u64]
    fn wire_subscribe(&mut self, arg: &[u8], out: &mut [u8]) -> i32 {
        let (Some(since), Some(prefix_len)) = (get_u64(arg, 0), get_u16(arg, 8)) else {
            return wire::E_INVAL;
        };
        let prefix_len = prefix_len as usize;
        if arg.len() < 10 + prefix_len || out.len() < 8 {
            return wire::E_INVAL;
        }
        let Ok(prefix) = std::str::from_utf8(&arg[10..10 + prefix_len]) else {
            return wire::E_INVAL;
        };
        let id = self.subscribe(prefix, since);
        put_u64(out, 0, id.0);
        8
    }

    // DRAIN arg: [watch_id:u64][max:u16]
    // out: [tag:u8] then either (DRAIN_EVENTS) [count:u32] × event, or
    //      (DRAIN_LOST) [resume_rev:u64]. Event: [rev:u64][kind:u8][key_len:u16][val_len:u32][key][val]
    fn wire_drain(&mut self, arg: &[u8], out: &mut [u8]) -> i32 {
        let (Some(id), Some(max)) = (get_u64(arg, 0), get_u16(arg, 8)) else {
            return wire::E_INVAL;
        };
        let Some(drained) = self.drain(WatchId(id), max as usize) else {
            return wire::E_BADWATCH;
        };
        match drained {
            Drain::Lost { resume_revision } => {
                if out.len() < 9 {
                    return wire::E_NOSPC;
                }
                out[0] = wire::DRAIN_LOST;
                put_u64(out, 1, resume_revision);
                9
            }
            Drain::Events(events) => {
                if out.len() < 5 {
                    // Not even room for the header — nothing was consumed, so
                    // return the whole batch (already off the ring) to it.
                    self.requeue_front(WatchId(id), events);
                    return wire::E_NOSPC;
                }
                let mut w = 5;
                let mut encoded = 0usize;
                for ev in &events {
                    let kb = ev.key.as_bytes();
                    let vb = ev.value.as_deref().unwrap_or(&[]);
                    let need = 8 + 1 + 2 + 4 + kb.len() + vb.len();
                    if w + need > out.len() {
                        break;
                    }
                    put_u64(out, w, ev.revision);
                    out[w + 8] = match ev.kind {
                        ChangeKind::Added => 1,
                        ChangeKind::Modified => 2,
                        ChangeKind::Deleted => 3,
                    };
                    put_u16(out, w + 9, kb.len() as u16);
                    put_u32(out, w + 11, vb.len() as u32);
                    out[w + 15..w + 15 + kb.len()].copy_from_slice(kb);
                    out[w + 15 + kb.len()..w + 15 + kb.len() + vb.len()].copy_from_slice(vb);
                    w += need;
                    encoded += 1;
                }
                // `drain` already removed these from the ring; put the tail that
                // did not fit back at the front so the next drain delivers it
                // rather than dropping it silently.
                if encoded < events.len() {
                    let mut events = events;
                    let tail = events.split_off(encoded);
                    self.requeue_front(WatchId(id), tail);
                    if encoded == 0 {
                        // Buffer too small for even one event — signal short
                        // rather than a spurious empty (nothing was consumed).
                        return wire::E_NOSPC;
                    }
                }
                out[0] = wire::DRAIN_EVENTS;
                put_u32(out, 1, encoded as u32);
                w as i32
            }
        }
    }

    fn wire_unsubscribe(&mut self, arg: &[u8]) -> i32 {
        let Some(id) = get_u64(arg, 0) else {
            return wire::E_INVAL;
        };
        if self.unsubscribe(WatchId(id)) {
            0
        } else {
            wire::E_BADWATCH
        }
    }
}

#[cfg(test)]
mod keyspace_store_tests {
    use super::*;

    fn v(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn put_get_stamps_monotone_revisions() {
        let mut ks = KeyspaceStore::new();
        assert_eq!(ks.revision(), 0);
        let r1 = ks.put("/a", v("1"), None).unwrap();
        let r2 = ks.put("/b", v("2"), None).unwrap();
        assert_eq!((r1, r2), (1, 2));
        assert_eq!(ks.get("/a"), Some((v("1").as_slice(), 1)));
        assert_eq!(ks.get("/b"), Some((v("2").as_slice(), 2)));
        assert_eq!(ks.revision(), 2);
    }

    #[test]
    fn if_match_cas_guards_writes() {
        let mut ks = KeyspaceStore::new();
        // create-if-absent: Some(0) succeeds when absent, conflicts when present.
        let r = ks.put("/k", v("a"), Some(0)).unwrap();
        assert_eq!(r, 1);
        assert_eq!(
            ks.put("/k", v("b"), Some(0)).unwrap_err().conflict(),
            Some(CasConflict { current: 1 })
        );
        // update-if-matches: correct revision succeeds, stale conflicts.
        assert_eq!(ks.put("/k", v("b"), Some(1)).unwrap(), 2);
        assert_eq!(
            ks.put("/k", v("c"), Some(1)).unwrap_err().conflict(),
            Some(CasConflict { current: 2 })
        );
        assert_eq!(ks.get("/k"), Some((v("b").as_slice(), 2)));
    }

    #[test]
    fn delete_conditional_and_unconditional() {
        let mut ks = KeyspaceStore::new();
        ks.put("/k", v("a"), None).unwrap();
        // stale if_match conflicts
        assert_eq!(
            ks.delete("/k", Some(99)).unwrap_err().conflict(),
            Some(CasConflict { current: 1 })
        );
        // correct if_match deletes
        assert_eq!(ks.delete("/k", Some(1)).unwrap(), Some(2));
        assert_eq!(ks.get("/k"), None);
        // unconditional delete of absent key is a no-op (no revision spent)
        assert_eq!(ks.delete("/k", None).unwrap(), None);
        assert_eq!(ks.revision(), 2);
    }

    #[test]
    fn list_is_key_ordered_and_prefix_scoped_with_watermark() {
        let mut ks = KeyspaceStore::new();
        ks.put("/svc/b", v("2"), None).unwrap();
        ks.put("/svc/a", v("1"), None).unwrap();
        ks.put("/pods/x", v("9"), None).unwrap();
        let (items, watermark) = ks.list("/svc/");
        let keys: Vec<&str> = items.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["/svc/a", "/svc/b"]); // key-ordered, prefix-scoped
        assert_eq!(watermark, ks.revision());
    }

    #[test]
    fn subscribe_replays_since_then_goes_live() {
        let mut ks = KeyspaceStore::new();
        ks.put("/svc/a", v("1"), None).unwrap(); // rev 1
        ks.put("/svc/b", v("2"), None).unwrap(); // rev 2
                                                 // Subscribe since rev 1 → replays only rev 2 (the change after the cursor).
        let w = ks.subscribe("/svc/", 1);
        let Drain::Events(replay) = ks.drain(w, 0).unwrap() else {
            panic!("expected events")
        };
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].revision, 2);
        assert_eq!(replay[0].key, "/svc/b");
        // A live change under the prefix is delivered; one outside is not.
        ks.put("/svc/c", v("3"), None).unwrap(); // rev 3
        ks.put("/pods/x", v("9"), None).unwrap(); // rev 4, different prefix
        let Drain::Events(live) = ks.drain(w, 0).unwrap() else {
            panic!("expected events")
        };
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].key, "/svc/c");
        assert_eq!(live[0].kind, ChangeKind::Added);
    }

    #[test]
    fn list_then_subscribe_watermark_has_no_gap() {
        // The list→watch handoff: LIST returns a watermark; SUBSCRIBE since the
        // watermark delivers exactly the changes after it — no miss, no dup.
        let mut ks = KeyspaceStore::new();
        ks.put("/svc/a", v("1"), None).unwrap();
        let (_snapshot, watermark) = ks.list("/svc/");
        // A change races in after the list.
        ks.put("/svc/b", v("2"), None).unwrap();
        let w = ks.subscribe("/svc/", watermark);
        let Drain::Events(evs) = ks.drain(w, 0).unwrap() else {
            panic!("events")
        };
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].key, "/svc/b"); // the raced write, delivered exactly once
    }

    #[test]
    fn ring_overflow_yields_lost_then_resumes() {
        let mut ks = KeyspaceStore::with_limits(1024, 2); // ring cap 2
        let w = ks.subscribe("/k", 0);
        for i in 0..5 {
            ks.put(&format!("/k{i}"), v("x"), None).unwrap();
        }
        // Overflowed → Lost with a resume revision at the overflow point.
        match ks.drain(w, 0).unwrap() {
            Drain::Lost { resume_revision } => assert!(resume_revision >= 2),
            other => panic!("expected Lost, got {other:?}"),
        }
        // After acknowledging Lost, the watch resumes buffering live changes.
        ks.put("/k99", v("y"), None).unwrap();
        let Drain::Events(evs) = ks.drain(w, 0).unwrap() else {
            panic!("events")
        };
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].key, "/k99");
    }

    #[test]
    fn subscribe_before_retained_history_is_lost() {
        let mut ks = KeyspaceStore::with_limits(2, 8); // history cap 2
        for i in 0..5 {
            ks.put(&format!("/k{i}"), v("x"), None).unwrap(); // revs 1..5
        }
        // Oldest retained change is rev 4; subscribing since rev 1 can't be
        // served from history → Lost immediately, resume at current revision.
        let w = ks.subscribe("/k", 1);
        match ks.drain(w, 0).unwrap() {
            Drain::Lost { resume_revision } => assert_eq!(resume_revision, ks.revision()),
            other => panic!("expected Lost, got {other:?}"),
        }
    }

    #[test]
    fn drain_respects_max_batch() {
        let mut ks = KeyspaceStore::new();
        let w = ks.subscribe("/k", 0);
        for i in 0..4 {
            ks.put(&format!("/k{i}"), v("x"), None).unwrap();
        }
        let Drain::Events(first) = ks.drain(w, 2).unwrap() else {
            panic!("events")
        };
        assert_eq!(first.len(), 2);
        let Drain::Events(rest) = ks.drain(w, 0).unwrap() else {
            panic!("events")
        };
        assert_eq!(rest.len(), 2);
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let mut d = std::env::temp_dir();
        d.push(format!(
            "fluxor-ks-test-{}-{}-{}",
            std::process::id(),
            tag,
            n
        ));
        d
    }

    #[test]
    fn recover_persists_across_restart() {
        let dir = temp_dir("roundtrip");
        {
            let mut ks = KeyspaceStore::recover(&dir, 1024, 256).unwrap();
            ks.put("/svc/a", v("1"), None).unwrap(); // rev 1
            ks.put("/svc/b", v("2"), Some(0)).unwrap(); // rev 2 (create-if-absent)
            ks.delete("/svc/a", None).unwrap(); // rev 3
        } // dropped; every op fsync'd its WAL record before returning
        let mut ks2 = KeyspaceStore::recover(&dir, 1024, 256).unwrap();
        assert_eq!(ks2.revision(), 3);
        assert_eq!(ks2.get("/svc/a"), None); // the delete survived
        assert_eq!(ks2.get("/svc/b"), Some((v("2").as_slice(), 2)));
        // The revision clock continues from the recovered high-water mark.
        assert_eq!(ks2.put("/svc/c", v("3"), None).unwrap(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recover_rebuilds_history_so_watch_resumes_across_restart() {
        let dir = temp_dir("watch");
        {
            let mut ks = KeyspaceStore::recover(&dir, 1024, 256).unwrap();
            ks.put("/k/a", v("1"), None).unwrap(); // rev 1
            ks.put("/k/b", v("2"), None).unwrap(); // rev 2
        }
        let mut ks2 = KeyspaceStore::recover(&dir, 1024, 256).unwrap();
        // A watch resuming from rev 1 replays rev 2 from the rebuilt history —
        // a reconciler survives a node restart without a full relist.
        let w = ks2.subscribe("/k/", 1);
        let Drain::Events(evs) = ks2.drain(w, 0).unwrap() else {
            panic!("events")
        };
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].revision, 2);
        assert_eq!(evs[0].key, "/k/b");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn torn_trailing_record_halts_replay_cleanly() {
        let dir = temp_dir("torn");
        {
            let mut ks = KeyspaceStore::recover(&dir, 1024, 256).unwrap();
            ks.put("/k", v("ok"), None).unwrap(); // one intact record, rev 1
        }
        // Simulate a crash mid-append: a partial (< header) trailing write.
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.join(WAL_FILE))
                .unwrap();
            f.write_all(&[0xFF, 0xFF, 0xFF]).unwrap();
        }
        // Replay stops at the torn record; the intact prefix stands.
        let mut ks2 = KeyspaceStore::recover(&dir, 1024, 256).unwrap();
        assert_eq!(ks2.revision(), 1);
        assert_eq!(ks2.get("/k"), Some((v("ok").as_slice(), 1)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- multi-process store sharing (two stores, one WAL directory) ----
    //
    // Two KeyspaceStore instances on the same directory are exactly the two
    // processes of the endpoints migration: nanocloud (projects services/pods
    // in) and the fluxor runtime hosting the reconciler fmod (writes
    // endpoints out). One store, no bridging.

    #[test]
    fn external_writes_are_visible_across_store_instances() {
        let dir = temp_dir("xproc-vis");
        let mut a = KeyspaceStore::recover(&dir, 1024, 256).unwrap();
        let mut b = KeyspaceStore::recover(&dir, 1024, 256).unwrap();

        // A writes; B sees it (value + revision) without reopening.
        assert_eq!(a.put("/svc/a", v("1"), None).unwrap(), 1);
        assert_eq!(b.get("/svc/a"), Some((v("1").as_slice(), 1)));
        assert_eq!(b.revision(), 1);

        // And the reverse: B writes at the NEXT global revision; A sees it.
        assert_eq!(b.put("/svc/b", v("2"), None).unwrap(), 2);
        assert_eq!(a.get("/svc/b"), Some((v("2").as_slice(), 2)));
        // A's list is the union, key-ordered, at the shared watermark.
        let (items, watermark) = a.list("/svc/");
        let keys: Vec<&str> = items.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["/svc/a", "/svc/b"]);
        assert_eq!(watermark, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn watch_receives_another_processes_writes_as_events() {
        let dir = temp_dir("xproc-watch");
        let mut writer = KeyspaceStore::recover(&dir, 1024, 256).unwrap();
        let mut watcher = KeyspaceStore::recover(&dir, 1024, 256).unwrap();

        // The reconciler-fmod shape: subscribe, then the OTHER process writes.
        let w = watcher.subscribe("/pods/", 0);
        writer.put("/pods/web-1", v("10.0.0.1"), None).unwrap();
        writer.put("/svc/other", v("x"), None).unwrap(); // outside the prefix

        let Drain::Events(evs) = watcher.drain(w, 0).unwrap() else {
            panic!("expected events");
        };
        assert_eq!(evs.len(), 1, "only the matching prefix is delivered");
        assert_eq!(evs[0].key, "/pods/web-1");
        assert_eq!(evs[0].kind, ChangeKind::Added);
        assert_eq!(evs[0].value.as_deref(), Some(v("10.0.0.1").as_slice()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cas_is_settled_against_other_processes_writes() {
        let dir = temp_dir("xproc-cas");
        let mut a = KeyspaceStore::recover(&dir, 1024, 256).unwrap();
        let mut b = KeyspaceStore::recover(&dir, 1024, 256).unwrap();

        a.put("/k", v("a1"), None).unwrap(); // rev 1
        assert_eq!(b.get("/k").map(|(_, r)| r), Some(1));
        // B updates at rev 1 → rev 2. A's stale if_match=1 must now conflict,
        // even though A hasn't read since — the lock-and-tail settles it.
        assert_eq!(b.put("/k", v("b2"), Some(1)).unwrap(), 2);
        let err = a.put("/k", v("stale"), Some(1)).unwrap_err();
        assert_eq!(err.conflict(), Some(CasConflict { current: 2 }));
        // A's retry against the true revision succeeds at rev 3.
        assert_eq!(a.put("/k", v("a3"), Some(2)).unwrap(), 3);
        assert_eq!(b.get("/k"), Some((v("a3").as_slice(), 3)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn torn_tail_is_truncated_by_the_next_appender() {
        let dir = temp_dir("xproc-torn");
        {
            let mut ks = KeyspaceStore::recover(&dir, 1024, 256).unwrap();
            ks.put("/k", v("ok"), None).unwrap(); // rev 1, intact
        }
        // A crashed writer left a torn tail.
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.join(WAL_FILE))
                .unwrap();
            f.write_all(&[0xAB, 0xCD]).unwrap();
        }
        // The next appender truncates the torn bytes under its exclusive lock
        // and appends cleanly; a fresh reader sees both intact records.
        let mut ks = KeyspaceStore::recover(&dir, 1024, 256).unwrap();
        assert_eq!(ks.put("/k2", v("new"), None).unwrap(), 2);
        let mut fresh = KeyspaceStore::recover(&dir, 1024, 256).unwrap();
        assert_eq!(fresh.get("/k"), Some((v("ok").as_slice(), 1)));
        assert_eq!(fresh.get("/k2"), Some((v("new").as_slice(), 2)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- provider dispatch (wire) ----

    fn put_arg(key: &str, if_match: u64, val: &[u8]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&(key.len() as u16).to_le_bytes());
        a.extend_from_slice(&if_match.to_le_bytes());
        a.extend_from_slice(&(val.len() as u32).to_le_bytes());
        a.extend_from_slice(key.as_bytes());
        a.extend_from_slice(val);
        a
    }

    #[test]
    fn dispatch_put_get_roundtrip_with_correct_fences() {
        let mut ks = KeyspaceStore::new();
        let mut out = [0u8; 64];
        let mut fence = [0u8; ks_fence::WIRE_MAX_LEN];
        // PUT (unconditional = if_match u64::MAX) → new rev 1, RevisionMonotone.
        let n = ks.dispatch(
            wire::KS_PUT,
            &put_arg("/svc/a", u64::MAX, b"1"),
            &mut out,
            &mut fence,
        );
        assert_eq!(n, 8);
        assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()), 1);
        assert_eq!(fence[0], ks_fence::TAG_REVISION_MONOTONE); // committed write
                                                               // GET → [rev][value], ViewConsistent (a read view).
        let mut garg = vec![6, 0];
        garg.extend_from_slice(b"/svc/a");
        let n = ks.dispatch(wire::KS_GET, &garg, &mut out, &mut fence);
        assert_eq!(n, 9);
        assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()), 1);
        assert_eq!(&out[8..9], b"1");
        assert_eq!(fence[0], ks_fence::TAG_VIEW_CONSISTENT);
    }

    #[test]
    fn dispatch_put_conflict_reports_current_revision() {
        let mut ks = KeyspaceStore::new();
        let mut out = [0u8; 64];
        let mut fence = [0u8; ks_fence::WIRE_MAX_LEN];
        ks.dispatch(wire::KS_PUT, &put_arg("/k", 0, b"a"), &mut out, &mut fence); // create → rev 1
                                                                                  // create-if-absent again → conflict carrying the current revision.
        let r = ks.dispatch(wire::KS_PUT, &put_arg("/k", 0, b"b"), &mut out, &mut fence);
        assert_eq!(r, wire::E_CONFLICT);
        assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()), 1);
    }

    #[test]
    fn dispatch_list_encodes_watermark_entries_and_view_fence() {
        let mut ks = KeyspaceStore::new();
        let mut out = [0u8; 256];
        let mut fence = [0u8; ks_fence::WIRE_MAX_LEN];
        ks.dispatch(
            wire::KS_PUT,
            &put_arg("/svc/b", u64::MAX, b"2"),
            &mut out,
            &mut fence,
        );
        ks.dispatch(
            wire::KS_PUT,
            &put_arg("/svc/a", u64::MAX, b"1"),
            &mut out,
            &mut fence,
        );
        let mut larg = vec![5, 0];
        larg.extend_from_slice(b"/svc/");
        let n = ks.dispatch(wire::KS_LIST, &larg, &mut out, &mut fence);
        assert!(n > 0);
        assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()), 2); // watermark
        assert_eq!(u32::from_le_bytes(out[8..12].try_into().unwrap()), 2); // count
        assert_eq!(fence[0], ks_fence::TAG_VIEW_CONSISTENT);
        // First entry is key-ordered → /svc/a: [key_len:u16][rev:u64][key]
        let klen = u16::from_le_bytes(out[12..14].try_into().unwrap()) as usize;
        assert_eq!(&out[22..22 + klen], b"/svc/a");
    }

    #[test]
    fn dispatch_subscribe_then_drain_delivers_events() {
        let mut ks = KeyspaceStore::new();
        let mut out = [0u8; 256];
        let mut fence = [0u8; ks_fence::WIRE_MAX_LEN];
        // SUBSCRIBE /k/ since 0 → watch id.
        let mut sarg = 0u64.to_le_bytes().to_vec();
        sarg.extend_from_slice(&3u16.to_le_bytes());
        sarg.extend_from_slice(b"/k/");
        assert_eq!(
            ks.dispatch(wire::KS_SUBSCRIBE, &sarg, &mut out, &mut fence),
            8
        );
        let wid = u64::from_le_bytes(out[..8].try_into().unwrap());
        // A matching PUT, then DRAIN all.
        ks.dispatch(
            wire::KS_PUT,
            &put_arg("/k/a", u64::MAX, b"1"),
            &mut out,
            &mut fence,
        );
        let mut darg = wid.to_le_bytes().to_vec();
        darg.extend_from_slice(&0u16.to_le_bytes()); // max=0 → all
        let n = ks.dispatch(wire::KS_DRAIN, &darg, &mut out, &mut fence);
        assert!(n > 0);
        assert_eq!(out[0], wire::DRAIN_EVENTS);
        assert_eq!(u32::from_le_bytes(out[1..5].try_into().unwrap()), 1); // one event
                                                                          // event: [rev:u64][kind:u8]...
        assert_eq!(u64::from_le_bytes(out[5..13].try_into().unwrap()), 1); // rev 1
        assert_eq!(out[13], 1); // Added
    }

    #[test]
    fn dispatch_drain_requeues_events_that_do_not_fit() {
        let mut ks = KeyspaceStore::new();
        let mut fence = [0u8; ks_fence::WIRE_MAX_LEN];
        let mut big = [0u8; 256];
        // Subscribe, then produce three matching events.
        let mut sarg = 0u64.to_le_bytes().to_vec();
        sarg.extend_from_slice(&3u16.to_le_bytes());
        sarg.extend_from_slice(b"/k/");
        assert_eq!(
            ks.dispatch(wire::KS_SUBSCRIBE, &sarg, &mut big, &mut fence),
            8
        );
        let wid = u64::from_le_bytes(big[..8].try_into().unwrap());
        for k in ["/k/a", "/k/b", "/k/c"] {
            ks.dispatch(
                wire::KS_PUT,
                &put_arg(k, u64::MAX, b"1"),
                &mut big,
                &mut fence,
            );
        }

        // A DRAIN whose out buffer holds the 5-byte header + exactly one event
        // (each event = 15 header + 4 key + 1 val = 20 bytes). The other two
        // must be redelivered, not dropped.
        let one_event = 5 + 20;
        let mut small = vec![0u8; one_event];
        let mut darg = wid.to_le_bytes().to_vec();
        darg.extend_from_slice(&0u16.to_le_bytes()); // max = 0 → all
        let n = ks.dispatch(wire::KS_DRAIN, &darg, &mut small, &mut fence);
        assert_eq!(n, one_event as i32);
        assert_eq!(small[0], wire::DRAIN_EVENTS);
        assert_eq!(u32::from_le_bytes(small[1..5].try_into().unwrap()), 1); // only one fit
        assert_eq!(u64::from_le_bytes(small[5..13].try_into().unwrap()), 1); // rev 1 (/k/a)

        // Drain the remainder into a large buffer: the two that did not fit are
        // still there, in order — no silent loss.
        let n = ks.dispatch(wire::KS_DRAIN, &darg, &mut big, &mut fence);
        assert!(n > 0);
        assert_eq!(u32::from_le_bytes(big[1..5].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(big[5..13].try_into().unwrap()), 2); // rev 2 (/k/b) next

        // A buffer too small for even the first event consumes nothing and
        // reports short — the events remain for a later, larger drain.
        assert_eq!(
            ks.dispatch(
                wire::KS_PUT,
                &put_arg("/k/d", u64::MAX, b"1"),
                &mut big,
                &mut fence
            ),
            8
        );
        let mut tiny = [0u8; 10];
        assert_eq!(
            ks.dispatch(wire::KS_DRAIN, &darg, &mut tiny, &mut fence),
            wire::E_NOSPC
        );
        ks.dispatch(wire::KS_DRAIN, &darg, &mut big, &mut fence);
        assert_eq!(u32::from_le_bytes(big[1..5].try_into().unwrap()), 1); // /k/d survived
    }
}
