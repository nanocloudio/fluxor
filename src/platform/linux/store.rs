//! Local versioned watchable store — the in-runtime backing for the
//! `storage.object` (0x14) and `storage.namespace` (0x13) contracts on Linux.
//!
//! A versioned watchable KV is not a bespoke contract: it decomposes into the
//! standard storage surfaces (`storage.object` CAS and LIST,
//! `storage.namespace` LIST/SUBSCRIBE/TAKE_RUNG/CHANGES, and a
//! `RevisionMonotone` fence). This module implements that decomposition: a
//! keyed byte store with a monotone revision clock, per-key revision (the CAS
//! token / etag), prefix enumeration, and a bounded key-only change history
//! that `CHANGES` pages from and the subscription pump rings from.
//!
//! A subscription is a doorbell: the store never writes a subscriber's
//! channel. It keeps one *rung* bit per subscription and signals the
//! subscriber's own kernel event when a change under the prefix finds the bit
//! clear; the subscriber asks `TAKE_RUNG` which of its subscriptions rang and
//! reads each with `CHANGES`, which answers from the history at the store's
//! current state, one bounded page per call.
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

/// One entry of the change history: which key a revision touched, and how.
/// Key-only — a `CHANGES` read takes the key's value at the store's current
/// state, never a copy kept here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub revision: u64,
    pub key: String,
    /// What the write did to the key. A hint for the record's
    /// Added-versus-Modified label; whether the key is present is read from
    /// the store, never from here.
    pub kind: ChangeKind,
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

struct Entry {
    value: Vec<u8>,
    revision: u64,
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
///
/// Every write takes exactly one revision and touches exactly one key, so the
/// history holds one entry per revision, in revision order. That is what lets
/// a `CHANGES` page always cut at a revision boundary and resume from a bare
/// revision.
pub struct Store {
    entries: BTreeMap<String, Entry>,
    revision: u64,
    /// The changes after `history_base`, oldest first, at most `history_cap`.
    history: VecDeque<Change>,
    history_cap: usize,
    /// The history covers every revision after this one: the revision of the
    /// newest entry dropped off its front, 0 while none has been. A `since`
    /// below it is a point the history can no longer answer.
    history_base: u64,
    /// The revision each absent key was deleted at, for keys whose delete the
    /// history still holds: what a `CHANGES` read reports a `Deleted` record
    /// at, and how it tells a delete it is looking at from a later one.
    tombstones: BTreeMap<String, u64>,
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

/// History entries one `CHANGES` call walks at most, and keys one relist page
/// walks at most: the per-call budget the contract says a provider states. A
/// page that spends it answers `more` and the caller asks again.
pub const CHANGES_SCAN_BUDGET: usize = 4096;

/// The kind byte a relist continuation opens with:
/// `[TOKEN_RELIST][pinned revision u64 LE][cursor key]`. Never 8 bytes long
/// (the cursor is a non-empty key), so it never reads as a bare revision.
const TOKEN_RELIST: u8 = 1;
/// A relist continuation's bytes before its cursor.
const RELIST_TOKEN_HEAD: usize = 1 + 8;

impl Store {
    pub fn new() -> Self {
        Self::with_limits(4096)
    }

    /// `history_cap` bounds how far back a `CHANGES since` read reaches: past
    /// it the read answers LOST and the reader relists.
    pub fn with_limits(history_cap: usize) -> Self {
        Store {
            entries: BTreeMap::new(),
            revision: 0,
            history: VecDeque::new(),
            history_cap: history_cap.max(1),
            history_base: 0,
            tombstones: BTreeMap::new(),
            log: None,
        }
    }

    /// Open a durable store, replaying its append log at `dir/store.log` to
    /// rebuild the map, the revision clock, and the tail of the change history.
    pub fn open(dir: &Path, history_cap: usize) -> std::io::Result<Self> {
        let created = !dir.exists();
        std::fs::create_dir_all(dir)?;
        let mut store = Self::with_limits(history_cap);
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
    /// `apply`, so history retains it for a reader resuming from before it.
    fn replay(&mut self, rev: u64, op: u8, key: String, value: Vec<u8>) {
        self.revision = self.revision.max(rev);
        self.apply(rev, op, &key, value);
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
        self.apply(rev, op, key, value);
    }

    /// Apply one write to the map and record it in the history.
    fn apply(&mut self, rev: u64, op: u8, key: &str, value: Vec<u8>) {
        let kind = if op == OP_DELETE {
            self.entries.remove(key);
            self.tombstones.insert(key.to_string(), rev);
            ChangeKind::Deleted
        } else {
            self.tombstones.remove(key);
            let existed = self
                .entries
                .insert(
                    key.to_string(),
                    Entry {
                        value,
                        revision: rev,
                    },
                )
                .is_some();
            if existed {
                ChangeKind::Modified
            } else {
                ChangeKind::Added
            }
        };
        self.record(Change {
            revision: rev,
            key: key.to_string(),
            kind,
        });
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
    /// subsequent `CHANGES since` resumes from with no gap.
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
        self.walk(prefix, after)
            .map(|(k, e)| (k, e.value.len() as u64, e.revision))
    }

    /// The entries under the byte `prefix` in key order, strictly after
    /// `after` when given.
    fn walk<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a str>,
    ) -> impl Iterator<Item = (&'a str, &'a Entry)> + 'a {
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
            .map(|(k, e)| (k.as_str(), e))
    }

    /// The history entries after `since`, oldest first.
    fn history_after(&self, since: u64) -> impl Iterator<Item = &Change> {
        let start = self.history.partition_point(|c| c.revision <= since);
        self.history.range(start..)
    }

    /// The lowest `since` the history still answers: a `CHANGES since` below
    /// it is LOST.
    pub fn history_base(&self) -> u64 {
        self.history_base
    }

    /// One `CHANGES` page under the byte `prefix`, resumed from `token`, into
    /// `out` — the [`namespace::CHANGES`](ns_op::CHANGES) answer, its length
    /// or a negative errno. `budget` bounds the history entries (or, for a
    /// relist, the keys) the call walks.
    ///
    /// Tokens: empty is a relist; 8 bytes a bare revision `since`; anything
    /// else must be a relist continuation this store issued (`EINVAL`
    /// otherwise). A history page always cuts at a revision boundary (one
    /// entry per revision), so its continuation is itself a bare revision.
    pub fn changes(&self, prefix: &[u8], token: &[u8], out: &mut [u8], budget: usize) -> i32 {
        let budget = budget.max(1);
        if token.is_empty() {
            return self.relist(prefix, self.revision, None, out, budget);
        }
        if let Some(since) = ns_op::changes::token_revision(token) {
            return self.changes_since(prefix, since, out, budget);
        }
        if token.len() <= RELIST_TOKEN_HEAD || token[0] != TOKEN_RELIST {
            return errno::EINVAL;
        }
        let pinned = u64::from_le_bytes(token[1..RELIST_TOKEN_HEAD].try_into().unwrap());
        let after = match list_cursor(&token[RELIST_TOKEN_HEAD..], prefix) {
            Ok(Some(after)) => after,
            _ => return errno::EINVAL,
        };
        if pinned > self.revision {
            return errno::EINVAL;
        }
        // The relist ends by handing the reader `pinned` to resume from; a
        // history that no longer reaches back to it would answer that resume
        // LOST, so the relist is LOST now rather than finished for nothing.
        if pinned < self.history_base {
            return lost(out);
        }
        self.relist(prefix, pinned, Some(after), out, budget)
    }

    /// A history page: one record per key under `prefix` with an entry after
    /// `since`, read at the current state.
    ///
    /// A key is reported at its LAST entry in the history — its current
    /// `mod_rev`, or the revision of the delete that left it absent — and
    /// passed over at every earlier one. So intermediate versions collapse,
    /// no record's `mod_rev` lies past the page's cut (the entry that holds
    /// it is on this page or a later one), and a key created and deleted
    /// inside the window is reported `Deleted`, never omitted.
    fn changes_since(&self, prefix: &[u8], since: u64, out: &mut [u8], budget: usize) -> i32 {
        use ns_op::changes as ch;
        // A point the history cannot answer — dropped off its front, or never
        // reached — is LOST, never an empty "nothing changed".
        if since < self.history_base || since > self.revision {
            return lost(out);
        }
        let Some(mut page) = ch::PageWriter::new(out, ch::REVISION_TOKEN_LEN) else {
            return errno::ENOMEM;
        };
        // The hint of the first entry this page saw for a key it passed over:
        // a key created earlier in the window is labelled Added.
        let mut first_hint: BTreeMap<&str, ChangeKind> = BTreeMap::new();
        let mut cut = since;
        let mut more = false;
        for (scanned, c) in self.history_after(since).enumerate() {
            if scanned == budget {
                more = true;
                break;
            }
            if c.key.as_bytes().starts_with(prefix) {
                if c.key.len() > STORAGE_KEY_MAX {
                    return errno::EOVERFLOW;
                }
                let present = self.entries.get(&c.key);
                let last = match present {
                    Some(e) => e.revision,
                    None => self.tombstones.get(&c.key).copied().unwrap_or(c.revision),
                };
                if last > c.revision {
                    first_hint.entry(c.key.as_str()).or_insert(c.kind);
                } else {
                    let (kind, val) = match present {
                        None => (ch::KIND_DELETED, &[][..]),
                        Some(e) => {
                            let hint = first_hint.get(c.key.as_str()).copied().unwrap_or(c.kind);
                            let kind = if hint == ChangeKind::Added {
                                ch::KIND_ADDED
                            } else {
                                ch::KIND_MODIFIED
                            };
                            (kind, e.value.as_slice())
                        }
                    };
                    if !page.push(c.revision, kind, c.key.as_bytes(), val) {
                        more = true;
                        break;
                    }
                }
            }
            cut = c.revision;
        }
        if more && cut == since {
            // Not even the first record fits: no progress.
            return errno::ENOMEM;
        }
        if !more {
            // The walk reached the newest entry: every revision through now
            // is covered.
            cut = self.revision;
        }
        match page.finish(more, cut, &ch::revision_token(cut)) {
            Some(n) => n as i32,
            None => errno::ENOMEM,
        }
    }

    /// A relist page: the keys under `prefix` after `after`, in key order,
    /// `Added` with their values, the walk pinned at revision `pinned`.
    ///
    /// A key changed after `pinned` is passed over: it has a history entry
    /// after `pinned`, so the `CHANGES since pinned` that follows the relist
    /// reports it, and no relist record carries a `mod_rev` past the point
    /// the reader resumes from. Nothing is delivered whole until the walk
    /// ends, so a page with `more` set carries `safe_rev` 0; the last carries
    /// `pinned`, as its bare revision token.
    fn relist(
        &self,
        prefix: &[u8],
        pinned: u64,
        after: Option<&str>,
        out: &mut [u8],
        budget: usize,
    ) -> i32 {
        use ns_op::changes as ch;
        let Some(mut page) = ch::PageWriter::new(out, RELIST_TOKEN_HEAD + STORAGE_KEY_MAX) else {
            return errno::ENOMEM;
        };
        let mut last: Option<&str> = None;
        let mut more = false;
        for (scanned, (key, e)) in self.walk(prefix, after).enumerate() {
            if scanned == budget {
                more = true;
                break;
            }
            if key.len() > STORAGE_KEY_MAX {
                return errno::EOVERFLOW;
            }
            if e.revision <= pinned
                && !page.push(e.revision, ch::KIND_ADDED, key.as_bytes(), &e.value)
            {
                more = true;
                break;
            }
            last = Some(key);
        }
        let n = match (more, last) {
            (false, _) => page.finish(false, pinned, &ch::revision_token(pinned)),
            // Not even the first record fits: no progress.
            (true, None) => return errno::ENOMEM,
            (true, Some(key)) => {
                let mut token = [0u8; RELIST_TOKEN_HEAD + STORAGE_KEY_MAX];
                token[0] = TOKEN_RELIST;
                token[1..RELIST_TOKEN_HEAD].copy_from_slice(&pinned.to_le_bytes());
                token[RELIST_TOKEN_HEAD..RELIST_TOKEN_HEAD + key.len()]
                    .copy_from_slice(key.as_bytes());
                page.finish(true, 0, &token[..RELIST_TOKEN_HEAD + key.len()])
            }
        };
        match n {
            Some(n) => n as i32,
            None => errno::ENOMEM,
        }
    }

    fn record(&mut self, change: Change) {
        self.history.push_back(change);
        while self.history.len() > self.history_cap {
            let Some(old) = self.history.pop_front() else {
                break;
            };
            self.history_base = old.revision;
            // A delete the history no longer holds is no longer asked about.
            if old.kind == ChangeKind::Deleted
                && self.tombstones.get(&old.key) == Some(&old.revision)
            {
                self.tombstones.remove(&old.key);
            }
        }
    }
}

/// Write a LOST page — the reader relists — into `out`.
fn lost(out: &mut [u8]) -> i32 {
    match ns_op::changes::write_lost(out) {
        Some(n) => n as i32,
        None => errno::ENOMEM,
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
use crate::kernel::ipc::fd::{
    slot_of, tag_fd, untag_fd, FD_TAG_EVENT, FD_TAG_STORAGE_NAMESPACE, FD_TAG_STORAGE_OBJECT,
};
use crate::kernel::sys::errno;
use crate::kernel::workload::owner::{OwnerHandle, OWNER_SYSTEM};
use crate::kernel::workload::storage::store_entry_cost;

/// A fixed 16-byte source id for this store's fences (ObjectId).
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

use crate::abi::contracts::resource as res;

/// The ceiling the boot plan gives `pool` (`resource_ledger::plan`): for the
/// node store's subscriptions, what the graph's store consumers declare plus
/// the reserve; for its reads, writes and grants, and for a workload store's
/// tables, the envelope entry or the profile's default.
fn plan_ceiling(pool: u16) -> usize {
    crate::kernel::sys::resource_ledger::ceiling(pool) as usize
}

/// A subscription: a prefix, the event that is its doorbell, and the rung
/// bit that coalesces its rings until the subscriber takes them.
#[derive(Clone)]
struct Sub {
    in_use: bool,
    prefix: String,
    /// The subscriber's event, as a raw event slot.
    event: i32,
    /// Set when a change rang the subscription; cleared by `TAKE_RUNG`. A
    /// change that finds it set signals nothing: the take still to come
    /// follows the change.
    rung: bool,
    /// The owner that subscribed, which the slot goes with.
    opener: OwnerHandle,
    /// The module occupancy that subscribed: it must still stand, and still
    /// own `event`, for the subscription to be signalled.
    module: Occupancy,
}
const SUB_EMPTY: Sub = Sub {
    in_use: false,
    prefix: String::new(),
    event: -1,
    rung: false,
    opener: OWNER_SYSTEM,
    module: Occupancy {
        idx: usize::MAX,
        generation: 0,
    },
};

/// One module occupancy: a slot and the generation it held. The slot's
/// generation moves whenever the slot is reset, restarted or reassigned, so
/// a stale stamp is detectable without being told.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Occupancy {
    idx: usize,
    generation: u32,
}

impl Occupancy {
    /// The module whose call this is — the host store runs in its caller's
    /// own context, so the current module, the one `event::CREATE` stamps an
    /// event with — or `None` outside any module.
    fn caller() -> Option<Self> {
        use crate::kernel::exec::scheduler;
        let idx = scheduler::current_module_index();
        (idx < scheduler::module_slots()).then(|| Occupancy {
            idx,
            generation: scheduler::module_slot_generation(idx),
        })
    }

    /// The slot still holds this generation and its module has not finished.
    fn live(self) -> bool {
        use crate::kernel::exec::scheduler;
        self.idx < scheduler::module_slots()
            && scheduler::module_slot_generation(self.idx) == self.generation
            && !scheduler::module_is_finished(self.idx)
    }

    /// This occupancy's module owns event slot `event`.
    fn owns_event(self, event: i32) -> bool {
        crate::kernel::ipc::event::event_owner(event).map(usize::from) == Some(self.idx)
    }
}

/// The raw event slot a tagged event fd names, or `None` when `fd` is not one.
fn event_slot(fd: i32) -> Option<i32> {
    let (tag, slot) = untag_fd(fd);
    (fd >= 0 && tag == FD_TAG_EVENT).then_some(slot)
}

/// Whether `s` may still be signalled: its module occupancy stands and its
/// event still belongs to that module. A subscription that fails this is
/// dead — its module is gone, or its event slot now another module's — and
/// is dropped rather than signalled.
fn sub_alive(s: &Sub) -> bool {
    s.in_use && s.module.live() && s.module.owns_event(s.event)
}

/// Ring `s`: set its rung bit and signal its event, unless the bit is
/// already set. A dead subscription is dropped instead, before any signal,
/// and so is one whose event the kernel no longer has.
fn ring(s: &mut Sub) {
    if !s.in_use || s.rung {
        return;
    }
    if !sub_alive(s) {
        *s = SUB_EMPTY;
        return;
    }
    s.rung = true;
    if crate::kernel::ipc::event::event_signal(s.event) == errno::EINVAL {
        *s = SUB_EMPTY;
    }
}

/// Drop every dead subscription in `subs`: what a refusal at capacity sweeps
/// first, so a table full of subscribers that are gone refuses no one.
fn reap_dead(subs: &mut [Sub]) {
    for s in subs.iter_mut().filter(|s| s.in_use && !sub_alive(s)) {
        *s = SUB_EMPTY;
    }
}

/// A GET-opened read slot: a value snapshot the caller drains via RANGE_GET.
struct ReadSlot {
    in_use: bool,
    value: Vec<u8>,
    revision: u64,
    /// The grant the slot was opened under, which it dies with.
    grant: Option<usize>,
    /// The owner that opened the slot, which it goes with.
    opener: OwnerHandle,
}
const READ_EMPTY: ReadSlot = ReadSlot {
    in_use: false,
    value: Vec::new(),
    revision: 0,
    grant: None,
    opener: OWNER_SYSTEM,
};

/// A `PUT_STREAMED_OPEN`-opened write slot: the bytes staged so far, and the
/// condition the commit will be judged by.
///
/// Staged in memory because that is where this store keeps objects anyway —
/// `PUT` takes a whole body and `apply_local` holds it — so a temp file would
/// buy nothing a single-shot `PUT` does not already pay. `STORE_STAGE_MAX`
/// bounds one stream so a caller that never commits is refused rather than
/// being allowed to exhaust the node; a provider for bulk objects stages to
/// disk instead and advertises the same contract.
struct WriteSlot {
    in_use: bool,
    /// Set by `COMMIT`: the bytes have landed and the handle awaits `CLOSE`.
    committed: bool,
    key: String,
    staged: Vec<u8>,
    /// Stated at `OPEN`, evaluated at `COMMIT` — the contract's single
    /// linearization point, which is why it is kept rather than checked here.
    precondition: Precondition,
    /// The grant the slot was opened under, which it dies with.
    grant: Option<usize>,
    /// The owner that opened the slot, which it goes with.
    opener: OwnerHandle,
}
const WRITE_EMPTY: WriteSlot = WriteSlot {
    in_use: false,
    committed: false,
    key: String::new(),
    staged: Vec::new(),
    precondition: Precondition::Any,
    grant: None,
    opener: OWNER_SYSTEM,
};

/// A store and the handles its callers hold on it: the `GET` reads, streamed
/// writes and subscriptions a handle names. Every store has tables of its
/// own, so a handle names a slot only of the store its caller is served by:
/// one owner's handle, forged by another, reaches nothing of the first's.
pub struct Served {
    store: Store,
    subs: Vec<Sub>,
    reads: Vec<ReadSlot>,
    writes: Vec<WriteSlot>,
    /// Bytes one streaming write may stage before `COMMIT`.
    stage_max: usize,
    /// The pools the tables are sized from, `[subs, reads, writes]`: what a
    /// refusal names.
    pools: [u16; 3],
    /// The revision the subscription pump has rung through: the history
    /// after it is what the next pump matches against the subscriptions.
    pumped: u64,
}

/// Refuse a slot past a table's ceiling: count it against `pool` and name it,
/// since a silently refused watch is a controller that silently stops.
fn refuse_slot(pool: u16, len: usize) -> i32 {
    log::warn!(
        "[store] pool '{}' at its ceiling of {len} slots; refused",
        crate::kernel::sys::resource_ledger::pool_name(pool)
    );
    crate::kernel::sys::resource_ledger::deny(pool);
    errno::ENOMEM
}

/// The node store's pools.
const NODE_POOLS: [u16; 3] = [
    res::POOL_STORE_SUBS,
    res::POOL_STORE_READS,
    res::POOL_STORE_WRITES,
];
/// A workload store's pools.
const OWNER_POOLS: [u16; 3] = [
    res::POOL_OWNER_STORE_SUBS,
    res::POOL_OWNER_STORE_READS,
    res::POOL_OWNER_STORE_WRITES,
];

impl Served {
    fn with_tables(store: Store, pools: [u16; 3], stage_max: usize) -> Self {
        let mut served = Self {
            pumped: store.revision(),
            store,
            subs: Vec::new(),
            reads: Vec::new(),
            writes: Vec::new(),
            stage_max,
            pools,
        };
        served.size_tables();
        served
    }

    /// Grow the tables to the plan's ceilings. Slots in use keep their place
    /// (a handle names a slot index); a table already past its ceiling keeps
    /// its slots, since a slot a live handle names cannot be taken away.
    fn size_tables(&mut self) {
        let [subs, reads, writes] = self.pools.map(plan_ceiling);
        if self.subs.len() < subs {
            self.subs.resize(subs, SUB_EMPTY);
        }
        while self.reads.len() < reads {
            self.reads.push(READ_EMPTY);
        }
        while self.writes.len() < writes {
            self.writes.push(WRITE_EMPTY);
        }
    }

    /// The node's control-plane store.
    fn node(store: Store) -> Self {
        Self::with_tables(store, NODE_POOLS, STORE_STAGE_MAX)
    }

    /// A workload's own store, with tables sized for one tenant.
    pub fn owner(store: Store) -> Self {
        Self::with_tables(store, OWNER_POOLS, OWNER_STAGE_MAX)
    }

    /// What the store's live entries cost an owner holding them: see
    /// [`store_entry_cost`].
    pub fn held_bytes(&self) -> u64 {
        self.store
            .scan(b"", None)
            .map(|(key, size, _)| store_entry_cost(key.len(), size as usize))
            .sum()
    }
}

/// Bytes one of a workload store's streamed writes may stage.
const OWNER_STAGE_MAX: usize = 16 * 1024 * 1024;

/// Bytes one streaming write may stage before `COMMIT`. Past it the write is
/// refused `ENOSPC` rather than growing until the node dies.
const STORE_STAGE_MAX: usize = 64 * 1024 * 1024;

/// Most a `PUT_STREAMED_OPEN` size hint may reserve up front. The hint is the
/// caller's, so it is taken as advice and not as an allocation request; past
/// this the staging buffer grows as the bytes arrive.
const STORE_STAGE_RESERVE_MAX: u64 = 1024 * 1024;

/// Grants presented to a guarded store at once: the plan's `store_grants`
/// ceiling. A presentation past it is refused `ENOMEM` until one is closed;
/// none is evicted, because an evicted grant is a caller whose next operation
/// silently starts failing.
fn store_max_grants() -> usize {
    plan_ceiling(res::POOL_STORE_GRANTS)
}

/// Streaming-write handles are store slots from here up to `GRANT_SLOT_BASE`.
/// A band of its own, so a handle names exactly one kind of slot and the
/// grant-close path below cannot mistake a write for a grant.
const WRITE_SLOT_BASE: usize = 0x8000;

/// Grant handles are store slots from here up, apart from read and write
/// slots.
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

/// The node's control-plane store and its handle tables.
static mut LINUX_STORE: Option<Served> = None;

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
    match Store::open(std::path::Path::new(&dir), 65536) {
        Ok(s) => {
            LINUX_STORE = Some(Served::node(s));
            StoreInit::Opened
        }
        Err(_) => StoreInit::Failed,
    }
}

/// Grow the node store's tables to the boot plan's ceilings, and make room
/// for its grants. Called when a graph is prepared, after the plan.
///
/// # Safety
/// Graph-preparation context on the scheduler thread.
pub unsafe fn size_from_plan() {
    if let Some(served) = (*core::ptr::addr_of_mut!(LINUX_STORE)).as_mut() {
        served.size_tables();
    }
    let grants = &mut *core::ptr::addr_of_mut!(GRANTS);
    let want = store_max_grants();
    if grants.capacity() < want {
        grants.reserve(want - grants.len());
    }
}

/// Slots of the node store's `pool` table in use — the resource ledger's
/// sample for the store pools.
pub fn pool_in_use(pool: u16) -> usize {
    // SAFETY: a read-only walk on the scheduler thread.
    unsafe {
        if pool == res::POOL_STORE_GRANTS {
            return (*core::ptr::addr_of!(GRANTS))
                .iter()
                .filter(|g| g.is_some())
                .count();
        }
        let Some(served) = (*core::ptr::addr_of!(LINUX_STORE)).as_ref() else {
            return 0;
        };
        match pool {
            res::POOL_STORE_SUBS => served.subs.iter().filter(|s| s.in_use).count(),
            res::POOL_STORE_READS => served.reads.iter().filter(|r| r.in_use).count(),
            res::POOL_STORE_WRITES => served.writes.iter().filter(|w| w.in_use).count(),
            _ => 0,
        }
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

/// The streaming-write slot `handle` names in `writes`, if it is a live one
/// `opener` opened: a slot answers its opener alone.
fn write_of(writes: &[WriteSlot], handle: i32, opener: OwnerHandle) -> Option<usize> {
    if handle < 0 {
        return None;
    }
    let slot = slot_of(handle) as usize;
    let i = slot.checked_sub(WRITE_SLOT_BASE)?;
    if slot >= GRANT_SLOT_BASE || i >= writes.len() {
        return None;
    }
    (writes[i].in_use && writes[i].opener == opener).then_some(i)
}

/// The `GET` read slot `handle` names in `reads`, if it is a live one
/// `opener` opened: a slot answers its opener alone.
fn read_of(reads: &[ReadSlot], handle: i32, opener: OwnerHandle) -> Option<usize> {
    if handle < 0 {
        return None;
    }
    let i = slot_of(handle) as usize;
    reads
        .get(i)
        .is_some_and(|r| r.in_use && r.opener == opener)
        .then_some(i)
}

/// The grant `handle` names, if it is a live one the caller owns.
unsafe fn grant_of(handle: i32) -> Option<usize> {
    if handle < 0 {
        return None;
    }
    let slot = slot_of(handle) as usize;
    let i = slot.checked_sub(GRANT_SLOT_BASE)?;
    let g = (&*core::ptr::addr_of!(GRANTS)).get(i)?.as_ref()?;
    let owner = crate::kernel::exec::scheduler::current_module_index();
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
        None if grants.len() < store_max_grants() => {
            grants.push(None);
            grants.len() - 1
        }
        None => {
            log::warn!(
                "[store] pool 'store_grants' at its ceiling of {} grants; refused",
                grants.len()
            );
            crate::kernel::sys::resource_ledger::deny(res::POOL_STORE_GRANTS);
            return errno::ENOMEM;
        }
    };
    let owner = crate::kernel::exec::scheduler::current_module_index();
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
unsafe fn admit(
    reads: &[ReadSlot],
    writes: &[WriteSlot],
    handle: i32,
    opcode: u32,
    a: &[u8],
) -> Result<Option<usize>, i32> {
    let Some(access) = obj_op::grant::access_of(opcode) else {
        return Ok(None);
    };
    if opcode == obj_op::RANGE_GET {
        // A read handle carries the grant it was opened under.
        let opener = crate::kernel::exec::scheduler::caller_owner();
        return match read_of(reads, handle, opener).and_then(|i| reads[i].grant) {
            Some(g) if grant_live(g) => Ok(None),
            _ => Err(errno::EACCES),
        };
    }
    if matches!(
        opcode,
        obj_op::PUT_STREAMED_WRITE | obj_op::PUT_STREAMED_COMMIT | obj_op::PUT_STREAMED_ABORT
    ) {
        // Likewise a write handle: the key was scoped once at OPEN, and the
        // grant is re-checked for life on every call so closing it stops a
        // stream already running.
        let opener = crate::kernel::exec::scheduler::caller_owner();
        return match write_of(writes, handle, opener).and_then(|i| writes[i].grant) {
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

unsafe fn store_ref() -> Option<&'static mut Served> {
    (*core::ptr::addr_of_mut!(LINUX_STORE)).as_mut()
}

/// Close every handle `opener` holds on the node's store: its `GET` reads,
/// its streamed writes (their staged bytes dropped, nothing committed) and
/// its subscriptions. Part of the platform's owner-release hook, for an
/// owner that acted with the node's authority: what it opened goes with it.
/// A workload's own store goes whole with its root.
///
/// # Safety
/// Single-threaded platform dispatch only.
pub unsafe fn release_opener(opener: OwnerHandle) {
    let Some(served) = store_ref() else {
        return;
    };
    for r in served
        .reads
        .iter_mut()
        .filter(|r| r.in_use && r.opener == opener)
    {
        *r = READ_EMPTY;
    }
    for w in served
        .writes
        .iter_mut()
        .filter(|w| w.in_use && w.opener == opener)
    {
        // The node's store charges no one: there is nothing to give back.
        *w = WRITE_EMPTY;
    }
    for s in served
        .subs
        .iter_mut()
        .filter(|s| s.in_use && s.opener == opener)
    {
        *s = SUB_EMPTY;
    }
}

/// What a `PUT` changes in its owner's charge: the cost of the new entry
/// over the one it replaces, or the other way round.
struct PutCharge {
    add: u64,
    give: u64,
}

/// Charge `owner` for a `PUT` of a `len`-byte value under `key` before it
/// runs: the growth is charged now, and a shrink is given back only once the
/// write lands. `None` when the owner's cap refuses the growth.
fn charge_put(store: &Store, owner: OwnerHandle, key: &str, len: usize) -> Option<PutCharge> {
    let old = store
        .get(key)
        .map(|(v, _)| store_entry_cost(key.len(), v.len()))
        .unwrap_or(0);
    let new = store_entry_cost(key.len(), len);
    let c = PutCharge {
        add: new.saturating_sub(old),
        give: old.saturating_sub(new),
    };
    if c.add > 0 && !charge(owner, c.add) {
        return None;
    }
    Some(c)
}

/// Settle a `PUT`'s charge once it is decided: a landed write gives back
/// what the replaced entry cost over the new one, a refused one what was
/// charged for it.
fn settle_put(owner: OwnerHandle, c: PutCharge, landed: bool) {
    release(owner, if landed { c.give } else { c.add });
}

/// Charge `bytes` to `owner`'s storage; `false` when its cap refuses.
fn charge(owner: OwnerHandle, bytes: u64) -> bool {
    bytes == 0
        || crate::kernel::exec::scheduler::owners_mut()
            .charge_storage(owner, bytes)
            .is_ok()
}

/// Give `bytes` of storage back to `owner`.
fn release(owner: OwnerHandle, bytes: u64) {
    if bytes > 0 {
        crate::kernel::exec::scheduler::owners_mut().release_storage(owner, bytes);
    }
}

/// Free a streamed write's slot, giving back what it had staged and not
/// committed.
fn drop_write(owner: OwnerHandle, w: &mut WriteSlot) {
    if !w.committed {
        release(owner, w.staged.len() as u64);
    }
    *w = WRITE_EMPTY;
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

/// A key a `PUT` may create. Empty is the "end of listing" cursor on `LIST`
/// and a relist's token on `CHANGES`; longer than `STORAGE_KEY_MAX` cannot be
/// carried by a listing or a change record.
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

// ---- subscription pump ----

/// Ring every subscription whose prefix holds a key the history recorded
/// since the last pump, then mark the history pumped through now. A pump that
/// finds the history has dropped revisions it never matched rings every
/// subscription: it cannot tell which prefixes they touched, and a spurious
/// ring costs one empty read where a missed one is a change never seen.
///
/// Synchronous — the pump point is the write itself (there is no async
/// provider callback). Writes no channel: a ring is a rung bit and an event
/// signal.
fn pump(store: &Store, subs: &mut [Sub], pumped: &mut u64) {
    if *pumped < store.history_base() {
        subs.iter_mut().for_each(ring);
    } else {
        for c in store.history_after(*pumped) {
            for s in subs
                .iter_mut()
                .filter(|s| s.in_use && c.key.starts_with(s.prefix.as_str()))
            {
                ring(s);
            }
        }
    }
    *pumped = store.revision();
}

// ---- storage.object dispatch (routed here when the store is active) ----

/// Handle a `storage.object` op against the control-plane store. Returns the
/// contract's i32 (bytes/handle/0 or negative errno).
/// # Safety
/// Single-threaded platform dispatch only: touches `static mut` provider
/// state without synchronization. `arg` must be null or valid for reads
/// and writes of `arg_len` bytes for the duration of the call.
pub unsafe fn dispatch_object(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let Some(served) = store_ref() else {
        return errno::ENOSYS;
    };
    dispatch_object_on(served, guarded(), handle, opcode, arg, arg_len)
}

/// [`dispatch_object`] against `served`: the node's store, or an owner's
/// own, which is never guarded. What an entry costs (see [`store_entry_cost`]) is
/// charged to the caller's owner as it is written, staged bytes while they
/// are staged, and a `DELETE` gives it back.
///
/// # Safety
/// As [`dispatch_object`].
pub unsafe fn dispatch_object_on(
    served: &mut Served,
    guarded: bool,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    // A slot goes with the owner that opened it; what is written is charged
    // to the authority the caller acts with — the node, which is never
    // charged, for its own modules and for an owner acting with its
    // authority.
    let opener = crate::kernel::exec::scheduler::caller_owner();
    let owner = crate::kernel::exec::scheduler::caller_authority();
    let stage_max = served.stage_max;
    let pools = served.pools;
    let store = &mut served.store;
    let subs = &mut served.subs;
    let pumped = &mut served.pumped;
    let reads = &mut served.reads;
    let writes = &mut served.writes;

    // Per-handle fence introspection for a GET-opened read slot.
    if opcode == QUERY_OP {
        if arg.is_null() || arg_len < WIRE_MAX_LEN {
            return errno::EINVAL;
        }
        let Some(idx) = read_of(reads, handle, opener) else {
            return errno::ENOSYS;
        };
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
        if !guarded {
            return errno::ENOSYS;
        }
        return present(arg, a);
    }
    if opcode == obj_op::CLOSE && handle >= 0 && slot_of(handle) as usize >= GRANT_SLOT_BASE {
        let Some(i) = grant_of(handle) else {
            return errno::EACCES;
        };
        (&mut *core::ptr::addr_of_mut!(GRANTS))[i] = None;
        // Read and write handles opened under it die with it; a staged
        // write that is never committed is dropped, not landed.
        for r in reads.iter_mut() {
            if r.grant == Some(i) {
                *r = READ_EMPTY;
            }
        }
        for w in writes.iter_mut() {
            if w.grant == Some(i) {
                drop_write(owner, w);
            }
        }
        return 0;
    }
    let grant = if guarded {
        match admit(reads, writes, handle, opcode, a) {
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
            let Some(charged) = charge_put(store, owner, &key, body.len()) else {
                return errno::ENOSPC;
            };
            match store.put(&key, body, precondition) {
                Ok(rev) => {
                    settle_put(owner, charged, true);
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
                    pump(store, subs, pumped);
                    0
                }
                // Two answers, because they ask the caller to do two
                // different things. `EEXIST`: somebody else created this key,
                // so a create-only caller has LOST. `EAGAIN`: the key moved
                // under a compare-and-swap, so re-read and retry.
                Err(e) => {
                    settle_put(owner, charged, false);
                    match e {
                        WriteError::Conflict(_) if absent => errno::EEXIST,
                        WriteError::Conflict(_) => errno::EAGAIN,
                        WriteError::Io(_) => errno::ERROR,
                    }
                }
            }
        }
        obj_op::PUT_STREAMED_OPEN => {
            // [key_len:u16][key][ct_len:u8][ct][expected_size:u64]
            // [precondition:u8][etag_len:u8][etag]
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
            let Some(expected) = get_u64(a, p) else {
                return errno::EINVAL;
            };
            p += 8;
            // Held, not evaluated: the contract's linearization point is the
            // commit, and a key that satisfies the condition now may not when
            // the bytes land.
            let Some(precondition) = read_precondition(a, &mut p) else {
                return errno::EINVAL;
            };
            let Some(idx) = writes.iter().position(|w| !w.in_use) else {
                return refuse_slot(pools[2], writes.len());
            };
            writes[idx] = WriteSlot {
                in_use: true,
                committed: false,
                key,
                staged: Vec::with_capacity(expected.min(STORE_STAGE_RESERVE_MAX) as usize),
                precondition,
                grant,
                opener,
            };
            tag_fd(FD_TAG_STORAGE_OBJECT, (WRITE_SLOT_BASE + idx) as i32)
        }
        obj_op::PUT_STREAMED_WRITE => {
            // arg = the chunk; appended to the staged body.
            let Some(idx) = write_of(writes, handle, opener) else {
                return errno::EINVAL;
            };
            if writes[idx].committed {
                return errno::EINVAL;
            }
            if writes[idx].staged.len() + a.len() > stage_max || !charge(owner, a.len() as u64) {
                return errno::ENOSPC;
            }
            writes[idx].staged.extend_from_slice(a);
            0
        }
        obj_op::PUT_STREAMED_COMMIT => {
            // [fence_out_ptr:u64][fence_out_cap:u16]
            let Some(idx) = write_of(writes, handle, opener) else {
                return errno::EINVAL;
            };
            let Some((fence_ptr, fence_cap)) = fence_out(a, 0) else {
                return errno::EINVAL;
            };
            if writes[idx].committed {
                return errno::EINVAL;
            }
            // The staged bytes move into the store; the slot keeps its key so
            // a later CLOSE is still well formed.
            let body = core::mem::take(&mut writes[idx].staged);
            let precondition = writes[idx].precondition;
            let absent = precondition == Precondition::Absent;
            let key = writes[idx].key.clone();
            // The staged bytes stop being staged and become the entry.
            release(owner, body.len() as u64);
            let Some(charged) = charge_put(store, owner, &key, body.len()) else {
                // Still staged: the caller may abort, or commit once room is
                // made. Re-charging what was just given back always fits.
                charge(owner, body.len() as u64);
                writes[idx].staged = body;
                return errno::ENOSPC;
            };
            match store.put(&key, body, precondition) {
                Ok(rev) => {
                    settle_put(owner, charged, true);
                    // One `put`, so the same durability the single-shot path
                    // reports: the log record is synced before this returns.
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
                    pump(store, subs, pumped);
                    writes[idx].committed = true;
                    0
                }
                // As for `PUT`: a create-only caller has lost the key, or a
                // compare-and-swap caller must re-read and retry. The staged
                // bytes are gone either way — the stream is finished, and a
                // retry is a new one.
                Err(e) => {
                    settle_put(owner, charged, false);
                    match e {
                        WriteError::Conflict(_) if absent => errno::EEXIST,
                        WriteError::Conflict(_) => errno::EAGAIN,
                        WriteError::Io(_) => errno::ERROR,
                    }
                }
            }
        }
        obj_op::PUT_STREAMED_ABORT => {
            // The staged bytes are dropped and the handle released, so no
            // CLOSE follows.
            let Some(idx) = write_of(writes, handle, opener) else {
                return errno::EINVAL;
            };
            drop_write(owner, &mut writes[idx]);
            0
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
            let Some(idx) = reads.iter().position(|r| !r.in_use) else {
                return refuse_slot(pools[1], reads.len());
            };
            reads[idx] = ReadSlot {
                in_use: true,
                value: val,
                revision: rev,
                grant,
                opener,
            };
            tag_fd(FD_TAG_STORAGE_OBJECT, idx as i32)
        }
        obj_op::RANGE_GET => {
            // [offset:u64][length:u32][out_ptr:u64]
            let Some(idx) = read_of(reads, handle, opener) else {
                return errno::ENOSYS;
            };
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
            let held = store
                .get(&key)
                .map(|(v, _)| store_entry_cost(key.len(), v.len()))
                .unwrap_or(0);
            match store.delete(&key, precondition) {
                Ok(opt) => {
                    release(owner, held);
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
                    pump(store, subs, pumped);
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
            if let Some(i) = write_of(writes, handle, opener) {
                drop_write(owner, &mut writes[i]);
                return 0;
            }
            if let Some(i) = read_of(reads, handle, opener) {
                reads[i] = READ_EMPTY;
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
    let Some(served) = store_ref() else {
        return errno::ENOSYS;
    };
    dispatch_namespace_on(served, handle, opcode, arg, arg_len)
}

/// [`dispatch_namespace`] against `served`: the node's store, or an owner's
/// own.
///
/// # Safety
/// As [`dispatch_namespace`].
pub unsafe fn dispatch_namespace_on(
    served: &mut Served,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    let opener = crate::kernel::exec::scheduler::caller_owner();
    let store = &mut served.store;
    let pools = served.pools;
    let subs = &mut served.subs;
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
        // Versioned store: subscriptions (SUBSCRIBE + TAKE_RUNG) and paged
        // change reads are implemented; mutation (BIND/RENAME/DELETE) flows through the
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
            let Some(req) = ns_op::subscribe::parse(a) else {
                return errno::EINVAL;
            };
            // Keys are UTF-8, so a prefix that is not could match nothing.
            let Ok(prefix) = core::str::from_utf8(req.prefix) else {
                return errno::EINVAL;
            };
            // The doorbell must be the calling module's own event: a
            // subscription on another module's event would wake a stranger.
            let (Some(event), Some(module)) = (event_slot(req.event), Occupancy::caller()) else {
                return errno::EINVAL;
            };
            if !module.owns_event(event) {
                return errno::EINVAL;
            }
            let ring_now = req.flags & ns_op::subscribe::FLAG_RING_NOW != 0;
            // Idempotent: a module re-running its subscribe path gets the
            // subscription it already has, never a second one.
            let same = |s: &Sub| {
                s.in_use
                    && s.opener == opener
                    && s.module == module
                    && s.event == event
                    && s.prefix == prefix
            };
            if let Some(idx) = subs.iter().position(same) {
                if ring_now {
                    ring(&mut subs[idx]);
                }
                return tag_fd(FD_TAG_STORAGE_NAMESPACE, idx as i32);
            }
            let idx = match subs.iter().position(|s| !s.in_use) {
                Some(idx) => idx,
                None => {
                    reap_dead(subs);
                    match subs.iter().position(|s| !s.in_use) {
                        Some(idx) => idx,
                        None => return refuse_slot(pools[0], subs.len()),
                    }
                }
            };
            subs[idx] = Sub {
                in_use: true,
                prefix: prefix.to_string(),
                event,
                rung: false,
                opener,
                module,
            };
            if ring_now {
                ring(&mut subs[idx]);
            }
            tag_fd(FD_TAG_STORAGE_NAMESPACE, idx as i32)
        }
        ns_op::TAKE_RUNG => {
            let Some(req) = ns_op::take::parse(a) else {
                return errno::EINVAL;
            };
            let out = core::slice::from_raw_parts_mut(req.out_ptr as *mut u8, req.out_cap as usize);
            let Some(mut answer) = ns_op::take::Writer::new(out) else {
                return errno::ENOMEM;
            };
            // Only the caller's own subscriptions on that event are named: its
            // owner and its occupancy both.
            let (Some(event), Some(module)) = (event_slot(req.event), Occupancy::caller()) else {
                return answer.finish(false) as i32;
            };
            let mut more = false;
            for (idx, s) in subs.iter_mut().enumerate() {
                if !(s.in_use
                    && s.rung
                    && s.opener == opener
                    && s.module == module
                    && s.event == event)
                {
                    continue;
                }
                if !answer.push(tag_fd(FD_TAG_STORAGE_NAMESPACE, idx as i32)) {
                    // Its bit stays set, and the event rings again so the
                    // rest is taken on the next wake.
                    more = true;
                    break;
                }
                s.rung = false;
            }
            if more && module.owns_event(event) {
                crate::kernel::ipc::event::event_signal(event);
            }
            answer.finish(more) as i32
        }
        ns_op::CHANGES => {
            let Some(req) = ns_op::changes::parse_request(a) else {
                return errno::EINVAL;
            };
            // `req.sub` names the subscription the read serves, for a
            // provider that may answer EAGAIN and re-ring it later. This one
            // answers from memory inside the call and never waits, so it has
            // nothing to re-ring.
            let out = core::slice::from_raw_parts_mut(req.out_ptr as *mut u8, req.out_cap as usize);
            let n = store.changes(req.prefix, req.token, out, CHANGES_SCAN_BUDGET);
            if n >= 0 {
                // The records were read at the current state.
                write_fence(
                    Fence::ViewConsistent {
                        source: STORE_SOURCE,
                        revision: store.revision(),
                    },
                    req.fence_out_ptr,
                    req.fence_out_cap,
                );
            }
            n
        }
        // The store enumerates and watches; it has no per-path handle.
        ns_op::LOOKUP | ns_op::STAT => errno::ENOSYS,
        ns_op::CLOSE => {
            // A subscription answers its opener alone: its owner AND its
            // module occupancy, since every node module shares the system
            // owner. To anyone else CLOSE is a no-op, as if it were not open.
            let idx = slot_of(handle) as usize;
            let module = Occupancy::caller();
            if handle >= 0
                && idx < subs.len()
                && subs[idx].in_use
                && subs[idx].opener == opener
                && Some(subs[idx].module) == module
            {
                subs[idx] = SUB_EMPTY;
            }
            0
        }
        _ => errno::ENOSYS,
    }
}
