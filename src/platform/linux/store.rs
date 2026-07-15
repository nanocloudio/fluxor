//! Local versioned watchable store — the in-runtime backing for the
//! `storage.object` (0x14) and `storage.namespace` (0x13) contracts on Linux.
//!
//! Per `.context/fluxor_nanocloud.md` §3, a versioned watchable KV is not a
//! bespoke fluxor contract — it decomposes into the standard storage surfaces
//! (`storage.object` CAS + `storage.namespace` LIST/SUBSCRIBE + a
//! `RevisionMonotone` fence). This module is the primitive-level implementation
//! of that: a keyed byte store with a monotone revision clock, per-key revision
//! (the CAS token / etag), prefix enumeration, and a bounded change history that
//! drives SUBSCRIBE with resume-from-revision.
//!
//! There is deliberately **no multi-process WAL and no `flock`**: the
//! control plane is fmods in one
//! runtime (§8), so the store is single-writer — the provider serialises calls.
//! Durability is a plain single-writer append log (no lock, no concurrent tail):
//! written by whoever runs the store, and replayed at open. That log is also the
//! seam a test harness seeds through between phases.

use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

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

/// A single-writer append log — the store's durability + seed seam. No `flock`:
/// the store has one writer at a time (the runtime, or a harness between phases).
/// Record: `[rev:u64 LE][op:u8][key_len:u16 LE][val_len:u32 LE][key][val]`.
struct Log {
    file: File,
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
        let records = parse_log(&data);
        file.seek(SeekFrom::End(0))?;
        Ok((Log { file }, records))
    }

    fn append(&mut self, rev: u64, op: u8, key: &str, value: &[u8]) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(15 + key.len() + value.len());
        buf.extend_from_slice(&rev.to_le_bytes());
        buf.push(op);
        buf.extend_from_slice(&(key.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(value);
        self.file.write_all(&buf)?;
        self.file.flush()?;
        self.file.sync_data()
    }
}

/// Parse an append log into `(rev, op, key, value)` records, stopping at the
/// first truncated tail (a crash mid-append leaves at most one partial record).
fn parse_log(data: &[u8]) -> Vec<LogRecord> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 15 <= data.len() {
        let rev = u64::from_le_bytes(data[p..p + 8].try_into().unwrap());
        let op = data[p + 8];
        let kl = u16::from_le_bytes(data[p + 9..p + 11].try_into().unwrap()) as usize;
        let vl = u32::from_le_bytes(data[p + 11..p + 15].try_into().unwrap()) as usize;
        if p + 15 + kl + vl > data.len() {
            break;
        }
        let key = match std::str::from_utf8(&data[p + 15..p + 15 + kl]) {
            Ok(k) => k.to_string(),
            Err(_) => break,
        };
        let value = data[p + 15 + kl..p + 15 + kl + vl].to_vec();
        out.push((rev, op, key, value));
        p += 15 + kl + vl;
    }
    out
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
    #[allow(
        dead_code,
        reason = "store root retained for future compaction; unread today"
    )]
    dir: Option<PathBuf>,
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
            dir: None,
        }
    }

    /// Open a durable store, replaying its append log at `dir/store.log` to
    /// rebuild the map, the revision clock, and the tail of the change history.
    pub fn open(dir: &Path, history_cap: usize, ring_cap: usize) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let mut store = Self::with_limits(history_cap, ring_cap);
        let (log, records) = Log::open(&dir.join("store.log"))?;
        for (rev, op, key, value) in records {
            store.replay(rev, op, key, value);
        }
        store.log = Some(log);
        store.dir = Some(dir.to_path_buf());
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

    /// Insert or update. `if_match`: `None` = unconditional; `Some(0)` = must not
    /// exist; `Some(r)` = current per-key revision must equal `r`. Returns the
    /// new store revision. Appends to the durable log (if any) before applying.
    pub fn put(
        &mut self,
        key: &str,
        value: Vec<u8>,
        if_match: Option<u64>,
    ) -> Result<u64, WriteError> {
        let existing_rev = self.entries.get(key).map(|e| e.revision);
        if let Some(expect) = if_match {
            let current = existing_rev.unwrap_or(0);
            if current != expect {
                return Err(WriteError::Conflict(CasConflict { current }));
            }
        }
        let rev = self.revision + 1;
        if let Some(log) = self.log.as_mut() {
            log.append(rev, OP_PUT, key, &value)
                .map_err(WriteError::Io)?;
        }
        self.apply_local(rev, OP_PUT, key, value);
        Ok(rev)
    }

    /// Remove a key. `if_match` as in `put`. Returns the new revision, or
    /// `Ok(None)` for an unconditional delete of an absent key (no-op).
    pub fn delete(&mut self, key: &str, if_match: Option<u64>) -> Result<Option<u64>, WriteError> {
        let existing_rev = self.entries.get(key).map(|e| e.revision);
        match Self::delete_precheck(if_match, existing_rev) {
            Err(conflict) => return Err(WriteError::Conflict(conflict)),
            Ok(false) => return Ok(None),
            Ok(true) => {}
        }
        let rev = self.revision + 1;
        if let Some(log) = self.log.as_mut() {
            log.append(rev, OP_DELETE, key, &[])
                .map_err(WriteError::Io)?;
        }
        self.apply_local(rev, OP_DELETE, key, Vec::new());
        Ok(Some(rev))
    }

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
            (None, None) => Ok(false),
            (None, Some(_)) => Ok(true),
        }
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
// scheduler thread (see kernel::provider), so the `static mut` singletons need
// no locking.
// ===========================================================================

use crate::abi::contracts::fence::{Fence, QUERY_OP, WIRE_MAX_LEN};
use crate::abi::contracts::storage::{namespace as ns_op, object as obj_op};
use crate::kernel::channel::channel_write;
use crate::kernel::errno;
use crate::kernel::fd::{slot_of, tag_fd, FD_TAG_STORAGE_NAMESPACE, FD_TAG_STORAGE_OBJECT};

/// mesh Event content-type for a `namespace.change` record (not yet in the mesh
/// registry — assigned here; registry addition is a follow-up).
const CT_NAMESPACE_CHANGE: u8 = 15;
/// mesh Event header size (see `modules/foundation/mesh/mesh_types.rs`).
const EVENT_HEADER_SIZE: usize = 32;

/// A fixed 16-byte source id for this store's fences/events (ObjectId).
const STORE_SOURCE: [u8; 16] = *b"fluxor-cp-store\0";

const STORE_MAX_SUBS: usize = 64;
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
}
const READ_EMPTY: ReadSlot = ReadSlot {
    in_use: false,
    value: Vec::new(),
    revision: 0,
};

static mut LINUX_STORE: Option<Store> = None;
static mut LINUX_SUBS: [Sub; STORE_MAX_SUBS] = [SUB_EMPTY; STORE_MAX_SUBS];
static mut LINUX_READS: [ReadSlot; STORE_MAX_READS] = [READ_EMPTY; STORE_MAX_READS];

/// Initialise the control-plane store from `FLUXOR_STORE_DIR`, if set. Called
/// once at provider registration. Returns true if the store is now active.
/// # Safety
/// Single-threaded platform dispatch only: initialises the `static mut`
/// store singleton without synchronization.
pub unsafe fn store_init_from_env() -> bool {
    if (*core::ptr::addr_of!(LINUX_STORE)).is_some() {
        return true;
    }
    let Ok(dir) = std::env::var("FLUXOR_STORE_DIR") else {
        return false;
    };
    match Store::open(std::path::Path::new(&dir), 65536, 4096) {
        Ok(s) => {
            LINUX_STORE = Some(s);
            true
        }
        Err(_) => false,
    }
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
fn rev_from_etag(etag: &[u8]) -> u64 {
    if etag.len() >= 8 {
        u64::from_le_bytes(etag[..8].try_into().unwrap())
    } else {
        0
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

/// Write an encoded fence into a caller `[fence_out_ptr:u64][fence_out_cap:u16]`.
unsafe fn write_fence(fence: Fence, ptr: u64, cap: u16) {
    if ptr == 0 || (cap as usize) < 25 {
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

    match opcode {
        obj_op::PUT => {
            // [key_len:u16][key][ct_len:u8][ct][body_ptr:u64][body_len:u64]
            // [if_match_len:u8][if_match][fence_out_ptr:u64][fence_out_cap:u16]
            let Some(kl) = get_u16(a, 0).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            let mut p = 2 + kl;
            let Ok(key) = core::str::from_utf8(&a[2..2 + kl]) else {
                return errno::EINVAL;
            };
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
            let Some(&iml) = a.get(p) else {
                return errno::EINVAL;
            };
            p += 1;
            let if_match = if iml == 0 {
                None
            } else {
                Some(rev_from_etag(&a[p..p + iml as usize]))
            };
            p += iml as usize;
            let fence_ptr = get_u64(a, p).unwrap_or(0);
            let fence_cap = get_u16(a, p + 8).unwrap_or(0);

            let body = if body_len == 0 {
                Vec::new()
            } else {
                core::slice::from_raw_parts(body_ptr as *const u8, body_len as usize).to_vec()
            };
            match store.put(&key, body, if_match) {
                Ok(rev) => {
                    write_fence(
                        Fence::RevisionMonotone {
                            source: STORE_SOURCE,
                            revision: rev,
                        },
                        fence_ptr,
                        fence_cap,
                    );
                    pump_subscriptions(store);
                    0
                }
                Err(WriteError::Conflict(_)) => errno::EAGAIN, // CAS conflict
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
            let Some(kl) = get_u16(a, 0).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            let Ok(key) = core::str::from_utf8(&a[2..2 + kl]) else {
                return errno::EINVAL;
            };
            let Some((val, rev)) = store.get(key) else {
                return errno::ENXIO;
            };
            let out_ptr = get_u64(a, 2 + kl).unwrap_or(0);
            let out_cap = get_u32(a, 2 + kl + 8).unwrap_or(0) as usize;
            // HEAD record: [size:u64][mtime:u64][content_type_len:u8][ct][etag_len:u8][etag]
            let etag = etag_from_rev(rev);
            let mut rec = Vec::new();
            rec.extend_from_slice(&(val.len() as u64).to_le_bytes());
            rec.extend_from_slice(&0u64.to_le_bytes());
            rec.push(0); // content_type_len
            rec.push(32); // etag_len
            rec.extend_from_slice(&etag);
            if out_ptr != 0 && rec.len() <= out_cap {
                core::ptr::copy_nonoverlapping(rec.as_ptr(), out_ptr as *mut u8, rec.len());
            }
            let fptr = get_u64(a, 2 + kl + 12).unwrap_or(0);
            let fcap = get_u16(a, 2 + kl + 20).unwrap_or(0);
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
            // [key_len:u16][key][if_match_len:u8][if_match][fence_out_ptr:u64][fence_out_cap:u16]
            let Some(kl) = get_u16(a, 0).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            let Ok(key) = core::str::from_utf8(&a[2..2 + kl]) else {
                return errno::EINVAL;
            };
            let key = key.to_string();
            let mut p = 2 + kl;
            let Some(&iml) = a.get(p) else {
                return errno::EINVAL;
            };
            p += 1;
            let if_match = if iml == 0 {
                None
            } else {
                Some(rev_from_etag(&a[p..p + iml as usize]))
            };
            p += iml as usize;
            let fptr = get_u64(a, p).unwrap_or(0);
            let fcap = get_u16(a, p + 8).unwrap_or(0);
            match store.delete(&key, if_match) {
                Ok(opt) => {
                    let rev = opt.unwrap_or_else(|| store.revision());
                    write_fence(
                        Fence::RevisionMonotone {
                            source: STORE_SOURCE,
                            revision: rev,
                        },
                        fptr,
                        fcap,
                    );
                    pump_subscriptions(store);
                    0
                }
                Err(WriteError::Conflict(_)) => errno::EAGAIN,
                Err(WriteError::Io(_)) => errno::ERROR,
            }
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
        ns_op::LIST => {
            // [prefix_len:u16][prefix][cursor_len:u16][cursor][out_buf:u64][out_cap:u32]
            // [fence_out_ptr:u64][fence_out_cap:u16]
            let Some(pl) = get_u16(a, 0).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            let Ok(prefix) = core::str::from_utf8(&a[2..2 + pl]) else {
                return errno::EINVAL;
            };
            let mut p = 2 + pl;
            let Some(cl) = get_u16(a, p).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            p += 2 + cl; // cursor ignored (single-page; store lists are small)
            let out_buf = get_u64(a, p).unwrap_or(0);
            let out_cap = get_u32(a, p + 8).unwrap_or(0) as usize;
            let fptr = get_u64(a, p + 12).unwrap_or(0);
            let fcap = get_u16(a, p + 20).unwrap_or(0);

            let (items, watermark) = store.list(prefix);
            // entries: [name_len:u8][kind:u8][name] ; trailing [0xFF][cursor_len:u16=0]
            let mut buf = Vec::new();
            for (k, _rev) in &items {
                let name = k.as_bytes();
                if name.len() > 255 {
                    continue;
                }
                buf.push(name.len() as u8);
                buf.push(ns_op::KIND_OBJECT);
                buf.extend_from_slice(name);
            }
            buf.push(0xFF);
            buf.extend_from_slice(&0u16.to_le_bytes()); // cursor_len 0 = end
            if out_buf != 0 && buf.len() <= out_cap {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), out_buf as *mut u8, buf.len());
            } else if out_buf != 0 {
                return errno::ENOMEM;
            }
            write_fence(
                Fence::ViewConsistent {
                    source: STORE_SOURCE,
                    revision: watermark,
                },
                fptr,
                fcap,
            );
            buf.len() as i32
        }
        ns_op::SUBSCRIBE => {
            // [prefix_len:u16][prefix][sink_chan:u32][flags:u8]
            let Some(pl) = get_u16(a, 0).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            let Ok(prefix) = core::str::from_utf8(&a[2..2 + pl]) else {
                return errno::EINVAL;
            };
            let prefix = prefix.to_string();
            let Some(sink_chan) = get_u32(a, 2 + pl) else {
                return errno::EINVAL;
            };
            let flags = *a.get(2 + pl + 4).unwrap_or(&0);
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
                    let _ = channel_write(sink_chan as i32, bytes.as_ptr(), bytes.len());
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
            let Some(pl) = get_u16(a, 0).map(|v| v as usize) else {
                return errno::EINVAL;
            };
            if a.len() < 2 + pl {
                return errno::EINVAL;
            }
            let Ok(prefix) = core::str::from_utf8(&a[2..2 + pl]) else {
                return errno::EINVAL;
            };
            let prefix = prefix.to_string();
            let mut p = 2 + pl;
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
        ns_op::LOOKUP => {
            // Snapshot handle over a path — reuse the SUBSCRIBE slot table's
            // sibling not needed; just return a synthetic handle (STAT reads by
            // path re-lookup). We record nothing; STAT takes the path via LIST.
            // Return a tagged handle whose slot is the read table (unused body).
            errno::ENOSYS // LOOKUP/STAT not needed by the reconcilers; deferred
        }
        ns_op::STAT => errno::ENOSYS,
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
