// ── Persistence: labelled keys as sealed records ────────────────────────
//
// A key named by a label survives a restart, because that is what an issuer
// key has to do — a signing key regenerated at every boot invalidates every
// credential the previous boot issued. It survives as a record in the
// store's image: sealed under the record key, or (`seal = none`) readable.
// `CUSTODY` reports what the sealing is worth separately: a key that
// survives a restart is not thereby protected from the host.
//
// The `persisted` table is the RAM view of the records this instance has
// read or written: their facts, their sealed bytes and the image sequence a
// fresh one waits on to be durable.

#[repr(C)]
#[derive(Clone, Copy)]
struct Persisted {
    live: bool,
    clear: bool,
    label_len: u8,
    sealed_len: u8,
    suite: u16,
    _pad: u16,
    usage: u32,
    namespace: u32,
    realm: [u8; 16],
    label: [u8; MAX_LABEL],
    /// The image sequence this record waits on to be durable; 0 once it is.
    pending: u64,
    sealed: [u8; record::MAX_SEALED],
}

impl Persisted {
    const fn empty() -> Self {
        Self {
            live: false,
            clear: false,
            label_len: 0,
            sealed_len: 0,
            suite: 0,
            _pad: 0,
            usage: 0,
            namespace: 0,
            realm: NODE_REALM,
            label: [0; MAX_LABEL],
            pending: 0,
            sealed: [0; record::MAX_SEALED],
        }
    }

    fn label_bytes(&self) -> &[u8] {
        &self.label[..usize::from(self.label_len)]
    }

    fn scope(&self) -> Scope {
        Scope {
            namespace: self.namespace,
            realm: self.realm,
        }
    }
}

fn persisted(s: &mut State) -> &mut [Persisted] {
    if s.persisted.is_null() {
        return &mut [];
    }
    // SAFETY: `persisted` names `n_persisted` entries of this instance's
    // heap, taken at construction; one call at a time.
    unsafe { core::slice::from_raw_parts_mut(s.persisted, usize::from(s.n_persisted)) }
}

/// What persisting a key achieved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Persist {
    /// Sealed and on the medium: the key survives a restart.
    Durable,
    /// No store, or no record key: the key serves this instance and does
    /// not come back. `DESCRIBE` reports it unpersisted.
    Unavailable,
    /// The store could not take it: the key is not handed out.
    Failed,
    /// In the image at this sequence, not on the medium yet: the key is not
    /// handed out until it is (the caller asks again, `EAGAIN`).
    Pending(u64),
}

/// The filing of a key of `scope` under `label`: a workload's record in this
/// node's vault is bound to its realm; a vault kept under one owner's key
/// binds none.
fn filing<'a>(s: &State, scope: &'a Scope, label: &'a [u8]) -> record::Filing<'a> {
    record::Filing {
        namespace: scope.namespace,
        realm: (!scope.is_node() && s.seal != seal_mode::OWNER).then_some(&scope.realm),
        label,
    }
}

/// Whether records are kept readable.
fn keeps_clear(s: &State) -> bool {
    s.seal == seal_mode::NONE
}

/// The labelled store cannot answer yet: its image is loading, or the
/// owner's key has not arrived. Answered as empty, a labelled open would
/// generate a fresh key over the one already stored.
fn store_not_ready(s: &State) -> bool {
    s.key_state == record_key::AWAITING || (s.image_len != 0 && !store_ready(s))
}

/// Whether a record waiting on the image at `seq` is durable yet.
fn settled(s: &State, pending: u64) -> Result<(), i32> {
    if pending == 0 {
        return Ok(());
    }
    match store_durability(s, pending) {
        Durability::Durable => Ok(()),
        Durability::Pending(_) => Err(EAGAIN),
        Durability::Failed => Err(ERROR),
    }
}

fn settle(s: &mut State, pi: usize) -> Result<(), i32> {
    let pending = persisted(s)[pi].pending;
    settled(s, pending)?;
    persisted(s)[pi].pending = 0;
    Ok(())
}

/// A free `persisted` entry.
fn free_persisted(s: &mut State) -> Option<usize> {
    persisted(s).iter().position(|e| !e.live)
}

/// Find a persisted key by scope and label: `Ok(None)` when no such key
/// exists, `Err(ENOMEM)` when one does and the table has no entry to hold
/// it — never confused, or a caller would generate a key over one that
/// exists.
fn find_persisted(s: &mut State, scope: Scope, label: &[u8]) -> Result<Option<usize>, i32> {
    if let Some(i) = persisted(s)
        .iter()
        .position(|e| e.live && e.scope() == scope && e.label_bytes() == label)
    {
        return Ok(Some(i));
    }
    rehydrate(s, scope, label)
}

/// Pull a record back from the image into the table. A record whose header
/// does not match, or that does not open under its own header, is absent,
/// not guessed at; one that proves out with no entry free is `ENOMEM`.
fn rehydrate(s: &mut State, scope: Scope, label: &[u8]) -> Result<Option<usize>, i32> {
    if label.is_empty() || label.len() > MAX_LABEL || s.image_len == 0 {
        return Ok(None);
    }
    // A vault kept under one owner's key holds that owner's records only:
    // one that is there and does not open is refused, never read as absent
    // (an open would write a fresh key over it).
    let unreadable = if s.seal == seal_mode::OWNER {
        Err(EACCES)
    } else {
        Ok(None)
    };
    let f = filing(s, &scope, label);
    let mut name = [0u8; record::MAX_NAME];
    let Some(nl) = record::name(&f, &mut name) else {
        return Ok(None);
    };
    let mut blob = [0u8; record::MAX_RECORD];
    let Some(n) = image::read(store_image(s), &name[..nl], &mut blob) else {
        return Ok(None);
    };
    let Some((suite, usage, clear)) = record::facts(&blob[..n]) else {
        zeroize(&mut blob);
        return unreadable;
    };
    // A readable record in a sealed store is a key planted on the medium.
    if clear != keeps_clear(s) {
        zeroize(&mut blob);
        return unreadable;
    }
    let mut header = [0u8; record::MAX_HEADER];
    let Some(h) = record::header(&f, suite, usage, clear, &mut header) else {
        zeroize(&mut blob);
        return unreadable;
    };
    if n <= h || blob[..h] != header[..h] || n - h > record::MAX_SEALED {
        zeroize(&mut blob);
        return unreadable;
    }
    if clear {
        if n - h != suite_private_len(suite) {
            zeroize(&mut blob);
            return unreadable;
        }
    } else {
        let mut probe = [0u8; MAX_KEY_BYTES];
        let opened = record::open(&s.record_key, &header[..h], &blob[h..n], &mut probe);
        zeroize(&mut probe);
        if opened.is_none() {
            zeroize(&mut blob);
            return unreadable;
        }
    }
    let Some(idx) = free_persisted(s) else {
        zeroize(&mut blob);
        return Err(ENOMEM);
    };
    // Read from an image the medium may not hold yet: only as durable as it.
    let pending = match store_durability(s, store_live_seq(s)) {
        Durability::Durable => 0,
        _ => store_live_seq(s),
    };
    let e = &mut persisted(s)[idx];
    *e = Persisted::empty();
    e.label[..label.len()].copy_from_slice(label);
    e.label_len = label.len() as u8;
    e.namespace = scope.namespace;
    e.realm = scope.realm;
    e.suite = suite;
    e.usage = usage;
    e.clear = clear;
    e.pending = pending;
    e.sealed[..n - h].copy_from_slice(&blob[h..n]);
    e.sealed_len = (n - h) as u8;
    e.live = true;
    zeroize(&mut blob);
    Ok(Some(idx))
}

/// Seal `key` under `scope`/`label` and file it in the image.
fn persist_key(
    s: &mut State,
    scope: Scope,
    label: &[u8],
    suite: u16,
    usage: u32,
    key: &[u8],
) -> Persist {
    if label.is_empty() || label.len() > MAX_LABEL {
        return Persist::Failed;
    }
    if s.image_len == 0 {
        return Persist::Unavailable;
    }
    let clear = keeps_clear(s);
    if !clear && s.key_state != record_key::READY {
        if s.warned_unsealable == 0 {
            s.warned_unsealable = 1;
            log(
                s,
                2,
                b"[key_vault] no record key: keys are not persisted (seal: none keeps them readable)",
            );
        }
        return Persist::Unavailable;
    }
    let mut nonce = [0u8; 12];
    if !clear && !random(s, &mut nonce) {
        return Persist::Failed;
    }
    let f = filing(s, &scope, label);
    let mut rec = [0u8; record::MAX_RECORD];
    let rk = (!clear).then_some(&s.record_key);
    let Some(n) = record::encode(&f, suite, usage, key, rk, &nonce, &mut rec) else {
        return Persist::Failed;
    };
    let mut name = [0u8; record::MAX_NAME];
    let Some(nl) = record::name(&f, &mut name) else {
        zeroize(&mut rec);
        return Persist::Failed;
    };
    let mut header = [0u8; record::MAX_HEADER];
    let h = record::header(&f, suite, usage, clear, &mut header).unwrap_or(0);
    let outcome = match store_write(s, &name[..nl], Some(&rec[..n])) {
        Durability::Durable => Persist::Durable,
        Durability::Pending(seq) => Persist::Pending(seq),
        Durability::Failed => {
            log(s, 2, b"[key_vault] persist failed: the record was not kept");
            zeroize(&mut rec);
            return Persist::Failed;
        }
    };
    let idx = match find_persisted(s, scope, label) {
        Ok(Some(i)) => Some(i),
        _ => free_persisted(s),
    };
    if let Some(idx) = idx {
        let e = &mut persisted(s)[idx];
        *e = Persisted::empty();
        e.label[..label.len()].copy_from_slice(label);
        e.label_len = label.len() as u8;
        e.namespace = scope.namespace;
        e.realm = scope.realm;
        e.suite = suite;
        e.usage = usage;
        e.clear = clear;
        e.pending = match outcome {
            Persist::Pending(seq) => seq,
            _ => 0,
        };
        e.sealed[..n - h].copy_from_slice(&rec[h..n]);
        e.sealed_len = (n - h) as u8;
        e.live = true;
    }
    zeroize(&mut rec);
    outcome
}

/// Load a slot from persisted entry `pi`: the slot index, `ENOMEM` with no
/// slot free, `ERROR` when the entry does not open.
fn open_persisted(s: &mut State, pi: usize) -> Result<usize, i32> {
    let entry = persisted(s)[pi];
    let scope = entry.scope();
    let mut key = [0u8; MAX_KEY_BYTES];
    let n = if entry.clear {
        let n = usize::from(entry.sealed_len);
        if n > MAX_KEY_BYTES {
            return Err(ERROR);
        }
        key[..n].copy_from_slice(&entry.sealed[..n]);
        n
    } else {
        let f = filing(s, &scope, entry.label_bytes());
        let mut header = [0u8; record::MAX_HEADER];
        let Some(h) = record::header(&f, entry.suite, entry.usage, false, &mut header) else {
            return Err(ERROR);
        };
        let Some(n) = record::open(
            &s.record_key,
            &header[..h],
            &entry.sealed[..usize::from(entry.sealed_len)],
            &mut key,
        ) else {
            return Err(ERROR);
        };
        n
    };
    if n == 0 || n > MAX_KEY_BYTES {
        zeroize(&mut key);
        return Err(ERROR);
    }
    let Some(slot) = alloc_slot(s) else {
        zeroize(&mut key);
        return Err(ENOMEM);
    };
    label_slot(s, slot, entry.label_bytes());
    let flags = FLAG_IN_USE | FLAG_PERSISTED | if entry.clear { FLAG_CLEAR } else { 0 };
    fill_slot(s, slot, entry.suite, entry.usage, &key[..n], flags);
    zeroize(&mut key);
    Ok(slot)
}

/// Remove a persisted key: its entry and its record. Whether there was one,
/// and where its removal stands: `Durable` when no record remains on the
/// medium, `Pending` while the medium still holds it, `Failed` when it
/// would come back.
fn forget_persisted(s: &mut State, scope: Scope, label: &[u8]) -> (bool, Durability) {
    let mut found = false;
    for e in persisted(s).iter_mut() {
        if e.live && e.scope() == scope && e.label_bytes() == label {
            zeroize(&mut e.sealed);
            *e = Persisted::empty();
            found = true;
        }
    }
    if s.image_len == 0 || !store_ready(s) {
        return (found, Durability::Durable);
    }
    let f = filing(s, &scope, label);
    let mut name = [0u8; record::MAX_NAME];
    let Some(nl) = record::name(&f, &mut name) else {
        return (found, Durability::Durable);
    };
    let mut probe = [0u8; record::MAX_RECORD];
    if image::read(store_image(s), &name[..nl], &mut probe).is_some() {
        found = true;
    }
    zeroize(&mut probe);
    (found, store_write(s, &name[..nl], None))
}
