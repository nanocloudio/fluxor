// ── The keyspace ──────────────────────────────────────────────────────
//
// An entry slot holds one key from the write that made it until the
// tombstone of its delete leaves the history: live, or a tombstone whose
// revision is the delete's. The index holds the slots in key order, so a
// listing or a relist walks keys in order from a binary search. A history
// entry names its key by slot: a slot keeps its key for as long as any
// history entry names it, because a tombstone is retired only once the
// history no longer reaches its delete (and every earlier entry of its key).

/// The slot is unused.
const ENTRY_FREE: u8 = 0;
/// The slot holds a live key.
const ENTRY_LIVE: u8 = 1;
/// The slot holds a deleted key whose delete the history still holds.
const ENTRY_TOMB: u8 = 2;

/// History kinds, as the log's ops name a write.
const KIND_ADDED: u8 = 0;
const KIND_MODIFIED: u8 = 1;
const KIND_DELETED: u8 = 2;

/// A block's header: `[holders u32][size u32]`, then the key, then the
/// value. A block is held by its entry and by every `GET` slot reading it,
/// and freed by the last.
const BLOCK_HDR: usize = 8;
/// What one heap allocation costs beyond its bytes: the allocator's header
/// and its alignment. Charged against `value_bytes` with every block and
/// staged chunk, so the arena the composer sizes holds what is charged.
const ALLOC_OVERHEAD: u64 = 16;

/// The kind byte a relist continuation opens with:
/// `[TOKEN_RELIST][pinned revision u64 LE][cursor key]`. Never 8 bytes long
/// (the cursor is a non-empty key), so it never reads as a bare revision.
const TOKEN_RELIST: u8 = 1;
const RELIST_TOKEN_HEAD: usize = 1 + 8;

#[repr(C)]
#[derive(Clone, Copy)]
struct Entry {
    block: *mut u8,
    /// The revision of the key's last write: its CAS token, or a
    /// tombstone's delete.
    rev: u64,
    val_len: u32,
    /// The `CHANGES` call that last passed over this key, and the hint of
    /// the first entry it saw for it.
    mark: u32,
    key_len: u16,
    flags: u8,
    hint: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Hist {
    rev: u64,
    slot: u32,
    kind: u8,
}

fn entries(s: &State) -> &[Entry] {
    // SAFETY: `construct` took `n_objects` entries; the instance is the
    // provider's alone, single-threaded.
    unsafe { core::slice::from_raw_parts(s.entries, s.n_objects as usize) }
}

fn entries_mut(s: &mut State) -> &mut [Entry] {
    // SAFETY: as `entries`.
    unsafe { core::slice::from_raw_parts_mut(s.entries, s.n_objects as usize) }
}

fn index(s: &State) -> &[u32] {
    // SAFETY: as `entries`.
    unsafe { core::slice::from_raw_parts(s.index, s.n_objects as usize) }
}

fn index_mut(s: &mut State) -> &mut [u32] {
    // SAFETY: as `entries`.
    unsafe { core::slice::from_raw_parts_mut(s.index, s.n_objects as usize) }
}

fn hist(s: &State) -> &[Hist] {
    // SAFETY: as `entries`.
    unsafe { core::slice::from_raw_parts(s.hist, s.n_history as usize) }
}

fn hist_mut(s: &mut State) -> &mut [Hist] {
    // SAFETY: as `entries`.
    unsafe { core::slice::from_raw_parts_mut(s.hist, s.n_history as usize) }
}

fn block_key<'a>(b: *mut u8, kl: u16) -> &'a [u8] {
    // SAFETY: a block holds its header, then `kl` key bytes.
    unsafe { core::slice::from_raw_parts(b.add(BLOCK_HDR), usize::from(kl)) }
}

fn block_val<'a>(b: *mut u8, kl: u16, vl: u32) -> &'a mut [u8] {
    // SAFETY: a block holds its header, the key, then `vl` value bytes.
    unsafe { core::slice::from_raw_parts_mut(b.add(BLOCK_HDR + usize::from(kl)), vl as usize) }
}

fn block_word(b: *mut u8, at: usize) -> *mut u32 {
    // SAFETY: the header's two words.
    unsafe { b.add(at).cast::<u32>() }
}

/// A block for `key` and a `vl`-byte value, held once, charged against the
/// value arena; null when the arena or the heap cannot hold it.
fn block_alloc(s: &mut State, key: &[u8], vl: u32) -> *mut u8 {
    let b = block_alloc_raw(s, key.len(), vl);
    if !b.is_null() {
        // SAFETY: the block holds `key.len()` key bytes after its header.
        unsafe { core::ptr::copy_nonoverlapping(key.as_ptr(), b.add(BLOCK_HDR), key.len()) };
    }
    b
}

/// [`block_alloc`] for a `kl`-byte key the caller writes in.
fn block_alloc_raw(s: &mut State, kl: usize, vl: u32) -> *mut u8 {
    let size = BLOCK_HDR + kl + vl as usize;
    let cost = size as u64 + ALLOC_OVERHEAD;
    if s.value_used + cost > u64::from(s.value_bytes) {
        return core::ptr::null_mut();
    }
    let b = heap_take(s, size);
    if b.is_null() {
        return b;
    }
    // SAFETY: `b` names `size` fresh bytes.
    unsafe {
        *block_word(b, 0) = 1;
        *block_word(b, 4) = size as u32;
    }
    s.value_used += cost;
    b
}

fn block_hold(b: *mut u8) {
    // SAFETY: a live block.
    unsafe { *block_word(b, 0) += 1 };
}

fn block_release(s: &mut State, b: *mut u8) {
    if b.is_null() {
        return;
    }
    // SAFETY: a live block, held by the caller.
    let (holders, size) = unsafe { (*block_word(b, 0) - 1, *block_word(b, 4)) };
    if holders > 0 {
        // SAFETY: as above.
        unsafe { *block_word(b, 0) = holders };
        return;
    }
    s.value_used = s
        .value_used
        .saturating_sub(u64::from(size) + ALLOC_OVERHEAD);
    heap_give(s, b);
}

fn key_of(s: &State, slot: u32) -> &[u8] {
    let e = &entries(s)[slot as usize];
    block_key(e.block, e.key_len)
}

/// Move the index's positions `from..n_index` to start at `to`: one place
/// up to open a position, or down to close one. The caller keeps `to` and
/// the moved run inside the table.
fn shift_index(s: &mut State, from: usize, to: usize) {
    let n = s.n_index as usize;
    if from >= n || to + (n - from) > s.n_objects as usize {
        return;
    }
    // SAFETY: both runs lie inside the `n_objects` index; `copy` allows
    // overlap.
    unsafe { core::ptr::copy(s.index.add(from), s.index.add(to), n - from) };
}

/// The index position of `key`, or where it would be inserted.
fn find(s: &State, key: &[u8]) -> Result<usize, usize> {
    let idx = &index(s)[..s.n_index as usize];
    idx.binary_search_by(|&slot| key_of(s, slot).cmp(key))
}

/// The first index position whose key is `>= key`.
fn lower_bound(s: &State, key: &[u8]) -> usize {
    match find(s, key) {
        Ok(p) | Err(p) => p,
    }
}

/// The first index position whose key is `> key`.
fn upper_bound(s: &State, key: &[u8]) -> usize {
    match find(s, key) {
        Ok(p) => p + 1,
        Err(p) => p,
    }
}

/// The live entry `key` names: its slot.
fn live_slot(s: &State, key: &[u8]) -> Option<u32> {
    let p = find(s, key).ok()?;
    let slot = index(s)[p];
    (entries(s)[slot as usize].flags == ENTRY_LIVE).then_some(slot)
}

/// `(value, revision)` of a live key.
fn get<'a>(s: &'a State, key: &[u8]) -> Option<(&'a [u8], u64)> {
    let slot = live_slot(s, key)?;
    let e = &entries(s)[slot as usize];
    Some((&*block_val(e.block, e.key_len, e.val_len), e.rev))
}

/// The slot a write to `key` lands in: its own (live or a tombstone), or a
/// free one with its index position. A full table retires its oldest
/// tombstone first; `None` when it holds no tombstone to retire.
fn slot_for(s: &mut State, key: &[u8]) -> Option<(u32, Option<usize>)> {
    match find(s, key) {
        Ok(p) => Some((index(s)[p], None)),
        Err(_) => {
            if s.n_index >= s.n_objects && !retire_oldest_tombstone(s) {
                return None;
            }
            let slot = entries(s).iter().position(|e| e.flags == ENTRY_FREE)? as u32;
            let at = lower_bound(s, key);
            Some((slot, Some(at)))
        }
    }
}

/// Free tombstone `slot`: out of the index, its block released.
fn free_tombstone(s: &mut State, slot: u32) {
    let e = entries(s)[slot as usize];
    if let Ok(p) = find(s, block_key(e.block, e.key_len)) {
        shift_index(s, p + 1, p);
        s.n_index -= 1;
    }
    let b = entries(s)[slot as usize].block;
    block_release(s, b);
    entries_mut(s)[slot as usize] = Entry {
        block: core::ptr::null_mut(),
        rev: 0,
        val_len: 0,
        mark: 0,
        key_len: 0,
        flags: ENTRY_FREE,
        hint: 0,
    };
}

/// Retire the tombstone with the oldest delete to make room for a key, and
/// move the history base past it: a reader behind it is answered LOST.
fn retire_oldest_tombstone(s: &mut State) -> bool {
    let mut pick: Option<(u32, u64)> = None;
    for (i, e) in entries(s).iter().enumerate() {
        if e.flags == ENTRY_TOMB && pick.is_none_or(|(_, r)| e.rev < r) {
            pick = Some((i as u32, e.rev));
        }
    }
    let Some((slot, rev)) = pick else {
        return false;
    };
    while s.hist_len > 0 && hist_at(s, 0).rev <= rev {
        pop_hist(s);
    }
    if s.history_base < rev {
        s.history_base = rev;
    }
    if entries(s)[slot as usize].flags == ENTRY_TOMB {
        free_tombstone(s, slot);
    }
    true
}

fn hist_at(s: &State, i: usize) -> Hist {
    hist(s)[(s.hist_head as usize + i) % s.n_history as usize]
}

/// Drop the oldest history entry, and the tombstone of its key when that
/// entry was the key's last.
fn pop_hist(s: &mut State) {
    let old = hist_at(s, 0);
    s.hist_head = (s.hist_head + 1) % s.n_history;
    s.hist_len -= 1;
    s.history_base = s.history_base.max(old.rev);
    let e = entries(s)[old.slot as usize];
    if old.kind == KIND_DELETED && e.flags == ENTRY_TOMB && e.rev == old.rev {
        free_tombstone(s, old.slot);
    }
}

fn record(s: &mut State, rev: u64, kind: u8, slot: u32) {
    if s.hist_len == s.n_history {
        pop_hist(s);
    }
    let at = (s.hist_head + s.hist_len) % s.n_history;
    hist_mut(s)[at as usize] = Hist { rev, slot, kind };
    s.hist_len += 1;
}

/// The first history position whose revision is after `since`.
fn hist_after(s: &State, since: u64) -> usize {
    let (mut lo, mut hi) = (0usize, s.hist_len as usize);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if hist_at(s, mid).rev <= since {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Install a put of `block` (key and value, held once) in `slot` at `rev`:
/// a new slot enters the index at `at`.
fn apply_put(
    s: &mut State,
    slot: u32,
    at: Option<usize>,
    block: *mut u8,
    kl: u16,
    vl: u32,
    rev: u64,
) {
    if let Some(at) = at {
        shift_index(s, at, at + 1);
        index_mut(s)[at] = slot;
        s.n_index += 1;
    }
    let old = entries(s)[slot as usize];
    let kind = if old.flags == ENTRY_LIVE {
        KIND_MODIFIED
    } else {
        KIND_ADDED
    };
    if old.flags != ENTRY_FREE {
        block_release(s, old.block);
    }
    entries_mut(s)[slot as usize] = Entry {
        block,
        rev,
        val_len: vl,
        mark: 0,
        key_len: kl,
        flags: ENTRY_LIVE,
        hint: 0,
    };
    s.revision = s.revision.max(rev);
    record(s, rev, kind, slot);
}

/// Install a delete of live `slot` at `rev`: the key becomes a tombstone
/// holding its key alone (the value goes when no `GET` reads it).
fn apply_delete(s: &mut State, slot: u32, rev: u64) {
    let e = entries(s)[slot as usize];
    let lean = block_alloc(s, block_key(e.block, e.key_len), 0);
    let block = if lean.is_null() {
        e.block
    } else {
        block_release(s, e.block);
        lean
    };
    entries_mut(s)[slot as usize] = Entry {
        block,
        rev,
        val_len: if lean.is_null() { e.val_len } else { 0 },
        mark: 0,
        key_len: e.key_len,
        flags: ENTRY_TOMB,
        hint: 0,
    };
    s.revision = s.revision.max(rev);
    record(s, rev, KIND_DELETED, slot);
}

/// What a mutating write is conditional on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Precondition {
    Any,
    Absent,
    Revision(u64),
}

impl Precondition {
    /// The condition a request's `precondition` byte and etag state. `None`
    /// for a kind the store does not know, or `ETAG` without a whole
    /// revision: a malformed request, never a weaker condition.
    fn read(kind: u8, etag: &[u8]) -> Option<Self> {
        use obj_op::precondition as pre;
        match kind {
            pre::ANY => Some(Self::Any),
            pre::ABSENT => Some(Self::Absent),
            pre::ETAG if etag.len() >= 8 => {
                let mut r = [0u8; 8];
                r.copy_from_slice(&etag[..8]);
                Some(Self::Revision(u64::from_le_bytes(r)))
            }
            _ => None,
        }
    }

    /// Whether a key at `existing` (its revision, `None` when absent)
    /// passes.
    fn passes(self, existing: Option<u64>) -> bool {
        match self {
            Self::Any => true,
            Self::Absent => existing.is_none(),
            Self::Revision(want) => existing == Some(want),
        }
    }

    fn encode(self) -> (u8, u64) {
        match self {
            Self::Any => (0, 0),
            Self::Absent => (1, 0),
            Self::Revision(r) => (2, r),
        }
    }

    fn decode(kind: u8, rev: u64) -> Self {
        match kind {
            1 => Self::Absent,
            2 => Self::Revision(rev),
            _ => Self::Any,
        }
    }
}

/// The etag a key's revision travels as: the revision in its first 8
/// bytes, the rest zero.
fn etag_from_rev(rev: u64) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[..8].copy_from_slice(&rev.to_le_bytes());
    e
}

/// A key a write may create: one a listing and a change record can carry.
fn writable_key(key: &[u8]) -> bool {
    !key.is_empty() && key.len() <= STORAGE_KEY_MAX && utf8_valid(key)
}

/// The `LIST` cursor as a key under `prefix`, or `EINVAL`: it is the last
/// key a page returned, so anything else was not issued here.
fn list_cursor<'a>(cursor: &'a [u8], prefix: &[u8]) -> Result<Option<&'a [u8]>, i32> {
    if cursor.is_empty() {
        Ok(None)
    } else if utf8_valid(cursor) && cursor.starts_with(prefix) {
        Ok(Some(cursor))
    } else {
        Err(EINVAL)
    }
}

/// The index position a walk of `prefix` starts at, strictly after `after`.
fn walk_start(s: &State, prefix: &[u8], after: Option<&[u8]>) -> usize {
    let from = lower_bound(s, prefix);
    match after {
        Some(a) => from.max(upper_bound(s, a)),
        None => from,
    }
}

/// Write a LOST page — the reader relists — into `out`.
fn lost(out: &mut [u8]) -> i32 {
    ns_op::changes::write_lost(out).map_or(ENOMEM, |n| n as i32)
}

/// One `CHANGES` page under `prefix`, resumed from `token`: empty is a
/// relist, 8 bytes a bare revision, anything else a relist continuation
/// this store issued.
fn changes(s: &mut State, prefix: &[u8], token: &[u8], out: &mut [u8]) -> i32 {
    if token.is_empty() {
        return relist(s, prefix, s.revision, None, out);
    }
    if let Some(since) = ns_op::changes::token_revision(token) {
        return changes_since(s, prefix, since, out);
    }
    if token.len() <= RELIST_TOKEN_HEAD || token[0] != TOKEN_RELIST {
        return EINVAL;
    }
    let mut r = [0u8; 8];
    r.copy_from_slice(&token[1..RELIST_TOKEN_HEAD]);
    let pinned = u64::from_le_bytes(r);
    let after = match list_cursor(&token[RELIST_TOKEN_HEAD..], prefix) {
        Ok(Some(after)) => after,
        _ => return EINVAL,
    };
    if pinned > s.revision {
        return EINVAL;
    }
    // The relist ends by handing the reader `pinned`; a history that no
    // longer reaches it would answer that resume LOST, so it is LOST now.
    if pinned < s.history_base {
        return lost(out);
    }
    let mut cursor = [0u8; STORAGE_KEY_MAX];
    cursor[..after.len()].copy_from_slice(after);
    let al = after.len();
    relist(s, prefix, pinned, Some(&cursor[..al]), out)
}

/// A history page: one record per key under `prefix` with an entry after
/// `since`, read at the current state, each key at its last entry — its
/// current revision, or the delete that left it absent — and passed over at
/// every earlier one. A key whose first entry this page saw was its
/// creation is labelled `Added`.
fn changes_since(s: &mut State, prefix: &[u8], since: u64, out: &mut [u8]) -> i32 {
    use ns_op::changes as ch;
    if since < s.history_base || since > s.revision {
        return lost(out);
    }
    let Some(mut page) = ch::PageWriter::new(out, ch::REVISION_TOKEN_LEN) else {
        return ENOMEM;
    };
    s.call_mark = s.call_mark.wrapping_add(1).max(1);
    let mark = s.call_mark;
    let mut cut = since;
    let mut more = false;
    let start = hist_after(s, since);
    let mut i = start;
    while i < s.hist_len as usize {
        if i - start == s.changes_budget as usize {
            more = true;
            break;
        }
        let c = hist_at(s, i);
        let e = entries(s)[c.slot as usize];
        let key = block_key(e.block, e.key_len);
        if key.starts_with(prefix) {
            // A key no change record can carry refuses the read rather than
            // vanish from it (only a hand-seeded log holds one).
            if key.len() > STORAGE_KEY_MAX {
                return EOVERFLOW;
            }
            if e.rev > c.rev {
                let ent = &mut entries_mut(s)[c.slot as usize];
                if ent.mark != mark {
                    ent.mark = mark;
                    ent.hint = c.kind;
                }
            } else {
                let (kind, val): (u8, &[u8]) = if e.flags == ENTRY_LIVE {
                    let hint = if e.mark == mark { e.hint } else { c.kind };
                    let kind = if hint == KIND_ADDED {
                        ch::KIND_ADDED
                    } else {
                        ch::KIND_MODIFIED
                    };
                    (kind, block_val(e.block, e.key_len, e.val_len))
                } else {
                    (ch::KIND_DELETED, &[])
                };
                if !page.push(c.rev, kind, key, val) {
                    more = true;
                    break;
                }
            }
        }
        cut = c.rev;
        i += 1;
    }
    if more && cut == since {
        return ENOMEM;
    }
    if !more {
        cut = s.revision;
    }
    page.finish(more, cut, &ch::revision_token(cut))
        .map_or(ENOMEM, |n| n as i32)
}

/// A relist page: the live keys under `prefix` after `after`, in key order,
/// `Added` with their values, the walk pinned at `pinned`. A key changed
/// after `pinned` is passed over: the `CHANGES` from `pinned` that follows
/// reports it. A page with `more` set carries `safe_rev` 0; the last
/// carries `pinned`, as its bare revision token.
fn relist(s: &State, prefix: &[u8], pinned: u64, after: Option<&[u8]>, out: &mut [u8]) -> i32 {
    use ns_op::changes as ch;
    let Some(mut page) = ch::PageWriter::new(out, RELIST_TOKEN_HEAD + STORAGE_KEY_MAX) else {
        return ENOMEM;
    };
    let mut last: Option<u32> = None;
    let mut more = false;
    let mut scanned = 0usize;
    let mut p = walk_start(s, prefix, after);
    while p < s.n_index as usize {
        let slot = index(s)[p];
        let e = entries(s)[slot as usize];
        let key = block_key(e.block, e.key_len);
        if !key.starts_with(prefix) {
            break;
        }
        p += 1;
        if e.flags != ENTRY_LIVE {
            continue;
        }
        if scanned == s.changes_budget as usize {
            more = true;
            break;
        }
        if key.len() > STORAGE_KEY_MAX {
            return EOVERFLOW;
        }
        scanned += 1;
        if e.rev <= pinned
            && !page.push(
                e.rev,
                ch::KIND_ADDED,
                key,
                block_val(e.block, e.key_len, e.val_len),
            )
        {
            more = true;
            break;
        }
        last = Some(slot);
    }
    let n = match (more, last) {
        (false, _) => page.finish(false, pinned, &ch::revision_token(pinned)),
        (true, None) => return ENOMEM,
        (true, Some(slot)) => {
            let key = key_of(s, slot);
            let mut token = [0u8; RELIST_TOKEN_HEAD + STORAGE_KEY_MAX];
            token[0] = TOKEN_RELIST;
            token[1..RELIST_TOKEN_HEAD].copy_from_slice(&pinned.to_le_bytes());
            token[RELIST_TOKEN_HEAD..RELIST_TOKEN_HEAD + key.len()].copy_from_slice(key);
            page.finish(true, 0, &token[..RELIST_TOKEN_HEAD + key.len()])
        }
    };
    n.map_or(ENOMEM, |n| n as i32)
}
