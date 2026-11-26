// ── storage.object ────────────────────────────────────────────────────

/// Streamed-write handles are slots from here up to `GRANT_SLOT_BASE`.
const WRITE_SLOT_BASE: i32 = 0x8000;
/// Grant handles are slots from here up.
const GRANT_SLOT_BASE: i32 = 0x1_0000;

/// Bytes one staged chunk of a streamed write holds, its link included.
const STAGE_CHUNK: usize = 4096;
/// A staged chunk's link to the next: the first word.
const CHUNK_LINK: usize = core::mem::size_of::<usize>();

/// A `GET` read: the block it reads (held), and the revision it read at.
#[repr(C)]
#[derive(Clone, Copy)]
struct ReadSlot {
    block: *mut u8,
    rev: u64,
    owner: [u8; 8],
    val_len: u32,
    key_len: u16,
    in_use: u8,
    /// The grant it was opened under, or -1.
    grant: i16,
}

/// A streamed write: its key and condition, held for the commit, and the
/// bytes staged so far in a chain of heap chunks.
#[repr(C)]
#[derive(Clone, Copy)]
struct WriteSlot {
    head: *mut u8,
    tail: *mut u8,
    staged: u32,
    prec_rev: u64,
    owner: [u8; 8],
    grant: i16,
    in_use: u8,
    committed: u8,
    prec_kind: u8,
    key_len: u8,
    key: [u8; STORAGE_KEY_MAX],
}

/// A grant a caller presented: its scope, its rights and expiry, and the
/// module occupancy it belongs to.
#[repr(C)]
#[derive(Clone, Copy)]
struct Grant {
    module: [u8; 8],
    not_after: u32,
    permissions: u16,
    in_use: u8,
    scope_len: u8,
    scope: [u8; obj_op::grant::SCOPE_MAX],
}

fn reads(s: &State) -> &[ReadSlot] {
    if s.reads.is_null() {
        return &[];
    }
    // SAFETY: `construct` took `n_reads` slots.
    unsafe { core::slice::from_raw_parts(s.reads, usize::from(s.n_reads)) }
}

fn reads_mut(s: &mut State) -> &mut [ReadSlot] {
    if s.reads.is_null() {
        return &mut [];
    }
    // SAFETY: as `reads`.
    unsafe { core::slice::from_raw_parts_mut(s.reads, usize::from(s.n_reads)) }
}

fn writes(s: &State) -> &[WriteSlot] {
    if s.writes.is_null() {
        return &[];
    }
    // SAFETY: `construct` took `n_writes` slots.
    unsafe { core::slice::from_raw_parts(s.writes, usize::from(s.n_writes)) }
}

fn writes_mut(s: &mut State) -> &mut [WriteSlot] {
    if s.writes.is_null() {
        return &mut [];
    }
    // SAFETY: as `writes`.
    unsafe { core::slice::from_raw_parts_mut(s.writes, usize::from(s.n_writes)) }
}

fn grants(s: &State) -> &[Grant] {
    if s.grants.is_null() {
        return &[];
    }
    // SAFETY: `construct` took `n_grants` slots.
    unsafe { core::slice::from_raw_parts(s.grants, usize::from(s.n_grants)) }
}

fn grants_mut(s: &mut State) -> &mut [Grant] {
    if s.grants.is_null() {
        return &mut [];
    }
    // SAFETY: as `grants`.
    unsafe { core::slice::from_raw_parts_mut(s.grants, usize::from(s.n_grants)) }
}

/// The read slot `handle` names, if it is one `owner` opened.
fn read_of(s: &State, handle: i32, owner: &[u8; 8]) -> Option<usize> {
    let i = usize::try_from(handle).ok()?;
    reads(s)
        .get(i)
        .is_some_and(|r| r.in_use != 0 && &r.owner == owner)
        .then_some(i)
}

/// The streamed-write slot `handle` names, if it is one `owner` opened.
fn write_of(s: &State, handle: i32, owner: &[u8; 8]) -> Option<usize> {
    if !(WRITE_SLOT_BASE..GRANT_SLOT_BASE).contains(&handle) {
        return None;
    }
    let i = (handle - WRITE_SLOT_BASE) as usize;
    writes(s)
        .get(i)
        .is_some_and(|w| w.in_use != 0 && &w.owner == owner)
        .then_some(i)
}

/// The grant `handle` names, if it is one the calling module presented.
fn grant_of(s: &State, handle: i32) -> Option<usize> {
    if handle < GRANT_SLOT_BASE {
        return None;
    }
    let i = (handle - GRANT_SLOT_BASE) as usize;
    let module = caller_module(s);
    grants(s)
        .get(i)
        .is_some_and(|g| g.in_use != 0 && g.module == module)
        .then_some(i)
}

fn close_read(s: &mut State, i: usize) {
    let b = reads(s)[i].block;
    reads_mut(s)[i].in_use = 0;
    reads_mut(s)[i].block = core::ptr::null_mut();
    block_release(s, b);
}

/// Free a streamed write's chunks.
fn free_chunks(s: &mut State, i: usize) {
    let mut c = writes(s)[i].head;
    while !c.is_null() {
        // SAFETY: a chunk's first word links the next.
        let next = unsafe { *c.cast::<*mut u8>() };
        heap_give(s, c);
        s.value_used = s
            .value_used
            .saturating_sub(STAGE_CHUNK as u64 + ALLOC_OVERHEAD);
        c = next;
    }
    let w = &mut writes_mut(s)[i];
    w.head = core::ptr::null_mut();
    w.tail = core::ptr::null_mut();
    w.staged = 0;
}

/// Free a streamed write: its staged bytes dropped, nothing committed. A
/// commit already in the log lands; its slot is no longer named.
fn drop_write(s: &mut State, i: usize) {
    free_chunks(s, i);
    writes_mut(s)[i].in_use = 0;
    writes_mut(s)[i].committed = 0;
    writes_mut(s)[i].grant = -1;
    if s.inflight.live != 0 && s.inflight.stream == i as i16 {
        s.inflight.stream = -1;
    }
}

/// Append `bytes` to streamed write `i`'s chunks: all or nothing.
fn stage(s: &mut State, i: usize, bytes: &[u8]) -> i32 {
    let room = (STAGE_CHUNK - CHUNK_LINK) as u32;
    let w = writes(s)[i];
    let fill = w.staged % room;
    let have = if w.tail.is_null() || fill == 0 {
        0
    } else {
        room - fill
    };
    let need = (bytes.len() as u32).saturating_sub(have);
    let chunks = need.div_ceil(room) as u64;
    if s.value_used + chunks * (STAGE_CHUNK as u64 + ALLOC_OVERHEAD) > u64::from(s.value_bytes) {
        return ENOSPC;
    }
    let mut done = 0usize;
    while done < bytes.len() {
        let w = writes(s)[i];
        let off = (w.staged % room) as usize;
        if w.tail.is_null() || (off == 0 && w.staged > 0) {
            let c = heap_take(s, STAGE_CHUNK);
            if c.is_null() {
                return ENOSPC;
            }
            s.value_used += STAGE_CHUNK as u64 + ALLOC_OVERHEAD;
            let w = &mut writes_mut(s)[i];
            if w.tail.is_null() {
                w.head = c;
            } else {
                // SAFETY: the tail chunk's link word.
                unsafe { *w.tail.cast::<*mut u8>() = c };
            }
            w.tail = c;
        }
        let w = writes(s)[i];
        let off = (w.staged % room) as usize;
        let take = (room as usize - off).min(bytes.len() - done);
        // SAFETY: `take` bytes into the tail chunk past its link and fill.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes[done..].as_ptr(),
                w.tail.add(CHUNK_LINK + off),
                take,
            );
        }
        writes_mut(s)[i].staged += take as u32;
        done += take;
    }
    0
}

/// Copy streamed write `i`'s staged bytes into `out`.
fn unstage(s: &State, i: usize, out: &mut [u8]) {
    let room = STAGE_CHUNK - CHUNK_LINK;
    let mut c = writes(s)[i].head;
    let mut at = 0usize;
    while !c.is_null() && at < out.len() {
        let take = room.min(out.len() - at);
        // SAFETY: a chunk holds `room` bytes past its link.
        unsafe { core::ptr::copy_nonoverlapping(c.add(CHUNK_LINK), out[at..].as_mut_ptr(), take) };
        at += take;
        // SAFETY: the link word.
        c = unsafe { *c.cast::<*mut u8>() };
    }
}

fn object_caps(s: &State, a: &mut [u8]) -> i32 {
    use obj_op::caps;
    let mut word = caps::WRITE | caps::IF_ABSENT | caps::IF_ETAG | caps::STREAMED | caps::LIST;
    if s.guarded() {
        word |= caps::GRANTS;
    }
    abi::kernel_abi::caps_word::answer(a, word)
}

/// Per-handle fence introspection: a `GET` read's view.
fn read_fence(s: &State, handle: i32, a: &mut [u8]) -> i32 {
    if a.len() < abi::fence::WIRE_MAX_LEN {
        return EINVAL;
    }
    let owner = caller_owner(s);
    let Some(i) = read_of(s, handle, &owner) else {
        return ENOSYS;
    };
    (Fence::ViewConsistent {
        source: STORE_SOURCE,
        revision: reads(s)[i].rev,
    })
    .encode(a)
    .map_or(EINVAL, |n| n as i32)
}

// ── grants ────────────────────────────────────────────────────────────

struct Crypto;

impl cap::CapCrypto for Crypto {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        sha256(data)
    }
    fn ed25519_verify(&self, key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        ed25519_verify(key, msg, sig)
    }
}

fn trusted_clock(s: &State) -> Option<cap::Clock> {
    // SAFETY: the instance's syscall table.
    cap::Clock::from_trusted(&unsafe { dev_trusted_unix(s.sys()) })
}

/// Whether grant `i` is still inside its window by the trusted clock.
fn grant_live(s: &State, i: usize) -> bool {
    let Some(g) = grants(s).get(i).filter(|g| g.in_use != 0) else {
        return false;
    };
    match trusted_clock(s) {
        Some(c) => c.now.saturating_add(c.uncertainty) <= u64::from(g.not_after),
        None => false,
    }
}

/// `PRESENT`: verify the chain in `chain` over the scope `arg` names and
/// mint a grant. The first byte of `arg` receives the refusal.
fn present(s: &mut State, arg: &mut [u8], chain: &[u8]) -> i32 {
    let Some(scope) = obj_op::grant::parse_present(arg) else {
        return EINVAL;
    };
    let mut sc = [0u8; obj_op::grant::SCOPE_MAX];
    let sl = scope.len().min(sc.len());
    sc[..sl].copy_from_slice(&scope[..sl]);
    let Some(object) = obj_op::grant::scope_object(&Crypto, &sc[..sl]) else {
        return EINVAL;
    };
    let roots = &s.roots[..usize::from(s.n_roots)];
    let verdict = cap::verify(&Crypto, chain, roots, trusted_clock(s), None).and_then(|g| {
        if g.object_id == object {
            Ok(g)
        } else {
            Err(cap::Refusal::ObjectMismatch)
        }
    });
    let g = match verdict {
        Ok(g) => g,
        Err(r) => {
            arg[obj_op::grant::REFUSAL_AT] = r as u8;
            return EACCES;
        }
    };
    let i = match grants(s).iter().position(|g| g.in_use == 0) {
        Some(i) => i,
        None => {
            // A grant of a module that is gone frees its slot.
            for j in 0..grants(s).len() {
                let m = grants(s)[j].module;
                if !module_live(s, &m) {
                    release_grant(s, j);
                }
            }
            match grants(s).iter().position(|g| g.in_use == 0) {
                Some(i) => i,
                None => {
                    log(s, 2, b"[store] every grant slot is held; PRESENT refused");
                    return ENOMEM;
                }
            }
        }
    };
    let module = caller_module(s);
    let gr = &mut grants_mut(s)[i];
    gr.in_use = 1;
    gr.module = module;
    gr.permissions = g.permissions;
    gr.not_after = g.not_after;
    gr.scope_len = sl as u8;
    gr.scope[..sl].copy_from_slice(&sc[..sl]);
    GRANT_SLOT_BASE + i as i32
}

/// Drop grant `i`, and every read and streamed write opened under it.
fn release_grant(s: &mut State, i: usize) {
    grants_mut(s)[i].in_use = 0;
    for r in 0..reads(s).len() {
        if reads(s)[r].in_use != 0 && reads(s)[r].grant == i as i16 {
            close_read(s, r);
        }
    }
    for w in 0..writes(s).len() {
        if writes(s)[w].in_use != 0 && writes(s)[w].grant == i as i16 {
            drop_write(s, w);
        }
    }
}

/// The key (or `LIST` prefix) an op addresses, for its scope check.
fn op_key(opcode: u32, a: &[u8]) -> Option<&[u8]> {
    match opcode {
        obj_op::GET => obj_op::key::parse(a),
        obj_op::LIST => obj_op::list::parse_request(a).map(|r| r.prefix),
        obj_op::PUT => obj_op::put::parse(a).map(|r| r.key),
        obj_op::PUT_STREAMED_OPEN => obj_op::put::parse_record(a).map(|r| r.key),
        obj_op::HEAD => obj_op::head::parse_request(a),
        obj_op::DELETE => obj_op::delete::parse_request(a).map(|r| r.key),
        obj_op::RETAIN => obj_op::retain::parse_request(a).map(|r| r.key),
        _ => None,
    }
}

/// Admit an op on a guarded store: `Ok(grant)` for an op run under a grant
/// (-1 for one no grant covers: a handle's own ops, `CLOSE`), `Err(errno)`
/// to refuse it.
fn admit(s: &State, handle: i32, opcode: u32, a: &[u8], owner: &[u8; 8]) -> Result<i16, i32> {
    let Some(access) = obj_op::grant::access_of(opcode) else {
        return Ok(-1);
    };
    if opcode == obj_op::RANGE_GET {
        return match read_of(s, handle, owner).map(|i| reads(s)[i].grant) {
            Some(g) if g >= 0 && grant_live(s, g as usize) => Ok(-1),
            _ => Err(EACCES),
        };
    }
    if matches!(
        opcode,
        obj_op::PUT_STREAMED_WRITE | obj_op::PUT_STREAMED_COMMIT | obj_op::PUT_STREAMED_ABORT
    ) {
        return match write_of(s, handle, owner).map(|i| writes(s)[i].grant) {
            Some(g) if g >= 0 && grant_live(s, g as usize) => Ok(-1),
            _ => Err(EACCES),
        };
    }
    let i = grant_of(s, handle).ok_or(EACCES)?;
    if !grant_live(s, i) {
        return Err(EACCES);
    }
    let g = &grants(s)[i];
    let need = access.permission();
    if g.permissions & need != need {
        return Err(EACCES);
    }
    let key = op_key(opcode, a).ok_or(EINVAL)?;
    if !obj_op::grant::in_scope(&g.scope[..usize::from(g.scope_len)], key) {
        return Err(EACCES);
    }
    Ok(i as i16)
}

fn object_call(s: &mut State, handle: i32, opcode: u32, a: &mut [u8], d: &mut [u8]) -> i32 {
    let owner = caller_owner(s);
    if opcode == obj_op::PRESENT {
        if !s.guarded() {
            return ENOSYS;
        }
        return present(s, a, d);
    }
    if opcode == obj_op::CLOSE && handle >= GRANT_SLOT_BASE {
        let Some(i) = grant_of(s, handle) else {
            return EACCES;
        };
        release_grant(s, i);
        return 0;
    }
    let grant = if s.guarded() {
        match admit(s, handle, opcode, a, &owner) {
            Ok(g) => g,
            Err(e) => return e,
        }
    } else {
        -1
    };
    match opcode {
        obj_op::PUT => obj_put(s, opcode, a, d),
        obj_op::PUT_STREAMED_OPEN => obj_stream_open(s, a, owner, grant),
        obj_op::PUT_STREAMED_WRITE => {
            let Some(i) = write_of(s, handle, &owner) else {
                return EINVAL;
            };
            if writes(s)[i].committed != 0 || s.inflight.live != 0 && s.inflight.stream == i as i16
            {
                return EINVAL;
            }
            if u64::from(writes(s)[i].staged) + d.len() as u64 > u64::from(s.stage_max) {
                return ENOSPC;
            }
            stage(s, i, d)
        }
        obj_op::PUT_STREAMED_COMMIT => obj_stream_commit(s, opcode, handle, a, &owner),
        obj_op::PUT_STREAMED_ABORT => {
            let Some(i) = write_of(s, handle, &owner) else {
                return EINVAL;
            };
            drop_write(s, i);
            0
        }
        obj_op::GET => {
            let Some(key) = obj_op::key::parse(a) else {
                return EINVAL;
            };
            let Some(slot) = live_slot(s, key) else {
                return ENXIO;
            };
            let Some(i) = reads(s).iter().position(|r| r.in_use == 0) else {
                log(s, 2, b"[store] every read slot is open; GET refused");
                return ENOMEM;
            };
            let e = entries(s)[slot as usize];
            block_hold(e.block);
            reads_mut(s)[i] = ReadSlot {
                block: e.block,
                rev: e.rev,
                owner,
                val_len: e.val_len,
                key_len: e.key_len,
                in_use: 1,
                grant,
            };
            i as i32
        }
        obj_op::RANGE_GET => {
            let Some(i) = read_of(s, handle, &owner) else {
                return ENOSYS;
            };
            let Some(offset) = obj_op::range_get::parse(a) else {
                return EINVAL;
            };
            let r = reads(s)[i];
            let val = block_val(r.block, r.key_len, r.val_len);
            let Some(tail) = usize::try_from(offset).ok().and_then(|o| val.get(o..)) else {
                return 0;
            };
            let n = tail.len().min(d.len());
            d[..n].copy_from_slice(&tail[..n]);
            n as i32
        }
        obj_op::HEAD => {
            let Some(key) = obj_op::head::parse_request(a) else {
                return EINVAL;
            };
            let Some((size, rev)) = get(s, key).map(|(v, r)| (v.len() as u64, r)) else {
                return ENXIO;
            };
            let Some(area) = obj_op::head::answer_area(a) else {
                return EINVAL;
            };
            // mtime 0: the store keeps no clock, and no kept field.
            let Some(n) = obj_op::range::encode_head(
                area,
                size,
                0,
                &[],
                &etag_from_rev(rev),
                obj_op::Kept::none(),
            ) else {
                return ENOMEM;
            };
            write_fence(view_fence(s), a);
            n as i32
        }
        obj_op::DELETE => obj_delete(s, opcode, a),
        obj_op::LIST => obj_list(s, a, d),
        obj_op::CLOSE => {
            if let Some(i) = write_of(s, handle, &owner) {
                drop_write(s, i);
            } else if let Some(i) = read_of(s, handle, &owner) {
                close_read(s, i);
            }
            0
        }
        _ => ENOSYS,
    }
}

/// `PUT`; `opcode` is the request's, which its ask is keyed by.
fn obj_put(s: &mut State, opcode: u32, a: &mut [u8], d: &[u8]) -> i32 {
    let ask = ask_of(s, opcode, a, d.len() as u64);
    if let Some(rc) = reask(s, &ask, a) {
        return rc;
    }
    let Some(req) = obj_op::put::parse(a) else {
        return EINVAL;
    };
    if !writable_key(req.key) {
        return EINVAL;
    }
    let Some(pre) = Precondition::read(req.precondition, req.etag) else {
        return EINVAL;
    };
    if !req.kept.is_none() {
        return ENOSYS;
    }
    let mut key = [0u8; STORAGE_KEY_MAX];
    let kl = req.key.len();
    key[..kl].copy_from_slice(req.key);
    put_value(s, ask, &key[..kl], pre, d, -1, a)
}

/// Write `value` under `key` if `pre` passes: the answer of a `PUT` or a
/// streamed commit.
#[allow(
    clippy::too_many_arguments,
    reason = "a value's write: its ask, key, precondition, bytes, stream and the request to answer"
)]
fn put_value(
    s: &mut State,
    ask: [u8; 32],
    key: &[u8],
    pre: Precondition,
    value: &[u8],
    stream: i16,
    a: &mut [u8],
) -> i32 {
    let existing = get(s, key).map(|(_, r)| r);
    if !pre.passes(existing) {
        // Two answers, because they ask two different things: a create-only
        // caller has lost the key; a compare-and-swap caller re-reads.
        return if pre == Precondition::Absent {
            EEXIST
        } else {
            EAGAIN
        };
    }
    let Ok(vl) = u32::try_from(value.len()) else {
        return ENOSPC;
    };
    let block = block_alloc(s, key, vl);
    if block.is_null() {
        return ENOSPC;
    }
    block_val(block, key.len() as u16, vl).copy_from_slice(value);
    let Some((slot, at)) = slot_for(s, key) else {
        block_release(s, block);
        log(s, 2, b"[store] every object slot is held; write refused");
        return ENOMEM;
    };
    let started = begin_write(
        s,
        ask,
        OP_PUT,
        slot,
        at,
        block,
        key.len() as u16,
        vl,
        stream,
    );
    answer_write(s, started, a)
}

fn obj_stream_open(s: &mut State, a: &[u8], owner: [u8; 8], grant: i16) -> i32 {
    let Some(req) = obj_op::put::parse_record(a) else {
        return EINVAL;
    };
    if !writable_key(req.key) {
        return EINVAL;
    }
    // Held, not evaluated: the commit is the linearization point.
    let Some(pre) = Precondition::read(req.precondition, req.etag) else {
        return EINVAL;
    };
    if !req.kept.is_none() {
        return ENOSYS;
    }
    let Some(i) = writes(s).iter().position(|w| w.in_use == 0) else {
        log(
            s,
            2,
            b"[store] every streamed-write slot is open; PUT_STREAMED_OPEN refused",
        );
        return ENOMEM;
    };
    let (kind, rev) = pre.encode();
    let w = &mut writes_mut(s)[i];
    w.in_use = 1;
    w.committed = 0;
    w.owner = owner;
    w.grant = grant;
    w.prec_kind = kind;
    w.prec_rev = rev;
    w.key_len = req.key.len() as u8;
    w.key[..req.key.len()].copy_from_slice(req.key);
    w.head = core::ptr::null_mut();
    w.tail = core::ptr::null_mut();
    w.staged = 0;
    WRITE_SLOT_BASE + i as i32
}

/// `PUT_STREAMED_COMMIT`; `opcode` is the request's, which its ask is keyed
/// by.
fn obj_stream_commit(
    s: &mut State,
    opcode: u32,
    handle: i32,
    a: &mut [u8],
    owner: &[u8; 8],
) -> i32 {
    let Some(i) = write_of(s, handle, owner) else {
        return EINVAL;
    };
    if a.len() != obj_op::COMMIT_ARG_LEN {
        return EINVAL;
    }
    let mut id = [0u8; 4];
    id.copy_from_slice(&handle.to_le_bytes());
    let ask = ask_of(s, opcode, &id, 0);
    if let Some(rc) = reask(s, &ask, a) {
        return rc;
    }
    if writes(s)[i].committed != 0 {
        return EINVAL;
    }
    let w = writes(s)[i];
    let key = &w.key[..usize::from(w.key_len)];
    let pre = Precondition::decode(w.prec_kind, w.prec_rev);
    let existing = get(s, key).map(|(_, r)| r);
    if !pre.passes(existing) {
        // The stream is finished either way; a retry is a new one.
        free_chunks(s, i);
        return if pre == Precondition::Absent {
            EEXIST
        } else {
            EAGAIN
        };
    }
    let block = block_alloc(s, key, w.staged);
    if block.is_null() {
        // Still staged: the caller may abort, or commit once room is made.
        return ENOSPC;
    }
    unstage(s, i, block_val(block, w.key_len.into(), w.staged));
    free_chunks(s, i);
    let Some((slot, at)) = slot_for(s, key) else {
        block_release(s, block);
        return ENOMEM;
    };
    let started = begin_write(
        s,
        ask,
        OP_PUT,
        slot,
        at,
        block,
        u16::from(w.key_len),
        w.staged,
        i as i16,
    );
    if started == Some(0) {
        writes_mut(s)[i].committed = 1;
    }
    answer_write(s, started, a)
}

/// `DELETE`; `opcode` is the request's, which its ask is keyed by.
fn obj_delete(s: &mut State, opcode: u32, a: &mut [u8]) -> i32 {
    let ask = ask_of(s, opcode, a, 0);
    if let Some(rc) = reask(s, &ask, a) {
        return rc;
    }
    let Some(req) = obj_op::delete::parse_request(a) else {
        return EINVAL;
    };
    let Some(pre) = Precondition::read(req.precondition, req.etag) else {
        return EINVAL;
    };
    let mut key = [0u8; STORAGE_KEY_MAX];
    if req.key.len() > STORAGE_KEY_MAX {
        return EINVAL;
    }
    let kl = req.key.len();
    key[..kl].copy_from_slice(req.key);
    let existing = get(s, &key[..kl]).map(|(_, r)| r);
    if !pre.passes(existing) {
        return EAGAIN;
    }
    let Some(slot) = live_slot(s, &key[..kl]) else {
        // An unconditional delete of an absent key changes nothing, at the
        // current revision.
        let rev = s.revision;
        write_fence(write_fence_of(s, rev), a);
        return 0;
    };
    let started = begin_write(
        s,
        ask,
        OP_DELETE,
        slot,
        None,
        core::ptr::null_mut(),
        kl as u16,
        0,
        -1,
    );
    answer_write(s, started, a)
}

fn obj_list(s: &mut State, a: &mut [u8], d: &mut [u8]) -> i32 {
    let Some(req) = obj_op::list::parse_request(a) else {
        return EINVAL;
    };
    let after = match list_cursor(req.cursor, req.prefix) {
        Ok(after) => after,
        Err(e) => return e,
    };
    let mut page = obj_op::list::PageWriter::new(d, req.max_keys);
    let mut last: Option<u32> = None;
    let mut more = false;
    let mut p = walk_start(s, req.prefix, after);
    while p < s.n_index as usize {
        let slot = index(s)[p];
        let e = entries(s)[slot as usize];
        let key = block_key(e.block, e.key_len);
        if !key.starts_with(req.prefix) {
            break;
        }
        p += 1;
        if e.flags != ENTRY_LIVE {
            continue;
        }
        if page.is_full() {
            more = true;
            break;
        }
        // A key no cursor can carry refuses the listing rather than vanish
        // from it (only a hand-seeded log holds one).
        if key.len() > STORAGE_KEY_MAX {
            return EOVERFLOW;
        }
        if !page.push(key, u64::from(e.val_len), 0, &etag_from_rev(e.rev)) {
            more = true;
            break;
        }
        last = Some(slot);
    }
    let cursor: &[u8] = match last {
        Some(slot) if more => key_of(s, slot),
        None if more => return ENOMEM,
        _ => &[],
    };
    let Some(n) = page.finish(cursor) else {
        return ENOMEM;
    };
    write_fence(view_fence(s), a);
    n as i32
}
