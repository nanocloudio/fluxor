// ── storage.namespace ─────────────────────────────────────────────────
//
// `LIST` (key-shaped), `SUBSCRIBE` and `CHANGES`. The store is written
// through `storage.object`, so this surface has no `BIND`, `RENAME` or
// `DELETE`, and no per-path handle (`LOOKUP`, `STAT`).

/// Subscriptions one heap page holds.
const SUB_PAGE: usize = 8;
/// Pages the store keeps a subscription table in, at most.
const MAX_SUB_PAGES: usize = 512;
/// Subscription handles are slots from here up: apart from `GET` reads, so
/// a fence query on a handle names one kind of slot.
const SUB_BAND: i32 = 0x4000;

/// A subscription: a prefix and the doorbell the kernel handed for it.
#[repr(C)]
#[derive(Clone, Copy)]
struct Sub {
    owner: [u8; 8],
    /// The doorbell to ring (`kernel::BIND_DOORBELL`); -1 until bound.
    doorbell: i32,
    in_use: u8,
    /// A ring came before the doorbell did: rung when it is bound.
    owed: u8,
    prefix_len: u8,
    prefix: [u8; STORAGE_KEY_MAX],
}

fn sub_count(s: &State) -> usize {
    usize::from(s.n_sub_pages) * SUB_PAGE
}

fn sub_at(s: &State, i: usize) -> &Sub {
    let page = s.sub_pages[i / SUB_PAGE];
    // SAFETY: page `i / SUB_PAGE` was taken whole from the heap and lives
    // for the instance.
    unsafe { &*page.cast::<Sub>().add(i % SUB_PAGE) }
}

fn sub_mut(s: &mut State, i: usize) -> &mut Sub {
    let page = s.sub_pages[i / SUB_PAGE];
    // SAFETY: as `sub_at`.
    unsafe { &mut *page.cast::<Sub>().add(i % SUB_PAGE) }
}

fn live_subs(s: &State) -> usize {
    (0..sub_count(s))
        .filter(|&i| sub_at(s, i).in_use != 0)
        .count()
}

/// The subscription slot `handle` names, if it is a live one.
fn sub_slot(s: &State, handle: i32) -> Option<usize> {
    if !(SUB_BAND..WRITE_SLOT_BASE).contains(&handle) {
        return None;
    }
    let i = (handle - SUB_BAND) as usize;
    (i < sub_count(s) && sub_at(s, i).in_use != 0).then_some(i)
}

/// The caller's own live subscription `handle` names.
fn callers_sub(s: &State, handle: i32) -> Option<usize> {
    let i = sub_slot(s, handle)?;
    (sub_at(s, i).owner == caller_owner(s)).then_some(i)
}

/// A free subscription slot, a page taken from the heap when every slot is
/// held. `None` when the heap holds no more: the refusal is counted against
/// `store_subs`.
fn take_sub(s: &mut State) -> Option<usize> {
    if let Some(i) = (0..sub_count(s)).find(|&i| sub_at(s, i).in_use == 0) {
        return Some(i);
    }
    if usize::from(s.n_sub_pages) < MAX_SUB_PAGES {
        let page: *mut Sub = take_table(s, SUB_PAGE);
        if !page.is_null() {
            let n = usize::from(s.n_sub_pages);
            s.sub_pages[n] = page.cast();
            s.n_sub_pages += 1;
            return Some(n * SUB_PAGE);
        }
    }
    let mut pool = abi::contracts::resource::POOL_STORE_SUBS.to_le_bytes();
    let _ = kcall(s, abi::contracts::resource::LEDGER_DENY, &mut pool);
    log(
        s,
        2,
        b"[store] the heap holds no more subscriptions; SUBSCRIBE refused",
    );
    None
}

/// Ring subscription `i`'s doorbell, or owe the ring until it is bound.
fn ring(s: &mut State, i: usize) {
    let sub = sub_mut(s, i);
    if sub.in_use == 0 {
        return;
    }
    if sub.doorbell < 0 {
        sub.owed = 1;
        return;
    }
    sub.owed = 0;
    let mut arg = doorbell::ring_arg(sub.doorbell as u32);
    let _ = kcall(s, doorbell::DOORBELL_RING, &mut arg);
}

/// Ring every subscription whose prefix holds `key`. A write is the ring
/// point: the store writes no subscriber's channel, it rings a doorbell.
fn ring_matching(s: &mut State, key: &[u8]) {
    for i in 0..sub_count(s) {
        let sub = sub_at(s, i);
        if sub.in_use != 0 && key.starts_with(&sub.prefix[..usize::from(sub.prefix_len)]) {
            ring(s, i);
        }
    }
}

fn release_subs_of(s: &mut State, owner: &[u8; 8]) {
    for i in 0..sub_count(s) {
        let sub = sub_mut(s, i);
        if sub.in_use != 0 && &sub.owner == owner {
            sub.in_use = 0;
        }
    }
}

/// `kernel::BIND_DOORBELL` for subscription `handle`: keep the doorbell,
/// and ring it at once when a ring is owed.
fn ns_bind_doorbell(s: &mut State, handle: i32, a: &[u8]) -> i32 {
    let Some((d, _)) = doorbell::parse_bind(a) else {
        return EINVAL;
    };
    let Some(i) = callers_sub(s, handle) else {
        return EBADF;
    };
    let sub = sub_mut(s, i);
    sub.doorbell = d as i32;
    if sub.owed != 0 {
        ring(s, i);
    }
    0
}

/// `CLOSE`: the kernel closes a subscription it holds a route to, whoever
/// is running when it does (a departing subscriber included).
fn ns_close(s: &mut State, handle: i32) -> i32 {
    if let Some(i) = sub_slot(s, handle) {
        sub_mut(s, i).in_use = 0;
    }
    0
}

fn namespace_call(s: &mut State, handle: i32, opcode: u32, a: &mut [u8], d: &mut [u8]) -> i32 {
    // A guarded store is reached through `storage.object` under a grant;
    // this surface cannot carry one, so it answers nothing a scope hides.
    if s.guarded() {
        return EACCES;
    }
    match opcode {
        ns_op::LIST => {
            let Some(req) = ns_op::list::parse_request(a) else {
                return EINVAL;
            };
            let after = match list_cursor(req.cursor, req.prefix) {
                Ok(after) => after,
                Err(e) => return e,
            };
            let mut page = ns_op::list::PageWriter::new(d);
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
                if key.len() > STORAGE_KEY_MAX {
                    return EOVERFLOW;
                }
                if !page.push(key, ns_op::KIND_OBJECT) {
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
        ns_op::SUBSCRIBE => {
            let Some(req) = ns_op::subscribe::parse(a) else {
                return EINVAL;
            };
            // Keys are UTF-8: a prefix that is not could match nothing.
            if req.prefix.len() > STORAGE_KEY_MAX || !utf8_valid(req.prefix) {
                return EINVAL;
            }
            let owner = caller_owner(s);
            let Some(i) = take_sub(s) else {
                return ENOMEM;
            };
            let sub = sub_mut(s, i);
            sub.in_use = 1;
            sub.owner = owner;
            sub.doorbell = -1;
            sub.owed = u8::from(req.flags & ns_op::subscribe::FLAG_RING_NOW != 0);
            sub.prefix_len = req.prefix.len() as u8;
            sub.prefix[..req.prefix.len()].copy_from_slice(req.prefix);
            SUB_BAND + i as i32
        }
        ns_op::CHANGES => {
            // The handle names the subscription the read serves; this store
            // answers inside the call and never rings one later. It is the
            // caller's own or none.
            if handle >= 0 && callers_sub(s, handle).is_none() {
                return EBADF;
            }
            let Some(req) = ns_op::changes::parse_request(a) else {
                return EINVAL;
            };
            let mut prefix = [0u8; STORAGE_KEY_MAX];
            let mut token = [0u8; RELIST_TOKEN_HEAD + STORAGE_KEY_MAX];
            if req.prefix.len() > prefix.len() || req.token.len() > token.len() {
                return EINVAL;
            }
            let (pl, tl) = (req.prefix.len(), req.token.len());
            prefix[..pl].copy_from_slice(req.prefix);
            token[..tl].copy_from_slice(req.token);
            let n = changes(s, &prefix[..pl], &token[..tl], d);
            if n >= 0 {
                write_fence(view_fence(s), a);
            }
            n
        }
        ns_op::LOOKUP | ns_op::STAT => ENOSYS,
        _ => ENOSYS,
    }
}
