//! Store contract probe — proves `storage.object` + `storage.namespace` work
//! ON THE BOARD.
//!
//! A provider that compiles is not a provider that works, and a store-backed
//! graph reports neither: a source whose subscription never rings looks
//! exactly like a source with nothing to report. This fixture is the evidence the graph
//! itself cannot give.
//!
//! It walks the whole contract surface a store consumer uses, in order, and
//! stops at the first failure so the heartbeat names the step that broke. Keys
//! under `/probe/` are its own — it proves the contracts against state it
//! created, so it depends on nothing else in the graph. It empties the
//! prefix first: a store on a disk keeps whatever an earlier boot left.
//!
//!   1 PUT      two objects under one prefix
//!   2 GET      read one back and byte-compare it
//!   3 LIST     enumerate the prefix, expect both
//!   4 SUBSCRIBE + PUT, then wait for the ring — the wake a source depends
//!     on: the store rings the subscription's doorbell, the subscription
//!     handle polls ready, and a CHANGES read finds the write
//!   5 DELETE   remove one, LIST again, expect one
//!
//! A write the store has not decided (`EINPROGRESS`) is asked again next
//! step with the same request, and a read or a listing the store answers
//! "not yet" (`EAGAIN` -- `fs_object` over FAT32 does while it walks a large
//! directory) is asked again the same way rather than called a failure.
//!
//! `subscribe` (default 1) can be set 0 for a store with no subscriptions,
//! such as `fs_object`: step 4 then writes without subscribing, and the
//! verdict does not ask for a ring.
//!
//! **Acceptance:** `[stp] state=5 pass=1 put=3 got=1 listed=2 rung=N del=1
//! wit_a=A wit_b=B err=0`. Any `state=99` names the failure in `err`.
//! `rung` is the count of rings that ARRIVED and whose CHANGES read found
//! the write. It is reported separately rather than folded into the PUT's
//! pass/fail: a PUT that lands and a watcher that is never told are
//! different failures, and only the second is silent.
//!
//! WITNESS PREFIXES. `witness_a` / `witness_b` are optional graph params: each
//! is a prefix this probe LISTs on every heartbeat and reports the count of.
//! They exist because a store lives in RAM with nothing to inspect after a run,
//! so a graph whose own chain is asynchronous has no way to say what it
//! produced. The probe supplies the counting; the graph supplies the prefixes,
//! and what they mean is the graph's business, not this fixture's. Unset
//! prefixes are not listed and report 0.
//!
//! `after_ms` holds the probe until that long after boot, so its calls land
//! once the board's telemetry is up. `op_gap_ms` pauses between calls, each
//! announced by a heartbeat first: on a board that dies inside a call, the
//! last line that arrives names it.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

// storage.object (0x14) and storage.namespace (0x13).
// Opcodes come from the contracts this fixture drives, not from literals:
// a probe that restates the wire can pass against its own copy of it.
const OBJ_PUT: u32 = abi::contracts::storage::object::PUT;
const OBJ_GET: u32 = abi::contracts::storage::object::GET;
const OBJ_RANGE_GET: u32 = abi::contracts::storage::object::RANGE_GET;
const OBJ_DELETE: u32 = abi::contracts::storage::object::DELETE;
const OBJ_CLOSE: u32 = abi::contracts::storage::object::CLOSE;
use abi::contracts::storage::object::{write_answer, WriteAnswer};

const ENOENT: i32 = abi::kernel_abi::errno::ENOENT;
const NS_LIST: u32 = abi::contracts::storage::namespace::LIST;
const NS_SUBSCRIBE: u32 = abi::contracts::storage::namespace::SUBSCRIBE;
const NS_CHANGES: u32 = abi::contracts::storage::namespace::CHANGES;

const PREFIX: &[u8] = b"/probe/";
const KEY_A: &[u8] = b"/probe/a";
const KEY_B: &[u8] = b"/probe/b";
const KEY_C: &[u8] = b"/probe/c";
const VAL_A: &[u8] = b"{\"kind\":\"Probe\",\"n\":1}";
const VAL_C: &[u8] = b"{\"kind\":\"Probe\",\"n\":3}";

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    /// The subscription handle SUBSCRIBE returned; -1 before.
    sub: i32,
    out_chan: i32,
    step: u32,
    state: u32,
    pass: u32,
    put: u32,
    got: u32,
    listed: u32,
    /// Rings that arrived and whose CHANGES read found the write.
    rung: u32,
    del: u32,
    /// Objects under `witness_a` — evidence about a DIFFERENT module,
    /// reported by one that provably logs from this board. "Did it run" and
    /// "did its log reach me" are separate questions and the silent case
    /// cannot tell them apart.
    wit_a: u32,
    /// Objects under `witness_b`. Counted on every heartbeat, not once,
    /// because a chain that wakes on a change takes several passes: a single
    /// early sample would report zero and call a working chain broken.
    wit_b: u32,
    err: i32,
    /// Set once the verdict has been emitted. State 5 is TERMINAL — it is the
    /// state the acceptance line names — so completion is a separate flag
    /// rather than a state the probe advances into and out of.
    done: u32,
    /// Caller-named prefixes to LIST on each heartbeat. Empty = not watched.
    wit_a_pfx: [u8; MAX_WITNESS],
    wit_a_len: u32,
    wit_b_pfx: [u8; MAX_WITNESS],
    wit_b_len: u32,
    /// Start no earlier than this, in ms since boot (`after_ms`).
    after_ms: u32,
    /// Pause between store calls, in ms (`op_gap_ms`), each announced by a
    /// heartbeat first: on a board that dies inside a call, the last line
    /// that arrives names the call. 0 = no pause.
    op_gap_ms: u32,
    next_at: u64,
    /// Set once the prefix is empty: a durable store keeps what an
    /// earlier boot left under it, which the LIST would count.
    cleared: u32,
    /// The key being deleted while the prefix is emptied, held until its
    /// DELETE is decided so the write is asked again with the same request
    /// (a LIST in between no longer names a key whose unlink has happened).
    /// Empty when none is in flight.
    clear_key: [u8; MAX_WITNESS],
    clear_len: u32,
    /// 0 until subscribed in state 3 (a write asked again does not
    /// subscribe again), 1 subscribed, 2 rung and reading, 3 rung but the
    /// read did not find the write.
    subscribed: u32,
    /// Whether to prove SUBSCRIBE (`subscribe`, default 1). A store with no
    /// subscriptions -- `fs_object` -- is walked with it 0: step 4 then
    /// writes without subscribing, and the verdict does not ask for a ring.
    want_ring: u32,
    scratch: [u8; 1024],
}

/// Longest witness prefix. A prefix is a path fragment, not a key.
const MAX_WITNESS: usize = 96;

mod params_def {
    use super::ptr_copy;
    use super::State;
    use super::MAX_WITNESS;

    fluxor_rt::define_params! {
        State;

        1, witness_a, str, 0
            => |s, d, len| {
                let n = if len > MAX_WITNESS { MAX_WITNESS } else { len };
                s.wit_a_len = n as u32;
                if n > 0 { ptr_copy(s.wit_a_pfx.as_mut_ptr(), d, n); }
            };

        2, witness_b, str, 0
            => |s, d, len| {
                let n = if len > MAX_WITNESS { MAX_WITNESS } else { len };
                s.wit_b_len = n as u32;
                if n > 0 { ptr_copy(s.wit_b_pfx.as_mut_ptr(), d, n); }
            };

        3, after_ms, u32, 0
            => |s, d, len| { s.after_ms = super::p_u32(d, len, 0, 0); };

        4, op_gap_ms, u32, 0
            => |s, d, len| { s.op_gap_ms = super::p_u32(d, len, 0, 0); };

        5, subscribe, u8, 1
            => |s, d, len| { s.want_ring = u32::from(super::p_u8(d, len, 0, 1)); };
    }
}

#[inline(always)]
unsafe fn ptr_copy(dst: *mut u8, src: *const u8, n: usize) {
    core::ptr::copy_nonoverlapping(src, dst, n);
}

/// LIST both witness prefixes and record their counts. An unset prefix is
/// not listed and counts 0 — the graph that named none is simply not
/// witnessed. A listing that fails or is not yet answered keeps the last
/// count rather than reporting an empty prefix.
unsafe fn witness_counts(sys: &SyscallTable, s: &mut State) {
    let mut scratch = [0u8; 1024];
    let mut one = |pfx: &[u8], last: u32| -> u32 {
        if pfx.is_empty() {
            return 0;
        }
        let n = list_count(sys, pfx, &mut scratch);
        if n >= 0 {
            n as u32
        } else {
            last
        }
    };
    s.wit_a = one(&s.wit_a_pfx[..s.wit_a_len as usize], s.wit_a);
    s.wit_b = one(&s.wit_b_pfx[..s.wit_b_len as usize], s.wit_b);
}

unsafe fn put(sys: &SyscallTable, key: &[u8], val: &[u8]) -> WriteAnswer {
    use abi::contracts::storage::object::{precondition, put, Kept};
    let mut arg = [0u8; put::arg_len(abi::contracts::storage::handle::STORAGE_KEY_MAX, 0, 0, 0)];
    let req = put::Request {
        key,
        content_type: &[],
        precondition: precondition::ANY,
        etag: &[],
        kept: Kept::none(),
    };
    let Some(len) = put::encode(&mut arg, &req) else {
        return WriteAnswer::Decided(E_INVAL);
    };
    write_answer((sys.provider_call)(
        -1,
        OBJ_PUT,
        arg.as_mut_ptr(),
        len,
        val.as_ptr() as *mut u8,
        val.len(),
    ))
}

unsafe fn get(sys: &SyscallTable, key: &[u8], dst: &mut [u8]) -> i32 {
    use abi::contracts::storage::object::{key as okey, range_get};
    let mut karg = [0u8; okey::ARG_MAX];
    let Some(klen) = okey::encode(&mut karg, key) else {
        return E_INVAL;
    };
    let h = (sys.provider_call)(
        -1,
        OBJ_GET,
        karg.as_mut_ptr(),
        klen,
        core::ptr::null_mut(),
        0,
    );
    if h < 0 {
        return h;
    }
    let mut rarg = range_get::encode(0);
    let n = (sys.provider_call)(
        h,
        OBJ_RANGE_GET,
        rarg.as_mut_ptr(),
        rarg.len(),
        dst.as_mut_ptr(),
        dst.len(),
    );
    (sys.provider_call)(
        h,
        OBJ_CLOSE,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
    );
    n
}

unsafe fn delete(sys: &SyscallTable, key: &[u8]) -> WriteAnswer {
    use abi::contracts::storage::object::{delete, precondition};
    let mut arg = [0u8; delete::arg_len(abi::contracts::storage::handle::STORAGE_KEY_MAX, 0)];
    let req = delete::Request {
        key,
        precondition: precondition::ANY,
        etag: &[],
    };
    let Some(len) = delete::encode_request(&mut arg, &req) else {
        return WriteAnswer::Decided(E_INVAL);
    };
    write_answer((sys.provider_call)(
        -1,
        OBJ_DELETE,
        arg.as_mut_ptr(),
        len,
        core::ptr::null_mut(),
        0,
    ))
}

/// LIST every page of `prefix`; returns the number of entries counted, or a
/// negative errno. Each page resumes after the last name the previous one
/// returned.
unsafe fn list_count(sys: &SyscallTable, prefix: &[u8], page: &mut [u8]) -> i32 {
    use abi::contracts::storage::namespace::list;
    let mut cursor = [0u8; abi::contracts::storage::handle::STORAGE_KEY_MAX];
    let mut cursor_len = 0usize;
    let mut count = 0i32;
    let mut pages = 0;
    while pages < 4096 {
        pages += 1;
        let req = list::Request {
            prefix,
            cursor: &cursor[..cursor_len],
        };
        let mut arg = [0u8; list::ARG_MAX];
        let Some(len) = list::encode_request(&mut arg, &req) else {
            return E_INVAL;
        };
        let n = (sys.provider_call)(
            -1,
            NS_LIST,
            arg.as_mut_ptr(),
            len,
            page.as_mut_ptr(),
            page.len(),
        );
        if n < 0 {
            return n;
        }
        let Some(decoded) = list::decode_page(&page[..n as usize]) else {
            return E_INVAL;
        };
        count += decoded.entries().count() as i32;
        if decoded.is_last() {
            return count;
        }
        let next = decoded.cursor();
        cursor[..next.len()].copy_from_slice(next);
        cursor_len = next.len();
    }
    E_INVAL
}

/// One LIST page of `prefix`, from its first entry, into `page`: the bytes
/// written, or a negative errno.
unsafe fn list_page(sys: &SyscallTable, prefix: &[u8], page: &mut [u8]) -> i32 {
    use abi::contracts::storage::namespace::list;
    let req = list::Request {
        prefix,
        cursor: &[],
    };
    let mut arg = [0u8; list::ARG_MAX];
    let Some(len) = list::encode_request(&mut arg, &req) else {
        return E_INVAL;
    };
    (sys.provider_call)(
        -1,
        NS_LIST,
        arg.as_mut_ptr(),
        len,
        page.as_mut_ptr(),
        page.len(),
    )
}

/// The key of the first entry LIST returns under `prefix`, copied into
/// `out`: its length, 0 when the prefix is empty, or a negative errno. An
/// entry is named relative to the prefix, so the key is the two joined; a
/// child that is itself a namespace is not an object and answers `EINVAL`.
unsafe fn first_key(sys: &SyscallTable, prefix: &[u8], page: &mut [u8], out: &mut [u8]) -> i32 {
    use abi::contracts::storage::namespace::{list, KIND_OBJECT};
    let n = list_page(sys, prefix, page);
    if n < 0 {
        return n;
    }
    let Some(decoded) = list::decode_page(&page[..n as usize]) else {
        return E_INVAL;
    };
    // A directory-shaped store names an entry relative to the prefix; a
    // key-shaped one names the whole key. The contract says which by
    // `CHILD_NAMES`.
    let mut caps = [0u8; abi::kernel_abi::caps_word::LEN];
    let rc = (sys.provider_call)(
        -1,
        abi::contracts::storage::namespace::CAPS,
        caps.as_mut_ptr(),
        caps.len(),
        core::ptr::null_mut(),
        0,
    );
    let child_names = rc == 0
        && u32::from_le_bytes(caps) & abi::contracts::storage::namespace::caps::CHILD_NAMES != 0;
    let head = if child_names { prefix } else { &[][..] };
    match decoded.entries().next() {
        None => 0,
        Some(e) if e.kind == KIND_OBJECT && head.len() + e.name.len() <= out.len() => {
            out[..head.len()].copy_from_slice(head);
            out[head.len()..head.len() + e.name.len()].copy_from_slice(e.name);
            (head.len() + e.name.len()) as i32
        }
        Some(_) => E_INVAL,
    }
}

/// Log the names on the first LIST page of `prefix` — what a count that
/// came out wrong actually counted.
unsafe fn log_names(sys: &SyscallTable, prefix: &[u8], page: &mut [u8]) {
    use abi::contracts::storage::namespace::list;
    let n = list_page(sys, prefix, page);
    if n < 0 {
        return;
    }
    let Some(decoded) = list::decode_page(&page[..n as usize]) else {
        return;
    };
    let mut line = [0u8; 160];
    let head = b"[stp] listed:";
    line[..head.len()].copy_from_slice(head);
    let mut pos = head.len();
    for e in decoded.entries() {
        if pos + 1 + e.name.len() > line.len() {
            break;
        }
        line[pos] = b' ';
        line[pos + 1..pos + 1 + e.name.len()].copy_from_slice(e.name);
        pos += 1 + e.name.len();
    }
    dev_log(sys, 3, line.as_ptr(), pos);
}

unsafe fn subscribe(sys: &SyscallTable, prefix: &[u8]) -> i32 {
    use abi::contracts::storage::namespace::subscribe;
    let mut arg = [0u8; subscribe::ARG_MAX];
    // No ring at subscribe — we want the ring the WRITE causes.
    let req = subscribe::Request { prefix, flags: 0 };
    let Some(len) = subscribe::encode(&mut arg, &req) else {
        return E_INVAL;
    };
    (sys.provider_call)(
        -1,
        NS_SUBSCRIBE,
        arg.as_mut_ptr(),
        len,
        core::ptr::null_mut(),
        0,
    )
}

/// Whether subscription `sub` rang since the last poll: 1 rang, 0 not
/// (yet), or a negative errno. `HANDLE_POLL` takes the ring.
unsafe fn rang(sys: &SyscallTable, sub: i32) -> i32 {
    let rc = dev_fd_poll(sys, sub, POLL_IN);
    if rc < 0 {
        return rc;
    }
    i32::from(rc as u32 & POLL_IN != 0)
}

/// Relist `prefix` through CHANGES, every page, and report whether `key`
/// came back with `val`: 1 found, 0 not, or a negative errno. A watcher
/// reads what it was rung for, through its subscription `sub`; this is that
/// read.
unsafe fn changes_has(
    sys: &SyscallTable,
    prefix: &[u8],
    sub: i32,
    key: &[u8],
    val: &[u8],
    page: &mut [u8],
) -> i32 {
    use abi::contracts::storage::namespace::changes;
    let mut token = [0u8; changes::TOKEN_MAX];
    let mut token_len = 0usize;
    let mut found = 0;
    let mut pages = 0;
    while pages < 4096 {
        pages += 1;
        let req = changes::Request {
            prefix,
            token: &token[..token_len],
        };
        let mut arg = [0u8; changes::ARG_MAX];
        let Some(len) = changes::encode_request(&mut arg, &req) else {
            return E_INVAL;
        };
        let n = (sys.provider_call)(
            sub,
            NS_CHANGES,
            arg.as_mut_ptr(),
            len,
            page.as_mut_ptr(),
            page.len(),
        );
        if n < 0 {
            return n;
        }
        let Some(decoded) = changes::decode_page(&page[..n as usize]) else {
            return E_INVAL;
        };
        if decoded.lost {
            // The history moved past the revision the relist pinned: the
            // walk starts over.
            token_len = 0;
            found = 0;
            continue;
        }
        if decoded
            .records()
            .any(|r| r.kind != changes::KIND_DELETED && r.key == key && r.val == val)
        {
            found = 1;
        }
        if !decoded.more {
            return found;
        }
        token[..decoded.token.len()].copy_from_slice(decoded.token);
        token_len = decoded.token.len();
    }
    E_INVAL
}

fn write_dec(p: *mut u8, pos: &mut usize, mut v: u32) {
    let mut tmp = [0u8; 10];
    let mut n = 0usize;
    if v == 0 {
        tmp[0] = b'0';
        n = 1;
    }
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    unsafe {
        for i in 0..n {
            *p.add(*pos + i) = tmp[n - 1 - i];
        }
    }
    *pos += n;
}

unsafe fn emit(s: &State) {
    let mut buf = [0u8; 160];
    let p = buf.as_mut_ptr();
    let mut pos = 0usize;
    macro_rules! lit {
        ($b:expr) => {{
            let b = $b;
            core::ptr::copy_nonoverlapping(b.as_ptr(), p.add(pos), b.len());
            pos += b.len();
        }};
    }
    lit!(b"[stp] state=");
    write_dec(p, &mut pos, s.state);
    lit!(b" pass=");
    write_dec(p, &mut pos, s.pass);
    lit!(b" put=");
    write_dec(p, &mut pos, s.put);
    lit!(b" got=");
    write_dec(p, &mut pos, s.got);
    lit!(b" listed=");
    write_dec(p, &mut pos, s.listed);
    lit!(b" rung=");
    write_dec(p, &mut pos, s.rung);
    lit!(b" del=");
    write_dec(p, &mut pos, s.del);
    lit!(b" wit_a=");
    write_dec(p, &mut pos, s.wit_a);
    lit!(b" wit_b=");
    write_dec(p, &mut pos, s.wit_b);
    lit!(b" err=");
    write_dec(p, &mut pos, s.err.unsigned_abs());
    dev_log(&*s.syscalls, 3, p, pos);
}

fluxor_rt::module_facts! { state: State }

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<State>() {
            return -2;
        }
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.sub = -1;
        s.out_chan = out_chan;
        s.step = 0;
        s.state = 0;
        s.pass = 0;
        s.put = 0;
        s.got = 0;
        s.listed = 0;
        s.rung = 0;
        s.del = 0;
        s.err = 0;
        s.wit_a = 0;
        s.wit_b = 0;
        s.done = 0;
        s.wit_a_len = 0;
        s.wit_b_len = 0;
        s.after_ms = 0;
        s.op_gap_ms = 0;
        s.next_at = 0;
        s.cleared = 0;
        s.clear_len = 0;
        s.subscribed = 0;
        params_def::set_defaults(s);
        params_def::parse_tlv(s, params, params_len);
        0
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub extern "C" fn module_step(state: *mut u8) -> StepReturn {
    unsafe {
        if state.is_null() {
            return StepReturn::Continue;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return StepReturn::Continue;
        }
        let sys = &*s.syscalls;
        if s.after_ms != 0 && dev_millis(sys) < u64::from(s.after_ms) {
            return StepReturn::Continue;
        }
        if s.op_gap_ms != 0 && s.done == 0 && s.state != 99 {
            let now = dev_millis(sys);
            if s.next_at == 0 {
                // Announce the call, then make it once the line is away.
                emit(s);
                s.next_at = now + u64::from(s.op_gap_ms);
                return StepReturn::Continue;
            }
            if now < s.next_at {
                return StepReturn::Continue;
            }
            s.next_at = 0;
        }
        s.step = s.step.wrapping_add(1);

        match s.state {
            0 if s.cleared == 0 => {
                // 0. Start from an empty prefix: a store on a disk keeps
                // whatever an earlier boot left under it. The first key the
                // LIST returns is deleted, asked again until decided, then
                // the next, until the LIST is empty.
                if s.clear_len == 0 {
                    let mut key = [0u8; MAX_WITNESS];
                    let n = first_key(sys, PREFIX, &mut s.scratch, &mut key);
                    if n == E_AGAIN {
                        return StepReturn::Continue;
                    }
                    if n < 0 {
                        s.err = -10;
                        s.state = 99;
                        emit(s);
                        return StepReturn::Continue;
                    }
                    if n == 0 {
                        s.cleared = 1;
                        return StepReturn::Continue;
                    }
                    s.clear_key = key;
                    s.clear_len = n as u32;
                }
                let key = s.clear_key;
                match delete(sys, &key[..s.clear_len as usize]) {
                    WriteAnswer::Pending => {}
                    // Gone either way: clearing wants the key absent, and a
                    // DELETE whose answer a fault lost finds it so when asked
                    // again.
                    WriteAnswer::Decided(0 | ENOENT) => s.clear_len = 0,
                    WriteAnswer::Decided(_) => {
                        s.err = -11;
                        s.state = 99;
                        emit(s);
                    }
                }
            }
            0 => {
                // 1. PUT two objects. A write the store has not decided yet
                // is asked again next step, with the same request.
                let (key, err) = if s.put == 0 { (KEY_A, -1) } else { (KEY_B, -2) };
                match put(sys, key, VAL_A) {
                    WriteAnswer::Pending => return StepReturn::Continue,
                    WriteAnswer::Decided(0) => s.put += 1,
                    WriteAnswer::Decided(_) => {
                        s.err = err;
                        s.state = 99;
                        emit(s);
                        return StepReturn::Continue;
                    }
                }
                if s.put == 2 {
                    s.state = 1;
                }
            }
            1 => {
                // 2. GET one back and BYTE-COMPARE. A provider that answers a
                // length without the bytes passes a shallower check than this.
                let mut buf = [0u8; 256];
                let n = get(sys, KEY_A, &mut buf);
                if n == E_AGAIN {
                    return StepReturn::Continue;
                }
                if n as usize != VAL_A.len() || &buf[..VAL_A.len()] != VAL_A {
                    s.err = -3;
                    s.state = 99;
                    emit(s);
                    return StepReturn::Continue;
                }
                s.got = 1;
                s.state = 2;
            }
            2 => {
                // 3. LIST the prefix.
                let n = list_count(sys, PREFIX, &mut s.scratch);
                if n == E_AGAIN {
                    return StepReturn::Continue;
                }
                if n < 0 {
                    s.err = -4;
                    s.state = 99;
                    emit(s);
                    return StepReturn::Continue;
                }
                s.listed = n as u32;
                if s.listed != 2 {
                    log_names(sys, PREFIX, &mut s.scratch);
                    s.err = -5;
                    s.state = 99;
                    emit(s);
                    return StepReturn::Continue;
                }
                s.state = 3;
            }
            3 => {
                // 4. SUBSCRIBE, then write — the wake every source depends on.
                // A store with no subscriptions writes and moves on.
                if s.want_ring == 0 {
                    match put(sys, KEY_C, VAL_C) {
                        WriteAnswer::Pending => return StepReturn::Continue,
                        WriteAnswer::Decided(0) => {}
                        WriteAnswer::Decided(_) => {
                            s.err = -8;
                            s.state = 99;
                            emit(s);
                            return StepReturn::Continue;
                        }
                    }
                    s.put += 1;
                    s.state = 5;
                    return StepReturn::Continue;
                }
                if s.subscribed == 0 {
                    let h = subscribe(sys, PREFIX);
                    if h == E_AGAIN {
                        return StepReturn::Continue;
                    }
                    if h < 0 {
                        s.err = -7;
                        s.state = 99;
                        emit(s);
                        return StepReturn::Continue;
                    }
                    s.sub = h;
                    s.subscribed = 1;
                }
                match put(sys, KEY_C, VAL_C) {
                    WriteAnswer::Pending => return StepReturn::Continue,
                    WriteAnswer::Decided(0) => {}
                    WriteAnswer::Decided(_) => {
                        s.err = -8;
                        s.state = 99;
                        emit(s);
                        return StepReturn::Continue;
                    }
                }
                s.put += 1;
                s.state = 4;
            }
            4 => {
                // Wait for the ring. It must ARRIVE, not merely have been
                // accepted: SUBSCRIBE returning a handle proves nothing about
                // whether a change ever rings it. Once it rings, the
                // read it asks for must find the write. A read the store
                // answers "not yet" is asked again next step.
                if s.subscribed == 1 && rang(sys, s.sub) == 1 {
                    s.subscribed = 2;
                }
                if s.subscribed == 2 {
                    match changes_has(sys, PREFIX, s.sub, KEY_C, VAL_C, &mut s.scratch) {
                        1 => s.rung += 1,
                        E_AGAIN => {}
                        _ => s.subscribed = 3, // rang, but the read missed the write
                    }
                }
                // Give the ring a bounded number of steps before judging it.
                if s.rung > 0 || s.subscribed == 3 || s.step > 2000 {
                    s.state = 5;
                }
            }
            5 if s.done == 0 => {
                // 5. DELETE one, LIST again. A LIST the store defers is asked
                // again without deleting again.
                if s.del == 0 {
                    match delete(sys, KEY_B) {
                        WriteAnswer::Pending => return StepReturn::Continue,
                        WriteAnswer::Decided(0) => {}
                        WriteAnswer::Decided(_) => {
                            s.err = -9;
                            s.state = 99;
                            emit(s);
                            return StepReturn::Continue;
                        }
                    }
                    s.del = 1;
                }
                let n = list_count(sys, PREFIX, &mut s.scratch);
                if n == E_AGAIN {
                    return StepReturn::Continue;
                }
                if n != 2 {
                    // a and c remain
                    s.err = -10;
                    s.state = 99;
                    emit(s);
                    return StepReturn::Continue;
                }
                s.listed = n as u32;
                witness_counts(sys, s);
                s.pass = u32::from(s.rung > 0 || s.want_ring == 0);
                s.state = 5;
                emit(s);
                s.done = 1;
            }
            _ if s.done == 1 || s.state == 99 => {
                // Re-emit sparsely so a late UDP listener still catches the
                // verdict — log_net needs time to warm up. Re-COUNT each time:
                // the interesting number is produced by another chain, later.
                if s.step.is_multiple_of(1000) {
                    witness_counts(sys, s);
                    emit(s);
                }
            }
            _ => {}
        }
        StepReturn::Continue
    }
}
