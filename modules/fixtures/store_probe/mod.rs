//! Store contract probe — proves `storage.object` + `storage.namespace` work
//! ON THE BOARD.
//!
//! A provider that compiles is not a provider that works, and a store-backed
//! graph reports neither: a source whose SUBSCRIBE fails looks exactly like a
//! source with nothing to report. This fixture is the evidence the graph
//! itself cannot give.
//!
//! It walks the whole contract surface a store consumer uses, in order, and
//! stops at the first failure so the heartbeat names the step that broke. Keys
//! under `/probe/` are its own — it proves the contracts against state it
//! created, so it depends on nothing else in the graph:
//!
//!   1 PUT      two objects under one prefix
//!   2 GET      read one back and byte-compare it
//!   3 LIST     enumerate the prefix, expect both
//!   4 SUBSCRIBE + PUT, then drain the sink — the PUSH a source depends on
//!   5 DELETE   remove one, LIST again, expect one
//!
//! **Acceptance:** `[stp] state=5 pass=1 put=2 got=1 listed=2 pushed=N del=1
//! err=0`. Any `pass=0` names the state it stopped in. `pushed` is the count of
//! namespace.change events that ARRIVED. It is reported separately rather than
//! folded into the PUT's pass/fail: a PUT that lands and a watcher that is
//! never told are different failures, and only the second is silent.
//!
//! WITNESS PREFIXES. `witness_a` / `witness_b` are optional graph params: each
//! is a prefix this probe LISTs on every heartbeat and reports the count of.
//! They exist because a store lives in RAM with nothing to inspect after a run,
//! so a graph whose own chain is asynchronous has no way to say what it
//! produced. The probe supplies the counting; the graph supplies the prefixes,
//! and what they mean is the graph's business, not this fixture's. Unset
//! prefixes are not listed and report 0.

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

// storage.object (0x14) and storage.namespace (0x13).
// Opcodes come from the contracts this fixture drives, not from literals:
// a probe that restates the wire can pass against its own copy of it.
const OBJ_PUT: u32 = abi::contracts::storage::object::PUT;
const OBJ_GET: u32 = abi::contracts::storage::object::GET;
const OBJ_RANGE_GET: u32 = abi::contracts::storage::object::RANGE_GET;
const OBJ_DELETE: u32 = abi::contracts::storage::object::DELETE;
const OBJ_CLOSE: u32 = abi::contracts::storage::object::CLOSE;
const NS_LIST: u32 = abi::contracts::storage::namespace::LIST;
const NS_SUBSCRIBE: u32 = abi::contracts::storage::namespace::SUBSCRIBE;

const PREFIX: &[u8] = b"/probe/";
const KEY_A: &[u8] = b"/probe/a";
const KEY_B: &[u8] = b"/probe/b";
const KEY_C: &[u8] = b"/probe/c";
const VAL_A: &[u8] = b"{\"kind\":\"Probe\",\"n\":1}";
const VAL_C: &[u8] = b"{\"kind\":\"Probe\",\"n\":3}";

const EVENT_HEADER_SIZE: usize = 32;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    sink: i32,
    out_chan: i32,
    step: u32,
    state: u32,
    pass: u32,
    put: u32,
    got: u32,
    listed: u32,
    pushed: u32,
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
    scratch: [u8; 1024],
}

/// Longest witness prefix. A prefix is a path fragment, not a key.
const MAX_WITNESS: usize = 96;

mod params_def {
    use super::ptr_copy;
    use super::State;
    use super::MAX_WITNESS;
    use super::SCHEMA_MAX;

    define_params! {
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
    }
}

#[inline(always)]
unsafe fn ptr_copy(dst: *mut u8, src: *const u8, n: usize) {
    core::ptr::copy_nonoverlapping(src, dst, n);
}

/// LIST both witness prefixes and return their counts. An unset prefix is not
/// listed and counts 0 — the graph that named none is simply not witnessed.
unsafe fn witness_counts(sys: &SyscallTable, s: &mut State) -> (u32, u32) {
    let mut scratch = [0u8; 1024];
    let mut one = |pfx: &[u8]| -> u32 {
        if pfx.is_empty() {
            return 0;
        }
        let n = list_count(sys, pfx, &mut scratch);
        if n > 0 {
            n as u32
        } else {
            0
        }
    };
    let a = one(&s.wit_a_pfx[..s.wit_a_len as usize]);
    let b = one(&s.wit_b_pfx[..s.wit_b_len as usize]);
    (a, b)
}

unsafe fn put(sys: &SyscallTable, key: &[u8], val: &[u8]) -> i32 {
    // [key_len:u16][key][ct_len:u8][body_ptr:u64][body_len:u64]
    // [precondition:u8][etag_len:u8][fence_ptr:u64][fence_cap:u16]
    let mut arg = [0u8; 320];
    let mut p = 0usize;
    arg[0..2].copy_from_slice(&(key.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + key.len()].copy_from_slice(key);
    p += key.len();
    arg[p] = 0; // content_type_len
    p += 1;
    arg[p..p + 8].copy_from_slice(&(val.as_ptr() as u64).to_le_bytes());
    p += 8;
    arg[p..p + 8].copy_from_slice(&(val.len() as u64).to_le_bytes());
    p += 8;
    arg[p] = 0; // precondition ANY
    arg[p + 1] = 0; // etag_len
    p += 2;
    arg[p..p + 8].copy_from_slice(&0u64.to_le_bytes()); // fence_out_ptr
    p += 8;
    arg[p..p + 2].copy_from_slice(&0u16.to_le_bytes()); // fence_out_cap
    p += 2;
    (sys.provider_call)(-1, OBJ_PUT, arg.as_mut_ptr(), p)
}

unsafe fn get(sys: &SyscallTable, key: &[u8], dst: &mut [u8]) -> i32 {
    let mut karg = [0u8; 192];
    karg[..key.len()].copy_from_slice(key);
    let h = (sys.provider_call)(-1, OBJ_GET, karg.as_mut_ptr(), key.len());
    if h < 0 {
        return h;
    }
    let mut rarg = [0u8; 20];
    rarg[8..12].copy_from_slice(&(dst.len() as u32).to_le_bytes());
    rarg[12..20].copy_from_slice(&(dst.as_mut_ptr() as u64).to_le_bytes());
    let n = (sys.provider_call)(h, OBJ_RANGE_GET, rarg.as_mut_ptr(), 20);
    let mut carg = [0u8; 4];
    (sys.provider_call)(h, OBJ_CLOSE, carg.as_mut_ptr(), 0);
    n
}

unsafe fn delete(sys: &SyscallTable, key: &[u8]) -> i32 {
    let mut arg = [0u8; 224];
    let mut p = 0usize;
    arg[0..2].copy_from_slice(&(key.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + key.len()].copy_from_slice(key);
    p += key.len();
    arg[p] = 0; // precondition ANY
    arg[p + 1] = 0; // etag_len
    p += 2;
    arg[p..p + 8].copy_from_slice(&0u64.to_le_bytes());
    p += 8;
    arg[p..p + 2].copy_from_slice(&0u16.to_le_bytes());
    p += 2;
    (sys.provider_call)(-1, OBJ_DELETE, arg.as_mut_ptr(), p)
}

/// LIST one page of `prefix`; returns the number of entries counted, or a
/// negative errno.
unsafe fn list_count(sys: &SyscallTable, prefix: &[u8], page: &mut [u8]) -> i32 {
    // [prefix_len:u16][prefix][cursor_len:u16][out_buf:u64][out_cap:u32]
    // [fence_ptr:u64][fence_cap:u16]
    let mut arg = [0u8; 256];
    let mut p = 0usize;
    arg[0..2].copy_from_slice(&(prefix.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + prefix.len()].copy_from_slice(prefix);
    p += prefix.len();
    arg[p..p + 2].copy_from_slice(&0u16.to_le_bytes()); // cursor_len 0
    p += 2;
    arg[p..p + 8].copy_from_slice(&(page.as_mut_ptr() as u64).to_le_bytes());
    p += 8;
    arg[p..p + 4].copy_from_slice(&(page.len() as u32).to_le_bytes());
    p += 4;
    arg[p..p + 8].copy_from_slice(&0u64.to_le_bytes());
    p += 8;
    arg[p..p + 2].copy_from_slice(&0u16.to_le_bytes());
    p += 2;
    let n = (sys.provider_call)(-1, NS_LIST, arg.as_mut_ptr(), p);
    if n < 0 {
        return n;
    }
    // entries: [name_len:u8][kind:u8][name]… then the trailing record
    // [0xFF][0xFF][cursor_len:u8][cursor]. Both marker bytes are
    // checked: a 255-byte name puts 0xFF in `name_len`, so a one-byte
    // test ends the page early and undercounts.
    let mut count = 0i32;
    let mut o = 0usize;
    let n = n as usize;
    while o + 1 < n {
        if page[o] == 0xFF && page[o + 1] == 0xFF {
            break;
        }
        let l = page[o] as usize;
        o += 2 + l;
        count += 1;
    }
    count
}

unsafe fn subscribe(sys: &SyscallTable, prefix: &[u8], sink: i32) -> i32 {
    // [prefix_len:u16][prefix][sink_chan:u32][flags:u8]
    let mut arg = [0u8; 224];
    let mut p = 0usize;
    arg[0..2].copy_from_slice(&(prefix.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + prefix.len()].copy_from_slice(prefix);
    p += prefix.len();
    arg[p..p + 4].copy_from_slice(&(sink as u32).to_le_bytes());
    p += 4;
    arg[p] = 0; // no initial listing — we want the LIVE push, not a replay
    p += 1;
    (sys.provider_call)(-1, NS_SUBSCRIBE, arg.as_mut_ptr(), p)
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
    lit!(b" pushed=");
    write_dec(p, &mut pos, s.pushed);
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

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point.
#[no_mangle]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
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
        s.sink = in_chan;
        s.out_chan = out_chan;
        s.step = 0;
        s.state = 0;
        s.pass = 0;
        s.put = 0;
        s.got = 0;
        s.listed = 0;
        s.pushed = 0;
        s.del = 0;
        s.err = 0;
        s.wit_a = 0;
        s.wit_b = 0;
        s.done = 0;
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return 0;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return 0;
        }
        let sys = &*s.syscalls;
        s.step = s.step.wrapping_add(1);

        match s.state {
            0 => {
                // 1. PUT two objects.
                if put(sys, KEY_A, VAL_A) != 0 {
                    s.err = -1;
                    s.state = 99;
                    emit(s);
                    return 0;
                }
                s.put += 1;
                if put(sys, KEY_B, VAL_A) != 0 {
                    s.err = -2;
                    s.state = 99;
                    emit(s);
                    return 0;
                }
                s.put += 1;
                s.state = 1;
            }
            1 => {
                // 2. GET one back and BYTE-COMPARE. A provider that answers a
                // length without the bytes passes a shallower check than this.
                let mut buf = [0u8; 256];
                let n = get(sys, KEY_A, &mut buf);
                if n as usize != VAL_A.len() || &buf[..VAL_A.len()] != VAL_A {
                    s.err = -3;
                    s.state = 99;
                    emit(s);
                    return 0;
                }
                s.got = 1;
                s.state = 2;
            }
            2 => {
                // 3. LIST the prefix.
                let n = list_count(sys, PREFIX, &mut s.scratch);
                if n < 0 {
                    s.err = -4;
                    s.state = 99;
                    emit(s);
                    return 0;
                }
                s.listed = n as u32;
                if s.listed != 2 {
                    s.err = -5;
                    s.state = 99;
                    emit(s);
                    return 0;
                }
                s.state = 3;
            }
            3 => {
                // 4. SUBSCRIBE, then write — the PUSH every source depends on.
                if s.sink < 0 {
                    s.err = -6;
                    s.state = 99;
                    emit(s);
                    return 0;
                }
                if subscribe(sys, PREFIX, s.sink) < 0 {
                    s.err = -7;
                    s.state = 99;
                    emit(s);
                    return 0;
                }
                if put(sys, KEY_C, VAL_C) != 0 {
                    s.err = -8;
                    s.state = 99;
                    emit(s);
                    return 0;
                }
                s.put += 1;
                s.state = 4;
            }
            4 => {
                // Drain the sink. The event must ARRIVE, not merely have been
                // accepted: SUBSCRIBE returning a handle proves nothing about
                // whether a change ever reaches the channel.
                let poll = (sys.channel_poll)(s.sink, POLL_IN);
                if poll > 0 && ((poll as u32) & POLL_IN) != 0 {
                    let n = (sys.channel_read)(s.sink, s.scratch.as_mut_ptr(), s.scratch.len());
                    if n as usize >= EVENT_HEADER_SIZE {
                        s.pushed += 1;
                    }
                }
                // Give the push a bounded number of steps before judging it.
                if s.pushed > 0 || s.step > 2000 {
                    s.state = 5;
                }
            }
            5 if s.done == 0 => {
                // 5. DELETE one, LIST again.
                if delete(sys, KEY_B) != 0 {
                    s.err = -9;
                    s.state = 99;
                    emit(s);
                    return 0;
                }
                s.del = 1;
                let n = list_count(sys, PREFIX, &mut s.scratch);
                if n != 2 {
                    // a and c remain
                    s.err = -10;
                    s.state = 99;
                    emit(s);
                    return 0;
                }
                s.listed = n as u32;
                let (a, b) = witness_counts(sys, s);
                s.wit_a = a;
                s.wit_b = b;
                s.pass = u32::from(s.pushed > 0);
                s.state = 5;
                emit(s);
                s.done = 1;
            }
            _ if s.done == 1 || s.state == 99 => {
                // Re-emit sparsely so a late UDP listener still catches the
                // verdict — log_net needs time to warm up. Re-COUNT each time:
                // the interesting number is produced by another chain, later.
                if s.step % 1000 == 0 {
                    let (a, b) = witness_counts(sys, s);
                    s.wit_a = a;
                    s.wit_b = b;
                    emit(s);
                }
            }
            _ => {}
        }
        0
    }
}
