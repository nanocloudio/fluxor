//! `storage.namespace` over `fs`: directory enumeration from the file system
//! beneath.
//!
//! Where `fs` opens bytes by path, this answers the questions a scanner asks
//! of a directory tree: "what lives under this prefix?" (`LIST`) and "what is
//! this entry?" (`STAT`, on a handle `LOOKUP` bound). It reads the `fs`
//! provider below with `OPENDIR`/`READDIR`/`OPEN`/`STAT`, so it works over
//! `fat32` on a board and the host file system on Linux alike.
//!
//! ## One key space with `fs`
//!
//! An entry's key is its `fs` path beneath the `root` param: with `root`
//! unset, the very path `fs` opens, so a consumer LISTs here and opens each
//! hit through `fs` by the same key. An empty prefix names `root` (`/` when
//! it is unset). A component that climbs (`..`) is refused.
//!
//! ## Paging
//!
//! A page is name-sorted; the cursor is the last name a page returned and the
//! next page resumes strictly after it, so an entry made or removed between
//! pages never shifts the entries behind the cursor. A page takes as many
//! passes over the directory as it needs, each keeping the [`PICK`] smallest
//! names past the last one listed. A name that is not UTF-8 is not
//! expressible in the contract and is not listed.
//! The file system may answer `EAGAIN` (a cold `fat32` cluster): the call
//! answers it too and is asked again with the same bytes.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    clippy::manual_contains,
    reason = "`<[u8]>::contains` lowers to core's memchr, which a PIC module cannot link"
)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

use abi::contracts::storage::fs as fsop;
use abi::contracts::storage::namespace as ns;
use abi::fence;
use abi::kernel_abi::errno;

/// Names one pass keeps; a page takes as many passes as it needs.
const PICK: usize = 8;
/// Longest name an entry has.
const NAME_MAX: usize = abi::contracts::storage::handle::STORAGE_KEY_MAX;
/// Longest path handed down: `root`, a separator and a key.
const PMAX: usize = ROOT_MAX + 1 + NAME_MAX;
/// Longest `root` param.
const ROOT_MAX: usize = 96;
/// `root_len` of a `root` param longer than [`ROOT_MAX`].
const ROOT_TOO_LONG: u8 = ROOT_MAX as u8 + 1;
/// Handles bound at once.
const MAX_OPEN: usize = 8;
/// A `READDIR` batch.
const BATCH: usize = 512;
const ENOTDIR: i32 = -20;

#[derive(Clone, Copy)]
struct Path {
    b: [u8; PMAX],
    n: usize,
}

impl Path {
    const EMPTY: Self = Self { b: [0; PMAX], n: 0 };

    fn bytes(&self) -> &[u8] {
        &self.b[..self.n]
    }
    fn push(&mut self, s: &[u8]) -> bool {
        let end = self.n + s.len();
        if end > PMAX {
            return false;
        }
        self.b[self.n..end].copy_from_slice(s);
        self.n = end;
        true
    }
}

#[derive(Clone, Copy)]
struct Bound {
    in_use: bool,
    /// The opener, as the kernel names it (`CALLER_OWNER`).
    owner: [u8; 8],
    path: Path,
}

const BOUND_EMPTY: Bound = Bound {
    in_use: false,
    owner: [0; 8],
    path: Path::EMPTY,
};

#[derive(Clone, Copy)]
struct Pick {
    name: [u8; NAME_MAX],
    n: u16,
    dir: bool,
}

const PICK_EMPTY: Pick = Pick {
    name: [0; NAME_MAX],
    n: 0,
    dir: false,
};

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    root: [u8; ROOT_MAX],
    root_len: u8,
    bound: [Bound; MAX_OPEN],
    picks: [Pick; PICK],
}

impl State {
    fn sys(&self) -> &SyscallTable {
        // SAFETY: set in `module_new` from the kernel's table.
        unsafe { &*self.syscalls }
    }
}

fn fs_call(s: &State, handle: i32, op: u32, arg: &mut [u8], data: &mut [u8]) -> i32 {
    let (ap, al) = if arg.is_empty() {
        (core::ptr::null_mut(), 0)
    } else {
        (arg.as_mut_ptr(), arg.len())
    };
    let (dp, dl) = if data.is_empty() {
        (core::ptr::null_mut(), 0)
    } else {
        (data.as_mut_ptr(), data.len())
    };
    // SAFETY: both spans are this frame's, disjoint, live for the call.
    unsafe { (s.sys().provider_call)(handle, op, ap, al, dp, dl) }
}

fn fs_close(s: &State, handle: i32) {
    if handle >= 0 {
        // SAFETY: a handle this module holds.
        unsafe { (s.sys().provider_close)(handle) };
    }
}

fn caller(s: &State) -> [u8; 8] {
    let mut r = [0u8; 8];
    // SAFETY: `r` is this frame's own.
    let rc = unsafe {
        (s.sys().provider_query)(
            -1,
            abi::kernel_abi::query_key::CALLER_OWNER,
            r.as_mut_ptr(),
            r.len(),
        )
    };
    if rc == 8 {
        r
    } else {
        [0xFF; 8]
    }
}

/// `key` beneath `root`: an empty key names `root` (`/` when unset), a
/// component that climbs is refused.
fn resolve(s: &State, key: &[u8]) -> Result<Path, i32> {
    if key.len() > NAME_MAX {
        return Err(errno::EINVAL);
    }
    if key
        .split(|&b| b == b'/')
        .any(|c| !c.is_empty() && c.iter().all(|&b| b == b'.') && c.len() > 1)
        || key.iter().any(|&b| b == 0)
    {
        return Err(errno::EACCES);
    }
    let mut p = Path::EMPTY;
    let root = &s.root[..usize::from(s.root_len)];
    p.push(root);
    if !key.is_empty() {
        if !root.is_empty() && !key.starts_with(b"/") && !p.push(b"/") {
            return Err(errno::E2BIG);
        }
        if !p.push(key) {
            return Err(errno::E2BIG);
        }
    }
    if p.n == 0 {
        p.push(b"/");
    }
    Ok(p)
}

/// Keep `name` if it is among the [`PICK`] smallest past `after`; whether a
/// name past `after` was left out.
fn consider(picks: &mut [Pick; PICK], n_picked: &mut usize, name: &[u8], dir: bool) -> bool {
    let pos = picks[..*n_picked]
        .iter()
        .position(|p| name < &p.name[..usize::from(p.n)])
        .unwrap_or(*n_picked);
    if pos == PICK {
        return true;
    }
    let dropped = *n_picked == PICK;
    let end = (*n_picked).min(PICK - 1);
    let mut i = end;
    while i > pos {
        picks[i] = picks[i - 1];
        i -= 1;
    }
    let mut p = PICK_EMPTY;
    p.name[..name.len()].copy_from_slice(name);
    p.n = name.len() as u16;
    p.dir = dir;
    picks[pos] = p;
    *n_picked = (*n_picked + 1).min(PICK);
    dropped
}

/// One pass over directory `dir`: keep the [`PICK`] smallest names past
/// `after` in `s.picks`. The count kept and whether a name past `after` was
/// left out, or the error that stopped the pass.
fn pick_pass(s: &mut State, dir: &Path, after: &[u8]) -> Result<(usize, bool), i32> {
    let mut path = *dir;
    let d = fs_call(s, -1, fsop::OPENDIR, &mut path.b[..path.n], &mut []);
    if d == errno::ENOENT || d == ENOTDIR || d == errno::ENODEV {
        return Ok((0, false));
    }
    if d < 0 {
        return Err(d);
    }
    let mut picked = 0usize;
    let mut left_out = false;
    loop {
        let mut batch = [0u8; BATCH];
        let rc = fs_call(s, d, fsop::READDIR, &mut [], &mut batch);
        if rc < 0 {
            fs_close(s, d);
            return Err(rc);
        }
        if rc == 0 {
            break;
        }
        let n = (rc as usize).min(BATCH);
        let mut left = u16::from_le_bytes([batch[0], batch[1]]);
        let mut pos = 2usize;
        while left > 0 && pos + 2 <= n {
            left -= 1;
            let nl = usize::from(batch[pos]);
            let kind = batch[pos + 1];
            let Some(name) = batch.get(pos + 2..pos + 2 + nl) else {
                break;
            };
            pos += 2 + nl;
            // A name that is not UTF-8 is not expressible in the contract.
            if name.is_empty() || !utf8(name) || (!after.is_empty() && name <= after) {
                continue;
            }
            if name.len() > NAME_MAX {
                fs_close(s, d);
                return Err(errno::EOVERFLOW);
            }
            if consider(&mut s.picks, &mut picked, name, kind == 1) {
                left_out = true;
            }
        }
    }
    fs_close(s, d);
    Ok((picked, left_out))
}

/// `LIST`: one page of the prefix's immediate children, name-sorted, as
/// many as the page holds.
fn list(s: &mut State, arg: &mut [u8], out: &mut [u8]) -> i32 {
    let Some(req) = ns::list::parse_request(arg) else {
        return errno::EINVAL;
    };
    // Directory-shaped: the cursor is a child name, so one that is not UTF-8
    // or that holds a `/` was not issued here.
    if req.cursor.iter().any(|&b| b == b'/') || !utf8(req.cursor) {
        return errno::EINVAL;
    }
    let dir = match resolve(s, req.prefix) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut after = [0u8; NAME_MAX];
    let mut al = req.cursor.len().min(NAME_MAX);
    after[..al].copy_from_slice(&req.cursor[..al]);

    let mut page = ns::list::PageWriter::new(out);
    let mut listed = false;
    let mut more = false;
    'pages: loop {
        let (picked, left_out) = match pick_pass(s, &dir, &after[..al]) {
            Ok(v) => v,
            Err(e) => return e,
        };
        for i in 0..picked {
            let p = s.picks[i];
            let kind = if p.dir {
                ns::KIND_NAMESPACE
            } else {
                ns::KIND_OBJECT
            };
            let name = &p.name[..usize::from(p.n)];
            if !page.push(name, kind) {
                more = true;
                break 'pages;
            }
            listed = true;
            al = name.len();
            after[..al].copy_from_slice(name);
        }
        if !left_out {
            break;
        }
    }
    let cursor: &[u8] = if more {
        // A page that cannot hold the next entry made no progress.
        if !listed {
            return errno::ENOMEM;
        }
        &after[..al]
    } else {
        &[]
    };
    let Some(n) = page.finish(cursor) else {
        return errno::ENOMEM;
    };
    fence::trailer::put(arg, &fence::Fence::Volatile);
    n as i32
}

/// Whether `b` is well-formed UTF-8 (the contract's names are).
fn utf8(b: &[u8]) -> bool {
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        let (n, min) = match c {
            0x00..=0x7F => (0, 0),
            0xC2..=0xDF => (1, 0x80),
            0xE0..=0xEF => (2, 0x800),
            0xF0..=0xF4 => (3, 0x1_0000),
            _ => return false,
        };
        let mut v = u32::from(c) & (0x7F >> n);
        let mut k = 1usize;
        while k <= n {
            let Some(&t) = b.get(i + k) else {
                return false;
            };
            if t & 0xC0 != 0x80 {
                return false;
            }
            v = (v << 6) | u32::from(t & 0x3F);
            k += 1;
        }
        if v < min || v > 0x10_FFFF || (0xD800..=0xDFFF).contains(&v) {
            return false;
        }
        i += 1 + n;
    }
    true
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// `STAT`: `[size][mtime][kind][etag]` of the bound path.
fn stat(s: &State, idx: usize, out: &mut [u8]) -> i32 {
    if out.len() < ns::stat::FIXED_LEN {
        return errno::EINVAL;
    }
    let mut path = s.bound[idx].path;
    let n = path.n;
    let (size, mtime, kind) = {
        let h = fs_call(s, -1, fsop::OPEN, &mut path.b[..n], &mut []);
        if h >= 0 {
            let mut st = [0u8; fsop::stat::LEN];
            let rc = fs_call(s, h, fsop::STAT, &mut st, &mut []);
            fs_close(s, h);
            if rc < 0 {
                return rc;
            }
            let Some(st) = fsop::Stat::decode(&st) else {
                return errno::EINVAL;
            };
            (st.size, st.mtime, ns::KIND_OBJECT)
        } else if h == errno::EAGAIN {
            return h;
        } else {
            let mut path = s.bound[idx].path;
            let d = fs_call(s, -1, fsop::OPENDIR, &mut path.b[..n], &mut []);
            if d < 0 {
                return if d == errno::EAGAIN { d } else { errno::ENODEV };
            }
            fs_close(s, d);
            (0, 0, ns::KIND_NAMESPACE)
        }
    };
    let etag = fnv1a64(s.bound[idx].path.bytes()) ^ size ^ mtime.rotate_left(17);
    match ns::stat::encode(out, size, mtime, kind, &etag.to_le_bytes()) {
        Some(n) => n as i32,
        None => errno::EINVAL,
    }
}

/// The bound handle `handle`, when it is the caller's.
fn owned(s: &State, handle: i32) -> Option<usize> {
    let i = usize::try_from(handle).ok()?;
    let me = caller(s);
    (i < MAX_OPEN && s.bound[i].in_use && s.bound[i].owner == me).then_some(i)
}

fn dispatch(s: &mut State, handle: i32, op: u32, arg: &mut [u8], data: &mut [u8]) -> i32 {
    if op == fence::QUERY_OP {
        if arg.len() < fence::WIRE_MAX_LEN || owned(s, handle).is_none() {
            return errno::ENOSYS;
        }
        return match fence::Fence::Volatile.encode(arg) {
            Some(n) => n as i32,
            None => errno::EINVAL,
        };
    }
    match op {
        ns::LOOKUP => {
            let p = match resolve(s, arg) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let Some(i) = s.bound.iter().position(|b| !b.in_use) else {
                return errno::ENOMEM;
            };
            s.bound[i] = Bound {
                in_use: true,
                owner: caller(s),
                path: p,
            };
            i as i32
        }
        ns::STAT => match owned(s, handle) {
            Some(i) => stat(s, i, arg),
            None => errno::EINVAL,
        },
        ns::LIST => list(s, arg, data),
        ns::CLOSE => match owned(s, handle) {
            Some(i) => {
                s.bound[i] = BOUND_EMPTY;
                0
            }
            None => errno::EINVAL,
        },
        // Read-only and directory-shaped.
        ns::CAPS => abi::kernel_abi::caps_word::answer(arg, ns::caps::CHILD_NAMES),
        _ => errno::ENOSYS,
    }
}

/// `OWNER_RELEASED`: what the owner bound goes with it.
fn owner_released(s: &mut State, rec: &[u8]) {
    let Some(head) = rec.get(..8) else { return };
    for b in s.bound.iter_mut() {
        if b.in_use && b.owner[..] == *head {
            *b = BOUND_EMPTY;
        }
    }
}

mod params_def {
    use super::State;

    fluxor_rt::define_params! {
        State;

        1, root, str, 0, max super::ROOT_MAX
            => |s, d, len| { super::set_root(s, d, len); };
    }
}

/// `root`, its trailing separators dropped. A value longer than [`ROOT_MAX`]
/// is marked, not cut or ignored: either would list a directory other than
/// the one named, and `module_new` refuses it.
fn set_root(s: &mut State, d: *const u8, len: usize) {
    if len > ROOT_MAX {
        s.root_len = ROOT_TOO_LONG;
        return;
    }
    if d.is_null() || len == 0 {
        return;
    }
    // SAFETY: `d` names `len` bytes of the params blob.
    let v = unsafe { core::slice::from_raw_parts(d, len) };
    let mut end = v.len();
    while end > 1 && v[end - 1] == b'/' {
        end -= 1;
    }
    s.root[..end].copy_from_slice(&v[..end]);
    s.root_len = end as u8;
}

// ── Exported PIC module interface ───────────────────────────────────────────

fluxor_rt::module_facts! { state: State }

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() {
        return -2;
    }
    if state.is_null() || state_size < core::mem::size_of::<State>() {
        return -3;
    }
    // SAFETY: the loader's block, sized for `State`, zeroed before use.
    let s = unsafe {
        core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
        &mut *state.cast::<State>()
    };
    s.syscalls = syscalls.cast::<SyscallTable>();
    // SAFETY: the params blob the loader hands, `params_len` bytes.
    unsafe {
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
    }
    if s.root_len == ROOT_TOO_LONG {
        let why = b"[fs_namespace] refusing to construct: `root` is longer than 96 bytes";
        // SAFETY: `why` is live for the call.
        unsafe { dev_log(s.sys(), 1, why.as_ptr(), why.len()) };
        return -1;
    }
    0
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub extern "C" fn module_step(_state: *mut u8) -> StepReturn {
    StepReturn::Continue
}

/// # Safety
/// Kernel provider-dispatch entry point: `state` is the instance block this
/// module's `module_new` initialised, `arg` points to `arg_len` bytes and
/// `data` to `data_len` bytes (either may be null when its length is 0),
/// valid for the call and disjoint.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(
    not(feature = "host-test"),
    link_section = ".text.module_provider_dispatch"
)]
pub unsafe extern "C" fn module_provider_dispatch(
    state: *mut u8,
    handle: i32,
    op: u32,
    arg: *mut u8,
    arg_len: usize,
    data: *mut u8,
    data_len: usize,
) -> i32 {
    if state.is_null() {
        return errno::EINVAL;
    }
    // SAFETY: this module's own state, and the caller's spans, valid and
    // disjoint for the call.
    let (s, a, d) = unsafe {
        let s = &mut *state.cast::<State>();
        let a: &mut [u8] = if arg.is_null() || arg_len == 0 {
            &mut []
        } else {
            core::slice::from_raw_parts_mut(arg, arg_len)
        };
        let d: &mut [u8] = if data.is_null() || data_len == 0 {
            &mut []
        } else {
            core::slice::from_raw_parts_mut(data, data_len)
        };
        (s, a, d)
    };
    if s.syscalls.is_null() {
        return errno::EINVAL;
    }
    if op == abi::internal::reconfigure::OWNER_RELEASED {
        owner_released(s, a);
        return 0;
    }
    dispatch(s, handle, op, a, d)
}

#[cfg(all(target_arch = "wasm32", not(feature = "host-test")))]
fluxor_rt::wasm_entry!();
