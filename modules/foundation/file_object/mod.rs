//! `storage.object` over `fs`, read only: the files beneath a directory,
//! served as objects.
//!
//! An object is a file under the `root` param and its key is the file's
//! path relative to `root` -- the key `fs_namespace` gives the same file, so
//! a graph composes the two side by side (each provides one surface) and a
//! consumer LISTs through `fs_namespace` and opens through this module by
//! the same key. It reads the `fs` provider below with `OPEN`, `STAT`,
//! `SEEK` and `READ`, so it serves `fat32` on a board and the host file
//! system on Linux alike.
//!
//! ## Keys
//!
//! A key is joined beneath `root` exactly as `fs_namespace` joins a prefix:
//! with `root` unset it is the very path `fs` opens, and with `root` set a
//! leading `/` does not leave it (`/a` and `a` name the same file). A key
//! holding a component that climbs (`..`) or a NUL byte is refused
//! `EACCES`; the empty key is `EINVAL`. The confinement is lexical, as the
//! `fs` beneath is: a link planted inside `root` is followed.
//!
//! A directory is not an object: `GET` answers `ENOENT` for one and `HEAD`
//! `ENXIO`, as for a key that names nothing.
//!
//! ## Reads
//!
//! `GET` opens the file and holds it as the handle ([`READS`] at once, each
//! the opener's alone); `RANGE_GET` seeks and reads into `data`, a short
//! count near the end and 0 past it; `CLOSE` lets it go. `HEAD` answers the
//! file's size and modification time, no content type, and an 8-byte etag
//! of the path, size and mtime -- the etag `fs_namespace`'s `STAT` gives the
//! same file. Every read is `Volatile`. The file system's `EAGAIN` (a cold
//! `fat32` cluster) is answered as it is, to be asked again.
//!
//! ## What it does not do
//!
//! No writes: `PUT`, `DELETE`, `RETAIN` and the streamed puts are refused
//! `EROFS`, and `CAPS` sets neither `WRITE` nor `LIST`. No listing (`LIST`
//! is `ENOSYS`: the directory is `fs_namespace`'s to enumerate) and no
//! grants (`PRESENT` is `ENOSYS`).

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
use abi::contracts::storage::object as obj;
use abi::fence;
use abi::kernel_abi::errno;

/// Longest key.
const KEY_MAX: usize = abi::contracts::storage::handle::STORAGE_KEY_MAX;
/// Longest path handed down: `root`, a separator and a key.
const PMAX: usize = ROOT_MAX + 1 + KEY_MAX;
/// Longest `root` param.
const ROOT_MAX: usize = 96;
/// `root_len` of a `root` param longer than [`ROOT_MAX`].
const ROOT_TOO_LONG: u8 = ROOT_MAX as u8 + 1;
/// `GET` handles open at once.
const READS: usize = 8;
const ENOTDIR: i32 = -20;
const EISDIR: i32 = -21;

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
struct Read {
    in_use: bool,
    /// The opener, as the kernel names it (`CALLER_OWNER`).
    owner: [u8; 8],
    /// The open file beneath.
    fd: i32,
    size: u64,
}

const READ_EMPTY: Read = Read {
    in_use: false,
    owner: [0; 8],
    fd: -1,
    size: 0,
};

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    root: [u8; ROOT_MAX],
    root_len: u8,
    reads: [Read; READS],
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

/// `key` beneath `root`, as `fs_namespace` joins a prefix: the empty key is
/// no object, and a component that climbs or a NUL byte is refused.
fn resolve(s: &State, key: &[u8]) -> Result<Path, i32> {
    if key.is_empty() || key.len() > KEY_MAX {
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
    if !root.is_empty() && !key.starts_with(b"/") && !p.push(b"/") {
        return Err(errno::E2BIG);
    }
    if !p.push(key) {
        return Err(errno::E2BIG);
    }
    Ok(p)
}

/// The file `key` names, open, with its size and mtime: `ENOENT` when it
/// names nothing or a directory.
fn open_file(s: &State, key: &[u8]) -> Result<(i32, u64, u64, Path), i32> {
    let path = resolve(s, key)?;
    let mut p = path;
    let fd = fs_call(s, -1, fsop::OPEN, &mut p.b[..p.n], &mut []);
    if fd < 0 {
        return Err(if fd == ENOTDIR || fd == EISDIR {
            errno::ENOENT
        } else {
            fd
        });
    }
    // A directory opens on some file systems; it is not an object.
    let mut p = path;
    let d = fs_call(s, -1, fsop::OPENDIR, &mut p.b[..p.n], &mut []);
    if d >= 0 {
        fs_close(s, d);
        fs_close(s, fd);
        return Err(errno::ENOENT);
    }
    if d == errno::EAGAIN {
        fs_close(s, fd);
        return Err(d);
    }
    let mut st = [0u8; fsop::stat::LEN];
    let rc = fs_call(s, fd, fsop::STAT, &mut st, &mut []);
    if rc < 0 {
        fs_close(s, fd);
        return Err(rc);
    }
    let Some(st) = fsop::Stat::decode(&st) else {
        fs_close(s, fd);
        return Err(errno::EINVAL);
    };
    Ok((fd, st.size, st.mtime, path))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// `GET`: the file open as a read handle.
fn op_get(s: &mut State, arg: &[u8]) -> i32 {
    let Some(key) = obj::key::parse(arg) else {
        return errno::EINVAL;
    };
    let Some(slot) = s.reads.iter().position(|r| !r.in_use) else {
        return errno::EBUSY;
    };
    let (fd, size, _, _) = match open_file(s, key) {
        Ok(v) => v,
        Err(e) => return e,
    };
    s.reads[slot] = Read {
        in_use: true,
        owner: caller(s),
        fd,
        size,
    };
    slot as i32
}

/// The read handle `handle`, when it is the caller's.
fn owned(s: &State, handle: i32) -> Option<usize> {
    let i = usize::try_from(handle).ok()?;
    let me = caller(s);
    (i < READS && s.reads[i].in_use && s.reads[i].owner == me).then_some(i)
}

/// `RANGE_GET`: `[offset u64]`, the bytes from there into `out`.
fn op_range(s: &State, handle: i32, arg: &[u8], out: &mut [u8]) -> i32 {
    let Some(i) = owned(s, handle) else {
        return errno::EBADF;
    };
    let Some(offset) = obj::range_get::parse(arg) else {
        return errno::EINVAL;
    };
    let r = s.reads[i];
    if offset >= r.size || out.is_empty() {
        return 0;
    }
    // The count is answered as an `i32`.
    let len = core::cmp::min(out.len() as u64, r.size - offset);
    let len = core::cmp::min(len, i32::MAX as u64) as usize;
    let mut seek = fsop::seek::encode(offset);
    let rc = fs_call(s, r.fd, fsop::SEEK, &mut seek, &mut []);
    if rc < 0 {
        return rc;
    }
    // A short count is an answer: the caller asks for the rest at the
    // offset it reaches. Progress already made is never discarded.
    let mut got = 0usize;
    while got < len {
        let rc = fs_call(s, r.fd, fsop::READ, &mut [], &mut out[got..len]);
        if rc == errno::EAGAIN && got > 0 {
            break;
        }
        if rc < 0 {
            return rc;
        }
        if rc == 0 {
            break;
        }
        if rc as usize > len - got {
            return errno::EIO;
        }
        got += rc as usize;
    }
    got as i32
}

/// `HEAD`: the key in, `[size][mtime][no content type][etag]` out, in place.
fn op_head(s: &mut State, arg: &mut [u8]) -> i32 {
    let mut kb = [0u8; KEY_MAX];
    let kl = {
        let Some(k) = obj::head::parse_request(arg) else {
            return errno::EINVAL;
        };
        if k.len() > KEY_MAX {
            return errno::EINVAL;
        }
        kb[..k.len()].copy_from_slice(k);
        k.len()
    };
    let (fd, size, mtime, path) = match open_file(s, &kb[..kl]) {
        Ok(v) => v,
        Err(e) if e == errno::ENOENT => return errno::ENXIO,
        Err(e) => return e,
    };
    fs_close(s, fd);
    let etag = (fnv1a64(path.bytes()) ^ size ^ mtime.rotate_left(17)).to_le_bytes();
    let Some(out) = obj::head::answer_area(arg) else {
        return errno::EINVAL;
    };
    let Some(n) = obj::range::encode_head(out, size, mtime, &[], &etag, obj::Kept::none()) else {
        return errno::ENOMEM;
    };
    fence::trailer::put(arg, &fence::Fence::Volatile);
    n as i32
}

fn op_close(s: &mut State, handle: i32) -> i32 {
    let Some(i) = owned(s, handle) else {
        return errno::EBADF;
    };
    fs_close(s, s.reads[i].fd);
    s.reads[i] = READ_EMPTY;
    0
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
        obj::GET => op_get(s, arg),
        obj::RANGE_GET => op_range(s, handle, arg, data),
        obj::HEAD => op_head(s, arg),
        obj::CLOSE => op_close(s, handle),
        // Read only.
        obj::PUT
        | obj::DELETE
        | obj::RETAIN
        | obj::PUT_STREAMED_OPEN
        | obj::PUT_STREAMED_WRITE
        | obj::PUT_STREAMED_COMMIT
        | obj::PUT_STREAMED_ABORT => errno::EROFS,
        obj::CAPS => abi::kernel_abi::caps_word::answer(arg, 0),
        _ => errno::ENOSYS,
    }
}

/// `OWNER_RELEASED`: what the owner opened goes with it.
fn owner_released(s: &mut State, rec: &[u8]) {
    let Some(head) = rec.get(..8) else { return };
    for i in 0..READS {
        if s.reads[i].in_use && s.reads[i].owner[..] == *head {
            fs_close(s, s.reads[i].fd);
            s.reads[i] = READ_EMPTY;
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
/// is marked, not cut or ignored: either would serve a directory other than
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
    s.reads = [READ_EMPTY; READS];
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
        let why = b"[file_object] refusing to construct: `root` is longer than 96 bytes";
        // SAFETY: `why` is live for the call.
        unsafe { dev_log(s.sys(), 1, why.as_ptr(), why.len()) };
        return -1;
    }
    0
}

/// Providers are called through `provider_call`, never stepped for work.
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
