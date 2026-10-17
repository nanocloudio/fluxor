//! file_block — a `storage.block` source over one file.
//!
//! The image is a file reached through the `fs` contract, so the same module
//! is a loop device over a FAT32 file on bare metal and a disk image on a
//! Linux host. Blocks map to byte offsets `lba * block_size`.
//!
//! The `fs` contract never waits on the device inside a call, so a request
//! is a resumable job, not a loop. `SUBMIT` queues it and `REAP` hands back
//! its completion; the queue runs strictly in submission order, advanced
//! inside `SUBMIT`/`REAP` and by the module's own step, and a job parked on
//! `EAGAIN` (nothing moved) or `EINPROGRESS` (a taken `FSYNC`, re-asked
//! byte-identically) resumes exactly where it stopped: short counts advance
//! by what moved. A queued write's buffer is therefore read when its turn
//! comes, so it stays lent until reaped (no `F_WRITE_COPIES`). `EXEC` runs
//! the same job inside the call and answers `EAGAIN` while it is undecided;
//! re-asking the identical request resumes it.
//!
//! Writes reach the file but not necessarily the medium under it: they
//! complete `Volatile`, and `FLUSH` (or `FUA`) fences them with the file's
//! `FSYNC`. `DISCARD` writes zeros, so a discarded block reads back as zeros.
//!
//! Parameters:
//! - `path`: the image file, created when absent.
//! - `block_size`: logical block size in bytes, a power of two from 512.
//! - `blocks`: minimum image size in blocks; a shorter file is extended.
//! - `volume`: the `fs` provider the image is reached through. Absent, the
//!   default provider; a keyed volume's name; or `platform`, the platform's
//!   own provider — the host filesystem on Linux — which stays reachable when
//!   the graph carries a filesystem of its own (a `fat32` over this very
//!   source, say) as the default.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

use abi::contracts::storage::block::{self as blk, Caps, Cpl, Req};
use abi::contracts::storage::fs;
use abi::fence::Fence;

/// Requests in flight: queued, running, or done and waiting for `REAP`.
pub const QUEUE_DEPTH: usize = 8;
/// `fs` calls one pump may issue. Each is decided now or parks the job.
const PUMP_CALLS: u32 = 32;
/// Blocks one request may carry.
pub const MAX_BLOCKS: u32 = 64;
/// Longest image path.
const PATH_CAP: usize = 96;
/// Longest `volume` name.
const VOLUME_CAP: usize = 16;

#[repr(C)]
struct FileBlockState {
    syscalls: *const SyscallTable,
    /// The `blocks` output this source answers on.
    out_chan: i32,
    /// Open image handle, or -1. Set as soon as the open call answers; the
    /// source is attached once `ready` is.
    fd: i32,
    /// Logical block size.
    block_size: u32,
    /// Negative errno the image failed to open with; 0 while opening or open.
    open_err: i32,
    /// Minimum image size in blocks.
    min_blocks: u64,
    /// Blocks the open image holds.
    block_count: u64,
    /// FNV-1a 64 of the path: the device a `LocalDurable` fence names.
    device_id: u64,
    path_len: u8,
    /// Length of `volume`; 0 = the default fs provider.
    volume_len: u8,
    /// The image is open and sized; `caps_of` answers.
    ready: u8,
    _pad: u8,
    /// The request ring, oldest at `head`: `count` slots in use, of which
    /// the first `ndone` are finished and wait for `REAP`; the slot after
    /// them is the one `job` is running.
    head: u8,
    count: u8,
    ndone: u8,
    /// Phase of the open machine (`OPEN_*`).
    open_phase: u8,
    /// `1` while an `EXEC` job is parked in `job`, undecided; `exec_req` is
    /// the request it runs, so only the identical request resumes it.
    exec_parked: u8,
    /// `1` when `fd_pos` is the handle's file offset.
    fd_pos_valid: u8,
    _pad2: [u8; 2],
    /// The handle's file offset, as this module last set or advanced it.
    fd_pos: u64,
    job: Job,
    exec_req: Req,
    path: [u8; PATH_CAP],
    /// Selector of the fs provider the image lives on.
    volume: [u8; VOLUME_CAP],
    reqs: [Req; QUEUE_DEPTH],
    done: [Cpl; QUEUE_DEPTH],
    /// One block of zeros, for extending the image and for `DISCARD`.
    zeros: [u8; 512],
}

impl FileBlockState {
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }

    /// One `fs` op on the image's provider. With a `volume`, every op — the
    /// open and each op on the handle it returns — names that provider, so
    /// none of them can land on whichever filesystem is the graph's default.
    unsafe fn fs(&self, handle: i32, op: u32, arg: *mut u8, len: usize) -> i32 {
        let n = self.volume_len as usize;
        if n == 0 {
            (self.sys().provider_call)(handle, op, arg, len)
        } else {
            dev_provider_call_sel(self.sys(), &self.volume[..n], handle, op, arg, len)
        }
    }
}

mod params_def {
    use super::p_u32;
    use super::FileBlockState;
    use super::SCHEMA_MAX;

    define_params! {
        FileBlockState;

        1, path, str, 0
            => |s, d, len| {
                // A path that does not fit is refused at open rather than
                // clipped: a clipped path names, and creates, another file.
                for i in 0..s.path.len() { s.path[i] = 0; }
                if len <= s.path.len() {
                    for i in 0..len { s.path[i] = *d.add(i); }
                    s.path_len = len as u8;
                } else {
                    s.path_len = u8::MAX;
                }
            };

        2, block_size, u32, 512
            => |s, d, len| { s.block_size = p_u32(d, len, 0, 512); };

        3, blocks, u32, 0
            => |s, d, len| { s.min_blocks = u64::from(p_u32(d, len, 0, 0)); };

        4, volume, str, 0
            => |s, d, len| {
                // A name that does not fit is refused at open rather than
                // clipped: a clipped selector names some other provider.
                for i in 0..s.volume.len() { s.volume[i] = 0; }
                if len <= s.volume.len() {
                    for i in 0..len { s.volume[i] = *d.add(i); }
                    s.volume_len = len as u8;
                } else {
                    s.volume_len = u8::MAX;
                }
            };
    }
}

/// FNV-1a 64 over `bytes`.
pub fn fnv64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// The device a `LocalDurable` fence names: the image path, qualified by the
/// volume when one is named, since one path on two filesystems is two files.
fn image_id(s: &FileBlockState) -> u64 {
    let path = &s.path[..s.path_len as usize];
    let n = s.volume_len as usize;
    if n == 0 || n > VOLUME_CAP {
        return fnv64(path);
    }
    // Volume, a zero separator, then the path, as one FNV-1a stream.
    let mut h = fnv64(&s.volume[..n]).wrapping_mul(0x0000_0100_0000_01B3);
    for &b in path {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

fn caps_of(s: &FileBlockState) -> Option<Caps> {
    if s.ready == 0 {
        return None;
    }
    Some(Caps {
        logical_block_size: s.block_size,
        block_count: s.block_count,
        max_blocks: MAX_BLOCKS,
        atomic_blocks: 1,
        queue_depth: QUEUE_DEPTH as u16,
        flags: blk::caps::F_WRITE
            | blk::caps::F_FLUSH
            | blk::caps::F_DISCARD
            | blk::caps::F_DISCARD_ZEROES
            | blk::caps::F_ASYNC,
        device_id: s.device_id,
    })
}

/// Progress of the one request being run.
#[derive(Clone, Copy)]
struct Job {
    /// `JOB_*`.
    phase: u8,
    _pad: [u8; 7],
    /// Bytes moved so far.
    done: u64,
}

impl Job {
    const fn new() -> Job {
        Job {
            phase: JOB_PREFLUSH,
            _pad: [0; 7],
            done: 0,
        }
    }
}

/// `F_PREFLUSH`'s fence, then the transfer, then the `FLUSH`/`FUA` fence.
const JOB_PREFLUSH: u8 = 0;
const JOB_XFER: u8 = 1;
const JOB_FENCE: u8 = 2;

/// The open machine (`open_phase`): open, size, extend, fence the extension.
const OPEN_OPEN: u8 = 0;
const OPEN_STAT: u8 = 1;
const OPEN_EXTEND: u8 = 2;
const OPEN_FSYNC: u8 = 3;

/// Whether an `fs` answer is "not decided yet": `EAGAIN` (nothing moved,
/// ask again) or `EINPROGRESS` (taken; the identical re-ask collects it).
fn undecided(rc: i32) -> bool {
    rc == E_AGAIN || rc == E_INPROGRESS
}

/// Make the handle's offset `off`. `SEEK` answers or `EAGAIN`; the offset
/// is remembered so an uninterrupted run of transfers seeks once.
unsafe fn position(s: &mut FileBlockState, off: u64) -> i32 {
    if s.fd_pos_valid != 0 && s.fd_pos == off {
        return 0;
    }
    let mut arg = off.to_le_bytes();
    let rc = s.fs(s.fd, fs::SEEK, arg.as_mut_ptr(), 8);
    if rc < 0 {
        return rc;
    }
    s.fd_pos = off;
    s.fd_pos_valid = 1;
    0
}

/// One `READ`/`WRITE` of at most `len` bytes at `off`. Answers the count
/// moved (never 0 for `len > 0`: an empty transfer is `E_IO`), `EAGAIN`, or
/// a negative errno.
unsafe fn transfer_once(
    s: &mut FileBlockState,
    write: bool,
    off: u64,
    buf: *mut u8,
    len: usize,
) -> i32 {
    let rc = position(s, off);
    if rc < 0 {
        return rc;
    }
    let op = if write { fs::WRITE } else { fs::READ };
    let n = s.fs(s.fd, op, buf, len);
    if n == E_AGAIN {
        return n;
    }
    if n < 0 {
        // Whatever the failure did to the offset, it is not known now.
        s.fd_pos_valid = 0;
        return n;
    }
    if n == 0 || n as usize > len {
        s.fd_pos_valid = 0;
        return E_IO;
    }
    s.fd_pos = off + n as u64;
    n
}

/// The file's byte-durability fence. 0 once durable; `EAGAIN` /
/// `EINPROGRESS` while undecided — the re-ask (same handle, no argument) is
/// identical by construction.
unsafe fn fsync(s: &FileBlockState) -> i32 {
    let rc = s.fs(s.fd, fs::FSYNC, core::ptr::null_mut(), 0);
    if rc < 0 {
        rc
    } else {
        0
    }
}

/// Bytes request `r` moves.
fn req_bytes(s: &FileBlockState, r: &Req) -> u64 {
    match r.op {
        blk::op::READ | blk::op::WRITE => u64::from(r.buf_len),
        blk::op::DISCARD => u64::from(r.nblocks) * u64::from(s.block_size),
        _ => 0,
    }
}

/// Advance `job` running `r` by at most `*calls` `fs` calls. `Some(status)`
/// once decided; `None` while parked on an undecided call, to be resumed
/// with the same `r` and `job`.
unsafe fn job_advance(
    s: &mut FileBlockState,
    r: &Req,
    job: &mut Job,
    calls: &mut u32,
) -> Option<i32> {
    loop {
        if *calls == 0 {
            return None;
        }
        match job.phase {
            JOB_PREFLUSH => {
                if r.flags & blk::F_PREFLUSH != 0 {
                    *calls -= 1;
                    let rc = fsync(s);
                    if undecided(rc) {
                        return None;
                    }
                    if rc < 0 {
                        return Some(rc);
                    }
                }
                if !matches!(
                    r.op,
                    blk::op::READ | blk::op::WRITE | blk::op::DISCARD | blk::op::FLUSH
                ) {
                    return Some(E_INVAL);
                }
                job.phase = JOB_XFER;
            }
            JOB_XFER => {
                let total = req_bytes(s, r);
                if job.done >= total {
                    job.phase = JOB_FENCE;
                    continue;
                }
                let off = r.lba * u64::from(s.block_size) + job.done;
                let left = (total - job.done) as usize;
                let (write, buf, len) = match r.op {
                    blk::op::READ => (false, (r.buf_ptr as *mut u8).add(job.done as usize), left),
                    blk::op::WRITE => (true, (r.buf_ptr as *mut u8).add(job.done as usize), left),
                    _ => {
                        let chunk = s.zeros.len().min(s.block_size as usize);
                        (true, s.zeros.as_mut_ptr(), left.min(chunk))
                    }
                };
                *calls -= 1;
                let n = transfer_once(s, write, off, buf, len);
                if n == E_AGAIN {
                    return None;
                }
                if n < 0 {
                    return Some(n);
                }
                // A short count is progress: advance by what moved.
                job.done += n as u64;
            }
            _ => {
                let fence =
                    r.op == blk::op::FLUSH || (r.op == blk::op::WRITE && r.flags & blk::F_FUA != 0);
                if fence {
                    *calls -= 1;
                    let rc = fsync(s);
                    if undecided(rc) {
                        return None;
                    }
                    return Some(rc);
                }
                return Some(0);
            }
        }
    }
}

/// The completion of `r` decided with `status`.
fn completion(s: &FileBlockState, r: &Req, status: i32) -> Cpl {
    let mut c = Cpl::bare(r.tag, status);
    if status != 0 {
        return c;
    }
    let durable = r.op == blk::op::FLUSH || r.flags & blk::F_FUA != 0;
    let fence = match r.op {
        blk::op::READ => None,
        _ if durable => Some(Fence::LocalDurable {
            device_id: s.device_id,
        }),
        _ => Some(Fence::Volatile),
    };
    if let Some(f) = fence {
        if let Some(n) = f.encode(&mut c.fence) {
            c.fence_len = n as u16;
        }
    }
    c
}

/// Run the queue in order, as far as the provider decides now. A queued
/// request takes the job from a parked `EXEC`, which then starts over when
/// it is asked again.
unsafe fn pump(s: &mut FileBlockState) {
    if s.ready == 0 {
        return;
    }
    let mut calls = PUMP_CALLS;
    while s.ndone < s.count && calls > 0 {
        if s.exec_parked != 0 {
            s.exec_parked = 0;
            s.job = Job::new();
        }
        let i = (s.head as usize + s.ndone as usize) % QUEUE_DEPTH;
        let r = s.reqs[i];
        let mut job = s.job;
        let out = job_advance(s, &r, &mut job, &mut calls);
        match out {
            Some(status) => {
                s.done[i] = completion(s, &r, status);
                s.ndone += 1;
                s.job = Job::new();
            }
            None => {
                s.job = job;
                return;
            }
        }
    }
}

/// `EXEC`: run `r` inside the call. Answers its status, or `EAGAIN` while
/// it is undecided (the job stays parked for the identical re-ask) or while
/// queued requests hold the job.
unsafe fn exec(s: &mut FileBlockState, r: &Req, c: &mut Cpl) -> i32 {
    pump(s);
    if s.ndone < s.count {
        return E_AGAIN;
    }
    if s.exec_parked == 0 || s.exec_req != *r {
        s.job = Job::new();
        s.exec_req = *r;
    }
    s.exec_parked = 1;
    let mut calls = PUMP_CALLS;
    let mut job = s.job;
    let out = job_advance(s, r, &mut job, &mut calls);
    s.job = job;
    match out {
        Some(status) => {
            s.exec_parked = 0;
            s.job = Job::new();
            *c = completion(s, r, status);
            status
        }
        None => E_AGAIN,
    }
}

unsafe fn admitted(s: &FileBlockState, body: &[u8]) -> Result<Req, i32> {
    let Some(caps) = caps_of(s) else {
        return Err(if s.open_err < 0 { s.open_err } else { E_AGAIN });
    };
    match Req::decode(body) {
        Some(r) if caps.admits(&r) => Ok(r),
        _ => Err(E_INVAL),
    }
}

unsafe extern "C" fn file_block_ioctl(state: *mut c_void, cmd: u32, arg: *mut u8) -> i32 {
    if state.is_null() || arg.is_null() {
        return E_INVAL;
    }
    let s = &mut *(state as *mut FileBlockState);
    match cmd {
        blk::ioctl::CAPS => match caps_of(s) {
            Some(c) => {
                c.encode(core::slice::from_raw_parts_mut(arg, blk::caps::LEN));
                blk::caps::LEN as i32
            }
            None if s.open_err < 0 => s.open_err,
            None => E_AGAIN,
        },
        blk::ioctl::EXEC => {
            let r = match admitted(s, core::slice::from_raw_parts(arg, blk::req::LEN)) {
                Ok(r) => r,
                Err(rc) => return rc,
            };
            let mut c = Cpl::bare(r.tag, E_AGAIN);
            let rc = exec(s, &r, &mut c);
            c.encode(core::slice::from_raw_parts_mut(
                arg.add(blk::req::LEN),
                blk::cpl::LEN,
            ));
            rc
        }
        blk::ioctl::SUBMIT => {
            let r = match admitted(s, core::slice::from_raw_parts(arg, blk::req::LEN)) {
                Ok(r) => r,
                Err(rc) => return rc,
            };
            if s.count as usize >= QUEUE_DEPTH {
                return E_AGAIN;
            }
            let tail = (s.head as usize + s.count as usize) % QUEUE_DEPTH;
            s.reqs[tail] = r;
            s.count += 1;
            pump(s);
            0
        }
        blk::ioctl::REAP => {
            pump(s);
            if s.ndone == 0 {
                return 0;
            }
            let c = s.done[s.head as usize];
            s.head = ((s.head as usize + 1) % QUEUE_DEPTH) as u8;
            s.count -= 1;
            s.ndone -= 1;
            c.encode(core::slice::from_raw_parts_mut(arg, blk::cpl::LEN));
            1
        }
        _ => E_NOSYS,
    }
}

/// Open the image, and extend it to `min_blocks` if it is shorter: a step
/// machine that resumes at the call it stopped on. `E_AGAIN` means not
/// decided yet (the provider answered `EAGAIN`, or `EINPROGRESS` for a call
/// it took and that is re-asked identically next step).
unsafe fn open_image(s: &mut FileBlockState) -> i32 {
    if s.path_len == 0 || s.path_len as usize > PATH_CAP || s.volume_len as usize > VOLUME_CAP {
        return E_INVAL;
    }
    let bs = s.block_size;
    if bs < 512 || !bs.is_power_of_two() {
        return E_INVAL;
    }
    let mut calls = PUMP_CALLS;
    let mut sized = false;
    while !sized {
        if calls == 0 {
            // The step's share ran out mid-open; the next step resumes it.
            return E_AGAIN;
        }
        calls -= 1;
        match s.open_phase {
            OPEN_OPEN => {
                let path = s.path.as_mut_ptr();
                let fd = s.fs(-1, fs::OPEN_CREATE, path, s.path_len as usize);
                if undecided(fd) {
                    return E_AGAIN;
                }
                if fd < 0 {
                    return fd;
                }
                s.fd = fd;
                s.fd_pos_valid = 0;
                s.open_phase = OPEN_STAT;
            }
            OPEN_STAT => {
                let mut st = [0u8; 16];
                let rc = s.fs(s.fd, fs::STAT, st.as_mut_ptr(), 16);
                if rc == E_AGAIN {
                    return E_AGAIN;
                }
                if rc < 0 {
                    return rc;
                }
                let size =
                    u64::from_le_bytes([st[0], st[1], st[2], st[3], st[4], st[5], st[6], st[7]]);
                let want = s.min_blocks * u64::from(bs);
                if size < want {
                    s.job = Job::new();
                    s.open_phase = OPEN_EXTEND;
                    continue;
                }
                s.block_count = size / u64::from(bs);
                sized = true;
            }
            OPEN_EXTEND => {
                // Write the last block; the file system fills the gap.
                let off = (s.min_blocks - 1) * u64::from(bs);
                if s.job.done >= u64::from(bs) {
                    s.open_phase = OPEN_FSYNC;
                    continue;
                }
                let left = (u64::from(bs) - s.job.done) as usize;
                let len = left.min(s.zeros.len());
                let z = s.zeros.as_mut_ptr();
                let n = transfer_once(s, true, off + s.job.done, z, len);
                if n == E_AGAIN {
                    return E_AGAIN;
                }
                if n < 0 {
                    return n;
                }
                s.job.done += n as u64;
            }
            _ => {
                let rc = fsync(s);
                if undecided(rc) {
                    return E_AGAIN;
                }
                if rc < 0 {
                    return rc;
                }
                s.job = Job::new();
                s.block_count = s.min_blocks;
                sized = true;
            }
        }
    }
    s.device_id = image_id(s);
    s.ready = 1;
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<FileBlockState>()
}

/// Consumers wait for the image to open: `Ready` gates them.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 {
    1
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
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
        if state_size < core::mem::size_of::<FileBlockState>() {
            return -2;
        }
        core::ptr::write_bytes(state, 0, core::mem::size_of::<FileBlockState>());
        let s = &mut *(state as *mut FileBlockState);
        s.syscalls = syscalls as *const SyscallTable;
        s.out_chan = out_chan;
        s.fd = -1;
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        if out_chan >= 0 {
            dev_channel_register_ioctl(
                &*s.syscalls,
                out_chan,
                state as *mut c_void,
                Some(file_block_ioctl),
            );
        }
        0
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut FileBlockState);
        if s.ready != 0 {
            // Queued requests advance between their consumer's calls too.
            pump(s);
            return 0;
        }
        if s.open_err < 0 {
            return 0;
        }
        match open_image(s) {
            0 => {
                dev_log(s.sys(), 3, b"[file_block] ready".as_ptr(), 18);
                3
            }
            E_AGAIN => 0,
            rc => {
                if s.fd >= 0 {
                    s.fs(s.fd, fs::CLOSE, core::ptr::null_mut(), 0);
                    s.fd = -1;
                }
                s.open_err = rc;
                dev_log(s.sys(), 1, b"[file_block] image failed".as_ptr(), 25);
                rc
            }
        }
    }
}

include!("../../sdk/runtime/wasm_entry.rs");
