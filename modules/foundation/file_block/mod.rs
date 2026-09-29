//! file_block — a `storage.block` source over one file.
//!
//! The image is a file reached through the `fs` contract, so the same module
//! is a loop device over a FAT32 file on bare metal and a disk image on a
//! Linux host. Blocks map to byte offsets `lba * block_size`.
//!
//! Every request runs inside the call that carries it. A `SUBMIT` executes at
//! once and queues its completion for `REAP`, so write data is consumed
//! before `SUBMIT` returns. Writes reach the file but not necessarily the
//! medium under it: they complete `Volatile`, and `FLUSH` (or `FUA`) runs the
//! file's `FSYNC`. `DISCARD` writes zeros, so a discarded block reads back as
//! zeros.
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

/// Requests whose completions wait for `REAP`.
pub const QUEUE_DEPTH: usize = 8;
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
    /// Completions waiting for `REAP`, oldest at `head`.
    head: u8,
    count: u8,
    _pad2: [u8; 2],
    path: [u8; PATH_CAP],
    /// Selector of the fs provider the image lives on.
    volume: [u8; VOLUME_CAP],
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
            | blk::caps::F_ASYNC
            | blk::caps::F_WRITE_COPIES,
        device_id: s.device_id,
    })
}

unsafe fn seek(s: &FileBlockState, off: u64) -> i32 {
    let mut arg = off.to_le_bytes();
    let rc = s.fs(s.fd, fs::SEEK, arg.as_mut_ptr(), 8);
    if rc < 0 {
        rc
    } else {
        0
    }
}

/// Read or write exactly `len` bytes at `off`, looping over short transfers.
unsafe fn transfer(s: &FileBlockState, write: bool, off: u64, buf: *mut u8, len: usize) -> i32 {
    let rc = seek(s, off);
    if rc < 0 {
        return rc;
    }
    let op = if write { fs::WRITE } else { fs::READ };
    let mut done = 0usize;
    while done < len {
        let rc = s.fs(s.fd, op, buf.add(done), len - done);
        if rc < 0 {
            return rc;
        }
        if rc == 0 {
            return E_IO;
        }
        done += rc as usize;
    }
    0
}

unsafe fn fsync(s: &FileBlockState) -> i32 {
    let rc = s.fs(s.fd, fs::FSYNC, core::ptr::null_mut(), 0);
    if rc < 0 {
        rc
    } else {
        0
    }
}

/// Write zeros over `nblocks` blocks from `lba`.
unsafe fn zero_blocks(s: &mut FileBlockState, lba: u64, nblocks: u32) -> i32 {
    let chunk = s.zeros.len().min(s.block_size as usize);
    let z = s.zeros.as_mut_ptr();
    let mut b = 0u64;
    let total = u64::from(nblocks) * u64::from(s.block_size);
    while b < total {
        let n = (total - b).min(chunk as u64) as usize;
        let rc = transfer(s, true, lba * u64::from(s.block_size) + b, z, n);
        if rc < 0 {
            return rc;
        }
        b += n as u64;
    }
    0
}

/// Run `r` and build its completion.
unsafe fn execute(s: &mut FileBlockState, r: &Req) -> Cpl {
    let mut c = Cpl::bare(r.tag, 0);
    if r.flags & blk::F_PREFLUSH != 0 {
        c.status = fsync(s);
        if c.status < 0 {
            return c;
        }
    }
    let off = r.lba * u64::from(s.block_size);
    let len = r.buf_len as usize;
    c.status = match r.op {
        blk::op::READ => transfer(s, false, off, r.buf_ptr as *mut u8, len),
        blk::op::WRITE => {
            let rc = transfer(s, true, off, r.buf_ptr as *mut u8, len);
            if rc == 0 && r.flags & blk::F_FUA != 0 {
                fsync(s)
            } else {
                rc
            }
        }
        blk::op::DISCARD => zero_blocks(s, r.lba, r.nblocks),
        blk::op::FLUSH => fsync(s),
        _ => E_INVAL,
    };
    if c.status != 0 {
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
            let c = execute(s, &r);
            c.encode(core::slice::from_raw_parts_mut(
                arg.add(blk::req::LEN),
                blk::cpl::LEN,
            ));
            c.status
        }
        blk::ioctl::SUBMIT => {
            let r = match admitted(s, core::slice::from_raw_parts(arg, blk::req::LEN)) {
                Ok(r) => r,
                Err(rc) => return rc,
            };
            if s.count as usize >= QUEUE_DEPTH {
                return E_AGAIN;
            }
            let c = execute(s, &r);
            if c.status == E_AGAIN {
                // The provider was busy. Every op is idempotent, so the
                // caller submits it again rather than reaping a failure.
                return E_AGAIN;
            }
            let tail = (s.head as usize + s.count as usize) % QUEUE_DEPTH;
            s.done[tail] = c;
            s.count += 1;
            0
        }
        blk::ioctl::REAP => {
            if s.count == 0 {
                return 0;
            }
            let c = s.done[s.head as usize];
            s.head = ((s.head as usize + 1) % QUEUE_DEPTH) as u8;
            s.count -= 1;
            c.encode(core::slice::from_raw_parts_mut(arg, blk::cpl::LEN));
            1
        }
        _ => E_NOSYS,
    }
}

/// Open the image, and extend it to `min_blocks` if it is shorter. `E_AGAIN`
/// means the provider was busy: the call is repeated, and resumes after an
/// open that already succeeded.
unsafe fn open_image(s: &mut FileBlockState) -> i32 {
    if s.path_len == 0 || s.path_len as usize > PATH_CAP || s.volume_len as usize > VOLUME_CAP {
        return E_INVAL;
    }
    let bs = s.block_size;
    if bs < 512 || !bs.is_power_of_two() {
        return E_INVAL;
    }
    if s.fd < 0 {
        let path = s.path.as_mut_ptr();
        let fd = s.fs(-1, fs::OPEN_CREATE, path, s.path_len as usize);
        if fd < 0 {
            return fd;
        }
        s.fd = fd;
    }
    let mut st = [0u8; 16];
    let rc = s.fs(s.fd, fs::STAT, st.as_mut_ptr(), 16);
    if rc < 0 {
        return rc;
    }
    let mut size = u64::from_le_bytes([st[0], st[1], st[2], st[3], st[4], st[5], st[6], st[7]]);
    let want = s.min_blocks * u64::from(bs);
    if size < want {
        // Write the last block; the file system fills the gap.
        let rc = zero_blocks(s, s.min_blocks - 1, 1);
        if rc < 0 {
            return rc;
        }
        let rc = fsync(s);
        if rc < 0 {
            return rc;
        }
        size = want;
    }
    s.block_count = size / u64::from(bs);
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
        if s.ready != 0 || s.open_err < 0 {
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
