//! vault_store — the key vault's durable store, on any `storage.block` source.
//!
//! The vault keeps the node's persisted records as one image in kernel RAM
//! (`kernel::security::vault_store`, format `FXVS` v1). This module carries
//! that image to and from two A/B slots on the block source wired to its
//! `blocks` input — a flash region, a file on an SD card's FAT, a raw
//! partition, an NVMe window, a host file: one implementation behind all of
//! them. The kernel owns the format and every validity decision; this module
//! owns the I/O. The wire is `abi::internal::vault_store`.
//!
//! - **Geometry** comes from the source: a slot is `image` bytes, which must
//!   be a whole number of the source's blocks (512 B to 4 KiB). Slot A starts
//!   at `start_sector`, slot B right after it; the window (`sector_count`, or
//!   the rest of the source) must hold both. Sectors are 512 bytes whatever
//!   the source's block size, so a window is named the same on any medium.
//! - **Load.** Both slots are read and digested, then the newer valid one
//!   is read again into the kernel: one image of RAM, never two. A read that
//!   fails, or a pass the kernel refuses (the slot changed between the
//!   passes), attaches again, which starts the load over.
//! - **Writes.** A new image goes to the slot not holding the durable one,
//!   one block at a time, then a flush; only then is it reported, and only
//!   then is a key made since handed out. An image that changes under the
//!   write is started again from its beginning; the durable slot is never
//!   touched. A write the medium refuses is reported, and retried a second
//!   later.
//! - **Sealing** (`seal`): `hardware` keeps records sealed under the
//!   platform's key, which the medium never holds; a board without one
//!   persists nothing. `none` keeps them readable, and each key says so.
//!
//! Parameters:
//! - `image`: image size in bytes, a multiple of 512: up to 4096 on an
//!   RP2040, 8192 on an RP2350, 16384 elsewhere. Default 8192.
//! - `seal`: `hardware` (default) or `none`.
//! - `start_sector`: where slot A starts, in 512-byte sectors. Default 0.
//! - `sector_count`: the window, in 512-byte sectors; 0 (default) is the
//!   rest of the source.

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

use abi::contracts::storage::block as blk;
use abi::internal::vault_store as vs;

/// Largest source block this module writes whole.
pub const MAX_BLOCK: usize = 4096;
/// Bytes per sector, the unit `start_sector` and `sector_count` count in.
pub const SECTOR: u64 = 512;
/// Pause after a failed write or read before trying again.
const RETRY_MS: u64 = 1000;
/// The tag every read this module submits carries (one in flight).
const READ_TAG: u64 = 1;

/// Where the module is.
pub mod phase {
    pub const CAPS: u8 = 0;
    pub const ATTACH: u8 = 1;
    pub const SCAN: u8 = 2;
    pub const DECIDE: u8 = 3;
    pub const FILL: u8 = 4;
    pub const RUN: u8 = 5;
    /// Copying the pending image's next block and writing it.
    pub const WRITE: u8 = 6;
    /// The block written, waiting for its completion.
    pub const WRITTEN: u8 = 7;
    /// Every block written, waiting for the flush.
    pub const FENCE: u8 = 8;
    /// Waiting out `RETRY_MS`, then `resume` (`ATTACH` or `RUN`).
    pub const BACKOFF: u8 = 9;
    /// Misconfigured: nothing more is done.
    pub const STOPPED: u8 = 10;
}

#[repr(C, align(8))]
pub struct Block(pub [u8; MAX_BLOCK]);

#[repr(C)]
pub struct VaultStoreState {
    syscalls: *const SyscallTable,
    blk: BlockClient,
    /// `blocks` input channel.
    chan: i32,
    /// Image size in bytes.
    image: u32,
    /// Window, in 512-byte sectors.
    start_sector: u32,
    sector_count: u32,
    seal: u8,
    pub phase: u8,
    /// The phase `BACKOFF` returns to.
    resume: u8,
    /// Slot of the pass or write in progress.
    slot: u8,
    /// The source's block size.
    bs: u32,
    /// `log2(bs)`.
    shift: u32,
    /// Blocks per slot.
    slot_blocks: u32,
    /// Byte offset within the slot of the block in progress.
    off: u32,
    /// A read is in flight.
    reading: u8,
    _pad: [u8; 7],
    /// First block of slot A.
    base_lba: u64,
    /// Sequence of the image being written.
    seq: u64,
    /// The client's sequence of the block write in flight.
    wseq: u64,
    /// Fence ticket covering the image's writes.
    ticket: u64,
    /// When `BACKOFF` ends (ms since boot).
    until: u64,
    buf: Block,
}

impl VaultStoreState {
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

mod params_def {
    use super::p_u32;
    use super::p_u8;
    use super::VaultStoreState;
    use super::SCHEMA_MAX;

    define_params! {
        VaultStoreState;

        1, image, u32, 8192
            => |s, d, len| { s.image = p_u32(d, len, 0, 8192); };

        2, seal, u8, 0, enum { hardware=0, none=1 }
            => |s, d, len| { s.seal = p_u8(d, len, 0, 0); };

        3, start_sector, u32, 0
            => |s, d, len| { s.start_sector = p_u32(d, len, 0, 0); };

        4, sector_count, u32, 0
            => |s, d, len| { s.sector_count = p_u32(d, len, 0, 0); };
    }
}

unsafe fn log(s: &VaultStoreState, level: u8, msg: &[u8]) {
    dev_log(s.sys(), level, msg.as_ptr(), msg.len());
}

/// Log `msg` followed by a decimal `n`.
unsafe fn log_n(s: &VaultStoreState, level: u8, msg: &[u8], n: u32) {
    let mut line = [0u8; 96];
    let m = msg.len().min(80);
    line[..m].copy_from_slice(&msg[..m]);
    let k = fmt_u32_raw(line.as_mut_ptr().add(m), n);
    dev_log(s.sys(), level, line.as_ptr(), m + k);
}

/// The vault-store opcode `op` with `arg`.
unsafe fn call(s: &VaultStoreState, op: u32, arg: &mut [u8]) -> i32 {
    (s.sys().provider_call)(-1, op, arg.as_mut_ptr(), arg.len())
}

/// Stop for good: the configuration cannot work.
unsafe fn stop(s: &mut VaultStoreState, why: &[u8]) -> i32 {
    log(s, 1, why);
    s.phase = phase::STOPPED;
    -1
}

/// Wait `RETRY_MS`, then go to `resume`, with a fresh client: a source that
/// failed a request is asked again from its capabilities.
unsafe fn back_off(s: &mut VaultStoreState, resume: u8) {
    s.blk.bind(s.chan);
    s.reading = 0;
    s.resume = resume;
    s.until = dev_millis(s.sys()) + RETRY_MS;
    s.phase = phase::BACKOFF;
}

/// The source's geometry, checked against the parameters.
unsafe fn caps(s: &mut VaultStoreState) -> i32 {
    match s.blk.caps(&*s.syscalls) {
        0 => {}
        E_AGAIN => return 0,
        _ => return stop(s, b"[vault_store] the blocks source answers no CAPS"),
    }
    let bs = s.blk.block_size();
    let flags = s.blk.flags();
    if !(512..=MAX_BLOCK as u32).contains(&bs) || !bs.is_power_of_two() {
        return stop(s, b"[vault_store] source block size outside 512..4096");
    }
    if flags & blk::caps::F_WRITE == 0 || flags & blk::caps::F_ASYNC == 0 {
        return stop(
            s,
            b"[vault_store] source does not queue writes (F_WRITE, F_ASYNC)",
        );
    }
    // Powers of two throughout: no division reaches the PIC build.
    let shift = bs.trailing_zeros();
    if s.image & (bs - 1) != 0 {
        return stop(
            s,
            b"[vault_store] image is not a whole number of source blocks",
        );
    }
    let start = u64::from(s.start_sector) * SECTOR;
    if start & u64::from(bs - 1) != 0 {
        return stop(s, b"[vault_store] start_sector is not on a source block");
    }
    let total = s.blk.block_count().saturating_mul(u64::from(bs));
    let window = if s.sector_count != 0 {
        u64::from(s.sector_count) * SECTOR
    } else {
        total.saturating_sub(start)
    };
    if start + window > total || window < 2 * u64::from(s.image) {
        return stop(s, b"[vault_store] the window does not hold two slots");
    }
    s.bs = bs;
    s.shift = shift;
    s.slot_blocks = s.image >> shift;
    s.base_lba = start >> shift;
    s.phase = phase::ATTACH;
    0
}

unsafe fn attach(s: &mut VaultStoreState) -> i32 {
    let mut a = [0u8; vs::ATTACH_LEN];
    a[0..4].copy_from_slice(&s.image.to_le_bytes());
    a[4] = s.seal;
    match call(s, vs::ATTACH, &mut a) {
        0 => {
            s.phase = phase::SCAN;
            s.slot = 0;
            s.off = 0;
            0
        }
        1 => {
            s.phase = phase::RUN;
            0
        }
        E_BUSY => stop(s, b"[vault_store] another vault_store is the vault's store"),
        rc => {
            log_n(s, 1, b"[vault_store] attach refused errno=", (-rc) as u32);
            s.phase = phase::STOPPED;
            -1
        }
    }
}

fn lba(s: &VaultStoreState) -> u64 {
    s.base_lba + u64::from(s.slot) * u64::from(s.slot_blocks) + u64::from(s.off >> s.shift)
}

/// One step of a load pass (`SCAN` or `FILL`): one block read and handed in.
unsafe fn load_step(s: &mut VaultStoreState) -> i32 {
    if s.reading == 0 {
        let at = lba(s);
        let buf = s.buf.0.as_mut_ptr();
        match s.blk.submit_read(&*s.syscalls, at, 1, buf, READ_TAG) {
            0 => s.reading = 1,
            E_AGAIN => {}
            _ => back_off(s, phase::ATTACH),
        }
        return 0;
    }
    s.blk.reap(&*s.syscalls);
    let Some((_, status)) = s.blk.take_read() else {
        return 0;
    };
    s.reading = 0;
    if status < 0 {
        log_n(
            s,
            2,
            b"[vault_store] read failed, loading again errno=",
            (-status) as u32,
        );
        back_off(s, phase::ATTACH);
        return 0;
    }
    let mut a = [0u8; vs::LOAD_LEN];
    a[0] = if s.phase == phase::FILL {
        vs::phase::FILL
    } else {
        vs::phase::SCAN
    };
    a[1] = s.slot;
    a[4..8].copy_from_slice(&s.off.to_le_bytes());
    a[8..16].copy_from_slice(&(s.buf.0.as_ptr() as u64).to_le_bytes());
    a[16..20].copy_from_slice(&s.bs.to_le_bytes());
    let rc = call(s, vs::LOAD, &mut a);
    if rc < 0 {
        // The slot changed between the passes, or the kernel's load is not
        // the one this pass belongs to: attaching again restarts it there
        // and here alike.
        log_n(
            s,
            2,
            b"[vault_store] load refused, loading again errno=",
            (-rc) as u32,
        );
        s.phase = phase::ATTACH;
        return 0;
    }
    s.off += s.bs;
    if s.off < s.image {
        return 0;
    }
    s.off = 0;
    if s.phase == phase::FILL {
        log(s, 3, b"[vault_store] loaded");
        s.phase = phase::RUN;
    } else if s.slot == 0 {
        s.slot = 1;
    } else {
        s.phase = phase::DECIDE;
    }
    0
}

unsafe fn decide(s: &mut VaultStoreState) -> i32 {
    let mut a = [0u8; 8];
    match call(s, vs::DECIDE, &mut a) {
        rc @ (0 | 1) => {
            s.slot = rc as u8;
            s.off = 0;
            s.phase = phase::FILL;
        }
        vs::DECIDE_EMPTY => {
            log(s, 3, b"[vault_store] empty: no image in either slot");
            s.phase = phase::RUN;
        }
        // The kernel has not seen both slots whole: load again.
        _ => s.phase = phase::ATTACH,
    }
    0
}

/// Ask for the next image to write.
unsafe fn run(s: &mut VaultStoreState) -> i32 {
    let mut a = [0u8; vs::PENDING_LEN];
    if call(s, vs::PENDING, &mut a) != 1 {
        return 0;
    }
    let mut seq = [0u8; 8];
    seq.copy_from_slice(&a[0..8]);
    s.seq = u64::from_le_bytes(seq);
    s.slot = a[8];
    s.off = 0;
    s.phase = phase::WRITE;
    write_step(s)
}

unsafe fn report(s: &VaultStoreState, status: i32) {
    let mut a = [0u8; vs::DONE_LEN];
    a[0..8].copy_from_slice(&s.seq.to_le_bytes());
    a[8..12].copy_from_slice(&status.to_le_bytes());
    call(s, vs::DONE, &mut a);
}

/// Copy the image's next block and submit its write.
unsafe fn write_step(s: &mut VaultStoreState) -> i32 {
    let mut a = [0u8; vs::READ_LEN];
    a[0..8].copy_from_slice(&s.seq.to_le_bytes());
    a[8..12].copy_from_slice(&s.off.to_le_bytes());
    a[12..16].copy_from_slice(&s.bs.to_le_bytes());
    a[16..24].copy_from_slice(&(s.buf.0.as_mut_ptr() as u64).to_le_bytes());
    if call(s, vs::READ, &mut a) != 0 {
        // A newer image: start it from its beginning (same slot).
        s.phase = phase::RUN;
        return 0;
    }
    let at = lba(s);
    let buf = s.buf.0.as_ptr();
    match s.blk.submit_write(&*s.syscalls, at, 1, buf) {
        0 => {
            s.wseq = s.blk.last_seq();
            s.phase = phase::WRITTEN;
        }
        // The queue is full: copy and ask again next step.
        E_AGAIN => {}
        rc => fail_write(s, rc),
    }
    0
}

unsafe fn fail_write(s: &mut VaultStoreState, rc: i32) {
    log_n(
        s,
        2,
        b"[vault_store] write failed, retrying errno=",
        (-rc) as u32,
    );
    report(s, if rc < 0 { rc } else { E_IO });
    back_off(s, phase::RUN);
}

unsafe fn written(s: &mut VaultStoreState) -> i32 {
    s.blk.reap(&*s.syscalls);
    match s.blk.write_state(s.wseq) {
        1 => return 0,
        0 => {}
        rc => {
            fail_write(s, rc);
            return 0;
        }
    }
    s.off += s.bs;
    if s.off < s.image {
        s.phase = phase::WRITE;
        return write_step(s);
    }
    s.ticket = s.blk.flush_submit();
    s.phase = phase::FENCE;
    fence(s)
}

unsafe fn fence(s: &mut VaultStoreState) -> i32 {
    match s.blk.fence_poll(&*s.syscalls, s.ticket) {
        1 => 0,
        0 => {
            report(s, 0);
            s.phase = phase::RUN;
            0
        }
        rc => {
            fail_write(s, rc);
            0
        }
    }
}

unsafe fn step(s: &mut VaultStoreState) -> i32 {
    match s.phase {
        phase::CAPS => caps(s),
        phase::ATTACH => attach(s),
        phase::SCAN | phase::FILL => load_step(s),
        phase::DECIDE => decide(s),
        phase::RUN => run(s),
        phase::WRITE => write_step(s),
        phase::WRITTEN => written(s),
        phase::FENCE => fence(s),
        phase::BACKOFF => {
            if dev_millis(s.sys()) >= s.until {
                s.phase = s.resume;
            }
            0
        }
        _ => 0,
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<VaultStoreState>()
}

declare_module_state_bytes!(VaultStoreState);

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    _out_chan: i32,
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
        if state_size < core::mem::size_of::<VaultStoreState>() {
            return -2;
        }
        core::ptr::write_bytes(state, 0, core::mem::size_of::<VaultStoreState>());
        let s = &mut *(state as *mut VaultStoreState);
        s.syscalls = syscalls as *const SyscallTable;
        s.chan = in_chan;
        s.blk.bind(in_chan);
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        if in_chan < 0 {
            return -1;
        }
        s.phase = phase::CAPS;
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
        let s = &mut *(state as *mut VaultStoreState);
        // A stopped store has said why once; the module keeps running idle.
        step(s);
        0
    }
}

include!("../../sdk/runtime/wasm_entry.rs");
