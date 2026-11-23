//! program_probe — reads the program the node image carries for it.
//!
//! A buffer of work a step: `PROGRAM_INFO` for slot 0, the whole program
//! through `PROGRAM_READ` hashed, and the same bytes read in place when the
//! kernel answers an address, hashed again. The two digests must agree with
//! each other and with the file the graph named. With `poke: 1` it then
//! reads the first byte past what it is granted of its program region,
//! which an isolated module must not be able to do.
//!
//! With `blob` set (a param that takes an asset) it then opens that value
//! with `fluxor_rt::asset` and reports what the target handed it: a program
//! hashed in place and through `PROGRAM_READ`, or a file left to the `fs`
//! contract.

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

use abi::kernel_abi::{program as pg, PROGRAM_INFO, PROGRAM_READ};
use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::asset::{self, Asset};
use fluxor_rt::*;
pub use fluxor_sdk::crypto::sha256::*;

/// Bytes of the `blob` param the probe keeps: a program reference, a bundle
/// URL or a path.
const BLOB_MAX: usize = 160;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    poke: u8,
    /// Steps to wait before starting: a board whose log reaches the bench
    /// over the network says nothing before its address is bound.
    delay: u32,
    /// 0 = ask for the program, 1 = reading through the kernel, 2 = reading
    /// in place, 3 = report, 4 = open the asset, 5 = reading it through the
    /// kernel, 6 = reading it in place, 7 = report it, 8 = done.
    phase: u8,
    /// The `blob` param's value and its length; 0 when the graph sets none.
    blob: [u8; BLOB_MAX],
    blob_len: u8,
    /// The asset's slot, size and in-place address (0 when it has none).
    asset_slot: u8,
    asset_size: u32,
    asset_addr: usize,
    info: [u8; pg::INFO_LEN],
    at: u32,
    through: Sha256,
    inplace: Sha256,
    buf: [u8; 512],
}

mod params_def {
    use super::*;
    fluxor_rt::define_params! {
        State;
        1, poke, u8, 0 => |s, d, len| { s.poke = p_u8(d, len, 0, 0); };
        2, delay, u32, 0 => |s, d, len| { s.delay = p_u32(d, len, 0, 0); };
        3, blob, str, 0 => |s, d, len| {
            // A value too long to keep is kept as none: the probe reports
            // only an asset it opened whole.
            if len <= BLOB_MAX {
                let mut i = 0;
                while i < len {
                    s.blob[i] = *d.add(i);
                    i += 1;
                }
                s.blob_len = len as u8;
            }
        };
    }
}

fn hex8(d: &[u8; 32], out: &mut [u8]) {
    const H: [u8; 16] = *b"0123456789abcdef";
    let mut i = 0;
    while i < 4 {
        out[2 * i] = H[(d[i] >> 4) as usize];
        out[2 * i + 1] = H[(d[i] & 15) as usize];
        i += 1;
    }
}

fn put(line: &mut [u8], n: &mut usize, b: &[u8]) {
    let mut i = 0;
    while i < b.len() && *n < line.len() {
        line[*n] = b[i];
        *n += 1;
        i += 1;
    }
}

fn put_dec(line: &mut [u8], n: &mut usize, mut v: u32) {
    let mut d = [0u8; 10];
    let mut k = 0;
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        put(line, n, &[d[k]]);
    }
}

fn put_hex32(line: &mut [u8], n: &mut usize, v: u32) {
    const H: [u8; 16] = *b"0123456789abcdef";
    let mut i = 0;
    while i < 8 {
        put(line, n, &[H[((v >> (28 - 4 * i)) & 15) as usize]]);
        i += 1;
    }
}

/// One unit of work a step: the program is read a buffer at a time, so a
/// large one never holds a step past its deadline.
unsafe fn probe_step(s: &mut State) {
    let sys = &*s.syscalls;
    let r = |info: &[u8], o: usize| {
        u32::from_le_bytes([info[o], info[o + 1], info[o + 2], info[o + 3]])
    };
    let at = pg::info::ADDR;
    let addr = u64::from_le_bytes([
        s.info[at],
        s.info[at + 1],
        s.info[at + 2],
        s.info[at + 3],
        s.info[at + 4],
        s.info[at + 5],
        s.info[at + 6],
        s.info[at + 7],
    ]);
    let size = r(&s.info, pg::info::SIZE);
    match s.phase {
        0 if s.delay > 0 => s.delay -= 1,
        0 => {
            s.info[0] = 0;
            let rc = (sys.provider_call)(
                -1,
                PROGRAM_INFO,
                s.info.as_mut_ptr(),
                s.info.len(),
                core::ptr::null_mut(),
                0,
            );
            if rc < 0 {
                let mut line = [0u8; 16];
                let mut n = 0;
                put(&mut line, &mut n, b"[prog] none");
                dev_log(sys, 3, line.as_ptr(), n);
                s.phase = 4;
                return;
            }
            s.through = Sha256::new();
            s.inplace = Sha256::new();
            s.at = 0;
            s.phase = 1;
        }
        1 => {
            if s.at >= size {
                s.at = 0;
                s.phase = 2;
                return;
            }
            // `arg` = `[slot 0][0; 3][offset]`; the bytes come back in `data`.
            let mut req = [0u8; 8];
            req[4..8].copy_from_slice(&s.at.to_le_bytes());
            let got = (sys.provider_call)(
                -1,
                PROGRAM_READ,
                req.as_mut_ptr(),
                req.len(),
                s.buf.as_mut_ptr(),
                s.buf.len(),
            );
            if got <= 0 {
                s.at = size;
                return;
            }
            s.through.update(&s.buf[..got as usize]);
            s.at += got as u32;
        }
        2 => {
            // In place: flash on a board, the mapped node image on a host.
            if addr == 0 || s.at >= size {
                s.phase = 3;
                return;
            }
            let n = core::cmp::min(512, size - s.at) as usize;
            let bytes =
                core::slice::from_raw_parts((addr as usize + s.at as usize) as *const u8, n);
            s.inplace.update(bytes);
            s.at += n as u32;
        }
        3 => {
            s.phase = 4;
            report(s, addr, size);
        }
        4 => open_asset(s),
        5 => {
            if s.at >= s.asset_size {
                s.at = 0;
                s.phase = 6;
                return;
            }
            let got = asset::read(sys, s.asset_slot, s.at, &mut s.buf);
            if got <= 0 {
                s.at = s.asset_size;
                return;
            }
            s.through.update(&s.buf[..got as usize]);
            s.at += got as u32;
        }
        6 => {
            if s.asset_addr == 0 || s.at >= s.asset_size {
                s.phase = 7;
                return;
            }
            let n = core::cmp::min(512, s.asset_size - s.at) as usize;
            let bytes = core::slice::from_raw_parts((s.asset_addr + s.at as usize) as *const u8, n);
            s.inplace.update(bytes);
            s.at += n as u32;
        }
        7 => {
            s.phase = 8;
            report_asset(s);
        }
        _ => {}
    }
}

/// Open the `blob` param's value as an asset and say what it is: a file
/// (left to the `fs` contract), a refusal, or a program to hash.
unsafe fn open_asset(s: &mut State) {
    let sys = &*s.syscalls;
    if s.blob_len == 0 {
        s.phase = 8;
        return;
    }
    let mut line = [0u8; 48];
    let mut n = 0;
    let (blob, len) = (s.blob, s.blob_len as usize);
    match asset::open(sys, &blob[..len]) {
        Ok(Asset::Fs(path)) => {
            put(&mut line, &mut n, b"[asset] fs len=");
            put_dec(&mut line, &mut n, path.len() as u32);
            dev_log(sys, 3, line.as_ptr(), n);
            s.phase = 8;
        }
        Err(rc) => {
            put(&mut line, &mut n, b"[asset] error=-");
            put_dec(&mut line, &mut n, rc.unsigned_abs());
            dev_log(sys, 3, line.as_ptr(), n);
            s.phase = 8;
        }
        Ok(found) => {
            // A program: `open` accepted the value, so it names a slot.
            let slot = asset::slot(&blob[..len]).unwrap_or(0);
            let (addr, size) = match found {
                Asset::InPlace(bytes) => (bytes.as_ptr() as usize, bytes.len() as u32),
                _ => (0, asset::size(sys, slot).unwrap_or(0)),
            };
            s.asset_slot = slot;
            s.asset_addr = addr;
            s.asset_size = size;
            s.through = Sha256::new();
            s.inplace = Sha256::new();
            s.at = 0;
            s.phase = 5;
        }
    }
}

/// `[asset] slot=<n> size=<n> addr=<hex8> inplace=<sha8|none> read=<sha8>`.
unsafe fn report_asset(s: &mut State) {
    let sys = &*s.syscalls;
    let mut line = [0u8; 120];
    let mut n = 0;
    let mut hx = [0u8; 8];
    put(&mut line, &mut n, b"[asset] slot=");
    put_dec(&mut line, &mut n, u32::from(s.asset_slot));
    put(&mut line, &mut n, b" size=");
    put_dec(&mut line, &mut n, s.asset_size);
    put(&mut line, &mut n, b" addr=");
    put_hex32(&mut line, &mut n, s.asset_addr as u32);
    put(&mut line, &mut n, b" inplace=");
    if s.asset_addr != 0 {
        hex8(&s.inplace.clone().finalize(), &mut hx);
        put(&mut line, &mut n, &hx);
    } else {
        put(&mut line, &mut n, b"none");
    }
    put(&mut line, &mut n, b" read=");
    hex8(&s.through.clone().finalize(), &mut hx);
    put(&mut line, &mut n, &hx);
    dev_log(sys, 3, line.as_ptr(), n);
}

unsafe fn report(s: &mut State, addr: u64, size: u32) {
    let sys = &*s.syscalls;
    let r = |o: usize| u32::from_le_bytes([s.info[o], s.info[o + 1], s.info[o + 2], s.info[o + 3]]);
    let kind = r(pg::info::KIND);
    let region_end = r(pg::info::REGION_END);
    let mut line = [0u8; 120];
    let mut n = 0;
    let mut hx = [0u8; 8];
    put(&mut line, &mut n, b"[prog] slot=0 size=");
    put_dec(&mut line, &mut n, size);
    put(&mut line, &mut n, b" kind=");
    put_hex32(&mut line, &mut n, kind);
    put(&mut line, &mut n, b" format=");
    let mut f = [0u8; 32];
    f.copy_from_slice(&s.info[pg::info::FORMAT..pg::info::FORMAT + 32]);
    hex8(&f, &mut hx);
    put(&mut line, &mut n, &hx);
    put(&mut line, &mut n, b" read=");
    hex8(&s.through.clone().finalize(), &mut hx);
    put(&mut line, &mut n, &hx);
    put(&mut line, &mut n, b" inplace=");
    if addr != 0 {
        hex8(&s.inplace.clone().finalize(), &mut hx);
        put(&mut line, &mut n, &hx);
    } else {
        put(&mut line, &mut n, b"none");
    }
    dev_log(sys, 3, line.as_ptr(), n);
    if s.poke != 0 && addr != 0 && region_end != 0 {
        // The first byte the module is not granted: the region's end on an
        // MPU (32-byte granular), the end of its last page under a page
        // table, whose tail past the programs is the owner's padding (the
        // region starts on a page).
        let end = addr as usize + region_end as usize;
        #[cfg(target_arch = "aarch64")]
        let end = (end + 4095) & !4095;
        let past = end as *const u8;
        let mut l2 = [0u8; 48];
        let mut m = 0;
        put(&mut l2, &mut m, b"[prog] poking past region at ");
        put_hex32(&mut l2, &mut m, past as usize as u32);
        dev_log(sys, 3, l2.as_ptr(), m);
        let v = core::ptr::read_volatile(past);
        m = 0;
        put(&mut l2, &mut m, b"[prog] poked ");
        put_dec(&mut l2, &mut m, u32::from(v));
        dev_log(sys, 3, l2.as_ptr(), m);
    }
}

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
    if syscalls.is_null() || state.is_null() || state_size < core::mem::size_of::<State>() {
        return -22;
    }
    core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
    let s = &mut *(state as *mut State);
    s.syscalls = syscalls as *const SyscallTable;
    core::ptr::write(&mut s.through, Sha256::new());
    core::ptr::write(&mut s.inplace, Sha256::new());
    params_def::set_defaults(s);
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut State);
    probe_step(s);
    StepReturn::Continue
}

fluxor_rt::wasm_entry!();
