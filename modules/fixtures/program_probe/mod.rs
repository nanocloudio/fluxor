//! program_probe — reads the program the bundle carries for it.
//!
//! A buffer of work a step: `PROGRAM_INFO` for slot 0, the whole program
//! through `PROGRAM_READ` hashed, and the same bytes read in place when the
//! kernel answers an address, hashed again. The two digests must agree with
//! each other and with the file the graph named. With `poke: 1` it then
//! reads the first byte past what it is granted of its program region,
//! which an isolated module must not be able to do.

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
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::kernel_abi::{program as pg, PROGRAM_INFO, PROGRAM_READ};
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
include!("../../sdk/crypto/sha256.rs");

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    poke: u8,
    /// Steps to wait before starting: a board whose log reaches the bench
    /// over the network says nothing before its address is bound.
    delay: u32,
    /// 0 = ask for the program, 1 = reading through the kernel, 2 = reading
    /// in place, 3 = report, 4 = done.
    phase: u8,
    info: [u8; pg::INFO_LEN],
    at: u32,
    through: Sha256,
    inplace: Sha256,
    buf: [u8; 512],
}

mod params_def {
    use super::*;
    define_params! {
        State;
        1, poke, u8, 0 => |s, d, len| { s.poke = p_u8(d, len, 0, 0); };
        2, delay, u32, 0 => |s, d, len| { s.delay = p_u32(d, len, 0, 0); };
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
    let addr = u64::from_le_bytes([
        s.info[0], s.info[1], s.info[2], s.info[3], s.info[4], s.info[5], s.info[6], s.info[7],
    ]);
    let size = r(&s.info, 8);
    match s.phase {
        0 if s.delay > 0 => s.delay -= 1,
        0 => {
            s.info[0] = 0;
            let rc = (sys.provider_call)(-1, PROGRAM_INFO, s.info.as_mut_ptr(), s.info.len());
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
            s.buf[0..4].fill(0);
            s.buf[4..8].copy_from_slice(&s.at.to_le_bytes());
            let got = (sys.provider_call)(-1, PROGRAM_READ, s.buf.as_mut_ptr(), s.buf.len());
            if got <= 0 {
                s.at = size;
                return;
            }
            s.through.update(&s.buf[..got as usize]);
            s.at += got as u32;
        }
        2 => {
            // In place: flash on a board, the mapped bundle on a host.
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
        _ => {}
    }
}

unsafe fn report(s: &mut State, addr: u64, size: u32) {
    let sys = &*s.syscalls;
    let r = |o: usize| u32::from_le_bytes([s.info[o], s.info[o + 1], s.info[o + 2], s.info[o + 3]]);
    let kind = r(12);
    let region = u64::from_le_bytes([
        s.info[16], s.info[17], s.info[18], s.info[19], s.info[20], s.info[21], s.info[22],
        s.info[23],
    ]);
    let region_len = r(24);
    let mut line = [0u8; 120];
    let mut n = 0;
    let mut hx = [0u8; 8];
    put(&mut line, &mut n, b"[prog] slot=0 size=");
    put_dec(&mut line, &mut n, size);
    put(&mut line, &mut n, b" kind=");
    put_hex32(&mut line, &mut n, kind);
    put(&mut line, &mut n, b" format=");
    let mut f = [0u8; 32];
    f.copy_from_slice(&s.info[32..64]);
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
    if s.poke != 0 && region != 0 {
        // The first byte the module is not granted: the region's end on an
        // MPU (32-byte granular), the end of its last page under a page
        // table, whose tail past the programs is the owner's padding.
        #[cfg(target_arch = "aarch64")]
        let end = (region_len as usize + 4095) & !4095;
        #[cfg(not(target_arch = "aarch64"))]
        let end = region_len as usize;
        let past = (region as usize + end) as *const u8;
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

declare_module_state_bytes!(State);

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_state_size")]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

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
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut State);
    probe_step(s);
    0
}

include!("../../sdk/runtime/wasm_entry.rs");
