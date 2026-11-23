//! sample_log — reads `MeasurementStream` records of 32-bit samples and logs
//! each one decoded, so a scenario reads what a producer published off the
//! console.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::contracts::measurement;
use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

/// Samples of a block this logs.
const SAMPLES_MAX: usize = 8;
/// The longest record it reads.
const RECORD_MAX: usize = measurement::HEADER_SIZE + SAMPLES_MAX * 4;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    in_chan: i32,
}

fn put(line: &mut [u8], n: &mut usize, b: &[u8]) {
    let mut i = 0;
    while i < b.len() && *n < line.len() {
        line[*n] = b[i];
        *n += 1;
        i += 1;
    }
}

fn put_dec(line: &mut [u8], n: &mut usize, v: u32) {
    let mut x = v;
    let mut d = [0u8; 10];
    let mut k = 0;
    loop {
        d[k] = b'0' + (x % 10) as u8;
        k += 1;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        put(line, n, &[d[k]]);
    }
}

fluxor_rt::module_facts! { state: State }

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes and `syscalls` the kernel's syscall table.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() || state.is_null() || state_size < core::mem::size_of::<State>() {
        return -22;
    }
    let s = &mut *(state as *mut State);
    s.syscalls = syscalls as *const SyscallTable;
    s.in_chan = in_chan;
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut State);
    let sys = &*s.syscalls;
    let mut record = [0u8; RECORD_MAX];
    let got = (sys.channel_read)(s.in_chan, record.as_mut_ptr(), RECORD_MAX);
    if got <= 0 {
        return StepReturn::Continue;
    }
    let mut line = [0u8; 160];
    let mut n = 0;
    match measurement::decode(&record[..got as usize]) {
        Some((header, block)) if block.len() % 4 == 0 => {
            put(&mut line, &mut n, b"[sample_log] seq=");
            put_dec(&mut line, &mut n, header.seq);
            put(&mut line, &mut n, b" t_us=");
            put_dec(&mut line, &mut n, header.t_micros as u32);
            put(&mut line, &mut n, b" v=");
            let mut i = 0;
            while i + 4 <= block.len() {
                if i != 0 {
                    put(&mut line, &mut n, b",");
                }
                let v = u32::from_le_bytes([block[i], block[i + 1], block[i + 2], block[i + 3]]);
                put_dec(&mut line, &mut n, v);
                i += 4;
            }
        }
        _ => {
            put(&mut line, &mut n, b"[sample_log] bad len=");
            put_dec(&mut line, &mut n, got as u32);
        }
    }
    dev_log(sys, 3, line.as_ptr(), n);
    StepReturn::Burst
}

fluxor_rt::wasm_entry!();
