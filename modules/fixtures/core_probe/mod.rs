//! core_probe — a module whose stepping is the evidence.
//!
//! Placed in a domain, it shows that domain's loop kept running: `count`
//! reports its steps and the longest it waited between two of them, and
//! `flash` programs one page of a flash sector on a period, erasing the
//! sector as it starts and each time it fills, and reports every answer.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

const MODE_COUNT: u8 = 0;
const MODE_FLASH: u8 = 1;

/// A flash page and the pages of one erase sector.
const PAGE: usize = 256;
const SECTOR_PAGES: u16 = 16;

/// How often `count` reports.
const REPORT_US: u64 = 1_000_000;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    /// When the last step ran, microseconds; 0 before the first.
    last_step_us: u64,
    /// When the next report or store is due, microseconds.
    next_due_us: u64,
    /// Steps taken.
    steps: u32,
    /// The longest wait between two steps since the last report.
    gap_us: u32,
    /// `flash`: the period between page programs, milliseconds.
    period_ms: u32,
    /// `flash`: the offset in flash of the sector written.
    sector: u32,
    /// `flash`: page programs to make.
    count: u16,
    /// `flash`: programs made, and how many flash ops were refused.
    done: u16,
    failed: u16,
    mode: u8,
    /// One letter naming this instance in its lines.
    tag: u8,
    /// `count`: ask to be stepped again at once, as a module with work
    /// always pending does.
    busy: u8,
    finished: u8,
}

mod params_def {
    use super::State;
    use super::{p_u16, p_u32, p_u8};

    fluxor_rt::define_params! {
        State;
        1, mode, u8, 0, enum { count=0, flash=1 }
            => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };
        2, period_ms, u32, 500
            => |s, d, len| { s.period_ms = p_u32(d, len, 0, 500); };
        3, count, u16, 60
            => |s, d, len| { s.count = p_u16(d, len, 0, 60); };
        4, tag, u8, 97
            => |s, d, len| { s.tag = p_u8(d, len, 0, 97); };
        5, busy, u8, 0
            => |s, d, len| { s.busy = p_u8(d, len, 0, 0); };
        6, sector, u32, 0
            => |s, d, len| { s.sector = p_u32(d, len, 0, 0); };
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

fn put_dec(line: &mut [u8], n: &mut usize, v: i64) {
    if v < 0 {
        put(line, n, b"-");
    }
    let mut x = v.unsigned_abs();
    let mut d = [0u8; 20];
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

/// `[core_probe] <tag> `, the head of every line.
fn head(s: &State, line: &mut [u8], n: &mut usize) {
    put(line, n, b"[core_probe] ");
    put(line, n, &[s.tag]);
    put(line, n, b" ");
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
    s.steps = s.steps.wrapping_add(1);
    if s.finished != 0 {
        return StepReturn::Continue;
    }
    let sys = &*s.syscalls;
    let now = dev_micros(sys);
    if s.last_step_us != 0 {
        let gap = now.saturating_sub(s.last_step_us).min(u64::from(u32::MAX)) as u32;
        if gap > s.gap_us {
            s.gap_us = gap;
        }
    }
    s.last_step_us = now;
    // A busy counter keeps its domain's loop spinning.
    let again = if s.mode == MODE_COUNT && s.busy != 0 {
        StepReturn::Burst
    } else {
        StepReturn::Continue
    };
    if s.next_due_us == 0 {
        s.next_due_us = now
            + if s.mode == MODE_FLASH {
                u64::from(s.period_ms) * 1000
            } else {
                REPORT_US
            };
        return again;
    }
    if now < s.next_due_us {
        return again;
    }

    let mut line = [0u8; 72];
    let mut n = 0;
    head(s, &mut line, &mut n);
    if s.mode == MODE_COUNT {
        s.next_due_us = now + REPORT_US;
        put(&mut line, &mut n, b"steps=");
        put_dec(&mut line, &mut n, i64::from(s.steps));
        put(&mut line, &mut n, b" gap_us=");
        put_dec(&mut line, &mut n, i64::from(s.gap_us));
        s.gap_us = 0;
        dev_log(sys, 3, line.as_ptr(), n);
        return again;
    }

    // `flash`: the sector is erased before its first page and again each
    // time every page of it has been programmed, then the next page is
    // programmed with this write's number.
    s.next_due_us = now + u64::from(s.period_ms) * 1000;
    if s.done >= s.count {
        return finish_flash(s, sys);
    }
    let page = s.done % SECTOR_PAGES;
    let mut erase_rc = 0;
    if page == 0 {
        erase_rc = erase(sys, s.sector);
    }
    s.done += 1;
    let program_rc = program(sys, s.sector + u32::from(page) * PAGE as u32, s.done);
    if erase_rc < 0 || program_rc < 0 {
        s.failed += 1;
    }
    put(&mut line, &mut n, b"flash n=");
    put_dec(&mut line, &mut n, i64::from(s.done));
    put(&mut line, &mut n, b" erase=");
    put_dec(&mut line, &mut n, i64::from(erase_rc));
    put(&mut line, &mut n, b" program=");
    put_dec(&mut line, &mut n, i64::from(program_rc));
    dev_log(sys, 3, line.as_ptr(), n);
    StepReturn::Continue
}

/// `flash`, once every page is programmed: leave the sector as an erased
/// one and report the total. A step of its own, a period after the last
/// program: each flash op empties the XIP cache, and what a step runs after
/// one is fetched from flash again on the step's own time.
unsafe fn finish_flash(s: &mut State, sys: &SyscallTable) -> StepReturn {
    s.finished = 1;
    let last = erase(sys, s.sector);
    if last < 0 {
        s.failed += 1;
    }
    let mut line = [0u8; 72];
    let mut n = 0;
    head(s, &mut line, &mut n);
    put(&mut line, &mut n, b"flashes ok=");
    put_dec(&mut line, &mut n, i64::from(s.done - s.failed.min(s.done)));
    put(&mut line, &mut n, b" failed=");
    put_dec(&mut line, &mut n, i64::from(s.failed));
    dev_log(sys, 3, line.as_ptr(), n);
    StepReturn::Continue
}

/// Erase the flash sector at `offset`.
unsafe fn erase(sys: &SyscallTable, offset: u32) -> i32 {
    let mut arg = offset.to_le_bytes();
    (sys.provider_call)(
        -1,
        abi::registry::flash::RAW_ERASE,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    )
}

/// Program the page at `offset` with `value` repeated.
unsafe fn program(sys: &SyscallTable, offset: u32, value: u16) -> i32 {
    let mut arg = [0u8; 4 + PAGE];
    let (head, body) = arg.split_at_mut(4);
    head.copy_from_slice(&offset.to_le_bytes());
    let v = value.to_le_bytes();
    let mut i = 0;
    while i < body.len() {
        body[i] = v[i & 1];
        i += 1;
    }
    (sys.provider_call)(
        -1,
        abi::registry::flash::RAW_PROGRAM,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    )
}

fluxor_rt::wasm_entry!();
