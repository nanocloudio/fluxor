//! counter_probe — a module that measures a loop of its own with the
//! `counters` contract.
//!
//! The loop is fixed: on Arm, one subtract and one taken branch a turn, so
//! the cycles a turn costs are the core's and a scenario states them. The
//! probe warms the loop once, reads the counters, runs it `iterations`
//! times, reads them again, and reports what ran between the two readings
//! less the cost of a reading, which it measured first the way it pays it.
//! Each report is also a `MeasurementStream` record on its output.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::contracts::measurement;
use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

/// The samples of one record's block: cycles, cache hits, cache accesses.
const CHANNELS: usize = 3;
/// One record: the header and the block.
const RECORD: usize = measurement::HEADER_SIZE + CHANNELS * 4;

/// Waiting for `delay` to pass.
const PHASE_WAIT: u8 = 0;
/// Describing the counters and measuring a read.
const PHASE_DESCRIBE: u8 = 1;
/// Measuring every period.
const PHASE_MEASURE: u8 = 2;
/// A call was refused; nothing more to do.
const PHASE_REFUSED: u8 = 3;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    /// When the next phase is due, microseconds; 0 before the first step.
    next_due_us: u64,
    out_chan: i32,
    /// Runs of the loop between the two readings, and turns in a run.
    iterations: u32,
    turns: u32,
    /// Hundredths of a cycle a turn costs on this core; 0 when the graph
    /// states none.
    cycles_per_turn_x100: u32,
    period_ms: u32,
    delay_ms: u32,
    /// Cycles one read costs this module.
    read_cost: u32,
    /// Reports made.
    reports: u32,
    /// Records the output had no room for.
    dropped: u32,
    phase: u8,
}

mod params_def {
    use super::p_u32;
    use super::State;

    fluxor_rt::define_params! {
        State;
        1, iterations, u32, 1000
            => |s, d, len| { s.iterations = p_u32(d, len, 0, 1000); };
        2, turns, u32, 32
            => |s, d, len| { s.turns = p_u32(d, len, 0, 32); };
        3, cycles_per_turn_x100, u32, 0
            => |s, d, len| { s.cycles_per_turn_x100 = p_u32(d, len, 0, 0); };
        4, period_ms, u32, 1000
            => |s, d, len| { s.period_ms = p_u32(d, len, 0, 1000); };
        5, delay, u32, 2000
            => |s, d, len| { s.delay_ms = p_u32(d, len, 0, 2000); };
    }
}

/// The fixed loop: `turns` turns, at least one.
#[inline(never)]
fn spin(turns: u32) {
    let turns = turns.max(1);
    #[cfg(target_arch = "arm")]
    // SAFETY: a countdown in one register; no memory, no stack.
    unsafe {
        core::arch::asm!(
            "2:",
            "subs {n}, #1",
            "bne 2b",
            n = inout(reg) turns => _,
            options(nomem, nostack),
        );
    }
    #[cfg(not(target_arch = "arm"))]
    {
        let mut left = turns;
        while left != 0 {
            left = core::hint::black_box(left) - 1;
        }
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

/// `[counter_probe] <key>=<value> ...`, logged.
unsafe fn report(sys: &SyscallTable, fields: &[(&[u8], u32)]) {
    let mut line = [0u8; 160];
    let mut n = 0;
    put(&mut line, &mut n, b"[counter_probe]");
    let mut i = 0;
    while i < fields.len() {
        put(&mut line, &mut n, b" ");
        put(&mut line, &mut n, fields[i].0);
        put(&mut line, &mut n, b"=");
        put_dec(&mut line, &mut n, fields[i].1);
        i += 1;
    }
    dev_log(sys, 3, line.as_ptr(), n);
}

unsafe fn refused(s: &mut State, sys: &SyscallTable) -> StepReturn {
    let line = b"[counter_probe] refused";
    dev_log(sys, 2, line.as_ptr(), line.len());
    s.phase = PHASE_REFUSED;
    StepReturn::Continue
}

/// What the target's counters are, and what one read costs.
unsafe fn describe(s: &mut State, sys: &SyscallTable) -> StepReturn {
    let Some(d) = counters::describe(sys) else {
        return refused(s, sys);
    };
    s.read_cost = counters::calibrate(sys).unwrap_or(0);
    let mut line = [0u8; 128];
    let mut n = 0;
    put(&mut line, &mut n, b"[counter_probe] present=");
    put_dec(&mut line, &mut n, u32::from(d.present));
    put(&mut line, &mut n, b" clock=");
    put(
        &mut line,
        &mut n,
        if d.cycles_clock == counters::CLOCK_CORE {
            b"core"
        } else {
            b"system"
        },
    );
    put(&mut line, &mut n, b" scope=");
    put(
        &mut line,
        &mut n,
        if d.icache_scope == counters::SCOPE_CORE {
            b"core"
        } else if d.icache_scope == counters::SCOPE_NODE {
            b"node"
        } else {
            b"none"
        },
    );
    put(&mut line, &mut n, b" hz=");
    put_dec(&mut line, &mut n, d.cycles_hz);
    put(&mut line, &mut n, b" cost=");
    put_dec(&mut line, &mut n, s.read_cost);
    dev_log(sys, 3, line.as_ptr(), n);
    s.phase = PHASE_MEASURE;
    StepReturn::Continue
}

/// One measurement: the warm-up, the region between two readings, the
/// report and the record.
unsafe fn measure(s: &mut State, sys: &SyscallTable, now: u64) -> StepReturn {
    spin(s.turns);
    let Some(before) = counters::read(sys) else {
        return refused(s, sys);
    };
    let total = s.iterations.max(1).saturating_mul(s.turns.max(1));
    spin(total);
    let Some(after) = counters::read(sys) else {
        return refused(s, sys);
    };
    let e = counters::elapsed(&before, &after);
    let cycles = e.cycles.saturating_sub(s.read_cost);
    let want = (u64::from(s.cycles_per_turn_x100) * u64::from(total) / 100).min(u64::from(u32::MAX))
        as u32;
    let ok = if want == 0 {
        cycles != 0
    } else {
        // Within 5 % of the cycles the turns should cost.
        u64::from(cycles.abs_diff(want)) * 20 <= u64::from(want)
    };
    let permille = if e.icache_access == 0 {
        0
    } else {
        (u64::from(e.icache_hit) * 1000 / u64::from(e.icache_access)) as u32
    };
    s.reports = s.reports.wrapping_add(1);
    report(
        sys,
        &[
            (b"n", s.reports),
            (b"turns", total),
            (b"cycles", cycles),
            (b"hit", e.icache_hit),
            (b"access", e.icache_access),
            (b"permille", permille),
            (b"want", want),
            (b"ok", u32::from(ok)),
        ],
    );

    if s.out_chan >= 0 {
        let mut record = [0u8; RECORD];
        let block = [cycles, e.icache_hit, e.icache_access];
        if measurement::encode_header(&mut record, s.reports, now, (CHANNELS * 4) as u32).is_some()
        {
            let mut i = 0;
            while i < CHANNELS {
                let at = measurement::OFF_BLOCK + i * 4;
                record[at..at + 4].copy_from_slice(&block[i].to_le_bytes());
                i += 1;
            }
            if (sys.channel_write)(s.out_chan, record.as_ptr(), RECORD) != RECORD as i32 {
                s.dropped = s.dropped.wrapping_add(1);
            }
        }
    }
    StepReturn::Continue
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
    out_chan: i32,
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
    s.out_chan = out_chan;
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
    if s.phase == PHASE_REFUSED {
        return StepReturn::Continue;
    }
    let sys = &*s.syscalls;
    let now = dev_micros(sys);
    if s.next_due_us == 0 {
        s.next_due_us = now + u64::from(s.delay_ms) * 1000;
        return StepReturn::Continue;
    }
    if now < s.next_due_us {
        return StepReturn::Continue;
    }
    match s.phase {
        PHASE_WAIT => {
            s.phase = PHASE_DESCRIBE;
            StepReturn::Continue
        }
        PHASE_DESCRIBE => describe(s, sys),
        _ => {
            s.next_due_us = now + u64::from(s.period_ms) * 1000;
            measure(s, sys, now)
        }
    }
}

fluxor_rt::wasm_entry!();
