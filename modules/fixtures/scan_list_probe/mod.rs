//! scan_list_probe — a module that runs a DMA scan list into a UART's
//! transmit FIFO and keeps it armed.
//!
//! The UART transmits at its baud whether or not anything is attached to
//! its pin, so its FIFO paces the list at a rate the module can state: the
//! entries the kernel reports sent, against that rate, are the evidence
//! that the list runs on the DMA's own clock, and the entries reported sent
//! as fill are the evidence of whether the module armed each one in time.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::platform::rp::dma_raw::{self, fd as dma_fd};
use abi::platform::rp::{raw_claim, uart_raw};
use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

/// Bytes an entry sends, spans in the ring the entries are armed from, and
/// the cookie of the ring's lend on the fd.
const SPAN: usize = 256;
const SLOTS: usize = 4;
const RING_LEND: u32 = 1;

/// PL011 registers the fixture writes, and the bits it sets.
const UARTIBRD: u8 = 0x24;
const UARTFBRD: u8 = 0x28;
const UARTLCR_H: u8 = 0x2C;
const UARTDMACR: u8 = 0x48;
/// 8 data bits, FIFOs enabled.
const LCR_8N1_FIFO: u32 = 0x70;
/// Transmit DMA requests enabled.
const DMACR_TXDMAE: u32 = 1 << 1;

/// How often it reports.
const REPORT_US: u64 = 1_000_000;

const STARTING: u8 = 0;
const RUNNING: u8 = 1;
const FAILED: u8 = 2;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    /// When the next report is due, and the clock at the last one.
    next_report_us: u64,
    last_report_us: u64,
    /// The UART's system clock in hertz and its baud.
    clock_hz: u32,
    baud: u32,
    /// The list's fd, or negative.
    fd: i32,
    /// The next band to arm, counted from the list's start: band `k` is
    /// entry `k % entries`, armed from span `k % SLOTS`.
    next_band: u32,
    /// Position and underruns at the last report.
    last_position: u32,
    last_underruns: u32,
    /// Arms made and arms refused as busy.
    armed: u32,
    busy: u32,
    entries: u16,
    /// The UART and the DREQ of its transmit FIFO.
    uart: u8,
    dreq: u8,
    phase: u8,
    /// The spans the entries send, lent to the kernel on the fd.
    ring: [u8; SPAN * SLOTS],
}

mod params_def {
    use super::State;
    use super::{p_u16, p_u32, p_u8};

    fluxor_rt::define_params! {
        State;
        1, uart, u8, 1
            => |s, d, len| { s.uart = p_u8(d, len, 0, 1); };
        2, dreq, u8, 30
            => |s, d, len| { s.dreq = p_u8(d, len, 0, 30); };
        3, entries, u16, 8
            => |s, d, len| { s.entries = p_u16(d, len, 0, 8); };
        4, baud, u32, 1000000
            => |s, d, len| { s.baud = p_u32(d, len, 0, 1_000_000); };
        5, clock_hz, u32, 150000000
            => |s, d, len| { s.clock_hz = p_u32(d, len, 0, 150_000_000); };
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
    s.fd = -1;
    params_def::set_defaults(s);
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    // Each span holds its own byte, so a capture of the pin tells the spans
    // from each other and from the fill.
    let mut i = 0;
    while i < s.ring.len() {
        s.ring[i] = b'A' + (i / SPAN) as u8;
        i += 1;
    }
    0
}

/// Write `value` to the claimed UART's register at `offset`.
unsafe fn uart_write(sys: &SyscallTable, claim: i32, offset: u8, value: u32) -> i32 {
    let v = value.to_le_bytes();
    let mut arg = [offset, v[0], v[1], v[2], v[3]];
    dev_call(sys, claim, uart_raw::REG_WRITE, arg.as_mut_ptr(), arg.len())
}

/// Claim the UART, set it transmitting, open the fd with the ring lent on
/// it, and start the list. `Err((errno, step))` names the step that failed.
unsafe fn start(s: &mut State, sys: &SyscallTable) -> Result<(), (i32, i64)> {
    let mut claim_arg = [raw_claim::family::UART, s.uart];
    let claim = dev_call(sys, -1, raw_claim::CLAIM, claim_arg.as_mut_ptr(), 2);
    if claim < 0 {
        return Err((claim, 1));
    }
    // The baud divisor in sixty-fourths: clock / (16 x baud).
    let divisor = (u64::from(s.clock_hz) * 4 / u64::from(s.baud.max(1))) as u32;
    let steps = [
        (UARTIBRD, divisor >> 6),
        (UARTFBRD, divisor & 0x3F),
        (UARTLCR_H, LCR_8N1_FIFO),
        (UARTDMACR, DMACR_TXDMAE),
    ];
    let mut i = 0;
    while i < steps.len() {
        let rc = uart_write(sys, claim, steps[i].0, steps[i].1);
        if rc < 0 {
            return Err((rc, 2));
        }
        i += 1;
    }
    let mut on = [1u8];
    let rc = dev_call(sys, claim, uart_raw::SET_ENABLE, on.as_mut_ptr(), 1);
    if rc < 0 {
        return Err((rc, 3));
    }

    const PLATFORM_DMA_FD: u32 = abi::registry::platform_dma_fd::ID as u32;
    let fd = (sys.provider_open)(PLATFORM_DMA_FD, dma_fd::CREATE, core::ptr::null(), 0);
    if fd < 0 {
        return Err((fd, 4));
    }
    s.fd = fd;
    let rc = dev_lend_open(
        sys,
        fd,
        LEND_IN,
        RING_LEND,
        s.ring.as_mut_ptr(),
        s.ring.len(),
    );
    if rc < 0 {
        return Err((rc, 5));
    }
    let mut arg = dma_raw::list_start::encode(
        RING_LEND,
        s.entries,
        s.dreq,
        dma_raw::flags::SIZE_BYTE,
        u32::from(b'.'),
        SPAN as u32,
    );
    let rc = dev_call(sys, fd, dma_fd::LIST_START, arg.as_mut_ptr(), arg.len());
    if rc < 0 {
        return Err((rc, 6));
    }
    Ok(())
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut State);
    let sys = &*s.syscalls;
    let mut line = [0u8; 96];
    let mut n = 0;
    put(&mut line, &mut n, b"[scan_list] ");

    if s.phase == FAILED {
        return StepReturn::Continue;
    }
    if s.phase == STARTING {
        match start(s, sys) {
            Ok(()) => {
                s.phase = RUNNING;
                s.next_band = 2;
                let now = dev_micros(sys);
                s.last_report_us = now;
                s.next_report_us = now + REPORT_US;
            }
            Err((rc, step)) => {
                s.phase = FAILED;
                put(&mut line, &mut n, b"start rc=");
                put_dec(&mut line, &mut n, i64::from(rc));
                put(&mut line, &mut n, b" at=");
                put_dec(&mut line, &mut n, step);
                dev_log(sys, 1, line.as_ptr(), n);
            }
        }
        return StepReturn::Continue;
    }

    let mut status = [0u8; dma_raw::list_status::LEN];
    if dev_call(
        sys,
        s.fd,
        dma_fd::LIST_STATUS,
        status.as_mut_ptr(),
        status.len(),
    ) < 0
    {
        return StepReturn::Continue;
    }
    let Some((position, underruns)) = dma_raw::list_status::decode(&status) else {
        return StepReturn::Continue;
    };

    // The entry being sent is band `position` and the next is already
    // loaded or about to be: the first band worth arming is two ahead. A
    // module that fell behind resumes there and does not chase the scan. A
    // span is free again once the band that last used it has been sent.
    if s.next_band.wrapping_sub(position) > SLOTS as u32 || s.next_band.wrapping_sub(position) < 2 {
        s.next_band = position.wrapping_add(2);
    }
    while s.next_band.wrapping_sub(position) < SLOTS as u32 {
        let entry = (s.next_band % u32::from(s.entries.max(1))) as u16;
        let offset = (s.next_band as usize % SLOTS * SPAN) as u32;
        let mut arg = dma_raw::list_arm::encode(entry, offset);
        let rc = dev_call(sys, s.fd, dma_fd::LIST_ARM, arg.as_mut_ptr(), arg.len());
        if rc == 0 {
            s.armed = s.armed.wrapping_add(1);
            s.next_band = s.next_band.wrapping_add(1);
        } else {
            s.busy = s.busy.wrapping_add(1);
            break;
        }
    }

    let now = dev_micros(sys);
    if now < s.next_report_us {
        return StepReturn::Continue;
    }
    let window_us = now.saturating_sub(s.last_report_us).max(1);
    let sent = position.wrapping_sub(s.last_position);
    let late = underruns.wrapping_sub(s.last_underruns);
    // Entries a second, in thousandths, against the rate the baud sets: ten
    // bit times a byte, `SPAN` bytes an entry.
    let milli_hz = u64::from(sent) * 1_000_000_000 / window_us;
    let want = u64::from(s.baud) * 100 / SPAN as u64;
    let ok = milli_hz.abs_diff(want) * 50 <= want;
    s.last_position = position;
    s.last_underruns = underruns;
    s.last_report_us = now;
    s.next_report_us = now + REPORT_US;

    put(&mut line, &mut n, b"pos=");
    put_dec(&mut line, &mut n, i64::from(position));
    put(&mut line, &mut n, b" late=");
    put_dec(&mut line, &mut n, i64::from(late));
    put(&mut line, &mut n, b" armed=");
    put_dec(&mut line, &mut n, i64::from(s.armed));
    put(&mut line, &mut n, b" busy=");
    put_dec(&mut line, &mut n, i64::from(s.busy));
    put(&mut line, &mut n, b" hz=");
    put_dec(&mut line, &mut n, (milli_hz / 1000) as i64);
    put(&mut line, &mut n, b" want=");
    put_dec(&mut line, &mut n, (want / 1000) as i64);
    put(&mut line, &mut n, b" ok=");
    put_dec(&mut line, &mut n, i64::from(ok));
    dev_log(sys, 3, line.as_ptr(), n);
    StepReturn::Continue
}

fluxor_rt::wasm_entry!();
