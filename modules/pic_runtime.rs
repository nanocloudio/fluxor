// Shared PIC module runtime support.
//
// Provides compiler runtime intrinsics and helper functions required by all
// PIC modules. Each module includes this via `include!("pic_runtime.rs")`.
//
// Compiler Intrinsics: ARM EABI memclr/memcpy for struct init/assignment.
// Param Helpers: Safe(r) little-endian reads from a raw params pointer.

// ============================================================================
// Compiler Runtime Intrinsics
// ============================================================================

// Use write_volatile in all memset/memclr implementations to prevent LLVM's
// loop idiom recognition from converting the loop into a call to memset/memclr,
// which would create infinite recursion (the function calling itself).

#[no_mangle]
pub unsafe extern "C" fn __aeabi_memclr(dest: *mut u8, n: usize) {
    let mut i = 0;
    while i < n {
        core::ptr::write_volatile(dest.add(i), 0);
        i += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn __aeabi_memclr4(dest: *mut u8, n: usize) {
    __aeabi_memclr(dest, n);
}

#[no_mangle]
pub unsafe extern "C" fn __aeabi_memclr8(dest: *mut u8, n: usize) {
    __aeabi_memclr(dest, n);
}

#[no_mangle]
#[link_section = ".text.aeabi_memset"]
pub unsafe extern "C" fn __aeabi_memset(dest: *mut u8, n: usize, val: i32) {
    let byte = val as u8;
    let mut i = 0;
    while i < n {
        core::ptr::write_volatile(dest.add(i), byte);
        i += 1;
    }
}

#[no_mangle]
#[link_section = ".text.aeabi_memset4"]
pub unsafe extern "C" fn __aeabi_memset4(dest: *mut u8, n: usize, val: i32) {
    __aeabi_memset(dest, n, val);
}

#[no_mangle]
#[link_section = ".text.aeabi_memset8"]
pub unsafe extern "C" fn __aeabi_memset8(dest: *mut u8, n: usize, val: i32) {
    __aeabi_memset(dest, n, val);
}

// Force retention of memset symbols that LTO might otherwise eliminate
#[used]
static _KEEP_MEMSET: [unsafe extern "C" fn(*mut u8, usize, i32); 3] = [
    __aeabi_memset,
    __aeabi_memset4,
    __aeabi_memset8,
];

// Use read_volatile/write_volatile in memcpy/memmove too — while LLVM
// currently doesn't self-recurse these, future compiler versions might.

#[no_mangle]
pub unsafe extern "C" fn __aeabi_memcpy(dest: *mut u8, src: *const u8, n: usize) {
    let mut i = 0;
    while i < n {
        core::ptr::write_volatile(dest.add(i), core::ptr::read_volatile(src.add(i)));
        i += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn __aeabi_memcpy4(dest: *mut u8, src: *const u8, n: usize) {
    __aeabi_memcpy(dest, src, n);
}

#[no_mangle]
pub unsafe extern "C" fn __aeabi_memcpy8(dest: *mut u8, src: *const u8, n: usize) {
    __aeabi_memcpy(dest, src, n);
}

#[no_mangle]
#[link_section = ".text.aeabi_memmove"]
pub unsafe extern "C" fn __aeabi_memmove(dest: *mut u8, src: *const u8, n: usize) {
    if (dest as usize) < (src as usize) {
        let mut i = 0;
        while i < n {
            core::ptr::write_volatile(dest.add(i), core::ptr::read_volatile(src.add(i)));
            i += 1;
        }
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            core::ptr::write_volatile(dest.add(i), core::ptr::read_volatile(src.add(i)));
        }
    }
}

#[no_mangle]
#[link_section = ".text.aeabi_memmove4"]
pub unsafe extern "C" fn __aeabi_memmove4(dest: *mut u8, src: *const u8, n: usize) {
    __aeabi_memmove(dest, src, n);
}

#[no_mangle]
#[link_section = ".text.aeabi_memmove8"]
pub unsafe extern "C" fn __aeabi_memmove8(dest: *mut u8, src: *const u8, n: usize) {
    __aeabi_memmove(dest, src, n);
}

#[used]
static _KEEP_MEMMOVE: [unsafe extern "C" fn(*mut u8, *const u8, usize); 3] = [
    __aeabi_memmove,
    __aeabi_memmove4,
    __aeabi_memmove8,
];

// ============================================================================
// Standard C memory functions (required on aarch64 — no __aeabi_* there)
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut u8, val: i32, n: usize) -> *mut u8 {
    __aeabi_memset(dest, n, val);
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    __aeabi_memcpy(dest, src, n);
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    __aeabi_memmove(dest, src, n);
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let va = core::ptr::read_volatile(a.add(i));
        let vb = core::ptr::read_volatile(b.add(i));
        if va != vb {
            return (va as i32) - (vb as i32);
        }
        i += 1;
    }
    0
}

// ============================================================================
// Integer Division (ARM EABI — required on Cortex-M0+ / RP2040)
// ============================================================================
//
// Cortex-M33 (RP2350) emits UDIV/SDIV instructions for variable-divisor
// divisions and never calls these. Cortex-M0+ (RP2040) has no hardware
// divide, so any non-constant divisor generates an ARM EABI library call.
// PIC modules link against no standard library, so we must provide them.
//
// Pure bit-shift long-division: no further intrinsic calls, no recursion.

/// Unsigned 32-bit division: returns n / d. Returns 0 if d == 0.
#[no_mangle]
pub unsafe extern "C" fn __aeabi_uidiv(n: u32, d: u32) -> u32 {
    if d == 0 { return 0; }
    let mut quotient = 0u32;
    let mut remainder = 0u32;
    let mut i = 32u32;
    while i > 0 {
        i -= 1;
        remainder = (remainder << 1) | ((n >> i) & 1);
        if remainder >= d {
            remainder -= d;
            quotient |= 1u32 << i;
        }
    }
    quotient
}

/// Unsigned division-and-remainder: quotient in low 32 bits (r0), remainder in high 32 bits (r1).
#[no_mangle]
pub unsafe extern "C" fn __aeabi_uidivmod(n: u32, d: u32) -> u64 {
    let q = __aeabi_uidiv(n, d);
    let r = n.wrapping_sub(q.wrapping_mul(d));
    (q as u64) | ((r as u64) << 32)
}

/// Signed 32-bit division: returns n / d (truncates toward zero). Returns 0 if d == 0.
#[no_mangle]
pub unsafe extern "C" fn __aeabi_idiv(n: i32, d: i32) -> i32 {
    if d == 0 { return 0; }
    let neg = (n < 0) != (d < 0);
    let un = if n < 0 { (n as u32).wrapping_neg() } else { n as u32 };
    let ud = if d < 0 { (d as u32).wrapping_neg() } else { d as u32 };
    let q = __aeabi_uidiv(un, ud);
    if neg { (q as i32).wrapping_neg() } else { q as i32 }
}

/// Signed division-and-remainder: quotient in low 32 bits (r0), remainder in high 32 bits (r1).
#[no_mangle]
pub unsafe extern "C" fn __aeabi_idivmod(n: i32, d: i32) -> u64 {
    let q = __aeabi_idiv(n, d);
    let r = n.wrapping_sub(q.wrapping_mul(d));
    (q as u32 as u64) | ((r as u32 as u64) << 32)
}

// ============================================================================
// 64-bit Integer Operations (ARM EABI — required on Cortex-M0+ / RP2040)
// ============================================================================
//
// Cortex-M33 (RP2350) emits UMULL/SDIV/shift instructions natively; these
// are never called there. Cortex-M0+ (RP2040) has no 64-bit multiply or
// large-shift hardware, so variable-operand 64-bit ops become library calls.
//
// Functions use pairs of u32 parameters (matching ARM EABI r0:r1 convention)
// so that the bodies contain only 32-bit arithmetic — avoiding any recursion.

/// Helper: 32×32 → 64-bit unsigned multiply using 16-bit halves.
/// Returns (lo32, hi32). All inner multiplications are 32-bit (MULS).
#[inline(always)]
fn umull32(a: u32, b: u32) -> (u32, u32) {
    let a_lo = a & 0xFFFF;
    let a_hi = a >> 16;
    let b_lo = b & 0xFFFF;
    let b_hi = b >> 16;

    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;

    let mid = lh.wrapping_add(hl);
    let mid_carry = if mid < lh { 1u32 } else { 0u32 };

    let mid_lo = mid << 16;
    let result_lo = ll.wrapping_add(mid_lo);
    let carry_lo = if result_lo < ll { 1u32 } else { 0u32 };

    let result_hi = hh
        .wrapping_add(mid >> 16)
        .wrapping_add(mid_carry << 16)
        .wrapping_add(carry_lo);

    (result_lo, result_hi)
}

/// 64-bit multiply (low 64 bits of the 128-bit product).
/// ARM EABI: r0=a_lo, r1=a_hi, r2=b_lo, r3=b_hi → r0:r1 = result.
#[no_mangle]
pub unsafe extern "C" fn __aeabi_lmul(a_lo: u32, a_hi: u32, b_lo: u32, b_hi: u32) -> u64 {
    let (ll, lh) = umull32(a_lo, b_lo);
    // Cross terms only affect the high 32 bits of the 64-bit result
    let cross = a_lo.wrapping_mul(b_hi).wrapping_add(a_hi.wrapping_mul(b_lo));
    let result_hi = lh.wrapping_add(cross);
    (ll as u64) | ((result_hi as u64) << 32)
}

/// 64-bit logical left shift.
/// ARM EABI: r0=v_lo, r1=v_hi, r2=shift → r0:r1 = v << shift.
#[no_mangle]
pub unsafe extern "C" fn __aeabi_llsl(v_lo: u32, v_hi: u32, shift: u32) -> u64 {
    if shift >= 64 { return 0; }
    if shift == 0 { return (v_lo as u64) | ((v_hi as u64) << 32); }
    if shift >= 32 {
        let hi = v_lo << (shift - 32);
        return (hi as u64) << 32;
    }
    let hi = (v_hi << shift) | (v_lo >> (32 - shift));
    let lo = v_lo << shift;
    (lo as u64) | ((hi as u64) << 32)
}

/// 64-bit arithmetic right shift (sign-extending).
/// ARM EABI: r0=v_lo, r1=v_hi, r2=shift → r0:r1 = v >> shift (signed).
#[no_mangle]
pub unsafe extern "C" fn __aeabi_lasr(v_lo: u32, v_hi: u32, shift: u32) -> u64 {
    let sign_fill = ((v_hi as i32) >> 31) as u32; // 0x00000000 or 0xFFFFFFFF
    if shift >= 64 {
        return (sign_fill as u64) | ((sign_fill as u64) << 32);
    }
    if shift == 0 { return (v_lo as u64) | ((v_hi as u64) << 32); }
    if shift >= 32 {
        let lo = ((v_hi as i32) >> (shift - 32)) as u32;
        return (lo as u64) | ((sign_fill as u64) << 32);
    }
    let lo = (v_lo >> shift) | (v_hi << (32 - shift));
    let hi = ((v_hi as i32) >> shift) as u32;
    (lo as u64) | ((hi as u64) << 32)
}

/// 64-bit logical right shift (zero-extending).
/// ARM EABI: r0=v_lo, r1=v_hi, r2=shift → r0:r1 = v >> shift (unsigned).
#[no_mangle]
pub unsafe extern "C" fn __aeabi_llsr(v_lo: u32, v_hi: u32, shift: u32) -> u64 {
    if shift >= 64 { return 0; }
    if shift == 0 { return (v_lo as u64) | ((v_hi as u64) << 32); }
    if shift >= 32 {
        let lo = v_hi >> (shift - 32);
        return lo as u64;
    }
    let lo = (v_lo >> shift) | (v_hi << (32 - shift));
    let hi = v_hi >> shift;
    (lo as u64) | ((hi as u64) << 32)
}

// ============================================================================
// Channel Poll Constants
// ============================================================================

pub const POLL_IN: u8 = 0x01;
pub const POLL_OUT: u8 = 0x02;
pub const POLL_ERR: u8 = 0x04;
pub const POLL_HUP: u8 = 0x08;
pub const POLL_CONN: u8 = 0x10;

// ============================================================================
// Common Error Codes (from kernel errno)
// ============================================================================

pub const E_AGAIN: i32 = -11;
pub const E_BUSY: i32 = -16;
pub const E_INVAL: i32 = -22;
pub const E_INPROGRESS: i32 = -36;
pub const E_CONNREFUSED: i32 = -111;

// ============================================================================
// Socket Types
// ============================================================================

pub const SOCK_TYPE_STREAM: u8 = 1;
pub const SOCK_TYPE_DGRAM: u8 = 2;

// ============================================================================
// Network Interface State (set via dev_netif_set_state)
// ============================================================================

pub const NETIF_STATE_DOWN: u8 = 0;
pub const NETIF_STATE_NO_LINK: u8 = 2;
pub const NETIF_STATE_NO_ADDRESS: u8 = 4;
pub const NETIF_STATE_READY: u8 = 5;
pub const NETIF_STATE_ERROR: u8 = 255;
pub const NETIF_TYPE_WIFI: u8 = 1;

// ============================================================================
// Channel Ioctl Commands
// ============================================================================

pub const IOCTL_NOTIFY: u32 = 1;
pub const IOCTL_POLL_NOTIFY: u32 = 2;
pub const IOCTL_FLUSH: u32 = 3;
pub const IOCTL_EOF: u32 = 4;

// ============================================================================
// FMP Well-Known Message Types (pre-computed FNV-1a hashes)
// ============================================================================

// WiFi lifecycle
pub const MSG_RADIO_READY: u32 = fnv1a(b"radio_ready");
pub const MSG_CONNECTED: u32 = fnv1a(b"connected");
pub const MSG_DISCONNECTED: u32 = fnv1a(b"disconnected");
pub const MSG_CONNECT: u32 = fnv1a(b"connect");
pub const MSG_DISCONNECT: u32 = fnv1a(b"disconnect");
pub const MSG_SCAN: u32 = fnv1a(b"scan");
pub const MSG_SCAN_DONE: u32 = fnv1a(b"scan_done");
pub const MSG_SCAN_RESULT: u32 = fnv1a(b"scan_result");

// UI / control
pub const MSG_CLICK: u32 = fnv1a(b"click");
pub const MSG_LONG_PRESS: u32 = fnv1a(b"long_press");
pub const MSG_PRESS: u32 = fnv1a(b"press");
pub const MSG_RELEASE: u32 = fnv1a(b"release");
pub const MSG_TOGGLE: u32 = fnv1a(b"toggle");
pub const MSG_NEXT: u32 = fnv1a(b"next");
pub const MSG_PREV: u32 = fnv1a(b"prev");
pub const MSG_SELECT: u32 = fnv1a(b"select");
pub const MSG_STATUS: u32 = fnv1a(b"status");
pub const MSG_ON: u32 = fnv1a(b"on");
pub const MSG_OFF: u32 = fnv1a(b"off");
pub const MSG_BLINK: u32 = fnv1a(b"blink");

// ============================================================================
// Numeric Formatting Helpers (raw pointer — no bounds checks for PIC safety)
// ============================================================================

/// Format u32 as decimal. Caller must ensure `dst` has at least 10 bytes.
#[inline(always)]
pub unsafe fn fmt_u32_raw(dst: *mut u8, val: u32) -> usize {
    if val == 0 {
        *dst = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let tp = tmp.as_mut_ptr();
    let mut n = val;
    let mut i = 0usize;
    while n > 0 {
        *tp.add(i) = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let mut j = 0usize;
    while j < i {
        *dst.add(j) = *tp.add(i - 1 - j);
        j += 1;
    }
    j
}

/// Format IPv4 address (network byte order u32) as dotted decimal.
/// Caller must ensure `dst` has at least 15 bytes.
#[inline(always)]
pub unsafe fn fmt_ip_raw(dst: *mut u8, ip: u32) -> usize {
    let b = ip.to_be_bytes();
    let mut pos = 0usize;
    let mut octet = 0usize;
    while octet < 4 {
        pos += fmt_u32_raw(dst.add(pos), b[octet] as u32);
        if octet < 3 {
            *dst.add(pos) = b'.';
            pos += 1;
        }
        octet += 1;
    }
    pos
}

/// Format i16 as signed decimal. Caller must ensure `dst` has at least 6 bytes.
#[inline(always)]
pub unsafe fn fmt_i16_raw(dst: *mut u8, val: i16) -> usize {
    let mut pos = 0usize;
    let abs_val: u16 = if val < 0 {
        *dst = b'-';
        pos = 1;
        (0i32 - val as i32) as u16
    } else {
        val as u16
    };
    pos += fmt_u32_raw(dst.add(pos), abs_val as u32);
    pos
}

/// Format u8 as 2-digit hex. Caller must ensure `dst` has at least 2 bytes.
#[inline(always)]
pub unsafe fn fmt_hex_u8(dst: *mut u8, val: u8) -> usize {
    let hi = val >> 4;
    let lo = val & 0x0F;
    *dst = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
    *dst.add(1) = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
    2
}

// ============================================================================
// Output Pacing Helpers
// ============================================================================

/// Drain pending output buffer. Returns true if all pending data was flushed.
/// Call at the top of module_step before reading new input.
#[inline(always)]
pub unsafe fn drain_pending(
    sys: &SyscallTable,
    out_chan: i32,
    buf: *const u8,
    pending_out: &mut u16,
    pending_offset: &mut u16,
) -> bool {
    if *pending_out == 0 { return true; }
    let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
    if out_poll > 0 && ((out_poll as u8) & POLL_OUT) != 0 {
        let written = (sys.channel_write)(out_chan, buf.add(*pending_offset as usize), *pending_out as usize);
        if written > 0 {
            let w = written as u16;
            *pending_offset += w;
            *pending_out -= w;
        }
    }
    *pending_out == 0
}

/// Track a channel_write result, setting pending fields for partial/failed writes.
#[inline(always)]
pub fn track_pending(written: i32, total: usize, pending_out: &mut u16, pending_offset: &mut u16) {
    if written > 0 && (written as usize) < total {
        *pending_offset = written as u16;
        *pending_out = (total - written as usize) as u16;
    } else if written <= 0 {
        *pending_offset = 0;
        *pending_out = total as u16;
    }
}

// ============================================================================
// Channel Hints
// ============================================================================

/// Declares per-port buffer size requirements for a module.
///
/// Modules export `module_channel_hints(out, max_len) -> count` to tell the
/// kernel how large each port's channel buffer should be. Without hints,
/// all ports get the default 2048-byte buffer.
#[repr(C)]
pub struct ChannelHint {
    /// Port direction: 0=in, 1=out, 2=ctrl
    pub port_type: u8,
    /// Port index within that direction
    pub port_index: u8,
    /// Requested buffer size in bytes (0 = use default 2048)
    pub buffer_size: u16,
}

/// Write channel hints to output buffer. Returns number of hints written,
/// or -1 if the buffer is too small.
///
/// # Safety
/// `out` must point to a buffer of at least `max_len` bytes.
#[inline(always)]
pub unsafe fn write_channel_hints(
    out: *mut u8,
    max_len: usize,
    hints: &[ChannelHint],
) -> i32 {
    let needed = hints.len() * 4; // Each ChannelHint is 4 bytes
    if needed > max_len {
        return -1;
    }
    let mut offset = 0;
    for hint in hints {
        *out.add(offset) = hint.port_type;
        *out.add(offset + 1) = hint.port_index;
        *out.add(offset + 2) = (hint.buffer_size & 0xFF) as u8;
        *out.add(offset + 3) = (hint.buffer_size >> 8) as u8;
        offset += 4;
    }
    hints.len() as i32
}

// ============================================================================
// dev_call Convenience Helpers
// ============================================================================

/// Get monotonic time in milliseconds via dev_call (TIMER::MILLIS 0x0602).
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_millis(sys: &SyscallTable) -> u64 {
    let mut buf = [0u8; 8];
    (sys.dev_call)(-1, 0x0602, buf.as_mut_ptr(), 8);
    u64::from_le_bytes(buf)
}

/// Log a message via dev_call (SYSTEM::LOG 0x0C40). Level encoded as handle.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_log(sys: &SyscallTable, level: u8, msg: *const u8, len: usize) {
    (sys.dev_call)(level as i32, 0x0C40, msg as *mut u8, len);
}

/// Poll any fd via dev_call (SYSTEM::FD_POLL 0x0C41).
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_fd_poll(sys: &SyscallTable, fd: i32, events: u8) -> i32 {
    let mut buf = [events];
    (sys.dev_call)(fd, 0x0C41, buf.as_mut_ptr(), 1)
}

/// Query graph-level sample rate via dev_query (SYSTEM::GRAPH_SAMPLE_RATE 0x0C31).
/// Returns 0 if not configured.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_graph_sample_rate(sys: &SyscallTable) -> u32 {
    let mut buf = [0u8; 4];
    let r = (sys.dev_query)(-1, 0x0C31, buf.as_mut_ptr(), 4);
    if r >= 0 { u32::from_le_bytes(buf) } else { 0 }
}

/// Query system clock frequency via dev_query (SYSTEM::SYS_CLOCK_HZ 0x0C3B).
/// Returns 0 on error (should not happen in practice).
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_sys_clock_hz(sys: &SyscallTable) -> u32 {
    let mut buf = [0u8; 4];
    let r = (sys.dev_query)(-1, 0x0C3B, buf.as_mut_ptr(), 4);
    if r >= 0 { u32::from_le_bytes(buf) } else { 0 }
}

/// Query PIO stream time via dev_query (SYSTEM::STREAM_TIME 0x0C30).
/// Returns (consumed_units, queued_units, units_per_sec_q16, t0_micros) or zeros on error.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_stream_time(sys: &SyscallTable) -> (u64, u32, u32, u64) {
    let mut buf = [0u8; 24]; // StreamTime is 24 bytes
    let r = (sys.dev_query)(-1, 0x0C30, buf.as_mut_ptr(), 24);
    if r < 0 {
        return (0, 0, 0, 0);
    }
    let consumed = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
    let queued = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let rate_q16 = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let t0 = u64::from_le_bytes([buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]]);
    (consumed, queued, rate_q16, t0)
}

/// Query downstream latency via dev_query (SYSTEM::DOWNSTREAM_LATENCY 0x0C33).
/// Returns frames of latency downstream from the calling module, or 0.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_downstream_latency(sys: &SyscallTable) -> u32 {
    let mut buf = [0u8; 4];
    let r = (sys.dev_query)(-1, 0x0C33, buf.as_mut_ptr(), 4);
    if r >= 0 { u32::from_le_bytes(buf) } else { 0 }
}

/// Report module's processing latency via dev_call (SYSTEM::REPORT_LATENCY 0x0C50).
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_report_latency(sys: &SyscallTable, frames: u32) {
    let mut buf = frames.to_le_bytes();
    (sys.dev_call)(-1, 0x0C50, buf.as_mut_ptr(), 4);
}

/// Discover channel port via dev_call (CHANNEL::PORT 0x050C).
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_channel_port(sys: &SyscallTable, port_type: u8, index: u8) -> i32 {
    let mut buf = [port_type, index];
    (sys.dev_call)(-1, 0x050C, buf.as_mut_ptr(), 2)
}

/// Channel ioctl via dev_call (CHANNEL::IOCTL 0x0506).
/// data: pointer to u32 for SET_U32/GET_U32, or null for FLUSH/SET_HUP.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_channel_ioctl(sys: &SyscallTable, handle: i32, cmd: u32, data: *mut u8) -> i32 {
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&cmd.to_le_bytes());
    if !data.is_null() {
        core::ptr::copy_nonoverlapping(data, buf.as_mut_ptr().add(4), 4);
    }
    let len = if data.is_null() { 4 } else { 8 };
    let result = (sys.dev_call)(handle, 0x0506, buf.as_mut_ptr(), len);
    if !data.is_null() {
        core::ptr::copy_nonoverlapping(buf.as_ptr().add(4), data, 4);
    }
    result
}

/// Acquire write access to mailbox buffer via dev_call (BUFFER::ACQUIRE_WRITE 0x0A00).
/// Returns pointer (as *mut u8) or null. capacity_out receives buffer capacity.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_buffer_acquire_write(sys: &SyscallTable, chan: i32, capacity_out: *mut u32) -> *mut u8 {
    (sys.dev_call)(chan, 0x0A00, capacity_out as *mut u8, 4) as *mut u8
}

/// Release write buffer via dev_call (BUFFER::RELEASE_WRITE 0x0A01).
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_buffer_release_write(sys: &SyscallTable, chan: i32, len: u32) -> i32 {
    let mut buf = len.to_le_bytes();
    (sys.dev_call)(chan, 0x0A01, buf.as_mut_ptr(), 4)
}

/// Acquire in-place buffer access via dev_call (BUFFER::ACQUIRE_INPLACE 0x0A04).
/// Returns pointer to existing data or null. len_out receives data length.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_buffer_acquire_inplace(sys: &SyscallTable, chan: i32, len_out: *mut u32) -> *mut u8 {
    (sys.dev_call)(chan, 0x0A04, len_out as *mut u8, 4) as *mut u8
}

/// Acquire read access to buffer via dev_call (BUFFER::ACQUIRE_READ 0x0A02).
/// Returns pointer to data or null. len_out receives data length.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_buffer_acquire_read(sys: &SyscallTable, chan: i32, len_out: *mut u32) -> *const u8 {
    (sys.dev_call)(chan, 0x0A02, len_out as *mut u8, 4) as *const u8
}

/// Release read buffer via dev_call (BUFFER::RELEASE_READ 0x0A03).
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_buffer_release_read(sys: &SyscallTable, chan: i32) -> i32 {
    (sys.dev_call)(chan, 0x0A03, core::ptr::null_mut(), 0)
}

// ============================================================================
// Socket helpers (dev_call wrappers for SOCKET class 0x08)
// ============================================================================

/// Open a socket. socket_type: 1=stream, 2=dgram. Returns tagged fd or <0.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_socket_open(sys: &SyscallTable, socket_type: u8) -> i32 {
    let mut buf = [socket_type];
    (sys.dev_call)(-1, 0x0800, buf.as_mut_ptr(), 1)
}

/// Connect socket to remote address. Returns EINPROGRESS or error.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_socket_connect(sys: &SyscallTable, handle: i32, addr: *mut u8) -> i32 {
    (sys.dev_call)(handle, 0x0801, addr, 8) // ChannelAddr is 8 bytes
}

/// Send data on socket. Returns bytes sent or EAGAIN.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_socket_send(sys: &SyscallTable, handle: i32, data: *const u8, len: usize) -> i32 {
    (sys.dev_call)(handle, 0x0802, data as *mut u8, len)
}

/// Receive data from socket. Returns bytes received or EAGAIN.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_socket_recv(sys: &SyscallTable, handle: i32, buf: *mut u8, len: usize) -> i32 {
    (sys.dev_call)(handle, 0x0803, buf, len)
}

/// Poll socket readiness. Returns bitmask of ready events.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_socket_poll(sys: &SyscallTable, handle: i32, events: u8) -> i32 {
    let mut buf = [events];
    (sys.dev_call)(handle, 0x0804, buf.as_mut_ptr(), 1)
}

/// Close socket.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_socket_close(sys: &SyscallTable, handle: i32) -> i32 {
    (sys.dev_call)(handle, 0x0805, core::ptr::null_mut(), 0)
}

/// Bind socket to local port.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_socket_bind(sys: &SyscallTable, handle: i32, port: u16) -> i32 {
    let mut buf = port.to_le_bytes();
    (sys.dev_call)(handle, 0x0806, buf.as_mut_ptr(), 2)
}

/// Listen for incoming connections.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_socket_listen(sys: &SyscallTable, handle: i32) -> i32 {
    (sys.dev_call)(handle, 0x0807, core::ptr::null_mut(), 0)
}

/// Accept incoming connection. Transforms listening socket into connected.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_socket_accept(sys: &SyscallTable, handle: i32) -> i32 {
    (sys.dev_call)(handle, 0x0808, core::ptr::null_mut(), 0)
}

// ============================================================================
// Network Interface helpers
// ============================================================================

/// Set netif state via NETIF::IOCTL (0x0705), cmd=SET_STATE (1).
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_netif_set_state(sys: &SyscallTable, handle: i32, state: u8) {
    let mut buf = [0u8; 5];
    buf[0] = 1; // NETIF_IOCTL_SET_STATE
    buf[4] = state;
    (sys.dev_call)(handle, 0x0705, buf.as_mut_ptr(), 5);
}

// ============================================================================
// Runtime parameter store (persists across reboots)
// ============================================================================

/// Store a parameter override that persists across reboots.
/// `tag`: TLV v2 tag number for this module's param.
/// `value`: pointer to raw value bytes.
/// `len`: value byte count (max 250).
/// Returns 0 on success, negative errno on error.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_param_store(sys: &SyscallTable, tag: u8, value: *const u8, len: usize) -> i32 {
    let mut buf = [0u8; 252]; // 1 tag + 250 max value + 1 spare
    let bp = buf.as_mut_ptr();
    *bp = tag;
    let copy_len = if len > 250 { 250 } else { len };
    let mut i = 0usize;
    while i < copy_len {
        *bp.add(1 + i) = *value.add(i);
        i += 1;
    }
    (sys.dev_call)(-1, 0x0C34, bp, 1 + copy_len)
}

/// Store a u8 parameter override.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_param_store_u8(sys: &SyscallTable, tag: u8, val: u8) -> i32 {
    let mut buf = [tag, val];
    (sys.dev_call)(-1, 0x0C34, buf.as_mut_ptr(), 2)
}

/// Store a string parameter override.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_param_store_str(sys: &SyscallTable, tag: u8, s: *const u8, len: usize) -> i32 {
    dev_param_store(sys, tag, s, len)
}

/// Delete a parameter override (reverts to compiled default on next boot).
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_param_delete(sys: &SyscallTable, tag: u8) -> i32 {
    let mut buf = [tag];
    (sys.dev_call)(-1, 0x0C35, buf.as_mut_ptr(), 1)
}

/// Clear all runtime overrides for this module.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_param_clear_all(sys: &SyscallTable) -> i32 {
    (sys.dev_call)(-1, 0x0C36, core::ptr::null_mut(), 0)
}

/// Get this module's arena allocation (from module_arena_size export).
/// Returns (ptr, size). ptr is null and size is 0 if no arena was allocated.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_arena_get(sys: &SyscallTable) -> (*mut u8, u32) {
    let mut buf = [0u8; 4];
    let size = (sys.dev_call)(-1, 0x0C3A, buf.as_mut_ptr(), 4);
    let addr = u32::from_le_bytes(buf);
    (addr as *mut u8, if size > 0 { size as u32 } else { 0 })
}

// ============================================================================
// Paged Arena (demand-paged memory larger than RAM)
// ============================================================================

/// Paged arena stats returned by dev_paged_arena_stats.
#[repr(C)]
#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct PagedArenaStats {
    resident: u32,
    faults: u32,
    evictions: u32,
    dirty: u32,
    writebacks: u32,
    hit_ratio_q8: u16,
    _reserved: u16,
}

/// Get paged arena base address and size.
/// Returns (base_ptr, size, status). status=1 if active, 0 if not.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_paged_arena_get(sys: &SyscallTable) -> (*mut u8, usize, u32) {
    let mut buf = [0u8; 20];
    let rc = (sys.dev_call)(-1, 0x0CF8, buf.as_mut_ptr(), 20);
    if rc < 0 {
        return (core::ptr::null_mut(), 0, 0);
    }
    let base = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
    let size = u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]);
    let status = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    (base as *mut u8, size as usize, status)
}

/// Get paged arena statistics.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_paged_arena_stats(sys: &SyscallTable) -> PagedArenaStats {
    let mut stats = PagedArenaStats::default();
    let p = &mut stats as *mut _ as *mut u8;
    (sys.dev_call)(-1, 0x0CF9, p, core::mem::size_of::<PagedArenaStats>());
    stats
}

/// Prefault pages into the paged arena.
/// `offset`: starting page index, `count`: number of pages to prefault.
/// Returns number of pages actually prefaulted.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_paged_arena_prefault(sys: &SyscallTable, offset: u32, count: u32) -> u32 {
    let mut buf = [0u8; 8];
    let bp = buf.as_mut_ptr();
    let ob = offset.to_le_bytes();
    let cb = count.to_le_bytes();
    *bp = ob[0]; *bp.add(1) = ob[1]; *bp.add(2) = ob[2]; *bp.add(3) = ob[3];
    *bp.add(4) = cb[0]; *bp.add(5) = cb[1]; *bp.add(6) = cb[2]; *bp.add(7) = cb[3];
    let rc = (sys.dev_call)(-1, 0x0CFA, bp, 8);
    if rc > 0 { rc as u32 } else { 0 }
}

// ============================================================================
// FMP (Fluxor Message Protocol) — typed messages on channels
// ============================================================================

// Wire format: [type:4 LE][len:2 LE][payload:len]
// type = FNV-1a 32-bit hash of the message name
// len  = payload byte count (0 = no payload)
// Modules are stepped sequentially (cooperative, single-core), so split
// writes/reads within one step are safe — no interleaving.

const MSG_HDR_SIZE: usize = 6;

/// FNV-1a 32-bit hash. Const-evaluable for compile-time message type IDs.
#[allow(dead_code)]
const fn fnv1a(s: &[u8]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    let mut i = 0;
    while i < s.len() {
        h ^= s[i] as u32;
        h = h.wrapping_mul(0x01000193);
        i += 1;
    }
    h
}

/// Write a typed message to a channel.
/// Returns 0 on success, -1 if the header write failed.
#[allow(dead_code)]
#[inline(always)]
unsafe fn msg_write(
    sys: &SyscallTable,
    chan: i32,
    msg_type: u32,
    payload: *const u8,
    payload_len: u16,
) -> i32 {
    let mut hdr = [0u8; MSG_HDR_SIZE];
    let tb = msg_type.to_le_bytes();
    hdr[0] = tb[0]; hdr[1] = tb[1]; hdr[2] = tb[2]; hdr[3] = tb[3];
    let lb = payload_len.to_le_bytes();
    hdr[4] = lb[0]; hdr[5] = lb[1];

    let written = (sys.channel_write)(chan, hdr.as_ptr(), MSG_HDR_SIZE);
    if written < MSG_HDR_SIZE as i32 {
        return -1;
    }
    if payload_len > 0 && !payload.is_null() {
        let w2 = (sys.channel_write)(chan, payload, payload_len as usize);
        if w2 < payload_len as i32 {
            return -1;
        }
    }
    0
}

/// Write a typed message with no payload.
#[allow(dead_code)]
#[inline(always)]
unsafe fn msg_write_empty(sys: &SyscallTable, chan: i32, msg_type: u32) -> i32 {
    msg_write(sys, chan, msg_type, core::ptr::null(), 0)
}

/// Read a typed message from a channel.
/// Returns (msg_type, payload_len). (0, 0) if no complete header available.
/// Payload bytes are written to buf[0..payload_len.min(buf_cap)].
/// Excess payload bytes (beyond buf_cap) are consumed and discarded.
#[allow(dead_code)]
#[inline(always)]
unsafe fn msg_read(
    sys: &SyscallTable,
    chan: i32,
    buf: *mut u8,
    buf_cap: usize,
) -> (u32, u16) {
    let mut hdr = [0u8; MSG_HDR_SIZE];
    let n = (sys.channel_read)(chan, hdr.as_mut_ptr(), MSG_HDR_SIZE);
    if n < MSG_HDR_SIZE as i32 {
        return (0, 0);
    }
    let msg_type = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let payload_len = u16::from_le_bytes([hdr[4], hdr[5]]);
    if payload_len > 0 {
        let to_read = (payload_len as usize).min(buf_cap);
        if to_read > 0 && !buf.is_null() {
            (sys.channel_read)(chan, buf, to_read);
        }
        // Discard excess bytes if payload > buf_cap
        let excess = payload_len as usize - to_read;
        if excess > 0 {
            let mut discard = [0u8; 64];
            let mut remaining = excess;
            while remaining > 0 {
                let chunk = remaining.min(64);
                (sys.channel_read)(chan, discard.as_mut_ptr(), chunk);
                remaining -= chunk;
            }
        }
    }
    (msg_type, payload_len)
}

// ============================================================================
// Param Reading Helpers
// ============================================================================

/// Read u8 from params blob at `offset`. Returns `default` if out of bounds.
#[inline(always)]
pub unsafe fn p_u8(params: *const u8, len: usize, offset: usize, default: u8) -> u8 {
    if offset < len { *params.add(offset) } else { default }
}

/// Read little-endian u16 from params blob at `offset`. Returns `default` if out of bounds.
#[inline(always)]
pub unsafe fn p_u16(params: *const u8, len: usize, offset: usize, default: u16) -> u16 {
    if offset + 1 < len {
        let lo = *params.add(offset) as u16;
        let hi = *params.add(offset + 1) as u16;
        lo | (hi << 8)
    } else {
        default
    }
}

/// Read little-endian u32 from params blob at `offset`. Returns `default` if out of bounds.
#[inline(always)]
pub unsafe fn p_u32(params: *const u8, len: usize, offset: usize, default: u32) -> u32 {
    if offset + 3 < len {
        let p = params.add(offset);
        (*p as u32) | ((*p.add(1) as u32) << 8) | ((*p.add(2) as u32) << 16) | ((*p.add(3) as u32) << 24)
    } else {
        default
    }
}

// ============================================================================
// Heap Allocation Helpers
// ============================================================================
//
// Wrappers for the kernel-managed per-module heap. Modules that export
// `module_arena_size() -> u32` with a non-zero return value receive a
// heap arena. These helpers call through the SyscallTable function pointers.
//
// The heap is bounded per-module: allocation failures return null.
// Modules MUST check for null returns and handle gracefully.

/// Allocate `size` bytes from this module's heap arena.
///
/// Returns a pointer to the allocated memory, or null if the heap is
/// exhausted or if this module has no heap. Size is rounded up to 16-byte
/// alignment internally by the kernel allocator.
///
/// # Safety
/// Caller must ensure `sys` points to a valid SyscallTable.
#[allow(dead_code)]
#[inline(always)]
pub unsafe fn heap_alloc(sys: &SyscallTable, size: u32) -> *mut u8 {
    (sys.heap_alloc)(size)
}

/// Free memory previously allocated by `heap_alloc`.
///
/// Passing null is a no-op. Passing a pointer not returned by `heap_alloc`
/// for this module is detected by the kernel (logged, not crashed).
///
/// # Safety
/// Caller must ensure `sys` points to a valid SyscallTable.
/// `ptr` must be null or a pointer previously returned by `heap_alloc`.
#[allow(dead_code)]
#[inline(always)]
pub unsafe fn heap_free(sys: &SyscallTable, ptr: *mut u8) {
    (sys.heap_free)(ptr)
}

/// Reallocate memory to `new_size` bytes.
///
/// Returns a new pointer on success, or null on failure. If null is returned,
/// the original allocation at `ptr` is unchanged (not freed).
///
/// If `ptr` is null, behaves like `heap_alloc(sys, new_size)`.
/// If `new_size` is 0, behaves like `heap_free(sys, ptr)` and returns null.
///
/// # Safety
/// Caller must ensure `sys` points to a valid SyscallTable.
/// `ptr` must be null or a pointer previously returned by `heap_alloc`.
#[allow(dead_code)]
#[inline(always)]
pub unsafe fn heap_realloc(sys: &SyscallTable, ptr: *mut u8, new_size: u32) -> *mut u8 {
    (sys.heap_realloc)(ptr, new_size)
}

/// Query heap statistics for this module.
///
/// Returns a HeapStats struct with current usage, high-water mark, etc.
/// All fields are zero if this module has no heap.
///
/// # Safety
/// Caller must ensure `sys` points to a valid SyscallTable.
#[allow(dead_code)]
#[inline(always)]
pub unsafe fn heap_stats(sys: &SyscallTable) -> (u32, u32, u16, u16, u32) {
    // Query via dev_query with HEAP_STATS key (6)
    let mut buf = [0u8; 16];
    let r = (sys.dev_query)(-1, 6, buf.as_mut_ptr(), 16);
    if r < 0 {
        return (0, 0, 0, 0, 0);
    }
    let arena_size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let allocated = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let alloc_count = u16::from_le_bytes([buf[8], buf[9]]);
    let total_allocs = u16::from_le_bytes([buf[10], buf[11]]);
    let high_water = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    (arena_size, allocated, alloc_count, total_allocs, high_water)
}

// ============================================================================
// Bridge channel helpers (SYSTEM class 0x0CE0-0x0CE3)
// ============================================================================

/// Write data to a bridge channel. Returns 0 on success, -EAGAIN if ring full.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_bridge_write(sys: &SyscallTable, bridge_fd: i32, data: *const u8, len: usize) -> i32 {
    (sys.dev_call)(bridge_fd, 0x0CE0, data as *mut u8, len)
}

/// Read data from a bridge channel. Returns bytes read, -EAGAIN if empty/no new.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_bridge_read(sys: &SyscallTable, bridge_fd: i32, buf: *mut u8, len: usize) -> i32 {
    (sys.dev_call)(bridge_fd, 0x0CE1, buf, len)
}

/// Poll bridge readiness. Returns 1 if readable, 0 if not.
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_bridge_poll(sys: &SyscallTable, bridge_fd: i32) -> i32 {
    (sys.dev_call)(bridge_fd, 0x0CE2, core::ptr::null_mut(), 0)
}

/// Get bridge info. Returns 12 bytes: [type, from, to, _, drops:u32, seq:u32].
#[allow(dead_code)]
#[inline(always)]
unsafe fn dev_bridge_info(sys: &SyscallTable, bridge_fd: i32, buf: &mut [u8; 12]) -> i32 {
    (sys.dev_call)(bridge_fd, 0x0CE3, buf.as_mut_ptr(), 12)
}
