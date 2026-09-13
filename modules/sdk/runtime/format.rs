// ============================================================================
// Numeric Formatting Helpers (raw pointer — no bounds checks for PIC safety)
// ============================================================================

/// Format u32 as decimal. Caller must ensure `dst` has at least 10 bytes.
///
/// # Safety
/// `dst` must be valid for writes of up to 10 bytes (the maximum decimal
/// width of `u32::MAX`). Pointer is written without bounds checks.
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
///
/// # Safety
/// `dst` must be valid for writes of up to 15 bytes
/// (`xxx.xxx.xxx.xxx` = 4×3 digits + 3 dots). Bounds are not checked.
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
///
/// # Safety
/// `dst` must be valid for writes of up to 6 bytes (`-32768` is the widest
/// case). Bounds are not checked.
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
///
/// # Safety
/// `dst` must be valid for writes of 2 bytes. Bounds are not checked.
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
///
/// # Safety
/// `buf` must be valid for reads of at least `*pending_out + *pending_offset`
/// bytes. `sys` must outlive the call. The kernel guarantees both when the
/// helper is invoked from `module_step`.
#[inline(always)]
pub unsafe fn drain_pending(
    sys: &SyscallTable,
    out_chan: i32,
    buf: *const u8,
    pending_out: &mut u16,
    pending_offset: &mut u16,
) -> bool {
    if *pending_out == 0 {
        return true;
    }
    let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
    if out_poll > 0 && (out_poll as u32 & POLL_OUT) != 0 {
        let written = (sys.channel_write)(
            out_chan,
            buf.add(*pending_offset as usize),
            *pending_out as usize,
        );
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

// ============================================================================
// Panic handler
// ============================================================================
//
// Every module compilation unit needs exactly one `#[panic_handler]`.
// `wasm32-unknown-unknown` cdylib builds require it at compile time;
// bare-metal PIC ELF builds get it from the kernel's panic stub at
// link time. Providing one here in `runtime.rs` means modules don't
// have to declare their own. Module faults are detected and restarted
// by the kernel, so the trap loop never needs to return usefully.

#[cfg(any(target_os = "none", target_arch = "wasm32"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
