// ============================================================================
// PIC-only runtime intrinsics
// ============================================================================
//
// Everything in `_pic_intrinsics` below exists to resolve symbols the
// compiler emits in PIC builds where libcore's panic / EABI runtime
// is not linked. On a hosted target (Linux, macOS) the compiler
// emits calls into libcore / libc directly, and emitting these
// `#[no_mangle]` symbols ourselves would either collide with libc
// (`memset` / `memcpy`) or be unused dead code.
//
// `target_os = "none"` covers ARM bare-metal and aarch64 bare-metal
// (rp2040 / rp2350 / bcm2712); `target_arch = "wasm32"` covers the
// browser host (no libc, but still needs ABI helpers).

#[cfg(any(target_os = "none", target_arch = "wasm32"))]
mod _pic_intrinsics {

    #[allow(
        dead_code,
        reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
    )]
    mod core_stubs {
        #[inline(never)]
        pub fn slice_index_trap() -> ! {
            loop {}
        }
    }

    // The compiler emits mangled calls into core::slice::index and core::panicking.
    // Hash suffixes are toolchain-dependent. If a toolchain upgrade changes them,
    // extract new hashes: readelf -Ws module.o | grep UND
    // thumbv8m (RP2350):
    #[no_mangle]
    pub extern "C" fn _ZN4core5slice5index16slice_index_fail17h4ded73b0c5f4c0cfE(
        _: usize,
        _: usize,
    ) -> ! {
        loop {}
    }
    #[no_mangle]
    pub extern "C" fn _ZN4core9panicking18panic_bounds_check17h974ddc284291fde1E(
        _: usize,
        _: usize,
    ) -> ! {
        loop {}
    }
    // aarch64 (BCM2712/Linux):
    #[no_mangle]
    pub extern "C" fn _ZN4core5slice5index16slice_index_fail17hf6dd4a5d97b8b298E(
        _: usize,
        _: usize,
    ) -> ! {
        loop {}
    }
    #[no_mangle]
    pub extern "C" fn _ZN4core9panicking18panic_bounds_check17he29bb21320f32a38E(
        _: usize,
        _: usize,
    ) -> ! {
        loop {}
    }
    // thumbv6m (RP2040):
    #[no_mangle]
    pub extern "C" fn _ZN4core5slice5index16slice_index_fail17h9ac54fc02d7db528E(
        _: usize,
        _: usize,
    ) -> ! {
        loop {}
    }
    #[no_mangle]
    pub extern "C" fn _ZN4core9panicking18panic_bounds_check17h1329d9c5a4d8cefbE(
        _: usize,
        _: usize,
    ) -> ! {
        loop {}
    }

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
    static _KEEP_MEMSET: [unsafe extern "C" fn(*mut u8, usize, i32); 3] =
        [__aeabi_memset, __aeabi_memset4, __aeabi_memset8];

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
    static _KEEP_MEMMOVE: [unsafe extern "C" fn(*mut u8, *const u8, usize); 3] =
        [__aeabi_memmove, __aeabi_memmove4, __aeabi_memmove8];

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
        if d == 0 {
            return 0;
        }
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
        if d == 0 {
            return 0;
        }
        let neg = (n < 0) != (d < 0);
        let un = if n < 0 {
            (n as u32).wrapping_neg()
        } else {
            n as u32
        };
        let ud = if d < 0 {
            (d as u32).wrapping_neg()
        } else {
            d as u32
        };
        let q = __aeabi_uidiv(un, ud);
        if neg {
            (q as i32).wrapping_neg()
        } else {
            q as i32
        }
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
        let cross = a_lo
            .wrapping_mul(b_hi)
            .wrapping_add(a_hi.wrapping_mul(b_lo));
        let result_hi = lh.wrapping_add(cross);
        (ll as u64) | ((result_hi as u64) << 32)
    }

    /// 64-bit logical left shift.
    /// ARM EABI: r0=v_lo, r1=v_hi, r2=shift → r0:r1 = v << shift.
    #[no_mangle]
    pub unsafe extern "C" fn __aeabi_llsl(v_lo: u32, v_hi: u32, shift: u32) -> u64 {
        if shift >= 64 {
            return 0;
        }
        if shift == 0 {
            return (v_lo as u64) | ((v_hi as u64) << 32);
        }
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
        if shift == 0 {
            return (v_lo as u64) | ((v_hi as u64) << 32);
        }
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
        if shift >= 64 {
            return 0;
        }
        if shift == 0 {
            return (v_lo as u64) | ((v_hi as u64) << 32);
        }
        if shift >= 32 {
            let lo = v_hi >> (shift - 32);
            return lo as u64;
        }
        let lo = (v_lo >> shift) | (v_hi << (32 - shift));
        let hi = v_hi >> shift;
        (lo as u64) | ((hi as u64) << 32)
    }
} // mod _pic_intrinsics — end of PIC-only block

// Re-export the PIC intrinsics at the includer's top-level scope so
// module code that calls `__aeabi_memcpy` etc. by name keeps working.
// Gated identically — on host the symbols don't exist.
#[cfg(any(target_os = "none", target_arch = "wasm32"))]
#[allow(
    unused_imports,
    reason = "import surface kept for downstream re-export consumers"
)]
use _pic_intrinsics::*;
