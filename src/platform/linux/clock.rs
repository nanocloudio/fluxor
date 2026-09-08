//! The Linux wall clock's synchronisation evidence, via `adjtimex(2)`.
//!
//! In the library rather than the runtime binary so the host harness can
//! call the same function the HAL table points at and hold its answer
//! against the kernel's own status word.

/// What the kernel knows about the wall clock, via `adjtimex(2)`.
///
/// `now_unix_millis` cannot answer this and never could: a nonzero reading
/// from a clock nobody synchronised looks exactly like a good one. The
/// kernel, however, tracks it — `STA_UNSYNC` is clear once a time protocol
/// has disciplined the clock, and `maxerror` is its own estimate of how far
/// off it may be. That is evidence, and it is the difference between a
/// provider stuck at `RTC` forever and one that can honestly report
/// `NETWORK_SYNC`.
///
/// Returns `(synchronised, max_error_us)`. `synchronised: false` is a real
/// answer — the kernel can tell, and the answer is no.
pub fn sync_status() -> Option<(bool, u64)> {
    // `struct timex` is declared here rather than linked, so its layout is
    // this file's responsibility: the kernel writes the whole struct back,
    // and a field read at the wrong offset would be indistinguishable from
    // a real answer. The declaration below is the LP64 shape — `int`
    // followed by explicit padding to align each `__kernel_long_t` — and
    // the assertion under it refuses to build anywhere that shape is not
    // the right one, because the failure it prevents is a garbage `status`
    // read as "synchronised" and a clock promoted to TRUSTED on it.
    //
    // `adjtimex` with `modes = 0` is a pure query and needs no privilege.
    #[repr(C)]
    #[derive(Default)]
    struct Timex {
        modes: i32,
        _pad0: i32,
        offset: i64,
        freq: i64,
        maxerror: i64,
        esterror: i64,
        status: i32,
        _pad1: i32,
        constant: i64,
        precision: i64,
        tolerance: i64,
        time_sec: i64,
        time_usec: i64,
        tick: i64,
        ppsfreq: i64,
        jitter: i64,
        shift: i32,
        _pad2: i32,
        stabil: i64,
        jitcnt: i64,
        calcnt: i64,
        errcnt: i64,
        stbcnt: i64,
        tai: i32,
        _reserved: [i32; 11],
    }

    // The layout above is LP64's. On any other pointer width the padding
    // and the `__kernel_long_t` width both differ, and every field past
    // `modes` would be read from the wrong place.
    const _: () = assert!(
        core::mem::size_of::<usize>() == 8,
        "struct timex is declared for LP64; a 32-bit target needs its own shape"
    );

    unsafe extern "C" {
        fn adjtimex(buf: *mut core::ffi::c_void) -> i32;
    }

    /// `STA_UNSYNC` — set while the clock is NOT synchronised.
    const STA_UNSYNC: i32 = 0x0040;

    let mut tx = Timex::default();
    // SAFETY: `modes = 0` makes this a read-only query, and `tx` is a
    // zeroed, correctly-sized `struct timex` owned by this frame.
    let rc = unsafe { adjtimex((&raw mut tx).cast()) };
    if rc < 0 {
        // The kernel could not answer, which is not the same as "not
        // synchronised": reporting `false` here would claim knowledge this
        // call did not obtain.
        return None;
    }
    let synchronised = (tx.status & STA_UNSYNC) == 0;
    // `maxerror` saturates at 16 seconds when unsynchronised; clamped so a
    // consumer sizing a window from it cannot get a negative or absurd one.
    let max_error_us = if tx.maxerror < 0 {
        u64::MAX
    } else {
        tx.maxerror as u64
    };
    Some((synchronised, max_error_us))
}
