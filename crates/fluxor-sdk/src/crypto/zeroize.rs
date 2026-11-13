// Clearing secrets so the clearing survives optimisation.

/// Zeroise a byte buffer via volatile writes. `#[inline(never)]` prevents
/// the compiler from eliding the stores after proving the buffer is dead.
#[inline(never)]
pub fn zeroize(buf: &mut [u8]) {
    let mut i = 0;
    while i < buf.len() {
        // SAFETY: `i < buf.len()`, so the write stays inside `buf`.
        unsafe {
            core::ptr::write_volatile(buf.as_mut_ptr().add(i), 0);
        }
        i += 1;
    }
}
