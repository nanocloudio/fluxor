//! The boot incarnation: 16 bytes drawn from the CSPRNG once per boot.
//!
//! Anything minted during a boot that must not be honoured by a later boot
//! — an emission token, a fence epoch, a directory registration — mixes
//! this in. Two boots never share one, so a stale value from a previous
//! life of the host cannot match by construction; nothing has to remember
//! which boot it came from.
//!
//! Drawn on first read rather than at boot so the entropy source has come
//! up; a read before it has answers zero, which no consumer may treat as
//! an incarnation.

use portable_atomic::{AtomicU8, Ordering};

static mut VALUE: [u8; 16] = [0; 16];
static STATE: AtomicU8 = AtomicU8::new(0);

/// The incarnation, or all-zero if the entropy source has not answered.
pub fn get() -> [u8; 16] {
    if STATE.load(Ordering::Acquire) == 2 {
        // SAFETY: written exactly once before STATE became 2.
        return unsafe { *core::ptr::addr_of!(VALUE) };
    }
    if STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        let mut buf = [0u8; 16];
        let rc = crate::kernel::sys::hal::csprng_fill(buf.as_mut_ptr(), buf.len());
        if rc >= 0 && buf != [0u8; 16] {
            // SAFETY: the only writer, gated by the 0→1 transition above.
            unsafe { core::ptr::write(core::ptr::addr_of_mut!(VALUE), buf) };
            STATE.store(2, Ordering::Release);
            return buf;
        }
        // No entropy yet: let a later reader try again.
        STATE.store(0, Ordering::Release);
    }
    [0u8; 16]
}
