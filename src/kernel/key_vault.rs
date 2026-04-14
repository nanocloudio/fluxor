//! KEY_VAULT device class — kernel-managed asymmetric-key slots.
//!
//! Callers STORE a private key and receive an opaque handle. The raw bytes
//! live in kernel static memory and are never returned to callers. Keys are
//! zeroised on DESTROY and on scheduler reset.
//!
//! Slot management (PROBE, STORE, DESTROY) is implemented here. ECDH, SIGN
//! and VERIFY return `ENOSYS` at this layer and are expected to be handled
//! by a kernel P-256 provider registered separately; callers that see
//! `ENOSYS` are responsible for falling back to their own signer.

use crate::abi::dev_key_vault;
use crate::abi::errno::{ENOSYS, EINVAL};

/// Number of key slots. Sized for TLS session fan-out.
pub const MAX_SLOTS: usize = 8;

/// Maximum key material length per slot. 32 bytes fits a P-256 scalar;
/// the extra 32 bytes allow larger keying material without breaking ABI.
pub const MAX_KEY_BYTES: usize = 64;

/// Slot flags.
const FLAG_IN_USE: u8 = 0x01;

#[repr(C)]
struct Slot {
    flags: u8,
    key_type: u8,
    key_len: u8,
    _pad: u8,
    data: [u8; MAX_KEY_BYTES],
}

impl Slot {
    const fn empty() -> Self {
        Self { flags: 0, key_type: 0, key_len: 0, _pad: 0, data: [0; MAX_KEY_BYTES] }
    }
}

// Static slot table. Access is serialised via the scheduler's single-core
// cooperative model; no explicit lock needed.
static mut SLOTS: [Slot; MAX_SLOTS] = [
    Slot::empty(), Slot::empty(), Slot::empty(), Slot::empty(),
    Slot::empty(), Slot::empty(), Slot::empty(), Slot::empty(),
];

/// Zeroise every slot. Called on scheduler reset / graph reconfigure.
pub unsafe fn reset_all() {
    for i in 0..MAX_SLOTS {
        zeroise_slot(i);
    }
}

unsafe fn zeroise_slot(i: usize) {
    if i >= MAX_SLOTS { return; }
    // Volatile writes so the compiler doesn't optimise the wipe away.
    let p = (&raw mut SLOTS[i].data) as *mut u8;
    for j in 0..MAX_KEY_BYTES {
        core::ptr::write_volatile(p.add(j), 0);
    }
    SLOTS[i].flags = 0;
    SLOTS[i].key_type = 0;
    SLOTS[i].key_len = 0;
}

/// Provider dispatch function registered against dev_class::KEY_VAULT.
/// Signature matches the `provider_dispatch` contract.
pub unsafe fn provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    match opcode {
        dev_key_vault::PROBE => {
            // Presence indicator — 1 means the vault is available.
            1
        }

        dev_key_vault::STORE => {
            // arg layout: [key_type:u8][len:u8][pad:u16][bytes[len]]
            if arg.is_null() || arg_len < 4 { return EINVAL; }
            let key_type = *arg;
            let key_len = *arg.add(1) as usize;
            if key_len == 0 || key_len > MAX_KEY_BYTES || 4 + key_len > arg_len {
                return EINVAL;
            }

            // Find a free slot.
            let mut slot_idx: isize = -1;
            for i in 0..MAX_SLOTS {
                if (SLOTS[i].flags & FLAG_IN_USE) == 0 {
                    slot_idx = i as isize;
                    break;
                }
            }
            if slot_idx < 0 { return crate::abi::errno::ENOMEM; }
            let idx = slot_idx as usize;

            SLOTS[idx].key_type = key_type;
            SLOTS[idx].key_len = key_len as u8;
            let src = arg.add(4);
            for j in 0..key_len {
                core::ptr::write_volatile(&raw mut SLOTS[idx].data[j], *src.add(j));
            }
            // Mark in-use last so partial fills can't be observed.
            SLOTS[idx].flags = FLAG_IN_USE;
            idx as i32
        }

        dev_key_vault::DESTROY => {
            if handle < 0 || (handle as usize) >= MAX_SLOTS { return EINVAL; }
            zeroise_slot(handle as usize);
            0
        }

        dev_key_vault::ECDH | dev_key_vault::SIGN | dev_key_vault::VERIFY => {
            // Crypto operations are expected to be satisfied by a registered
            // provider. If none is attached, report ENOSYS so callers can
            // fall back rather than hang.
            ENOSYS
        }

        _ => ENOSYS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STORE -> handle returns a valid slot; key bytes are accepted but
    /// cannot be observed through any inspection API (there is no dev_query
    /// path that exposes the slot content).
    #[test]
    fn store_and_destroy_roundtrip() {
        unsafe { reset_all(); }

        let mut buf = [0u8; 4 + 32];
        buf[0] = 1; // key_type = P-256 scalar
        buf[1] = 32; // key_len
        for i in 0..32 { buf[4 + i] = i as u8 + 1; }

        let handle = unsafe {
            provider_dispatch(-1, dev_key_vault::STORE, buf.as_mut_ptr(), buf.len())
        };
        assert!(handle >= 0, "store should succeed, got {}", handle);

        // No API path exposes the raw key. Confirm the slot holds our bytes
        // via the private accessor (test-only).
        unsafe {
            let slot = &SLOTS[handle as usize];
            assert_eq!(slot.key_len, 32);
            assert_eq!(slot.key_type, 1);
            for i in 0..32 { assert_eq!(slot.data[i], (i as u8) + 1); }
        }

        // Destroy wipes the bytes.
        let rc = unsafe { provider_dispatch(handle, dev_key_vault::DESTROY, core::ptr::null_mut(), 0) };
        assert_eq!(rc, 0);
        unsafe {
            let slot = &SLOTS[handle as usize];
            assert_eq!(slot.flags, 0);
            assert_eq!(slot.key_len, 0);
            for i in 0..32 { assert_eq!(slot.data[i], 0, "slot byte {} not wiped", i); }
        }
    }

    #[test]
    fn slots_exhaust() {
        unsafe { reset_all(); }
        let mut buf = [0u8; 4 + 4];
        buf[0] = 1;
        buf[1] = 4;
        let mut handles = [0i32; MAX_SLOTS];
        for i in 0..MAX_SLOTS {
            handles[i] = unsafe {
                provider_dispatch(-1, dev_key_vault::STORE, buf.as_mut_ptr(), buf.len())
            };
            assert!(handles[i] >= 0);
        }
        // Next store must fail with ENOMEM.
        let over = unsafe {
            provider_dispatch(-1, dev_key_vault::STORE, buf.as_mut_ptr(), buf.len())
        };
        assert_eq!(over, crate::abi::errno::ENOMEM);

        // Free one, confirm a new store fits.
        let rc = unsafe { provider_dispatch(handles[0], dev_key_vault::DESTROY, core::ptr::null_mut(), 0) };
        assert_eq!(rc, 0);
        let again = unsafe {
            provider_dispatch(-1, dev_key_vault::STORE, buf.as_mut_ptr(), buf.len())
        };
        assert!(again >= 0);
    }

    #[test]
    fn crypto_ops_report_not_implemented() {
        unsafe { reset_all(); }
        assert_eq!(
            unsafe { provider_dispatch(0, dev_key_vault::SIGN, core::ptr::null_mut(), 0) },
            crate::abi::errno::ENOSYS,
        );
        assert_eq!(
            unsafe { provider_dispatch(0, dev_key_vault::ECDH, core::ptr::null_mut(), 0) },
            crate::abi::errno::ENOSYS,
        );
        assert_eq!(
            unsafe { provider_dispatch(0, dev_key_vault::VERIFY, core::ptr::null_mut(), 0) },
            crate::abi::errno::ENOSYS,
        );
    }

    #[test]
    fn probe_returns_present() {
        assert_eq!(
            unsafe { provider_dispatch(-1, dev_key_vault::PROBE, core::ptr::null_mut(), 0) },
            1,
        );
    }
}
