//! KEY_VAULT device class — kernel-managed asymmetric-key slots.
//!
//! Callers STORE a private key and receive an opaque handle. The raw bytes
//! live in kernel static memory and are never returned to callers. Keys are
//! zeroised on DESTROY and on scheduler reset.
//!
//! ECDH, SIGN and VERIFY run the kernel P-256 primitives directly: the
//! vault is authoritative for any slot holding P-256 scalar material.

use crate::abi::contracts::key_vault as dev_key_vault;
use crate::abi::errno::{EINVAL, ENOSYS};
use crate::kernel::crypto::p256;
use crate::kernel::fd;

/// P-256 raw-scalar key type, as passed in the STORE `key_type` byte.
const KEY_TYPE_P256_SCALAR: u8 = 1;

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
        Self {
            flags: 0,
            key_type: 0,
            key_len: 0,
            _pad: 0,
            data: [0; MAX_KEY_BYTES],
        }
    }
}

// Static slot table. Access is serialised via the scheduler's single-core
// cooperative model; no explicit lock needed.
static mut SLOTS: [Slot; MAX_SLOTS] = [
    Slot::empty(),
    Slot::empty(),
    Slot::empty(),
    Slot::empty(),
    Slot::empty(),
    Slot::empty(),
    Slot::empty(),
    Slot::empty(),
];

/// Zeroise every slot. Called on scheduler reset / graph reconfigure.
///
/// # Safety
/// Must be called from kernel context with exclusive access to `SLOTS`
/// (i.e. while no module is mid-`provider_dispatch`). Wipes all key
/// material in place via volatile writes; concurrent SIGN/ECDH would
/// observe partially-zeroed keys.
pub unsafe fn reset_all() {
    for i in 0..MAX_SLOTS {
        zeroise_slot(i);
    }
}

unsafe fn zeroise_slot(i: usize) {
    if i >= MAX_SLOTS {
        return;
    }
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
///
/// Slot-bound ops (DESTROY / SIGN / ECDH) take a `FD_TAG_KEY_VAULT`-tagged
/// handle; PROBE / STORE / VERIFY take `handle=-1`. Tagging keeps KV
/// handles distinct from other drivers' untagged integer handles in the
/// kernel's global handle-tracking table.
///
/// # Safety
/// `arg` must be valid for `arg_len` bytes for both reads (input fields
/// per the opcode's TLV layout) and writes (signature / shared-secret
/// output regions). Caller must not retain `arg` after return.
pub unsafe fn provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let slot_handle = match opcode {
        dev_key_vault::PROBE | dev_key_vault::STORE | dev_key_vault::VERIFY => handle,
        _ => {
            if handle < 0 {
                return EINVAL;
            }
            let (tag, slot) = fd::untag_fd(handle);
            if tag != fd::FD_TAG_KEY_VAULT {
                return EINVAL;
            }
            slot
        }
    };
    match opcode {
        dev_key_vault::PROBE => {
            // Presence indicator — 1 means the vault is available.
            1
        }

        dev_key_vault::STORE => {
            // arg layout: [key_type:u8][len:u8][pad:u16][bytes[len]]
            if arg.is_null() || arg_len < 4 {
                return EINVAL;
            }
            let key_type = *arg;
            let key_len = *arg.add(1) as usize;
            if key_len == 0 || key_len > MAX_KEY_BYTES || 4 + key_len > arg_len {
                return EINVAL;
            }

            // Find a free slot.
            let mut slot_idx: isize = -1;
            let slots_ptr = &raw const SLOTS;
            for (i, s) in (*slots_ptr).iter().enumerate() {
                if (s.flags & FLAG_IN_USE) == 0 {
                    slot_idx = i as isize;
                    break;
                }
            }
            if slot_idx < 0 {
                return crate::abi::errno::ENOMEM;
            }
            let idx = slot_idx as usize;

            SLOTS[idx].key_type = key_type;
            SLOTS[idx].key_len = key_len as u8;
            let src = arg.add(4);
            for j in 0..key_len {
                core::ptr::write_volatile(&raw mut SLOTS[idx].data[j], *src.add(j));
            }
            // Mark in-use last so partial fills can't be observed.
            SLOTS[idx].flags = FLAG_IN_USE;
            fd::tag_fd(fd::FD_TAG_KEY_VAULT, idx as i32)
        }

        dev_key_vault::DESTROY => {
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            zeroise_slot(slot_handle as usize);
            0
        }

        dev_key_vault::SIGN => {
            if arg.is_null() || arg_len < 4 + 32 + 64 {
                return EINVAL;
            }
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            let slot = &SLOTS[slot_handle as usize];
            if (slot.flags & FLAG_IN_USE) == 0
                || slot.key_type != KEY_TYPE_P256_SCALAR
                || slot.key_len != 32
            {
                return EINVAL;
            }
            let hash_len = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
            if hash_len == 0 || hash_len > 64 || 4 + hash_len + 64 > arg_len {
                return EINVAL;
            }
            let hash = core::slice::from_raw_parts(arg.add(4), hash_len);
            let mut priv_key = [0u8; 32];
            priv_key.copy_from_slice(&slot.data[..32]);
            // RFC 6979 derives its nonce deterministically; the `_random` arg
            // on ecdsa_sign is unused.
            let sig = p256::ecdsa_sign(&priv_key, hash, &[0u8; 32]);
            for byte in priv_key.iter_mut() {
                core::ptr::write_volatile(byte as *mut u8, 0);
            }
            let out = arg.add(4 + hash_len);
            core::ptr::copy_nonoverlapping(sig.as_ptr(), out, 64);
            0
        }

        dev_key_vault::ECDH => {
            if arg.is_null() || arg_len < 4 {
                return EINVAL;
            }
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            let slot = &SLOTS[slot_handle as usize];
            if (slot.flags & FLAG_IN_USE) == 0
                || slot.key_type != KEY_TYPE_P256_SCALAR
                || slot.key_len != 32
            {
                return EINVAL;
            }
            let peer_len = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
            if peer_len == 0 || 4 + peer_len + 32 > arg_len {
                return EINVAL;
            }
            let peer = core::slice::from_raw_parts(arg.add(4), peer_len);
            let mut priv_key = [0u8; 32];
            priv_key.copy_from_slice(&slot.data[..32]);
            let result = p256::ecdh_shared_secret(&priv_key, peer);
            for byte in priv_key.iter_mut() {
                core::ptr::write_volatile(byte as *mut u8, 0);
            }
            match result {
                Some(shared) => {
                    let out = arg.add(4 + peer_len);
                    core::ptr::copy_nonoverlapping(shared.as_ptr(), out, 32);
                    0
                }
                None => crate::abi::errno::EINVAL,
            }
        }

        dev_key_vault::VERIFY => {
            // VERIFY is independent of the stored key — it takes a
            // caller-supplied public key in the peer field of the argument.
            // We accept: [hash_len:u16][sig_len:u16][pub_len:u16][pad:u16]
            //            [hash][sig][pub]. For backward compatibility with a
            //            simpler call (no pub embedded), fall back to ENOSYS.
            if arg.is_null() || arg_len < 8 {
                return EINVAL;
            }
            let hash_len = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
            let sig_len = u16::from_le_bytes([*arg.add(2), *arg.add(3)]) as usize;
            let pub_len = u16::from_le_bytes([*arg.add(4), *arg.add(5)]) as usize;
            if hash_len == 0
                || sig_len != 64
                || pub_len < 64
                || 8 + hash_len + sig_len + pub_len > arg_len
            {
                return EINVAL;
            }
            let hash = core::slice::from_raw_parts(arg.add(8), hash_len);
            let sig = core::slice::from_raw_parts(arg.add(8 + hash_len), sig_len);
            let pk = core::slice::from_raw_parts(arg.add(8 + hash_len + sig_len), pub_len);
            if p256::ecdsa_verify(pk, hash, sig) {
                1
            } else {
                0
            }
        }

        _ => ENOSYS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STORE -> handle returns a valid slot; key bytes are accepted but
    /// cannot be observed through any inspection API (no `provider_query`
    /// path exposes slot content).
    #[test]
    fn store_and_destroy_roundtrip() {
        unsafe {
            reset_all();
        }

        let mut buf = [0u8; 4 + 32];
        buf[0] = 1; // key_type = P-256 scalar
        buf[1] = 32; // key_len
        for i in 0..32 {
            buf[4 + i] = i as u8 + 1;
        }

        let handle =
            unsafe { provider_dispatch(-1, dev_key_vault::STORE, buf.as_mut_ptr(), buf.len()) };
        assert!(handle >= 0, "store should succeed, got {}", handle);
        let (tag, slot_idx) = fd::untag_fd(handle);
        assert_eq!(tag, fd::FD_TAG_KEY_VAULT);
        let slot_idx = slot_idx as usize;

        // No API path exposes the raw key. Confirm the slot holds our bytes
        // via the private accessor (test-only).
        unsafe {
            let slot = &SLOTS[slot_idx];
            assert_eq!(slot.key_len, 32);
            assert_eq!(slot.key_type, 1);
            for i in 0..32 {
                assert_eq!(slot.data[i], (i as u8) + 1);
            }
        }

        // Destroy wipes the bytes.
        let rc =
            unsafe { provider_dispatch(handle, dev_key_vault::DESTROY, core::ptr::null_mut(), 0) };
        assert_eq!(rc, 0);
        unsafe {
            let slot = &SLOTS[slot_idx];
            assert_eq!(slot.flags, 0);
            assert_eq!(slot.key_len, 0);
            for i in 0..32 {
                assert_eq!(slot.data[i], 0, "slot byte {} not wiped", i);
            }
        }
    }

    /// Slot-bound ops reject handles that aren't FD_TAG_KEY_VAULT-tagged,
    /// so a raw integer handle from another contract's allocator cannot
    /// be misrouted into this dispatcher.
    #[test]
    fn untagged_handle_rejected() {
        unsafe {
            reset_all();
        }
        let mut sign_arg = [0u8; 4 + 32 + 64];
        sign_arg[0] = 32;
        let rc = unsafe {
            provider_dispatch(
                0,
                dev_key_vault::SIGN,
                sign_arg.as_mut_ptr(),
                sign_arg.len(),
            )
        };
        assert_eq!(rc, EINVAL);
        let foreign = fd::tag_fd(fd::FD_TAG_EVENT, 0);
        let rc = unsafe {
            provider_dispatch(
                foreign,
                dev_key_vault::SIGN,
                sign_arg.as_mut_ptr(),
                sign_arg.len(),
            )
        };
        assert_eq!(rc, EINVAL);
    }

    #[test]
    fn slots_exhaust() {
        unsafe {
            reset_all();
        }
        let mut buf = [0u8; 4 + 4];
        buf[0] = 1;
        buf[1] = 4;
        let mut handles = [0i32; MAX_SLOTS];
        for i in 0..MAX_SLOTS {
            handles[i] =
                unsafe { provider_dispatch(-1, dev_key_vault::STORE, buf.as_mut_ptr(), buf.len()) };
            assert!(handles[i] >= 0);
        }
        // Next store must fail with ENOMEM.
        let over =
            unsafe { provider_dispatch(-1, dev_key_vault::STORE, buf.as_mut_ptr(), buf.len()) };
        assert_eq!(over, crate::abi::errno::ENOMEM);

        // Free one, confirm a new store fits.
        let rc = unsafe {
            provider_dispatch(handles[0], dev_key_vault::DESTROY, core::ptr::null_mut(), 0)
        };
        assert_eq!(rc, 0);
        let again =
            unsafe { provider_dispatch(-1, dev_key_vault::STORE, buf.as_mut_ptr(), buf.len()) };
        assert!(again >= 0);
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        use crate::kernel::crypto::p256;
        unsafe {
            reset_all();
        }

        // Deterministic test private key.
        let priv_key: [u8; 32] = [
            0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1,
            0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b,
            0x12, 0x0f, 0x67, 0x21,
        ];

        let mut store_arg = [0u8; 4 + 32];
        store_arg[0] = KEY_TYPE_P256_SCALAR;
        store_arg[1] = 32;
        store_arg[4..4 + 32].copy_from_slice(&priv_key);
        let handle = unsafe {
            provider_dispatch(
                -1,
                dev_key_vault::STORE,
                store_arg.as_mut_ptr(),
                store_arg.len(),
            )
        };
        assert!(handle >= 0);

        // Public key for the above private scalar (uncompressed 0x04 || X || Y).
        let pk = p256::public_key_from_scalar(&priv_key);

        // SIGN a known hash through the vault, then VERIFY with the public key.
        let hash = [0x42u8; 32];
        let mut sign_arg = [0u8; 4 + 32 + 64];
        sign_arg[0] = 32;
        sign_arg[4..4 + 32].copy_from_slice(&hash);
        let rc = unsafe {
            provider_dispatch(
                handle,
                dev_key_vault::SIGN,
                sign_arg.as_mut_ptr(),
                sign_arg.len(),
            )
        };
        assert_eq!(rc, 0);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sign_arg[4 + 32..]);

        // Cross-check with the kernel verify path.
        assert!(p256::ecdsa_verify(&pk, &hash, &sig));

        unsafe {
            provider_dispatch(handle, dev_key_vault::DESTROY, core::ptr::null_mut(), 0);
        }
    }

    #[test]
    fn probe_returns_present() {
        assert_eq!(
            unsafe { provider_dispatch(-1, dev_key_vault::PROBE, core::ptr::null_mut(), 0) },
            1,
        );
    }
}
