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
            // Layout: `[hash_len:u16][sig_len:u16][pub_len:u16][pad:u16]
            // [hash][sig][pub]`. v1 has only this shape; shorter
            // payloads are rejected as EINVAL.
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
