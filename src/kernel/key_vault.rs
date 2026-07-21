//! KEY_VAULT device class — the kernel *software backend* for the
//! `key_vault` contract (kernel-managed asymmetric-key slots).
//!
//! Callers STORE or GENERATE a private key and receive an opaque handle.
//! The raw bytes live in kernel static memory and are never returned to
//! callers. Keys are zeroised on DESTROY and on scheduler reset.
//!
//! ECDH, SIGN and VERIFY run the kernel P-256 / Ed25519 primitives
//! directly: the vault is authoritative for any slot holding private
//! key material.
//!
//! This is the platform-overridable *default* backend
//! (rfc_crypto_extensions §4.1): a hardware platform may re-register both the
//! KEY_VAULT class dispatch and its vtable at platform boot (e.g. the
//! Linux PKCS#11 backend), swapping custody transparently behind the
//! same contract. Isolation honesty: this backend reports
//! `TIER = SOFTWARE` — kernel static memory isolates against a
//! compromised *module*, not a compromised host/kernel.
use crate::abi::contracts::key_vault as dev_key_vault;
use crate::abi::errno::{EINVAL, ENOSYS, ERROR};
use crate::kernel::crypto::{ed25519, p256};
use crate::kernel::fd;
/// P-256 raw-scalar key type, as passed in the STORE `key_type` byte.
const KEY_TYPE_P256_SCALAR: u8 = 1;
/// Ed25519 raw-seed key type (RFC 8032), STORE/GENERATE `key_type` 2.
const KEY_TYPE_ED25519_SEED: u8 = 2;
/// P-256 group order n (big-endian) — GENERATE rejection-samples the
/// scalar into [1, n-1] because `p256::ecdsa_sign` uses the scalar
/// unreduced while `public_key_from_scalar` reduces mod n; only an
/// in-range scalar is interpreted identically by both.
const P256_ORDER_BE: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];
/// CAPS bitmap for the software backend: everything this file
/// implements. `NON_EXTRACTABLE` stays clear — software keys are
/// extractable-in-principle by the host, so the backend must not
/// advertise a guarantee it cannot enforce.
const SOFTWARE_CAPS: u32 = dev_key_vault::caps::GENERATE
    | dev_key_vault::caps::PUBLIC
    | dev_key_vault::caps::STORE_IMPORT
    | dev_key_vault::caps::ALG_P256
    | dev_key_vault::caps::ALG_ED25519;
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
/// True iff `k` (big-endian) is a valid P-256 scalar: 1 <= k < n.
fn p256_scalar_in_range(k: &[u8; 32]) -> bool {
    // Big-endian compare against the group order: first differing
    // byte decides. Not constant-time — a rejected sample is never
    // used, and an accepted one reveals only "in range".
    let mut less_than_n = false;
    for i in 0..32 {
        if k[i] < P256_ORDER_BE[i] {
            less_than_n = true;
            break;
        }
        if k[i] > P256_ORDER_BE[i] {
            return false;
        }
    }
    less_than_n && k.iter().any(|&b| b != 0)
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
        // Global (handle=-1) ops: anything not listed here must carry a
        // FD_TAG_KEY_VAULT-tagged slot handle or is rejected with EINVAL.
        dev_key_vault::PROBE
        | dev_key_vault::STORE
        | dev_key_vault::VERIFY
        | dev_key_vault::GENERATE
        | dev_key_vault::CAPS
        | dev_key_vault::TIER => handle,
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
            if arg.is_null() || arg_len < 4 {
                return EINVAL;
            }
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            let slot = &SLOTS[slot_handle as usize];
            if (slot.flags & FLAG_IN_USE) == 0 || slot.key_len != 32 {
                return EINVAL;
            }
            let hash_len = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
            if hash_len == 0 || 4 + hash_len + 64 > arg_len {
                return EINVAL;
            }
            let mut priv_key = [0u8; 32];
            priv_key.copy_from_slice(&slot.data[..32]);
            let sig = match slot.key_type {
                KEY_TYPE_P256_SCALAR => {
                    // ECDSA over a caller-supplied digest, at most 64 bytes.
                    if hash_len > 64 {
                        for byte in priv_key.iter_mut() {
                            core::ptr::write_volatile(byte as *mut u8, 0);
                        }
                        return EINVAL;
                    }
                    let hash = core::slice::from_raw_parts(arg.add(4), hash_len);
                    // RFC 6979 derives its nonce deterministically; the
                    // `_random` arg on ecdsa_sign is unused.
                    p256::ecdsa_sign(&priv_key, hash, &[0u8; 32])
                }
                KEY_TYPE_ED25519_SEED => {
                    // Ed25519 is not prehashed: the `hash` field carries
                    // the whole message (any length the arg buffer fits).
                    let msg = core::slice::from_raw_parts(arg.add(4), hash_len);
                    ed25519::sign(&priv_key, msg)
                }
                _ => {
                    for byte in priv_key.iter_mut() {
                        core::ptr::write_volatile(byte as *mut u8, 0);
                    }
                    return EINVAL;
                }
            };
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
        dev_key_vault::GENERATE => {
            // arg layout: [key_type:u8][flags:u8][pad:u16][pub_out[N]]
            if arg.is_null() || arg_len < 4 {
                return EINVAL;
            }
            let key_type = *arg;
            // Byte 1 is `generate_flags`: bit 0 requests non-extractable.
            // The software backend cannot enforce it (its CAPS
            // NON_EXTRACTABLE bit is clear) — callers that require the
            // guarantee check CAPS, so the flag is accepted and ignored.
            let pub_len: usize = match key_type {
                KEY_TYPE_P256_SCALAR => 65,
                KEY_TYPE_ED25519_SEED => 32,
                _ => return EINVAL,
            };
            if 4 + pub_len > arg_len {
                return EINVAL;
            }
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
            let mut key = [0u8; 32];
            match key_type {
                KEY_TYPE_P256_SCALAR => {
                    // Rejection-sample into [1, n-1]; each retry has
                    // ~2^-32 probability, so the bound is unreachable in
                    // practice and exists only to make the loop finite.
                    let mut in_range = false;
                    for _ in 0..128 {
                        if crate::kernel::hal::csprng_fill(key.as_mut_ptr(), 32) != 0 {
                            return ERROR;
                        }
                        if p256_scalar_in_range(&key) {
                            in_range = true;
                            break;
                        }
                    }
                    if !in_range {
                        return ERROR;
                    }
                    let pk = p256::public_key_from_scalar(&key);
                    core::ptr::copy_nonoverlapping(pk.as_ptr(), arg.add(4), 65);
                }
                _ => {
                    // Ed25519: any 32-byte seed is valid (RFC 8032).
                    if crate::kernel::hal::csprng_fill(key.as_mut_ptr(), 32) != 0 {
                        return ERROR;
                    }
                    let pk = ed25519::public_key(&key);
                    core::ptr::copy_nonoverlapping(pk.as_ptr(), arg.add(4), 32);
                }
            }
            SLOTS[idx].key_type = key_type;
            SLOTS[idx].key_len = 32;
            for (j, b) in key.iter().enumerate() {
                core::ptr::write_volatile(&raw mut SLOTS[idx].data[j], *b);
            }
            for byte in key.iter_mut() {
                core::ptr::write_volatile(byte as *mut u8, 0);
            }
            // Mark in-use last so partial fills can't be observed.
            SLOTS[idx].flags = FLAG_IN_USE;
            fd::tag_fd(fd::FD_TAG_KEY_VAULT, idx as i32)
        }
        dev_key_vault::PUBLIC => {
            // arg layout: [pub_out[N]], N fixed by the slot's key_type.
            if arg.is_null() {
                return EINVAL;
            }
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            let slot = &SLOTS[slot_handle as usize];
            if (slot.flags & FLAG_IN_USE) == 0 || slot.key_len != 32 {
                return EINVAL;
            }
            let mut priv_key = [0u8; 32];
            priv_key.copy_from_slice(&slot.data[..32]);
            let rc = match slot.key_type {
                KEY_TYPE_P256_SCALAR if arg_len >= 65 => {
                    let pk = p256::public_key_from_scalar(&priv_key);
                    core::ptr::copy_nonoverlapping(pk.as_ptr(), arg, 65);
                    0
                }
                KEY_TYPE_ED25519_SEED if arg_len >= 32 => {
                    let pk = ed25519::public_key(&priv_key);
                    core::ptr::copy_nonoverlapping(pk.as_ptr(), arg, 32);
                    0
                }
                _ => EINVAL,
            };
            for byte in priv_key.iter_mut() {
                core::ptr::write_volatile(byte as *mut u8, 0);
            }
            rc
        }
        dev_key_vault::TIER => {
            // Isolation honesty (rfc_crypto_extensions §3.5): kernel
            // static slots isolate against a compromised module, not a
            // compromised host/kernel.
            if arg.is_null() || arg_len < 1 {
                return EINVAL;
            }
            *arg = dev_key_vault::tier::SOFTWARE;
            1
        }
        dev_key_vault::CAPS => {
            if arg.is_null() || arg_len < 4 {
                return EINVAL;
            }
            let bytes = SOFTWARE_CAPS.to_le_bytes();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), arg, 4);
            4
        }
        _ => ENOSYS,
    }
}
