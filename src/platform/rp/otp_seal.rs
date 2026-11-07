//! The RP2350's sealing key, in OTP.
//!
//! **Unproven on hardware.** Built and host-tested (the decision, the layout,
//! the derivation), never run against a real part: programming OTP is
//! irreversible. Confirm the page choice and the lock encodings against the
//! RP2350 datasheet (OTP chapter) on a sacrificial board before enabling
//! `rp-otp-provision` anywhere.
//!
//! # Layout
//!
//! One OTP page, [`SEAL_PAGE`], in the user area. Its first rows hold
//! [`SEAL_KEY_MAGIC`] then 32 bytes of key, ECC-protected (2 bytes a row):
//!
//! ```text
//! row base+0..2    "KSK1"
//! row base+2..18   key, 32 bytes from the TRNG
//! ```
//!
//! The magic is the provenance rule's guard against an unprogrammed or
//! mis-addressed read (`kernel::sys::seal_provenance`): blank OTP reads as
//! zeros, and a key whose magic is absent or whose 4-byte groups are blank is
//! no key.
//!
//! # Who can read it
//!
//! - **The bootloader (`picotool`, BOOTSEL) never.** Provisioning sets the
//!   page's permanent lock (`PAGEn_LOCK1`) so the bootloader and non-secure
//!   code cannot read it; only secure code — this kernel — can.
//! - **Modules never.** The kernel reads the key once, at first use (a seal,
//!   or the vault asking its provenance), keeps it in RAM, and then sets the page's software lock (`SW_LOCKn`) so
//!   nothing else in this boot reads it, secure or not. The lock clears only
//!   at reset.
//!
//! # Provisioning
//!
//! Only with the `rp-otp-provision` feature, which no shipped image carries:
//! a board whose page is blank gets a fresh key from the TRNG, then the magic,
//! then the lock. The page is read back afterwards and only what it holds
//! decides. A run cut short leaves the page partly programmed, which the
//! provenance rule refuses (blank groups), and the board seals nothing.

use crate::kernel::security::crypto::sha256::Sha256;
use crate::kernel::sys::hal::{provenance_from_hardware_key, SealProvenance, SEAL_KEY_MAGIC};

/// The OTP page holding the seal key: 64 rows from `SEAL_PAGE * 64`.
pub const SEAL_PAGE: u16 = 32;
/// First row of the page.
pub const SEAL_ROW: u16 = SEAL_PAGE * 64;
/// Bytes of key material.
pub const KEY_BYTES: usize = 32;
/// Bytes read: the magic and the key.
pub const BLOB_BYTES: usize = SEAL_KEY_MAGIC.len() + KEY_BYTES;
/// ECC rows the blob spans (2 bytes a row).
pub const BLOB_ROWS: u16 = (BLOB_BYTES / 2) as u16;

/// `otp_access` command bits.
pub mod cmd {
    pub const ROW_MASK: u32 = 0xFFFF;
    pub const WRITE: u32 = 1 << 16;
    pub const ECC: u32 = 1 << 17;
}

/// The permanent lock row of `page`: `PAGEn_LOCK1`, at `0xF81 + 2n`.
pub const fn page_lock1_row(page: u16) -> u16 {
    0xF81 + 2 * page
}

/// `PAGEn_LOCK1` for a page only secure code may read: the bootloader
/// (bits 5:4) and non-secure code (bits 3:2) locked out (3, inaccessible),
/// secure (bits 1:0) read-only (1).
pub const LOCK1_SECURE_ONLY: u8 = (3 << 4) | (3 << 2) | 1;

/// A raw lock row as `otp_access` writes it: the byte three times over (the
/// lock rows are triple-redundant, not ECC), padded to a 4-byte row.
pub const fn lock_row_bytes(v: u8) -> [u8; 4] {
    [v, v, v, 0]
}

/// The working seal key from a blob the provenance rule accepted: the raw key
/// expanded under this platform's context, as the rule asks.
pub fn derive_key(blob: &[u8; BLOB_BYTES]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"fluxor/seal/rp2350/v1");
    h.update(&blob[SEAL_KEY_MAGIC.len()..]);
    h.finalize()
}

/// What a read of the page is worth, and the key when it is one.
pub fn decide(read_ok: bool, blob: &[u8; BLOB_BYTES]) -> (SealProvenance, Option<[u8; 32]>) {
    let p = provenance_from_hardware_key(read_ok, blob);
    match p {
        SealProvenance::DeviceUnique => (p, Some(derive_key(blob))),
        _ => (p, None),
    }
}

#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
pub use hw::*;

#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
mod hw {
    use super::*;
    use core::sync::atomic::{AtomicU8, Ordering};

    /// `OTP.SW_LOCK0`: one register per page, 4 bytes apart.
    const OTP_SW_LOCK0: usize = 0x4012_0000;
    /// `SW_LOCKn` value: secure (1:0) and non-secure (3:2) inaccessible.
    const SW_LOCK_INACCESSIBLE: u32 = 0xF;

    /// Not read yet.
    const UNREAD: u8 = 0;
    /// Read: [`KEY`] holds the key.
    const KEYED: u8 = 1;
    /// Read: no key.
    const KEYLESS: u8 = 2;
    /// One caller is reading the page; the rest wait for its answer.
    const READING: u8 = 3;
    static STATE: AtomicU8 = AtomicU8::new(UNREAD);
    static mut KEY: [u8; 32] = [0; 32];

    fn read_blob(blob: &mut [u8; BLOB_BYTES]) -> bool {
        let Some(access) = crate::platform::rp_bootrom::otp_access_fn() else {
            return false;
        };
        // SAFETY: a bootrom read of rows this kernel owns into `blob`.
        let rc = unsafe {
            access(
                blob.as_mut_ptr(),
                BLOB_BYTES as u32,
                u32::from(SEAL_ROW) | cmd::ECC,
            )
        };
        rc == 0
    }

    /// Nothing else this boot reads the page.
    fn soft_lock() {
        let reg = (OTP_SW_LOCK0 + 4 * SEAL_PAGE as usize) as *mut u32;
        // SAFETY: the OTP block's own lock register; a lock only advances.
        unsafe { core::ptr::write_volatile(reg, SW_LOCK_INACCESSIBLE) };
    }

    /// Program a fresh key into a blank page, then lock it. `blob` holds what
    /// was read; it is used as scratch for the rows written.
    #[cfg(feature = "rp-otp-provision")]
    fn provision(blob: &mut [u8; BLOB_BYTES]) {
        // Only a blank page: a partly programmed one is a failure to report,
        // never one to write over.
        if blob.iter().any(|&b| b != 0) {
            return;
        }
        let Some(access) = crate::platform::rp_bootrom::otp_access_fn() else {
            return;
        };
        let mut key = [0u8; KEY_BYTES];
        if crate::kernel::sys::hal::csprng_fill(key.as_mut_ptr(), KEY_BYTES) != 0 {
            return;
        }
        blob[..4].copy_from_slice(&SEAL_KEY_MAGIC);
        blob[4..].copy_from_slice(&key);
        key.fill(0);
        let mut lock = lock_row_bytes(LOCK1_SECURE_ONLY);
        // SAFETY: bootrom writes of rows in this kernel's page and its lock.
        let ok = unsafe {
            // The key first, the magic last of the data: a cut leaves no magic.
            access(
                blob.as_mut_ptr().add(4),
                KEY_BYTES as u32,
                u32::from(SEAL_ROW + 2) | cmd::ECC | cmd::WRITE,
            ) == 0
                && access(
                    blob.as_mut_ptr(),
                    4,
                    u32::from(SEAL_ROW) | cmd::ECC | cmd::WRITE,
                ) == 0
                && access(
                    lock.as_mut_ptr(),
                    4,
                    u32::from(page_lock1_row(SEAL_PAGE)) | cmd::WRITE,
                ) == 0
        };
        log::warn!("[seal] OTP seal key provisioned (page {SEAL_PAGE}): ok={ok}");
    }

    /// The seal key, read (and on a provisioning build, made) once. The
    /// first caller reads the page and soft-locks it; a caller on the other
    /// core meanwhile waits for that answer rather than read a locked page.
    pub fn key() -> Option<[u8; 32]> {
        loop {
            match STATE.compare_exchange(UNREAD, READING, Ordering::Acquire, Ordering::Acquire) {
                Ok(_) => break,
                // SAFETY: written once, before STATE published KEYED.
                Err(KEYED) => return Some(unsafe { *core::ptr::addr_of!(KEY) }),
                Err(KEYLESS) => return None,
                Err(_) => core::hint::spin_loop(),
            }
        }
        let mut blob = [0u8; BLOB_BYTES];
        let ok = read_blob(&mut blob);
        // What decides is always what the page holds: provisioning builds its
        // rows in `blob`, and a write that failed part-way must not leave a
        // key in RAM that the page lacks.
        #[cfg(feature = "rp-otp-provision")]
        let ok = ok && {
            provision(&mut blob);
            blob.fill(0);
            read_blob(&mut blob)
        };
        let (p, key) = decide(ok, &blob);
        blob.fill(0);
        soft_lock();
        match key {
            Some(k) => {
                // SAFETY: only the caller holding READING writes KEY, once,
                // before STATE publishes it.
                unsafe { *core::ptr::addr_of_mut!(KEY) = k };
                STATE.store(KEYED, Ordering::Release);
                log::info!("[seal] OTP seal key: keys sealed (unproven on hardware)");
            }
            None => {
                STATE.store(KEYLESS, Ordering::Release);
                log::info!("[seal] no OTP seal key ({p:?}): nothing is sealed");
            }
        }
        key
    }

    /// `HalOps::seal_provenance`.
    pub fn provenance() -> SealProvenance {
        if key().is_some() {
            SealProvenance::DeviceUnique
        } else {
            SealProvenance::None
        }
    }
}
