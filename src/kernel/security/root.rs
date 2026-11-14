//! The signing root: the one Ed25519 public key every module manifest and
//! every graph-slot header is verified against.
//!
//! It lives in the kernel image as a 40-byte item (`abi::wire::image_root`)
//! that the packager writes after link (`fluxor build --root`, `fluxor image
//! root set`). The kernel is built with the key all zero, which is no root:
//! the loader then verifies nothing and says so once at boot. With a root,
//! a module whose signature does not verify is refused, and an unsigned one
//! runs gated or not at all; a graph image must carry a signature by it.
//!
//! What binds the image to the device is the target's boot chain (RP2350
//! secure boot, Pi 5 signed boot, UEFI Secure Boot, the Linux binary's
//! provenance), not this item.

use crate::abi::wire::image_root as item;

/// The item as the image lays it out. Aligned so it never straddles a UF2
/// block's payload.
#[repr(C, align(64))]
struct RootItem {
    tag: [u8; 8],
    key: [u8; item::KEY_LEN],
}

/// The image's root item; the packager overwrites `key`.
#[used]
static ROOT: RootItem = RootItem {
    tag: item::TAG,
    key: [0; item::KEY_LEN],
};

/// The root written into this kernel image, or `None` for the all-zero key.
/// Each platform's HAL answers `signing_root` with it.
pub fn image_root() -> Option<[u8; 32]> {
    // SAFETY: an aligned read of an initialised static. Volatile, so the key
    // is read from the image the packager wrote rather than folded to the
    // zeros it was compiled with.
    let key = unsafe { core::ptr::read_volatile(&raw const ROOT.key) };
    (key != [0; item::KEY_LEN]).then_some(key)
}

/// The signing root modules and graph images are verified against.
pub fn signing_root() -> Option<[u8; 32]> {
    crate::kernel::sys::hal::signing_root()
}

/// Say once, at boot, what this kernel verifies.
pub fn log_signing_root() {
    match signing_root() {
        Some(k) => log::info!(
            "signing: root {:02x}{:02x}{:02x}{:02x}",
            k[0],
            k[1],
            k[2],
            k[3]
        ),
        None => log::warn!("signing: no root; modules unverified"),
    }
}
