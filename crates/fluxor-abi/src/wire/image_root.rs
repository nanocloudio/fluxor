// The signing root item in a kernel image.
//
// A kernel image carries one 40-byte item: an 8-byte tag, then the 32-byte
// Ed25519 public key every module manifest and graph-slot header is verified
// against. The kernel is built with the key all zero, which is no root; the
// packager writes the key into the built image (`fluxor build --root`,
// `fluxor image root set`), so a build never bakes one in and one binary
// serves a rootless and a rooted device alike.
//
// The item is 64-byte aligned in the kernel image, so it never straddles a
// UF2 block's 256-byte payload, and the same scan finds it in an ELF, a raw
// binary, a PE image or a UF2. The scan is byte by byte: a UF2 payload sits
// 32 bytes into its block, so an aligned item is not aligned in the file.

/// `"FXRT"` then `"root"`: what opens the item.
pub const TAG: [u8; 8] = *b"FXRTroot";
/// Size of the item.
pub const SIZE: usize = 40;
/// Where the key starts in the item.
pub const KEY_AT: usize = 8;
/// Bytes of the key.
pub const KEY_LEN: usize = 32;
/// Alignment of the item in a kernel image.
pub const ALIGN: usize = 64;

/// Why an image's root item cannot be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemError {
    /// The image carries no item: it is not a kernel this layout describes.
    Missing,
    /// The image carries more than one: which one the kernel reads is not
    /// knowable from the bytes.
    Ambiguous,
}

/// The offset of the image's one root item.
pub fn find(image: &[u8]) -> Result<usize, ItemError> {
    let mut found = None;
    let mut at = 0;
    while at + SIZE <= image.len() {
        if image[at..at + TAG.len()] == TAG {
            if found.is_some() {
                return Err(ItemError::Ambiguous);
            }
            found = Some(at);
        }
        at += 1;
    }
    found.ok_or(ItemError::Missing)
}

/// The root an image carries: `None` for the all-zero key, which is no root.
pub fn read(image: &[u8]) -> Result<Option<[u8; KEY_LEN]>, ItemError> {
    let at = find(image)? + KEY_AT;
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&image[at..at + KEY_LEN]);
    Ok((key != [0u8; KEY_LEN]).then_some(key))
}

/// Write `root` into the image's item (`None` clears it).
pub fn write(image: &mut [u8], root: Option<[u8; KEY_LEN]>) -> Result<(), ItemError> {
    let at = find(image)? + KEY_AT;
    image[at..at + KEY_LEN].copy_from_slice(&root.unwrap_or([0u8; KEY_LEN]));
    Ok(())
}
