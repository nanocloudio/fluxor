//! The RP2350 IMAGE_DEF block.
//!
//! RP2350's bootrom will not run an image that does not carry one. It is a
//! small block of words in the first 4 KiB of flash saying what the image is:
//! executable rather than data, which architecture, which chip, and what
//! security posture it expects.
//!
//! # Why it is generated rather than written out
//!
//! Every field is a packed bitfield, and a wrong one is not a build error —
//! it is a bootrom that refuses the image, silently, at power-on. There is
//! nothing to read afterwards, because nothing ran.
//!
//! The security posture in particular must be preserved rather than chosen
//! afresh: an image declaring itself non-secure when the rest of the build
//! assumes secure does not fail loudly, it runs with a different view of the
//! address map.

/// The word the bootrom scans for.
pub const MARKER_START: u32 = 0xffff_ded3;
/// The word that closes the block.
pub const MARKER_END: u32 = 0xab12_3579;

/// Item types within a block.
mod item {
    /// Declares what kind of image this is. The `0x40` bit marks a
    /// one-byte-size item, which is how the bootrom knows how far to skip.
    pub const IMAGE_TYPE: u32 = 0x42;
    /// Closes the item list. `0x80 | 0x7f`.
    pub const LAST: u32 = 0xff;
}

/// `IMAGE_TYPE` field positions.
mod image_type {
    /// Image kind, bits 0..3.
    pub const KIND_LSB: u32 = 0;
    /// An executable image, as opposed to data.
    pub const KIND_EXE: u32 = 0x1;
    /// Security posture, bits 4..5.
    pub const SECURITY_LSB: u32 = 4;
    /// Secure. This build runs secure — it owns the whole part — and
    /// declaring otherwise would run it with a different view of the address
    /// map rather than failing.
    pub const SECURITY_SECURE: u32 = 0x2;
    /// CPU architecture, bits 8..10.
    pub const CPU_LSB: u32 = 8;
    /// Arm, as opposed to the RISC-V cores RP2350 also has.
    pub const CPU_ARM: u32 = 0;
    /// Chip, bits 12..14.
    pub const CHIP_LSB: u32 = 12;
    /// RP2350.
    pub const CHIP_RP2350: u32 = 1;
}

/// Words in the block.
pub const BLOCK_WORDS: usize = 5;

/// Build the `IMAGE_TYPE` item's flag half.
///
/// Separated from the block so the packing can be checked on a host against
/// the value a known-good image carries.
pub const fn image_type_flags() -> u32 {
    (image_type::KIND_EXE << image_type::KIND_LSB)
        | (image_type::SECURITY_SECURE << image_type::SECURITY_LSB)
        | (image_type::CPU_ARM << image_type::CPU_LSB)
        | (image_type::CHIP_RP2350 << image_type::CHIP_LSB)
}

/// The minimal IMAGE_DEF: start marker, an image-type item, the list
/// terminator, a self-relative link, and the end marker.
///
/// The link word is zero, which means "this block loops to itself" — a
/// single-block image. A non-zero value there points at another block, and a
/// wrong one sends the bootrom walking into whatever follows in flash.
pub const fn block() -> [u32; BLOCK_WORDS] {
    [
        MARKER_START,
        // One word of payload, so size = 1.
        item::IMAGE_TYPE | (1 << 8) | (image_type_flags() << 16),
        // The terminator also carries a size of one word.
        item::LAST | (1 << 8),
        0,
        MARKER_END,
    ]
}

/// The block, placed where the bootrom looks for it.
///
/// `.start_block` is the section the linker script puts in the first 4 KiB,
/// immediately after the vector table.
#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
#[unsafe(link_section = ".start_block")]
#[used]
#[no_mangle]
pub static IMAGE_DEF: [u32; BLOCK_WORDS] = block();
