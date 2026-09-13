//! USB device identity: VID/PID policy, descriptors and stable serials.
//!
//! # The VID/PID policy is the point
//!
//! A USB vendor ID is assigned to an organisation, and a device that reports
//! one it was not assigned is claiming to be someone else's product. Hosts
//! act on that: udev rules, driver bindings and firmware-update tools all key
//! off VID/PID, so a squatted identifier can cause a host to apply another
//! vendor's driver or update policy to this board.
//!
//! So an identity is only [`Identity::is_shippable`] once it has been
//! *admitted*: declared as an allocation the project is entitled to use.
//! The one built in is the pico-sdk's "stdio over USB" pair, which Raspberry
//! Pi publishes for applications running on its boards and which `picotool`
//! keys off; an RP build is entitled to it, so it is admitted.
//!
//! # Serials
//!
//! A serial is what makes two attached boards individually addressable, which
//! is what a multi-board rig needs. It must be
//! stable across reboots — a random one per boot makes every reconnect look
//! like a different device and breaks any rule written against it — and
//! distinct between boards.
//!
//! The chip's unique ID satisfies both. Deriving the string from it is here;
//! reading it is the platform's.

/// Raspberry Pi's vendor ID.
///
/// Not a claim to be a Raspberry Pi product: it is the identity `picotool`
/// requires of a running board before it will drive the reset interface.
/// picotool applies its vendor/product filter to *every* device it looks at,
/// including the ROM's BOOTSEL device it waits for after asking a board to
/// reboot — so a board under any other vendor ID can be told to reboot but
/// never found again, and `--vid`/`--pid` cannot fix that because they
/// filter the BOOTSEL device out too. With this pair, `picotool load -f`
/// against a running board is one command, which is what makes a board
/// with no debug probe a rig.
pub const PICO_SDK_VENDOR_ID: u16 = 0x2e8a;
/// The pico-sdk's "stdio over USB" product ID, which picotool classifies as
/// a running application it may reset (`PRODUCT_ID_STDIO_USB`).
pub const PICO_SDK_PRODUCT_ID: u16 = 0x000a;

/// Characters in a serial derived from a 64-bit unique ID.
pub const SERIAL_LEN: usize = 16;

/// A device's USB identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Vendor ID.
    pub vendor_id: u16,
    /// Product ID.
    pub product_id: u16,
    /// Device release, BCD.
    pub device_release: u16,
    /// Whether the project is entitled to this allocation.
    pub admitted: bool,
}

impl Default for Identity {
    fn default() -> Self {
        Self::pico_sdk()
    }
}

impl Identity {
    /// The pico-sdk's "stdio over USB" identity, admitted for RP boards.
    pub const fn pico_sdk() -> Self {
        Self {
            vendor_id: PICO_SDK_VENDOR_ID,
            product_id: PICO_SDK_PRODUCT_ID,
            device_release: 0x0100,
            admitted: true,
        }
    }

    /// Whether this identity may appear on a shipped device.
    ///
    /// False for any identity not explicitly admitted, and for the zero
    /// identifier, which is no identifier at all. Reporting a vendor ID that
    /// was not assigned to this project is claiming to be another vendor's
    /// product, and hosts act on that — udev rules, driver binding and
    /// firmware-update tooling all key off VID/PID.
    pub const fn is_shippable(&self) -> bool {
        self.admitted && self.vendor_id != 0 && self.product_id != 0
    }
}

/// Render a 64-bit unique ID as a stable, uppercase-hex serial.
///
/// Uppercase because the USB specification calls for it in serial strings and
/// some hosts compare case-sensitively; fixed-width because a serial that
/// changes length between boards makes host-side matching rules fragile.
///
/// Deterministic: the same chip produces the same serial every boot, which is
/// what lets a rig address one board out of several.
pub fn serial_from_unique_id(id: u64) -> [u8; SERIAL_LEN] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = [b'0'; SERIAL_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        // Most-significant nibble first, so the string reads in the same
        // order as the number.
        let shift = 4 * (SERIAL_LEN - 1 - i);
        *slot = HEX[((id >> shift) & 0xf) as usize];
    }
    out
}

/// Encode an ASCII string as a USB string descriptor (UTF-16LE, with the
/// two-byte header).
///
/// Returns how many bytes were written, or `None` if the result would not
/// fit. `bLength` is one byte, so a string descriptor cannot exceed 255
/// bytes — 126 characters — and a caller that assumed otherwise would
/// silently truncate the length field rather than the string.
pub fn encode_string_descriptor(s: &[u8], out: &mut [u8]) -> Option<usize> {
    let len = 2 + s.len() * 2;
    if len > 255 || len > out.len() {
        return None;
    }
    out[0] = len as u8;
    out[1] = super::descriptor::desc_type::STRING;
    for (i, &c) in s.iter().enumerate() {
        // ASCII only: a byte above 0x7f is not a valid UTF-16 code unit on
        // its own, and guessing an encoding for it would produce a different
        // string on the host than the one intended.
        out[2 + i * 2] = if c.is_ascii() { c } else { b'?' };
        out[3 + i * 2] = 0;
    }
    Some(len)
}

/// The language-ID string descriptor (index 0), declaring US English.
///
/// Every device needs this before any other string can be fetched: the host
/// asks for index 0 first and uses the language it returns for every
/// subsequent request.
pub const LANG_ID_DESCRIPTOR: [u8; 4] = [
    0x04,
    super::descriptor::desc_type::STRING,
    0x09,
    0x04, // 0x0409, English (United States)
];
