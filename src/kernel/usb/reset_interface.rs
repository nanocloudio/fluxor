//! The reset interface `picotool` looks for on a running device.
//!
//! A vendor-class interface with no endpoints, identified by its class
//! triple (`0xff` / `0x00` / `0x01`). `picotool reboot -f` and `picotool
//! load -f` find it by scanning the configuration's interfaces and then
//! send one class request to it: reboot into BOOTSEL, or reboot into the
//! application. That is what turns a board with no debug probe into a rig:
//! flashing and rebooting become host commands.
//!
//! Requests are `bmRequestType 0x21` (host-to-device, class, interface) with
//! `wIndex` naming this interface and no data stage. The request is
//! acknowledged first and acted on after — picotool's own source notes that
//! rebooting inside the setup handler makes libusb return "fairly
//! unpredictable errors".
//!
//! Layout and codes are from `pico-sdk`'s `reset_interface.h` and
//! `picotool`'s `reboot_device`.

/// `bInterfaceClass`: vendor-specific.
pub const CLASS: u8 = 0xff;
/// `bInterfaceSubClass`, as picotool matches it.
pub const SUBCLASS: u8 = 0x00;
/// `bInterfaceProtocol`, as picotool matches it.
pub const PROTOCOL: u8 = 0x01;

/// Request codes (pico-sdk `reset_interface.h`).
pub mod request {
    /// Reboot into the ROM bootloader (BOOTSEL).
    pub const BOOTSEL: u8 = 0x01;
    /// Reboot into the application in flash.
    pub const FLASH: u8 = 0x02;
}

/// `wValue` bits of a BOOTSEL request (pico-sdk `reset_interface.c`).
pub mod bootsel_value {
    /// Bits 0-6: BOOTSEL interface-disable mask. Bit 0 hides the USB mass
    /// storage volume; bit 1 would hide PICOBOOT, which picotool needs.
    pub const INTERFACE_DISABLE_MASK: u16 = 0x7f;
    /// Bit 0 of that mask.
    pub const DISABLE_MSD: u16 = 0x01;
    /// Set when bits 9+ carry an activity-LED GPIO number.
    pub const GPIO_SPECIFIED: u16 = 0x100;
}

/// What the host asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebootRequest {
    /// Into BOOTSEL. `disable_msd` hides the drag-and-drop volume, which a
    /// rig wants: an appearing drive triggers automounters and indexers.
    Bootsel { disable_msd: bool },
    /// Into the application in flash.
    Flash,
}

/// Decode a class request addressed to the reset interface, or `None` for
/// anything that is not one.
pub fn decode(request: u8, value: u16) -> Option<RebootRequest> {
    match request {
        request::BOOTSEL => Some(RebootRequest::Bootsel {
            disable_msd: value & bootsel_value::DISABLE_MSD != 0,
        }),
        request::FLASH => Some(RebootRequest::Flash),
        _ => None,
    }
}
