//! The device-side descriptor set for a CDC ACM function.
//!
//! [`descriptor`](crate::kernel::usb::descriptor) reads descriptors that
//! somebody else wrote — it is the host side, used when this kernel is the
//! one enumerating a peripheral. This module is the other direction: the
//! bytes this device sends when a host asks what it is.
//!
//! # Why these are const arrays and not a builder
//!
//! [`DevicePump::step`](crate::kernel::usb::device::DevicePump::step) asks for
//! `&'static [u8]` at the moment a `GET_DESCRIPTOR` arrives, because that is
//! the only point at which the answer can neither be discarded by the SETUP
//! that follows nor arrive after the first packet has gone out. A static
//! table is what that signature wants, and a descriptor set that never varies
//! at runtime has nothing to gain from being assembled.
//!
//! The one exception is the serial string, which is per-board and is built
//! from the chip's unique ID — [`serial_descriptor`] fills a caller-owned
//! buffer rather than returning a static, because there is nothing static
//! about it.
//!
//! # What the host does with these, in order
//!
//! A host enumerating a device asks, roughly: device descriptor (8 bytes,
//! to learn `bMaxPacketSize0`), bus reset, `SET_ADDRESS`, device descriptor
//! again in full, configuration descriptor (9 bytes, to learn
//! `wTotalLength`), configuration descriptor again in full, then strings.
//! Every one of those must be answered or enumeration stops there. A request
//! this module has no answer for is a STALL, and a host that is stalled on
//! any of them abandons the device: it asked what this was, heard nothing,
//! and left.
//!
//! # The composite layout is not optional
//!
//! A CDC ACM function is **two** interfaces — a communications interface
//! carrying the class-specific functional descriptors and an interrupt
//! endpoint, and a data interface carrying the two bulk endpoints. They are
//! bound together by the Union functional descriptor. A host driver that
//! finds one without the other does not bind, so the set below is a package
//! rather than a menu.

use super::descriptor::desc_type;
use super::identity::{
    encode_string_descriptor, serial_from_unique_id, LANG_ID_DESCRIPTOR, PICO_SDK_PRODUCT_ID,
    PICO_SDK_VENDOR_ID,
};
use super::reset_interface as reset;

/// Endpoint addresses this function uses.
///
/// **These are a contract with the device controller, not a preference.** The
/// host is told here which endpoints to talk to, and it will. An address
/// declared here that the controller has not configured is a promise the
/// hardware does not keep: the port opens, the write succeeds as far as the
/// host is concerned, and the bytes go nowhere.
pub mod endpoint {
    /// Notification endpoint (interrupt IN) on the communications interface.
    /// A communications interface must declare one for the descriptor set to
    /// be valid. It is where `SERIAL_STATE` would go; this function has no
    /// modem state to report and leaves it idle, which a host reads as a line
    /// whose state never changes.
    pub const NOTIFICATION_IN: u8 = 0x81;
    /// Bulk OUT — host to device.
    pub const DATA_OUT: u8 = 0x02;
    /// Bulk IN — device to host.
    pub const DATA_IN: u8 = 0x82;

    /// Notification endpoint packet size. Eight bytes holds a
    /// `SERIAL_STATE` notification exactly.
    pub const NOTIFICATION_MAX_PACKET: u16 = 8;
    /// Bulk endpoint packet size. Full speed permits 8, 16, 32 or 64; 64 is
    /// the only one worth using for a console.
    pub const DATA_MAX_PACKET: u16 = 64;
    /// Polling interval for the notification endpoint. `bInterval` counts
    /// frames, which are a millisecond each at full speed.
    pub const NOTIFICATION_INTERVAL_FRAMES: u8 = 16;
}

/// Class, subclass and protocol codes.
mod class {
    /// Communications Device Class, on the interface that describes it.
    pub const CDC: u8 = 0x02;
    /// Abstract Control Model.
    pub const ACM_SUBCLASS: u8 = 0x02;
    /// No class-specific protocol. **Not `0x01` (AT commands)** — that tells
    /// a host this is a modem, and some will try to talk to it as one.
    pub const NO_PROTOCOL: u8 = 0x00;
    /// CDC Data interface.
    pub const CDC_DATA: u8 = 0x0a;
    /// Declared on the *device* descriptor so the host looks at the
    /// interface association rather than assuming a single function.
    pub const DEVICE_MISCELLANEOUS: u8 = 0xef;
    /// Common class, on the device descriptor.
    pub const DEVICE_COMMON_SUBCLASS: u8 = 0x02;
    /// Interface Association Descriptor protocol, on the device descriptor.
    pub const DEVICE_IAD_PROTOCOL: u8 = 0x01;
}

/// Class-specific descriptor types and subtypes.
mod cs {
    /// `CS_INTERFACE`.
    pub const INTERFACE: u8 = 0x24;
    /// Header functional descriptor.
    pub const SUBTYPE_HEADER: u8 = 0x00;
    /// Call Management functional descriptor.
    pub const SUBTYPE_CALL_MANAGEMENT: u8 = 0x01;
    /// Abstract Control Management functional descriptor.
    pub const SUBTYPE_ACM: u8 = 0x02;
    /// Union functional descriptor.
    pub const SUBTYPE_UNION: u8 = 0x06;
    /// Interface Association Descriptor. A standard descriptor type rather
    /// than a class-specific one, kept here because the composite layout it
    /// declares exists only to bind the two interfaces below together.
    pub const INTERFACE_ASSOCIATION: u8 = 0x0b;
}

/// Endpoint transfer types, in `bmAttributes`.
mod transfer {
    /// Bulk.
    pub const BULK: u8 = 0x02;
    /// Interrupt.
    pub const INTERRUPT: u8 = 0x03;
}

/// Interface numbers. The Union descriptor names these, so they are written
/// once here and referenced rather than repeated as literals.
pub mod interface_number {
    /// Communications interface.
    pub const COMM: u8 = 0;
    /// Data interface.
    pub const DATA: u8 = 1;
    /// The reset interface picotool drives. No endpoints; found by its
    /// class triple, addressed by this number in `wIndex`.
    pub const RESET: u8 = 2;
    /// How many this configuration declares.
    pub const COUNT: u8 = 3;
}

/// String descriptor indices. Index 0 is the language list, which is not a
/// string.
pub mod string_index {
    /// Manufacturer.
    pub const MANUFACTURER: u8 = 1;
    /// Product.
    pub const PRODUCT: u8 = 2;
    /// Serial number.
    pub const SERIAL: u8 = 3;
}

/// `bMaxPacketSize0`. The control endpoint's packet size, which the host
/// reads out of the first eight bytes of the device descriptor before it
/// knows anything else.
pub const EP0_MAX_PACKET: u8 = 64;

/// USB 2.0, BCD.
const USB_VERSION_BCD: u16 = 0x0200;
/// This function's release, BCD.
const DEVICE_RELEASE_BCD: u16 = 0x0100;

/// Power draw declared to the host, in 2 mA units. 100 mA is the most a
/// device may draw before it has been configured, so it is what an
/// unconfigured bus-powered board is entitled to ask for.
const MAX_POWER_2MA: u8 = 50;

/// `bmAttributes` for the configuration: bus-powered, no remote wakeup. Bit 7
/// is reserved and must be set.
const CONFIG_ATTRIBUTES: u8 = 0x80;

/// The device descriptor.
///
/// Declared as a **miscellaneous / common / IAD** device rather than
/// `class::CDC`. Putting the CDC class on the device descriptor tells the
/// host the whole device is one CDC function, which forecloses ever adding a
/// second function beside it; the IAD triple says "read the interface
/// associations" and costs nothing now.
pub const DEVICE: [u8; 18] = [
    18,                            // bLength
    desc_type::DEVICE,             // bDescriptorType
    lo(USB_VERSION_BCD),           // bcdUSB
    hi(USB_VERSION_BCD),           //
    class::DEVICE_MISCELLANEOUS,   // bDeviceClass
    class::DEVICE_COMMON_SUBCLASS, // bDeviceSubClass
    class::DEVICE_IAD_PROTOCOL,    // bDeviceProtocol
    EP0_MAX_PACKET,                // bMaxPacketSize0
    lo(PICO_SDK_VENDOR_ID),        // idVendor
    hi(PICO_SDK_VENDOR_ID),        //
    lo(PICO_SDK_PRODUCT_ID),       // idProduct
    hi(PICO_SDK_PRODUCT_ID),       //
    lo(DEVICE_RELEASE_BCD),        // bcdDevice
    hi(DEVICE_RELEASE_BCD),        //
    string_index::MANUFACTURER,    // iManufacturer
    string_index::PRODUCT,         // iProduct
    // The serial is the chip's unique ID, as `serial_descriptor` encodes
    // it. It is what makes two boards on one rig two boards, and it is how
    // picotool finds this board again after asking it to reboot: the ROM
    // presents the same ID in BOOTSEL, and picotool matches the strings.
    string_index::SERIAL, // iSerialNumber
    1,                    // bNumConfigurations
];

/// Total length of the configuration descriptor and everything that follows
/// it. The host reads the first nine bytes to learn this, then asks again for
/// exactly this many — so a wrong value here truncates the set and the host
/// sees a malformed interface rather than an error.
const CONFIG_TOTAL_LEN: u16 = CONFIGURATION.len() as u16;

/// The configuration descriptor, with both interfaces, the CDC functional
/// descriptors and all three endpoints.
///
/// One array rather than a list of descriptors that a builder concatenates:
/// the host asks for this as a single contiguous read of `wTotalLength`
/// bytes, so a contiguous array is the shape it is consumed in, and
/// `CONFIG_TOTAL_LEN` can then be `len()` rather than a hand-maintained sum
/// that drifts the moment an endpoint is added.
pub const CONFIGURATION: [u8; 84] = [
    // ---- Configuration -------------------------------------------------
    9,                        // bLength
    desc_type::CONFIGURATION, // bDescriptorType
    84,                       // wTotalLength, lo — see the assert below
    0,                        // wTotalLength, hi
    interface_number::COUNT,  // bNumInterfaces
    1,                        // bConfigurationValue
    0,                        // iConfiguration
    CONFIG_ATTRIBUTES,        // bmAttributes
    MAX_POWER_2MA,            // bMaxPower
    // ---- Interface Association: the two interfaces are one function ----
    8,                         // bLength
    cs::INTERFACE_ASSOCIATION, // bDescriptorType
    interface_number::COMM,    // bFirstInterface
    2,                         // bInterfaceCount
    class::CDC,                // bFunctionClass
    class::ACM_SUBCLASS,       // bFunctionSubClass
    class::NO_PROTOCOL,        // bFunctionProtocol
    0,                         // iFunction
    // ---- Interface 0: communications -----------------------------------
    9,                      // bLength
    desc_type::INTERFACE,   // bDescriptorType
    interface_number::COMM, // bInterfaceNumber
    0,                      // bAlternateSetting
    1,                      // bNumEndpoints
    class::CDC,             // bInterfaceClass
    class::ACM_SUBCLASS,    // bInterfaceSubClass
    class::NO_PROTOCOL,     // bInterfaceProtocol
    0,                      // iInterface
    // ---- CDC Header ----------------------------------------------------
    5,                  // bLength
    cs::INTERFACE,      // bDescriptorType
    cs::SUBTYPE_HEADER, // bDescriptorSubtype
    0x10,               // bcdCDC lo — 1.10
    0x01,               // bcdCDC hi
    // ---- CDC Call Management -------------------------------------------
    5,                           // bLength
    cs::INTERFACE,               // bDescriptorType
    cs::SUBTYPE_CALL_MANAGEMENT, // bDescriptorSubtype
    // bmCapabilities = 0: this function does not handle call management
    // itself. Claiming otherwise commits it to answering the call-management
    // requests a host would then send.
    0x00,
    interface_number::DATA, // bDataInterface
    // ---- CDC Abstract Control Management --------------------------------
    4,               // bLength
    cs::INTERFACE,   // bDescriptorType
    cs::SUBTYPE_ACM, // bDescriptorSubtype
    // bmCapabilities bit 1: the line-coding and control-line-state requests,
    // whose state `cdc.rs` holds. Nothing else is claimed — in particular
    // not `SEND_BREAK` (bit 2). A console host sets the line coding it wants
    // and proceeds whatever the device echoes back, because the coding
    // describes a UART this function does not have behind it.
    0x02,
    // ---- CDC Union ------------------------------------------------------
    5,                      // bLength
    cs::INTERFACE,          // bDescriptorType
    cs::SUBTYPE_UNION,      // bDescriptorSubtype
    interface_number::COMM, // bControlInterface
    interface_number::DATA, // bSubordinateInterface0
    // ---- Endpoint: notification (interrupt IN) --------------------------
    7,                                      // bLength
    desc_type::ENDPOINT,                    // bDescriptorType
    endpoint::NOTIFICATION_IN,              // bEndpointAddress
    transfer::INTERRUPT,                    // bmAttributes
    lo(endpoint::NOTIFICATION_MAX_PACKET),  // wMaxPacketSize
    hi(endpoint::NOTIFICATION_MAX_PACKET),  //
    endpoint::NOTIFICATION_INTERVAL_FRAMES, // bInterval
    // ---- Interface 1: data ----------------------------------------------
    9,                      // bLength
    desc_type::INTERFACE,   // bDescriptorType
    interface_number::DATA, // bInterfaceNumber
    0,                      // bAlternateSetting
    2,                      // bNumEndpoints
    class::CDC_DATA,        // bInterfaceClass
    0,                      // bInterfaceSubClass
    class::NO_PROTOCOL,     // bInterfaceProtocol
    0,                      // iInterface
    // ---- Endpoint: bulk OUT ---------------------------------------------
    7,                             // bLength
    desc_type::ENDPOINT,           // bDescriptorType
    endpoint::DATA_OUT,            // bEndpointAddress
    transfer::BULK,                // bmAttributes
    lo(endpoint::DATA_MAX_PACKET), // wMaxPacketSize
    hi(endpoint::DATA_MAX_PACKET), //
    0,                             // bInterval — ignored for bulk
    // ---- Endpoint: bulk IN ----------------------------------------------
    7,                             // bLength
    desc_type::ENDPOINT,           // bDescriptorType
    endpoint::DATA_IN,             // bEndpointAddress
    transfer::BULK,                // bmAttributes
    lo(endpoint::DATA_MAX_PACKET), // wMaxPacketSize
    hi(endpoint::DATA_MAX_PACKET), //
    0,                             // bInterval
    // ── Interface 2: reset (picotool) ──────────────────────────────────
    // Outside the IAD on purpose: the association groups the two CDC
    // interfaces into one function for the host's serial driver, and this
    // one is a separate function that picotool claims for itself.
    9,                       // bLength
    desc_type::INTERFACE,    // bDescriptorType
    interface_number::RESET, // bInterfaceNumber
    0,                       // bAlternateSetting
    0,                       // bNumEndpoints
    reset::CLASS,            // bInterfaceClass
    reset::SUBCLASS,         // bInterfaceSubClass
    reset::PROTOCOL,         // bInterfaceProtocol
    0,                       // iInterface
];

/// The `wTotalLength` field must equal the array it describes. Written as a
/// literal above because a `const` cannot reference the array it is inside,
/// and checked here because a hand-written length is exactly the kind of
/// thing that stays right until an endpoint is added.
const _: () = assert!(
    CONFIGURATION[2] as u16 | ((CONFIGURATION[3] as u16) << 8) == CONFIG_TOTAL_LEN,
    "configuration wTotalLength disagrees with the descriptor it describes"
);

/// Manufacturer and product strings.
///
/// ASCII, because [`encode_string_descriptor`] substitutes `?` for anything
/// else rather than guessing an encoding — a byte above `0x7f` is not a
/// UTF-16 code unit on its own, and a wrong guess would show the user a
/// different name than the one written here. Keeping these ASCII is what
/// makes the substitution unreachable.
pub const MANUFACTURER: &[u8] = b"Fluxor";
/// The product string a host shows in its device list.
pub const PRODUCT: &[u8] = b"Fluxor CDC Console";

/// Bytes needed for the longest string descriptor this module produces.
///
/// Two header bytes plus two per character. Sized to the product string,
/// which is the longest; [`serial_descriptor`] is shorter and shares the
/// bound so a caller needs one buffer size rather than three.
pub const STRING_DESCRIPTOR_MAX: usize = 2 + 2 * PRODUCT.len();

/// Encode the serial-number string descriptor into `out`.
///
/// Not a static, because it is not one: the serial is derived from this
/// board's unique ID, and two boards on the same rig must not present the
/// same one or a udev rule written against it addresses whichever enumerated
/// first. [`serial_from_unique_id`] does the derivation; this wraps it in a
/// string descriptor.
///
/// Returns how many bytes were written, or `None` if `out` is too small —
/// [`STRING_DESCRIPTOR_MAX`] is always enough.
pub fn serial_descriptor(unique_id: u64, out: &mut [u8]) -> Option<usize> {
    let serial = serial_from_unique_id(unique_id);
    encode_string_descriptor(&serial, out)
}

/// The string descriptor for `index`, written into `out`.
///
/// Index 0 is the language list, which is a fixed four bytes rather than an
/// encoded string. Anything this function does not know is `None`, which the
/// caller must turn into a STALL — answering an unknown index with an empty
/// descriptor tells the host a string exists and is blank, and it will show
/// that blank where a name should be.
pub fn string_descriptor(index: u8, unique_id: u64, out: &mut [u8]) -> Option<usize> {
    match index {
        0 => {
            let n = LANG_ID_DESCRIPTOR.len();
            if out.len() < n {
                return None;
            }
            out[..n].copy_from_slice(&LANG_ID_DESCRIPTOR);
            Some(n)
        }
        string_index::MANUFACTURER => encode_string_descriptor(MANUFACTURER, out),
        string_index::PRODUCT => encode_string_descriptor(PRODUCT, out),
        string_index::SERIAL => serial_descriptor(unique_id, out),
        _ => None,
    }
}

/// Low byte, for the little-endian fields above.
const fn lo(v: u16) -> u8 {
    v as u8
}

/// High byte.
const fn hi(v: u16) -> u8 {
    (v >> 8) as u8
}
