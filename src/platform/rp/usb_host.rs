//! RP2 USB host-mode DPRAM layout.
//!
//! The same 4 KiB of dual-port RAM the device backend uses, arranged
//! completely differently.
//!
//! # Why this is a separate backend and not a flag
//!
//! Device and host are role-exclusive backends rather than one driver with
//! branches, and the layouts are why. They are not variations on a theme —
//! at offset `0x100`:
//!
//! - **device mode** has EP0's first data buffer;
//! - **host mode** has `epx_ctrl`, a control register.
//!
//! So a driver that mixed them would write endpoint payload over a control
//! register, or configure an endpoint by writing into a data buffer. Neither
//! faults. Both produce a controller doing something other than what was
//! asked, with no indication of which.
//!
//! The whole region below `0x180` differs in this way; the shared parts are
//! the setup-packet area at the start and the data area at the end.

/// Interrupt endpoints the host controller supports.
///
/// Fifteen: one per endpoint number other than zero. The "EPX" single
/// general-purpose endpoint handles everything else — control, bulk, and
/// whichever interrupt transfer is currently scheduled.
pub const INTERRUPT_ENDPOINTS: usize = 15;

/// Host-mode DPRAM offsets.
pub mod dpram {
    use super::INTERRUPT_ENDPOINTS;

    /// The setup packet. Shared with device mode — the one part that is.
    pub const SETUP_PACKET: usize = 0x00;
    /// Interrupt endpoint control words, two words each (control + spare).
    pub const INT_EP_CTRL: usize = 0x08;
    /// Bytes per interrupt endpoint control entry.
    pub const INT_EP_CTRL_STRIDE: usize = 0x08;
    /// EPX's buffer control — the general-purpose endpoint.
    pub const EPX_BUF_CTRL: usize = 0x80;
    /// Interrupt endpoint buffer control, two words each.
    pub const INT_EP_BUFFER_CTRL: usize = 0x88;
    /// Bytes per interrupt endpoint buffer control entry.
    pub const INT_EP_BUFFER_CTRL_STRIDE: usize = 0x08;
    /// **EPX's endpoint control.**
    ///
    /// Device mode has EP0's data buffer at this address. Writing endpoint
    /// payload here in host mode reconfigures the general-purpose endpoint
    /// mid-transfer.
    pub const EPX_CTRL: usize = 0x100;
    /// Where driver-usable data begins. The same as device mode, which is
    /// the other part the two layouts share.
    pub const DATA_START: usize = 0x180;

    /// Control word offset for interrupt endpoint `idx` (0-based, naming
    /// endpoints 1..=15).
    #[inline]
    pub const fn int_ep_ctrl(idx: usize) -> Option<usize> {
        if idx >= INTERRUPT_ENDPOINTS {
            return None;
        }
        Some(INT_EP_CTRL + idx * INT_EP_CTRL_STRIDE)
    }

    /// Buffer control offset for interrupt endpoint `idx`.
    #[inline]
    pub const fn int_ep_buffer_ctrl(idx: usize) -> Option<usize> {
        if idx >= INTERRUPT_ENDPOINTS {
            return None;
        }
        Some(INT_EP_BUFFER_CTRL + idx * INT_EP_BUFFER_CTRL_STRIDE)
    }
}

/// Host-mode fields in `SIE_CTRL`, beyond the ones device mode uses.
pub mod sie_ctrl {
    /// Start a transfer on EPX.
    pub const START_TRANS: u32 = 1 << 31;
    /// Transfer direction: set for a host send (OUT).
    pub const RECEIVE_DATA: u32 = 1 << 29;
    /// Transfer direction: set for a host receive (IN).
    pub const SEND_DATA: u32 = 1 << 28;
    /// Send a setup packet.
    pub const SEND_SETUP: u32 = 1 << 27;
    /// Enable SOF generation, which a host must produce for the bus to be
    /// alive at all.
    pub const SOF_EN: u32 = 1 << 3;
    /// Keep the bus alive between transfers.
    pub const KEEP_ALIVE_EN: u32 = 1 << 4;
    /// Enable pull-downs, which is what makes this end of the cable a host.
    pub const PULLDOWN_EN: u32 = 1 << 2;
}

/// `ADDR_ENDP` fields, which in host mode address the *device* being talked
/// to rather than declaring this device's own address.
///
/// The same register, the opposite meaning — one more reason the two roles
/// are separate backends.
pub mod addr_endp {
    /// The device address being addressed, bits 0..6.
    pub const ADDRESS_LSB: u32 = 0;
    /// The endpoint on that device, bits 16..19.
    pub const ENDPOINT_LSB: u32 = 16;
    /// Transfer direction toward the device, bit 25.
    pub const INTERRUPT_EP_DIR_OUT: u32 = 1 << 25;

    /// Encode a device address and endpoint.
    #[inline]
    pub const fn encode(device_address: u8, endpoint: u8, out: bool) -> u32 {
        let mut v = ((device_address & 0x7f) as u32) << ADDRESS_LSB;
        v |= ((endpoint & 0x0f) as u32) << ENDPOINT_LSB;
        if out {
            v |= INTERRUPT_EP_DIR_OUT;
        }
        v
    }
}

/// Whether a device address is one a host may address.
///
/// Zero is the default address every device answers on before it is
/// assigned one, so it is legal to *address* but is not an assignment. The
/// field is seven bits, so 128 and above silently truncate into a different
/// device — which is why this is checked rather than masked at the call site.
#[inline]
pub const fn is_addressable(device_address: u8) -> bool {
    device_address <= 0x7f
}

/// Whether an address may be *assigned* to a device.
///
/// Distinct from [`is_addressable`]: assigning zero would leave the device
/// on the default address, where it collides with every other unaddressed
/// device on the bus.
#[inline]
pub const fn is_assignable(device_address: u8) -> bool {
    device_address >= 1 && device_address <= 0x7f
}
