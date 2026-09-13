//! The EP0 control-transfer state machine (USB 2.0 Chapter 9).
//!
//! Every control transfer is setup stage, optional data stage, status stage.
//! The rules are short and the ways to get them wrong are specific, so they
//! live here once rather than inside each controller backend.
//!
//! # The three that actually bite
//!
//! **`SET_ADDRESS` takes effect after the status stage, not when it
//! arrives.** The device must acknowledge the request at address 0 and only
//! then start answering on the new address. Applying it immediately is the
//! classic enumeration failure: the host sends its status-stage token to
//! address 0, the device is no longer listening there, and enumeration
//! retries forever. The board looks dead on the bus.
//!
//! **The status stage runs in the opposite direction to the data stage,**
//! and is always DATA1. A control read ends with a zero-length OUT; a control
//! write ends with a zero-length IN. Getting this backwards hangs the
//! transfer with each end waiting for the other.
//!
//! **A new SETUP packet abandons whatever was in progress.** The host is
//! entitled to do that at any point, and a backend that queues the new setup
//! behind the old transfer's completion deadlocks against a host that will
//! never send it.

/// `bmRequestType` direction bit.
pub const REQUEST_TYPE_DIRECTION_IN: u8 = 0x80;

/// `bmRequestType` type field, once masked (USB 2.0 Table 9-2).
///
/// The request number alone does not identify a request: standard, class and
/// vendor requests are numbered in separate spaces, so the same byte means
/// different things depending on this field. Reading the number without it
/// answers a class request as though it were the standard one that happens
/// to share its number.
pub const REQUEST_TYPE_MASK: u8 = 0x60;
/// A standard request, defined by the USB specification itself.
pub const REQUEST_TYPE_STANDARD: u8 = 0x00;
/// `bmRequestType` type field: class-specific.
pub const REQUEST_TYPE_CLASS: u8 = 0x20;

/// Standard request codes this core acts on directly (USB 2.0 Table 9-4).
pub mod request {
    /// `GET_STATUS`.
    pub const GET_STATUS: u8 = 0x00;
    /// `CLEAR_FEATURE`.
    pub const CLEAR_FEATURE: u8 = 0x01;
    /// `SET_FEATURE`.
    pub const SET_FEATURE: u8 = 0x03;
    /// `SET_ADDRESS` — the one with the deferred effect.
    pub const SET_ADDRESS: u8 = 0x05;
    /// `GET_DESCRIPTOR`.
    pub const GET_DESCRIPTOR: u8 = 0x06;
    /// `SET_DESCRIPTOR`.
    pub const SET_DESCRIPTOR: u8 = 0x07;
    /// `GET_CONFIGURATION`.
    pub const GET_CONFIGURATION: u8 = 0x08;
    /// `SET_CONFIGURATION`.
    pub const SET_CONFIGURATION: u8 = 0x09;
    /// `GET_INTERFACE` — which alternate setting an interface is using.
    pub const GET_INTERFACE: u8 = 0x0a;
    /// `SET_INTERFACE`.
    pub const SET_INTERFACE: u8 = 0x0b;
}

/// A decoded setup packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setup {
    /// `bmRequestType`.
    pub request_type: u8,
    /// `bRequest`.
    pub request: u8,
    /// `wValue`.
    pub value: u16,
    /// `wIndex`.
    pub index: u16,
    /// `wLength` — how many bytes the data stage may carry.
    pub length: u16,
}

impl Setup {
    /// Decode the eight bytes the SIE deposits in DPRAM.
    ///
    /// Returns `None` for anything but exactly eight bytes: a setup packet
    /// is fixed-size, and a short one would leave fields reading whatever
    /// was in the buffer from the previous transfer.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 8 {
            return None;
        }
        Some(Self {
            request_type: bytes[0],
            request: bytes[1],
            value: u16::from_le_bytes([bytes[2], bytes[3]]),
            index: u16::from_le_bytes([bytes[4], bytes[5]]),
            length: u16::from_le_bytes([bytes[6], bytes[7]]),
        })
    }

    /// Whether the data stage flows device-to-host.
    #[inline]
    pub const fn is_device_to_host(&self) -> bool {
        self.request_type & REQUEST_TYPE_DIRECTION_IN != 0
    }

    /// Whether this transfer has a data stage at all.
    #[inline]
    pub const fn has_data_stage(&self) -> bool {
        self.length != 0
    }

    /// Whether this is a standard request rather than a class or vendor one.
    #[inline]
    pub const fn is_standard(&self) -> bool {
        self.request_type & REQUEST_TYPE_MASK == REQUEST_TYPE_STANDARD
    }

    /// Whether this is a class-specific request (`bmRequestType` type 01).
    #[inline]
    pub const fn is_class(&self) -> bool {
        self.request_type & REQUEST_TYPE_MASK == REQUEST_TYPE_CLASS
    }
}

/// Where a control transfer is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// No transfer in progress.
    Idle,
    /// Sending data to the host.
    DataIn,
    /// Receiving data from the host.
    DataOut,
    /// Awaiting the zero-length status packet, which runs in the opposite
    /// direction to the data stage.
    StatusIn,
    /// As [`StatusIn`](Stage::StatusIn), the other way.
    StatusOut,
    /// The request was refused; the endpoint is stalled until the next SETUP.
    Stalled,
}

/// What the backend should do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Send `len` bytes to the host with this data toggle.
    SendData { len: u16, data1: bool },
    /// Await up to `len` bytes from the host.
    ReceiveData { len: u16, data1: bool },
    /// Send the zero-length status packet (always DATA1).
    SendStatus,
    /// Await the zero-length status packet (always DATA1).
    ReceiveStatus,
    /// Stall EP0: the request is not supported or is malformed.
    Stall,
    /// The transfer is finished.
    Complete,
}

/// EP0's state across one control transfer.
///
/// Holds no buffers: the backend owns DPRAM, and this owns only the rules
/// about what may happen next.
#[derive(Clone, Copy, Debug)]
pub struct ControlState {
    stage: Stage,
    setup: Option<Setup>,
    transferred: u16,
    toggle: bool,
    /// Address to adopt once the status stage completes. `None` when no
    /// `SET_ADDRESS` is pending.
    pending_address: Option<u8>,
    /// The address currently in force.
    address: u8,
}

impl Default for ControlState {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlState {
    /// Idle, at address 0, as after a bus reset.
    pub const fn new() -> Self {
        Self {
            stage: Stage::Idle,
            setup: None,
            transferred: 0,
            toggle: false,
            pending_address: None,
            address: 0,
        }
    }

    /// Current stage.
    pub const fn stage(&self) -> Stage {
        self.stage
    }

    /// The address the device is answering on.
    pub const fn address(&self) -> u8 {
        self.address
    }

    /// The setup packet being serviced, if any.
    pub const fn setup(&self) -> Option<Setup> {
        self.setup
    }

    /// Reset to the post-bus-reset state.
    ///
    /// A bus reset returns the device to address 0 and abandons any transfer,
    /// including a pending `SET_ADDRESS` — the host resets precisely when it
    /// wants to start over, and carrying an address across would leave the
    /// device answering somewhere the host is not looking.
    pub fn bus_reset(&mut self) {
        *self = Self::new();
    }

    /// Begin the transfer described by `setup`.
    ///
    /// A SETUP arriving mid-transfer abandons the previous one. The host may
    /// do that at any point, and queuing the new setup behind the old
    /// transfer's completion deadlocks against a host that will never send
    /// it.
    pub fn on_setup(&mut self, setup: Setup) -> Action {
        self.setup = Some(setup);
        self.transferred = 0;
        self.pending_address = None;

        // The data stage always starts at DATA1; the SETUP itself was DATA0.
        self.toggle = true;

        if setup.request == request::SET_ADDRESS && !setup.is_device_to_host() {
            let addr = (setup.value & 0x7f) as u8;
            // Deferred, not applied. The status stage still has to be
            // acknowledged at the current address.
            self.pending_address = Some(addr);
            self.stage = Stage::StatusIn;
            return Action::SendStatus;
        }

        if !setup.has_data_stage() {
            // No data: a zero-length request is acknowledged with an IN
            // status packet.
            self.stage = Stage::StatusIn;
            return Action::SendStatus;
        }

        if setup.is_device_to_host() {
            self.stage = Stage::DataIn;
            Action::SendData {
                len: setup.length,
                data1: self.toggle,
            }
        } else {
            self.stage = Stage::DataOut;
            Action::ReceiveData {
                len: setup.length,
                data1: self.toggle,
            }
        }
    }

    /// Record that `len` bytes moved in the data stage, and say what is next.
    ///
    /// A packet shorter than the endpoint's maximum ends the data stage: that
    /// is how a device says "this is all there is" for a request whose
    /// `wLength` was an upper bound rather than an exact size.
    pub fn on_data(&mut self, len: u16, max_packet: u16) -> Action {
        let Some(setup) = self.setup else {
            return self.stall();
        };
        if !matches!(self.stage, Stage::DataIn | Stage::DataOut) {
            return self.stall();
        }

        self.transferred = self.transferred.saturating_add(len);
        self.toggle = !self.toggle;

        let short = len < max_packet;
        let done = short || self.transferred >= setup.length;

        if !done {
            let remaining = setup.length - self.transferred;
            return if self.stage == Stage::DataIn {
                Action::SendData {
                    len: remaining,
                    data1: self.toggle,
                }
            } else {
                Action::ReceiveData {
                    len: remaining,
                    data1: self.toggle,
                }
            };
        }

        // The status stage is the opposite direction to the data stage.
        if self.stage == Stage::DataIn {
            self.stage = Stage::StatusOut;
            Action::ReceiveStatus
        } else {
            self.stage = Stage::StatusIn;
            Action::SendStatus
        }
    }

    /// Record that the status stage completed.
    ///
    /// This is where a pending `SET_ADDRESS` takes effect — after the host
    /// has seen the acknowledgement at the old address, never before.
    pub fn on_status(&mut self) -> Action {
        if !matches!(self.stage, Stage::StatusIn | Stage::StatusOut) {
            return self.stall();
        }
        if let Some(addr) = self.pending_address.take() {
            self.address = addr;
        }
        self.stage = Stage::Idle;
        self.setup = None;
        self.transferred = 0;
        Action::Complete
    }

    /// Refuse the current request.
    pub fn stall(&mut self) -> Action {
        self.stage = Stage::Stalled;
        self.setup = None;
        self.pending_address = None;
        Action::Stall
    }

    /// The toggle the next packet of the current stage should carry.
    pub const fn toggle(&self) -> bool {
        self.toggle
    }
}
