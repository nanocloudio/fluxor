//! The RP2 USB controller's event vocabulary, and what its bitmaps mean.
//!
//! Separate from the controller itself because none of it touches hardware:
//! it is the interpretation of what the hardware reported, and the place the
//! interpretation can be wrong without anything faulting. Declared
//! unconditionally so that interpretation is host-testable — the register
//! reads that produce these events are not, and the bug that hid here was
//! not a register bug.

use crate::kernel::usb::control;
use crate::kernel::usb::device::DeviceEvent;

/// Something the controller reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The host reset the bus. The device returns to address 0 and every
    /// endpoint configuration is void.
    BusReset,
    /// A setup packet is in DPRAM.
    Setup(control::Setup),
    /// Buffers completed; the bitmap is one bit per endpoint-direction.
    /// **IN is the even bit and OUT the odd one**: `ep * 2` for IN,
    /// `ep * 2 + 1` for OUT.
    BuffersComplete(u32),
    /// The bus went idle.
    Suspended,
    /// The host resumed the bus.
    Resumed,
}

/// Translate a controller event into the pump's vocabulary.
///
/// The buffer bitmap needs interpreting: bit 0 is EP0 OUT and bit 1 is EP0 IN,
/// and which of those means "data" versus "status" depends on the control
/// transfer's stage — which the pump knows and this does not. So a completion
/// on EP0 is reported as data and the control state machine decides; a
/// zero-length completion is the status stage.
///
/// **The length must come from the direction that completed.** `ep0_len` is
/// asked for one or the other rather than given a number, because the two
/// buffers hold unrelated values: an IN buffer keeps the length of the
/// packet it sent, so reading it when an OUT completed reports the previous
/// transfer's size. A zero-length status OUT then arrives as data, the
/// control machine is asked to accept data in a status stage, and it stalls
/// — which is every control read on the device failing at the last step,
/// after the descriptor itself went out correctly.
pub fn translate(event: Event, ep0_len: impl Fn(bool) -> u16) -> Option<DeviceEvent> {
    match event {
        Event::BusReset => Some(DeviceEvent::BusReset),
        Event::Setup(s) => Some(DeviceEvent::Setup(s)),
        Event::BuffersComplete(mask) => {
            // IN is the even bit, OUT the odd one — the opposite way round
            // to the order the names are usually written in. Reversed, every
            // EP0 IN completion is read as an OUT: the length comes from a
            // buffer that was never armed, so it reads zero, the completion
            // is reported as a status stage, and the control machine is
            // handed a status stage in the middle of its data stage. It
            // refuses, which is correct, and the device stalls every
            // control transfer that carries data.
            const EP0_IN: u32 = 1 << 0;
            const EP0_OUT: u32 = 1 << 1;
            const CDC_IN: u32 = 1 << (crate::kernel::usb::device::CDC_IN_ENDPOINT as u32 * 2);
            if mask & (EP0_OUT | EP0_IN) != 0 {
                let is_in = mask & EP0_IN != 0;
                let len = ep0_len(is_in);
                if len == 0 {
                    Some(DeviceEvent::Ep0Status)
                } else {
                    Some(DeviceEvent::Ep0Data(len))
                }
            } else if mask & CDC_IN != 0 {
                Some(DeviceEvent::CdcInReady)
            } else {
                None
            }
        }
        // Suspend and resume carry no work for the pump; the link state is
        // the controller's and the class layer has nothing to do about it.
        Event::Suspended | Event::Resumed => None,
    }
}
