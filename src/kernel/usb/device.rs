//! The native device pump: one step, no executor.
//!
//! The device state machine is a function the scheduler calls once per step.
//! It does a bounded amount of work and returns.
//!
//! # Why the shape matters more than the code
//!
//! An executor shared between the USB stack and the kernel's idle loop
//! couples them: anything that blocks in one starves the other, and a board
//! whose USB is dead still passes every host gate, because no host gate can
//! see a task that stopped yielding.
//!
//! A pump has no such coupling. It cannot block, because it has no way to
//! wait — every operation it performs is an offer or a poll with a budget.
//! That failure mode is unavailable by construction rather than avoided by
//! discipline.
//!
//! # It owns no registers
//!
//! Controller access is the backend's, and the backend is injected. That is
//! what lets the whole state machine be driven from a host test with a
//! simulated controller, which is where the reset/detach/cancel races it asks
//! about are actually reachable.

use super::cdc::{request as cdc_request, CdcState};
use super::cdc_descriptors::interface_number;
use super::control::{request, Action, ControlState, Setup};
use super::reset_interface::{self, RebootRequest};

/// What a control read is answered with.
#[derive(Clone, Copy, Debug)]
enum Pending {
    /// Fixed bytes: descriptors and the spec-defined standard replies.
    Bytes(&'static [u8]),
    /// The current line coding, encoded when sent.
    LineCoding,
}

/// What the pump asks of its controller.
///
/// Small on purpose: everything above this is portable, so a second
/// controller — RP2 host mode, or Pi 5's xHCI — implements this and inherits
/// the whole state machine rather than reimplementing it.
pub trait DeviceController {
    /// Send `data` on an IN endpoint.
    ///
    /// `data1` is the toggle for **EP0 only**, where the transfer's shape
    /// fixes it and the control state machine is the authority. On every
    /// other endpoint the toggle alternates per packet with no reference to
    /// the transfer above it, so the controller owns it and this argument
    /// is ignored.
    fn send(&mut self, endpoint: u8, data: &[u8], data1: bool);
    /// Arm an OUT endpoint to receive up to `len` bytes.
    fn receive(&mut self, endpoint: u8, len: u16, data1: bool);
    /// Stall an endpoint, refusing the current transfer.
    fn stall(&mut self, endpoint: u8);
    /// Adopt a device address. Called only after a status stage completes.
    fn set_address(&mut self, address: u8);
    /// Bytes the control endpoint can carry in one packet.
    fn ep0_max_packet(&self) -> u16;
    /// Discard per-endpoint state the bus reset invalidated.
    ///
    /// Data toggles above all: the host returns every endpoint to DATA0 on
    /// a reset whether or not the device does. Defaulted empty because a
    /// controller with nothing of its own to forget is a legitimate one.
    fn bus_reset(&mut self) {}
}

/// Something the controller reported, in terms the pump understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceEvent {
    /// The host reset the bus.
    BusReset,
    /// A setup packet arrived.
    Setup(Setup),
    /// `len` bytes moved on EP0.
    Ep0Data(u16),
    /// The EP0 status stage completed.
    Ep0Status,
    /// The CDC IN endpoint is ready for more.
    CdcInReady,
}

/// How many events one pump call will process.
///
/// Bounded, because events arrive while they are being handled: a host
/// hammering the control endpoint would otherwise hold the step forever, and
/// the step guard would terminate the module rather than the host.
pub const EVENTS_PER_STEP: u32 = 16;

/// The device stack: control state, CDC state and the descriptors between
/// them and a host.
pub struct DevicePump {
    control: ControlState,
    cdc: CdcState,
    /// What the current control read is serving, and how far in.
    pending: Option<(Pending, usize)>,
    /// Whether the host has selected the configuration.
    configured: bool,
    /// Whether the last bulk IN packet was a full one, so a zero-length
    /// packet is owed if the queue then runs dry.
    ///
    /// CDC framing: a transfer ends at a short packet, and a full packet
    /// says more is coming. Output that happens to end on a 64-byte
    /// boundary would otherwise sit in the host's driver waiting for the
    /// rest, delivered only when some later line pushes it out.
    cdc_zlp_due: bool,
    /// A reboot the host has asked for, not yet acknowledged. It becomes
    /// [`reboot_due`](Self::reboot_due) when the status stage completes —
    /// acting inside the request leaves the host with a transfer that never
    /// finished.
    reboot_armed: Option<RebootRequest>,
    /// A reboot acknowledged to the host and owed to the runtime.
    reboot_due: Option<RebootRequest>,
    /// Whether a bulk IN packet is with the controller.
    ///
    /// The endpoint holds one buffer, and arming it again before the host
    /// has collected the last one overwrites data that was never sent. The
    /// hardware reports neither, so the state is tracked here.
    cdc_in_busy: bool,
}

impl Default for DevicePump {
    fn default() -> Self {
        Self::new()
    }
}

impl DevicePump {
    /// A pump with nothing configured, as after power-on.
    pub const fn new() -> Self {
        Self {
            control: ControlState::new(),
            cdc: CdcState::new(),
            pending: None,
            configured: false,
            reboot_armed: None,
            reboot_due: None,
            cdc_zlp_due: false,
            cdc_in_busy: false,
        }
    }

    /// The CDC endpoint's state, for a log producer to write into.
    pub fn cdc(&mut self) -> &mut CdcState {
        &mut self.cdc
    }

    /// The device address currently in force.
    pub fn address(&self) -> u8 {
        self.control.address()
    }

    /// Whether the host has selected a configuration.
    ///
    /// The line between "the host can see us" and "the host can talk to us":
    /// a device that answers every descriptor request but never reaches this
    /// appears in the host's device list and offers no working function.
    pub fn is_configured(&self) -> bool {
        self.configured
    }

    /// Where EP0 is in the current control transfer.
    pub fn stage(&self) -> crate::kernel::usb::control::Stage {
        self.control.stage()
    }

    /// The setup packet being serviced, if one is.
    pub fn setup(&self) -> Option<Setup> {
        self.control.setup()
    }

    /// Process up to [`EVENTS_PER_STEP`] events, returning how many.
    ///
    /// Never blocks and never waits: every path through this function
    /// returns.
    ///
    /// `descriptors` is asked what to serve when a control read arrives. It
    /// is a callback rather than state set beforehand because the pump clears
    /// any previous transfer on each SETUP: a descriptor handed over before
    /// the request would be discarded by it, and one handed over afterwards
    /// would arrive after the first packet had already gone out. Asking at
    /// the moment of the request is the only ordering that works, so it is
    /// the only one the API offers.
    ///
    /// Keeping it a callback also keeps the descriptor tables out of this
    /// module. What a device says about itself is board and build policy, and
    /// baking it in here would make the pump unusable for anything else.
    pub fn step(
        &mut self,
        controller: &mut impl DeviceController,
        mut next_event: impl FnMut() -> Option<DeviceEvent>,
        mut descriptors: impl FnMut(&Setup) -> Option<&'static [u8]>,
    ) -> u32 {
        let mut handled = 0;
        while handled < EVENTS_PER_STEP {
            let Some(event) = next_event() else {
                break;
            };
            self.handle(controller, event, &mut descriptors);
            handled += 1;
        }
        handled
    }

    fn handle(
        &mut self,
        controller: &mut impl DeviceController,
        event: DeviceEvent,
        descriptors: &mut impl FnMut(&Setup) -> Option<&'static [u8]>,
    ) {
        match event {
            DeviceEvent::BusReset => {
                // Everything the host knew about this device is void.
                self.control.bus_reset();
                self.cdc.bus_reset();
                self.pending = None;
                // A bus reset returns the device to Default: unaddressed and
                // unconfigured. Keeping `configured` across one would have
                // us answer `GET_CONFIGURATION` with a configuration the
                // host has just discarded.
                self.configured = false;
                // Whatever was in flight is gone with the reset; a buffer
                // believed busy for ever would silence the console.
                self.cdc_in_busy = false;
                self.cdc_zlp_due = false;
                // The controller's own per-endpoint state — data toggles
                // above all — is void too. The host resets its side
                // regardless, so a device that keeps them is out of step
                // from the first packet it sends afterwards.
                controller.bus_reset();
                controller.set_address(0);
            }
            DeviceEvent::Setup(setup) => {
                // Ask before driving the state machine: `on_setup` may emit
                // the first data packet immediately, and it must have
                // something to send.
                //
                // Standard requests are answered here rather than by the
                // caller's descriptor table, because they are protocol
                // rather than policy: what this device *is* varies by board,
                // but what `GET_STATUS` returns does not. Leaving them to
                // fall through is not a missing feature — the generic path
                // finds nothing pending and sends a zero-length packet,
                // which for a request whose length the spec fixes is a
                // protocol violation. A host reads it as a device that
                // enumerated and then failed to configure, which is
                // precisely as far as it gets.
                self.pending = self
                    .standard_response(&setup)
                    .map(Pending::Bytes)
                    .or_else(|| self.class_response(&setup))
                    .or_else(|| descriptors(&setup).map(Pending::Bytes))
                    .map(|reply| (reply, 0));
                self.note_standard_request(&setup);
                self.note_class_request(&setup);

                // **Nothing to serve is a refusal, not an empty answer.**
                // A zero-length reply to a device-to-host request tells the
                // host "here is your data, and there is none of it", and the
                // host believes it. A descriptor this device does not have
                // must be STALLed instead, which is the only reply that
                // means "I do not have that". This also covers every class
                // and vendor request, which this core does not answer.
                if setup.is_device_to_host() && setup.has_data_stage() && self.pending.is_none() {
                    let action = self.control.stall();
                    self.apply(controller, action);
                    return;
                }
                let action = self.control.on_setup(setup);
                self.apply(controller, action);
            }
            DeviceEvent::Ep0Data(len) => {
                let action = self.control.on_data(len, controller.ep0_max_packet());
                self.apply(controller, action);
            }
            DeviceEvent::Ep0Status => {
                let before = self.control.address();
                let action = self.control.on_status();
                let after = self.control.address();
                // The address changes only here, after the host has seen the
                // acknowledgement at the old one.
                if after != before {
                    controller.set_address(after);
                }
                if action == Action::Complete {
                    self.pending = None;
                    // Acknowledged: the host has its status stage, so the
                    // reboot may now happen without cutting a transfer off.
                    if let Some(r) = self.reboot_armed.take() {
                        self.reboot_due = Some(r);
                    }
                }
            }
            DeviceEvent::CdcInReady => {
                // The host has collected the previous packet.
                self.cdc_in_busy = false;
                self.service_cdc_tx(controller);
            }
        }
    }

    /// The reply to a standard device request whose content the spec fixes,
    /// or `None` to let the caller's descriptor table answer.
    ///
    /// Every reply is a static: these are one and two byte constants, and the
    /// only one that varies is `GET_CONFIGURATION`, which has exactly two
    /// possible answers and so has one static each.
    fn standard_response(&self, setup: &Setup) -> Option<&'static [u8]> {
        /// `GET_STATUS`, device: bus-powered, remote wakeup disabled. Two
        /// bytes, little-endian, and the host will not accept fewer.
        static STATUS: [u8; 2] = [0, 0];
        /// `GET_CONFIGURATION` before `SET_CONFIGURATION`.
        static UNCONFIGURED: [u8; 1] = [0];
        /// `GET_CONFIGURATION` after it. This device has one configuration
        /// and its `bConfigurationValue` is 1.
        static CONFIGURED: [u8; 1] = [1];
        /// `GET_INTERFACE`: neither interface has an alternate setting.
        static ALT_SETTING: [u8; 1] = [0];

        if !setup.is_device_to_host() || !setup.is_standard() {
            return None;
        }
        match setup.request {
            request::GET_STATUS => Some(&STATUS),
            request::GET_CONFIGURATION => Some(if self.configured {
                &CONFIGURED
            } else {
                &UNCONFIGURED
            }),
            request::GET_INTERFACE => Some(&ALT_SETTING),
            _ => None,
        }
    }

    /// The reply to a CDC class request the host reads.
    ///
    /// `GET_LINE_CODING` is the only one. Its answer is whatever the host
    /// last set, which is state rather than a constant, so it is served on
    /// demand rather than from a static.
    fn class_response(&self, setup: &Setup) -> Option<Pending> {
        if !setup.is_device_to_host() || !setup.is_class() {
            return None;
        }
        match setup.request {
            cdc_request::GET_LINE_CODING => Some(Pending::LineCoding),
            _ => None,
        }
    }

    /// Record the effect of a CDC class request that carries no data stage
    /// the pump reads.
    ///
    /// `SET_CONTROL_LINE_STATE` is the one that matters: DTR is how a host
    /// program says it has the port open, and the runtime uses it to decide
    /// when the console has a reader. Acknowledged without being recorded,
    /// the port opens and nothing ever knows.
    ///
    /// `SET_LINE_CODING` arrives with seven bytes the pump does not read; the
    /// coding is meaningless to a link with no UART on the other side, so the
    /// request is accepted and the default is reported back.
    fn note_class_request(&mut self, setup: &Setup) {
        if setup.is_device_to_host() || !setup.is_class() {
            return;
        }
        // `wIndex` says which interface the request is for. The reset
        // interface's request codes overlap CDC's numerically (both are
        // small integers), so the interface is what tells them apart.
        if setup.index == u16::from(interface_number::RESET) {
            self.reboot_armed = reset_interface::decode(setup.request, setup.value);
            return;
        }
        if setup.request == cdc_request::SET_CONTROL_LINE_STATE {
            self.cdc.set_control_line_state(setup.value);
        }
    }

    /// A reboot the host asked for and has been told is accepted.
    ///
    /// The runtime takes it and performs it; the pump only decides that it
    /// is safe to. Returned once.
    pub fn take_reboot_request(&mut self) -> Option<RebootRequest> {
        self.reboot_due.take()
    }

    /// Record the effect of a standard request that carries no data.
    ///
    /// `SET_CONFIGURATION` is the one that matters: the host asks for the
    /// value back, and a device that acknowledges the request without
    /// remembering it answers the next `GET_CONFIGURATION` with a lie.
    fn note_standard_request(&mut self, setup: &Setup) {
        if setup.is_standard()
            && setup.request == request::SET_CONFIGURATION
            && !setup.is_device_to_host()
        {
            self.configured = setup.value != 0;
        }
    }

    /// Hand the next queued console bytes to the bulk IN endpoint.
    ///
    /// Called both when the host collects a packet and from the runtime's
    /// step, because those are the two ways the situation can change and
    /// only one of them is an event. With the event alone, a queue that
    /// went empty stops the chain: nothing is in flight, so no completion
    /// is coming, so nothing restarts it, and the console goes silent with
    /// bytes still waiting.
    pub fn service_cdc_tx(&mut self, controller: &mut impl DeviceController) {
        if self.cdc_in_busy || !self.configured {
            return;
        }
        let mut packet = [0u8; 64];
        let n = self.cdc.read_tx(&mut packet);
        if n > 0 {
            // Bulk endpoints carry no toggle the class layer tracks; the
            // controller owns it.
            controller.send(CDC_IN_ENDPOINT, &packet[..n], false);
            self.cdc_in_busy = true;
            self.cdc_zlp_due = n == packet.len();
        } else if self.cdc_zlp_due {
            // The queue ran dry on a full packet: end the transfer.
            controller.send(CDC_IN_ENDPOINT, &[], false);
            self.cdc_in_busy = true;
            self.cdc_zlp_due = false;
        }
    }

    fn apply(&mut self, controller: &mut impl DeviceController, action: Action) {
        match action {
            Action::SendData { len, data1 } => {
                let max = controller.ep0_max_packet();
                let chunk = len.min(max) as usize;
                let coding = self.cdc.line_coding().to_bytes();
                match self.pending.as_mut() {
                    Some((reply, offset)) => {
                        let bytes: &[u8] = match reply {
                            Pending::Bytes(b) => b,
                            Pending::LineCoding => &coding,
                        };
                        let end = (*offset + chunk).min(bytes.len());
                        let slice = &bytes[*offset..end];
                        *offset = end;
                        controller.send(0, slice, data1);
                    }
                    // Nothing to serve: a zero-length packet tells the host
                    // the device has no more, which ends the transfer
                    // cleanly rather than leaving it waiting.
                    None => controller.send(0, &[], data1),
                }
            }
            Action::ReceiveData { len, data1 } => {
                controller.receive(0, len.min(controller.ep0_max_packet()), data1)
            }
            Action::SendStatus => controller.send(0, &[], true),
            Action::ReceiveStatus => controller.receive(0, 0, true),
            Action::Stall => controller.stall(0),
            Action::Complete => {}
        }
    }
}

/// The CDC bulk IN endpoint number: the console's data path to the host.
///
/// Taken from the descriptor set rather than restated, because the host
/// reads the endpoint it was told about and nothing reconciles a second
/// opinion. Writing console bytes to any other endpoint succeeds at every
/// layer — the buffer is armed, the SIE sends it — and the port stays
/// silent, which is the same symptom as a device that was never configured.
pub const CDC_IN_ENDPOINT: u8 = super::cdc_descriptors::endpoint::DATA_IN & 0x0f;
