//! RP2 USB device controller: bring-up and event drain.
//!
//! The register-level half of the device controller. It owns the reset, PHY
//! and pull-up sequence, and turns the SIE's status bits into the events the
//! common core in [`crate::kernel::usb`] understands. It deliberately owns no
//! policy: what to do with a setup packet is [`control::ControlState`]'s, and
//! what a descriptor means is the semantic core's.
//!
//! # Order matters in bring-up
//!
//! The pull-up is what tells the host a device is present. Enabling it before
//! the controller can answer means the host starts enumerating into a device
//! that is not ready, and the first `GET_DESCRIPTOR` is answered with nothing.
//! Some hosts retry; some mark the port failed and never look again — which
//! reads as a board that does not enumerate at all, intermittently.
//!
//! So the pull-up is last, and deliberately separate from [`init`].

use crate::kernel::usb::control;
use crate::platform::rp_regs::{clear_w1c, modify32, read32, set_bits, wait_until, write32};
use crate::platform::rp_usb_dpram::{dpram, reg, DPRAM_BASE, REGS_BASE};
pub use crate::platform::rp_usb_events::{translate, Event};

/// `MAIN_CTRL` bits.
mod main_ctrl {
    /// Enable the controller.
    pub const CONTROLLER_EN: u32 = 1 << 0;
    /// Host mode when set, device mode when clear.
    ///
    /// Named but unused: device mode is "this bit clear", and writing
    /// MAIN_CTRL with only CONTROLLER_EN is what selects it. Naming the bit
    /// is what makes that a stated choice rather than an omission. Device
    /// and host are role-exclusive backends, so a future HCD sets this bit
    /// and this DCD must never see it set.
    #[expect(
        dead_code,
        reason = "device mode is this bit clear; naming it states the choice"
    )]
    pub const HOST_NDEVICE: u32 = 1 << 1;
}

/// `SIE_CTRL` bits.
mod sie_ctrl {
    /// Interrupt on every EP0 buffer, rather than only on the last.
    pub const EP0_INT_1BUF: u32 = 1 << 29;
    /// Drive the D+ pull-up: this is what announces the device to the host.
    pub const PULLUP_EN: u32 = 1 << 16;
}

/// `SIE_STATUS` bits. All write-one-to-clear.
mod sie_status {
    /// The host reset the bus.
    pub const BUS_RESET: u32 = 1 << 19;
    /// A setup packet has been written to DPRAM.
    pub const SETUP_REC: u32 = 1 << 17;
    /// The bus is suspended.
    pub const SUSPENDED: u32 = 1 << 4;
    /// Resume signalling from the host.
    pub const RESUME: u32 = 1 << 11;
}

/// `INTE` bits.
mod inte {
    /// A buffer completed.
    pub const BUFF_STATUS: u32 = 1 << 4;
    /// Bus reset.
    pub const BUS_RESET: u32 = 1 << 12;
    /// Suspend.
    pub const DEV_SUSPEND: u32 = 1 << 14;
    /// Resume.
    pub const DEV_RESUME_FROM_HOST: u32 = 1 << 15;
    /// Setup packet received.
    pub const SETUP_REQ: u32 = 1 << 16;
}

/// `USB_MUXING` bits.
mod muxing {
    /// Route the controller to the on-chip PHY.
    pub const TO_PHY: u32 = 1 << 0;
    /// Software-controlled connect.
    pub const SOFTCON: u32 = 1 << 3;
}

/// `USB_PWR` bits.
mod pwr {
    /// Assert VBUS detect.
    pub const VBUS_DETECT: u32 = 1 << 2;
    /// Let software override VBUS detection, which a bus-powered device must
    /// do — it has no way to sense VBUS and is by definition attached.
    pub const VBUS_DETECT_OVERRIDE_EN: u32 = 1 << 3;
}

/// Release the USB controller from reset.
///
/// Bounded. A reset that never completes is indistinguishable from
/// a hang, and this runs during boot where nothing is yet watching.
///
/// Returns whether the controller came out of reset.
#[must_use]
pub fn release_reset() -> bool {
    use crate::platform::chip::{RESETS_BASE, RESETS_USBCTRL_BIT};
    const RESET: usize = 0x00;
    const RESET_DONE: usize = 0x08;
    /// Generous against a reset that takes a few cycles.
    const LIMIT: u32 = 100_000;

    let base = RESETS_BASE as usize;
    let bit = 1u32 << RESETS_USBCTRL_BIT;

    // SAFETY: the generated reset-controller base and bit for this silicon.
    // RESET has atomic aliases, so clearing one peripheral's bit cannot
    // disturb another's — a read-modify-write here would race every other
    // driver doing the same thing.
    unsafe {
        crate::platform::rp_regs::clear_bits(base + RESET, bit);
        wait_until(LIMIT, || read32(base + RESET_DONE) & bit != 0)
    }
}

/// Bring the controller up in device mode, **without** announcing to the host.
///
/// Call [`attach`] afterwards, once the device can answer EP0. Splitting them
/// is the point: a pull-up raised before the device can answer invites the
/// host to enumerate something that is not ready.
///
/// Returns whether the controller left reset.
#[must_use]
pub fn init() -> bool {
    if !release_reset() {
        return false;
    }

    // SAFETY: the controller's own registers and its DPRAM, both at fixed
    // addresses this platform owns, with no other writer before attach.
    unsafe {
        // Clear DPRAM. The controller does not zero it, and stale endpoint
        // control words from a previous boot describe buffers this run has
        // not allocated — the SIE would act on them the moment it is enabled.
        for offset in (0..dpram::DATA_START).step_by(4) {
            write32(DPRAM_BASE + offset, 0);
        }

        // Route to the on-chip PHY and take software control of connect.
        write32(
            REGS_BASE + reg::USB_MUXING,
            muxing::TO_PHY | muxing::SOFTCON,
        );

        // A bus-powered device cannot sense VBUS and is attached by
        // definition, so it asserts detection rather than waiting for it.
        write32(
            REGS_BASE + reg::USB_PWR,
            pwr::VBUS_DETECT | pwr::VBUS_DETECT_OVERRIDE_EN,
        );

        // Device mode: HOST_NDEVICE clear.
        write32(REGS_BASE + reg::MAIN_CTRL, main_ctrl::CONTROLLER_EN);

        // Interrupt per EP0 buffer, so a multi-packet control transfer is
        // driven packet by packet rather than only at the end.
        set_bits(REGS_BASE + reg::SIE_CTRL, sie_ctrl::EP0_INT_1BUF);

        write32(
            REGS_BASE + reg::INTE,
            inte::BUFF_STATUS
                | inte::BUS_RESET
                | inte::SETUP_REQ
                | inte::DEV_SUSPEND
                | inte::DEV_RESUME_FROM_HOST,
        );
    }
    true
}

/// Raise the D+ pull-up, announcing the device to the host.
///
/// Separate from [`init`] on purpose — see this module's docs.
pub fn attach() {
    // SAFETY: the controller's own register, after init.
    unsafe { set_bits(REGS_BASE + reg::SIE_CTRL, sie_ctrl::PULLUP_EN) };
}

/// Drop the pull-up, so the host sees a disconnect.
pub fn detach() {
    // SAFETY: as `attach`.
    unsafe { crate::platform::rp_regs::clear_bits(REGS_BASE + reg::SIE_CTRL, sie_ctrl::PULLUP_EN) };
}

/// Set the device address the controller answers on.
///
/// Called from the control state machine's status-stage completion, never
/// when the request arrives — see [`control::ControlState`].
pub fn set_address(address: u8) {
    // SAFETY: the controller's own register.
    unsafe { write32(REGS_BASE + reg::ADDR_ENDP, (address & 0x7f) as u32) };
}

/// Read the setup packet the SIE deposited at the start of DPRAM.
pub fn read_setup() -> Option<control::Setup> {
    let mut bytes = [0u8; 8];
    // SAFETY: the first eight bytes of DPRAM are the setup region, written
    // by the SIE and read-only to us.
    unsafe {
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = core::ptr::read_volatile((DPRAM_BASE + dpram::SETUP_PACKET + i) as *const u8);
        }
    }
    control::Setup::parse(&bytes)
}

/// Drain up to `budget` controller events.
///
/// Bounded, and the bound is not cosmetic: `BUFF_STATUS` is set by hardware
/// while traffic continues, so an unbounded drain under load never returns
/// and starves every other module in the step. A bounded IRQ
/// completion bitmap drain" for exactly this reason.
///
/// Events are acknowledged as they are taken. Every status bit here is
/// write-one-to-clear, so acknowledging is a single-bit write — a
/// read-modify-write would clear whichever other events happened to be
/// pending at that instant, which is an interrupt silently lost.
pub fn drain(budget: u32, mut on_event: impl FnMut(Event)) -> u32 {
    let mut taken = 0;
    while taken < budget {
        // SAFETY: the controller's own status registers.
        let status = unsafe { read32(REGS_BASE + reg::SIE_STATUS) };

        // Bus reset first: it invalidates everything else that might be
        // pending, so reporting a stale setup packet after one would drive
        // the state machine from a configuration that no longer exists.
        if status & sie_status::BUS_RESET != 0 {
            // SAFETY: W1C, single bit.
            unsafe { clear_w1c(REGS_BASE + reg::SIE_STATUS, sie_status::BUS_RESET) };
            // Every completion still pending belongs to a transfer the
            // reset has just voided. Delivered after the reset, a data
            // stage the host never collected arrives into an idle control
            // machine, which refuses it and stalls EP0 — and the host's
            // first request after its reset meets a stalled endpoint.
            //
            // SAFETY: W1C; the reset has voided every endpoint's transfer,
            // so clearing all of them is what the bus state now is.
            unsafe { write32(REGS_BASE + reg::BUFF_STATUS, u32::MAX) };
            on_event(Event::BusReset);
            taken += 1;
            continue;
        }

        if status & sie_status::SETUP_REC != 0 {
            let setup = read_setup();
            // SAFETY: W1C, single bit.
            unsafe { clear_w1c(REGS_BASE + reg::SIE_STATUS, sie_status::SETUP_REC) };

            // A SETUP abandons whatever EP0 was doing (USB 2.0 §8.5.3, and
            // `ControlState::on_setup` implements the same rule), so any
            // EP0 buffer still flagged complete belongs to the transfer
            // just abandoned. Left set, it is delivered into the *new*
            // transfer one pass later: a stale OUT arrives as the status
            // stage of a read that has not had its data stage yet, and the
            // control machine refuses it — correctly, having been told
            // something that is not true. The host sees a device that
            // stalls its first descriptor read, resets, and finds the same
            // thing again.
            const EP0_BUFFERS: u32 = (1 << 0) | (1 << 1);
            // SAFETY: W1C; clearing only EP0's two bits leaves every other
            // endpoint's completion pending, which is correct — a SETUP
            // says nothing about them.
            unsafe { write32(REGS_BASE + reg::BUFF_STATUS, EP0_BUFFERS) };

            if let Some(setup) = setup {
                on_event(Event::Setup(setup));
            }
            taken += 1;
            continue;
        }

        // SAFETY: the controller's own register.
        let buffers = unsafe { read32(REGS_BASE + reg::BUFF_STATUS) };
        if buffers != 0 {
            // SAFETY: W1C; clearing exactly the bits just read leaves any
            // that were set in between still pending, which is correct.
            unsafe { write32(REGS_BASE + reg::BUFF_STATUS, buffers) };
            // One event per endpoint-direction, not one carrying the bitmap.
            //
            // The bits are independent endpoints and each is a separate
            // thing that happened. Handing over the raw bitmap made a
            // consumer pick one of them, and the others were cleared here
            // and never reported — a control completion alongside a bulk
            // one silently lost the bulk.
            //
            // Every bit read is reported, budget or not: they have already
            // been cleared, so anything not delivered now is gone.
            let mut bit = 0;
            while bit < 32 {
                let mask = 1u32 << bit;
                if buffers & mask != 0 {
                    on_event(Event::BuffersComplete(mask));
                    taken += 1;
                }
                bit += 1;
            }
            continue;
        }

        if status & sie_status::RESUME != 0 {
            // SAFETY: W1C, single bit.
            unsafe { clear_w1c(REGS_BASE + reg::SIE_STATUS, sie_status::RESUME) };
            on_event(Event::Resumed);
            taken += 1;
            continue;
        }

        if status & sie_status::SUSPENDED != 0 {
            // SAFETY: W1C, single bit.
            unsafe { clear_w1c(REGS_BASE + reg::SIE_STATUS, sie_status::SUSPENDED) };
            on_event(Event::Suspended);
            taken += 1;
            continue;
        }

        break;
    }
    taken
}

/// Why an endpoint could not be configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointError {
    /// This endpoint has no control word. Endpoint 0's buffers are at fixed
    /// addresses the SIE already knows, and an offset computed for it would
    /// land on the setup-packet region.
    NoControlWord,
}

/// Configure an endpoint's control word.
///
/// # Safety
/// `buffer_offset` must come from the DPRAM allocator, and the endpoint must
/// not currently be in use by the SIE.
pub unsafe fn configure_endpoint(
    endpoint: usize,
    is_in: bool,
    control_word: u32,
) -> Result<(), EndpointError> {
    let Some(offset) = dpram::ep_control(endpoint, is_in) else {
        return Err(EndpointError::NoControlWord);
    };
    // SAFETY: the caller's contract; `offset` is inside the endpoint-control
    // region, which `ep_control` bounds.
    unsafe { write32(DPRAM_BASE + offset, control_word) };
    Ok(())
}

/// Stall an endpoint.
pub fn stall(endpoint: usize, is_in: bool) {
    let bit = 1u32 << (endpoint * 2 + usize::from(is_in));
    // SAFETY: the controller's own register; a read-modify-write is correct
    // here because this register is not write-one-to-clear.
    unsafe { modify32(REGS_BASE + reg::EP_STATUS_STALL_NAK, |v| v | bit) };
}

// ============================================================================
// The pump's controller backend
// ============================================================================

use crate::kernel::usb::device::DeviceController;
use crate::platform::rp_usb_dpram::{
    buf_ctrl, buffer_control, dpram as dpram_map, endpoint_control, DpramAllocator,
    EndpointToggles, DPRAM_BASE as DPRAM,
};

/// A snapshot of the controller's registers.
///
/// A device that enumerates part-way leaves its evidence here and nowhere
/// else. Whether the host is still sending SETUPs, which buffers the SIE has
/// finished with, and which endpoints are stalled are all register state;
/// none of it is visible from the portable core, which sees only the events
/// this file chooses to raise.
#[derive(Clone, Copy, Debug, Default)]
pub struct Registers {
    /// `SIE_STATUS` — bus reset, setup received, suspend, resume.
    pub sie_status: u32,
    /// `SIE_CTRL` — pull-up, PHY and interrupt-per-buffer configuration.
    pub sie_ctrl: u32,
    /// `ADDR_ENDP` — the address the SIE is answering on.
    pub addr_endp: u32,
    /// `BUFF_STATUS` — one bit per endpoint direction the SIE has finished.
    pub buff_status: u32,
    /// `EP_STATUS_STALL_NAK`.
    pub stall_nak: u32,
    /// `INTS` — latched interrupt causes, whether or not they are enabled.
    pub ints: u32,
    /// Endpoint control words for EP1 IN/OUT and EP2 IN/OUT, in that order.
    /// EP0 has none: its buffers live at addresses the SIE already knows.
    pub ep_control: [u32; 4],
    /// Buffer control words for EP0 IN/OUT, EP1 IN/OUT, EP2 IN/OUT.
    pub buf_control: [u32; 6],
}

/// Read the controller's registers.
///
/// Reads only; nothing here is write-one-to-clear, so a snapshot cannot
/// consume the event the caller is trying to explain.
pub fn registers() -> Registers {
    // SAFETY: plain MMIO reads of the controller's own register block and
    // its DPRAM, at offsets fixed by the datasheet; nothing here is
    // write-one-to-clear, so reading consumes no event.
    unsafe {
        let mut r = Registers {
            sie_status: read32(REGS_BASE + reg::SIE_STATUS),
            sie_ctrl: read32(REGS_BASE + reg::SIE_CTRL),
            addr_endp: read32(REGS_BASE + reg::ADDR_ENDP),
            buff_status: read32(REGS_BASE + reg::BUFF_STATUS),
            stall_nak: read32(REGS_BASE + reg::EP_STATUS_STALL_NAK),
            ints: read32(REGS_BASE + reg::INTS),
            ep_control: [0; 4],
            buf_control: [0; 6],
        };
        for (i, w) in r.ep_control.iter_mut().enumerate() {
            // EP_CONTROL is indexed from EP1, two words per endpoint (IN, OUT).
            *w = read32(DPRAM_BASE + dpram::EP_CONTROL + i * 4);
        }
        for (i, w) in r.buf_control.iter_mut().enumerate() {
            *w = read32(DPRAM_BASE + dpram::EP_BUFFER_CONTROL + i * 4);
        }
        r
    }
}

/// EP0's maximum packet size. Sixty-four bytes is the full-speed maximum and
/// what the RP controller's fixed EP0 buffers hold.
pub const EP0_MAX_PACKET: u16 = 64;

/// The RP2 device controller, as the portable pump sees it.
///
/// Holds the DPRAM allocator and the per-endpoint data toggles the hardware
/// does not track for us.
pub struct RpDeviceController {
    allocator: DpramAllocator,
    /// Data toggles for the class endpoints. The hardware carries whatever
    /// PID the buffer-control word says, and tracks nothing itself.
    toggles: EndpointToggles,
}

impl Default for RpDeviceController {
    fn default() -> Self {
        Self::new()
    }
}

impl RpDeviceController {
    /// A controller with DPRAM unallocated.
    pub const fn new() -> Self {
        Self {
            allocator: DpramAllocator::new(),
            toggles: EndpointToggles::new(),
        }
    }

    /// The DPRAM allocator, for endpoint configuration.
    pub fn allocator(&mut self) -> &mut DpramAllocator {
        &mut self.allocator
    }

    /// Allocate DPRAM and enable the CDC function's three non-zero
    /// endpoints.
    ///
    /// **The descriptors are a promise and this is what keeps it.** A host
    /// that has read the configuration will open the pipes it was told
    /// about; an endpoint that was described but never given a buffer or an
    /// enable bit is not an error the host can see, it is a pipe that
    /// accepts a transfer and moves nothing. The device enumerates, the
    /// driver binds, and the port is silent — which is the hardest shape of
    /// failure to attribute, because every layer reports success.
    ///
    /// Idempotent: a second call finds the endpoints already allocated and
    /// returns true without disturbing buffers the SIE may be holding.
    ///
    /// Endpoint numbers and sizes come from
    /// [`cdc_descriptors::endpoint`](crate::kernel::usb::cdc_descriptors::endpoint),
    /// so the hardware is configured from the same constants the host was
    /// told about rather than from a parallel set that can drift.
    pub fn configure_cdc_endpoints(&mut self) -> bool {
        use crate::kernel::usb::cdc_descriptors::endpoint as cdc_ep;

        /// `EP_CTRL.ENDPOINT_TYPE`.
        const TYPE_BULK: u32 = 2;
        /// `EP_CTRL.ENDPOINT_TYPE`.
        const TYPE_INTERRUPT: u32 = 3;

        // (endpoint number, is_in, packet size, transfer type)
        let plan = [
            (
                (cdc_ep::NOTIFICATION_IN & 0x0f) as usize,
                true,
                cdc_ep::NOTIFICATION_MAX_PACKET as usize,
                TYPE_INTERRUPT,
            ),
            (
                (cdc_ep::DATA_OUT & 0x0f) as usize,
                false,
                cdc_ep::DATA_MAX_PACKET as usize,
                TYPE_BULK,
            ),
            (
                (cdc_ep::DATA_IN & 0x0f) as usize,
                true,
                cdc_ep::DATA_MAX_PACKET as usize,
                TYPE_BULK,
            ),
        ];

        for (ep, is_in, size, kind) in plan {
            if self.allocator.is_allocated(ep, is_in) {
                continue;
            }
            let Ok(offset) = self.allocator.allocate(ep, is_in, size) else {
                return false;
            };
            let Some(ctrl) = dpram_map::ep_control(ep, is_in) else {
                return false;
            };
            // Interrupt per buffer on every one of them: the pump is polled
            // and reads the buffer-status bitmap to learn what completed, so
            // an endpoint that does not set its bit is an endpoint the pump
            // never services.
            let Ok(word) = endpoint_control(offset, kind, true) else {
                return false;
            };
            // SAFETY: `ctrl` is an endpoint-control word inside DPRAM and
            // `word` carries an offset this allocator just handed out.
            unsafe { write32(DPRAM + ctrl, word) };
        }

        // Hand the bulk OUT buffer to the SIE so the host can send to us
        // immediately. An OUT endpoint with no buffer available NAKs every
        // packet, which a host reads as a device that is merely busy — so it
        // retries forever rather than reporting anything.
        self.arm_bulk_out();
        true
    }

    /// Give the SIE an empty bulk OUT buffer to fill.
    ///
    /// One buffer is one packet: the endpoint accepts a packet into it and
    /// then NAKs until it is armed again. Configuration arms it once, which
    /// is what a console that only carries bytes outward needs; carrying
    /// host-to-device bytes means arming it again for each packet, from
    /// wherever that packet is consumed.
    pub fn arm_bulk_out(&mut self) {
        use crate::kernel::usb::cdc_descriptors::endpoint as cdc_ep;
        let ep = (cdc_ep::DATA_OUT & 0x0f) as usize;
        let Some(offset) = dpram_map::ep_buffer_control(ep, false) else {
            return;
        };
        let Ok(control) = buffer_control(cdc_ep::DATA_MAX_PACKET, false, false, true) else {
            return;
        };
        Self::arm(offset, control);
    }

    /// The largest packet an endpoint carries.
    ///
    /// Used to decide whether a packet ends a transfer, so it has to be the
    /// endpoint's real size rather than a convenient constant: a packet
    /// judged short against the wrong number is marked as ending a transfer
    /// that has more to come.
    fn max_packet(endpoint: u8) -> u16 {
        use crate::kernel::usb::cdc_descriptors::endpoint as cdc_ep;
        if endpoint == 0 {
            EP0_MAX_PACKET
        } else if endpoint == cdc_ep::NOTIFICATION_IN & 0x0f {
            cdc_ep::NOTIFICATION_MAX_PACKET
        } else {
            cdc_ep::DATA_MAX_PACKET
        }
    }

    /// Address of an endpoint's data buffer, or `None` for an endpoint that
    /// has not been given one.
    ///
    /// EP0's buffers are at a fixed address the SIE already knows;
    /// everything else is read back from the allocator that assigned it, so
    /// this address and the one in the endpoint's control word are the same
    /// number by construction.
    fn buffer(&self, endpoint: u8, is_in: bool) -> Option<usize> {
        if endpoint == 0 {
            return Some(DPRAM + dpram_map::EP0_BUFFER_A);
        }
        self.allocator
            .offset(endpoint as usize, is_in)
            .map(|offset| DPRAM + offset)
    }

    /// Hand a buffer to the SIE.
    ///
    /// **Two writes, deliberately.** `AVAILABLE` transfers ownership of the
    /// buffer-control word to the hardware, so setting it in the same write
    /// as the length and toggle lets the SIE act before the rest of the word
    /// is visible. The barrier between them is what makes that ordering real
    /// rather than a hope about the compiler.
    fn arm(offset: usize, control: u32) {
        // SAFETY: `offset` is a buffer-control word inside DPRAM.
        unsafe {
            write32(DPRAM + offset, control);
            crate::arch::cortex_m::dmb();
            write32(DPRAM + offset, control | buf_ctrl::AVAILABLE);
        }
    }
}

impl DeviceController for RpDeviceController {
    fn send(&mut self, endpoint: u8, data: &[u8], data1: bool) {
        let Some(offset) = dpram_map::ep_buffer_control(endpoint as usize, true) else {
            return;
        };
        let Some(buf) = self.buffer(endpoint, true) else {
            return;
        };
        // SAFETY: the endpoint's own data buffer, sized at least as large as
        // one packet by the allocator (or fixed, for EP0).
        unsafe {
            for (i, &b) in data.iter().enumerate() {
                core::ptr::write_volatile((buf + i) as *mut u8, b);
            }
        }
        // FULL: this buffer holds data to send.
        //
        // **LAST only when this packet really is the last.** `LAST_BUFF`
        // tells the SIE the transfer ends with this buffer, and the SIE
        // believes it: setting it on a full-size packet that has more to
        // follow completes the transfer early, and the remainder is never
        // sent. A short packet ends a transfer by definition, and a
        // full-size one never does — the host keeps reading until it sees a
        // short packet or has the length it asked for.
        //
        // The distinction only bites above one packet, because a transfer
        // that fits in a single buffer is last by definition. The first one
        // that does not is the configuration descriptor, and a device that
        // cannot deliver that enumerates fully and then never configures.
        let last = data.len() < Self::max_packet(endpoint) as usize;

        // EP0's toggle comes from the control state machine, which knows the
        // transfer's shape. Every other endpoint alternates per packet and
        // nothing above this layer is tracking it: sent with a fixed PID,
        // the host acknowledges each packet and keeps only the first, having
        // read the rest as retransmissions of it. The endpoint completes
        // every transfer, so from the device's side the link looks perfect.
        let data1 = if endpoint == 0 {
            data1
        } else {
            self.toggles.take(endpoint as usize, true)
        };

        let Ok(control) = buffer_control(data.len() as u16, data1, true, last) else {
            return;
        };
        Self::arm(offset, control);
    }

    fn receive(&mut self, endpoint: u8, len: u16, data1: bool) {
        let Some(offset) = dpram_map::ep_buffer_control(endpoint as usize, false) else {
            return;
        };
        // Not FULL: the buffer is empty and waiting for the host.
        let Ok(control) = buffer_control(len.min(EP0_MAX_PACKET), data1, false, true) else {
            return;
        };
        Self::arm(offset, control);
    }

    fn stall(&mut self, endpoint: u8) {
        // Both directions: a stalled control endpoint refuses the transfer
        // whichever way the host tries to continue it.
        stall(endpoint as usize, true);
        stall(endpoint as usize, false);
    }

    fn set_address(&mut self, address: u8) {
        set_address(address);
    }

    fn ep0_max_packet(&self) -> u16 {
        EP0_MAX_PACKET
    }

    fn bus_reset(&mut self) {
        self.toggles.reset();
        // An EP0 buffer left armed from before the reset would complete
        // against the host's first packet afterwards, as a stage of a
        // transfer that no longer exists.
        for is_in in [true, false] {
            if let Some(offset) = dpram_map::ep_buffer_control(0, is_in) {
                // SAFETY: an EP0 buffer-control word inside DPRAM; zero is
                // "not available", which disarms it.
                unsafe { write32(DPRAM + offset, 0) };
            }
        }
    }
}

/// Bytes the SIE reports it moved on an EP0 buffer.
pub fn ep0_transferred(is_in: bool) -> u16 {
    let Some(offset) = dpram_map::ep_buffer_control(0, is_in) else {
        return 0;
    };
    // SAFETY: an EP0 buffer-control word inside DPRAM.
    let w = unsafe { read32(DPRAM + offset) };
    (w & ((1 << buf_ctrl::LENGTH_WIDTH) - 1)) as u16
}
