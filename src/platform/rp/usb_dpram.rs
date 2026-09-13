//! RP2 USB controller registers and DPRAM allocation.
//!
//! The USB controller has 4 KiB of dual-port RAM shared between the CPU and
//! the serial interface engine. Its first 0x180 bytes are fixed by hardware —
//! the setup packet, the per-endpoint control words, and EP0's two buffers —
//! and everything after that is for the driver to hand out.
//!
//! # Why the allocator is the interesting part
//!
//! Nothing checks this layout at runtime. An endpoint buffer address is
//! written into a control word and the SIE uses it; two endpoints given
//! overlapping ranges both work, in the sense that neither faults, and each
//! silently corrupts the other's data. The symptom is a flaky USB link that
//! looks like an electrical problem.
//!
//! So allocation is deterministic, checked, and refuses rather than wraps:
//! a graph asking for more endpoint buffer than the part has is a
//! configuration error to report at bring-up, not a corruption to debug later.
//!
//! The register map and DPRAM layout are identical on RP2040 and RP2350 —
//! unusually for this family, and worth stating because almost nothing else
//! in `platform/rp` is.

/// DPRAM base. The same address on both chips.
pub const DPRAM_BASE: usize = 0x5010_0000;
/// Controller register base. The same address on both chips.
pub const REGS_BASE: usize = 0x5011_0000;
/// Total DPRAM, in bytes.
pub const DPRAM_SIZE: usize = 4096;

/// Controller register offsets. Identical on both chips.
pub mod reg {
    /// Device address and endpoint.
    pub const ADDR_ENDP: usize = 0x00;
    /// Main control: controller enable, device/host mode.
    pub const MAIN_CTRL: usize = 0x40;
    /// Serial interface engine control.
    pub const SIE_CTRL: usize = 0x4c;
    /// Serial interface engine status.
    pub const SIE_STATUS: usize = 0x50;
    /// Which buffers the SIE has finished with — one bit per endpoint
    /// direction.
    pub const BUFF_STATUS: usize = 0x58;
    /// Abort a transfer in progress.
    pub const EP_ABORT: usize = 0x60;
    /// Per-endpoint stall/NAK status.
    pub const EP_STATUS_STALL_NAK: usize = 0x70;
    /// PHY muxing: which pins the controller drives.
    pub const USB_MUXING: usize = 0x74;
    /// VBUS detect and power override.
    pub const USB_PWR: usize = 0x78;
    /// Interrupt enable.
    pub const INTE: usize = 0x90;
    /// Interrupt status.
    pub const INTS: usize = 0x98;
}

/// Fixed DPRAM offsets, from the RP datasheet's device-mode layout.
pub mod dpram {
    /// The setup packet the SIE writes on a control transfer. Eight bytes,
    /// always at the start.
    pub const SETUP_PACKET: usize = 0x00;
    /// Length of the setup packet region.
    pub const SETUP_PACKET_LEN: usize = 8;
    /// Endpoint control words, for endpoints 1..=15 only — EP0 has none,
    /// because its buffers are at fixed addresses the SIE already knows.
    pub const EP_CONTROL: usize = 0x08;
    /// Buffer control words, for endpoints 0..=15.
    pub const EP_BUFFER_CONTROL: usize = 0x80;
    /// EP0's first buffer, 64 bytes at a fixed address.
    pub const EP0_BUFFER_A: usize = 0x100;
    /// EP0's second buffer.
    pub const EP0_BUFFER_B: usize = 0x140;
    /// Where driver-allocated endpoint data may begin.
    pub const DATA_START: usize = 0x180;

    /// Endpoints the controller implements.
    pub const NUM_ENDPOINTS: usize = 16;

    /// Offset of endpoint `ep`'s control word for a direction.
    ///
    /// `None` for endpoint 0: it has no control word, and returning an
    /// address for it would write over the setup-packet region.
    #[inline]
    pub const fn ep_control(ep: usize, is_in: bool) -> Option<usize> {
        if ep == 0 || ep >= NUM_ENDPOINTS {
            return None;
        }
        // Two words per endpoint, IN first, starting from endpoint 1.
        let dir = if is_in { 0 } else { 4 };
        Some(EP_CONTROL + (ep - 1) * 8 + dir)
    }

    /// Offset of endpoint `ep`'s buffer control word for a direction.
    /// Endpoint 0 *does* have these.
    #[inline]
    pub const fn ep_buffer_control(ep: usize, is_in: bool) -> Option<usize> {
        if ep >= NUM_ENDPOINTS {
            return None;
        }
        let dir = if is_in { 0 } else { 4 };
        Some(EP_BUFFER_CONTROL + ep * 8 + dir)
    }
}

/// `EP_CONTROL` word fields.
pub mod ep_ctrl {
    /// Endpoint enabled.
    pub const ENABLE: u32 = 1 << 31;
    /// Raise an interrupt for every buffer completed.
    pub const INTERRUPT_PER_BUFFER: u32 = 1 << 29;
    /// Transfer type, two bits.
    pub const TYPE_LSB: u32 = 26;
    /// Width of the transfer-type field.
    pub const TYPE_WIDTH: u32 = 2;
    /// Buffer address, as an offset into DPRAM.
    pub const BUFFER_ADDRESS_LSB: u32 = 0;
    /// Width of the buffer-address field.
    pub const BUFFER_ADDRESS_WIDTH: u32 = 16;
}

/// `EP_BUFFER_CONTROL` word fields, for the first of the two buffers.
///
/// The SIE owns this word while `AVAILABLE` is set. Writing any other field
/// at that moment races the hardware, which is why [`buffer_control`] builds
/// the whole word and the caller sets `AVAILABLE` as a separate, later write.
pub mod buf_ctrl {
    /// The buffer holds data the SIE may send, or has received.
    pub const FULL: u32 = 1 << 15;
    /// This buffer ends the transfer.
    pub const LAST: u32 = 1 << 14;
    /// Data toggle: DATA1 when set, DATA0 when clear.
    pub const PID_DATA1: u32 = 1 << 13;
    /// Hand the buffer to the SIE. Must be written *after* the rest.
    pub const AVAILABLE: u32 = 1 << 10;
    /// Byte count, ten bits.
    pub const LENGTH_LSB: u32 = 0;
    /// Width of the length field.
    pub const LENGTH_WIDTH: u32 = 10;
}

/// Largest length the buffer-control word can express.
pub const MAX_BUFFER_LENGTH: u16 = (1 << buf_ctrl::LENGTH_WIDTH) - 1;

/// Buffer alignment the controller requires.
///
/// The buffer-address field is a byte offset, but the SIE requires 64-byte
/// alignment; an unaligned address is accepted by the register and produces
/// transfers to the wrong place.
pub const BUFFER_ALIGN: usize = 64;

/// Why a DPRAM allocation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpramError {
    /// Not enough DPRAM left for the requested buffer.
    Exhausted,
    /// The endpoint number is outside 0..16, or is 0 where 0 is not allowed.
    InvalidEndpoint,
    /// The requested size is zero or beyond what one buffer can describe.
    InvalidSize,
    /// This endpoint and direction already has a buffer.
    AlreadyAllocated,
}

/// Deterministic bump allocator for the driver-usable part of DPRAM.
///
/// A bump allocator, deliberately: endpoint buffers live for as long as the
/// configuration does, so there is nothing to free, and a free list would add
/// a fragmentation failure mode in exchange for flexibility nothing wants.
/// Reconfiguration resets the whole allocator, which is the only correct
/// moment to reuse any of it.
pub struct DpramAllocator {
    next: usize,
    /// Bit per endpoint-direction: `ep * 2 + is_in`.
    allocated: u32,
    /// The offset handed to each endpoint direction, same index as
    /// `allocated`. The endpoint's control word and the address the driver
    /// writes its bytes through have to name the same buffer; holding the
    /// offset here makes that one fact rather than two that can drift.
    offsets: [u16; dpram::NUM_ENDPOINTS * 2],
}

impl Default for DpramAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl DpramAllocator {
    /// An allocator with the fixed region reserved.
    pub const fn new() -> Self {
        Self {
            next: dpram::DATA_START,
            allocated: 0,
            offsets: [0; dpram::NUM_ENDPOINTS * 2],
        }
    }

    /// Reset to the empty state, releasing every endpoint buffer.
    ///
    /// Only valid when no endpoint is enabled — the SIE holds buffer
    /// addresses in its control words, and handing the same DPRAM out again
    /// while it is still reading them is the corruption this type exists to
    /// prevent.
    pub fn reset(&mut self) {
        self.next = dpram::DATA_START;
        self.allocated = 0;
        self.offsets = [0; dpram::NUM_ENDPOINTS * 2];
    }

    /// Bytes still available.
    pub const fn remaining(&self) -> usize {
        DPRAM_SIZE - self.next
    }

    /// Allocate a buffer for one endpoint direction, returning its DPRAM
    /// offset.
    ///
    /// The offset is what goes in the endpoint's control word, so it is
    /// aligned here rather than trusted from the caller.
    pub fn allocate(
        &mut self,
        endpoint: usize,
        is_in: bool,
        size: usize,
    ) -> Result<usize, DpramError> {
        if endpoint >= dpram::NUM_ENDPOINTS {
            return Err(DpramError::InvalidEndpoint);
        }
        if size == 0 || size > MAX_BUFFER_LENGTH as usize {
            return Err(DpramError::InvalidSize);
        }

        let bit = 1u32 << (endpoint * 2 + usize::from(is_in));
        if self.allocated & bit != 0 {
            return Err(DpramError::AlreadyAllocated);
        }

        // Round the size up, not just the start: the next buffer must also
        // land on an alignment boundary, and rounding only the start lets a
        // 65-byte buffer overlap the one after it.
        let stride = size.div_ceil(BUFFER_ALIGN) * BUFFER_ALIGN;
        let start = self.next;
        let end = start.checked_add(stride).ok_or(DpramError::Exhausted)?;
        if end > DPRAM_SIZE {
            return Err(DpramError::Exhausted);
        }

        self.next = end;
        self.allocated |= bit;
        self.offsets[endpoint * 2 + usize::from(is_in)] = start as u16;
        Ok(start)
    }

    /// Whether this endpoint direction has a buffer.
    pub const fn is_allocated(&self, endpoint: usize, is_in: bool) -> bool {
        if endpoint >= dpram::NUM_ENDPOINTS {
            return false;
        }
        self.allocated & (1u32 << (endpoint * 2 + if is_in { 1 } else { 0 })) != 0
    }

    /// Where this endpoint direction's buffer starts, or `None` if it has
    /// none. This is the address the driver must write through: the SIE
    /// reads the endpoint's bytes from wherever the control word points,
    /// and a write to any other address is a transfer that reports success
    /// and moves nothing the host will read.
    pub const fn offset(&self, endpoint: usize, is_in: bool) -> Option<usize> {
        if !self.is_allocated(endpoint, is_in) {
            return None;
        }
        Some(self.offsets[endpoint * 2 + if is_in { 1 } else { 0 }] as usize)
    }
}

/// Build an endpoint control word.
///
/// `buffer_offset` must come from [`DpramAllocator::allocate`]; it is
/// re-checked here because a misaligned or out-of-range address is accepted
/// by the register and produces transfers to the wrong place rather than an
/// error.
pub fn endpoint_control(
    buffer_offset: usize,
    transfer_type: u32,
    interrupt_per_buffer: bool,
) -> Result<u32, DpramError> {
    if buffer_offset < dpram::DATA_START
        || buffer_offset >= DPRAM_SIZE
        || !buffer_offset.is_multiple_of(BUFFER_ALIGN)
    {
        return Err(DpramError::InvalidSize);
    }
    let mut w = ep_ctrl::ENABLE;
    if interrupt_per_buffer {
        w |= ep_ctrl::INTERRUPT_PER_BUFFER;
    }
    w |= (transfer_type & 0x3) << ep_ctrl::TYPE_LSB;
    w |= buffer_offset as u32 & ((1 << ep_ctrl::BUFFER_ADDRESS_WIDTH) - 1);
    Ok(w)
}

/// Build a buffer control word **without** `AVAILABLE`.
///
/// `AVAILABLE` hands the buffer to the SIE, and from that moment the SIE owns
/// the word. Setting it in the same write as the length and toggle is a race:
/// the hardware may act on the word before the rest of it is visible. The
/// caller writes this value, then sets `AVAILABLE` in a second write.
pub fn buffer_control(length: u16, data1: bool, full: bool, last: bool) -> Result<u32, DpramError> {
    if length > MAX_BUFFER_LENGTH {
        return Err(DpramError::InvalidSize);
    }
    let mut w = (length as u32) << buf_ctrl::LENGTH_LSB;
    if data1 {
        w |= buf_ctrl::PID_DATA1;
    }
    if full {
        w |= buf_ctrl::FULL;
    }
    if last {
        w |= buf_ctrl::LAST;
    }
    Ok(w)
}

/// The next data toggle for a control transfer's data stage.
///
/// Control transfers start their data stage at DATA1 and alternate. Getting
/// this wrong does not error: the host discards the packet as a retransmission
/// and the transfer stalls with both sides believing they are correct.
#[inline]
pub const fn next_toggle(current: bool) -> bool {
    !current
}

/// The data toggles for non-control endpoints, one bit per endpoint and
/// direction.
///
/// The hardware does not track these: the buffer-control word carries
/// whatever PID the driver puts in it. A toggle that never alternates is
/// accepted and acknowledged by the host and then *discarded* as a
/// retransmission of the packet it already has — so the first packet after
/// a reset arrives, every later one vanishes, and the link looks alive from
/// the device's side because the transfers all complete.
///
/// Control endpoints are not here. Their toggles are fixed by the transfer's
/// shape (a data stage starts at DATA1, a status stage is always DATA1), so
/// the control state machine is the authority for EP0.
#[derive(Clone, Copy, Debug, Default)]
pub struct EndpointToggles {
    in_bits: u16,
    out_bits: u16,
}

impl EndpointToggles {
    /// All toggles at DATA0, as after a bus reset.
    pub const fn new() -> Self {
        Self {
            in_bits: 0,
            out_bits: 0,
        }
    }

    /// The toggle this packet carries, advancing the endpoint to the next.
    pub fn take(&mut self, endpoint: usize, is_in: bool) -> bool {
        if endpoint >= 16 {
            return false;
        }
        let bit = 1u16 << endpoint;
        let bits = if is_in {
            &mut self.in_bits
        } else {
            &mut self.out_bits
        };
        let current = *bits & bit != 0;
        *bits ^= bit;
        current
    }

    /// Return every endpoint to DATA0.
    ///
    /// A bus reset does this on the host's side whether or not the device
    /// agrees, so a device that keeps its toggles across one is out of step
    /// from the first packet.
    pub fn reset(&mut self) {
        self.in_bits = 0;
        self.out_bits = 0;
    }
}
