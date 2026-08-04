// Core: dgram_egress — reusable UDP datagram egress endpoint.
//
// Layer: cores (reusable SDK implementation, `include!`d at a consumer module's
// top level so it shares the module's `sdk/runtime` scope — `net_write_frame`,
// `net_read_frame`, `dev_dg_send_to_v4`, `dev_micros`, the `DG_*` opcodes). NOT a
// wire contract: it drives the EXISTING `datagram` contract (CMD_DG_BIND /
// MSG_DG_BOUND / CMD_DG_SEND_TO), it does not define a new one.
//
// Owns the datagram-endpoint lifecycle every "push a byte stream out as UDP"
// module needs — the bind handshake (`CMD_DG_BIND` → `MSG_DG_BOUND`, backoff on
// `MSG_DG_ERROR`, give-up cap) and the addressed send — so `log_net`,
// `transport_buffer`, and any future datagram sender share ONE implementation
// instead of each re-rolling the state machine. The caller supplies its ip
// channels + a scratch buffer and its own payload source (log ring, channel).
//
// Usage each step (the caller owns dst_ip/dst_port/bind_port, e.g. from params):
//   if egress.poll(sys, net_out, net_in, bind_port, dst_ip, scratch, max) {
//       egress.send(sys, net_out, dst_ip, dst_port, data, len, scratch, max);
//   }

/// Give up binding after this many consecutive failures (stays faultless).
const EGRESS_MAX_BIND_ATTEMPTS: u16 = 50;
/// Backoff window between bind retries — wall-clock, tick-rate independent
/// (RFC adaptive_tick §7.6: diagnostic cadence, no correctness impact).
const EGRESS_BACKOFF_MICROS: u64 = 100_000; // 100 ms

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum EgressPhase {
    Init = 0,
    Binding = 1,
    WaitBound = 2,
    Serving = 3,
    Backoff = 4,
    /// `dst_ip` unset (0) or L2 broadcast — terminal dormant.
    Disabled = 5,
}

/// A bound UDP datagram endpoint over the ip datagram surface.
pub struct DgramEgress {
    phase: EgressPhase,
    /// endpoint id from MSG_DG_BOUND (`0xFF` = unallocated).
    ep_id: u8,
    bind_attempts: u16,
    backoff_until_micros: u64,
}

impl DgramEgress {
    pub const fn new() -> Self {
        DgramEgress {
            phase: EgressPhase::Init,
            ep_id: 0xFF,
            bind_attempts: 0,
            backoff_until_micros: 0,
        }
    }

    /// `dst_ip` was unset / broadcast — the endpoint will never bind.
    pub fn is_disabled(&self) -> bool {
        self.phase == EgressPhase::Disabled
    }

    /// The endpoint is bound and ready to `send`.
    pub fn is_ready(&self) -> bool {
        self.phase == EgressPhase::Serving
    }

    /// Drive the bind lifecycle one step. `net_out`/`net_in` are the caller's ip
    /// channels; `scratch` (len `scratch_max`) is a work buffer for bind frames.
    /// Returns true once the endpoint is bound (Serving) and can `send`.
    ///
    /// # Safety
    /// `scratch` must be valid for writes of `scratch_max` bytes; `sys` is the
    /// live syscall table.
    pub unsafe fn poll(
        &mut self,
        sys: &SyscallTable,
        net_out: i32,
        net_in: i32,
        bind_port: u16,
        dst_ip: u32,
        scratch: *mut u8,
        scratch_max: usize,
    ) -> bool {
        match self.phase {
            EgressPhase::Init => {
                if dst_ip == 0 || dst_ip == 0xFFFF_FFFF {
                    self.phase = EgressPhase::Disabled;
                } else {
                    self.phase = EgressPhase::Binding;
                }
                false
            }
            EgressPhase::Disabled => false,
            EgressPhase::Binding => {
                if net_out < 0 || self.bind_attempts >= EGRESS_MAX_BIND_ATTEMPTS {
                    return false;
                }
                // CMD_DG_BIND payload: [port: u16 LE][flags: u8 = 0]
                let mut payload = [0u8; 3];
                let p = bind_port.to_le_bytes();
                payload[0] = p[0];
                payload[1] = p[1];
                payload[2] = 0;
                let wrote =
                    net_write_frame(sys, net_out, DG_CMD_BIND, payload.as_ptr(), 3, scratch, scratch_max);
                if wrote == 0 {
                    return false; // channel full — retry next step.
                }
                self.bind_attempts += 1;
                self.phase = EgressPhase::WaitBound;
                false
            }
            EgressPhase::WaitBound => {
                if net_in < 0 {
                    return false;
                }
                let poll = (sys.channel_poll)(net_in, 0x01 /* POLL_IN */);
                if poll <= 0 || (poll & 0x01) == 0 {
                    return false;
                }
                let (msg_type, payload_len) = net_read_frame(sys, net_in, scratch, scratch_max);
                if msg_type == DG_MSG_BOUND && payload_len >= 3 {
                    // MSG_DG_BOUND payload: [ep_id:1][local_port:2 LE].
                    let bound_port = (*scratch.add(4) as u16) | ((*scratch.add(5) as u16) << 8);
                    if bound_port == bind_port {
                        self.ep_id = *scratch.add(3);
                        self.phase = EgressPhase::Serving;
                        self.bind_attempts = 0;
                        return true;
                    }
                } else if msg_type == DG_MSG_ERROR {
                    self.phase = EgressPhase::Backoff;
                    self.backoff_until_micros = dev_micros(sys).wrapping_add(EGRESS_BACKOFF_MICROS);
                }
                // Other message (e.g. a bound reply for someone else's port on a
                // tee'd net_out) — stay in WaitBound.
                false
            }
            EgressPhase::Backoff => {
                if dev_micros(sys) < self.backoff_until_micros {
                    return false;
                }
                self.phase = EgressPhase::Binding;
                false
            }
            EgressPhase::Serving => true,
        }
    }

    /// Send `data[..len]` as one datagram to the configured destination. A
    /// datagram is atomic: returns `len` (whole payload accepted) or `0`
    /// (backpressure / not ready). Only meaningful once `is_ready()`.
    ///
    /// # Safety
    /// `data` valid for `len` reads; `scratch` valid for `scratch_max` writes.
    pub unsafe fn send(
        &self,
        sys: &SyscallTable,
        net_out: i32,
        dst_ip: u32,
        dst_port: u16,
        data: *const u8,
        len: usize,
        scratch: *mut u8,
        scratch_max: usize,
    ) -> usize {
        if self.phase != EgressPhase::Serving || net_out < 0 || self.ep_id == 0xFF {
            return 0;
        }
        let n = dev_dg_send_to_v4(
            sys,
            net_out,
            self.ep_id,
            dst_ip,
            dst_port,
            data,
            len,
            scratch,
            scratch_max,
        );
        if n > 0 {
            len
        } else {
            0
        }
    }
}
