// Core: datagram_endpoint — reusable bound UDP datagram socket (bind + send + recv).
//
// Layer: cores (reusable SDK implementation, `include!`d at a consumer module's
// top level so it shares the module's `sdk/runtime` scope — `net_write_frame`,
// `net_read_frame`, `parse_dg_rx_from_v4`, `dev_dg_send_to_v4`, `dev_micros`, the
// `DG_*` opcodes). NOT a wire contract: it drives the EXISTING `datagram`
// contract (CMD_DG_BIND / MSG_DG_BOUND / CMD_DG_SEND_TO / MSG_DG_RX_FROM), it
// does not define a new one.
//
// One struct == one bound endpoint (one `ep_id`). It owns the bind lifecycle
// (bind handshake with backoff) and the addressed send — the parts every "talk
// UDP over the datagram surface" module (`log_net`, `transport_buffer`, `dns`,
// `quic`, `dtls`) would otherwise re-roll.
//
// RECEIVE is deliberately NOT an endpoint method. The datagram contract stamps
// every RX frame with its `ep_id`, so ONE channel fans-in many endpoints. The
// consumer therefore drains `net_in` with the free `dg_recv` helper and routes
// each event itself — by `ep_id` (`dns`), by an upper-layer key (`quic` DCID,
// `dtls` 4-tuple), or ignoring it (send-only). Burying the channel read inside a
// per-endpoint `recv` would drop another endpoint's frames on a shared channel.
//
// Two usage modes:
//   send-only / single endpoint:
//       let ready = ep.poll(sys, net_out, net_in, bind_port, dst_ip, scratch, max);
//       if ready { ep.send_to(sys, net_out, dst_ip, dst_port, data, len, scratch, max); }
//   receiving / multiple endpoints on one channel:
//       ep.poll_bind(sys, net_out, bind_port, scratch, max);   // per endpoint, each step
//       while let Some(ev) = dg_recv(sys, net_in, scratch, max) {
//           match ev {
//               DgEvent::Bound { ep_id, local_port } => awaiting_ep.on_bound(ep_id, local_port),
//               DgEvent::Rx { ep_id, src_ip, src_port, data, len } => { /* route by ep_id / DCID / 4-tuple */ }
//               DgEvent::Err { .. } => ep.on_error(sys),
//               DgEvent::Closed { .. } => { /* teardown */ }
//           }
//       }
// With multiple endpoints on one channel, bind them SEQUENTIALLY (or with
// distinct known ports) so each MSG_DG_BOUND routes unambiguously to the single
// endpoint currently in WaitBound.

// This core is `include!`d into several modules, each of which drives only a
// subset of the surface (send-only appliances use `poll`/`send_to`; receivers
// use `poll_bind`/`dg_recv`), so items unused in a given consumer are expected.
// Hence the per-item `#[allow(dead_code, reason = ...)]` below — the same
// convention `sdk/runtime/net.rs` uses for its re-exported constants.

/// Give up binding after this many consecutive failures (stays faultless).
const BIND_MAX_ATTEMPTS: u16 = 50;
/// Backoff window between bind retries — wall-clock, tick-rate independent
/// (RFC adaptive_tick §7.6: diagnostic cadence, no correctness impact).
const BIND_BACKOFF_MICROS: u64 = 100_000; // 100 ms

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
#[allow(dead_code, reason = "shared datagram-endpoint core; each including module uses a subset")]
enum BindPhase {
    Unbound = 0,
    Binding = 1,
    WaitBound = 2,
    Bound = 3,
    Backoff = 4,
    /// `dst_ip` unset (0) or L2 broadcast — terminal dormant. Only reachable via
    /// the send-only `poll` convenience; the `poll_bind` primitive never disables
    /// (a listener/server binds with no fixed destination).
    Disabled = 5,
}

/// One classified inbound datagram-surface event, produced by [`dg_recv`].
/// `Rx.data` points into the caller's `scratch` buffer (valid until the next
/// `net_in` read).
#[allow(dead_code, reason = "shared datagram-endpoint core; each including module uses a subset")]
enum DgEvent {
    Bound { ep_id: u8, local_port: u16 },
    Rx { ep_id: u8, src_ip: u32, src_port: u16, data: *const u8, len: usize },
    Err { ep_id: u8, errno: i8 },
    Closed { ep_id: u8 },
}

/// A bound UDP datagram endpoint over the ip datagram surface.
///
/// Assumes a *dedicated* datagram channel pair (its own ip-wired `net_out` /
/// `net_in`), as all consumers are — so any `MSG_DG_BOUND` on `net_in` is this
/// endpoint's. Multiple endpoints on one channel are distinguished by the
/// provider-stamped `ep_id`, not the local port; bind them sequentially so a
/// `MSG_DG_BOUND` routes to the single endpoint in `WaitBound`.
#[allow(dead_code, reason = "shared datagram-endpoint core; each including module uses a subset")]
pub struct DatagramEndpoint {
    phase: BindPhase,
    /// endpoint id from MSG_DG_BOUND (`0xFF` = unallocated).
    ep_id: u8,
    bind_attempts: u16,
    backoff_until_micros: u64,
}

impl Default for DatagramEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code, reason = "shared datagram-endpoint core; each including module uses a subset")]
impl DatagramEndpoint {
    pub const fn new() -> Self {
        DatagramEndpoint {
            phase: BindPhase::Unbound,
            ep_id: 0xFF,
            bind_attempts: 0,
            backoff_until_micros: 0,
        }
    }

    /// `dst_ip` was unset / broadcast — the endpoint will never bind. Only the
    /// send-only [`poll`](Self::poll) path can reach this.
    pub fn is_disabled(&self) -> bool {
        self.phase == BindPhase::Disabled
    }

    /// The endpoint is bound and ready to `send_to` / receive.
    pub fn is_ready(&self) -> bool {
        self.phase == BindPhase::Bound
    }

    /// The provider-allocated endpoint id (valid once [`is_ready`](Self::is_ready)).
    pub fn ep_id(&self) -> u8 {
        self.ep_id
    }

    /// True iff this bound endpoint owns `ep_id` — the demux key for routing an
    /// [`DgEvent::Rx`] to the right endpoint on a shared channel.
    pub fn owns(&self, ep_id: u8) -> bool {
        self.phase == BindPhase::Bound && self.ep_id == ep_id
    }

    /// Drive the *send* side of the bind lifecycle one step: emit `CMD_DG_BIND`
    /// while unbound, honour the retry backoff, and cap attempts. Never reads
    /// `net_in` and never disables — the consumer feeds completion via
    /// [`on_bound`](Self::on_bound) / [`on_error`](Self::on_error) from
    /// [`dg_recv`]. This is the receiver / multi-endpoint entry point.
    ///
    /// # Safety
    /// `scratch` must be valid for writes of `scratch_max` bytes; `sys` is the
    /// live syscall table.
    pub unsafe fn poll_bind(
        &mut self,
        sys: &SyscallTable,
        net_out: i32,
        bind_port: u16,
        scratch: *mut u8,
        scratch_max: usize,
    ) {
        // Backoff first: once the window elapses, fall through and re-emit this
        // same step.
        if self.phase == BindPhase::Backoff && dev_micros(sys) >= self.backoff_until_micros {
            self.phase = BindPhase::Binding;
        }
        // Unbound and Binding both attempt the emit, so an endpoint reaches
        // WaitBound in the SAME step it sends CMD_DG_BIND (a provider that has
        // pre-queued MSG_DG_BOUND is then consumed correctly, not while still
        // Binding).
        if self.phase == BindPhase::Unbound || self.phase == BindPhase::Binding {
            if net_out < 0 || self.bind_attempts >= BIND_MAX_ATTEMPTS {
                self.phase = BindPhase::Binding;
                return;
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
                self.phase = BindPhase::Binding; // channel full — retry next step.
                return;
            }
            self.bind_attempts += 1;
            self.phase = BindPhase::WaitBound;
        }
    }

    /// Consumer-fed bind completion: a `MSG_DG_BOUND` this endpoint is waiting
    /// for arrived. Latches its provider-assigned `ep_id`. The consumer is
    /// responsible for routing the event to the endpoint that requested it (a
    /// single endpoint per dedicated channel, or — with several — the one in
    /// `WaitBound`, since binds are sequential).
    pub fn on_bound(&mut self, ep_id: u8) {
        if self.phase == BindPhase::WaitBound {
            self.ep_id = ep_id;
            self.phase = BindPhase::Bound;
            self.bind_attempts = 0;
        }
    }

    /// Mark the endpoint bound to a known `ep_id` without the CMD_DG_BIND
    /// handshake — for setups where the id is supplied out of band (a fixed
    /// provider id, or a test that stands the module up without a live provider).
    pub fn bind_static(&mut self, ep_id: u8) {
        self.ep_id = ep_id;
        self.phase = BindPhase::Bound;
    }

    /// Consumer-fed bind failure: a `MSG_DG_ERROR` arrived while waiting — back
    /// off and retry.
    ///
    /// # Safety
    /// `sys` is the live syscall table (read for the wall clock).
    pub unsafe fn on_error(&mut self, sys: &SyscallTable) {
        if self.phase == BindPhase::WaitBound {
            self.phase = BindPhase::Backoff;
            self.backoff_until_micros = dev_micros(sys).wrapping_add(BIND_BACKOFF_MICROS);
        }
    }

    /// Send-only / single-endpoint convenience: drive the whole bind handshake
    /// including the `net_in` read, and go dormant if `dst_ip` is unset /
    /// broadcast (an appliance with nowhere to send never binds). Returns true
    /// once bound. Do NOT use with multiple endpoints on one channel — it reads
    /// `net_in` and would consume another endpoint's frames; use
    /// [`poll_bind`](Self::poll_bind) + [`dg_recv`] there.
    ///
    /// # Safety
    /// `scratch` valid for `scratch_max` writes; `sys` is the live syscall table.
    #[allow(
        clippy::too_many_arguments,
        reason = "the caller owns its ip channels, bind port and scratch buffer; passing them per call keeps this core stateless about the consumer's layout, and a config struct would just move the arg list"
    )]
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
        if self.phase == BindPhase::Unbound && (dst_ip == 0 || dst_ip == 0xFFFF_FFFF) {
            self.phase = BindPhase::Disabled;
        }
        if self.phase == BindPhase::Disabled {
            return false;
        }
        self.poll_bind(sys, net_out, bind_port, scratch, scratch_max);
        if net_in >= 0 && (self.phase == BindPhase::WaitBound || self.phase == BindPhase::Backoff) {
            if let Some(ev) = dg_recv(sys, net_in, scratch, scratch_max) {
                match ev {
                    DgEvent::Bound { ep_id, .. } => self.on_bound(ep_id),
                    DgEvent::Err { .. } => self.on_error(sys),
                    // An RX before we're bound (shouldn't happen on a dedicated
                    // channel) — ignore and stay waiting.
                    _ => {}
                }
            }
        }
        self.is_ready()
    }

    /// Send `data[..len]` as one datagram to `dst_ip`/`dst_port`. A datagram is
    /// atomic: returns `len` (whole payload accepted) or `0` (backpressure / not
    /// ready). The destination is a per-call argument — one bound endpoint sends
    /// to many peers (dns clients, quic/dtls connections). Only meaningful once
    /// [`is_ready`](Self::is_ready).
    ///
    /// # Safety
    /// `data` valid for `len` reads; `scratch` valid for `scratch_max` writes.
    #[allow(
        clippy::too_many_arguments,
        reason = "an addressed datagram send is destination plus payload plus scratch; grouping them into a struct would move the arg list, not shorten it"
    )]
    pub unsafe fn send_to(
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
        if self.phase != BindPhase::Bound || net_out < 0 || self.ep_id == 0xFF {
            return 0;
        }
        let n = dev_dg_send_to_v4(
            sys, net_out, self.ep_id, dst_ip, dst_port, data, len, scratch, scratch_max,
        );
        if n > 0 {
            len
        } else {
            0
        }
    }
}

/// Read and classify one inbound frame off the datagram surface `net_in`.
/// Returns `None` when the channel is empty or the frame is malformed / of an
/// unknown opcode. `DgEvent::Rx.data` points into `scratch` and is valid until
/// the next `net_in` read. The consumer feeds `Bound`/`Err` to the owning
/// endpoint and routes `Rx` by its own key (ep_id / DCID / 4-tuple).
///
/// # Safety
/// `scratch` must be valid for `scratch_max` writes; `sys` is the live syscall
/// table.
#[allow(dead_code, reason = "shared datagram-endpoint core; each including module uses a subset")]
unsafe fn dg_recv(
    sys: &SyscallTable,
    net_in: i32,
    scratch: *mut u8,
    scratch_max: usize,
) -> Option<DgEvent> {
    if net_in < 0 {
        return None;
    }
    let poll = (sys.channel_poll)(net_in, 0x01 /* POLL_IN */);
    if poll <= 0 || (poll & 0x01) == 0 {
        return None;
    }
    let (msg_type, payload_len) = net_read_frame(sys, net_in, scratch, scratch_max);
    if msg_type == DG_MSG_BOUND && payload_len >= 1 {
        // MSG_DG_BOUND payload: [ep_id:1][local_port:2 LE]. The local port is
        // informational (the endpoint routes by ep_id); tolerate its absence.
        let ep_id = *scratch.add(NET_FRAME_HDR);
        let local_port = if payload_len >= 3 {
            (*scratch.add(NET_FRAME_HDR + 1) as u16) | ((*scratch.add(NET_FRAME_HDR + 2) as u16) << 8)
        } else {
            0
        };
        Some(DgEvent::Bound { ep_id, local_port })
    } else if msg_type == DG_MSG_RX_FROM {
        parse_dg_rx_from_v4(scratch, payload_len)
            .map(|(ep_id, src_ip, src_port, data, len)| DgEvent::Rx { ep_id, src_ip, src_port, data, len })
    } else if msg_type == DG_MSG_ERROR && payload_len >= 2 {
        let ep_id = *scratch.add(NET_FRAME_HDR);
        let errno = *scratch.add(NET_FRAME_HDR + 1) as i8;
        Some(DgEvent::Err { ep_id, errno })
    } else if msg_type == DG_MSG_CLOSED && payload_len >= 1 {
        Some(DgEvent::Closed { ep_id: *scratch.add(NET_FRAME_HDR) })
    } else {
        None
    }
}
