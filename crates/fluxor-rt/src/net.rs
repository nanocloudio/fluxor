// ============================================================================
// Channel-based networking helpers (net_proto framing)
// ============================================================================

use crate::*;

/// Net protocol frame header size.
pub const NET_FRAME_HDR: usize = 3;

/// Write a net protocol frame: [msg_type: u8] [len: u16 LE] [payload].
/// The frame is assembled in `scratch` and written atomically.
/// Returns `total` bytes only when the kernel committed the full
/// frame; returns 0 on backpressure (channel ring full or atomic
/// FIFO write rejected) so callers can retry rather than treat a
/// dropped frame as committed, and 0 for a frame that can never be
/// written: one larger than `scratch`, or a payload longer than the
/// `u16` length names.
pub unsafe fn net_write_frame(
    sys: &SyscallTable,
    chan: i32,
    msg_type: u8,
    payload: *const u8,
    payload_len: usize,
    scratch: *mut u8,
    scratch_max: usize,
) -> usize {
    let total = NET_FRAME_HDR + payload_len;
    if chan < 0 || total > scratch_max || payload_len > u16::MAX as usize {
        return 0;
    }
    let len_le = (payload_len as u16).to_le_bytes();
    *scratch = msg_type;
    *scratch.add(1) = len_le[0];
    *scratch.add(2) = len_le[1];
    if payload_len > 0 && !payload.is_null() {
        core::ptr::copy_nonoverlapping(payload, scratch.add(NET_FRAME_HDR), payload_len);
    }
    let n = (sys.channel_write)(chan, scratch, total);
    if n == total as i32 {
        total
    } else {
        0
    }
}

/// Read one whole net protocol frame from `chan` into `buf`, or nothing.
///
/// Returns `(msg_type, payload_len)` with the payload at `buf[3..]`, or
/// `(0, 0)` when no whole frame is buffered yet. A frame is consumed only
/// once all of it is buffered and it fits `buf`, so a frame that arrives
/// over several steps is left on the channel until it is complete, and a
/// read never consumes part of one frame or the start of the next. A frame
/// larger than `buf`, or larger than the channel's ring, cannot be
/// delivered: it is dropped whole, now and as the rest of it arrives, logged,
/// and reported as `(0, 0)`. A consumer that must not lose a frame reads with
/// [`net_read_frame_sized`], which reports the drop.
///
/// `buf` must hold `NET_FRAME_HDR` plus the largest payload the port
/// carries.
pub unsafe fn net_read_frame(
    sys: &SyscallTable,
    chan: i32,
    buf: *mut u8,
    buf_max: usize,
) -> (u8, usize) {
    let (msg_type, copied, payload_len) = net_read_frame_sized(sys, chan, buf, buf_max);
    if msg_type != 0 && copied < payload_len {
        let m = b"[net] frame larger than its reader's buffer dropped";
        dev_log(sys, 2, m.as_ptr(), m.len());
        return (0, 0);
    }
    (msg_type, copied)
}

/// [`net_read_frame`] that reports what it could not deliver. Returns
/// `(msg_type, copied_len, payload_len)`:
///
/// - `(0, 0, 0)`: no whole frame is buffered yet; nothing was consumed.
/// - `copied_len == payload_len`: the frame is in `buf`, payload at `buf[3..]`.
/// - `copied_len < payload_len`: the frame was larger than `buf` or than the
///   ring, so it could not be delivered. Its head, `copied_len` payload
///   bytes, is in `buf`, and the whole frame is dropped, now and as the rest
///   of it arrives, so the channel is still frame-aligned. A consumer of a
///   reliable stream treats this as a lost frame and reconnects; a datagram
///   consumer has the datagram's head and its true length.
pub unsafe fn net_read_frame_sized(
    sys: &SyscallTable,
    chan: i32,
    buf: *mut u8,
    buf_max: usize,
) -> (u8, usize, usize) {
    if chan < 0 || buf_max < NET_FRAME_HDR {
        return (0, 0, 0);
    }
    let n = (sys.channel_peek)(chan, buf, NET_FRAME_HDR);
    if n < NET_FRAME_HDR as i32 {
        return (0, 0, 0);
    }
    let msg_type = *buf;
    let payload_len = (*buf.add(1) as u16 | ((*buf.add(2) as u16) << 8)) as usize;
    let total = NET_FRAME_HDR + payload_len;
    if total <= buf_max {
        let got = (sys.channel_peek)(chan, buf, total);
        if got == total as i32 {
            (sys.channel_discard)(chan, total);
            return (msg_type, payload_len, payload_len);
        }
        // Incomplete. It completes only if the channel has room for more:
        // a full ring holding less than the frame can never hold all of it,
        // and a mailbox record shorter than its header claims never grows.
        if (sys.channel_poll)(chan, POLL_OUT) & POLL_OUT as i32 != 0 {
            return (0, 0, 0);
        }
    }
    // Undeliverable: hand over the head that is buffered and fits, and drop
    // the whole frame, now and as the rest of it arrives.
    let got = (sys.channel_peek)(chan, buf, total.min(buf_max));
    let copied = (got.max(0) as usize).saturating_sub(NET_FRAME_HDR);
    (sys.channel_discard)(chan, total);
    (msg_type, copied, payload_len)
}

/// Fill buffer with cryptographically secure random bytes.
/// Returns 0 on success, negative errno on failure.
#[inline(always)]
pub unsafe fn dev_csprng_fill(sys: &SyscallTable, buf: *mut u8, len: usize) -> i32 {
    (sys.provider_call)(
        -1,
        abi::registry::kernel::RANDOM_FILL,
        core::ptr::null_mut(),
        0,
        buf,
        len,
    )
}

/// Build + emit a `MSG_TRACE_CTX` frame (`stream_trace`) carrying a
/// connection's W3C trace context downstream (the transport after
/// MSG_ACCEPTED, or a forwarding stage with its own span id), for a
/// connection granted `net_proto::flag::TRACE`. Payload:
/// `[conn_id][trace_id 16][parent_span_id 8][trace_flags 1]`. `flags` is the
/// W3C trace-flags byte (low bit = `sampled`). Returns true if the frame was
/// written.
#[allow(
    clippy::too_many_arguments,
    reason = "flat trace-context args (conn id, trace/span ids, flags) plus the caller's scratch buffer — a struct would just move the list"
)]
pub unsafe fn dev_net_send_trace_ctx(
    sys: &SyscallTable,
    chan: i32,
    conn_id: u16,
    trace_id: &[u8; 16],
    span_id: &[u8; 8],
    flags: u8,
    scratch: *mut u8,
    scratch_max: usize,
) -> bool {
    use abi::contracts::net::stream_trace::{ctx, CTX_LEN, MSG_TRACE_CTX};
    let payload = ctx(conn_id, trace_id, span_id, flags);
    net_write_frame(
        sys,
        chan,
        MSG_TRACE_CTX,
        payload.as_ptr(),
        CTX_LEN,
        scratch,
        scratch_max,
    ) > 0
}

/// Parse a received `MSG_TRACE_CTX` frame. `frame_buf` points at the frame start
/// (including the 3-byte header); `payload_len` is from `net_read_frame`.
/// Returns `(conn_id, trace_id, parent_span_id, trace_flags)`, or `None`
/// unless the payload is exactly one.
pub unsafe fn parse_trace_ctx(
    frame_buf: *const u8,
    payload_len: usize,
) -> Option<(u16, [u8; 16], [u8; 8], u8)> {
    use abi::contracts::net::stream_trace::{ctx_parts, CTX_LEN};
    if payload_len != CTX_LEN {
        return None;
    }
    let p = core::slice::from_raw_parts(frame_buf.add(NET_FRAME_HDR), CTX_LEN);
    ctx_parts(p)
}

// ============================================================================
// datagram contract helpers (crates/fluxor-abi/src/contracts/net/datagram.rs)
// ============================================================================

// datagram surface constants — the contract (`contracts/net/datagram.rs`) is
// the single source of truth. Re-exported here under the `DG_` prefix that the
// runtime helpers and the datagram modules use, so there is one definition of
// each value, not two.
pub const DG_V4_PREFIX: usize = abi::contracts::net::datagram::V4_ADDR_PREFIX;
pub const DG_CMD_BIND: u8 = abi::contracts::net::datagram::CMD_DG_BIND;
pub const DG_CMD_SEND_TO: u8 = abi::contracts::net::datagram::CMD_DG_SEND_TO;
pub const DG_CMD_CLOSE: u8 = abi::contracts::net::datagram::CMD_DG_CLOSE;
pub const DG_MSG_BOUND: u8 = abi::contracts::net::datagram::MSG_DG_BOUND;
pub const DG_MSG_RX_FROM: u8 = abi::contracts::net::datagram::MSG_DG_RX_FROM;
pub const DG_MSG_CLOSED: u8 = abi::contracts::net::datagram::MSG_DG_CLOSED;
pub const DG_MSG_ERROR: u8 = abi::contracts::net::datagram::MSG_DG_ERROR;
pub const DG_AF_INET: u8 = abi::contracts::net::datagram::AF_INET;
pub const DG_AF_INET6: u8 = abi::contracts::net::datagram::AF_INET6;
pub const DG_AF_NAME: u8 = abi::contracts::net::datagram::AF_NAME;

/// Build and emit a `CMD_DG_SEND_TO` frame for an IPv4 destination.
/// Layout:
///   `[0x21][len:2 LE][ep_id:1][af:1=4][dst_addr:4 BE][dst_port:2 LE][data...]`
///
/// `dst_ip` is a u32 whose high byte is the first IP octet (i.e.
/// `192.168.1.1` is stored as `0xC0A80101` so `to_be_bytes()` writes
/// the wire-order octets). Port is little-endian per contract.
///
/// Returns total bytes handed to `channel_write` (NET_FRAME_HDR +
/// payload_len). Returns `0` on validation failure (chan < 0, ep_id == 0xFF,
/// scratch too small for `DG_V4_PREFIX + data_len + NET_FRAME_HDR`) **or when
/// the channel rejected the write (backpressure)** — the datagram frame is
/// atomic, so a short write is a drop. Callers MUST treat 0 as "not sent" and
/// retain the payload.
///
/// See `crates/fluxor-abi/src/contracts/net/datagram.rs` for the wire spec.
#[expect(
    clippy::too_many_arguments,
    reason = "datagram send wire-shape: signature mirrors the on-wire datagram envelope fields"
)]
pub unsafe fn dev_dg_send_to_v4(
    sys: &SyscallTable,
    chan: i32,
    ep_id: u8,
    dst_ip: u32,
    dst_port: u16,
    data: *const u8,
    data_len: usize,
    scratch: *mut u8,
    scratch_max: usize,
) -> usize {
    let mut head = [0u8; 1 + 1 + 4 + 2];
    head[0] = ep_id;
    head[1] = DG_AF_INET;
    head[2..6].copy_from_slice(&dst_ip.to_be_bytes());
    head[6..8].copy_from_slice(&dst_port.to_le_bytes());
    dg_send_to(sys, chan, &head, data, data_len, scratch, scratch_max)
}

/// Send one datagram to a NAMED destination on the datagram surface:
/// `[ep_id][af = 1][len][name…][port: u16 LE][data…]`. The provider
/// resolves the name; a name it does not yet hold starts a lookup and drops
/// this datagram, so callers retransmit as on loss. Returns the frame length
/// written, or `0` when the name is not one the surface carries, the scratch
/// is too small, or the channel refused.
#[allow(
    clippy::too_many_arguments,
    reason = "an addressed datagram send is destination plus payload plus scratch"
)]
pub unsafe fn dev_dg_send_to_name(
    sys: &SyscallTable,
    chan: i32,
    ep_id: u8,
    name: &[u8],
    dst_port: u16,
    data: *const u8,
    data_len: usize,
    scratch: *mut u8,
    scratch_max: usize,
) -> usize {
    if name.is_empty() || name.len() > abi::contracts::net::net_proto::MAX_NAME_LEN {
        return 0;
    }
    let mut head = [0u8; 1 + 1 + 1 + abi::contracts::net::net_proto::MAX_NAME_LEN + 2];
    head[0] = ep_id;
    head[1] = DG_AF_NAME;
    head[2] = name.len() as u8;
    head[3..3 + name.len()].copy_from_slice(name);
    head[3 + name.len()..5 + name.len()].copy_from_slice(&dst_port.to_le_bytes());
    dg_send_to(
        sys,
        chan,
        &head[..5 + name.len()],
        data,
        data_len,
        scratch,
        scratch_max,
    )
}

/// `CMD_DG_SEND_TO` to an IPv6 destination: `[ep_id][af = 6][addr 16]
/// [port u16 LE][data]`. Same contract as the IPv4 form.
#[allow(
    clippy::too_many_arguments,
    reason = "an addressed datagram send is destination plus payload plus scratch"
)]
pub unsafe fn dev_dg_send_to_v6(
    sys: &SyscallTable,
    chan: i32,
    ep_id: u8,
    dst: &[u8; 16],
    dst_port: u16,
    data: *const u8,
    data_len: usize,
    scratch: *mut u8,
    scratch_max: usize,
) -> usize {
    let mut head = [0u8; 1 + 1 + 16 + 2];
    head[0] = ep_id;
    head[1] = DG_AF_INET6;
    head[2..18].copy_from_slice(dst);
    head[18..20].copy_from_slice(&dst_port.to_le_bytes());
    dg_send_to(sys, chan, &head, data, data_len, scratch, scratch_max)
}

/// One `CMD_DG_SEND_TO` frame: `head` (`[ep_id][af][addr][port]`), then the
/// data, written whole or not at all.
unsafe fn dg_send_to(
    sys: &SyscallTable,
    chan: i32,
    head: &[u8],
    data: *const u8,
    data_len: usize,
    scratch: *mut u8,
    scratch_max: usize,
) -> usize {
    if chan < 0 || head[0] == 0xFF {
        return 0;
    }
    let body_len = head.len() + data_len;
    let total = NET_FRAME_HDR + body_len;
    if total > scratch_max || body_len > u16::MAX as usize {
        return 0;
    }
    *scratch = DG_CMD_SEND_TO;
    let pl = (body_len as u16).to_le_bytes();
    *scratch.add(1) = pl[0];
    *scratch.add(2) = pl[1];
    core::ptr::copy_nonoverlapping(head.as_ptr(), scratch.add(NET_FRAME_HDR), head.len());
    if data_len > 0 && !data.is_null() {
        core::ptr::copy_nonoverlapping(data, scratch.add(NET_FRAME_HDR + head.len()), data_len);
    }
    // A datagram frame is atomic: anything short of the full `total` means the
    // channel rejected it, and the caller keeps the unsent payload.
    if (sys.channel_write)(chan, scratch, total) == total as i32 {
        total
    } else {
        0
    }
}

/// Parse a `MSG_DG_RX_FROM` frame's payload as IPv4. Caller passes the
/// pointer at the start of the *frame* (including the 3-byte TLV
/// header) plus the `payload_len` returned by `net_read_frame`.
///
/// Returns `Some((ep_id, src_ip, src_port, data_ptr, data_len))` on a
/// well-formed IPv4 datagram_v1 RX frame — `data_ptr` points to the
/// first byte of the inner datagram payload. Returns `None` if the
/// frame is too short, has the wrong `af`, or `payload_len` underflows
/// the prefix.
#[inline]
pub unsafe fn parse_dg_rx_from_v4(
    frame_buf: *const u8,
    payload_len: usize,
) -> Option<(u8, u32, u16, *const u8, usize)> {
    if payload_len < DG_V4_PREFIX {
        return None;
    }
    let p = frame_buf.add(NET_FRAME_HDR);
    let ep_id = *p;
    let af = *p.add(1);
    if af != DG_AF_INET {
        return None;
    }
    let src_ip = u32::from_be_bytes([*p.add(2), *p.add(3), *p.add(4), *p.add(5)]);
    let src_port = u16::from_le_bytes([*p.add(6), *p.add(7)]);
    let data_ptr = p.add(DG_V4_PREFIX);
    let data_len = payload_len - DG_V4_PREFIX;
    Some((ep_id, src_ip, src_port, data_ptr, data_len))
}
