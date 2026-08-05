// ============================================================================
// Channel-based networking helpers (net_proto framing)
// ============================================================================

/// Net protocol frame header size.
const NET_FRAME_HDR: usize = 3;

/// Write a net protocol frame: [msg_type: u8] [len: u16 LE] [payload].
/// The frame is assembled in `scratch` and written atomically.
/// Returns `total` bytes only when the kernel committed the full
/// frame; returns 0 on backpressure (channel ring full or atomic
/// FIFO write rejected) so callers can retry rather than treat a
/// dropped frame as committed.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
unsafe fn net_write_frame(
    sys: &SyscallTable,
    chan: i32,
    msg_type: u8,
    payload: *const u8,
    payload_len: usize,
    scratch: *mut u8,
    scratch_max: usize,
) -> usize {
    let total = NET_FRAME_HDR + payload_len;
    if chan < 0 || total > scratch_max {
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

/// Read a net protocol frame from channel into buf.
/// Returns (msg_type, payload_len) or (0, 0) if no data.
/// Payload starts at buf[3]. Caller must provide buf >= FRAME_HDR + max payload.
///
/// Two-step read: first the 3-byte TLV header, then exactly payload_len bytes.
/// This prevents consuming multiple frames from the byte-stream FIFO in one call.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
unsafe fn net_read_frame(
    sys: &SyscallTable,
    chan: i32,
    buf: *mut u8,
    buf_max: usize,
) -> (u8, usize) {
    if chan < 0 || buf_max < NET_FRAME_HDR {
        return (0, 0);
    }
    // Step 1: read just the 3-byte TLV header
    let n = (sys.channel_read)(chan, buf, NET_FRAME_HDR);
    if n < NET_FRAME_HDR as i32 {
        return (0, 0);
    }
    let msg_type = *buf;
    let payload_len = (*buf.add(1) as u16 | ((*buf.add(2) as u16) << 8)) as usize;
    if payload_len == 0 {
        return (msg_type, 0);
    }
    // Step 2: read exactly payload_len bytes into buf[3..]
    let max_payload = buf_max - NET_FRAME_HDR;
    let to_read = if payload_len < max_payload {
        payload_len
    } else {
        max_payload
    };
    let n2 = (sys.channel_read)(chan, buf.add(NET_FRAME_HDR), to_read);
    let actual = if n2 > 0 { n2 as usize } else { 0 };
    (msg_type, actual)
}

/// Like [`net_read_frame`] but **stays frame-aligned** when a frame's payload is
/// larger than `buf`: after copying `min(payload_len, buf-3)` bytes, it discards
/// the remaining `payload_len - copied` bytes from the channel so the next read
/// starts on a real frame header rather than mid-payload. Returns
/// `(msg_type, copied_len, payload_len)` — `copied_len < payload_len` signals the
/// frame was truncated into `buf` (the tail was dropped, not left to desync the
/// FIFO). A consumer that must not lose bytes can compare the two and reconnect.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
unsafe fn net_read_frame_aligned(
    sys: &SyscallTable,
    chan: i32,
    buf: *mut u8,
    buf_max: usize,
) -> (u8, usize, usize) {
    if chan < 0 || buf_max < NET_FRAME_HDR {
        return (0, 0, 0);
    }
    let n = (sys.channel_read)(chan, buf, NET_FRAME_HDR);
    if n < NET_FRAME_HDR as i32 {
        return (0, 0, 0);
    }
    let msg_type = *buf;
    let payload_len = (*buf.add(1) as u16 | ((*buf.add(2) as u16) << 8)) as usize;
    if payload_len == 0 {
        return (msg_type, 0, 0);
    }
    let max_payload = buf_max - NET_FRAME_HDR;
    let to_read = if payload_len < max_payload {
        payload_len
    } else {
        max_payload
    };
    let n2 = (sys.channel_read)(chan, buf.add(NET_FRAME_HDR), to_read);
    let copied = if n2 > 0 { n2 as usize } else { 0 };
    // Drain any tail beyond what fit, so the FIFO stays frame-aligned.
    let mut leftover = payload_len.saturating_sub(copied);
    if leftover > 0 {
        let mut scratch = [0u8; 64];
        while leftover > 0 {
            let take = if leftover < scratch.len() {
                leftover
            } else {
                scratch.len()
            };
            let got = (sys.channel_read)(chan, scratch.as_mut_ptr(), take);
            if got <= 0 {
                break; // nothing more buffered yet — avoid a busy spin.
            }
            leftover -= got as usize;
        }
    }
    (msg_type, copied, payload_len)
}

/// Fill buffer with cryptographically secure random bytes.
/// Returns 0 on success, negative errno on failure.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_csprng_fill(sys: &SyscallTable, buf: *mut u8, len: usize) -> i32 {
    (sys.provider_call)(-1, 0x0C3C, buf, len)
}

/// Build + emit a `MSG_TRACE_CTX` frame carrying a connection's W3C trace
/// context downstream (ingress IP after MSG_ACCEPTED, or a forwarding stage with
/// its own span id). Payload:
/// `[conn_id][trace_id 16][parent_span_id 8][trace_flags 1]`. `flags` is the
/// W3C trace-flags byte (low bit = `sampled`). Returns true if the frame was
/// written. See `contracts/net/net_proto.rs`.
#[allow(
    dead_code,
    reason = "observability propagation; invoked only by instrumented stream stages"
)]
#[allow(
    clippy::too_many_arguments,
    reason = "flat trace-context args (conn id, trace/span ids, flags) plus the caller's scratch buffer — a struct would just move the list"
)]
unsafe fn dev_net_send_trace_ctx(
    sys: &SyscallTable,
    chan: i32,
    conn_id: u8,
    trace_id: &[u8; 16],
    span_id: &[u8; 8],
    flags: u8,
    scratch: *mut u8,
    scratch_max: usize,
) -> bool {
    use abi::contracts::net::net_proto::{MSG_TRACE_CTX, TRACE_CTX_LEN};
    let mut payload = [0u8; TRACE_CTX_LEN];
    payload[0] = conn_id;
    payload[1..17].copy_from_slice(trace_id);
    payload[17..25].copy_from_slice(span_id);
    payload[25] = flags;
    net_write_frame(
        sys,
        chan,
        MSG_TRACE_CTX,
        payload.as_ptr(),
        TRACE_CTX_LEN,
        scratch,
        scratch_max,
    ) > 0
}

/// Parse a received `MSG_TRACE_CTX` frame. `frame_buf` points at the frame start
/// (including the 3-byte net_proto header); `payload_len` is from
/// `net_read_frame`. Returns `(conn_id, trace_id, parent_span_id, trace_flags)`
/// or `None`.
#[allow(
    dead_code,
    reason = "observability propagation; invoked only by instrumented stream stages"
)]
unsafe fn parse_trace_ctx(
    frame_buf: *const u8,
    payload_len: usize,
) -> Option<(u8, [u8; 16], [u8; 8], u8)> {
    use abi::contracts::net::net_proto::TRACE_CTX_LEN;
    if payload_len < TRACE_CTX_LEN {
        return None;
    }
    let p = frame_buf.add(NET_FRAME_HDR);
    let conn_id = *p;
    let mut trace_id = [0u8; 16];
    let mut span_id = [0u8; 8];
    core::ptr::copy_nonoverlapping(p.add(1), trace_id.as_mut_ptr(), 16);
    core::ptr::copy_nonoverlapping(p.add(17), span_id.as_mut_ptr(), 8);
    let flags = *p.add(25);
    Some((conn_id, trace_id, span_id, flags))
}

// ============================================================================
// datagram contract helpers (modules/sdk/contracts/net/datagram.rs)
// ============================================================================

// datagram surface constants — the contract (`contracts/net/datagram.rs`) is
// the single source of truth. Re-exported here under the `DG_` prefix that the
// runtime helpers and the datagram modules use, so there is one definition of
// each value, not two.
#[allow(dead_code, reason = "re-exported datagram surface; each consumer uses a subset")]
const DG_V4_PREFIX: usize = abi::contracts::net::datagram::V4_ADDR_PREFIX;
#[allow(dead_code, reason = "re-exported datagram surface; each consumer uses a subset")]
const DG_CMD_BIND: u8 = abi::contracts::net::datagram::CMD_DG_BIND;
#[allow(dead_code, reason = "re-exported datagram surface; each consumer uses a subset")]
const DG_CMD_SEND_TO: u8 = abi::contracts::net::datagram::CMD_DG_SEND_TO;
#[allow(dead_code, reason = "re-exported datagram surface; each consumer uses a subset")]
const DG_CMD_CLOSE: u8 = abi::contracts::net::datagram::CMD_DG_CLOSE;
#[allow(dead_code, reason = "re-exported datagram surface; each consumer uses a subset")]
const DG_MSG_BOUND: u8 = abi::contracts::net::datagram::MSG_DG_BOUND;
#[allow(dead_code, reason = "re-exported datagram surface; each consumer uses a subset")]
const DG_MSG_RX_FROM: u8 = abi::contracts::net::datagram::MSG_DG_RX_FROM;
#[allow(dead_code, reason = "re-exported datagram surface; each consumer uses a subset")]
const DG_MSG_CLOSED: u8 = abi::contracts::net::datagram::MSG_DG_CLOSED;
#[allow(dead_code, reason = "re-exported datagram surface; each consumer uses a subset")]
const DG_MSG_ERROR: u8 = abi::contracts::net::datagram::MSG_DG_ERROR;
#[allow(dead_code, reason = "re-exported datagram surface; each consumer uses a subset")]
const DG_AF_INET: u8 = abi::contracts::net::datagram::AF_INET;
#[allow(dead_code, reason = "re-exported datagram surface; each consumer uses a subset")]
const DG_AF_INET6: u8 = abi::contracts::net::datagram::AF_INET6;

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
/// See `modules/sdk/contracts/net/datagram.rs` for the wire spec.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "datagram send wire-shape: signature mirrors the on-wire datagram envelope fields"
)]
unsafe fn dev_dg_send_to_v4(
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
    if chan < 0 || ep_id == 0xFF {
        return 0;
    }
    let body_len = DG_V4_PREFIX + data_len;
    let total = NET_FRAME_HDR + body_len;
    if total > scratch_max {
        return 0;
    }

    *scratch = DG_CMD_SEND_TO;
    let pl = (body_len as u16).to_le_bytes();
    *scratch.add(1) = pl[0];
    *scratch.add(2) = pl[1];
    *scratch.add(3) = ep_id;
    *scratch.add(4) = DG_AF_INET;
    let ip_bytes = dst_ip.to_be_bytes();
    *scratch.add(5) = ip_bytes[0];
    *scratch.add(6) = ip_bytes[1];
    *scratch.add(7) = ip_bytes[2];
    *scratch.add(8) = ip_bytes[3];
    let port_bytes = dst_port.to_le_bytes();
    *scratch.add(9) = port_bytes[0];
    *scratch.add(10) = port_bytes[1];
    if data_len > 0 && !data.is_null() {
        core::ptr::copy_nonoverlapping(data, scratch.add(NET_FRAME_HDR + DG_V4_PREFIX), data_len);
    }
    // Honour backpressure: a datagram frame is atomic, so anything short of the
    // full `total` means the channel rejected it. Return 0 so the caller keeps
    // the unsent payload instead of treating a dropped write as success.
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
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline]
unsafe fn parse_dg_rx_from_v4(
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

