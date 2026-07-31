// ============================================================================
// FMP (Fluxor Message Protocol) — typed messages on channels
// ============================================================================

// Wire format: [type:4 LE][len:2 LE][payload:len]
// type = FNV-1a 32-bit hash of the message name
// len  = payload byte count (0 = no payload)
// Modules are stepped sequentially (cooperative, single-core), so split
// writes/reads within one step are safe — no interleaving.

const MSG_HDR_SIZE: usize = 6;

/// FNV-1a 32-bit hash. Const-evaluable for compile-time message type IDs.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
const fn fnv1a(s: &[u8]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    let mut i = 0;
    while i < s.len() {
        h ^= s[i] as u32;
        h = h.wrapping_mul(0x01000193);
        i += 1;
    }
    h
}

/// Write a typed message to a channel.
/// Returns 0 on success, -1 if the write failed.
///
/// Composes header + payload into a single stack buffer and emits one
/// `channel_write` so the channel lock spans the whole message. Two
/// separate writes would release the lock between them, allowing any
/// reader on the channel to observe a partial message and interleave
/// bytes from another producer. The buffer is sized to
/// `CHANNEL_BUFFER_SIZE` — messages above that cap cannot fit in the
/// channel anyway.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn msg_write(
    sys: &SyscallTable,
    chan: i32,
    msg_type: u32,
    payload: *const u8,
    payload_len: u16,
) -> i32 {
    const MAX_MSG: usize = crate::abi::CHANNEL_BUFFER_SIZE;
    let total = MSG_HDR_SIZE + payload_len as usize;
    if total > MAX_MSG {
        return -1;
    }
    let mut buf = [0u8; MAX_MSG];
    let tb = msg_type.to_le_bytes();
    buf[0] = tb[0];
    buf[1] = tb[1];
    buf[2] = tb[2];
    buf[3] = tb[3];
    let lb = payload_len.to_le_bytes();
    buf[4] = lb[0];
    buf[5] = lb[1];
    if payload_len > 0 && !payload.is_null() {
        core::ptr::copy_nonoverlapping(
            payload,
            buf.as_mut_ptr().add(MSG_HDR_SIZE),
            payload_len as usize,
        );
    }
    let w = (sys.channel_write)(chan, buf.as_ptr(), total);
    if w < total as i32 {
        return -1;
    }
    0
}

/// Write a typed message with no payload.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn msg_write_empty(sys: &SyscallTable, chan: i32, msg_type: u32) -> i32 {
    msg_write(sys, chan, msg_type, core::ptr::null(), 0)
}

/// Read a typed message from a channel.
/// Returns (msg_type, payload_len). (0, 0) if no complete header available.
/// Payload bytes are written to buf[0..payload_len.min(buf_cap)].
/// Excess payload bytes (beyond buf_cap) are consumed and discarded.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn msg_read(sys: &SyscallTable, chan: i32, buf: *mut u8, buf_cap: usize) -> (u32, u16) {
    let mut hdr = [0u8; MSG_HDR_SIZE];
    let n = (sys.channel_read)(chan, hdr.as_mut_ptr(), MSG_HDR_SIZE);
    if n < MSG_HDR_SIZE as i32 {
        return (0, 0);
    }
    let msg_type = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let payload_len = u16::from_le_bytes([hdr[4], hdr[5]]);
    if payload_len > 0 {
        let to_read = (payload_len as usize).min(buf_cap);
        if to_read > 0 && !buf.is_null() {
            (sys.channel_read)(chan, buf, to_read);
        }
        // Discard excess bytes if payload > buf_cap
        let excess = payload_len as usize - to_read;
        if excess > 0 {
            let mut discard = [0u8; 64];
            let mut remaining = excess;
            while remaining > 0 {
                let chunk = remaining.min(64);
                (sys.channel_read)(chan, discard.as_mut_ptr(), chunk);
                remaining -= chunk;
            }
        }
    }
    (msg_type, payload_len)
}

// ============================================================================
// Param Reading Helpers
// ============================================================================

/// Read u8 from params blob at `offset`. Returns `default` if out of bounds.
///
/// # Safety
/// `params` must be valid for reads of `len` bytes. The kernel passes the
/// module's params blob plus its size from the loader; both are checked
/// against the actual blob length before this function sees them.
#[inline(always)]
pub unsafe fn p_u8(params: *const u8, len: usize, offset: usize, default: u8) -> u8 {
    if offset < len {
        *params.add(offset)
    } else {
        default
    }
}

/// Read little-endian u16 from params blob at `offset`. Returns `default` if out of bounds.
///
/// # Safety
/// `params` must be valid for reads of `len` bytes. The kernel passes the
/// module's params blob plus its size; both are checked against the actual
/// blob length before this function sees them.
#[inline(always)]
pub unsafe fn p_u16(params: *const u8, len: usize, offset: usize, default: u16) -> u16 {
    if offset + 1 < len {
        let lo = *params.add(offset) as u16;
        let hi = *params.add(offset + 1) as u16;
        lo | (hi << 8)
    } else {
        default
    }
}

/// Read little-endian u32 from params blob at `offset`. Returns `default` if out of bounds.
///
/// # Safety
/// `params` must be valid for reads of `len` bytes. The kernel passes the
/// module's params blob plus its size; both are checked against the actual
/// blob length before this function sees them.
#[inline(always)]
pub unsafe fn p_u32(params: *const u8, len: usize, offset: usize, default: u32) -> u32 {
    if offset + 3 < len {
        let p = params.add(offset);
        (*p as u32)
            | ((*p.add(1) as u32) << 8)
            | ((*p.add(2) as u32) << 16)
            | ((*p.add(3) as u32) << 24)
    } else {
        default
    }
}

