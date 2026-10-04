// Contract: remote_session — the session state of a `remote_channel`.
//
// Layer: contracts/mesh (public, stable).
//
// A `remote_channel` instance carries local channels across one transport
// session at a time. Its optional `session` output says when that session
// opens and when it ends, so a consumer can stop sending toward a member
// that cannot hear it — refusing a request at once rather than waiting out
// a deadline for an answer that is not coming.
//
// Frames use the `[msg_type:1][len:2 LE][payload]` header the net contracts
// share, in a range disjoint from them and from `mesh::capability`.
//
// Every frame carries the session's ordinal: 1 for the first session the
// instance opened, counting up, so two `UP` frames with different ordinals
// say a session ended between them even if its `DOWN` was never read.
// Frames report the CURRENT state: when the output is full the next frame
// written is the latest transition, never a stale one. A consumer treats
// the session as down until it reads an `UP`.
//
// On `DOWN`, a record that `remote_channel` had begun sending is lost (see
// its `lost` counter); a record not yet begun waits in its input for the
// next session. A consumer that must not wait refuses its pending requests
// toward that member on `DOWN`.

/// Frame header bytes.
pub const FRAME_HDR: usize = 3;

/// The session opened: `[session:4 LE]`.
pub const MSG_SESSION_UP: u8 = 0xD8;
/// The session ended: `[session:4 LE]`, the ordinal of the session that
/// ended (0 when none had opened).
pub const MSG_SESSION_DOWN: u8 = 0xD9;

/// Payload bytes of either frame.
pub const PAYLOAD_LEN: usize = 4;
/// Whole-frame bytes of either frame.
pub const FRAME_LEN: usize = FRAME_HDR + PAYLOAD_LEN;

/// Encode a session frame: `up` for [`MSG_SESSION_UP`].
pub const fn encode(up: bool, session: u32) -> [u8; FRAME_LEN] {
    let s = session.to_le_bytes();
    [
        if up { MSG_SESSION_UP } else { MSG_SESSION_DOWN },
        PAYLOAD_LEN as u8,
        0,
        s[0],
        s[1],
        s[2],
        s[3],
    ]
}

/// Decode a session frame: `Some((up, session))`, or `None` for a frame
/// that is not one.
pub fn decode(frame: &[u8]) -> Option<(bool, u32)> {
    if frame.len() < FRAME_LEN || frame[1] != PAYLOAD_LEN as u8 || frame[2] != 0 {
        return None;
    }
    let up = match frame[0] {
        MSG_SESSION_UP => true,
        MSG_SESSION_DOWN => false,
        _ => return None,
    };
    Some((
        up,
        u32::from_le_bytes([frame[3], frame[4], frame[5], frame[6]]),
    ))
}
