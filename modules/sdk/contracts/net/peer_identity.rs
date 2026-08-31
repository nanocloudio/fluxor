// Contract: peer_identity — what a TLS handshake established about the peer.
//
// Layer: contracts/net (public, stable).
//
// The `tls` foundation module emits one of these per session, on its
// `peer_identity` output, after every handshake — including one whose peer
// presented no credential, because silence is indistinguishable from an event
// still in flight.
//
// The layout is declared ONCE, here, with accessors. A reader that counts
// offsets into somebody else's record is invisible to both review and the
// compiler: a field that moves or widens breaks it silently, and the failure
// surfaces as a wrong answer rather than a parse error. Consumers call the
// accessors; the offsets below are the only place the layout is counted.
//
// ─── Wire ────────────────────────────────────────────────────────────
//
//   [msg_type:1 = MSG_PEER_IDENTITY][payload_len:2 LE][payload]
//
//   payload:
//     [session_id:4][result:1][credential_kind:1][profile_id:2]
//     [not_before:8][not_after:8][flags:4]
//     [fp_alg:1][fp_len:1][principal_len:2][fingerprint][principal]
//
// `flags` says which checks actually RAN. It is not a `verified` boolean
// because a boolean cannot say WHICH — and "a certificate was presented" is a
// different fact from "a peer was authenticated". Treating the first as the
// second is the confused-deputy shape mTLS exists to close, so
// [`binds_identity`] requires the chain AND key possession, and nothing here
// offers a shortcut that skips them.

/// Frame type for a peer-identity record.
pub const MSG_PEER_IDENTITY: u8 = 0x5A;

/// `[msg_type:1][payload_len:2]`.
pub const FRAME_HDR: usize = 3;

/// Payload bytes before the variable-length fingerprint.
pub const PAYLOAD_FIXED: usize = 4 + 1 + 1 + 2 + 8 + 8 + 4 + 1 + 1 + 2;

/// `result`: the handshake produced a usable outcome. Alias of
/// [`result::OK`], for the accessors below.
pub const RESULT_OK: u8 = result::OK;

/// `result` values — WHY a handshake produced the identity it did.
pub mod result {
    /// A credential was presented and passed the configured profile.
    pub const OK: u8 = 0;
    /// No credential was presented (plaintext or anonymous handshake).
    pub const NO_CREDENTIAL: u8 = 1;
    /// A credential was presented and its chain did not validate.
    pub const CHAIN_FAILED: u8 = 2;
    /// The chain validated but the profile (EKU, name, usage) did not.
    pub const PROFILE_FAILED: u8 = 3;
    /// The credential was outside its validity window.
    pub const EXPIRED: u8 = 4;
    /// The credential used a suite this endpoint does not accept.
    pub const UNSUPPORTED_SUITE: u8 = 5;
}

/// `credential_kind` values — WHAT the peer presented.
pub mod credential {
    pub const NONE: u8 = 0;
    /// An X.509 certificate presented in a mutual-TLS handshake.
    pub const X509_MTLS: u8 = 1;
    /// A bare public key, with no certificate around it.
    pub const RAW_PUBLIC_KEY: u8 = 2;
}

/// `flags` bits — the checks that RAN, not the checks that were configured.
///
/// A consumer reads these to know what a result is worth: `CHAIN` set with
/// `VALIDITY` clear says the chain was trusted but its lifetime was not
/// enforced, which is exactly the thing a boolean could never express.
pub mod check {
    /// The certificate chain was validated to a trusted root.
    pub const CHAIN: u32 = 0x0000_0001;
    /// The certificate's validity window was enforced.
    pub const VALIDITY: u32 = 0x0000_0002;
    /// The required extended key usage was present.
    pub const EKU: u32 = 0x0000_0004;
    /// A subject alternative name was matched against the profile.
    pub const SAN: u32 = 0x0000_0008;
    /// The peer proved possession of the certificate's private key.
    pub const KEY_POSSESSION: u32 = 0x0000_0010;
}

/// `fp_alg` values — which hash the fingerprint is.
pub mod fp_alg {
    pub const NONE: u8 = 0;
    pub const SHA256: u8 = 1;
}

/// Longest fingerprint the record carries — one SHA-256.
pub const MAX_FINGERPRINT: usize = 32;

/// Longest principal. A SPIFFE URI fits comfortably; a longer name is
/// truncated to NOTHING rather than to a prefix, because half a name is a
/// different name.
pub const MAX_PRINCIPAL: usize = 128;

/// Largest complete record, frame header included.
pub const MAX_TOTAL: usize = FRAME_HDR + PAYLOAD_FIXED + MAX_FINGERPRINT + MAX_PRINCIPAL;

// Offsets, derived from the layout above ONCE so nobody counts them again:
//   session_id 0..4, result 4, credential_kind 5, profile_id 6..8,
//   not_before 8..16, not_after 16..24, flags 24..28, fp_alg 28, fp_len 29,
//   principal_len 30..32.
//
// Getting `flags` wrong is not a parse error — it reads some OTHER field as
// the check bits, `binds_identity` says false, and every mTLS caller is
// silently anonymous. Which is why they are derived from the layout above
// rather than restated at each call site.
const OFF_SESSION_ID: usize = 0;
const OFF_RESULT: usize = 4;
const OFF_FLAGS: usize = 24;
const OFF_FP_LEN: usize = 29;

/// Session id — the writer's connection id widened to `u32`.
///
/// Callers bounds-check `payload.len() >= PAYLOAD_FIXED` first.
#[inline]
pub fn session_id(payload: &[u8]) -> u32 {
    u32::from_le_bytes([
        payload[OFF_SESSION_ID],
        payload[OFF_SESSION_ID + 1],
        payload[OFF_SESSION_ID + 2],
        payload[OFF_SESSION_ID + 3],
    ])
}

/// The connection this identity belongs to.
///
/// `conn_id` is a `u16` on the wire everywhere else, so this reads two bytes.
/// Reading one would attribute every connection past 255 to the wrong peer —
/// a misattribution, not a failure, and therefore silent.
#[inline]
pub fn conn_id(payload: &[u8]) -> u16 {
    u16::from_le_bytes([payload[OFF_SESSION_ID], payload[OFF_SESSION_ID + 1]])
}

/// Which checks ran.
#[inline]
pub fn flags(payload: &[u8]) -> u32 {
    u32::from_le_bytes([
        payload[OFF_FLAGS],
        payload[OFF_FLAGS + 1],
        payload[OFF_FLAGS + 2],
        payload[OFF_FLAGS + 3],
    ])
}

/// Does this record establish WHO the peer is?
///
/// True only when the handshake succeeded AND the chain validated AND key
/// possession was proved. A fingerprint from an untrusted certificate, or from
/// one merely copied, is not an identity — binding on it would authenticate
/// whoever presented the bytes.
#[inline]
pub fn binds_identity(payload: &[u8]) -> bool {
    payload.len() >= PAYLOAD_FIXED
        && payload[OFF_RESULT] == RESULT_OK
        && flags(payload) & check::CHAIN != 0
        && flags(payload) & check::KEY_POSSESSION != 0
}

/// The peer's key fingerprint, or `None` when this record does not bind an
/// identity or is truncated.
///
/// Returns the WHOLE fingerprint or nothing: half a fingerprint is not a
/// weaker identity, it is a different one, and it can collide with somebody
/// else's.
#[inline]
pub fn fingerprint(payload: &[u8]) -> Option<&[u8]> {
    if !binds_identity(payload) {
        return None;
    }
    let n = payload[OFF_FP_LEN] as usize;
    if n == 0 || payload.len() < PAYLOAD_FIXED + n {
        return None;
    }
    Some(&payload[PAYLOAD_FIXED..PAYLOAD_FIXED + n])
}

/// Split a framed record into `(msg_type, payload)`, or `None` when the frame
/// is short or the length field overruns the buffer.
#[inline]
pub fn frame_parts(frame: &[u8]) -> Option<(u8, &[u8])> {
    if frame.len() < FRAME_HDR {
        return None;
    }
    let len = u16::from_le_bytes([frame[1], frame[2]]) as usize;
    if FRAME_HDR + len > frame.len() {
        return None;
    }
    Some((frame[0], &frame[FRAME_HDR..FRAME_HDR + len]))
}
