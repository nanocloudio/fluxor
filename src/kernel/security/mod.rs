//! Security domain — crypto primitives, key vault, and the build-time roots
//! of trust modules and graph slots are verified against.

pub mod crypto;
pub mod key_share;
pub mod key_vault;
pub mod key_vault_router;
pub mod slot_signature;

/// A build-time key that is set but is not 64 hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedKey;

/// A 32-byte public key given to the build as 64 hex digits (either case).
/// `Ok(None)` when the variable is unset, [`MalformedKey`] when it is set to
/// anything else: the caller turns that into a compile error, so a mistyped
/// root fails the build instead of producing a kernel that checks nothing.
pub const fn build_time_key(hex: Option<&str>) -> Result<Option<[u8; 32]>, MalformedKey> {
    let Some(hex) = hex else {
        return Ok(None);
    };
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return Err(MalformedKey);
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let (Some(hi), Some(lo)) = (hex_nibble(bytes[2 * i]), hex_nibble(bytes[2 * i + 1])) else {
            return Err(MalformedKey);
        };
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(Some(out))
}

const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
