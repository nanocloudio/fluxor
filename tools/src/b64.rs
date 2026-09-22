//! Base64, from the in-tree SDK core rather than an external crate.
//!
//! `modules/sdk/crypto/b64.rs` is the implementation every PIC module and the
//! kernel already use (RFC 4648, standard alphabet, `=` padding). Mounting it
//! here is the same move `src/kernel/security/crypto/*` makes: one
//! implementation of a primitive, one set of vectors, no second copy to
//! diverge from the first.
//!
//! The core is `no_std` and encodes into caller buffers. The two wrappers
//! below add the heap allocation a host tool wants, and nothing else.
//!
//! Deliberately not extended to SHA-256. The external `sha2` crate is an
//! *independent* implementation of the hash that CHECKS the in-tree SDK:
//! `hash.rs` computes the ABI-surface digest with it and asserts the result
//! against the committed pin. Mounting the SDK's own SHA-256 there would make
//! the checker and the checked the same code, so one defect would produce a
//! self-consistent wrong pin and corrupted OCI digests together. That
//! independence is the point, and it is why only base64 moves.

include!("../../modules/sdk/crypto/b64.rs");

/// Encode to a `String`.
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut out = vec![0u8; data.len().div_ceil(3) * 4];
    let n = b64_encode(data, &mut out).expect("buffer sized for the exact output length");
    out.truncate(n);
    String::from_utf8(out).expect("base64 alphabet is ASCII")
}

/// Decode, returning `None` on malformed input.
#[must_use]
pub fn decode(s: &str) -> Option<Vec<u8>> {
    // Every 4 input chars yield at most 3 bytes; padding only shortens it.
    let mut out = vec![0u8; s.len() / 4 * 3 + 3];
    let n = b64_decode(s.as_bytes(), &mut out)?;
    out.truncate(n);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_the_rfc_4648_vectors() {
        for (raw, enc) in [
            ("" as &str, ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(raw.as_bytes()), enc, "encode {raw:?}");
            assert_eq!(
                decode(enc).as_deref(),
                Some(raw.as_bytes()),
                "decode {enc:?}"
            );
        }
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(decode("!!!!"), None);
    }

    #[test]
    fn round_trips_binary() {
        let raw: Vec<u8> = (0u8..=255).collect();
        assert_eq!(decode(&encode(&raw)).as_deref(), Some(raw.as_slice()));
    }
}
