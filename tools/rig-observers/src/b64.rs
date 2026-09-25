//! Base64 for the NDJSON `bytes` records, from the in-tree SDK core rather
//! than an external crate.
//!
//! `modules/sdk/crypto/b64.rs` is the implementation every PIC module, the
//! kernel and the `fluxor` CLI already use (RFC 4648, standard alphabet, `=`
//! padding). One implementation of a primitive, one set of vectors, no second
//! copy to diverge from the first — and the probes emit base64 that the rig
//! matcher, running the CLI's decoder, has to read back exactly.
//!
//! The core is `no_std` and encodes into a caller buffer; the wrapper adds the
//! heap allocation a host tool wants and nothing else.

#[allow(
    dead_code,
    reason = "the mounted core carries the decode half too; these probes only encode"
)]
mod core {
    include!("../../../modules/sdk/crypto/b64.rs");
}

use core::b64_encode;

/// Encode to a `String`.
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut out = vec![0u8; data.len().div_ceil(3) * 4];
    let n = b64_encode(data, &mut out).expect("buffer sized for the exact output length");
    out.truncate(n);
    String::from_utf8(out).expect("base64 alphabet is ASCII")
}
