//! FNV-1a hash function (32-bit).
//!
//! Re-exports the canonical implementation from `crate::wire` (path-
//! mounted from `modules/sdk/wire.rs`) under the `fnv1a_hash` name
//! that the rest of the tools call.

pub use crate::wire::fnv1a32 as fnv1a_hash;
