//! Security: the signing root modules and node images are verified against,
//! and the sealing-key derivation modules reach through `SEAL_KEY_DERIVE`.
//! Key custody itself is the `key_vault` provider module's.

pub mod crypto;
pub mod image_signature;
pub mod root;
pub mod seal;
