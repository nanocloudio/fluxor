//! The destination-bound key wrap `KEY_WRAP` / `KEY_UNWRAP` perform, from
//! the SDK core (`modules/sdk/cores/custody_wrap.rs`) — the one
//! implementation the vault and anything checking its objects share.

#![allow(
    dead_code,
    reason = "the SDK core is mounted whole; the vault uses its seal/open entry points"
)]

use crate::kernel::security::crypto::chacha20::{
    chacha20_poly1305_decrypt, chacha20_poly1305_encrypt,
};
use crate::kernel::security::crypto::sha256::Sha256;

include!("../../../modules/sdk/cores/custody_wrap.rs");
