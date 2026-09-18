//! The SDK RSA core, mounted for the kernel key vault by the flat-`include!`
//! convention every PIC module uses. The core expects `sha256` and `sha384`
//! in scope; they come from the sibling mounts.

#![allow(
    dead_code,
    reason = "the vault uses the signing half; the verifying half is what the tls module uses from its own mount"
)]

use super::sha256::sha256;
use super::sha512::sha384;

include!("../../../../modules/sdk/crypto/rsa.rs");
