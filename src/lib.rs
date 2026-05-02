#![cfg_attr(not(feature = "host-linux"), no_std)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

#[cfg(any(feature = "rp", feature = "chip-bcm2712", feature = "host-linux", feature = "host-wasm"))]
#[path = "../modules/sdk/abi.rs"]
pub mod abi;
#[cfg(any(feature = "rp", feature = "chip-bcm2712", feature = "host-linux", feature = "host-wasm"))]
pub mod kernel;
#[cfg(any(feature = "rp", feature = "chip-bcm2712", feature = "host-linux", feature = "host-wasm"))]
#[path = "../modules/mod.rs"]
pub mod modules;
#[cfg(any(feature = "rp", feature = "chip-bcm2712", feature = "host-linux", feature = "host-wasm"))]
pub mod platform;

// WASM platform exports + host imports. Included as part of the
// `cdylib` build under `host-wasm` so `kernel_init` / `kernel_step` /
// etc. surface as WASM exports. See `src/platform/wasm.rs`.
#[cfg(feature = "host-wasm")]
#[path = "platform/wasm.rs"]
pub mod wasm_entry;

pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811C9DC5u32;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}
