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

// Top-level re-export so kernel call sites can reach the canonical
// FNV-1a hash as `crate::fnv1a32`. Implementation lives in `abi::wire`.
#[cfg(any(feature = "rp", feature = "chip-bcm2712", feature = "host-linux", feature = "host-wasm"))]
pub use abi::wire::fnv1a32;
