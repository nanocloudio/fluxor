#![cfg_attr(not(feature = "host-linux"), no_std)]
#![allow(
    unsafe_code,
    reason = "kernel + driver platform: MMIO, raw pointers, FFI, and bare-metal boot paths pervade the crate"
)]
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "kernel exposes raw-pointer entry points crossing the ABI boundary; deref is gated by the contract documented at each call site, not the type signature"
)]

#[cfg(any(
    feature = "rp",
    feature = "aarch64-metal",
    feature = "host-linux",
    feature = "host-wasm"
))]
#[path = "../modules/sdk/abi.rs"]
pub mod abi;

/// Architecture primitives: the Cortex-M ones (barriers, interrupt masks,
/// NVIC) and, for the AArch64 bare-metal platforms, `arch::aarch64` (vectors,
/// GIC, generic timer, PSCI, the boot identity map).
///
/// Unconditional so that `arch::nvic`'s arithmetic is compiled — and its
/// tests run — on host builds too. The asm-bearing half is ARM-gated inside.
pub mod arch;
#[cfg(any(
    feature = "rp",
    feature = "aarch64-metal",
    feature = "host-linux",
    feature = "host-wasm"
))]
pub mod kernel;
#[cfg(any(
    feature = "rp",
    feature = "aarch64-metal",
    feature = "host-linux",
    feature = "host-wasm"
))]
#[path = "../modules/mod.rs"]
pub mod modules;
#[cfg(any(
    feature = "rp",
    feature = "aarch64-metal",
    feature = "host-linux",
    feature = "host-wasm"
))]
pub mod platform;

/// The loader's handoff, for the `uefi` platform.
#[cfg(feature = "host-uefi")]
pub use fluxor_contracts::boot;

// WASM platform exports + host imports. Included as part of the
// `cdylib` build under `host-wasm` so `kernel_init` / `kernel_step` /
// etc. surface as WASM exports. See `src/platform/wasm.rs`.
#[cfg(feature = "host-wasm")]
#[path = "platform/wasm.rs"]
pub mod wasm_entry;

// Top-level re-export so kernel call sites can reach the canonical
// FNV-1a hash as `crate::fnv1a32`. Implementation lives in `abi::wire`.
#[cfg(any(
    feature = "rp",
    feature = "aarch64-metal",
    feature = "host-linux",
    feature = "host-wasm"
))]
pub use abi::wire::fnv1a32;
