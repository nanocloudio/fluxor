//! Fluxor SDK — `no_std` runtime helpers.
//!
//! Re-exports `modules/sdk/{sha256,sha384,hmac,chacha20,aes_gcm,
//! p256,varint,params}.rs` so cargo-based consumers (downstream
//! project tooling, host KAT harnesses, future common crates) can
//! `use fluxor_sdk::Sha256` instead of `#[path]`-mounting individual
//! files.
//!
//! Source of truth is `modules/sdk/`; this crate is a cargo-shaped
//! facade. PIC module builds continue using `#[path]` because they
//! compile via direct `rustc` rather than cargo — same source files,
//! two access paths.
//!
//! The SDK files were written to be `include!()`-flat: helpers
//! reference each other by bare name (e.g. `hmac.rs` uses
//! `Sha256::new()`). We preserve that by mounting them into one
//! inner module so cross-references resolve. Consumers see a flat
//! surface (`fluxor_sdk::Sha256`, `fluxor_sdk::chacha20_poly1305_encrypt`,
//! …).
//!
//! Skipped here: `runtime.rs` (PIC-only compiler intrinsics —
//! `target_os = "none"` / `target_arch = "wasm32"` gated, useless on
//! host); `wasm_entry.rs` (wasm bridge — different consumption
//! shape). Both can be added behind features if a host consumer
//! emerges.

#![no_std]
#![allow(
    unsafe_code,
    reason = "crypto primitives operate on raw byte buffers and use unsafe for chunked NEON / fixed-size pointer arithmetic"
)]
#![allow(
    dead_code,
    reason = "consumers use a subset of the SDK surface; the whole tree is mounted so every #[path] consumer agrees"
)]
#![allow(
    clippy::missing_safety_doc,
    clippy::too_many_arguments,
    clippy::manual_range_contains,
    clippy::needless_range_loop,
    clippy::identity_op,
    reason = "SDK source is shared with PIC builds where `unsafe_code = allow` and a different lint baseline applies"
)]

// Flat mount: the SDK files are `include!()`'d into a single inner
// module so their bare-name cross-references resolve. `pub use
// sdk_flat::*;` re-exports everything to the crate root.
//
// We reach the source via a `sdk/` symlink in this crate's directory
// pointing at `../../modules/sdk`. Cargo follows the symlink at
// package time and bundles the SDK source into the `.crate` tarball
// so published downloads are self-contained.
mod sdk_flat {
    // Wire constants (ABI_VERSION, fnv1a32) — needed by some helpers
    // and convenient to expose alongside the SDK surface.
    include!("../sdk/wire.rs");

    // Crypto primitives.
    include!("../sdk/sha256.rs");
    include!("../sdk/sha384.rs");
    include!("../sdk/hmac.rs");
    include!("../sdk/chacha20.rs");
    include!("../sdk/aes_gcm.rs");
    include!("../sdk/p256.rs");

    // Codecs.
    include!("../sdk/varint.rs");

    // Param-schema macro + helpers.
    include!("../sdk/params.rs");
}

pub use sdk_flat::*;
