//! Fluxor wire-ABI surface.
//!
//! Re-exports every layer in [`modules/sdk/abi.rs`] so cargo-based
//! consumers (the fluxor CLI, host tests, downstream projects'
//! tooling) can `use fluxor_abi::wire::ABI_VERSION` instead of
//! `#[path]`-mounting the source files. PIC module builds continue
//! using `#[path]` because they compile via direct `rustc` rather
//! than cargo — same source files, two access paths.
//!
//! Source of truth is `modules/sdk/abi.rs`; this crate is a
//! cargo-shaped facade over it.

#![no_std]
#![allow(
    unsafe_code,
    reason = "ABI surface includes raw register addresses, pointer-based syscall types, and chip-specific BAR maps"
)]
#![allow(
    dead_code,
    reason = "consumers use a subset of the ABI surface; the whole tree is mounted so every #[path] consumer agrees on layout"
)]

// `modules/sdk/abi.rs` is the assembler — it `include!`'s every
// layer (`wire.rs`, `kernel_abi.rs`, `contracts/*`, `internal/*`,
// `platform/*`) into nested `pub mod` blocks. We reach it via a
// `sdk/` symlink in this crate's directory pointing at
// `../../modules/sdk`. Cargo follows the symlink at package time and
// bundles the SDK source into the `.crate` tarball so published
// downloads are self-contained.
#[path = "../sdk/abi.rs"]
mod abi;

pub use abi::*;
