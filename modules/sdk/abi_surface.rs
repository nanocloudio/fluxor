// Canonical encoding of the kernel ↔ module ABI wire surface, for
// digest-pinning graph generations to the substrate they were built
// against: identity by digest, applied to the kernel/graph boundary.
//
// The surface is everything a compiled `.fmod` hardcodes against the
// kernel: the numbers declared in `abi/registry.toml` and the layouts and
// signatures of the SDK. This module folds them into one deterministic byte
// stream; sha256 of that stream is the **ABI-surface digest**. Two kernels with equal digests are
// wire-compatible for already-built modules; a generation records the digest
// it was built against, and boot selection accepts it only on equality —
// digest identity instead of version windows (latest-is-all-there-is).
//
// Attestation. Every module carries the digest it was built against: a PIC
// module's ELF embeds it (`runtime.rs` `FLUXOR_ABI_SURFACE`) and `pack`
// requires it to equal the packer's own before copying it into the manifest;
// a wasm module's payload must contain it, and the packer stamps it. The
// kernel loader compares that attestation to its own digest for every module
// it admits, signed or not, and refuses one that carries none or another. A
// signature covers the attestation, so on a signed module it is the signer's
// claim; on an unsigned one it is the builder's, which guards against a stale
// or mismatched build, not against a forger. The slot and generation pins
// (kernel boot selector, graph_slot activation) are the image-level check.
//
// What it does NOT cover: kernel *semantics* behind an unchanged number, and
// compiler/toolchain/build-config behavior. The manually-bumped
// `SEMANTIC_EPOCH` below is the escape hatch for the former — bump it to force
// a digest change when meaning changes but the numbers do not.
//
// Two inputs. (1) `SEMANTIC_EPOCH` from the registry. (2) The source pin
// (`abi_surface_srcpin.rs`): a token hash of every `.rs` file under
// `modules/sdk/` and `contracts/src/`, the generated `abi/registry_gen.rs`
// among them, so every ABI number moves it. Comments, doc comments and
// formatting are not tokens and leave it unchanged; every identifier,
// literal and real attribute is, so renames and most refactors of ANY SDK or
// contracts file DO change the digest, as does renaming a file. That
// over-sensitivity is the safe direction: a false-positive rebuild
// self-heals; a missed change is a field failure. Do not describe the digest
// as refactor-stable — it tracks the SDK source, by design.
//
// `no_std`, zero-alloc: the encoder writes through a caller-supplied sink.
// Shared by path-mount: host tools hash it with `sha2`; the kernel folds it
// with its own sha256.

mod surface_src {
    pub mod srcpin {
        include!("abi_surface_srcpin.rs");
    }
    #[allow(dead_code, reason = "the surface reads only SEMANTIC_EPOCH")]
    pub mod registry {
        include!("abi/registry_gen.rs");
    }
}

/// The embeddable full-digest const (generated; see
/// `abi_surface_srcpin.rs`), surfaced here so modules and the kernel reach
/// it as `abi::abi_surface::ABI_SURFACE_DIGEST`.
#[allow(
    dead_code,
    reason = "embedded by kernel/modules; tools use it only in tests"
)]
pub const ABI_SURFACE_DIGEST: [u8; 32] = self::surface_src::srcpin::ABI_SURFACE_DIGEST;

/// The checked-in source pin, for the tools' drift guard.
#[allow(
    dead_code,
    reason = "read by the tools' drift test; the kernel and modules fold it through write_surface"
)]
pub const CONTRACTS_PLATFORM_SRC_HASH: [u8; 32] =
    self::surface_src::srcpin::CONTRACTS_PLATFORM_SRC_HASH;

/// Stream the canonical bytes of this tree's surface through `sink`.
pub fn write_surface(sink: &mut impl FnMut(&[u8])) {
    write_surface_with(&surface_src::srcpin::CONTRACTS_PLATFORM_SRC_HASH, sink);
}

/// The canonical stream for a given source pin:
/// `"semantic_epoch" 0x00 epoch:i64 LE "contracts_platform_src" 0x00 pin`.
pub fn write_surface_with(srcpin: &[u8; 32], sink: &mut impl FnMut(&[u8])) {
    sink(b"semantic_epoch");
    sink(&[0u8]);
    sink(&i64::from(surface_src::registry::SEMANTIC_EPOCH).to_le_bytes());
    sink(b"contracts_platform_src");
    sink(&[0u8]);
    sink(srcpin);
}
