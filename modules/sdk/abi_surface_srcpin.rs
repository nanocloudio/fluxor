// GENERATED CONSTANT — regenerate with `fluxor abi-regen`, do not
// hand-edit the value.
//
// sha256 over the canonicalized source of ALL `modules/sdk/**/*.rs`
// except this generated file (sorted relative paths; per file:
// `path \0 canonical-content \0`). Canonicalization is token-based
// (`tools/src/hash.rs::canonicalize_source`): comments, doc comments,
// and formatting are digest-neutral, while every identifier, literal,
// and real attribute is significant. The relative path is folded in,
// so a file rename DOES move the digest.
//
// This folds the contract and platform layers — opcode name-hashes,
// wire structs, request/response layouts — into the ABI-surface digest
// without hand-enumerating thousands of constants, and without a
// build.rs in every consumer: the const is checked in, and
// `tools/src/hash.rs::contracts_platform_srcpin_is_current` recomputes
// it from the sources and fails (printing the replacement) when it
// drifts. Deliberately over-sensitive: a pure refactor of a contract
// file changes the digest and forces a rebuild/restage — the safe
// direction.
pub const CONTRACTS_PLATFORM_SRC_HASH: [u8; 32] = [
    0x1b, 0xe9, 0xc4, 0x9e, 0x80, 0x0d, 0xb2, 0x14, 0x9d, 0x1d, 0x78, 0x15, 0x7f, 0xb2, 0x7f, 0x7d,
    0x79, 0x5e, 0xcc, 0xab, 0x96, 0x53, 0x97, 0x3a, 0xe9, 0xab, 0x45, 0x0a, 0xd4, 0x72, 0xd9, 0x13,
];

/// The full ABI-surface digest (sha256 of the canonical surface stream:
/// numeric walk ‖ srcpin ‖ semantic epoch). GENERATED — regenerate via the
/// drift test alongside CONTRACTS_PLATFORM_SRC_HASH. Excluded from the
/// srcpin walk (this file is), so it is not self-referential.
///
/// This is the value the SDK embeds into every compiled module
/// (`runtime.rs` `FLUXOR_ABI_SURFACE`), so packing can verify the module
/// was COMPILED against this surface rather than merely stamped by a
/// current packer — the compile-provenance guarantee.
pub const ABI_SURFACE_DIGEST: [u8; 32] = [
    0x60, 0x28, 0xf5, 0xe9, 0x1e, 0x4f, 0xb3, 0x70, 0x91, 0x81, 0x3a, 0xad, 0xb8, 0xda, 0xa8, 0x04,
    0xef, 0xf4, 0x3c, 0x10, 0x5c, 0xe1, 0x27, 0x82, 0x77, 0x10, 0xb9, 0x46, 0xe2, 0xe4, 0xeb, 0xe4,
];
