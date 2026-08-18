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
    0x1f, 0xa9, 0x0c, 0x6e, 0xf3, 0xa3, 0xa4, 0x99, 0x8a, 0x95, 0x37, 0x6d, 0x1b, 0x5b, 0xd9,
    0x34, 0x6c, 0x28, 0xe5, 0xcc, 0x15, 0x6f, 0x09, 0x2d, 0xf9, 0xca, 0x27, 0xcd, 0x26, 0x81,
    0x28, 0xbf,
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
    0xe2, 0xd4, 0x00, 0x5c, 0xc8, 0xf4, 0x0c, 0x0d, 0x67, 0x78, 0xf8, 0xb5, 0x93, 0x1a, 0x72,
    0x0a, 0x4b, 0x13, 0x61, 0x2c, 0x14, 0x0e, 0x81, 0xb5, 0x77, 0x4a, 0x88, 0x41, 0x38, 0x42,
    0xc2, 0xdf,
];
