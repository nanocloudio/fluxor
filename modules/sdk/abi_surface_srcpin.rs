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
    0xff, 0x6b, 0xfc, 0xb2, 0x71, 0x4c, 0x93, 0x58, 0x3f, 0x44, 0x99, 0x90, 0x52, 0x6a, 0xae,
    0x64, 0xa5, 0x5e, 0x54, 0xa4, 0x6e, 0xd0, 0xa7, 0x85, 0xcf, 0x8c, 0x6b, 0x4c, 0x61, 0x45,
    0xc8, 0x58,
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
    0x50, 0x2d, 0x83, 0x07, 0xba, 0x1e, 0x5b, 0x0b, 0xf8, 0x20, 0x59, 0xd2, 0x70, 0xe0, 0x15,
    0x7d, 0xa9, 0xf8, 0x0d, 0xf7, 0xe6, 0xa8, 0x0d, 0x8f, 0xdf, 0xa4, 0x4e, 0xc1, 0xc9, 0xa4,
    0xe0, 0xda,
];
