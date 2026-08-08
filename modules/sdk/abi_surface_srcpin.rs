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
    0xb6, 0xa1, 0xc3, 0x20, 0x23, 0xc2, 0x9e, 0x20, 0xaa, 0x48, 0x72, 0xde, 0xa2, 0xc2, 0xd0,
    0xbc, 0xd9, 0xd7, 0x8b, 0x0c, 0xa0, 0x85, 0x5b, 0x12, 0x01, 0x54, 0x9f, 0x5e, 0x04, 0xe3,
    0x0c, 0x6e,
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
    0x3f, 0x41, 0x70, 0x51, 0xbc, 0x60, 0x2c, 0xbe, 0xc3, 0x4a, 0xd7, 0xf6, 0x44, 0x17, 0xe5,
    0x07, 0x1b, 0x68, 0x6d, 0x5b, 0x2e, 0xb1, 0xf7, 0xfb, 0x3e, 0xa4, 0x6d, 0x7f, 0x1b, 0xa0,
    0xc3, 0x03,
];
