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
    0x14, 0x34, 0xc4, 0x8b, 0x62, 0x4f, 0x2a, 0xf2, 0x30, 0x3b, 0x3d, 0x1d, 0x74, 0x29, 0x6e,
    0xbc, 0xf8, 0x3c, 0xbf, 0x42, 0xfe, 0x7a, 0x53, 0x35, 0xb3, 0x7c, 0x93, 0xc4, 0x44, 0x51,
    0xc7, 0x29,
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
    0xf2, 0xf9, 0xf1, 0x3a, 0xec, 0xf7, 0x45, 0x3d, 0xd5, 0x20, 0xc1, 0x45, 0x55, 0x1c, 0xd7,
    0xf4, 0x78, 0xa2, 0x05, 0xfa, 0xd3, 0xa1, 0x3a, 0x9f, 0x44, 0xf0, 0xf5, 0xf2, 0x74, 0x0e,
    0x6f, 0x99,
];
