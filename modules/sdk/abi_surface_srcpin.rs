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
    0xc3, 0xc3, 0x56, 0x55, 0xf6, 0xa1, 0x40, 0x2d, 0xd5, 0x5b, 0x96, 0x3f, 0x39, 0xac, 0xca,
    0x5e, 0x8b, 0x67, 0x36, 0x56, 0x4d, 0x2d, 0x2b, 0xa1, 0xa9, 0x66, 0xb0, 0xef, 0xe1, 0x4e,
    0x0e, 0x5d,
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
    0xeb, 0xed, 0x52, 0xa7, 0x4f, 0x32, 0x16, 0x51, 0x6a, 0x8a, 0xa4, 0x2b, 0xd4, 0x04, 0x45,
    0x8f, 0x8c, 0x3b, 0x2d, 0x16, 0x78, 0x87, 0xd8, 0x7e, 0x54, 0xd9, 0xac, 0x5e, 0xa5, 0xbe,
    0xd2, 0xf5,
];
