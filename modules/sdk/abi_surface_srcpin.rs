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
    0x6d, 0x24, 0x8f, 0x18, 0x55, 0x90, 0xc8, 0xa6, 0x7c, 0x76, 0xd7, 0xbd, 0xa6, 0xeb, 0x6e,
    0x9b, 0x72, 0x5a, 0xe9, 0xfb, 0xa2, 0xbe, 0x67, 0x26, 0x5b, 0x7c, 0x9a, 0xf6, 0x1f, 0xf1,
    0xab, 0x39,
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
    0x1f, 0x66, 0xed, 0xee, 0x2c, 0x10, 0x40, 0x4c, 0x3a, 0x3a, 0xa1, 0xb1, 0x58, 0xb0, 0x77,
    0xac, 0xcf, 0x75, 0x73, 0x6b, 0x33, 0x8c, 0xd2, 0x5e, 0x5d, 0xd6, 0xbc, 0x8f, 0x26, 0x9d,
    0xef, 0x7e,
];
