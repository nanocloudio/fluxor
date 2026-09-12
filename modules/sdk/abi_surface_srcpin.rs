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
    0x86, 0xb7, 0x50, 0x6b, 0xae, 0xd0, 0x4e, 0x68, 0x3c, 0xbd, 0x1b, 0xaa, 0x5d, 0xbb, 0x67,
    0xe2, 0x60, 0xdb, 0x03, 0xfc, 0x1a, 0xb6, 0x6f, 0xf5, 0xe8, 0xd4, 0xfc, 0x06, 0xfa, 0x4a,
    0xbf, 0x9f,
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
    0x3c, 0xe0, 0xe7, 0x12, 0xed, 0xe1, 0x04, 0x72, 0xd4, 0xc1, 0x8d, 0x38, 0x2e, 0xd5, 0xce,
    0x89, 0x54, 0x5e, 0x17, 0xa1, 0xda, 0xa2, 0xda, 0x37, 0x8e, 0xec, 0x36, 0xe8, 0x8c, 0xad,
    0xe7, 0xc6,
];
