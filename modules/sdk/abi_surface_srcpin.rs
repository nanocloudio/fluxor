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
    0x32, 0x96, 0xc4, 0x7f, 0x07, 0x4f, 0x04, 0x5d, 0xa9, 0x16, 0x0c, 0xf7, 0xc4, 0x6c, 0x85,
    0x2e, 0xd2, 0x2b, 0x7f, 0x9d, 0x52, 0xb3, 0x04, 0x8b, 0x05, 0xed, 0xd3, 0xe7, 0xb8, 0xea,
    0xfa, 0x73,
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
    0x44, 0x5d, 0x5d, 0x11, 0x58, 0xbb, 0x9c, 0xff, 0xca, 0xc4, 0x27, 0x23, 0xa0, 0xdd, 0xff,
    0xec, 0xf2, 0xbf, 0x96, 0x68, 0x6c, 0x96, 0xe6, 0x65, 0xa4, 0xe7, 0xb6, 0x61, 0xd4, 0x36,
    0xda, 0x80,
];
