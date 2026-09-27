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
    0xe2, 0x86, 0xbf, 0xd2, 0x31, 0x7e, 0x27, 0xa0, 0x6e, 0xe9, 0x89, 0x08, 0x8a, 0xaf, 0x8c, 0x9f,
    0xdb, 0xa0, 0xc8, 0xa4, 0xc7, 0x1b, 0x4f, 0x9c, 0x80, 0x4a, 0x84, 0xf5, 0xae, 0x7e, 0xbf, 0xbe,
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
    0xf5, 0xe7, 0x12, 0xc5, 0x82, 0x56, 0xae, 0xaf, 0x5d, 0xfb, 0x86, 0x9b, 0x68, 0xe5, 0xb3, 0x9d,
    0x50, 0x0f, 0x4f, 0x52, 0x79, 0xb5, 0x4a, 0x1b, 0xe6, 0x02, 0x99, 0xa1, 0x03, 0x37, 0x17, 0x80,
];
