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
    0xfe, 0x1e, 0x1e, 0xa1, 0xf5, 0x0b, 0xe1, 0x09, 0xa2, 0x20, 0xfd, 0x77, 0x0c, 0x8c, 0x6e, 0xd3,
    0xed, 0xbc, 0xc4, 0x95, 0xe6, 0x7c, 0xa4, 0x36, 0xb9, 0xac, 0x2a, 0xe4, 0xaa, 0xe8, 0x91, 0x57,
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
    0xe3, 0xa0, 0x9c, 0xfa, 0xa0, 0x64, 0x85, 0xa8, 0xee, 0xb4, 0xa8, 0xe9, 0x22, 0xca, 0xcb, 0xb0,
    0x62, 0x8d, 0xd8, 0xa9, 0x4e, 0x90, 0xfa, 0x78, 0x8b, 0xa4, 0x7f, 0x20, 0x91, 0xf9, 0x27, 0x60,
];
