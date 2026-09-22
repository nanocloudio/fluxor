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
    0x98, 0x96, 0x59, 0x54, 0xaa, 0x39, 0x63, 0x16, 0x41, 0x3a, 0x8e, 0x62, 0x45, 0xfa, 0x8c, 0xa6,
    0xd9, 0x43, 0x5c, 0xd5, 0x9d, 0x3d, 0x48, 0xf9, 0x8f, 0x9c, 0xcf, 0xf5, 0xaf, 0x02, 0xa2, 0xe2,
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
    0xb2, 0xc6, 0xca, 0x8d, 0xfd, 0xfe, 0x36, 0xfd, 0xef, 0xac, 0xce, 0x10, 0x40, 0x13, 0x7a, 0xab,
    0x5c, 0x05, 0x9d, 0xaf, 0xea, 0xa4, 0xca, 0x73, 0xe7, 0xd5, 0x4d, 0x95, 0xf7, 0x35, 0x94, 0x53,
];
