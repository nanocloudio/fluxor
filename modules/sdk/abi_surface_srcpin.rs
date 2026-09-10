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
    0xa1, 0x84, 0x48, 0x2f, 0xf3, 0xf5, 0xd6, 0xa4, 0x73, 0xea, 0x0f, 0x08, 0x8b, 0x97, 0xad,
    0xfe, 0x18, 0xaa, 0xe6, 0x10, 0xd3, 0xaa, 0xb4, 0xe3, 0xd4, 0x14, 0x9d, 0x4e, 0x30, 0x32,
    0x2d, 0x1f,
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
    0x1f, 0xa2, 0xb4, 0x96, 0x82, 0x12, 0xc3, 0x8b, 0x96, 0x16, 0xc7, 0xe8, 0x82, 0x07, 0xe2,
    0xdf, 0x28, 0x26, 0x32, 0xef, 0x38, 0x36, 0x9d, 0xa5, 0xb1, 0x72, 0x33, 0xcd, 0x7b, 0x1d,
    0x37, 0x2e,
];
