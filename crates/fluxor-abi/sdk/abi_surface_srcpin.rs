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
    0x5d, 0x6e, 0x51, 0xcc, 0x1d, 0xce, 0x0f, 0x22, 0x5f, 0x7e, 0x0e, 0x05, 0x51, 0x67, 0xb1,
    0xf5, 0x53, 0xdc, 0x33, 0x30, 0x9f, 0xc4, 0x86, 0xc3, 0xcb, 0x1f, 0xbb, 0xe6, 0x63, 0x2a,
    0xba, 0xa3,
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
    0x0c, 0x7c, 0x4c, 0xb9, 0x8d, 0x2a, 0xfb, 0xa2, 0xdb, 0xc9, 0x7a, 0x2d, 0x78, 0xd4, 0xf7,
    0x86, 0xcc, 0xc5, 0xa4, 0x95, 0x3a, 0x0f, 0xd5, 0xc7, 0x22, 0x05, 0x3c, 0x51, 0xad, 0x10,
    0x89, 0x49,
];
