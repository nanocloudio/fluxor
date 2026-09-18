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
    0x8b, 0x63, 0x77, 0x7f, 0x4a, 0x49, 0xc0, 0x5d, 0xb1, 0x7a, 0x2c, 0x5f, 0x5f, 0xff, 0x43,
    0xc4, 0xb4, 0xca, 0x4d, 0x8d, 0xe2, 0x7a, 0x31, 0x08, 0x55, 0xa4, 0xa6, 0xe2, 0x3d, 0xe5,
    0xc8, 0xb4,
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
    0x44, 0xfc, 0x01, 0x9c, 0x5f, 0x9f, 0x43, 0xf6, 0xf9, 0xf6, 0xd1, 0xb5, 0x51, 0xea, 0xc0,
    0xe1, 0x92, 0xf5, 0x8b, 0xbd, 0xbd, 0x9b, 0x53, 0x4f, 0x2d, 0xa3, 0x11, 0xed, 0x29, 0xd4,
    0x4f, 0x52,
];
