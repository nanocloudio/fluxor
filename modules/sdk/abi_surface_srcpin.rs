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
    0xae, 0xae, 0x39, 0xd7, 0xde, 0x77, 0x08, 0x1a, 0x07, 0xef, 0x03, 0x8c, 0x94, 0x51, 0x3d,
    0xd8, 0xd4, 0xd6, 0x9b, 0x0c, 0x56, 0x8c, 0x53, 0x0d, 0x4a, 0x8a, 0xb7, 0xc4, 0xce, 0x50,
    0xb2, 0x70,
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
    0x94, 0xbc, 0x41, 0x45, 0xc9, 0xf5, 0xa2, 0xc4, 0x93, 0xc0, 0x4b, 0x7e, 0xf1, 0x7a, 0xef,
    0xa6, 0x35, 0x51, 0xb1, 0xc4, 0xb6, 0xc7, 0xf3, 0x6c, 0x82, 0x3f, 0x03, 0xfc, 0x87, 0x06,
    0x21, 0xb7,
];
