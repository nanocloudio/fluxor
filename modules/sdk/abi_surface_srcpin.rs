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
    0xaa, 0x36, 0x8a, 0x8d, 0x30, 0x00, 0xc1, 0xf0, 0x90, 0x63, 0x77, 0x00, 0xbc, 0x7f, 0x4c, 0x03,
    0x55, 0x85, 0x88, 0x5a, 0xba, 0xd4, 0x59, 0xa4, 0x93, 0xeb, 0xe8, 0x8b, 0x59, 0x00, 0xe9, 0xb5,
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
    0x19, 0x0e, 0xb1, 0x6d, 0x3b, 0xf6, 0x7a, 0x4e, 0x77, 0xf6, 0xda, 0xce, 0x07, 0xb6, 0x00, 0xcc,
    0x10, 0xb8, 0x49, 0x5f, 0xc0, 0x56, 0x0b, 0xcb, 0x0c, 0x2c, 0xf2, 0x82, 0x0a, 0x25, 0x73, 0xd5,
];
