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
    0x1c, 0x24, 0x0c, 0x0c, 0x8c, 0xba, 0x28, 0x93, 0xe2, 0x30, 0x88, 0x69, 0x07, 0xf3, 0x00,
    0x4b, 0xea, 0xc7, 0x9b, 0xcb, 0x69, 0xee, 0xd8, 0x4e, 0xc1, 0x94, 0x54, 0xf0, 0x89, 0x20,
    0x59, 0xbb,
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
    0x89, 0x36, 0xcb, 0xe6, 0x46, 0xa9, 0x4d, 0x01, 0xa7, 0xa2, 0x15, 0xfb, 0x82, 0xb5, 0x8d,
    0xcd, 0xdc, 0x6d, 0xf2, 0x87, 0xc6, 0x0f, 0xbc, 0x77, 0xaa, 0xbe, 0x0f, 0x8e, 0x60, 0x1a,
    0xc6, 0x71,
];
