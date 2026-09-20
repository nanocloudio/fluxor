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
    0x24, 0xf4, 0x8e, 0xb3, 0xad, 0xfc, 0xe9, 0xc0, 0x45, 0x87, 0x63, 0xe2, 0xab, 0xde, 0xfd, 0x8c,
    0xbc, 0x36, 0x26, 0xcb, 0x38, 0xa3, 0x58, 0xaa, 0x6c, 0x6e, 0x8c, 0xa2, 0x60, 0x88, 0x73, 0xf3,
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
    0xce, 0x73, 0x55, 0xee, 0x5f, 0x0a, 0xcf, 0xee, 0x77, 0xf3, 0x09, 0x94, 0xa9, 0xb5, 0xc0, 0x11,
    0xe2, 0x1a, 0x5d, 0xf9, 0x15, 0xfe, 0x6e, 0x23, 0x75, 0x5b, 0xf2, 0x9d, 0xfc, 0x16, 0x9d, 0xc4,
];
