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
    0x2f, 0xd0, 0xdf, 0x18, 0x4f, 0x85, 0x2f, 0xe7, 0x8e, 0x7b, 0x3a, 0x63, 0xb6, 0x70, 0x5d, 0xd6,
    0x73, 0x9b, 0xf0, 0xbb, 0x78, 0x15, 0x2e, 0x0d, 0x7a, 0xd1, 0x17, 0x40, 0x93, 0xff, 0x83, 0x1d,
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
    0x54, 0x07, 0x6f, 0x08, 0xf2, 0x02, 0x62, 0xff, 0x8c, 0x7a, 0x9b, 0xfa, 0xa4, 0x3e, 0xf6, 0x2d,
    0xe2, 0xf4, 0x4e, 0xcf, 0x2c, 0x14, 0x9e, 0x6f, 0xd4, 0xfe, 0xe4, 0x5a, 0xf4, 0x2e, 0xde, 0x69,
];
