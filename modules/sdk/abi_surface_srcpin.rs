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
    0xec, 0xcf, 0x5d, 0xed, 0x04, 0x8e, 0xf5, 0x0f, 0x71, 0xd1, 0x70, 0xdc, 0xd4, 0x96, 0x45, 0xe9,
    0xe3, 0xa2, 0xb2, 0x3d, 0x34, 0x9a, 0x9a, 0x30, 0x85, 0x08, 0x54, 0xa1, 0xde, 0x15, 0x36, 0x4c,
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
    0x09, 0x23, 0x31, 0xcc, 0xdc, 0x71, 0xe9, 0xed, 0x13, 0x00, 0x0c, 0x7b, 0xf9, 0x3c, 0xd3, 0x48,
    0x56, 0x91, 0xed, 0x99, 0xfc, 0xbf, 0x9f, 0x2c, 0x2b, 0x30, 0xa5, 0x2a, 0x10, 0x59, 0xdd, 0x93,
];
