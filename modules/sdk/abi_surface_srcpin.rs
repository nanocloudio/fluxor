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
    0x08, 0x4a, 0xf8, 0xe9, 0xff, 0x1c, 0x23, 0x44, 0x84, 0x55, 0x0a, 0x13, 0xc2, 0xca, 0xbb,
    0xdd, 0x5d, 0x84, 0x01, 0x07, 0xae, 0xcc, 0x69, 0x8e, 0x8f, 0xe1, 0x1f, 0x2a, 0x72, 0x85,
    0x8d, 0x0c,
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
    0x2b, 0x4c, 0xf0, 0x68, 0x0a, 0xea, 0x10, 0x8f, 0x87, 0xb0, 0x69, 0xcb, 0x36, 0x8a, 0x20,
    0x7e, 0xce, 0x4e, 0xc8, 0xdf, 0x33, 0xd8, 0x36, 0xfa, 0x43, 0x8c, 0x67, 0x6c, 0x6a, 0xd2,
    0xb8, 0x24,
];
