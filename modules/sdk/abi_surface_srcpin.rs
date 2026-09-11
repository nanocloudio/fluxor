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
    0x13, 0x5d, 0x48, 0x45, 0x3e, 0x00, 0xd5, 0x5a, 0xac, 0x89, 0xb2, 0xea, 0x82, 0xc5, 0xc9,
    0x8c, 0x7e, 0x1a, 0xc0, 0x59, 0x8d, 0xc2, 0xaf, 0x7f, 0x84, 0xa0, 0xf9, 0x53, 0xae, 0xd8,
    0x61, 0xfb,
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
    0xdb, 0x1f, 0xc5, 0xa5, 0x67, 0x06, 0xd9, 0xe2, 0xff, 0xcf, 0x18, 0x00, 0xf8, 0x53, 0xc0,
    0xea, 0x39, 0x70, 0x89, 0xcb, 0x57, 0x9f, 0xd3, 0x48, 0xf1, 0xd4, 0x78, 0xd3, 0xc7, 0xa9,
    0x9d, 0x03,
];
