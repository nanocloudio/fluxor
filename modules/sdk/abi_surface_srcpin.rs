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
    0x5f, 0x78, 0xce, 0x4c, 0xe8, 0xcd, 0x60, 0xa7, 0xcc, 0x70, 0x27, 0xb1, 0x3c, 0xce, 0xff,
    0xa9, 0x49, 0xc6, 0x6c, 0xdc, 0x63, 0xb7, 0x87, 0xce, 0x31, 0x9c, 0x9d, 0x9b, 0x0c, 0x4c,
    0x3d, 0x9c,
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
    0x11, 0x8c, 0xd0, 0x21, 0x57, 0x8b, 0x9f, 0x1b, 0xc5, 0xa9, 0x89, 0x2b, 0x7f, 0x52, 0x3b,
    0x8c, 0x61, 0x98, 0x57, 0xf1, 0xa8, 0x46, 0x5a, 0xc3, 0x9b, 0xb6, 0xca, 0x2a, 0xc1, 0x39,
    0x91, 0xb7,
];
