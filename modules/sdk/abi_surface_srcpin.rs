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
    0x20, 0x48, 0x5e, 0x3c, 0x0b, 0x61, 0x19, 0xe7, 0x9f, 0x89, 0xc1, 0x71, 0x94, 0xbe, 0x4d,
    0xfd, 0xcf, 0x5f, 0x05, 0x40, 0x09, 0xf1, 0x4c, 0x92, 0x2e, 0xf8, 0x29, 0x41, 0x74, 0x1c,
    0xc8, 0x85,
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
    0xe3, 0xc7, 0x33, 0x9e, 0x0b, 0x54, 0x2b, 0x7e, 0x7e, 0x1a, 0x3d, 0x81, 0x84, 0xc2, 0x6e,
    0xf5, 0xe7, 0x70, 0x6e, 0x05, 0xfd, 0xc9, 0x5f, 0x13, 0x46, 0x09, 0x32, 0xe7, 0x61, 0x0a,
    0xad, 0xaf,
];
