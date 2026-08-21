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
    0x49, 0x86, 0xd2, 0xac, 0xd0, 0x95, 0xf6, 0x6e, 0x13, 0x18, 0x2e, 0x9e, 0x8a, 0x37, 0xfc,
    0x4d, 0x5f, 0x49, 0x1e, 0x89, 0x63, 0xe8, 0xcd, 0xbd, 0xe7, 0xd9, 0xc1, 0xec, 0x2c, 0x72,
    0x10, 0x39,
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
    0xa3, 0x00, 0x4a, 0xdd, 0xc3, 0x58, 0xed, 0xb6, 0x96, 0xec, 0xac, 0xa9, 0xf7, 0x3f, 0x27,
    0xda, 0xf3, 0x42, 0x6d, 0x0e, 0x9a, 0x12, 0x41, 0x9e, 0x1c, 0x90, 0x64, 0xe8, 0x39, 0xa5,
    0xa6, 0x7c,
];
