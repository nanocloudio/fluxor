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
    0x9d, 0x1e, 0x9c, 0x24, 0x33, 0x73, 0x8d, 0xd9, 0xa9, 0xba, 0x77, 0xdb, 0x94, 0x9c, 0x86, 0x45,
    0x15, 0x6e, 0xd5, 0x2f, 0x4e, 0x51, 0x92, 0x97, 0xb4, 0x7d, 0x04, 0x4c, 0x38, 0x1f, 0x14, 0xa9,
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
    0xa3, 0xb6, 0xd0, 0x57, 0x4e, 0x71, 0x7a, 0x4c, 0xc1, 0x0d, 0x34, 0xbf, 0x6d, 0x4d, 0x23, 0x74,
    0x00, 0xbe, 0x66, 0x71, 0xa9, 0x46, 0x72, 0x36, 0xa4, 0x32, 0x28, 0xdd, 0xa1, 0x09, 0x2e, 0xc6,
];
