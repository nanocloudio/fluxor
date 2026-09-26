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
    0x1a, 0x7b, 0xf5, 0xdf, 0xab, 0x37, 0x2b, 0x57, 0x34, 0x5c, 0x0a, 0x64, 0x3e, 0xa8, 0xda, 0xec,
    0x1e, 0x4c, 0x3b, 0x81, 0x10, 0x87, 0x09, 0x40, 0x89, 0x9c, 0xc9, 0x5f, 0xad, 0xb3, 0xac, 0x52,
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
    0x62, 0xbe, 0xe3, 0xc4, 0x05, 0x78, 0x9e, 0x4a, 0x12, 0xb2, 0x29, 0x74, 0xbd, 0x26, 0x09, 0x7d,
    0x87, 0xbc, 0x2b, 0x4c, 0x43, 0xc7, 0x6c, 0x77, 0x5e, 0x65, 0xc9, 0xd0, 0xc3, 0xe2, 0x89, 0x19,
];
