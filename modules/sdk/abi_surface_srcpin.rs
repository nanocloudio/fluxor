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
    0x89, 0x0a, 0xfd, 0xe5, 0xe6, 0xc2, 0x80, 0xe9, 0x5a, 0x90, 0x27, 0x9a, 0x45, 0x5c, 0x1a, 0x95,
    0x9a, 0xe8, 0x23, 0x3e, 0x79, 0xc1, 0xa6, 0x2e, 0x9c, 0x32, 0xe9, 0x95, 0xc3, 0xb9, 0x2d, 0xbc,
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
    0x14, 0x90, 0x5a, 0x91, 0xbc, 0xc2, 0x59, 0x24, 0x9c, 0x03, 0x48, 0x34, 0x35, 0x75, 0xab, 0xee,
    0x3d, 0x65, 0xb0, 0xc4, 0xe6, 0x30, 0xc8, 0xf5, 0x46, 0x62, 0x7a, 0x76, 0x10, 0x81, 0xe9, 0xe5,
];
