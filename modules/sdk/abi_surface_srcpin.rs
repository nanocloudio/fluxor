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
    0x9c, 0x2d, 0x59, 0x71, 0xfd, 0x49, 0x8c, 0xab, 0xc3, 0x2c, 0x0c, 0xdc, 0x61, 0x9f, 0x40, 0x3b,
    0x97, 0xc3, 0x69, 0x99, 0xba, 0x07, 0xd0, 0x54, 0x73, 0x46, 0x2b, 0xbd, 0xbc, 0x10, 0x86, 0xc5,
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
    0x53, 0xdf, 0xb8, 0x7f, 0xa2, 0xa4, 0x54, 0xb8, 0x9d, 0x43, 0x0c, 0x0b, 0xd1, 0xd8, 0x71, 0xaa,
    0x43, 0x39, 0xa6, 0x5a, 0xff, 0x69, 0x2f, 0xda, 0x7d, 0x5b, 0xd3, 0xbf, 0x38, 0x20, 0xb4, 0x30,
];
