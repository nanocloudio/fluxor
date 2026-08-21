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
    0x42, 0x69, 0xd5, 0xbc, 0x68, 0x17, 0x2e, 0xb4, 0xca, 0x9a, 0x9b, 0xc2, 0x60, 0xf4, 0x33,
    0xe5, 0x04, 0xed, 0x77, 0xce, 0x0f, 0x53, 0x93, 0x01, 0xb4, 0x4a, 0x2e, 0x95, 0xfe, 0xb0,
    0xb0, 0xf1,
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
    0x2d, 0xd6, 0x06, 0x31, 0xa1, 0xc7, 0x5d, 0x29, 0xe3, 0xc9, 0x21, 0x43, 0x1b, 0xe0, 0x1c,
    0x87, 0x2f, 0x03, 0xa2, 0x22, 0xf2, 0x6b, 0xf9, 0x67, 0xc3, 0x1e, 0xd6, 0x0d, 0xc4, 0x46,
    0x35, 0x2b,
];
