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
    0xdb, 0x79, 0x12, 0xb0, 0x3d, 0x0b, 0xf0, 0x1c, 0xd0, 0x07, 0xe7, 0x4b, 0xe9, 0x2c, 0x15, 0x57,
    0x0e, 0x5a, 0x0c, 0xee, 0xb4, 0x2b, 0x09, 0x68, 0xb0, 0x48, 0x05, 0x26, 0xf9, 0x7c, 0x8c, 0xac,
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
    0x39, 0xf0, 0xef, 0x17, 0x26, 0xe9, 0x32, 0xbc, 0x77, 0xdd, 0x53, 0x31, 0x54, 0xfc, 0xd7, 0xad,
    0x25, 0x56, 0x4f, 0x6b, 0x17, 0xb4, 0xf1, 0xb4, 0x35, 0xcd, 0xdc, 0x5a, 0x77, 0xab, 0x2d, 0x68,
];
