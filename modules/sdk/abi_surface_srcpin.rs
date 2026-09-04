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
    0xf9, 0xef, 0xe6, 0x13, 0x02, 0xb8, 0xa1, 0xd9, 0x2f, 0x7d, 0x0c, 0xdb, 0x65, 0xe2, 0x82,
    0x5d, 0x40, 0xe1, 0x2c, 0xb7, 0x10, 0xf0, 0x97, 0x2d, 0x81, 0x2c, 0x3d, 0xe3, 0x88, 0x0f,
    0x7a, 0xb3,
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
    0x3e, 0xe9, 0x50, 0x49, 0x95, 0xd0, 0xb3, 0x21, 0xdd, 0x1a, 0xea, 0x7e, 0x06, 0x27, 0x87,
    0xe4, 0xd2, 0x67, 0xec, 0x02, 0x19, 0x32, 0x8c, 0x45, 0x78, 0x62, 0x59, 0xaa, 0x38, 0xb5,
    0x72, 0x0f,
];
