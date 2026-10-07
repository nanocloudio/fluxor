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
    0x59, 0x5e, 0x0d, 0xe8, 0x21, 0x7a, 0x82, 0x0a, 0xc6, 0xb0, 0x82, 0xd1, 0xfc, 0xd3, 0x2c, 0xc6,
    0x72, 0xd1, 0xe7, 0xb0, 0x85, 0xbb, 0x31, 0x3b, 0xd7, 0xa3, 0x83, 0xd3, 0x67, 0x7e, 0x1a, 0xad,
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
    0x6f, 0x79, 0xe1, 0x96, 0xb9, 0x7b, 0x48, 0x35, 0x7f, 0x11, 0x64, 0xf8, 0xb8, 0x14, 0x53, 0x72,
    0x11, 0x45, 0x17, 0xa9, 0xb1, 0xb0, 0xda, 0x54, 0x99, 0xaa, 0x9b, 0x87, 0xe9, 0x51, 0xb8, 0x42,
];
