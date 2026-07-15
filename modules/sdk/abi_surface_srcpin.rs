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
    0xf3, 0x0c, 0x06, 0xb8, 0x02, 0x90, 0x18, 0x60, 0xda, 0x1f, 0x26, 0xc8, 0xf0, 0x7e, 0xfd,
    0x91, 0xa0, 0xbe, 0xd2, 0x88, 0x5d, 0x0e, 0xd2, 0xa4, 0x92, 0xb1, 0x5c, 0x2f, 0x9e, 0x33,
    0x1b, 0xb0,
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
    0x99, 0x6e, 0x3a, 0xf7, 0xe7, 0x12, 0xc2, 0xe3, 0x94, 0x5f, 0x8c, 0xd5, 0x8b, 0xe7, 0x0d,
    0x7f, 0x4e, 0x36, 0xdb, 0x12, 0xcb, 0xe5, 0x09, 0xa9, 0x9d, 0x0e, 0x2f, 0xee, 0x5b, 0x32,
    0xa1, 0x4e,
];
