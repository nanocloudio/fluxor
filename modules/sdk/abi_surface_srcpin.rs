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
    0xde, 0x34, 0xab, 0xfe, 0xf9, 0x31, 0xcd, 0xc8, 0xc6, 0x40, 0x52, 0x8e, 0x70, 0x38, 0xf2, 0xd9,
    0x94, 0x02, 0xf9, 0x7f, 0xe5, 0x9c, 0xcb, 0x59, 0xfd, 0x9d, 0x2d, 0xaf, 0x1c, 0x9c, 0x20, 0xc9,
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
    0xd1, 0x57, 0x9f, 0xf4, 0x76, 0x5c, 0x3e, 0x92, 0xc6, 0xd5, 0xe6, 0x87, 0xcc, 0x12, 0x67, 0x1b,
    0x63, 0xdc, 0x73, 0x8b, 0x76, 0x33, 0x80, 0x0b, 0x21, 0xa9, 0x1d, 0xa9, 0xee, 0xfe, 0x07, 0x8f,
];
