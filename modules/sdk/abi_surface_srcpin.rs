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
    0x8b, 0x8e, 0xe6, 0xfd, 0xe8, 0x41, 0xb3, 0x69, 0x80, 0x4d, 0x32, 0xf6, 0x90, 0xf1, 0x55,
    0x9f, 0x3b, 0xee, 0xa8, 0x31, 0x1d, 0x3f, 0x18, 0xad, 0x10, 0xe6, 0x73, 0xa6, 0x73, 0xa3,
    0x13, 0x34,
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
    0x50, 0xd7, 0x67, 0x35, 0xfd, 0xdb, 0x6b, 0x19, 0x43, 0x75, 0x50, 0xe9, 0x0f, 0x69, 0x88,
    0xc0, 0x3b, 0xc2, 0x22, 0x9e, 0xf0, 0x20, 0x9d, 0x31, 0x48, 0xa2, 0x7f, 0xe9, 0x00, 0x92,
    0xb8, 0x66,
];
