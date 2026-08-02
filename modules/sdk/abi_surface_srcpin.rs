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
    0xa5, 0xfa, 0x12, 0xc5, 0xe4, 0x31, 0x55, 0xc4, 0xee, 0x06, 0xb1, 0x29, 0x51, 0x96, 0x7e,
    0x76, 0xde, 0x50, 0x21, 0x4a, 0x36, 0x8e, 0xe3, 0x46, 0x8f, 0x8a, 0x3e, 0xac, 0x81, 0xfd,
    0x1c, 0xbb,
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
    0xcb, 0xd1, 0x46, 0xeb, 0x1c, 0xb0, 0xdd, 0x89, 0x9d, 0xa4, 0x22, 0x42, 0xef, 0x62, 0x34,
    0x33, 0x3e, 0x3e, 0xc1, 0x7b, 0xf5, 0x49, 0x96, 0xbc, 0x19, 0x20, 0x2f, 0x86, 0xb4, 0x6d,
    0x14, 0xed,
];
