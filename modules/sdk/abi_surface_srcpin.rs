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
    0x19, 0x38, 0x30, 0x02, 0xf3, 0x6f, 0xe6, 0xdc, 0x80, 0xa4, 0x06, 0xa7, 0x7c, 0xa2, 0x5e,
    0xfa, 0xe9, 0x12, 0x9b, 0x79, 0x1c, 0xf5, 0xe0, 0x8d, 0x52, 0x17, 0x3f, 0x8f, 0x9d, 0x0b,
    0x04, 0x65,
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
    0x17, 0x30, 0xf5, 0xa1, 0x9e, 0x2a, 0x80, 0x31, 0xd4, 0xc2, 0x74, 0xeb, 0xe5, 0xcc, 0x8f,
    0x1e, 0x46, 0x3f, 0xb7, 0x2e, 0xef, 0xcb, 0x4c, 0xfc, 0x91, 0x74, 0x45, 0xd9, 0x02, 0x32,
    0xa0, 0x12,
];
