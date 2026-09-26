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
    0xb5, 0xed, 0xc9, 0xaf, 0xce, 0x88, 0x4b, 0xb0, 0x93, 0x34, 0xc4, 0xdc, 0x00, 0x55, 0xf4, 0x39,
    0xe3, 0xab, 0x59, 0xd9, 0x17, 0x5c, 0x5b, 0x21, 0x74, 0x3b, 0x34, 0x6a, 0x95, 0x43, 0x8f, 0xd5,
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
    0x24, 0xc9, 0xcc, 0x7f, 0x9b, 0xb2, 0xd0, 0x66, 0xf6, 0x55, 0x8a, 0x79, 0xc9, 0xcb, 0xee, 0xb6,
    0x77, 0xc0, 0x54, 0xa3, 0x3a, 0xf3, 0x46, 0xe8, 0xb6, 0xe4, 0xba, 0xc1, 0x4c, 0x56, 0xc6, 0x95,
];
