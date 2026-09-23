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
    0x10, 0x5d, 0x6b, 0xbe, 0x0e, 0x91, 0xc3, 0x7f, 0x55, 0xb6, 0x72, 0xdb, 0xed, 0xe9, 0x83, 0x2f,
    0xaa, 0x83, 0xdc, 0x82, 0x51, 0x3b, 0xa1, 0xf2, 0x9b, 0xc6, 0x5d, 0x00, 0x89, 0xf0, 0xdd, 0x37,
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
    0xab, 0x8b, 0x97, 0x0e, 0xb4, 0xcb, 0xb8, 0x0b, 0x05, 0xee, 0xb6, 0x4e, 0xe6, 0x8c, 0x3a, 0xaf,
    0x87, 0xb2, 0x9c, 0x1c, 0xbd, 0x66, 0x23, 0xc5, 0x89, 0xd9, 0x1b, 0xac, 0x02, 0x6b, 0x62, 0xc5,
];
