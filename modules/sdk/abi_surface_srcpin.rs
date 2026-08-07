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
    0xee, 0xec, 0x2b, 0x35, 0x2a, 0x32, 0xdc, 0x41, 0x5f, 0xad, 0x91, 0x01, 0x6f, 0xd4, 0xae,
    0x30, 0x88, 0x16, 0x9b, 0xf6, 0x1d, 0xbd, 0x7d, 0x40, 0xb3, 0x56, 0x55, 0x56, 0xab, 0x76,
    0xe4, 0x41,
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
    0xdd, 0x1a, 0x2f, 0xb8, 0x8d, 0x55, 0x2a, 0xbf, 0x93, 0xd3, 0x4e, 0x4e, 0x6c, 0x71, 0x2a,
    0x2f, 0x68, 0x27, 0x0a, 0xc7, 0x7e, 0xa4, 0x08, 0x9a, 0x3f, 0x23, 0xa5, 0x2e, 0xe0, 0x8c,
    0x51, 0x78,
];
