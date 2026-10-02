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
    0xc5, 0xb6, 0x8d, 0x00, 0x33, 0x86, 0xa8, 0xd0, 0xbe, 0x71, 0xcb, 0xd2, 0xd4, 0x72, 0xfb, 0x1b,
    0x5c, 0x02, 0xa0, 0x0f, 0xab, 0xe4, 0x2e, 0xed, 0xe3, 0x2c, 0x09, 0x64, 0x28, 0xe5, 0xff, 0x23,
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
    0x46, 0x3c, 0x8d, 0x7a, 0x8d, 0xec, 0xd7, 0x4d, 0x7f, 0x7e, 0x8b, 0x45, 0x4f, 0x9b, 0x57, 0x59,
    0x54, 0x32, 0x30, 0xe5, 0x3c, 0xc3, 0x5f, 0x78, 0x1a, 0x6d, 0xd9, 0x19, 0x08, 0xb8, 0x0c, 0x66,
];
