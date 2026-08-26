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
    0x20, 0xc5, 0x51, 0x6f, 0xc8, 0x23, 0x03, 0xc3, 0x47, 0x17, 0xd2, 0x65, 0x49, 0xd7, 0x49,
    0x61, 0x07, 0x43, 0x4c, 0xae, 0x79, 0xaa, 0x6c, 0x7e, 0xc3, 0xc5, 0x5f, 0x4c, 0xfa, 0x4e,
    0x72, 0x18,
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
    0xb7, 0xa0, 0xc5, 0xc6, 0xfa, 0xbc, 0xd2, 0xa8, 0x86, 0x55, 0x3b, 0x17, 0x72, 0x70, 0xd9,
    0x32, 0x73, 0x8c, 0xfa, 0x15, 0x05, 0x22, 0x7f, 0xa7, 0x08, 0x20, 0x97, 0x4b, 0x4b, 0xc8,
    0x60, 0x1d,
];
