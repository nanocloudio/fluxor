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
    0x65, 0x8b, 0x1a, 0xda, 0x8b, 0xa1, 0x39, 0xdc, 0x0d, 0x1e, 0x61, 0xc3, 0x3c, 0x17, 0x9a, 0xec,
    0x7a, 0x60, 0x16, 0x16, 0x17, 0x6b, 0xc3, 0x52, 0x04, 0x63, 0x8b, 0xe9, 0x38, 0x79, 0xa9, 0x33,
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
    0xe1, 0xa9, 0xa6, 0x4a, 0x45, 0x52, 0x6c, 0x15, 0xaa, 0x69, 0x34, 0x7a, 0x10, 0xf5, 0xfc, 0xd8,
    0x6e, 0x4e, 0x0e, 0x37, 0x02, 0x65, 0x5e, 0xeb, 0xc8, 0xe6, 0xc0, 0xca, 0x48, 0x29, 0x08, 0xb1,
];
