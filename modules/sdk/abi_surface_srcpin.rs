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
    0xf5, 0x1d, 0x51, 0x44, 0x15, 0xe4, 0xca, 0xe1, 0x85, 0x92, 0xb2, 0x98, 0xb0, 0x51, 0xab,
    0x00, 0x30, 0x0d, 0x79, 0x1b, 0xb8, 0x41, 0xcf, 0x27, 0xc1, 0x3f, 0xc3, 0xd7, 0x2b, 0xee,
    0xba, 0x12,
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
    0x15, 0x4e, 0x75, 0xbb, 0xdd, 0x3c, 0xc2, 0x8a, 0x50, 0x3a, 0xc3, 0x25, 0x2e, 0xa3, 0x0d,
    0x79, 0xb3, 0x70, 0x17, 0xf5, 0x2d, 0x23, 0xb6, 0x13, 0x8c, 0xce, 0xd0, 0xc2, 0x67, 0x04,
    0xda, 0xa8,
];
