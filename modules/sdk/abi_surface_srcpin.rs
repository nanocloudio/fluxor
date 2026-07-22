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
    0x31, 0x9f, 0x03, 0x75, 0x45, 0x08, 0xd8, 0x0f, 0x30, 0x94, 0xa2, 0x42, 0xea, 0xba, 0x5d,
    0x22, 0xcc, 0x61, 0x70, 0x25, 0xc6, 0x6f, 0x9b, 0x98, 0xbe, 0x95, 0x46, 0x4e, 0xf4, 0xb0,
    0x70, 0xd0,
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
    0x5a, 0xa1, 0x53, 0x98, 0xe7, 0x91, 0x7e, 0x24, 0xbb, 0xef, 0x20, 0x0b, 0x82, 0x17, 0x31,
    0x43, 0x30, 0xc3, 0xfd, 0xb0, 0x51, 0x79, 0x27, 0x81, 0xa1, 0xa8, 0x32, 0x0e, 0x9b, 0x8a,
    0xf2, 0x01,
];
