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
    0x34, 0xa3, 0xb7, 0x31, 0x68, 0x54, 0xd2, 0x67, 0xca, 0x05, 0x02, 0x04, 0xca, 0x2b, 0xdb,
    0xc0, 0x15, 0xb3, 0x62, 0x0e, 0x73, 0xb8, 0xd7, 0x0e, 0x34, 0xe6, 0x3b, 0x9a, 0x5f, 0x3e,
    0x0c, 0xa6,
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
    0x0b, 0xa7, 0x32, 0x0a, 0x8f, 0x37, 0xed, 0x50, 0x41, 0x63, 0x3e, 0xa1, 0x39, 0x0e, 0xad,
    0x00, 0x60, 0x7e, 0x1b, 0x84, 0x34, 0x81, 0xe2, 0x6b, 0x02, 0x57, 0x47, 0x88, 0x84, 0xa5,
    0x2a, 0x3c,
];
