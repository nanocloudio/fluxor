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
    0xc2, 0xb7, 0x23, 0x0b, 0x24, 0x64, 0xbe, 0x04, 0x6e, 0x96, 0xe8, 0xcb, 0x00, 0xfa, 0xda,
    0x26, 0x20, 0x17, 0x19, 0xcf, 0xd0, 0xb5, 0x9f, 0xa9, 0x97, 0x06, 0x78, 0xd3, 0x05, 0xe5,
    0xba, 0xfa,
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
    0xa7, 0x47, 0x0c, 0xe0, 0xd5, 0x14, 0x38, 0xb1, 0x84, 0x96, 0x76, 0x39, 0xa5, 0x46, 0xb7,
    0x39, 0x8f, 0xe2, 0x79, 0xdc, 0x72, 0x63, 0x58, 0x35, 0x13, 0xd1, 0x48, 0xcc, 0x97, 0xe1,
    0xa4, 0x20,
];
