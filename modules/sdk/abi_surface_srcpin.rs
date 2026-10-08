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
    0x8f, 0x50, 0x8c, 0xd9, 0x38, 0x35, 0x00, 0x71, 0x5a, 0x50, 0x0f, 0xb6, 0x97, 0x42, 0x04, 0xe1,
    0xcb, 0xa7, 0x02, 0xdc, 0xae, 0x4f, 0x5f, 0x2c, 0x09, 0x8b, 0xb5, 0x99, 0x8e, 0xdb, 0x4a, 0x9a,
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
    0x2e, 0xaa, 0x60, 0x95, 0x46, 0xa3, 0x81, 0x7b, 0xa3, 0xee, 0x61, 0xb5, 0x19, 0x25, 0x35, 0xd5,
    0x29, 0xc3, 0x53, 0x71, 0x61, 0x98, 0x54, 0xc8, 0x64, 0x02, 0x2c, 0x7e, 0x6f, 0x91, 0x5e, 0x12,
];
