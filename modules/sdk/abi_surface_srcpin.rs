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
    0x70, 0xe8, 0xe4, 0xcb, 0x95, 0x21, 0xbb, 0xae, 0xf5, 0xed, 0xa2, 0xc3, 0x9f, 0x03, 0x07, 0xf5,
    0x5d, 0xad, 0x81, 0x28, 0x0e, 0x1f, 0x93, 0x5f, 0x39, 0x16, 0xaa, 0x76, 0x96, 0xda, 0xf1, 0x04,
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
    0x39, 0x11, 0x65, 0xdc, 0xd9, 0xc1, 0x48, 0x8e, 0xc1, 0xfb, 0xe7, 0x23, 0x1c, 0x7d, 0x25, 0xf7,
    0x4f, 0x09, 0x4a, 0x7d, 0x61, 0xfa, 0x0b, 0x87, 0x4d, 0x9c, 0xf2, 0x29, 0xd6, 0x26, 0x9b, 0x7e,
];
