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
    0x0e, 0x94, 0xa8, 0xb9, 0x55, 0xd3, 0x68, 0x7b, 0xb1, 0xc6, 0xb9, 0x06, 0xc5, 0xf9, 0xfd, 0x95,
    0xe4, 0xe6, 0x37, 0x6f, 0x59, 0xd6, 0x84, 0x65, 0x7f, 0x04, 0xfd, 0xb2, 0xac, 0x9d, 0xfd, 0x6a,
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
    0x47, 0x61, 0x30, 0x49, 0x27, 0xfa, 0x8d, 0x80, 0x25, 0x92, 0x55, 0x1c, 0x52, 0xe9, 0x63, 0xf5,
    0x57, 0xc6, 0x6f, 0x19, 0x42, 0x0f, 0x88, 0x0a, 0x91, 0x47, 0xa3, 0xd9, 0xbe, 0x05, 0x51, 0xaf,
];
