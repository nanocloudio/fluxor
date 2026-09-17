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
    0x1e, 0xb8, 0xd7, 0x6f, 0x70, 0x33, 0xec, 0x69, 0xac, 0xc4, 0x7e, 0xbd, 0x9a, 0xee, 0xd3,
    0x0b, 0x25, 0x5e, 0xe4, 0x3f, 0xa0, 0x4d, 0x4d, 0xff, 0xb5, 0xea, 0x7a, 0xf6, 0x7a, 0x88,
    0x76, 0x7a,
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
    0xc6, 0xae, 0x72, 0x41, 0x1f, 0x02, 0xae, 0xd8, 0x9f, 0xee, 0x77, 0x2a, 0x3e, 0xe9, 0x09,
    0x8a, 0xf7, 0x7d, 0x69, 0x0d, 0xd0, 0x00, 0xcc, 0x01, 0x4d, 0x3e, 0x58, 0xde, 0x32, 0xac,
    0xf5, 0x46,
];
