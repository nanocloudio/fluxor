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
    0x9b, 0x48, 0xc6, 0xdc, 0xeb, 0x31, 0xa5, 0x26, 0x67, 0x19, 0xdc, 0x20, 0x72, 0xeb, 0xf5,
    0x2c, 0xea, 0x9f, 0xa7, 0xf1, 0xc5, 0xd6, 0x4a, 0xd2, 0x1c, 0xf5, 0x2d, 0x9b, 0x6c, 0xf2,
    0x92, 0x81,
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
    0xfa, 0x99, 0x65, 0x3d, 0x99, 0x79, 0x9b, 0x00, 0x6a, 0xd1, 0x40, 0xe3, 0x7a, 0x16, 0xd3,
    0x81, 0xab, 0xa3, 0xb6, 0x53, 0xda, 0x24, 0x0a, 0x68, 0xda, 0x72, 0x43, 0x06, 0xc3, 0x43,
    0xb7, 0xf6,
];
