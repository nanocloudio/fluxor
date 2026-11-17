// Contract: storage.custody — custody of a keyed volume's key.
//
// Layer: contracts/storage (public, stable).
//
// A volume whose content is sealed under a key (an encrypted
// `storage.object` volume, say) holds that key in its own key_vault
// namespace: the vault scopes labels by module type, so no other module
// reaches it, and the key never leaves the vault. What a consumer needs of
// the key — a sealed backup of some bytes, the volume's recovery custodians,
// recovery shares of the key, a drill that those shares still rebuild it —
// it asks the volume for, by the volume's name, through this contract.
//
// A consumer binds the volume by name once (`kernel_abi::bind`, `NAME`)
// and calls every op through that bound handle; the provider sees
// `handle = -1`. Every `arg` is one bounded record the provider reads its
// input from and writes its answer back into; the bytes [`SEAL`] and
// [`OPEN`] transform travel in `data`, in place. No field is an address.
//
// Shares use key_vault's v1 share format (`key_vault::share`): a 2-of-3
// split of the 32-byte key, each share sealed to one recipient's P-256 key
// in a `share::P256_LEN`-byte envelope.

use super::super::key_vault::share;

/// Seal bytes under the volume's backup key, in place.
///
/// ```text
/// arg  (in):     [len:u32]
/// data (in/out): len plain bytes in, the sealed bytes out
/// ```
///
/// `data` must leave room for [`SEAL_OVERHEAD`] more than `len`. Answers the
/// sealed length, or `EINVAL` when `len` exceeds what `data` or the provider
/// takes. [`seal_arg`] encodes the record.
pub use super::super::super::registry::storage_custody::SEAL;

/// Open bytes [`SEAL`] produced, in place: the same shape, `len` sealed
/// bytes in `data`, the plain bytes out. Answers the plain length; bytes
/// sealed under another volume's key, or altered, do not open.
pub use super::super::super::registry::storage_custody::OPEN;

/// One of the volume's recovery custodians: its P-256 public key.
///
/// ```text
/// arg (in/out): [index:u8][_:3][public:share::P256_PUB_LEN]
/// ```
///
/// `index` is in `0..share::COUNT_V1`; the provider writes the key into
/// `public` and answers its length.
pub use super::super::super::registry::storage_custody::CUSTODIAN;

/// Split the volume's key into recovery shares, one sealed to each
/// recipient.
///
/// ```text
/// arg (in/out): [recipient:share::P256_PUB_LEN × share::COUNT_V1]
///               [envelope:share::P256_LEN × share::COUNT_V1]
/// ```
///
/// Envelope `i` is written for recipient `i`. Answers 0.
pub use super::super::super::registry::storage_custody::SPLIT;

/// Check that recovery shares rebuild the volume's key, without rebuilding
/// it anywhere but inside the vault.
///
/// ```text
/// arg (in): [custodian a:u8][custodian b:u8][_:2][envelope a][envelope b]
/// ```
///
/// Each envelope is `share::P256_LEN` bytes, opened by the named custodian's
/// key. Answers [`DRILL_REBUILDS`] when the two shares rebuild this
/// volume's key, [`DRILL_OTHER_KEY`] when they rebuild another key, and an
/// errno when they do not combine.
pub use super::super::super::registry::storage_custody::DRILL;

/// What sealing adds to a payload: the AEAD nonce and tag.
pub const SEAL_OVERHEAD: usize = 12 + 16;

/// A [`SEAL`] / [`OPEN`] `arg`: the length of the bytes in `data`.
pub const SEAL_ARG_LEN: usize = 4;

/// The [`SEAL`] / [`OPEN`] `arg` for `len` bytes.
pub const fn seal_arg(len: u32) -> [u8; SEAL_ARG_LEN] {
    len.to_le_bytes()
}

/// The length a [`SEAL`] / [`OPEN`] `arg` names; `None` unless it is
/// exactly one record.
pub fn parse_seal_arg(arg: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(arg.try_into().ok()?))
}

/// Offset of the public key in a [`CUSTODIAN`] block, and its length.
pub const CUSTODIAN_PUBLIC: usize = 4;
pub const CUSTODIAN_LEN: usize = CUSTODIAN_PUBLIC + share::P256_PUB_LEN;

/// A [`SPLIT`] block: recipients first, then the envelopes written back.
pub const SPLIT_ENVELOPES: usize = share::COUNT_V1 as usize * share::P256_PUB_LEN;
pub const SPLIT_LEN: usize = SPLIT_ENVELOPES + share::COUNT_V1 as usize * share::P256_LEN;

/// A [`DRILL`] block: two custodian indices, then their two envelopes.
pub const DRILL_ENVELOPES: usize = 4;
pub const DRILL_LEN: usize = DRILL_ENVELOPES + 2 * share::P256_LEN;

/// [`DRILL`]'s answers.
pub const DRILL_REBUILDS: i32 = 1;
pub const DRILL_OTHER_KEY: i32 = 0;

const _: () = assert!(SPLIT_LEN <= super::super::super::registry::gate::ARG_MAX);
