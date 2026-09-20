// Contract: trust — the platform decides whether a certificate chain is good.
//
// Layer: contracts (public, stable).
//
// This is a VERIFY contract, not a "read me your anchors" contract, and the
// distinction is the whole point of it. A consumer hands over the chain, the
// name it expects and the time it believes; the provider applies the
// platform's own policy — path building, name constraints, expiry, EKU,
// whatever revocation the platform does — and answers yes or no plus a
// statement of what it actually checked.
//
// No anchor DER crosses this boundary. Handing a module the platform's
// anchors and letting it verify with its own verifier reads as "system
// trust" while being something weaker and different: `tls`'s verifier
// applies no name constraints and no revocation, so a chain it accepted
// under a full public root set would be trusted far more broadly than the
// operator asked for. Here one call decides one handshake, and the
// provenance a consumer reports is a fact it was told rather than one it
// assumed.
//
// Little-endian, tightly packed, like every other contract arg here.

/// Provider class id (opcode class 0x1Dxx). Mirrors
/// `kernel::module::provider::contract::TRUST`.
pub const CLASS: u16 = 0x001D;

/// Returns 1 when a trust provider is present. Where none is registered
/// nothing answers this class at all, so the caller sees a negative errno
/// (`ENOSYS`) rather than 0. Call with handle=-1 and arg=null at
/// `module_new` to find that out at start rather than at the first
/// handshake; composition refuses a graph that asks for platform
/// verification on a target with no provider before either, through the
/// `trust.system` target capability.
pub const PROBE: u32 = 0x1D00;

/// Verify a certificate chain against the platform's trust policy.
/// handle=-1.
///
/// arg layout:
/// ```text
/// [purpose:u8][name_len:u8][cert_count:u8][reserved:u8]
/// [unix_seconds:u64]
/// [name[name_len]]                       -- ASCII, the expected identity
/// [cert_len:u16][cert_der[cert_len]] * cert_count
/// [result_out:u8][checks_out:u8][reason_out:u8][reserved_out:u8]
/// ```
///
/// The chain is leaf-first, exactly as it arrived on the wire, and the
/// provider is free to ignore intermediates it can build a better path
/// without — which is one of the things a platform verifier does that a
/// module-side one does not.
///
/// `unix_seconds` is what the CONSUMER believes the time to be. A provider
/// that has a trusted clock of its own may use that instead and say so with
/// [`check::TIME`]; one that has none uses what it was given. A consumer
/// passing 0 is saying it has no trusted time, which a provider may refuse
/// with [`reason::NO_TIME`] rather than silently skipping expiry.
///
/// The call is malformed — answered with `-EINVAL`, and no verdict written
/// — when `cert_count` is 0 or above [`MAX_CHAIN`], `name_len` is above
/// [`MAX_NAME`], a certificate length is 0 or above [`MAX_CERT`], or the
/// buffer does not carry every declared byte plus the trailing
/// [`OUT_LEN`]. An empty chain is therefore an error, not a refusal. A
/// certificate that is present but does not parse as X.509 is the other
/// way round: a verdict of [`result::REFUSED`] with [`reason::MALFORMED`].
///
/// Returns 0 when a verdict was formed (read `result_out` for it) or a
/// negative errno when none was. The two are different: a negative return
/// says the platform did not answer, so a consumer must fail closed
/// WITHOUT recording that the platform refused the chain — and must never
/// read it as a pass.
pub const VERIFY: u32 = 0x1D01;

/// What the chain is being verified FOR. A platform applies different
/// policy to a server it is dialling than to a client presenting itself,
/// and a provider that does not serve a purpose refuses it with
/// [`reason::BAD_PURPOSE`] rather than verifying under the other one.
pub mod purpose {
    /// The peer is a server this consumer dialled; `name` is the host.
    pub const SERVER: u8 = 0;
    /// The peer is a client that connected; `name` may be empty.
    pub const CLIENT: u8 = 1;
}

/// `result_out`: the verdict.
pub mod result {
    /// The platform trusts this chain for this name and purpose.
    pub const TRUSTED: u8 = 0;
    /// It does not. `reason_out` says the nearest thing to why. There is
    /// no third verdict: a provider whose trust source is unreadable can
    /// build no path either, so it refuses ([`super::reason::UNKNOWN_CA`])
    /// rather than reporting a state the contract cannot carry. Only the
    /// provider's own log tells that apart from a genuine refusal.
    pub const REFUSED: u8 = 1;
}

/// `checks_out`: a bitmask of what the provider ACTUALLY applied, so a
/// consumer's log says what was checked rather than what it hoped was.
///
/// A provider sets only the bits its policy really applies. A Linux
/// provider over the system store sets PATH | NAME | TIME | EKU |
/// CONSTRAINTS and leaves REVOCATION clear, because no revocation is
/// consulted there; saying so is the point of the field.
///
/// On a refusal the mask names the policy the provider applies, not the
/// checks that were reached: verification stops at the first failure, so a
/// chain refused with [`reason::UNKNOWN_CA`] may never have had its name
/// matched. A provider that refuses before applying any policy at all —
/// no time, no anchors, a purpose it does not serve — sets no bits.
pub mod check {
    /// A path was built to a root the platform trusts.
    pub const PATH: u8 = 1 << 0;
    /// The name was matched against the leaf's SANs.
    pub const NAME: u8 = 1 << 1;
    /// Validity dates were checked, against a clock the provider names.
    pub const TIME: u8 = 1 << 2;
    /// Extended key usage was checked for the purpose.
    pub const EKU: u8 = 1 << 3;
    /// Name constraints on the issuing chain were applied.
    pub const CONSTRAINTS: u8 = 1 << 4;
    /// Revocation was consulted (CRL, OCSP, or a platform cache).
    pub const REVOCATION: u8 = 1 << 5;
    /// The time used was the PROVIDER's own trusted clock, not the
    /// `unix_seconds` the consumer supplied.
    pub const OWN_CLOCK: u8 = 1 << 6;
}

/// `reason_out`: why a chain was refused. Advisory — it exists so an
/// operator reading a log is pointed at the right thing, and a consumer must
/// not branch on it as though it were a contract.
pub mod reason {
    pub const NONE: u8 = 0;
    /// No path to any anchor the platform holds.
    pub const UNKNOWN_CA: u8 = 1;
    /// A path exists but the leaf does not carry the expected name.
    pub const NAME_MISMATCH: u8 = 2;
    /// Something in the path is expired or not yet valid.
    pub const EXPIRED: u8 = 3;
    /// A certificate is revoked.
    pub const REVOKED: u8 = 4;
    /// A certificate does not parse, or the chain is malformed.
    pub const MALFORMED: u8 = 5;
    /// The purpose is not one this certificate may serve.
    pub const BAD_PURPOSE: u8 = 6;
    /// The consumer supplied no time and this provider will not verify
    /// without one.
    pub const NO_TIME: u8 = 7;
    /// Refused for a reason this vocabulary does not name.
    pub const OTHER: u8 = 255;
}

/// Longest `name` a VERIFY may carry. A DNS name is 253 bytes at most,
/// which the u8 `name_len` field carries exactly.
pub const MAX_NAME: usize = 253;

/// Most certificates one VERIFY may carry. A chain longer than this is not
/// a chain a deployment should be accepting.
pub const MAX_CHAIN: usize = 10;

/// Longest single certificate a VERIFY may carry.
pub const MAX_CERT: usize = 8192;

/// Byte offsets of the fixed header, for encoders and decoders that would
/// otherwise each count them.
pub mod offset {
    pub const PURPOSE: usize = 0;
    pub const NAME_LEN: usize = 1;
    pub const CERT_COUNT: usize = 2;
    pub const UNIX_SECONDS: usize = 4;
    /// Where the name begins; certificates follow it.
    pub const NAME: usize = 12;
}

/// Size of the trailing `*_out` block the provider writes back.
pub const OUT_LEN: usize = 4;
