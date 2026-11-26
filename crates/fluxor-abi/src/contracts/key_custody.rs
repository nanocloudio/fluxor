// Contract: key_custody — P-256 keys held by a host-side token, behind a
// process the kernel reaches through a host lane.
//
// Layer: contracts (public, stable).
//
// The key vault's hardware custody. A `key_custody` provider holds keys the
// caller can never read: it generates them, signs and agrees with them,
// reads their public halves, finds a persisted one again by name and
// destroys them. P-256 only. On Linux the provider is a host process
// (`fluxor-provider-hsm`, a PKCS#11 token) served through `host_lane
// serves = "key_custody"`; the caller is the key vault, which claims the
// contract (`[[resources]] requires_contract = "key_custody"`).
//
// ## Call shape
//
// Every op is one flat `arg` record, little-endian and tightly packed; no
// op takes a `data` span. Inputs sit at the head of `arg` and the answer is
// written back over `arg` from byte 0, so a caller sizes `arg` to the
// larger of the two (each layout's `ARG_LEN`). Lengths are in-band: a
// variable input carries its own length byte. A short `arg` is `ERANGE`
// and nothing is made or consumed.
//
// | op | handle | arg in | arg out | returns |
// |---|---|---|---|---|
// | `GENERATE` | -1 | `[ns:u32][usage:u32][label_len:u8][label]` | `[pub:65]` | a new key's handle |
// | `SIGN` | key | `[digest_len:u8][digest]` | `[sig:64]` (`r‖s`, low-s) | 64 |
// | `ECDH` | key | `[peer_len:u8][peer:64 or 65]` | `[secret:32]` (the shared X) | 32 |
// | `PUBLIC` | key | — | `[pub:65]` (SEC1 uncompressed) | 65 |
// | `FIND` | -1 | `[ns:u32][label_len:u8][label]` | `[usage:u32][persisted:u8][pub:65]` | the key's handle |
// | `DESTROY` | key | `[flags:u8]` (or empty) | — | 0 |
//
// ## Names and persistence
//
// `ns` is the caller's namespace — the key vault's label namespace for the
// module it serves — carried in the request because a provider process
// cannot see module identity. A key is named by `(ns, label)`; an empty
// label names nothing. `usage` is the vault's mask
// ([`super::key_vault::usage`]), sealed into the key at `GENERATE` and
// checked on every op: `SIGN` needs `usage::SIGN`, `ECDH` `usage::AGREE`,
// `PUBLIC` `usage::EXPORT_PUBLIC`.
//
// A labelled key generated with `usage::PERSIST` is held by the token
// itself and comes back to `FIND` from any later provider process; one
// without it lives as long as the provider process and is found only by
// that process. An unlabelled key is never persisted. `GENERATE` of a
// label that already names a key is `EEXIST`: "find it, else make it" is
// two calls, and the caller holds the order.
//
// `DESTROY` frees a handle: an unpersisted key goes with it, a persisted
// one stays on the token for the next `FIND`. With [`destroy::REMOVE`] it
// also removes every object the token files under the key's name and
// retires every other handle open on it, so the key does not come back.
// Removing a key by name is `FIND` then `DESTROY` with `REMOVE`: a handle
// is the one thing an op that closes may name.
//
// ## Callers
//
// A handle is its minting caller's: another caller naming it is `EACCES`.
// The provider frees the keys of a caller that is gone when the lane tells
// it so. Signatures are random-k on a token: verify them, do not
// byte-compare.
//
// ## Errors
//
// `EINVAL` a malformed record (a label over [`MAX_LABEL`], a usage outside
// [`USAGE`], `PERSIST` without a label, a digest of 0 or over
// [`DIGEST_MAX`] bytes, a peer key that is not a point); `EACCES` a use the
// key was not born with, or another caller's handle; `ENOENT` a handle or
// name that holds nothing; `EEXIST` a `GENERATE` of a name in use;
// `ENOMEM` every slot the provider holds is in use; `ERANGE` a short
// `arg`; `ERROR` the token refused.
//
// ## On a host lane
//
// A call crosses the lane as a `KeyCustodyCall` record and its answer comes
// back as a `KeyCustodyAnswer` record ([`CALL_CONTENT_TYPE`],
// [`ANSWER_CONTENT_TYPE`]); a provider states both in its `HELLO`. Every
// call is resumable by the key-vault rule: a call that is not answered
// within the lane's short wait answers `EAGAIN`, and the identical repeat
// collects the answer.

use super::key_vault::usage as kv_usage;

/// Free a handle, and with [`destroy::REMOVE`] remove its key. handle =
/// the key. arg in [`destroy`].
pub use super::super::registry::key_custody::DESTROY;
/// Agree a shared secret. handle = the key. arg inout [`ecdh`].
pub use super::super::registry::key_custody::ECDH;
/// Find a key by name. handle = -1. arg inout [`find`].
pub use super::super::registry::key_custody::FIND;
/// Generate a P-256 key. handle = -1. arg inout [`generate`].
pub use super::super::registry::key_custody::GENERATE;
/// The key's public half. handle = the key. arg out [`public`].
pub use super::super::registry::key_custody::PUBLIC;
/// Sign a digest. handle = the key. arg inout [`sign`].
pub use super::super::registry::key_custody::SIGN;

/// Longest label: the key vault's.
pub const MAX_LABEL: usize = super::key_vault::MAX_LABEL;
/// A SEC1 uncompressed P-256 point.
pub const PUB_LEN: usize = 65;
/// A raw `r‖s` P-256 signature.
pub const SIG_LEN: usize = 64;
/// The P-256 shared secret (the X coordinate).
pub const SECRET_LEN: usize = 32;
/// Most bytes a digest may hold.
pub const DIGEST_MAX: usize = super::key_vault::sign::DIGEST_MAX;

/// The uses a custody key may be born with.
pub const USAGE: u32 = kv_usage::SIGN
    | kv_usage::VERIFY
    | kv_usage::AGREE
    | kv_usage::EXPORT_PUBLIC
    | kv_usage::PERSIST;

/// The longest `arg` any op takes.
pub const ARG_MAX: usize = generate::ARG_LEN;

/// The lane channel a call crosses on.
pub const CALL_CONTENT_TYPE: &[u8] = b"KeyCustodyCall";
/// The lane channel an answer crosses on.
pub const ANSWER_CONTENT_TYPE: &[u8] = b"KeyCustodyAnswer";

fn rd32(b: &[u8], at: usize) -> Option<u32> {
    match b.get(at..at.checked_add(4)?)? {
        &[a, b2, c, d] => Some(u32::from_le_bytes([a, b2, c, d])),
        _ => None,
    }
}

/// [`DESTROY`]: in `[flags:u8]`; an empty `arg` is no flags.
pub mod destroy {
    pub const ARG_LEN: usize = 1;
    /// Remove the key from the token as well, and retire every other
    /// handle open on its name.
    pub const REMOVE: u8 = 1 << 0;

    /// The flags; `None` for a flag this layout does not define.
    pub fn parse(arg: &[u8]) -> Option<u8> {
        let f = arg.first().copied().unwrap_or(0);
        (f & !REMOVE == 0).then_some(f)
    }
}

/// A `(ns, label)` name at the head of `arg`: `[ns:u32][label_len:u8][label]`.
pub mod name {
    /// Bytes before the label.
    pub const HEADER: usize = 5;
    /// The longest name record.
    pub const ARG_LEN: usize = HEADER + super::MAX_LABEL;

    /// `(ns, label)`; `None` for a short record or a label over
    /// [`super::MAX_LABEL`].
    pub fn parse(arg: &[u8]) -> Option<(u32, &[u8])> {
        let ns = super::rd32(arg, 0)?;
        let n = *arg.get(4)? as usize;
        if n > super::MAX_LABEL {
            return None;
        }
        Some((ns, arg.get(HEADER..HEADER + n)?))
    }

    /// Write the record into `out`; its length, or `None` when it does not
    /// fit or the label is too long.
    pub fn encode(ns: u32, label: &[u8], out: &mut [u8]) -> Option<usize> {
        if label.len() > super::MAX_LABEL {
            return None;
        }
        let total = HEADER + label.len();
        let dst = out.get_mut(..total)?;
        let (head, tail) = dst.split_at_mut(HEADER);
        for (d, s) in head.iter_mut().zip(ns.to_le_bytes()) {
            *d = s;
        }
        if let Some(b) = head.get_mut(4) {
            *b = label.len() as u8;
        }
        for (d, s) in tail.iter_mut().zip(label) {
            *d = *s;
        }
        Some(total)
    }
}

/// [`GENERATE`]: in `[ns:u32][usage:u32][label_len:u8][label]`, out
/// `[pub:65]`.
pub mod generate {
    /// Bytes before the label.
    pub const HEADER: usize = 9;
    /// What a caller sizes `arg` to: the longest request (the answer is
    /// shorter).
    pub const ARG_LEN: usize = HEADER + super::MAX_LABEL;

    /// A parsed request.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Request<'a> {
        pub ns: u32,
        pub usage: u32,
        pub label: &'a [u8],
    }

    pub fn parse(arg: &[u8]) -> Option<Request<'_>> {
        let ns = super::rd32(arg, 0)?;
        let usage = super::rd32(arg, 4)?;
        let n = *arg.get(8)? as usize;
        if n > super::MAX_LABEL {
            return None;
        }
        Some(Request {
            ns,
            usage,
            label: arg.get(HEADER..HEADER + n)?,
        })
    }

    /// Write the request into `out`; its length, or `None` when it does
    /// not fit or the label is too long.
    pub fn encode(ns: u32, usage: u32, label: &[u8], out: &mut [u8]) -> Option<usize> {
        if label.len() > super::MAX_LABEL {
            return None;
        }
        let total = HEADER + label.len();
        let dst = out.get_mut(..total)?;
        let (head, tail) = dst.split_at_mut(HEADER);
        let mut fixed = [0u8; HEADER];
        let (a, b) = fixed.split_at_mut(4);
        for (d, s) in a.iter_mut().zip(ns.to_le_bytes()) {
            *d = s;
        }
        for (d, s) in b.iter_mut().zip(usage.to_le_bytes()) {
            *d = s;
        }
        if let Some(l) = fixed.get_mut(8) {
            *l = label.len() as u8;
        }
        head.copy_from_slice(&fixed);
        for (d, s) in tail.iter_mut().zip(label) {
            *d = *s;
        }
        Some(total)
    }

    /// Whether a request's `usage` is one a custody key may be born with:
    /// some use, nothing outside [`super::USAGE`], and `PERSIST` only on a
    /// labelled key.
    pub fn usage_ok(r: &Request<'_>) -> bool {
        r.usage != 0
            && r.usage & !super::USAGE == 0
            && (r.usage & super::super::key_vault::usage::PERSIST == 0 || !r.label.is_empty())
    }
}

/// [`SIGN`]: in `[digest_len:u8][digest]`, out `[sig:64]`.
pub mod sign {
    pub const ARG_LEN: usize = 1 + super::DIGEST_MAX;

    /// The digest; `None` for an empty one or one over
    /// [`super::DIGEST_MAX`].
    pub fn parse(arg: &[u8]) -> Option<&[u8]> {
        let n = *arg.first()? as usize;
        if n == 0 || n > super::DIGEST_MAX {
            return None;
        }
        arg.get(1..1 + n)
    }

    pub fn encode(digest: &[u8], out: &mut [u8]) -> Option<usize> {
        if digest.is_empty() || digest.len() > super::DIGEST_MAX {
            return None;
        }
        let dst = out.get_mut(..1 + digest.len())?;
        let (h, t) = dst.split_at_mut(1);
        h[0] = digest.len() as u8;
        t.copy_from_slice(digest);
        Some(1 + digest.len())
    }
}

/// [`ECDH`]: in `[peer_len:u8][peer]` (65 bytes with its `0x04`, or the bare
/// 64-byte `X‖Y`), out `[secret:32]`.
pub mod ecdh {
    pub const ARG_LEN: usize = 1 + super::PUB_LEN;

    /// The peer point as given; `None` unless it is 64 or 65 bytes.
    pub fn parse(arg: &[u8]) -> Option<&[u8]> {
        let n = *arg.first()? as usize;
        if n != super::PUB_LEN && n != super::PUB_LEN - 1 {
            return None;
        }
        arg.get(1..1 + n)
    }

    pub fn encode(peer: &[u8], out: &mut [u8]) -> Option<usize> {
        if peer.len() != super::PUB_LEN && peer.len() != super::PUB_LEN - 1 {
            return None;
        }
        let dst = out.get_mut(..1 + peer.len())?;
        let (h, t) = dst.split_at_mut(1);
        h[0] = peer.len() as u8;
        t.copy_from_slice(peer);
        Some(1 + peer.len())
    }
}

/// [`PUBLIC`]: out `[pub:65]`.
pub mod public {
    pub const ARG_LEN: usize = super::PUB_LEN;
}

/// [`FIND`]: in a [`super::name`] record, out
/// `[usage:u32][persisted:u8][pub:65]`.
pub mod find {
    /// The answer's length.
    pub const OUT_LEN: usize = 5 + super::PUB_LEN;
    /// What a caller sizes `arg` to.
    pub const ARG_LEN: usize = OUT_LEN;

    /// A found key's facts.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Found {
        pub usage: u32,
        pub persisted: bool,
        pub public: [u8; super::PUB_LEN],
    }

    pub fn encode_found(f: &Found, out: &mut [u8]) -> Option<usize> {
        let dst = out.get_mut(..OUT_LEN)?;
        let (h, p) = dst.split_at_mut(5);
        for (d, s) in h.iter_mut().zip(f.usage.to_le_bytes()) {
            *d = s;
        }
        h[4] = u8::from(f.persisted);
        p.copy_from_slice(&f.public);
        Some(OUT_LEN)
    }

    pub fn parse_found(arg: &[u8]) -> Option<Found> {
        let usage = super::rd32(arg, 0)?;
        let persisted = *arg.get(4)? != 0;
        let mut public = [0u8; super::PUB_LEN];
        public.copy_from_slice(arg.get(5..OUT_LEN)?);
        Some(Found {
            usage,
            persisted,
            public,
        })
    }
}
