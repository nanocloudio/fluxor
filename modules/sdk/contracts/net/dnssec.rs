// DNSSEC validation: the signatures, the keys, and the link to the parent.
//
// Layer: contracts (portable wire vocabulary), shared by any module that
// validates. Kept beside `dns_wire.rs` because it is the same wire format
// one layer up.
//
// What this answers is a narrower question than "is this answer true": it is
// whether the bytes in an RRset are the bytes the zone's key signed, and
// whether that key is the one its parent vouched for. It has no opinion
// about what a resolver should DO with a failure — that policy belongs to
// the caller, and every function here returns a verdict rather than acting
// on one.
//
// The rule that matters everywhere below: nothing here answers `Secure`
// until a signature has actually verified against a key the caller trusts.
// Anything unproven is `Insecure`, `Bogus` or `Indeterminate`, never
// `Secure` by omission. A validator that fails open is worse than no
// validator, because it produces the same log lines as one that works.
//
// What this file does NOT do, and what a caller therefore owes: it verifies
// one RRSIG against one DNSKEY and matches one DS against one DNSKEY. It
// does not walk a chain from an anchor, does not check that an RRSIG's
// signer is the RRset owner's zone or an ancestor of it (RFC 4035 §5.3.1),
// and does not prove denial of existence or a wildcard expansion (RFC 4035
// §5.3.4, §5.4). A caller that skips any of those has a verifier, not a
// validator, and must not call the result `Secure`.

/// Record types DNSSEC adds (RFC 4034 §2–4, RFC 5155).
pub const TYPE_DS: u16 = 43;
pub const TYPE_RRSIG: u16 = 46;
pub const TYPE_NSEC: u16 = 47;
pub const TYPE_DNSKEY: u16 = 48;
pub const TYPE_NSEC3: u16 = 50;

/// DNSKEY flags (RFC 4034 §2.1.1).
///
/// ZONE must be set for a key that signs zone data at all; SEP marks the
/// key a parent's DS points at. SEP is a HINT and not a rule — a validator
/// that required it would reject a zone that signs everything with one key,
/// which is legal — so it is never used to decide anything here.
pub const DNSKEY_FLAG_ZONE: u16 = 0x0100;
pub const DNSKEY_FLAG_SEP: u16 = 0x0001;

/// Signing algorithms (RFC 8624 §3.1), limited to those with a verifier
/// here. An algorithm outside this set is not a weaker answer, it is an
/// unvalidatable one: [`Verdict::Indeterminate`].
/// RSA/SHA-1. Named so a caller can recognise it; NOT verified here.
/// RFC 8624 §3.1 marks it MUST NOT for signing and lets a validator refuse
/// it, and this one does: [`verify_rrsig_with_key`] answers false for it, so
/// it can never be Secure. Which non-Secure verdict a caller draws from that
/// false is the caller's, and a caller that cannot tell a missing verifier
/// from a broken signature will report it as [`Verdict::Bogus`].
pub const ALG_RSASHA1: u8 = 5;
/// RSA/SHA-256 — the RSA algorithm this validator verifies.
pub const ALG_RSASHA256: u8 = 8;
/// RSA/SHA-512. Named, not verified: RFC 8624 marks it NOT RECOMMENDED,
/// and the PKCS#1 checker this shares with `tls` carries SHA-256 and
/// SHA-384 DigestInfo prefixes only. Extending a security-critical
/// primitive for an algorithm the RFC discourages is the wrong trade, so
/// an answer signed with it never verifies.
pub const ALG_RSASHA512: u8 = 10;
pub const ALG_ECDSAP256SHA256: u8 = 13;
pub const ALG_ECDSAP384SHA384: u8 = 14;
pub const ALG_ED25519: u8 = 15;

/// DS digest algorithms (RFC 4509, RFC 6605).
pub const DIGEST_SHA1: u8 = 1;
pub const DIGEST_SHA256: u8 = 2;
pub const DIGEST_SHA384: u8 = 4;

/// What validation concluded. The four are RFC 4035 §4.3's, and the
/// distinction between the last two is the one that matters operationally:
/// `Bogus` is an answer that claims protection and fails it, which is an
/// attack or a broken zone; `Indeterminate` is an answer this validator
/// cannot speak about at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Signed, and the signature verified to a configured anchor.
    Secure,
    /// Provably unsigned — the parent says this zone has no DS. Proving
    /// that needs the parent's denial, so nothing in this file answers it;
    /// only a caller that walks the delegation can.
    Insecure,
    /// Signed and the signature did NOT verify, or is missing where one
    /// was promised.
    Bogus,
    /// Not enough was seen to say, or the algorithm has no verifier here.
    Indeterminate,
}

/// The fixed part of an RRSIG's RDATA (RFC 4034 §3.1), with the signer's
/// name already decompressed.
#[derive(Clone, Copy)]
pub struct RrsigView {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub sig_expiration: u32,
    pub sig_inception: u32,
    pub key_tag: u16,
    /// Offset of the signer's name within the packet.
    pub signer_off: usize,
    /// Offset and length of the signature itself.
    pub signature_off: usize,
    pub signature_len: usize,
}

/// Compression-pointer hops followed while reading one name.
const MAX_POINTER_HOPS: u32 = 16;

/// Bytes of an RRSIG RDATA before the signer's name.
const RRSIG_FIXED: usize = 18;

/// Parse the fixed fields of an RRSIG RDATA at `rdata_off`.
///
/// # Safety
/// `pkt` is valid for `pkt_len` bytes. `rdata_off + rdlen` is checked
/// against `pkt_len` here rather than assumed.
pub unsafe fn parse_rrsig(
    pkt: *const u8,
    pkt_len: usize,
    rdata_off: usize,
    rdlen: usize,
) -> Option<RrsigView> {
    if rdlen < RRSIG_FIXED + 1 || rdata_off + rdlen > pkt_len {
        return None;
    }
    let at = |i: usize| -> u8 { *pkt.add(rdata_off + i) };
    let be16 = |i: usize| -> u16 { u16::from_be_bytes([at(i), at(i + 1)]) };
    let be32 = |i: usize| -> u32 { u32::from_be_bytes([at(i), at(i + 1), at(i + 2), at(i + 3)]) };
    // The signer's name follows the fixed fields. It is NOT compressed in
    // an RRSIG (RFC 4034 §3.1.7), so its length is its wire length.
    let signer_off = rdata_off + RRSIG_FIXED;
    let signer_len = wire_name_len(pkt, pkt_len, signer_off)?;
    if RRSIG_FIXED + signer_len > rdlen {
        return None;
    }
    Some(RrsigView {
        type_covered: be16(0),
        algorithm: at(2),
        labels: at(3),
        original_ttl: be32(4),
        sig_expiration: be32(8),
        sig_inception: be32(12),
        key_tag: be16(16),
        signer_off,
        signature_off: signer_off + signer_len,
        signature_len: rdlen - RRSIG_FIXED - signer_len,
    })
}

/// Length of an uncompressed wire-format name at `off`, including the root
/// label. `None` for a compression pointer, which these fields may not use.
///
/// # Safety
/// `pkt` is valid for `pkt_len` bytes.
pub unsafe fn wire_name_len(pkt: *const u8, pkt_len: usize, off: usize) -> Option<usize> {
    let mut at = off;
    let mut total = 0usize;
    loop {
        if at >= pkt_len {
            return None;
        }
        let len = *pkt.add(at) as usize;
        if len & 0xC0 != 0 {
            // A pointer where the format forbids one.
            return None;
        }
        total += 1;
        at += 1;
        if len == 0 {
            return Some(total);
        }
        if len > 63 || at + len > pkt_len {
            return None;
        }
        total += len;
        at += len;
        if total > 255 {
            return None;
        }
    }
}

/// The key tag of a DNSKEY's RDATA (RFC 4034 Appendix B).
///
/// A tag is a checksum and NOT an identifier: two keys in one zone may share
/// one, so a caller must try every key whose tag matches rather than the
/// first.
pub fn key_tag(rdata: &[u8]) -> u16 {
    // Algorithm 1 (RSA/MD5) had its own rule; it has no verifier here and
    // its tag is never needed.
    let mut acc: u32 = 0;
    let mut i = 0usize;
    while i < rdata.len() {
        let v = u32::from(rdata[i]);
        acc += if i & 1 == 0 { v << 8 } else { v };
        i += 1;
    }
    acc += (acc >> 16) & 0xFFFF;
    (acc & 0xFFFF) as u16
}

/// Write `name` (wire format, at `off`) in canonical form — every ASCII
/// letter lowercased, no compression — into `out`. Answers the length.
///
/// # Safety
/// `pkt` is valid for `pkt_len` bytes.
pub unsafe fn canonical_name(
    pkt: *const u8,
    pkt_len: usize,
    off: usize,
    out: &mut [u8],
) -> Option<usize> {
    let mut at = off;
    let mut written = 0usize;
    // Compression pointers ARE followed here. An owner name in a real
    // answer is almost always a pointer to the question — refusing one
    // means never building the signed form for any answer that came off a
    // wire, which is every answer. Where the format forbids a pointer, it
    // is `wire_name_len` that says so, and an RRSIG's signer is checked by
    // it before this is reached.
    let mut hops = 0u32;
    loop {
        if at >= pkt_len {
            return None;
        }
        let len = *pkt.add(at) as usize;
        if len & 0xC0 == 0xC0 {
            if at + 1 >= pkt_len {
                return None;
            }
            hops += 1;
            // A bound on hops is what stops a packet that points at itself.
            if hops > MAX_POINTER_HOPS {
                return None;
            }
            let target = ((len & 0x3F) << 8) | *pkt.add(at + 1) as usize;
            // A pointer must go BACKWARDS; forwards is how a loop is built
            // that the hop count alone would take a while to notice.
            if target >= at {
                return None;
            }
            at = target;
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        if written >= out.len() {
            return None;
        }
        out[written] = len as u8;
        written += 1;
        at += 1;
        if len == 0 {
            return Some(written);
        }
        if len > 63 || at + len > pkt_len || written + len > out.len() {
            return None;
        }
        let mut i = 0usize;
        while i < len {
            out[written + i] = (*pkt.add(at + i)).to_ascii_lowercase();
            i += 1;
        }
        written += len;
        at += len;
    }
}

/// Is `unix_seconds` inside the signature's validity window?
///
/// The fields are seconds since the epoch in a 32-bit field, so RFC 4034
/// §3.1.5 defines them with serial-number arithmetic: a comparison is about
/// which side of the circle a value falls on, not which integer is larger.
/// Plain `<=` breaks in 2106 and, more immediately, on any zone whose
/// inception is set before an epoch rollover.
pub fn signature_time_ok(now: u32, inception: u32, expiration: u32) -> bool {
    serial_ge(now, inception) && serial_ge(expiration, now)
}

/// RFC 1982 serial comparison: `a >= b` on the 32-bit circle.
fn serial_ge(a: u32, b: u32) -> bool {
    a.wrapping_sub(b) < 0x8000_0000
}

/// One record of an RRset, as the canonical form needs it: the RDATA and
/// nothing else, because owner, class and type are the same for every member
/// and the TTL is replaced by the signature's original TTL.
#[derive(Clone, Copy)]
pub struct RrsetMember {
    pub rdata_off: usize,
    pub rdlen: usize,
}

/// Build the byte string an RRSIG signs (RFC 4035 §5.3.2):
///
/// ```text
/// RRSIG_RDATA (fixed fields + signer, no signature)
/// | (owner | type | class | original_ttl | rdlen | rdata) sorted
/// ```
///
/// The owner written is the canonical one, and for a wildcard-expanded RRset
/// (`labels` fewer than the owner has) it is the wildcard rather than the
/// name that was asked for — which is the point of the `labels` field. A
/// `labels` larger than the owner carries is malformed (RFC 4035 §5.3.1);
/// it is not rejected here, it simply signs the owner as given and so
/// cannot verify. Signing the wildcard form is only half of accepting a
/// wildcard answer: RFC 4035 §5.3.4 also wants the NSEC/NSEC3 proof that
/// the queried name itself does not exist, which is the caller's to obtain.
///
/// RDATA containing embedded names would need those lowercased too for the
/// types RFC 4034 §6.2 lists. This builder does NOT do that, so it is
/// correct only for types whose RDATA carries no name — A, AAAA, DS,
/// DNSKEY, TXT among them — and a caller must not offer it one of the
/// others. `rdata_needs_name_lowering` is the guard.
///
/// # Safety
/// `pkt` is valid for `pkt_len` bytes and every member's extent is inside it.
#[allow(
    clippy::too_many_arguments,
    reason = "the signed form is exactly these fields"
)]
pub unsafe fn rrsig_signed_data(
    pkt: *const u8,
    pkt_len: usize,
    rrsig_rdata_off: usize,
    sig: &RrsigView,
    owner_off: usize,
    rtype: u16,
    rclass: u16,
    members: &[RrsetMember],
    out: &mut [u8],
) -> Option<usize> {
    let mut at = 0usize;
    // The RRSIG RDATA up to but NOT including the signature.
    let head = sig.signature_off - rrsig_rdata_off;
    if head > out.len() {
        return None;
    }
    let mut i = 0usize;
    while i < head {
        out[i] = *pkt.add(rrsig_rdata_off + i);
        i += 1;
    }
    // The signer's name inside that copy is canonicalised in place: it is
    // part of the signed data and must be lowercase.
    let signer_rel = sig.signer_off - rrsig_rdata_off;
    let mut tmp = [0u8; 256];
    let signer_len = canonical_name(pkt, pkt_len, sig.signer_off, &mut tmp)?;
    if signer_rel + signer_len > head {
        return None;
    }
    out[signer_rel..signer_rel + signer_len].copy_from_slice(&tmp[..signer_len]);
    at += head;

    // The owner, canonical, and wildcard-collapsed when the signature says
    // the RRset was expanded from one.
    let mut owner = [0u8; 256];
    let owner_len = canonical_name(pkt, pkt_len, owner_off, &mut owner)?;
    let owner_labels = count_labels(&owner[..owner_len]);
    let mut owner_use = [0u8; 256];
    let owner_use_len = if u16::from(sig.labels) < owner_labels {
        // `*.` followed by the last `labels` labels.
        let start = skip_labels(&owner[..owner_len], owner_labels - u16::from(sig.labels))?;
        owner_use[0] = 1;
        owner_use[1] = b'*';
        let rest = owner_len - start;
        if 2 + rest > owner_use.len() {
            return None;
        }
        owner_use[2..2 + rest].copy_from_slice(&owner[start..owner_len]);
        2 + rest
    } else {
        owner_use[..owner_len].copy_from_slice(&owner[..owner_len]);
        owner_len
    };

    // Members in canonical order: by RDATA, compared as unsigned octets
    // (RFC 4034 §6.3). Sorted by index so the packet is never rewritten.
    let mut order = [0usize; MAX_RRSET];
    let count = members.len().min(MAX_RRSET);
    let mut n = 0usize;
    while n < count {
        order[n] = n;
        n += 1;
    }
    let mut a = 1usize;
    while a < count {
        let key = order[a];
        let mut b = a;
        while b > 0 && rdata_greater(pkt, &members[order[b - 1]], &members[key]) {
            order[b] = order[b - 1];
            b -= 1;
        }
        order[b] = key;
        a += 1;
    }

    let mut k = 0usize;
    while k < count {
        let m = members[order[k]];
        let need = owner_use_len + 2 + 2 + 4 + 2 + m.rdlen;
        if at + need > out.len() {
            return None;
        }
        out[at..at + owner_use_len].copy_from_slice(&owner_use[..owner_use_len]);
        at += owner_use_len;
        out[at..at + 2].copy_from_slice(&rtype.to_be_bytes());
        at += 2;
        out[at..at + 2].copy_from_slice(&rclass.to_be_bytes());
        at += 2;
        // The signature's original TTL, NOT the one on the wire: a cache
        // decrements the latter and the signature would stop verifying.
        out[at..at + 4].copy_from_slice(&sig.original_ttl.to_be_bytes());
        at += 4;
        out[at..at + 2].copy_from_slice(&(m.rdlen as u16).to_be_bytes());
        at += 2;
        let mut j = 0usize;
        while j < m.rdlen {
            out[at + j] = *pkt.add(m.rdata_off + j);
            j += 1;
        }
        at += m.rdlen;
        k += 1;
    }
    Some(at)
}

/// Most records one RRset may carry through validation. A larger RRset
/// cannot have its signed form built here, so it cannot verify.
pub const MAX_RRSET: usize = 16;

/// Whether the RDATA of `a` sorts after `b`, unsigned octet order with the
/// shorter being smaller on a prefix (RFC 4034 §6.3).
unsafe fn rdata_greater(pkt: *const u8, a: &RrsetMember, b: &RrsetMember) -> bool {
    let n = a.rdlen.min(b.rdlen);
    let mut i = 0usize;
    while i < n {
        let x = *pkt.add(a.rdata_off + i);
        let y = *pkt.add(b.rdata_off + i);
        if x != y {
            return x > y;
        }
        i += 1;
    }
    a.rdlen > b.rdlen
}

/// Labels in a canonical wire name, the root not counted.
fn count_labels(name: &[u8]) -> u16 {
    let mut at = 0usize;
    let mut n = 0u16;
    while at < name.len() {
        let len = name[at] as usize;
        if len == 0 {
            break;
        }
        n += 1;
        at += 1 + len;
    }
    n
}

/// Offset of the name that remains after dropping `drop` leading labels.
fn skip_labels(name: &[u8], drop: u16) -> Option<usize> {
    let mut at = 0usize;
    let mut left = drop;
    while left > 0 {
        if at >= name.len() {
            return None;
        }
        let len = name[at] as usize;
        if len == 0 {
            return None;
        }
        at += 1 + len;
        left -= 1;
    }
    Some(at)
}

/// Whether a type's RDATA carries embedded names that RFC 4034 §6.2
/// requires lowercased before signing.
///
/// [`rrsig_signed_data`] does not lower them, so it must not be offered one
/// of these. Answering conservatively — anything not known to be
/// name-free — keeps a future type from being validated with the wrong
/// bytes and reported Secure.
pub fn rdata_needs_name_lowering(rtype: u16) -> bool {
    !matches!(
        rtype,
        1        // A
        | 28     // AAAA
        | 16     // TXT
        | 43     // DS
        | 48     // DNSKEY
        | 47     // NSEC -- next name is NOT lowered (RFC 6840 §5.1)
        | 50     // NSEC3
        | 13     // HINFO
        | 52 // TLSA
    )
}

/// Verify one RRSIG against one DNSKEY.
///
/// `signed` is what [`rrsig_signed_data`] produced. The DNSKEY's RDATA is
/// `key_rdata`; its public key begins after the four fixed bytes. The
/// key's own flags and protocol are not read here — whether a key is
/// allowed to sign this zone is a trust question, and trust is the
/// caller's.
///
/// False is the answer to a signature that did not verify AND to an
/// algorithm with no verifier in this build; the two are not distinguished
/// in the return, so a caller that wants to report Indeterminate for the
/// second must test the algorithm itself.
pub fn verify_rrsig_with_key(
    algorithm: u8,
    key_rdata: &[u8],
    signed: &[u8],
    signature: &[u8],
) -> bool {
    if key_rdata.len() < 5 {
        return false;
    }
    let key = &key_rdata[4..];
    match algorithm {
        ALG_ECDSAP256SHA256 => {
            // RFC 6605: the key is the raw 64-byte point, the signature raw
            // r||s. The verifier wants an uncompressed point.
            if key.len() != 64 || signature.len() != 64 {
                return false;
            }
            let mut point = [0u8; 65];
            point[0] = 0x04;
            point[1..].copy_from_slice(key);
            let digest = sha256(signed);
            ecdsa_verify(&point, &digest, signature)
        }
        ALG_ECDSAP384SHA384 => {
            if key.len() != 96 || signature.len() != 96 {
                return false;
            }
            let mut point = [0u8; 97];
            point[0] = 0x04;
            point[1..].copy_from_slice(key);
            let digest = sha384(signed);
            ecdsa384_verify(&point, &digest, signature)
        }
        ALG_ED25519 => {
            if key.len() != 32 || signature.len() != 64 {
                return false;
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(key);
            let mut sig = [0u8; 64];
            sig.copy_from_slice(signature);
            ed25519_verify(&pk, signed, &sig)
        }
        ALG_RSASHA256 => verify_rsa(key, signed, signature),
        // No verifier: not a failure of the signature, a limit of this
        // build — and false either way, so never Secure.
        _ => false,
    }
}

/// RSA in DNSKEY form (RFC 3110): `[exp_len:u8][exponent][modulus]`, or
/// `[0][exp_len:u16][exponent][modulus]` when the exponent is long.
fn verify_rsa(key: &[u8], signed: &[u8], signature: &[u8]) -> bool {
    if key.is_empty() {
        return false;
    }
    let (exp_len, exp_at) = if key[0] == 0 {
        if key.len() < 3 {
            return false;
        }
        (usize::from(u16::from_be_bytes([key[1], key[2]])), 3)
    } else {
        (usize::from(key[0]), 1)
    };
    if exp_len == 0 || exp_len > 4 || exp_at + exp_len >= key.len() {
        return false;
    }
    let mut e: u32 = 0;
    let mut i = 0usize;
    while i < exp_len {
        e = (e << 8) | u32::from(key[exp_at + i]);
        i += 1;
    }
    let n = &key[exp_at + exp_len..];
    if n.is_empty() || signature.len() != n.len() {
        return false;
    }
    let digest = sha256(signed);
    let mut job = RsaVerifyJob::new();
    let mut em = [0u8; 512];
    let Some(len) = rsa_public_decrypt(&mut job, n, e, signature, &mut em) else {
        return false;
    };
    rsa_pkcs1_v15_check(RsaHash::Sha256, &digest, &em[..len])
}

/// Whether a DS record's digest matches a DNSKEY (RFC 4034 §5.1.4): the
/// digest is over the key's canonical owner followed by its RDATA.
///
/// # Safety
/// `pkt` is valid for `pkt_len` bytes.
pub unsafe fn ds_matches_key(
    pkt: *const u8,
    pkt_len: usize,
    ds_rdata: &[u8],
    key_owner_off: usize,
    key_rdata: &[u8],
) -> bool {
    if ds_rdata.len() < 4 {
        return false;
    }
    let ds_tag = u16::from_be_bytes([ds_rdata[0], ds_rdata[1]]);
    let ds_alg = ds_rdata[2];
    let ds_digest_alg = ds_rdata[3];
    let ds_digest = &ds_rdata[4..];
    if key_rdata.len() < 4 || key_rdata[3] != ds_alg || key_tag(key_rdata) != ds_tag {
        return false;
    }
    let mut owner = [0u8; 256];
    let Some(owner_len) = canonical_name(pkt, pkt_len, key_owner_off, &mut owner) else {
        return false;
    };
    let mut buf = [0u8; 256 + 1024];
    if owner_len + key_rdata.len() > buf.len() {
        return false;
    }
    buf[..owner_len].copy_from_slice(&owner[..owner_len]);
    buf[owner_len..owner_len + key_rdata.len()].copy_from_slice(key_rdata);
    let material = &buf[..owner_len + key_rdata.len()];
    match ds_digest_alg {
        DIGEST_SHA256 => ds_digest.len() == 32 && sha256(material)[..] == *ds_digest,
        DIGEST_SHA384 => ds_digest.len() == 48 && sha384(material)[..] == *ds_digest,
        // SHA-1 DS records are still published by some zones. Accepted for
        // the digest only, where a collision would have to be against a key
        // the parent already chose; the SIGNATURE algorithms above are
        // where SHA-1 actually matters and RSASHA1 is the one weak entry.
        DIGEST_SHA1 => ds_digest.len() == 20 && sha1(material)[..] == *ds_digest,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_tag_matches_the_appendix_b_arithmetic() {
        // A DNSKEY RDATA shaped like a real one — flags 256, protocol 3,
        // algorithm 5 — but with invented key bytes. This is NOT the RFC's
        // worked example and does not pin the RFC's published tag value.
        let mut rdata = vec![0x01, 0x00, 0x03, 0x05];
        rdata.extend_from_slice(&[
            0x01, 0x03, 0x8a, 0x2f, 0x5f, 0x7a, 0x1b, 0x5f, 0x2d, 0x4c, 0x1e, 0x9b, 0x3a, 0x6c,
        ]);
        // The tag of any octet string is well defined even when the key is
        // not a real one. What is asserted is the ARITHMETIC of RFC 4034
        // Appendix B, restated here independently of the implementation.
        let expect = {
            let mut acc: u32 = 0;
            for (i, b) in rdata.iter().enumerate() {
                acc += if i & 1 == 0 {
                    u32::from(*b) << 8
                } else {
                    u32::from(*b)
                };
            }
            acc += (acc >> 16) & 0xFFFF;
            (acc & 0xFFFF) as u16
        };
        assert_eq!(key_tag(&rdata), expect);
    }

    #[test]
    fn a_name_is_lowercased_and_length_preserved() {
        // `ExAmPlE.COM.` in wire form.
        let pkt: Vec<u8> = vec![
            7, b'E', b'x', b'A', b'm', b'P', b'l', b'E', 3, b'C', b'O', b'M', 0,
        ];
        let mut out = [0u8; 64];
        let n = unsafe { canonical_name(pkt.as_ptr(), pkt.len(), 0, &mut out) }.expect("canonical");
        assert_eq!(n, pkt.len());
        assert_eq!(&out[..n], b"\x07example\x03com\x00");
    }

    #[test]
    fn a_compression_pointer_is_followed_for_an_owner_and_refused_for_a_signer() {
        // `example.com.` at offset 0, and a pointer to it at offset 13.
        let mut pkt: Vec<u8> = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        pkt.push(0xC0);
        pkt.push(0x00);
        let mut out = [0u8; 32];
        // An owner name: followed, because every answer off a wire has one.
        let n = unsafe { canonical_name(pkt.as_ptr(), pkt.len(), 13, &mut out) }.expect("followed");
        assert_eq!(&out[..n], b"\x07example\x03com\x00");
        // A signer name: refused, because RFC 4034 §3.1.7 forbids one there.
        assert!(unsafe { wire_name_len(pkt.as_ptr(), pkt.len(), 13) }.is_none());
    }

    #[test]
    fn a_forward_pointer_is_refused() {
        // A pointer that goes forwards is how a loop is built.
        let pkt: Vec<u8> = vec![0xC0, 0x04, 0, 0, 0xC0, 0x00];
        let mut out = [0u8; 16];
        assert!(unsafe { canonical_name(pkt.as_ptr(), pkt.len(), 0, &mut out) }.is_none());
    }

    #[test]
    fn validity_uses_serial_arithmetic_and_not_plain_ordering() {
        // An ordinary window.
        assert!(signature_time_ok(1000, 500, 1500));
        assert!(!signature_time_ok(2000, 500, 1500));
        assert!(!signature_time_ok(100, 500, 1500));
        // A window that straddles the 32-bit rollover: inception late in
        // the circle, expiration early. Plain `<=` calls this expired for
        // every `now`, which would refuse every signature such a zone makes.
        let inception = u32::MAX - 100;
        let expiration = 100u32;
        assert!(signature_time_ok(u32::MAX - 50, inception, expiration));
        assert!(signature_time_ok(50, inception, expiration));
        assert!(!signature_time_ok(1000, inception, expiration));
    }
}
