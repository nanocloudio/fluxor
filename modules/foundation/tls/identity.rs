// A served identity whose key is born in the vault and whose certificate
// arrives at runtime.
//
// `identity_label` names a P-256 key the vault opens, or generates the first
// time (`OPEN_OR_GENERATE`, SIGN | EXPORT_PUBLIC | PERSIST). The private half
// never exists outside the vault: CertificateVerify signs through it exactly
// as a `key_file` identity deposited at construction does. What the graph
// cannot embed is the certificate, because the key did not exist when the
// graph was built — so the instance asks for one.
//
//   identity_req  out[4]  [0x5B][len:2 LE = 65][SEC1 uncompressed point]
//                         every ID_REQ_PERIOD_MS while uncertified, and again
//                         once two thirds of the certificate's lifetime have
//                         passed (the current one is served meanwhile)
//   identity_cert in[3]   [0x5C][len:2 LE][leaf DER ‖ issuer DER ‖ …]
//                         the chain presented to peers, leaf first
//
// Both ports carry net_proto-framed messages. A chain is read off
// `identity_cert` only once its whole frame is buffered, and a frame larger
// than the inbox is dropped whole, so the port never holds part of one.
//
// A chain is taken only when its leaf parses and certifies THIS key; any
// other is dropped and counted, so a confused or hostile issuer cannot make
// the instance present a certificate it cannot prove possession of. Under
// `trust_issuer` it must also be a certification path from the leaf up to
// its last certificate, which becomes a trust anchor. Until a
// chain is taken no handshake proceeds past the point where one would be
// presented: there is nothing honest to present.
//
// A vault that is not yet readable (`EAGAIN` while the node's store comes up)
// is retried; no key is generated in its place, since one generated now would
// be replaced by the persisted one later and every certificate for it lost.

const ID_MSG_REQ: u8 = 0x5B;
const ID_MSG_CERT: u8 = 0x5C;
/// Between certificate requests, and between vault retries after a refusal.
const ID_REQ_PERIOD_MS: u64 = 1000;
/// Between vault retries while the store is not yet readable.
const ID_OPEN_RETRY_MS: u64 = 100;
pub const IDENTITY_LABEL_MAX: usize = 64;
const ID_POINT_LEN: usize = 65;

/// No label: the identity, if any, came from `cert_file` / `key_file`.
const ID_NONE: u8 = 0;
/// The key is not open yet.
const ID_OPENING: u8 = 1;
/// The key is open; no certificate has been taken.
const ID_UNCERTIFIED: u8 = 2;
/// A certificate for the key is held and presented.
const ID_CERTIFIED: u8 = 3;

/// The label-held identity's state, embedded in `TlsState`.
struct LabelIdentity {
    label: [u8; IDENTITY_LABEL_MAX],
    label_len: u8,
    /// The label was longer than `IDENTITY_LABEL_MAX`; construction refuses.
    overflow: u8,
    state: u8,
    point: [u8; ID_POINT_LEN],
    /// `dev_millis` at which the next open attempt / request is due.
    next_at: u64,
    /// `dev_millis` after which the held certificate is renewed; 0 = never.
    renew_at: u64,
    /// Chains dropped because they did not certify this key or did not parse.
    refused: u32,
    /// Handshakes refused because no certificate was held yet.
    early: u32,
    /// `trust_issuer`: the held chain's issuer is also a trust anchor.
    trust_issuer: u8,
    /// Anchors the graph configured; an adopted issuer sits after them.
    static_anchors: u8,
    /// Bumped each time an issuer is written to the adopted slot. A walk
    /// records it with the anchor it chose (`DeferredLinks::generation`),
    /// so a link still stepping when a renewal writes over the slot fails
    /// cleanly instead of reading key bytes from a different anchor.
    adopted_generation: u32,
    /// One `identity_cert` frame: its net_proto header, then the chain.
    inbox: [u8; NET_FRAME_HDR + MAX_CERT_CHAIN_BYTES],
}

impl LabelIdentity {
    fn set_label(&mut self, d: &[u8]) {
        if d.len() > IDENTITY_LABEL_MAX {
            self.overflow = 1;
            return;
        }
        // SAFETY: d.len() <= IDENTITY_LABEL_MAX, checked above.
        unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), self.label.as_mut_ptr(), d.len()) };
        self.label_len = d.len() as u8;
    }
    fn configured(&self) -> bool {
        self.label_len > 0
    }
}

/// May a handshake present this instance's certificate now? Always, for a
/// file identity; for a label identity only once one is held.
fn identity_presentable(s: &TlsState) -> bool {
    s.label_id.state == ID_NONE || s.label_id.state == ID_CERTIFIED
}

/// Refuse a session that reached its Certificate with nothing to present.
/// Counted, and logged on the first and every 64th, so a client hammering a
/// node that is still coming up does not flood the log.
unsafe fn identity_refuse_early(s: &mut TlsState) {
    s.label_id.early = s.label_id.early.wrapping_add(1);
    if s.label_id.early & 63 == 1 {
        let sys = &*s.syscalls;
        let msg = b"[tls] identity not yet certified: handshake refused";
        dev_log(sys, 2, msg.as_ptr(), msg.len());
    }
}

/// `OPEN_OR_GENERATE` the label's key. True once open.
unsafe fn identity_open(s: &mut TlsState, now: u64) -> bool {
    let sys = &*s.syscalls;
    const USAGE: u32 = kv::usage::SIGN | kv::usage::EXPORT_PUBLIC | kv::usage::PERSIST;
    let n = (s.label_id.label_len as usize).min(IDENTITY_LABEL_MAX);
    let mut point = [0u8; ID_POINT_LEN];
    let mut arg = [0u8; 8 + IDENTITY_LABEL_MAX + 12];
    arg[0..2].copy_from_slice(&kv::suite::P256.to_le_bytes());
    arg[2..6].copy_from_slice(&USAGE.to_le_bytes());
    arg[7] = n as u8;
    let a = arg.as_mut_ptr();
    core::ptr::copy_nonoverlapping(s.label_id.label.as_ptr(), a.add(8), n);
    let tail = 8 + n;
    let pub_ptr = (point.as_mut_ptr() as u64).to_le_bytes();
    core::ptr::copy_nonoverlapping(pub_ptr.as_ptr(), a.add(tail), 8);
    let cap = (ID_POINT_LEN as u16).to_le_bytes();
    core::ptr::copy_nonoverlapping(cap.as_ptr(), a.add(tail + 8), 2);
    let rc = (sys.provider_call)(-1, kv::OPEN_OR_GENERATE, a, tail + 12);
    if rc == abi::errno::EAGAIN {
        s.label_id.next_at = now + ID_OPEN_RETRY_MS;
        return false;
    }
    let got = u16::from_le_bytes([*a.add(tail + 10), *a.add(tail + 11)]) as usize;
    if rc >= 0 && (got != ID_POINT_LEN || point[0] != 0x04) {
        // A key opened under the label that is not an uncompressed P-256
        // point is no use here; its slot is freed (the persisted key stays)
        // before the open is retried.
        (sys.provider_call)(rc, kv::DESTROY, core::ptr::null_mut(), 0);
    }
    if rc < 0 || got != ID_POINT_LEN || point[0] != 0x04 {
        // A refusal (another suite under the label, a vault without room) is
        // the operator's to fix; retried slowly so a fix takes without a
        // restart, and said once.
        if s.label_id.next_at == 0 {
            let msg = b"[tls] identity: the vault refused the label's P-256 key";
            dev_log(sys, 1, msg.as_ptr(), msg.len());
        }
        s.label_id.next_at = now + ID_REQ_PERIOD_MS;
        return false;
    }
    s.key_vault_handle = rc;
    s.label_id.point = point;
    s.label_id.state = ID_UNCERTIFIED;
    s.label_id.next_at = now;
    let msg = b"[tls] identity key open; requesting a certificate";
    dev_log(sys, 3, msg.as_ptr(), msg.len());
    true
}

/// Take a chain off `identity_cert` if it certifies this key.
unsafe fn identity_take_chain(s: &mut TlsState, now: u64) -> bool {
    let sys = &*s.syscalls;
    let port = s.identity_cert_in;
    let cap = s.label_id.inbox.len();
    let (msg_type, copied, pl) =
        net_read_frame_sized(sys, port, s.label_id.inbox.as_mut_ptr(), cap);
    if msg_type == 0 {
        return false;
    }
    if msg_type != ID_MSG_CERT || copied != pl || pl == 0 || s.label_id.state < ID_UNCERTIFIED {
        s.label_id.refused = s.label_id.refused.wrapping_add(1);
        return true;
    }
    let chain = core::slice::from_raw_parts(s.label_id.inbox.as_ptr().add(NET_FRAME_HDR), pl);
    let leaf_len = match der_tlv(chain, 0) {
        Some((_, _, consumed)) if consumed > 0 && consumed <= pl => consumed,
        _ => 0,
    };
    let leaf = parse_certificate(core::slice::from_raw_parts(chain.as_ptr(), leaf_len));
    let (ok, lifetime) = match leaf {
        Some(c) => (
            c.public_key == s.label_id.point,
            c.not_after.saturating_sub(c.not_before),
        ),
        None => (false, 0),
    };
    if !ok {
        s.label_id.refused = s.label_id.refused.wrapping_add(1);
        let msg = b"[tls] identity: dropped a chain that does not certify this key";
        dev_log(sys, 1, msg.as_ptr(), msg.len());
        return true;
    }
    if s.label_id.trust_issuer != 0 && !identity_adopt_issuer(s, chain) {
        s.label_id.refused = s.label_id.refused.wrapping_add(1);
        let msg = b"[tls] identity: dropped a chain that is not a path to an issuer that can be an anchor";
        dev_log(sys, 1, msg.as_ptr(), msg.len());
        return true;
    }
    core::ptr::copy_nonoverlapping(chain.as_ptr(), s.cert.as_mut_ptr(), pl);
    s.cert_len = pl;
    s.label_id.state = ID_CERTIFIED;
    // Renewed at two thirds of its lifetime, measured from now rather than
    // from notBefore: monotonic time needs no trusted clock.
    s.label_id.renew_at = if lifetime == 0 {
        0
    } else {
        now.saturating_add(lifetime.saturating_mul(2000) / 3)
    };
    let mut line = [0u8; 96];
    let l = line.as_mut_ptr();
    let mut w = id_put(l, 0, b"[tls] identity certified: chain ");
    w += fmt_u32_raw(l.add(w), pl as u32);
    w = id_put(l, w, b" bytes, renews in ");
    w += fmt_u32_raw(l.add(w), (lifetime * 2 / 3).min(u32::MAX as u64) as u32);
    w = id_put(l, w, b" s");
    dev_log(sys, 3, l, w);
    true
}

/// The span of the last certificate of `chain` (concatenated DER, leaf
/// first) when the chain is a certification path up to it, else `None`.
///
/// Each certificate must name the next as its issuer and carry that
/// issuer's signature, and every certificate above the leaf must be a CA
/// permitted to sign certificates within its path-length constraint (RFC
/// 5280 §4.2.1.3, §4.2.1.9) and no weaker than what it signs. Lifetimes are
/// left to the peers' walks, which judge the anchor's under their own clock
/// policy. The signatures are verified whole, within the step: a renewal
/// is rare and its chain is the node's own, short and of the issuer's suite.
fn identity_issuer_path(chain: &[u8]) -> Option<(usize, usize)> {
    let mut spans = [(0usize, 0usize); MAX_CHAIN_LEN];
    let (mut pos, mut count) = (0usize, 0usize);
    while pos < chain.len() {
        let (_, _, total) = der_tlv(chain, pos)?;
        if total == 0 || pos + total > chain.len() || count >= MAX_CHAIN_LEN {
            return None;
        }
        spans[count] = (pos, total);
        count += 1;
        pos += total;
    }
    if count < 2 {
        return None;
    }
    let mut i = 0;
    while i + 1 < count {
        let (sa, sl) = spans[i];
        let (ia, il) = spans[i + 1];
        let subject_der = &chain[sa..sa + sl];
        let issuer_der = &chain[ia..ia + il];
        let subject = parse_certificate(subject_der)?;
        let issuer = parse_certificate(issuer_der)?;
        if !der_bytes_eq(subject.issuer_raw, issuer.subject_raw)
            || check_ca_shape(&issuer, issuer_der, i) != CERT_OK
            || !suite::is_implemented(issuer.key_suite)
            || suite::is_downgrade(issuer.key_suite, subject.key_suite)
            || !verify_cert_signature(subject_der, issuer.key_suite, issuer.public_key)
        {
            return None;
        }
        i += 1;
    }
    Some(spans[count - 1])
}

/// `trust_issuer`: make the last certificate of `chain` (its issuer) the
/// trust anchor after the configured ones, replacing one an earlier chain
/// adopted. An authority minted at runtime — a node's own — is what the
/// instance's peers chain to, and the graph could not name it. False, and
/// nothing changed, unless the chain is a certification path from its leaf
/// up to that issuer ([`identity_issuer_path`]) and the issuer fits a slot.
unsafe fn identity_adopt_issuer(s: &mut TlsState, chain: &[u8]) -> bool {
    let Some((at, len)) = identity_issuer_path(chain) else {
        return false;
    };
    let base = s.label_id.static_anchors as usize;
    if len > MAX_CERT_LEN || base >= MAX_ANCHORS {
        return false;
    }
    let issuer = &chain[at..at + len];
    // A session still stepping links read from the slot fails them on the
    // generation, never on bytes of the replacement.
    s.label_id.adopted_generation = s.label_id.adopted_generation.wrapping_add(1);
    s.anchors[base][..len].copy_from_slice(issuer);
    s.anchor_lens[base] = len as u16;
    s.anchor_count = (base + 1) as u8;
    true
}

/// Ask for a certificate: the key's public point on `identity_req`.
unsafe fn identity_request(s: &mut TlsState, now: u64) -> bool {
    let sys = &*s.syscalls;
    let port = s.identity_req_out;
    if port < 0 {
        return false;
    }
    let poll = (sys.channel_poll)(port, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return false;
    }
    let mut frame = [0u8; 3 + ID_POINT_LEN];
    frame[0] = ID_MSG_REQ;
    frame[1..3].copy_from_slice(&(ID_POINT_LEN as u16).to_le_bytes());
    frame[3..].copy_from_slice(&s.label_id.point);
    if (sys.channel_write)(port, frame.as_ptr(), frame.len()) == frame.len() as i32 {
        s.label_id.next_at = now + ID_REQ_PERIOD_MS;
        return true;
    }
    false
}

/// One step of the label identity. True when it did anything.
unsafe fn identity_step(s: &mut TlsState) -> bool {
    if s.label_id.state == ID_NONE {
        return false;
    }
    let sys = &*s.syscalls;
    let now = dev_millis(sys);
    let mut did = false;
    if s.label_id.state == ID_OPENING {
        if now < s.label_id.next_at {
            return false;
        }
        if !identity_open(s, now) {
            return false;
        }
        did = true;
    }
    if s.identity_cert_in >= 0 && identity_take_chain(s, now) {
        did = true;
    }
    let due = match s.label_id.state {
        ID_UNCERTIFIED => true,
        ID_CERTIFIED => s.label_id.renew_at != 0 && now >= s.label_id.renew_at,
        _ => false,
    };
    if due && now >= s.label_id.next_at && identity_request(s, now) {
        did = true;
    }
    did
}

/// Construction-time admission of a label identity. `None` when admitted.
unsafe fn identity_admit(s: &mut TlsState) -> Option<&'static [u8]> {
    if s.label_id.overflow != 0 {
        return Some(b"[tls] refusing to construct: identity_label exceeds 64 bytes");
    }
    if !s.label_id.configured() {
        if s.label_id.trust_issuer != 0 {
            return Some(b"[tls] refusing to construct: trust_issuer takes its authority from an identity_label chain, and there is none");
        }
        return None;
    }
    if s.cert_len > 0 || s.key_len > 0 {
        return Some(b"[tls] refusing to construct: identity_label names the identity; cert_file / key_file would name a second one");
    }
    let sys = &*s.syscalls;
    if (sys.provider_call)(-1, kv::PROBE, core::ptr::null_mut(), 0) != 1 {
        return Some(b"[tls] refusing to construct: identity_label needs a key vault, and this target has none");
    }
    if s.identity_cert_in < 0 || s.identity_req_out < 0 {
        return Some(b"[tls] refusing to construct: identity_label needs identity_req and identity_cert wired to an issuer");
    }
    if s.label_id.trust_issuer != 0
        && s.peer_auth != PROFILE_CA_DNS
        && s.peer_auth != PROFILE_CA_URI
    {
        return Some(b"[tls] refusing to construct: trust_issuer adopts an authority, and only a CA profile (ca_dns, ca_uri) verifies chains against one");
    }
    if s.label_id.trust_issuer != 0 && s.anchor_count as usize >= MAX_ANCHORS {
        return Some(b"[tls] refusing to construct: trust_issuer adopts an anchor after the configured ones, and they already fill MAX_ANCHORS");
    }
    s.label_id.static_anchors = s.anchor_count;
    s.label_id.state = ID_OPENING;
    s.label_id.next_at = 0;
    None
}

/// Append `text` at `at` in a 96-byte log line; the new end.
unsafe fn id_put(line: *mut u8, at: usize, text: &[u8]) -> usize {
    core::ptr::copy_nonoverlapping(text.as_ptr(), line.add(at), text.len());
    at + text.len()
}
