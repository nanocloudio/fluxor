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
    /// Client dials refused (`EAGAIN`) because no certificate was held yet.
    early_dials: u32,
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
    s.creds.ready() && (s.label_id.state == ID_NONE || s.label_id.state == ID_CERTIFIED)
}

/// May a client dial now? A label identity that holds no certificate yet
/// (and so, under `trust_issuer`, no adopted anchor either) could neither
/// present itself nor verify a peer of its runtime authority: a dial now
/// would fail its handshake and cost the peer one. Refused with `EAGAIN`
/// on the requester's tag instead, which a consumer's backoff redials; a
/// file identity, or none, may always dial.
fn identity_dialable(s: &TlsState) -> bool {
    // Credentials named by path and not yet read: nothing to present, and
    // perhaps no anchor to verify the peer against.
    if !s.creds.ready() {
        return false;
    }
    if !s.label_id.configured() {
        return true;
    }
    // Under `trust_issuer` a chain is taken only with its issuer adopted
    // (`identity_take_chain`), so a certified identity has its anchor.
    s.label_id.state == ID_CERTIFIED
}

/// Count, and say on the first and every 64th, a dial refused because the
/// label identity is not certified yet.
unsafe fn identity_refuse_dial(s: &mut TlsState) {
    s.label_id.early_dials = s.label_id.early_dials.wrapping_add(1);
    if s.label_id.early_dials & 63 == 1 {
        let sys = &*s.syscalls;
        let msg: &[u8] = if s.creds.ready() {
            b"[tls] identity not yet certified: dial refused EAGAIN"
        } else {
            b"[tls] credentials not yet read from their files: dial refused EAGAIN"
        };
        dev_log(sys, 2, msg.as_ptr(), msg.len());
    }
}

/// Refuse a session that reached its Certificate with nothing to present.
/// Counted, and logged on the first and every 64th, so a client hammering a
/// node that is still coming up does not flood the log.
unsafe fn identity_refuse_early(s: &mut TlsState) {
    s.label_id.early = s.label_id.early.wrapping_add(1);
    if s.label_id.early & 63 == 1 {
        let sys = &*s.syscalls;
        let msg: &[u8] = if s.creds.ready() {
            b"[tls] identity not yet certified: handshake refused"
        } else {
            b"[tls] credentials not yet read from their files: handshake refused"
        };
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
    // Anchors named by path are installed before an issuer is adopted
    // after them (`creds_install` places the adopted slot), so a label
    // identity waits for its instance's files.
    if s.label_id.state == ID_NONE || !s.creds.ready() {
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
    if s.cert_len > 0
        || s.key_len > 0
        || s.creds.files[CRED_CERT].configured()
        || s.creds.files[CRED_KEY].configured()
    {
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

// ── Credentials named by path (cred_file.rs) ─────────────────────────────

/// Construction-time admission of `cert_file` / `key_file` / `trust` named
/// by path. `None` when admitted. Each credential has one source: a path
/// read at runtime, or a blob the builder embedded, never both.
fn creds_admit(s: &TlsState) -> Option<&'static [u8]> {
    if s.creds.bad_path() {
        return Some(b"[tls] refusing to construct: cert_file / key_file / trust must be an absolute path of at most 255 bytes");
    }
    if s.creds.files[CRED_CERT].configured() && s.cert_len > 0 {
        return Some(b"[tls] refusing to construct: cert_file names a file read at runtime and an embedded chain");
    }
    if s.creds.files[CRED_KEY].configured() && (s.key_len > 0 || s.key_refused) {
        return Some(b"[tls] refusing to construct: key_file names a file read at runtime and an embedded key");
    }
    if s.creds.files[CRED_TRUST].configured()
        && (s.anchor_count > s.anchor_operator || s.trust_system)
    {
        return Some(
            b"[tls] refusing to construct: trust names a file read at runtime and another source",
        );
    }
    None
}

/// Where each credential file decodes: the staging buffers on `CRED_ROTATE`
/// targets, else straight into the live ones (read once, before the
/// instance is ready, so nothing is using them). Trust decodes as one
/// bundle over the anchor slots after the operator's.
unsafe fn creds_dests(s: &mut TlsState) -> [(*mut u8, usize); CRED_SLOTS] {
    let op = s.anchor_operator as usize;
    if CRED_ROTATE {
        [
            (s.cred_stage_cert.as_mut_ptr(), CRED_STAGE_CERT),
            (s.cred_stage_key.as_mut_ptr(), CRED_STAGE_KEY),
            (s.cred_stage_trust.as_mut_ptr(), CRED_STAGE_TRUST),
        ]
    } else {
        [
            (s.cert.as_mut_ptr(), MAX_CERT_CHAIN_BYTES),
            (s.key.as_mut_ptr(), MAX_KEY_LEN),
            (
                (s.anchors.as_mut_ptr() as *mut u8).add(op * MAX_CERT_LEN),
                (MAX_ANCHORS - op.min(MAX_ANCHORS)) * MAX_CERT_LEN,
            ),
        ]
    }
}

/// Is a handshake in flight, using the credentials a rotation would
/// replace (a certificate presented, a signature or a chain walk taking
/// several steps)?
fn creds_in_use(s: &TlsState) -> bool {
    let tcp = s.sessions.iter().any(|x| {
        matches!(
            x.state,
            SessionState::Allocated
                | SessionState::Connecting
                | SessionState::AcceptPending
                | SessionState::Handshaking
        )
    });
    tcp || s
        .peer_sessions
        .iter()
        .any(|p| p.phase == DtlsPhase::Handshaking)
}

/// The generation a deferred chain walk records for anchor slot `i`: the
/// adopted issuer's slot counts renewals, every other slot counts the
/// replacements of the anchors read from `trust`. The top bit keeps the
/// two counts from ever meeting at one value.
fn anchor_generation(s: &TlsState, i: usize) -> u32 {
    if s.label_id.trust_issuer != 0 && i == s.label_id.static_anchors as usize {
        s.label_id.adopted_generation | 0x8000_0000
    } else {
        s.trust_epoch & 0x7FFF_FFFF
    }
}

/// One step of the credential files. True when it installed or refused a
/// set.
unsafe fn creds_step(s: &mut TlsState) -> bool {
    if !s.creds.configured() {
        return false;
    }
    let sys = &*s.syscalls;
    let dest = creds_dests(s);
    if s.creds.step(sys, b"[tls]", &dest) != CS_CANDIDATE {
        return false;
    }
    if s.creds.ready && creds_in_use(s) && !s.creds.deferred_long_enough(sys) {
        return false;
    }
    match creds_install(s, &dest) {
        Ok(()) => s.creds.adopt(sys, b"[tls]"),
        Err((slot, why)) => s.creds.refuse(sys, b"[tls]", slot, why),
    }
    true
}

/// Validate the files just read and install them: all of them, or none
/// while the credentials in use stay. `Err((slot, why))` names the file.
unsafe fn creds_install(
    s: &mut TlsState,
    dest: &[(*mut u8, usize); CRED_SLOTS],
) -> Result<(), (usize, &'static [u8])> {
    let sys = &*s.syscalls;
    let cert_on = s.creds.files[CRED_CERT].configured();
    let key_on = s.creds.files[CRED_KEY].configured();
    let trust_on = s.creds.files[CRED_TRUST].configured();
    let cert_len = s.creds.files[CRED_CERT].len;
    let key_len = s.creds.files[CRED_KEY].len;
    let trust_len = s.creds.files[CRED_TRUST].len;
    let op = s.anchor_operator as usize;
    let issuer_room = usize::from(s.label_id.trust_issuer != 0);

    // ── Validate everything before anything changes.
    if cert_on {
        let chain = core::slice::from_raw_parts(dest[CRED_CERT].0, cert_len);
        if cert_len > MAX_CERT_CHAIN_BYTES || !chain_parses(chain) {
            return Err((
                CRED_CERT,
                b"does not hold a certificate chain this module presents (leaf first, at most 3072 bytes)",
            ));
        }
    }
    if key_on {
        let key = core::slice::from_raw_parts(dest[CRED_KEY].0, key_len);
        if key_len == 0 || key_len > MAX_KEY_LEN {
            return Err((
                CRED_KEY,
                b"is not a key this module holds (at most 2400 bytes)",
            ));
        }
        let rsa = rsa_identity_suite(key);
        let mut scalar = [0u8; 48];
        let ec = identity_ec_scalar(key, &mut scalar);
        zeroize(&mut scalar);
        if rsa.is_none() && ec != 32 && ec != 48 {
            return Err((
                CRED_KEY,
                b"is not a P-256, P-384 or RSA-2048/3072/4096 private key",
            ));
        }
        if rsa.is_some() && (sys.provider_call)(-1, kv::PROBE, core::ptr::null_mut(), 0) != 1 {
            return Err((
                CRED_KEY,
                b"is an RSA key, and this target's vault does not hold RSA",
            ));
        }
    }
    let mut n_trust = 0;
    if trust_on {
        let room = MAX_ANCHORS.saturating_sub(op + issuer_room);
        match count_certificates(dest[CRED_TRUST].0, trust_len, MAX_CERT_LEN, room) {
            Some(n) => n_trust = n,
            None => {
                return Err((
                    CRED_TRUST,
                    b"does not hold trust anchors this module takes (certificates of at most 2048 bytes, at most 8 with the operator's and an adopted issuer)",
                ))
            }
        }
    }

    // ── Install.
    if cert_on {
        core::ptr::copy(dest[CRED_CERT].0, s.cert.as_mut_ptr(), cert_len);
        s.cert_len = cert_len;
    }
    if key_on {
        let old = s.key_vault_handle;
        core::ptr::copy(dest[CRED_KEY].0, s.key.as_mut_ptr(), key_len);
        s.key_len = key_len;
        s.key_vault_handle = -1;
        if CRED_ROTATE {
            // The staged copy is not needed past this point.
            core::ptr::write_bytes(dest[CRED_KEY].0, 0, key_len);
        }
        let deposited = identity_key_deposit(s);
        if old >= 0 {
            (sys.provider_call)(old, kv::DESTROY, core::ptr::null_mut(), 0);
        }
        if !deposited {
            // Validated above against the vault's presence; a vault that
            // then refuses the key leaves no identity to serve.
            s.creds.ready = false;
            return Err((CRED_KEY, b"was refused by the vault"));
        }
    }
    if trust_on {
        let base = (s.anchors.as_mut_ptr() as *mut u8).add(op * MAX_CERT_LEN);
        let old_static = s.label_id.static_anchors as usize;
        let new_static = op + n_trust;
        let adopted = s.label_id.trust_issuer != 0 && s.anchor_count as usize > old_static;
        let move_issuer = |s: &mut TlsState| {
            if adopted && old_static != new_static {
                let (a, b) = (old_static, new_static);
                let len = s.anchor_lens[a] as usize;
                let src = s.anchors[a].as_ptr();
                let dst = s.anchors[b].as_mut_ptr();
                core::ptr::copy(src, dst, len);
                s.anchor_lens[b] = len as u16;
            }
        };
        if new_static > old_static {
            move_issuer(s);
        }
        let mut written = [0u16; MAX_ANCHORS];
        let _ = split_certificates(
            dest[CRED_TRUST].0,
            trust_len,
            base,
            MAX_CERT_LEN,
            MAX_ANCHORS - op,
            &mut written,
        );
        let mut k = 0;
        while k < n_trust {
            s.anchor_lens[op + k] = written[k];
            k += 1;
        }
        if new_static < old_static {
            move_issuer(s);
        }
        s.anchor_count = (new_static + usize::from(adopted)) as u8;
        s.label_id.static_anchors = new_static as u8;
        // Every walk that chose an anchor before now reads no key from
        // the table it chose from.
        s.trust_epoch = s.trust_epoch.wrapping_add(1);
        s.label_id.adopted_generation = s.label_id.adopted_generation.wrapping_add(1);
    }
    Ok(())
}
