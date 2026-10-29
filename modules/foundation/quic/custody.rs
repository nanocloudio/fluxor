// Vault-to-vault custody of a connection's continuity key (CT_QUIC), as
// `tls`'s (`tls/continuity.rs`): each flow's record is sealed under a key
// the vault derives from the continuity master (`quic-continuity-master`,
// a KDF key) for that flow and ownership epoch; a standby opens it when its
// vault holds that key — derived from the same master (a deployment that
// distributes it), or moved to it by `CMD_SC_CUSTODY`: the standby's vault
// attests a fresh recipient over the transfer's challenge (ATTEST, signed by
// its custody identity `quic-custody`), the primary's checks the evidence
// and its signature and wraps the flow's key to it bound to the attested
// composition (WRAP), the standby's unwraps it (UNWRAP) and keeps it for
// the flow until a shadow has opened with it. The key is in no frame.
//
// The primary's WRAP checks that the evidence is whole and self-consistent:
// it answers this transfer's challenge, names a fresh, unpersisted P-256
// agreement key whose thumbprint is the public key carried, and verifies
// under the signer it names. Whether that signer is the host the transfer
// was decided for, and its composition one to trust, is not this module's
// question: the coordinator answers it before it sends the WRAP. A
// recipient opens one wrapped key once and is destroyed with it, so a
// wrapped key replayed later finds no recipient to open it.

/// The continuity master (a KDF key) and the per-flow key's label.
const QCONT_MASTER_LABEL: &[u8] = b"quic-continuity-master";
const CONT_KEY_LABEL: &[u8] = b"quic/continuity";
/// This host's custody identity (a P-256 signing key).
const CUSTODY_ID_LABEL: &[u8] = b"quic-custody";
/// Key entries: derived, imported and recipient keys for the shadows and
/// the flows moving out.
pub const QCONT_KEYS: usize = 2 + 2 * MAX_SHADOW_SLOTS;

#[derive(Clone, Copy)]
pub struct ContKey {
    kind: u8,
    flow: [u8; CONT_FLOW_ID_BYTES],
    epoch: u32,
    handle: i32,
    stamp: u32,
    used: bool,
}

const KEY_FREE: u8 = 0;
const KEY_DERIVED: u8 = 1;
const KEY_IMPORTED: u8 = 2;
const KEY_RECIPIENT: u8 = 3;

pub const EMPTY_CONT_KEY: ContKey = ContKey {
    kind: KEY_FREE,
    flow: [0; CONT_FLOW_ID_BYTES],
    epoch: 0,
    handle: -1,
    stamp: 0,
    used: false,
};

unsafe fn cont_vault_open_or_generate(
    sys: &SyscallTable,
    suite: u16,
    usage: u32,
    label: &[u8],
    pub_out: &mut [u8],
) -> i32 {
    let mut arg = [0u8; 8 + kv::MAX_LABEL + 12];
    if label.len() > kv::MAX_LABEL {
        return -1;
    }
    arg[0..2].copy_from_slice(&suite.to_le_bytes());
    arg[2..6].copy_from_slice(&usage.to_le_bytes());
    arg[6] = 0;
    arg[7] = label.len() as u8;
    arg[8..8 + label.len()].copy_from_slice(label);
    let t = 8 + label.len();
    arg[t..t + 8].copy_from_slice(&(pub_out.as_mut_ptr() as u64).to_le_bytes());
    arg[t + 8..t + 10].copy_from_slice(&(pub_out.len() as u16).to_le_bytes());
    let rc = (sys.provider_call)(-1, kv::OPEN_OR_GENERATE, arg.as_mut_ptr(), t + 12);
    if rc < 0 {
        -1
    } else {
        rc
    }
}

/// Free a vault handle.
unsafe fn cont_vault_destroy(sys: &SyscallTable, handle: i32) {
    if handle >= 0 {
        let _ = (sys.provider_call)(handle, kv::DESTROY, core::ptr::null_mut(), 0);
    }
}

/// The continuity master's handle, opening (or generating) it on first use.
unsafe fn cont_master(s: &mut QuicState) -> i32 {
    if s.continuity.master >= 0 {
        return s.continuity.master;
    }
    let sys = &*s.syscalls;
    s.continuity.master = cont_vault_open_or_generate(
        sys,
        kv::suite::KDF_KEY,
        kv::usage::DERIVE | kv::usage::PERSIST,
        QCONT_MASTER_LABEL,
        &mut [],
    );
    s.continuity.master
}

/// Derive `flow`'s sealing key at `epoch` from the master: an AEAD key that
/// seals, opens and may leave this vault wrapped to an attested recipient.
unsafe fn cont_derive_key(s: &mut QuicState, flow: &[u8; CONT_FLOW_ID_BYTES], epoch: u32) -> i32 {
    let master = cont_master(s);
    if master < 0 {
        return -1;
    }
    use kv::derive as d;
    let ctx_len = CONT_FLOW_ID_BYTES + 4;
    let mut arg = [0u8; d::LABEL + 16 + CONT_FLOW_ID_BYTES + 4];
    arg[d::TARGET_SUITE..d::TARGET_SUITE + 2].copy_from_slice(&kv::suite::AEAD_KEY.to_le_bytes());
    let usage = kv::usage::SEAL | kv::usage::OPEN | kv::usage::WRAP;
    arg[d::TARGET_USAGE..d::TARGET_USAGE + 4].copy_from_slice(&usage.to_le_bytes());
    arg[d::LABEL_LEN] = CONT_KEY_LABEL.len() as u8;
    arg[d::CONTEXT_LEN..d::CONTEXT_LEN + 2].copy_from_slice(&(ctx_len as u16).to_le_bytes());
    let l = d::LABEL;
    arg[l..l + CONT_KEY_LABEL.len()].copy_from_slice(CONT_KEY_LABEL);
    let c = l + CONT_KEY_LABEL.len();
    arg[c..c + CONT_FLOW_ID_BYTES].copy_from_slice(flow);
    arg[c + CONT_FLOW_ID_BYTES..c + ctx_len].copy_from_slice(&epoch.to_le_bytes());
    let sys = &*s.syscalls;
    let rc = (sys.provider_call)(master, kv::DERIVE, arg.as_mut_ptr(), c + ctx_len);
    if rc < 0 {
        -1
    } else {
        rc
    }
}

/// Whether a live connection or a shadow of this instance is `(flow, epoch)`.
fn cont_key_referenced(s: &QuicState, k: &ContKey) -> bool {
    s.conns
        .iter()
        .any(|c| c.phase != ConnPhase::Idle && c.cont_epoch == k.epoch && c.cont_flow_id == k.flow)
        || s.continuity
            .shadows
            .iter()
            .any(|sd| sd.phase != ShadowPhase::Free && sd.epoch == k.epoch && sd.flow_id == k.flow)
}

/// The key entry of `kind` (a mask of kinds) for `(flow, epoch)`.
fn cont_key_find(s: &QuicState, kinds: &[u8], flow: &[u8], epoch: u32) -> Option<usize> {
    s.continuity
        .keys
        .iter()
        .position(|k| kinds.contains(&k.kind) && k.epoch == epoch && flow_eq(&k.flow, flow))
}

/// A free key entry: an empty one, else the one least worth keeping — a
/// derived key nothing references (it can be derived again), then the
/// oldest entry nothing references. `None` when every one is in use.
unsafe fn cont_key_alloc(s: &mut QuicState) -> Option<usize> {
    if let Some(i) = s.continuity.keys.iter().position(|k| k.kind == KEY_FREE) {
        return Some(i);
    }
    let mut pick: Option<usize> = None;
    let mut i = 0;
    while i < QCONT_KEYS {
        let k = s.continuity.keys[i];
        if !cont_key_referenced(s, &k) {
            let better = match pick {
                None => true,
                Some(p) => {
                    let q = &s.continuity.keys[p];
                    (k.kind == KEY_DERIVED && q.kind != KEY_DERIVED)
                        || ((k.kind == KEY_DERIVED) == (q.kind == KEY_DERIVED) && k.stamp < q.stamp)
                }
            };
            if better {
                pick = Some(i);
            }
        }
        i += 1;
    }
    let p = pick?;
    cont_key_free(s, p);
    Some(p)
}

unsafe fn cont_key_free(s: &mut QuicState, i: usize) {
    let sys = &*s.syscalls;
    cont_vault_destroy(sys, s.continuity.keys[i].handle);
    s.continuity.keys[i] = EMPTY_CONT_KEY;
}

unsafe fn cont_key_put(
    s: &mut QuicState,
    i: usize,
    kind: u8,
    flow: &[u8; CONT_FLOW_ID_BYTES],
    epoch: u32,
    handle: i32,
) {
    s.continuity.key_stamp = s.continuity.key_stamp.wrapping_add(1);
    s.continuity.keys[i] = ContKey {
        kind,
        flow: *flow,
        epoch,
        handle,
        stamp: s.continuity.key_stamp,
        used: false,
    };
}

/// The sealing key of `(flow, epoch)`: one a custody transfer brought, else
/// this vault's derivation from its master. -1 when neither is possible.
unsafe fn cont_flow_key(s: &mut QuicState, flow: &[u8; CONT_FLOW_ID_BYTES], epoch: u32) -> i32 {
    if let Some(i) = cont_key_find(s, &[KEY_IMPORTED], flow, epoch) {
        s.continuity.keys[i].used = true;
        return s.continuity.keys[i].handle;
    }
    if let Some(i) = cont_key_find(s, &[KEY_DERIVED], flow, epoch) {
        return s.continuity.keys[i].handle;
    }
    let Some(i) = cont_key_alloc(s) else {
        return -1;
    };
    let h = cont_derive_key(s, flow, epoch);
    if h < 0 {
        return -1;
    }
    cont_key_put(s, i, KEY_DERIVED, flow, epoch, h);
    h
}

/// Let go of keys nothing needs: a derived key no connection or shadow is
/// keyed by, and an unwrapped one whose shadow has opened with it and gone.
/// A recipient waits for its UNWRAP (or for eviction).
pub(crate) unsafe fn cont_keys_sweep(s: &mut QuicState) {
    let mut i = 0;
    while i < QCONT_KEYS {
        let k = s.continuity.keys[i];
        let stale = match k.kind {
            KEY_DERIVED => !cont_key_referenced(s, &k),
            KEY_IMPORTED => k.used && !cont_key_referenced(s, &k),
            _ => false,
        };
        if stale {
            cont_key_free(s, i);
        }
        i += 1;
    }
}

unsafe fn custody_reply(
    s: &mut QuicState,
    flow: &[u8],
    epoch: u32,
    op: u8,
    status: u8,
    reason: u8,
    bytes: &[u8],
) {
    let mut body = [0u8; 2 + sc::custody::EVIDENCE_MAX];
    let n = bytes.len().min(sc::custody::EVIDENCE_MAX);
    body[0] = op;
    body[1] = reason;
    body[2..2 + n].copy_from_slice(&bytes[..n]);
    let _ = cont_reply(s, flow, epoch, sc::CR_CUSTODY, status, &body[..2 + n]);
}

/// This host's custody identity and its public key, opened on first use.
unsafe fn custody_signer(s: &mut QuicState) -> i32 {
    if s.continuity.signer_open {
        return s.continuity.signer;
    }
    let sys = &*s.syscalls;
    let mut pubk = [0u8; sc::custody::PUB_LEN];
    let h = cont_vault_open_or_generate(
        sys,
        kv::suite::P256,
        kv::usage::SIGN | kv::usage::EXPORT_PUBLIC | kv::usage::PERSIST,
        CUSTODY_ID_LABEL,
        &mut pubk,
    );
    if h < 0 {
        return -1;
    }
    s.continuity.signer = h;
    s.continuity.signer_pub = pubk;
    s.continuity.signer_open = true;
    h
}

unsafe fn handle_custody(s: &mut QuicState, p: &[u8]) {
    use sc::custody as cu;
    if p.len() < sc::FLOW_HEADER_LEN + 1 {
        return;
    }
    let mut flow = [0u8; CONT_FLOW_ID_BYTES];
    flow.copy_from_slice(&p[..16]);
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let op = p[20];
    let body = &p[21..];
    let r = match op {
        cu::ATTEST => custody_attest(s, &flow, epoch, body),
        cu::WRAP => custody_wrap(s, &flow, epoch, body),
        cu::UNWRAP => custody_unwrap(s, &flow, epoch, body),
        _ => Err((sc::STATUS_UNSUPPORTED, 0)),
    };
    if let Err((status, reason)) = r {
        custody_reply(s, &flow, epoch, op, status, reason, &[]);
    }
}

type CustodyResult = Result<(), (u8, u8)>;

/// ATTEST `[challenge:32]`: a fresh recipient under `name`, attested.
unsafe fn custody_attest(
    s: &mut QuicState,
    name: &[u8; CONT_FLOW_ID_BYTES],
    epoch: u32,
    body: &[u8],
) -> CustodyResult {
    use sc::custody as cu;
    let vault = (sc::STATUS_NO_CAPACITY, cu::why::VAULT);
    if body.len() != 32 {
        return Err((sc::STATUS_CORRUPT, cu::why::EVIDENCE));
    }
    let signer = custody_signer(s);
    if signer < 0 {
        return Err(vault);
    }
    // A later ATTEST under the same name replaces the recipient.
    if let Some(i) = cont_key_find(s, &[KEY_RECIPIENT], name, epoch) {
        cont_key_free(s, i);
    }
    let Some(slot) = cont_key_alloc(s) else {
        return Err(vault);
    };
    let sys = &*s.syscalls;
    // GENERATE: [suite:u16][usage:u32][flags:u8][_pad:u8]
    //           [pub_out_ptr:u64][pub_out_cap:u16][pub_len_out:u16]
    let mut rpub = [0u8; cu::PUB_LEN];
    let mut g = [0u8; 20];
    g[0..2].copy_from_slice(&kv::suite::P256.to_le_bytes());
    let usage = kv::usage::AGREE | kv::usage::EXPORT_PUBLIC;
    g[2..6].copy_from_slice(&usage.to_le_bytes());
    g[8..16].copy_from_slice(&(rpub.as_mut_ptr() as u64).to_le_bytes());
    g[16..18].copy_from_slice(&(cu::PUB_LEN as u16).to_le_bytes());
    let recipient = (sys.provider_call)(-1, kv::GENERATE, g.as_mut_ptr(), g.len());
    if recipient < 0 || u16::from_le_bytes([g[18], g[19]]) as usize != cu::PUB_LEN {
        cont_vault_destroy(sys, recipient);
        return Err(vault);
    }
    // ATTEST_KEY: [challenge:32][signer:i32][_pad:u32][out_ptr:u64]
    //             [out_cap:u32][out_len_out:u32]
    let mut ev = [0u8; cu::EVIDENCE_MAX];
    let mut rec = [0u8; cu::RECORD_LEN + cu::SIG_MAX];
    let mut a = [0u8; kv::attest_key::ARG_LEN];
    a[..32].copy_from_slice(body);
    a[kv::attest_key::SIGNER..kv::attest_key::SIGNER + 4].copy_from_slice(&signer.to_le_bytes());
    a[kv::attest_key::OUT_PTR..kv::attest_key::OUT_PTR + 8]
        .copy_from_slice(&(rec.as_mut_ptr() as u64).to_le_bytes());
    a[kv::attest_key::OUT_CAP..kv::attest_key::OUT_CAP + 4]
        .copy_from_slice(&(rec.len() as u32).to_le_bytes());
    let rc = (sys.provider_call)(recipient, kv::ATTEST_KEY, a.as_mut_ptr(), a.len());
    let n = u32::from_le_bytes([
        a[kv::attest_key::OUT_LEN],
        a[kv::attest_key::OUT_LEN + 1],
        a[kv::attest_key::OUT_LEN + 2],
        a[kv::attest_key::OUT_LEN + 3],
    ]) as usize;
    if rc < 0 || n <= cu::RECORD_LEN || n > rec.len() {
        cont_vault_destroy(sys, recipient);
        return Err(vault);
    }
    let sig_len = n - cu::RECORD_LEN;
    ev[..cu::RECORD_LEN].copy_from_slice(&rec[..cu::RECORD_LEN]);
    ev[cu::RECIPIENT..cu::RECIPIENT + cu::PUB_LEN].copy_from_slice(&rpub);
    ev[cu::SIGNER..cu::SIGNER + cu::PUB_LEN].copy_from_slice(&s.continuity.signer_pub);
    ev[cu::SIG_LEN..cu::SIG_LEN + 2].copy_from_slice(&(sig_len as u16).to_le_bytes());
    ev[cu::SIG..cu::SIG + sig_len].copy_from_slice(&rec[cu::RECORD_LEN..n]);
    cont_key_put(s, slot, KEY_RECIPIENT, name, epoch, recipient);
    custody_reply(
        s,
        name,
        epoch,
        cu::ATTEST,
        sc::STATUS_OK,
        0,
        &ev[..cu::SIG + sig_len],
    );
    Ok(())
}

/// WRAP `[challenge:32][evidence]`: the flow's sealing key, wrapped to the
/// attested recipient.
unsafe fn custody_wrap(
    s: &mut QuicState,
    flow: &[u8; CONT_FLOW_ID_BYTES],
    epoch: u32,
    body: &[u8],
) -> CustodyResult {
    use sc::custody as cu;
    let refuse = |why| Err((sc::STATUS_CORRUPT, why));
    if body.len() < 32 + cu::SIG + 1 || body.len() > 32 + cu::EVIDENCE_MAX {
        return refuse(cu::why::EVIDENCE);
    }
    let (challenge, ev) = body.split_at(32);
    let sig_len = u16::from_le_bytes([ev[cu::SIG_LEN], ev[cu::SIG_LEN + 1]]) as usize;
    if sig_len != cu::SIG_MAX || cu::SIG + sig_len != ev.len() {
        return refuse(cu::why::EVIDENCE);
    }
    let record = &ev[..cu::RECORD_LEN];
    let recipient = &ev[cu::RECIPIENT..cu::RECIPIENT + cu::PUB_LEN];
    let signer = &ev[cu::SIGNER..cu::SIGNER + cu::PUB_LEN];
    let sig = &ev[cu::SIG..];
    use kv::attest_key as ak;
    if record[..4] != ak::MAGIC {
        return refuse(cu::why::EVIDENCE);
    }
    if record[ak::R_CHALLENGE..ak::R_CHALLENGE + 32] != *challenge {
        return refuse(cu::why::CHALLENGE);
    }
    let usage = u32::from_le_bytes([
        record[ak::R_USAGE],
        record[ak::R_USAGE + 1],
        record[ak::R_USAGE + 2],
        record[ak::R_USAGE + 3],
    ]);
    let suite = u16::from_le_bytes([record[ak::R_SUITE], record[ak::R_SUITE + 1]]);
    if suite != kv::suite::P256
        || usage & kv::usage::AGREE == 0
        || usage & (kv::usage::PERSIST | kv::usage::WRAP) != 0
        || record[ak::R_PERSISTED] != 0
        || record[ak::R_THUMBPRINT..ak::R_THUMBPRINT + 32] != sha256(recipient)
    {
        return refuse(cu::why::RECIPIENT);
    }
    let sys = &*s.syscalls;
    // VERIFY with the signer's public key: [hash_len:u16][sig_len:u16]
    // [pub_len:u16][_pad:u16][hash][sig][pub].
    let digest = sha256(record);
    let mut v = [0u8; 8 + 32 + cu::SIG_MAX + cu::PUB_LEN];
    v[0..2].copy_from_slice(&32u16.to_le_bytes());
    v[2..4].copy_from_slice(&(cu::SIG_MAX as u16).to_le_bytes());
    v[4..6].copy_from_slice(&(cu::PUB_LEN as u16).to_le_bytes());
    v[8..40].copy_from_slice(&digest);
    v[40..40 + cu::SIG_MAX].copy_from_slice(sig);
    v[40 + cu::SIG_MAX..].copy_from_slice(signer);
    if (sys.provider_call)(-1, kv::VERIFY, v.as_mut_ptr(), v.len()) != 1 {
        return refuse(cu::why::SIGNATURE);
    }
    // The flow must be a live connection of this instance at this epoch:
    // the key it seals under is what moves.
    let Some(idx) = find_live_by_flow(s, flow) else {
        return Err((sc::STATUS_UNKNOWN_SESSION, cu::why::NO_FLOW));
    };
    if s.conns[idx].cont_epoch != epoch {
        return Err((sc::STATUS_STALE_EPOCH, cu::why::NO_FLOW));
    }
    let key = cont_flow_key(s, flow, epoch);
    if key < 0 {
        return Err((sc::STATUS_NO_CAPACITY, cu::why::VAULT));
    }
    // KEY_WRAP: [dest_pub_len:u16][dest_pub][attest_digest:32]
    //           [out_ptr:u64][out_cap:u16][out_len_out:u16]
    let mut blob = [0u8; cu::WRAPPED_LEN];
    let mut w = [0u8; 2 + cu::PUB_LEN + 32 + 12];
    w[0..2].copy_from_slice(&(cu::PUB_LEN as u16).to_le_bytes());
    w[2..2 + cu::PUB_LEN].copy_from_slice(recipient);
    let c = 2 + cu::PUB_LEN;
    w[c..c + 32].copy_from_slice(&record[ak::R_COMPOSITION..ak::R_COMPOSITION + 32]);
    w[c + 32..c + 40].copy_from_slice(&(blob.as_mut_ptr() as u64).to_le_bytes());
    w[c + 40..c + 42].copy_from_slice(&(blob.len() as u16).to_le_bytes());
    let sys = &*s.syscalls;
    let rc = (sys.provider_call)(key, kv::KEY_WRAP, w.as_mut_ptr(), w.len());
    let n = u16::from_le_bytes([w[c + 42], w[c + 43]]) as usize;
    if rc < 0 || n != cu::WRAPPED_LEN {
        return Err((sc::STATUS_NO_CAPACITY, cu::why::VAULT));
    }
    custody_reply(s, flow, epoch, cu::WRAP, sc::STATUS_OK, 0, &blob);
    Ok(())
}

/// UNWRAP `[name:16][wrapped]`: the key the recipient `name` was attested
/// for, held for `(flow, epoch)` until a shadow imports with it.
unsafe fn custody_unwrap(
    s: &mut QuicState,
    flow: &[u8; CONT_FLOW_ID_BYTES],
    epoch: u32,
    body: &[u8],
) -> CustodyResult {
    use sc::custody as cu;
    if body.len() != 16 + cu::WRAPPED_LEN {
        return Err((sc::STATUS_CORRUPT, cu::why::EVIDENCE));
    }
    let (name, blob) = body.split_at(16);
    let Some(ri) = cont_key_find(s, &[KEY_RECIPIENT], name, epoch) else {
        return Err((sc::STATUS_UNKNOWN_SESSION, cu::why::NO_RECIPIENT));
    };
    let recipient = s.continuity.keys[ri].handle;
    let sys = &*s.syscalls;
    // KEY_UNWRAP: [blob_len:u16][blob]
    let mut u = [0u8; 2 + cu::WRAPPED_LEN];
    u[0..2].copy_from_slice(&(cu::WRAPPED_LEN as u16).to_le_bytes());
    u[2..].copy_from_slice(blob);
    let key = (sys.provider_call)(recipient, kv::KEY_UNWRAP, u.as_mut_ptr(), u.len());
    if key < 0 {
        return Err((sc::STATUS_CORRUPT, cu::why::VAULT));
    }
    // The recipient has opened its one object and is spent, whatever it
    // held.
    cont_vault_destroy(sys, recipient);
    s.continuity.keys[ri] = EMPTY_CONT_KEY;
    // It must be a sealing key, as the primary's are; DESCRIBE:
    // [suite_out:u16][usage_out:u32][tier_out:u8][persisted_out:u8].
    let mut d = [0u8; 8];
    let rc = (sys.provider_call)(key, kv::DESCRIBE, d.as_mut_ptr(), d.len());
    let suite = u16::from_le_bytes([d[0], d[1]]);
    let usage = u32::from_le_bytes([d[2], d[3], d[4], d[5]]);
    if rc < 0
        || suite != kv::suite::AEAD_KEY
        || usage & (kv::usage::SEAL | kv::usage::OPEN) != kv::usage::SEAL | kv::usage::OPEN
    {
        cont_vault_destroy(sys, key);
        return Err((sc::STATUS_CORRUPT, cu::why::VAULT));
    }
    // Its slot holds the flow's key now.
    while let Some(i) = cont_key_find(s, &[KEY_IMPORTED, KEY_DERIVED], flow, epoch) {
        cont_key_free(s, i);
    }
    cont_key_put(s, ri, KEY_IMPORTED, flow, epoch, key);
    custody_reply(s, flow, epoch, cu::UNWRAP, sc::STATUS_OK, 0, &[]);
    Ok(())
}
