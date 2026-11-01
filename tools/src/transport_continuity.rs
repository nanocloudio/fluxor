//! `TRANSPORT_CONTINUITY` and its provider core, mounted for the host
//! tests.
//!
//! Path-mounted rather than reimplemented: the anchor that drives the
//! provider, the standby that imports its checkpoints and deltas and the
//! projects that stage the SDK must agree byte for byte, and the only way
//! to guarantee that is one source. The canonical encoding is also pinned
//! by a digest vector, so an implementation outside this source is held to
//! the same bytes.
#![allow(
    dead_code,
    reason = "the contract surface is shared by anchors, providers and \
              mirrors; the host tests reach the provider half"
)]

include!("../../modules/sdk/crypto/sha256.rs");
include!("../../modules/sdk/contracts/net/transport_continuity.rs");
include!("../../modules/sdk/cores/transport_continuity.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const FLOW: [u8; 16] = [0xF1; 16];
    const ANCHOR_A: [u8; 8] = [0xA1; 8];
    const ANCHOR_B: [u8; 8] = [0xB2; 8];

    type Provider = TcProvider<2, 4>;

    // ── a record layer and vault, behind references ──────────────────────
    //
    // Records are `[type][epoch u16][len u16][ciphertext][tag 8]` under a
    // SHA-256 keystream and tag: a model of the sealed record, not TLS, so
    // the test can play both ends. The secrets stay in here.

    fn h(parts: &[&[u8]]) -> [u8; 32] {
        let mut d = Sha256::new();
        for p in parts {
            d.update(p);
        }
        d.finalize()
    }

    fn xor_keystream(secret: &[u8; 32], seq: u64, bytes: &mut [u8]) {
        for (block, chunk) in bytes.chunks_mut(32).enumerate() {
            let ks = h(&[
                b"ks",
                secret,
                &seq.to_le_bytes(),
                &(block as u32).to_le_bytes(),
            ]);
            for (b, k) in chunk.iter_mut().zip(ks.iter()) {
                *b ^= k;
            }
        }
    }

    fn seal_rec(secret: &[u8; 32], epoch: u32, seq: u64, rtype: u8, pt: &[u8]) -> Vec<u8> {
        let mut ct = pt.to_vec();
        xor_keystream(secret, seq, &mut ct);
        let mut rec = vec![rtype];
        rec.extend_from_slice(&(epoch as u16).to_le_bytes());
        rec.extend_from_slice(&(ct.len() as u16).to_le_bytes());
        rec.extend_from_slice(&ct);
        rec.extend_from_slice(&h(&[b"tag", secret, &seq.to_le_bytes(), &[rtype], &ct])[..8]);
        rec
    }

    fn open_rec(secret: &[u8; 32], seq: u64, rec: &[u8]) -> Option<(u8, Vec<u8>)> {
        let len = usize::from(u16::from_le_bytes([*rec.get(3)?, *rec.get(4)?]));
        if rec.len() != 5 + len + 8 {
            return None;
        }
        let ct = &rec[5..5 + len];
        if h(&[b"tag", secret, &seq.to_le_bytes(), &[rec[0]], ct])[..8] != rec[5 + len..] {
            return None;
        }
        let mut pt = ct.to_vec();
        xor_keystream(secret, seq, &mut pt);
        Some((rec[0], pt))
    }

    #[derive(Default)]
    struct Vault {
        backend: u8,
        keys: HashMap<([u8; 16], u8, u32), [u8; 32]>,
        destroyed: Vec<(u8, u32)>,
    }

    impl Vault {
        fn install(&mut self, purpose: u8, epoch: u32, secret: [u8; 32]) -> TsVaultRef {
            self.keys.insert((FLOW, purpose, epoch), secret);
            TsVaultRef {
                backend: self.backend,
                purpose,
                object: epoch,
                generation: 1,
                epoch,
            }
        }
    }

    impl TcRecords for Vault {
        fn holds(&self, flow: &[u8; 16], purpose: u8, epoch: u32) -> bool {
            self.keys.contains_key(&(*flow, purpose, epoch))
        }
        fn record_len(&self, b: &[u8]) -> Option<usize> {
            let n = 5 + usize::from(u16::from_le_bytes([*b.get(3)?, *b.get(4)?])) + 8;
            (b.len() >= n).then_some(n)
        }
        fn seal(
            &self,
            flow: &[u8; 16],
            epoch: u32,
            seq: u64,
            rtype: u8,
            pt: &[u8],
            out: &mut [u8],
        ) -> Option<usize> {
            let k = self.keys.get(&(*flow, TS_VAULT_WRITE, epoch))?;
            let r = seal_rec(k, epoch, seq, rtype, pt);
            out.get_mut(..r.len())?.copy_from_slice(&r);
            Some(r.len())
        }
        fn open(
            &self,
            flow: &[u8; 16],
            epoch: u32,
            seq: u64,
            rec: &[u8],
            out: &mut [u8],
        ) -> Option<(u8, usize)> {
            let k = self.keys.get(&(*flow, TS_VAULT_READ, epoch))?;
            let (t, pt) = open_rec(k, seq, rec)?;
            out.get_mut(..pt.len())?.copy_from_slice(&pt);
            Some((t, pt.len()))
        }
        fn derive_next(&mut self, flow: &[u8; 16], purpose: u8, epoch: u32) -> Option<TsVaultRef> {
            let s = *self.keys.get(&(*flow, purpose, epoch))?;
            let next = h(&[b"traffic upd", &s]);
            Some(self.install(purpose, epoch + 1, next))
        }
        fn destroy(&mut self, flow: &[u8; 16], purpose: u8, epoch: u32) {
            if self.keys.remove(&(*flow, purpose, epoch)).is_some() {
                self.destroyed.push((purpose, epoch));
            }
        }
        fn destroy_flow(&mut self, flow: &[u8; 16]) {
            let gone: Vec<_> = self.keys.keys().filter(|k| k.0 == *flow).copied().collect();
            for k in gone {
                self.keys.remove(&k);
                self.destroyed.push((k.1, k.2));
            }
        }
    }

    /// The authority's verifier: accepts exactly one token, and records
    /// every token it was asked about.
    struct Authority {
        good: Option<[u8; TC_FLOW_TOKEN_LEN]>,
        asked: std::cell::RefCell<Vec<[u8; TC_FLOW_TOKEN_LEN]>>,
    }

    impl TcTokenVerifier for Authority {
        fn verify(&self, t: &[u8; TC_FLOW_TOKEN_LEN]) -> Result<(), u8> {
            self.asked.borrow_mut().push(*t);
            if Some(*t) == self.good {
                Ok(())
            } else {
                Err(0x03)
            }
        }
    }

    fn nobody() -> Authority {
        Authority {
            good: None,
            asked: Default::default(),
        }
    }

    const C2S: [u8; 32] = [0xC2; 32];
    const S2C: [u8; 32] = [0x5C; 32];

    fn initial(vault: &mut Vault) -> TsState {
        let mut st = TsState::established();
        st.flow_id = FLOW;
        st.service_id = [0x5E; 16];
        st.client_ip[..4].copy_from_slice(&[10, 0, 0, 9]);
        st.client_port = 40001;
        st.service_ip[..4].copy_from_slice(&[10, 0, 0, 100]);
        st.service_port = 8883;
        st.iss = 1000;
        st.snd_una = 1001;
        st.snd_nxt = 1001;
        st.irs = 5000;
        st.rcv_nxt = 5001;
        st.rto_ms = 200;
        st.cwnd = 10 * 1460;
        st.peer_verified = true;
        st.read_key = vault.install(TS_VAULT_READ, 3, C2S);
        st.write_key = vault.install(TS_VAULT_WRITE, 3, S2C);
        st
    }

    // ── frames ────────────────────────────────────────────────────────────

    fn frame(op: u8, parts: &[&[u8]]) -> Vec<u8> {
        let mut f = vec![0u8; TC_FRAME_MAX];
        let n = tc_frame(&mut f, op, parts).unwrap();
        f.truncate(n);
        f
    }

    fn with_handle(op: u8, h: TcHandle, body: &[u8]) -> Vec<u8> {
        let mut hb = [0u8; 8];
        h.put(&mut hb);
        frame(op, &[&hb, body])
    }

    fn split(raw: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while let Some((op, len)) = tc_frame_hdr(&raw[at..]) {
            out.push((op, raw[at + 3..at + 3 + len].to_vec()));
            at += 3 + len;
        }
        out
    }

    fn status(ev: &[(u8, Vec<u8>)], op: u8) -> TcStatus {
        ev.iter()
            .filter(|(k, _)| *k == tc_evt::STATUS)
            .map(|(_, b)| TcStatus::decode(b).unwrap())
            .rfind(|s| s.op == op)
            .expect("a STATUS for the op")
    }

    /// One host: its provider, its vault, the verifier it was handed.
    struct Host {
        p: Box<Provider>,
        v: Vault,
        auth: Authority,
    }

    /// A provider is large (per slot a record, an assembler and the early
    /// segments): a module holds it in static state; a test builds it on a
    /// thread whose stack takes it whole, then keeps it boxed.
    fn boxed_provider(anchor: [u8; 8], custody_base: u32) -> Box<Provider> {
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(move || Box::new(Provider::new(anchor, custody_base, 4 * 1460)))
            .unwrap()
            .join()
            .unwrap()
    }

    impl Host {
        fn new(anchor: [u8; 8], backend: u8) -> Self {
            Self {
                p: boxed_provider(anchor, 0x100 * u32::from(backend)),
                v: Vault {
                    backend,
                    ..Vault::default()
                },
                auth: nobody(),
            }
        }

        fn ctl(&mut self, raw: &[u8], now: u64) -> Vec<(u8, Vec<u8>)> {
            let mut out = Vec::new();
            self.p.ctl(raw, &mut self.v, &self.auth, now, &mut |f| {
                out.extend_from_slice(f)
            });
            split(&out)
        }

        fn rx(&mut self, seq: u32, ack: u32, payload: &[u8]) -> Vec<(u8, Vec<u8>)> {
            let mut out = Vec::new();
            let s = TcSegIn {
                seq,
                ack,
                wnd: 65535,
                fin: false,
                payload,
            };
            self.p
                .rx(&FLOW, &s, &mut self.v, &mut |f| out.extend_from_slice(f));
            split(&out)
        }

        /// `(seq, ack, wnd, fin, epoch, payload)` of every segment now.
        fn tx(&mut self, now: u64) -> Vec<(u32, u32, u32, bool, u32, Vec<u8>)> {
            let mut out = Vec::new();
            self.p.tx(&FLOW, now, &mut |s| {
                out.push((s.seq, s.ack, s.wnd, s.fin, s.flow_epoch, s.payload.to_vec()))
            });
            out
        }

        fn produce(&mut self, pid: u64, pt: &[u8]) -> (TcProduced, Vec<(u8, Vec<u8>)>) {
            let mut out = Vec::new();
            let r = self
                .p
                .produce(&FLOW, pid, pt, &self.v, &mut |f| out.extend_from_slice(f));
            (r, split(&out))
        }

        fn st(&self) -> &TsState {
            &self.p.flow(&FLOW).unwrap().st
        }
    }

    fn pair_body(role: TcRole, mode: TcMode) -> [u8; TC_PAIR_LEN] {
        let mut b = [0u8; TC_PAIR_LEN];
        TcPair {
            flow_id: FLOW,
            flow_epoch: 1,
            role,
            mode,
            transport: TcTransport::TcpTls,
            mirror_generation: 1,
            service_id: [0x5E; 16],
        }
        .encode(&mut b);
        b
    }

    /// A paired primary (host A) and a standby (host B) holding A's
    /// checkpoint, with B's vault holding the same secrets (the transfer
    /// itself is the vault's, not this core's).
    struct Pair {
        a: Host,
        b: Host,
        ha: TcHandle,
        hb: TcHandle,
        /// Deltas A emitted, in order, not yet applied at B.
        deltas: Vec<Vec<u8>>,
        client_seq: u32,
        client_wseq: u64,
    }

    fn deltas_of(ev: &[(u8, Vec<u8>)]) -> Vec<Vec<u8>> {
        ev.iter()
            .filter(|(k, _)| *k == tc_evt::DELTA)
            .map(|(_, b)| b[8..].to_vec())
            .collect()
    }

    fn pair(mode: TcMode) -> Pair {
        let mut a = Host::new(ANCHOR_A, 1);
        let mut b = Host::new(ANCHOR_B, 2);
        let st = initial(&mut a.v);
        b.v.install(TS_VAULT_READ, 3, C2S);
        b.v.install(TS_VAULT_WRITE, 3, S2C);
        a.p.establish(&st).unwrap();
        let null = TcHandle::default();
        let ev = a.ctl(
            &with_handle(tc_op::PAIR_PREPARE, null, &pair_body(TcRole::Primary, mode)),
            0,
        );
        let ha = status(&ev, tc_op::PAIR_PREPARE).handle;
        let ev = b.ctl(
            &with_handle(tc_op::PAIR_PREPARE, null, &pair_body(TcRole::Standby, mode)),
            0,
        );
        let hb = status(&ev, tc_op::PAIR_PREPARE).handle;
        assert!(!ha.is_null() && !hb.is_null());
        let ev = a.ctl(
            &with_handle(tc_op::CHECKPOINT_BEGIN, ha, &7u64.to_le_bytes()),
            0,
        );
        for (k, c) in &ev {
            if *k == tc_evt::CHUNK {
                let got = b.ctl(&with_handle(tc_op::CHECKPOINT_NEXT, hb, &c[8..]), 0);
                assert!(got.is_empty(), "every chunk accepted");
            }
        }
        let ev = b.ctl(
            &with_handle(tc_op::CHECKPOINT_COMMIT, hb, &7u64.to_le_bytes()),
            0,
        );
        assert_eq!(ev[0].0, tc_evt::APPLIED, "the shadow published");
        assert_eq!(a.st(), b.st(), "the shadow is the primary's state");
        Pair {
            a,
            b,
            ha,
            hb,
            deltas: Vec::new(),
            client_seq: 5001,
            client_wseq: 0,
        }
    }

    impl Pair {
        /// The client sends one application record to A.
        fn client_send(&mut self, pt: &[u8]) {
            let rec = seal_rec(&C2S, 3, self.client_wseq, TC_RT_APP, pt);
            self.client_wseq += 1;
            let ev = self.a.rx(self.client_seq, 1001, &rec);
            self.client_seq += rec.len() as u32;
            self.deltas.extend(deltas_of(&ev));
        }

        /// Apply A's pending deltas at B in order; B's acks back to A.
        fn mirror(&mut self) -> u64 {
            let mut acked = 0;
            for d in std::mem::take(&mut self.deltas) {
                let ev = self.b.ctl(&with_handle(tc_op::DELTA_APPLY, self.hb, &d), 0);
                assert_eq!(ev[0].0, tc_evt::APPLIED, "delta applied: {ev:?}");
                acked = u64::from_le_bytes(ev[0].1[16..24].try_into().unwrap());
            }
            if acked > 0 {
                self.a.ctl(
                    &with_handle(tc_op::DELTA_ACK, self.ha, &acked.to_le_bytes()),
                    0,
                );
            }
            acked
        }
    }

    // ── the canonical record ──────────────────────────────────────────────

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The reference state: a client session holding a whole protected
    /// record partly received and two deliveries of a full record's
    /// plaintext.
    fn reference(vault: &mut Vault) -> Box<TsState> {
        let mut st = Box::new(initial(vault));
        st.local_client = true;
        st.recv_len = 16_645;
        for (i, b) in st.recv[..16_645].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        st.rcv_nxt = st.rcv_nxt.wrapping_add(16_645 + 2 * 16_384);
        // An idle close that runs: a minute, 42 s of it left.
        st.idle_ms = 60_000;
        st.idle_rem_ms = 42_000;
        st.next_delivery = 3;
        st.delivery_acked = 0;
        st.deliv_count = 2;
        for (k, d) in st.deliv[..2].iter_mut().enumerate() {
            d.id = k as u64 + 1;
            d.len = 16_384;
            d.bytes.fill(0xD0 + k as u8);
        }
        st
    }

    /// Re-digest a record after editing its body.
    fn redigest(b: &mut [u8]) {
        let n = b.len() - 32;
        let d = sha256(&b[..n]);
        b[n..].copy_from_slice(&d);
    }

    /// The canonical encoding of the reference state is pinned: any other
    /// implementation of the codec is held to the same digest, so the two
    /// cannot drift apart unnoticed.
    #[test]
    fn the_canonical_record_is_pinned_byte_for_byte() {
        let mut v = Vault {
            backend: 1,
            ..Vault::default()
        };
        let st = reference(&mut v);
        let mut out = vec![0u8; TS_CKPT_MAX];
        let n = ts_encode(&st, &mut out).unwrap();
        assert_eq!(&out[..4], b"WHTC");
        assert_eq!(out[4], TS_VERSION);
        assert_eq!(u16::from_le_bytes([out[6], out[7]]), TS_FLAG_CLIENT);
        assert_eq!(
            hex(&sha256(&out[..n])),
            TS_REFERENCE_DIGEST,
            "the canonical record changed"
        );
        let mut back = Box::new(TsState::zero());
        ts_decode(&out[..n], &mut back).unwrap();
        assert_eq!(*back, *st);
        // Every truncation and every flipped byte refused, never
        // half-decoded.
        for cut in (0..n).step_by(997) {
            assert!(ts_decode(&out[..cut], &mut back).is_err(), "cut at {cut}");
        }
        for at in (0..n).step_by(1009) {
            let mut b = out[..n].to_vec();
            b[at] ^= 0x01;
            assert!(ts_decode(&b, &mut back).is_err(), "flip at {at}");
        }
        // ... and of a small record, every one.
        let small = initial(&mut v);
        let m = ts_encode(&small, &mut out).unwrap();
        for cut in 0..m {
            assert!(ts_decode(&out[..cut], &mut back).is_err(), "cut at {cut}");
        }
    }

    const TS_REFERENCE_DIGEST: &str =
        "c9258d1d493db0fca6e338d6d11ed96f8c8a7ffb63eba34f19fb5db90ebf9079";

    /// A digest that verifies does not make the record readable: another
    /// version, a reserved flag, an IPv4 address with bytes past its four,
    /// a trailing byte are each refused by name.
    #[test]
    fn the_decoder_is_strict_past_the_digest() {
        let mut v = Vault {
            backend: 1,
            ..Vault::default()
        };
        let st = initial(&mut v);
        let mut out = vec![0u8; TS_CKPT_MAX];
        let n = ts_encode(&st, &mut out).unwrap();
        let refused = |edit: &dyn Fn(&mut Vec<u8>)| {
            let mut b = out[..n].to_vec();
            edit(&mut b);
            redigest(&mut b);
            ts_decode(&b, &mut Box::new(TsState::zero())).err()
        };
        assert_eq!(refused(&|b| b[4] = 2), Some(CkptError::Version));
        assert_eq!(refused(&|b| b[6] |= 2), Some(CkptError::Reserved));
        // `family` is at 40, `client_ip` at 41..57.
        assert_eq!(refused(&|b| b[41 + 15] = 1), Some(CkptError::Reserved));
        assert_eq!(refused(&|b| b.insert(n - 32, 0)), Some(CkptError::Trailing));
        // And the encoder refuses what the decoder would.
        let mut bad = Box::new(st);
        bad.service_ip[15] = 1;
        assert_eq!(ts_encode(&bad, &mut out), Err(CkptError::Reserved));
    }

    /// Each bound holds exactly: at it the state round-trips, one past it
    /// is refused.
    #[test]
    fn the_bounds_are_a_whole_record_and_no_more() {
        let mut v = Vault {
            backend: 1,
            ..Vault::default()
        };
        let base = Box::new(initial(&mut v));
        let mut out = vec![0u8; TS_CKPT_MAX];
        let cases: [fn(&mut TsState, usize); 2] = [
            |s, n| {
                s.deliv_count = 1;
                s.next_delivery = 2;
                s.deliv[0].id = 1;
                s.deliv[0].len = n as u16;
            },
            |s, n| {
                s.recv_len = n as u16;
                s.rcv_nxt = s.rcv_nxt.wrapping_add(n as u32);
            },
        ];
        for (i, (f, bound)) in cases.iter().zip([TS_DELIV_BYTES, TS_RECV_MAX]).enumerate() {
            let mut s = base.clone();
            f(&mut s, bound);
            let n = ts_encode(&s, &mut out).expect("at the bound");
            let mut back = Box::new(TsState::zero());
            ts_decode(&out[..n], &mut back).unwrap();
            assert_eq!(*back, *s, "case {i}");
            let mut s = base.clone();
            f(&mut s, bound + 1);
            assert_eq!(ts_encode(&s, &mut out), Err(CkptError::Bounds), "case {i}");
        }
    }

    #[test]
    fn a_whole_record_crosses_in_chunks_and_whole_record_deltas() {
        let mut v = Vault {
            backend: 1,
            ..Vault::default()
        };
        let st = reference(&mut v);
        let mut rec = vec![0u8; TS_CKPT_MAX];
        let n = ts_encode(&st, &mut rec).unwrap();
        let id = CkptId {
            checkpoint_id: 7,
            flow_id: st.flow_id,
            flow_epoch: st.flow_epoch,
            mirror_generation: st.mirror_generation,
            total: n as u32,
        };
        let count = ckpt_chunk_count(n);
        assert!(count > 1 && usize::from(count) <= CKPT_MAX_CHUNKS);
        let mut asm: Box<CkptAssembler> = Box::new(CkptAssembler::new(st.flow_id, 1));
        let mut chain = ckpt_chain_seed(&id);
        let mut chunks = Vec::new();
        let mut last = Err(CkptReject::Gap);
        for i in 0..count {
            let mut c = vec![0u8; CKPT_CHUNK_MAX];
            let m = ckpt_write_chunk(&id, &rec[..n], i, &mut chain, &mut c).unwrap();
            c.truncate(m);
            assert_eq!(&c[..4], b"WHCC");
            last = asm.offer(&c);
            chunks.push(c);
        }
        assert_eq!(last, Ok(CkptOffer::Complete));
        let (mut scratch, mut shadow) = (Box::new(TsState::zero()), Box::new(TsState::zero()));
        asm.publish(&mut scratch, &mut shadow).unwrap();
        assert_eq!(*shadow, *st);
        // A replay of the published checkpoint's first chunk only restarts
        // its assembly; an older checkpoint's chunk is stale, published or
        // not.
        assert_eq!(asm.offer(&chunks[0]), Ok(CkptOffer::Accepted));
        let older = CkptId {
            checkpoint_id: 6,
            ..id
        };
        let mut c = vec![0u8; CKPT_CHUNK_MAX];
        let mut ch = ckpt_chain_seed(&older);
        let m = ckpt_write_chunk(&older, &rec[..n], 0, &mut ch, &mut c).unwrap();
        assert_eq!(asm.offer(&c[..m]), Err(CkptReject::Stale));

        // A whole record's plaintext delivered, and a whole protected record
        // written, each one delta.
        let mut payload = vec![0u8; MD_PAYLOAD_MAX];
        let consume = 16_645u16;
        let plain = vec![0xAB; 16_384];
        let m = md_rx_record(&mut payload, consume, st.read_epoch, st.read_seq, 3, &plain).unwrap();
        let mut h = MdHdr {
            kind: MdKind::RxRecord,
            flow_id: st.flow_id,
            flow_epoch: st.flow_epoch,
            mirror_generation: st.mirror_generation,
            base_checkpoint: 7,
            seq: 1,
            prev: [0; 32],
            payload_len: 0,
            digest: [0; 32],
        };
        let mut f = vec![0u8; MD_FRAME_MAX];
        let fl = md_encode(&mut h, &payload[..m], &mut f).unwrap();
        let (hh, pl) = md_parse(&f[..fl]).unwrap();
        md_apply(&mut shadow, &mut scratch, hh.kind, pl).unwrap();
        assert_eq!(shadow.deliv_count, 3);
        assert_eq!(&shadow.deliv[2].bytes[..], &plain[..]);
        assert_eq!(shadow.recv_len, 0);
        // A delta of another version, or past the payload bound, is refused.
        let mut other = f[..fl].to_vec();
        other[4] = 2;
        assert_eq!(md_parse(&other).err(), Some(CkptError::Version));
        assert!(md_encode(&mut h, &vec![0; MD_PAYLOAD_MAX + 1], &mut f).is_none());

        let ct = vec![0x17; 16_645];
        let m = md_tx_record(
            &mut payload,
            1,
            shadow.write_epoch,
            shadow.write_seq,
            &ct,
            shadow.out_bytes + 5,
        )
        .unwrap();
        md_apply(&mut shadow, &mut scratch, MdKind::TxRecord, &payload[..m]).unwrap();
        assert_eq!(usize::from(shadow.send_len), 16_645);
    }

    /// An inbound KeyUpdate that asks for ours leaves the answer owed —
    /// through a later one that asks for none — until our own rotation.
    #[test]
    fn a_key_update_answer_owed_stays_owed_until_our_rotation() {
        let mut v = Vault {
            backend: 1,
            ..Vault::default()
        };
        let mut st = Box::new(initial(&mut v));
        let mut scratch = Box::new(TsState::zero());
        let mut p = [0u8; 64];
        let ku = |p: &mut [u8], dir, epoch, purpose, requested| {
            let r = TsVaultRef {
                backend: 1,
                purpose,
                object: epoch,
                generation: 1,
                epoch,
            };
            md_key_update(p, dir, epoch, &r, &[0; 32], requested).unwrap()
        };
        let n = ku(&mut p, MD_DIR_IN, 4, TS_VAULT_READ, true);
        assert_eq!(n, 54, "an inbound KeyUpdate carries `requested`");
        md_apply(&mut st, &mut scratch, MdKind::KeyUpdate, &p[..n]).unwrap();
        assert!(st.key_update_owed);
        let n = ku(&mut p, MD_DIR_IN, 5, TS_VAULT_READ, false);
        md_apply(&mut st, &mut scratch, MdKind::KeyUpdate, &p[..n]).unwrap();
        assert!(st.key_update_owed, "still owed");
        // `requested` is 0 or 1, and an inbound KeyUpdate must carry it.
        let n = ku(&mut p, MD_DIR_IN, 6, TS_VAULT_READ, false);
        p[n - 1] = 2;
        assert!(md_apply(&mut st, &mut scratch, MdKind::KeyUpdate, &p[..n]).is_err());
        assert!(md_apply(&mut st, &mut scratch, MdKind::KeyUpdate, &p[..n - 1]).is_err());
        let n = ku(&mut p, MD_DIR_OUT, 4, TS_VAULT_WRITE, true);
        assert_eq!(n, 53, "an outbound one does not");
        md_apply(&mut st, &mut scratch, MdKind::KeyUpdate, &p[..n]).unwrap();
        assert!(!st.key_update_owed, "our rotation answers it");
    }

    #[test]
    fn a_pairing_round_trips_and_is_refused_unless_whole_and_known() {
        let body = pair_body(TcRole::Primary, TcMode::CrashContinuous);
        assert_eq!(body.len(), 47);
        let p = TcPair::decode(&body).unwrap();
        let mut b = [0u8; TC_PAIR_LEN];
        p.encode(&mut b);
        assert_eq!(b, body);
        assert!(TcPair::decode(&body[..46]).is_none());
        assert!(TcPair::decode(&[&body[..], &[0]].concat()).is_none());
        for (at, bad) in [(20, 3), (21, 0), (22, 9)] {
            let mut x = body;
            x[at] = bad;
            assert!(TcPair::decode(&x).is_none(), "byte {at}");
        }
    }

    #[test]
    fn a_checkpoint_and_its_deltas_round_trip_into_an_identical_shadow() {
        let mut p = pair(TcMode::CrashContinuous);
        for i in 0..4u8 {
            p.client_send(&[i; 40]);
        }
        let (r, ev) = p.a.produce(1, b"puback");
        assert_eq!(r, TcProduced::Pending);
        p.deltas.extend(deltas_of(&ev));
        assert!(p.deltas.len() >= 9, "segment, record, production deltas");
        let acked = p.mirror();
        assert_eq!(acked, p.a.p.flow(&FLOW).unwrap().delta_seq);
        assert_eq!(
            p.a.st(),
            p.b.st(),
            "the standby holds the primary byte for byte"
        );
        let fa = p.a.p.flow(&FLOW).unwrap();
        assert!(fa.gate.covered());
        assert_eq!(fa.accepted_through(), 1, "the production is in the horizon");
        // The cut the primary exports is reproduced by the shadow.
        let ev = p.a.ctl(&with_handle(tc_op::CUT_EXPORT, p.ha, &[]), 0);
        let cut = ev.iter().find(|(k, _)| *k == tc_evt::CUT).unwrap().1[8..].to_vec();
        let ev = p.b.ctl(&with_handle(tc_op::CUT_IMPORT, p.hb, &cut), 0);
        assert_eq!(status(&ev, tc_op::CUT_IMPORT).status, tc_st::OK);
    }

    // ── the horizon gate ──────────────────────────────────────────────────

    #[test]
    fn the_horizon_gate_holds_ack_emission_delivery_and_production_under_loss_and_reorder() {
        let mut p = pair(TcMode::CrashContinuous);
        p.client_send(b"one");
        p.client_send(b"two");
        // Nothing acknowledged yet: the ACK the peer sees stays at the
        // checkpoint and nothing is delivered.
        let segs = p.a.tx(0);
        assert!(segs.iter().all(|s| s.1 == 5001), "the exposed ACK is held");
        let mut got = Vec::new();
        p.a.p.deliver(&FLOW, &mut |id, _| got.push(id));
        assert!(got.is_empty(), "no delivery before the standby holds it");
        // A production is sealed and journaled, but not emitted.
        let (r, ev) = p.a.produce(1, b"resp");
        assert_eq!(r, TcProduced::Pending);
        p.deltas.extend(deltas_of(&ev));
        assert!(
            p.a.tx(0).iter().all(|s| s.5.is_empty()),
            "no byte past the send horizon"
        );
        assert_eq!(p.a.p.flow(&FLOW).unwrap().accepted_through(), 0);

        // The mirror link loses delta 2 and delivers delta 3: the standby
        // refuses the gap (and needs a full checkpoint), the primary's
        // horizon does not move past what was acknowledged.
        let d = p.deltas.clone();
        let ev = p.b.ctl(&with_handle(tc_op::DELTA_APPLY, p.hb, &d[0]), 0);
        assert_eq!(ev[0].0, tc_evt::APPLIED);
        let ev = p.b.ctl(&with_handle(tc_op::DELTA_APPLY, p.hb, &d[0]), 0);
        assert_eq!(
            ev[0].0,
            tc_evt::APPLIED,
            "an identical retry is a duplicate"
        );
        let ev = p.b.ctl(&with_handle(tc_op::DELTA_APPLY, p.hb, &d[2]), 0);
        assert_eq!(
            (ev[0].0, ev[0].1[8]),
            (tc_evt::REJECTED, tc_rej::ORDER),
            "a gap is refused"
        );
        p.a.ctl(&with_handle(tc_op::DELTA_ACK, p.ha, &1u64.to_le_bytes()), 0);
        let lim = p.a.p.flow(&FLOW).unwrap().gate.limits;
        assert!(
            ts_seq_le(lim.rx_upto, p.b.st().rcv_nxt),
            "the ACK horizon is the standby's"
        );
        // Acks out of order: a stale one changes nothing.
        p.a.ctl(&with_handle(tc_op::DELTA_ACK, p.ha, &3u64.to_le_bytes()), 0);
        let after3 = p.a.p.flow(&FLOW).unwrap().gate.limits;
        p.a.ctl(&with_handle(tc_op::DELTA_ACK, p.ha, &2u64.to_le_bytes()), 0);
        assert_eq!(
            p.a.p.flow(&FLOW).unwrap().gate.limits,
            after3,
            "the horizon never retreats"
        );
        let segs = p.a.tx(0);
        assert!(
            segs.iter().all(|s| s.1 == after3.rx_upto),
            "the ACK shown is the acked horizon's"
        );
    }

    #[test]
    fn a_full_journal_closes_the_window_and_refuses_the_producer() {
        let mut p = pair(TcMode::CrashContinuous);
        let mut pid = 1;
        loop {
            let (r, ev) = p.a.produce(pid, b"x");
            p.deltas.extend(deltas_of(&ev));
            if r != TcProduced::Pending {
                break;
            }
            pid += 1;
        }
        assert_eq!(
            pid as usize,
            TC_GATE_J + 1,
            "the journal bounds what is unacknowledged"
        );
        assert!(p.a.p.flow(&FLOW).unwrap().backpressure_events > 0);
        assert!(p.a.tx(0).iter().all(|s| s.2 == 0), "the window is closed");
        p.mirror();
        assert_eq!(
            p.a.produce(pid, b"x").0,
            TcProduced::Pending,
            "acks free room"
        );
    }

    #[test]
    fn a_key_update_is_a_barrier_until_the_standby_installs_the_epoch() {
        let mut p = pair(TcMode::CrashContinuous);
        let mut ev = Vec::new();
        assert!(p
            .a
            .p
            .key_update(&FLOW, &mut p.a.v, &mut |f| ev.extend_from_slice(f)));
        p.deltas.extend(deltas_of(&split(&ev)));
        assert_eq!(p.a.st().write_epoch, 4);
        assert_eq!(
            p.a.produce(1, b"new").0,
            TcProduced::NotReady,
            "no record under epoch 4 yet"
        );
        p.mirror();
        assert!(
            p.b.v.holds(&FLOW, TS_VAULT_WRITE, 4),
            "the standby derived it in-vault"
        );
        assert_eq!(p.a.produce(1, b"new").0, TcProduced::Pending);
        assert_eq!(p.a.st().tx_records().last().unwrap().epoch, 4);
    }

    // ── import, arm, activate ─────────────────────────────────────────────

    fn activate_body(epoch: u32, fence: u32, cap: [u8; 16]) -> Vec<u8> {
        [&epoch.to_le_bytes()[..], &fence.to_le_bytes(), &cap].concat()
    }

    #[test]
    fn a_standby_activates_only_armed_fenced_higher_and_with_its_own_token() {
        let mut p = pair(TcMode::CrashContinuous);
        p.client_send(b"hello");
        let (_, ev) = p.a.produce(1, b"world");
        p.deltas.extend(deltas_of(&ev));
        p.mirror();
        let primary_bytes = p.a.tx(0);
        let cap = [0x77; 16];
        let act = |p: &mut Pair, e, f| {
            let ev = p.b.ctl(
                &with_handle(tc_op::ACTIVATE, p.hb, &activate_body(e, f, cap)),
                50,
            );
            status(&ev, tc_op::ACTIVATE)
        };
        // Not armed: refused before the authority is asked.
        let s = act(&mut p, 2, 9);
        assert_eq!(
            (s.status, s.reason),
            (tc_st::UNAUTHORIZED, tc_act::NOT_ARMED)
        );
        assert!(p.b.auth.asked.borrow().is_empty());
        let ev = p.b.ctl(&with_handle(tc_op::EMISSION_ARM, p.hb, &[]), 0);
        assert_eq!(status(&ev, tc_op::EMISSION_ARM).status, tc_st::OK);
        // Armed: silent, and early segments are held, not answered.
        p.b.rx(p.client_seq, 1001, b"early");
        assert!(p.b.tx(10).is_empty(), "an armed standby emits nothing");
        assert_eq!(p.b.p.flow(&FLOW).unwrap().early.count, 1);
        assert_eq!(act(&mut p, 2, 0).reason, tc_act::NO_FENCE);
        assert_eq!(act(&mut p, 1, 9).reason, tc_act::EPOCH_NOT_HIGHER);
        // A token the authority did not mint for this anchor: its refusal.
        let s = act(&mut p, 2, 9);
        assert_eq!((s.status, s.reason), (tc_st::UNAUTHORIZED, 0x03));
        let asked = p.b.auth.asked.borrow()[0];
        assert_eq!(&asked[0..16], &FLOW);
        assert_eq!(u32::from_le_bytes(asked[16..20].try_into().unwrap()), 2);
        assert_eq!(
            &asked[20..28],
            &ANCHOR_B,
            "the provider names its own anchor"
        );
        assert_eq!(u32::from_le_bytes(asked[28..32].try_into().unwrap()), 9);
        assert_eq!(&asked[32..48], &cap);
        assert!(p.b.tx(10).is_empty());
        // The token minted for (flow, 2, this anchor, 9): emission enabled.
        p.b.auth.good = Some(asked);
        let s = act(&mut p, 2, 9);
        assert_eq!(s.status, tc_st::OK);
        let f = p.b.p.flow(&FLOW).unwrap();
        assert!(f.emitting && f.st.flow_epoch == 2);
        // It retransmits what the primary may have emitted, byte for byte,
        // from SND.UNA, once its imported RTO fires on its own clock.
        let segs = p.b.tx(50 + 200);
        let data: Vec<_> = segs.iter().filter(|s| !s.5.is_empty()).collect();
        let theirs: Vec<_> = primary_bytes.iter().filter(|s| !s.5.is_empty()).collect();
        assert!(!data.is_empty());
        assert_eq!(data[0].0, theirs[0].0);
        assert_eq!(data[0].5, theirs[0].5, "byte-identical ciphertext");
        assert!(segs.iter().all(|s| s.4 == 2), "under the new epoch");
    }

    #[test]
    fn the_emission_disable_hook_stops_everything_and_reports_its_custody_generation() {
        let mut p = pair(TcMode::PlannedOnly);
        p.client_send(b"in");
        let ev = p.a.ctl(&with_handle(tc_op::EMISSION_DISABLE, p.ha, &[]), 0);
        let s = status(&ev, tc_op::EMISSION_DISABLE);
        assert_eq!((s.status, s.value), (tc_st::OK, 0x101));
        let ev = p.a.ctl(&with_handle(tc_op::EMISSION_DISABLE, p.ha, &[]), 0);
        assert_eq!(
            status(&ev, tc_op::EMISSION_DISABLE).value,
            0x102,
            "each cutoff its own"
        );
        assert!(p.a.tx(10_000).is_empty());
        assert_eq!(p.a.produce(1, b"out").0, TcProduced::NotReady);
        let mut got = 0;
        p.a.p.deliver(&FLOW, &mut |_, _| got += 1);
        assert_eq!(got, 0);
    }

    #[test]
    fn a_stale_handle_is_refused_before_anything_changes() {
        let mut p = pair(TcMode::CrashContinuous);
        let stale = TcHandle {
            slot: p.ha.slot,
            generation: p.ha.generation + 100,
        };
        let before = *p.a.st();
        let ev =
            p.a.ctl(&with_handle(tc_op::EMISSION_DISABLE, stale, &[]), 0);
        assert_eq!(
            status(&ev, tc_op::EMISSION_DISABLE).status,
            tc_st::STALE_HANDLE
        );
        assert!(p.a.p.flow(&FLOW).unwrap().emitting);
        assert_eq!(*p.a.st(), before);
    }

    // ── reset suppression ─────────────────────────────────────────────────

    #[test]
    fn a_migrated_flow_is_dropped_silently_never_reset() {
        let mut h = Host::new(ANCHOR_A, 1);
        let other = [0x0F; 16];
        assert_eq!(
            h.p.classify(&FLOW, 0),
            TcDisposition::Reset,
            "unknown: the ordinary path"
        );
        let body = [&FLOW[..], &4u32.to_le_bytes(), &1000u32.to_le_bytes()].concat();
        let ev = h.ctl(&frame(tc_op::TOMBSTONE, &[&[0u8; 8], &body]), 0);
        assert_eq!(status(&ev, tc_op::TOMBSTONE).value, 1);
        assert_eq!(h.p.classify(&FLOW, 500), TcDisposition::DropSilently);
        assert_eq!(h.p.classify(&other, 500), TcDisposition::Reset);
        assert_eq!(h.p.classify(&FLOW, 1000), TcDisposition::Reset, "expired");
        assert_eq!(h.p.tombs.suppressed, 1);
        // A full table refuses rather than evicts.
        for i in 0..4u8 {
            let b = [&[i; 16][..], &1u32.to_le_bytes(), &9000u32.to_le_bytes()].concat();
            h.ctl(&frame(tc_op::TOMBSTONE, &[&[0u8; 8], &b]), 2000);
        }
        let ev = h.ctl(&frame(tc_op::TOMBSTONE, &[&[0u8; 8], &body]), 2000);
        assert_eq!(status(&ev, tc_op::TOMBSTONE).status, tc_st::CAPACITY);
    }

    #[test]
    fn a_retired_primary_keeps_no_state_and_answers_no_late_segment_with_a_reset() {
        let mut p = pair(TcMode::PlannedOnly);
        assert_eq!(p.a.p.classify(&FLOW, 0), TcDisposition::Deliver);
        let ev = p.a.ctl(&with_handle(tc_op::RETIRE, p.ha, &[]), 100);
        assert_eq!(status(&ev, tc_op::RETIRE).status, tc_st::OK);
        assert!(p.a.p.flow(&FLOW).is_none());
        assert!(
            !p.a.v.holds(&FLOW, TS_VAULT_WRITE, 3),
            "its secrets destroyed"
        );
        assert_eq!(p.a.p.classify(&FLOW, 200), TcDisposition::DropSilently);
        assert!(p.a.tx(200).is_empty());
    }

    /// A record whose plaintext is past any small bound crosses a
    /// crash-continuous pair whole: the checkpoint in `WHCC` chunks, the
    /// record one delta, and the standby holds the primary byte for byte.
    #[test]
    fn a_whole_record_crosses_a_crash_continuous_pair() {
        let mut p = pair(TcMode::CrashContinuous);
        let pt = vec![0x42u8; 2000];
        p.client_send(&pt);
        assert!(
            !p.deltas.is_empty(),
            "{:?} {:?}",
            p.a.p.last_refusal,
            p.a.p.counters
        );
        let acked = p.mirror();
        let fa = p.a.p.flow(&FLOW).unwrap();
        assert_eq!(fa.st.next_delivery, 2, "the whole record is one delivery");
        assert_eq!(acked, fa.delta_seq);
        assert!(p.a.st() == p.b.st(), "the standby is the primary");
    }

    /// Two segments past a hole may meet end to start: both are held, and
    /// the segment that fills the hole takes them in.
    #[test]
    fn adjacent_out_of_order_segments_are_held_and_reassembled() {
        let mut v = Vault::default();
        let mut st = Box::new(initial(&mut v));
        let mut scratch = Box::new(TsState::zero());
        let mut p = [0u8; 64];
        let n = md_rx_segment(&mut p, 5001 + 10, &[2; 10]).unwrap();
        md_apply(&mut st, &mut scratch, MdKind::RxSegment, &p[..n]).unwrap();
        let n = md_rx_segment(&mut p, 5001 + 20, &[3; 10]).unwrap();
        md_apply(&mut st, &mut scratch, MdKind::RxSegment, &p[..n])
            .expect("a segment starting where the one before it ends");
        assert_eq!(st.ooo_count, 2);
        let n = md_rx_segment(&mut p, 5001, &[1; 10]).unwrap();
        md_apply(&mut st, &mut scratch, MdKind::RxSegment, &p[..n]).unwrap();
        assert_eq!((st.ooo_count, st.rcv_nxt, st.recv_len), (0, 5031, 30));
        assert_eq!(&st.recv[..30], &[[1u8; 10], [2; 10], [3; 10]].concat()[..]);
        // Overlap is still refused.
        let n = md_rx_segment(&mut p, 5031 + 10, &[4; 10]).unwrap();
        md_apply(&mut st, &mut scratch, MdKind::RxSegment, &p[..n]).unwrap();
        let n = md_rx_segment(&mut p, 5031 + 15, &[5; 10]).unwrap();
        assert_eq!(
            md_apply(&mut st, &mut scratch, MdKind::RxSegment, &p[..n]),
            Err(CkptError::SequenceImpossible)
        );
    }

    /// Once published, a checkpoint is not taken again: a replay of its
    /// chunks and commit cannot roll the shadow back behind the deltas
    /// applied since.
    #[test]
    fn a_published_checkpoint_replayed_does_not_roll_the_shadow_back() {
        let mut p = pair(TcMode::CrashContinuous);
        let ev = p.a.ctl(
            &with_handle(tc_op::CHECKPOINT_BEGIN, p.ha, &8u64.to_le_bytes()),
            0,
        );
        let chunks: Vec<Vec<u8>> = ev
            .iter()
            .filter(|(k, _)| *k == tc_evt::CHUNK)
            .map(|(_, c)| c[8..].to_vec())
            .collect();
        for c in &chunks {
            assert!(p
                .b
                .ctl(&with_handle(tc_op::CHECKPOINT_NEXT, p.hb, c), 0)
                .is_empty());
        }
        let commit = with_handle(tc_op::CHECKPOINT_COMMIT, p.hb, &8u64.to_le_bytes());
        assert_eq!(p.b.ctl(&commit, 0)[0].0, tc_evt::APPLIED);
        p.client_send(b"after the checkpoint");
        assert!(p.mirror() > 0);
        assert!(p.a.st() == p.b.st());
        for c in &chunks {
            let ev = p.b.ctl(&with_handle(tc_op::CHECKPOINT_NEXT, p.hb, c), 0);
            assert_eq!((ev[0].0, ev[0].1[8]), (tc_evt::REJECTED, tc_rej::CHUNK));
        }
        let ev = p.b.ctl(&commit, 0);
        assert_eq!((ev[0].0, ev[0].1[8]), (tc_evt::REJECTED, tc_rej::COMMIT));
        assert!(p.a.st() == p.b.st(), "the shadow still holds every delta");
    }

    /// An aborted crash-continuous pairing leaves the primary unprotected,
    /// not stalled: nothing waits on a standby that is gone.
    #[test]
    fn an_aborted_strict_primary_runs_on_unprotected() {
        let mut p = pair(TcMode::CrashContinuous);
        p.client_send(b"held for the standby");
        let mut got = Vec::new();
        p.a.p.deliver(&FLOW, &mut |id, _| got.push(id));
        assert!(got.is_empty(), "held while paired");
        let ev = p.a.ctl(&with_handle(tc_op::ABORT, p.ha, &[]), 0);
        assert_eq!(status(&ev, tc_op::ABORT).status, tc_st::OK);
        p.a.p.deliver(&FLOW, &mut |id, _| got.push(id));
        assert_eq!(got, vec![1], "delivered once unpaired");
        assert!(
            p.a.tx(0).iter().any(|s| s.1 == p.a.st().rcv_nxt),
            "the ACK is no longer held"
        );
    }

    /// An operation of the other side of the pair is refused before it
    /// touches anything: a primary takes no deltas or chunks, a standby
    /// exports nothing.
    #[test]
    fn each_operation_belongs_to_one_side_of_the_pair() {
        let mut p = pair(TcMode::CrashContinuous);
        let before = *p.a.st();
        let ev = p.a.ctl(&with_handle(tc_op::DELTA_APPLY, p.ha, &[0; 8]), 0);
        assert_eq!(status(&ev, tc_op::DELTA_APPLY).status, tc_st::INVALID);
        let ev = p.a.ctl(&with_handle(tc_op::EMISSION_ARM, p.ha, &[]), 0);
        assert_eq!(status(&ev, tc_op::EMISSION_ARM).status, tc_st::INVALID);
        assert!(*p.a.st() == before);
        let ev = p.b.ctl(
            &with_handle(tc_op::CHECKPOINT_BEGIN, p.hb, &9u64.to_le_bytes()),
            0,
        );
        assert_eq!(status(&ev, tc_op::CHECKPOINT_BEGIN).status, tc_st::INVALID);
        assert!(ev.iter().all(|(k, _)| *k != tc_evt::CHUNK));
    }

    /// Zeroed heap memory as a `T`.
    ///
    /// # Safety
    /// All-zero bytes must be a value of `T`.
    #[expect(
        clippy::unnecessary_box_returns,
        reason = "the value is built in heap memory: it is larger than a test thread's stack"
    )]
    unsafe fn zeroed<T>() -> Box<T> {
        // SAFETY: the caller's.
        unsafe { Box::<T>::new_zeroed().assume_init() }
    }

    /// The zero record, an assembler for no flow and an empty early-segment
    /// queue are all-zero memory, field for field: a provider holding them
    /// is initialised by zeroing it.
    #[test]
    fn the_empty_values_are_zeroed_memory() {
        static ZERO_STATE: TsState = TsState::zero();
        static EMPTY_ASM: CkptAssembler = CkptAssembler::new([0; 16], 0);
        static EMPTY_EARLY: TcEarly = TcEarly::new();
        // SAFETY: each comparison below is the claim; a byte pattern that is
        // not a value of the type would fail it.
        unsafe {
            assert!(*zeroed::<TsState>() == ZERO_STATE);
            assert!(*zeroed::<CkptAssembler>() == EMPTY_ASM);
            assert!(*zeroed::<TcEarly>() == EMPTY_EARLY);
            assert!(*zeroed::<MdOrder>() == MdOrder::after_checkpoint([0; 16], 0, 0, 0, [0; 32]));
        }
        // The zero record's enums are their first variants; the one a
        // standby starts from is a different, established value.
        assert_eq!(
            (ZERO_STATE.tcp, ZERO_STATE.tls_phase),
            (TsTcp::Established, TsTlsPhase::Established)
        );
        assert!(TsState::established() != ZERO_STATE);
        // In memory a wire enum is its position; on the wire, its byte.
        assert_eq!((TcRole::Primary.wire(), TcRole::Standby.wire()), (1, 2));
        assert_eq!(
            (TcMode::PlannedOnly.wire(), TcMode::CrashContinuous.wire()),
            (1, 2)
        );
        assert_eq!((TsTcp::Established.wire(), TsTcp::TimeWait.wire()), (4, 10));
        assert_eq!(TsTcp::Reset.wire(), 11);
        assert_eq!((MdKind::Reset.wire(), MdKind::QuicDelta.wire()), (11, 12));
        for v in 0..=u8::MAX {
            for w in [
                TcRole::from_u8(v).map(TcRole::wire),
                TcMode::from_u8(v).map(TcMode::wire),
                TcTransport::from_u8(v).map(TcTransport::wire),
                TsTcp::from_u8(v).map(TsTcp::wire),
                TsTlsPhase::from_u8(v).map(TsTlsPhase::wire),
                MdKind::from_u8(v).map(MdKind::wire),
            ]
            .into_iter()
            .flatten()
            {
                assert_eq!(w, v);
            }
        }
    }

    /// A stream counted from its checkpoint: the next delta is one past the
    /// last applied, a retry inside the window is a duplicate, one older is
    /// stale.
    #[test]
    fn the_delta_order_counts_from_its_checkpoint() {
        let base = [0x11; 32];
        let mut o = MdOrder::after_checkpoint(FLOW, 1, 1, 7, base);
        let hdr = |seq: u64, prev: [u8; 32], digest: [u8; 32]| MdHdr {
            kind: MdKind::Fin,
            flow_id: FLOW,
            flow_epoch: 1,
            mirror_generation: 1,
            base_checkpoint: 7,
            seq,
            prev,
            payload_len: 0,
            digest,
        };
        assert_eq!(o.applied(), 0);
        assert_eq!(o.verify(&hdr(0, base, [1; 32])), Err(MdReject::Conflict));
        assert_eq!(o.verify(&hdr(2, base, [1; 32])), Err(MdReject::Gap));
        let n = MD_DUP_WINDOW as u64 + 1;
        let mut prev = base;
        for seq in 1..=n {
            let h = hdr(seq, prev, [seq as u8; 32]);
            assert_eq!(o.verify(&h), Ok(MdVerdict::Apply));
            o.commit(&h);
            prev = h.digest;
        }
        assert_eq!(o.applied(), n);
        assert_eq!(
            o.verify(&hdr(2, [0; 32], [2; 32])),
            Ok(MdVerdict::Duplicate)
        );
        assert_eq!(
            o.verify(&hdr(n, [0; 32], [0xEE; 32])),
            Err(MdReject::Conflict)
        );
        assert_eq!(o.verify(&hdr(1, [0; 32], [1; 32])), Err(MdReject::Stale));
        assert_eq!(
            o.verify(&hdr(n + 1, [0; 32], [0; 32])),
            Err(MdReject::Conflict)
        );
        assert_eq!(o.verify(&hdr(n + 2, prev, [0; 32])), Err(MdReject::Gap));
        assert_eq!(o.verify(&hdr(n + 1, prev, [0; 32])), Ok(MdVerdict::Apply));
    }

    // ── a reset, and the timers ──────────────────────────────────────────

    fn apply(st: &mut TsState, kind: MdKind, p: &[u8]) -> Result<(), CkptError> {
        let mut scratch = Box::new(TsState::zero());
        md_apply(st, &mut scratch, kind, p)
    }

    fn tx(st: &mut TsState, n: usize) {
        let mut p = vec![0u8; 64 + n];
        let ct = vec![0x17; n];
        let m = md_tx_record(
            &mut p,
            st.next_production,
            st.write_epoch,
            st.write_seq,
            &ct,
            st.out_bytes + n as u64,
        )
        .unwrap();
        apply(st, MdKind::TxRecord, &p[..m]).unwrap();
    }

    fn peer_ack(st: &mut TsState, ack: u32) {
        let mut p = [0u8; 8];
        let m = md_peer_ack(&mut p, ack, 65_535).unwrap();
        apply(st, MdKind::PeerAck, &p[..m]).unwrap();
    }

    fn fin(st: &mut TsState, dir: u8) {
        let mut p = [0u8; 1];
        let m = md_dir(&mut p, dir).unwrap();
        apply(st, MdKind::Fin, &p[..m]).unwrap();
    }

    fn timers(st: &mut TsState, t: &MdTimers) -> Result<(), CkptError> {
        let mut p = [0u8; 4 * TS_TIMER_WORDS];
        let m = md_timers(&mut p, t).unwrap();
        apply(st, MdKind::Timers, &p[..m])
    }

    /// A reset ends the record: it validates (it is what a standby's shadow
    /// becomes), its timers stop, it applies nothing more, and it is never
    /// encoded — there is no connection left to export or take over.
    #[test]
    fn a_reset_ends_the_record_and_nothing_follows_it() {
        let mut v = Vault {
            backend: 1,
            ..Vault::default()
        };
        for dir in [MD_DIR_IN, MD_DIR_OUT] {
            let mut st = Box::new(initial(&mut v));
            st.idle_ms = 30_000;
            st.idle_rem_ms = 10_000;
            tx(&mut st, 100);
            assert_eq!(
                st.retx_rem_ms, st.rto_ms,
                "data out arms the retransmission timer"
            );
            let mut p = [0u8; 9];
            let m = md_reset(&mut p, dir, st.snd_nxt, st.rcv_nxt).unwrap();
            assert_eq!(m, 9);
            apply(&mut st, MdKind::Reset, &p[..m]).unwrap();
            assert_eq!(st.tcp, TsTcp::Reset);
            assert_eq!(ts_timer_remainders(&st), [0; 6], "every timer stops");
            assert_eq!(ts_validate(&st), Ok(()));
            let mut out = vec![0u8; TS_CKPT_MAX];
            assert_eq!(ts_encode(&st, &mut out), Err(CkptError::UnsupportedState));
            assert!(
                tc_state_digest(&st, &mut out).is_none(),
                "no cut of an ended flow"
            );
            // Nothing applies after it, not another reset, not a FIN.
            assert_eq!(
                apply(&mut st, MdKind::Reset, &p[..m]),
                Err(CkptError::SequenceImpossible)
            );
            let mut f = [0u8; 1];
            let k = md_dir(&mut f, MD_DIR_IN).unwrap();
            assert!(apply(&mut st, MdKind::Fin, &f[..k]).is_err());
        }
        // A direction that is neither, or a short payload, is refused.
        let mut st = Box::new(initial(&mut v));
        let mut p = [0u8; 9];
        let m = md_reset(&mut p, 3, 1, 1).unwrap();
        assert_eq!(
            apply(&mut st, MdKind::Reset, &p[..m]),
            Err(CkptError::UnknownField)
        );
        assert!(apply(&mut st, MdKind::Reset, &p[..8]).is_err());
        assert_eq!(st.tcp, TsTcp::Established, "refused, nothing changed");
        // A reset record with a timer still armed does not validate.
        let mut bad = Box::new(initial(&mut v));
        bad.tcp = TsTcp::Reset;
        bad.closing_rem_ms = 5;
        assert_eq!(ts_validate(&bad), Err(CkptError::SequenceImpossible));
    }

    /// Each timer is armed only where the state runs it, and a remainder
    /// runs down to due — never to disarmed.
    #[test]
    fn a_timer_is_armed_only_in_the_states_that_run_it() {
        let mut v = Vault {
            backend: 1,
            ..Vault::default()
        };
        let st = initial(&mut v);
        type Arm = fn(&mut TsState);
        let cases: [(&str, Arm); 7] = [
            ("retransmission with nothing outstanding", |s| {
                s.retx_rem_ms = 300
            }),
            ("idle with no period", |s| s.idle_rem_ms = 5),
            ("idle past its period", |s| {
                s.idle_ms = 10;
                s.idle_rem_ms = 11
            }),
            ("persist with a window open", |s| s.persist_rem_ms = 5),
            ("CLOSE-WAIT bound in ESTABLISHED", |s| {
                s.closewait_rem_ms = 5
            }),
            ("closing bound in ESTABLISHED", |s| s.closing_rem_ms = 5),
            ("TIME-WAIT in ESTABLISHED", |s| s.timewait_rem_ms = 5),
        ];
        for (what, f) in cases {
            let mut s = Box::new(st);
            f(&mut s);
            assert_eq!(
                ts_validate(&s),
                Err(CkptError::SequenceImpossible),
                "{what}"
            );
        }
        let mut s = Box::new(st);
        s.idle_ms = TS_TIMER_MAX_MS + 1;
        assert_eq!(ts_validate(&s), Err(CkptError::Bounds), "past the ceiling");
        // Aged: armed timers run down to due, disarmed ones stay so.
        let mut s = Box::new(st);
        s.idle_ms = 1_000;
        s.idle_rem_ms = 400;
        ts_age_timers(&mut s, &[0, 150, 0, 0, 0, 0]);
        assert_eq!(s.idle_rem_ms, 250);
        ts_age_timers(&mut s, &[9_999; 6]);
        assert_eq!((s.idle_rem_ms, s.retx_rem_ms), (TS_TIMER_DUE, 0));
        assert_eq!(ts_validate(&s), Ok(()));
    }

    /// The transitions keep the timers as a stack does: data out arms the
    /// retransmission timer, an acknowledgement of new data restarts or
    /// stops it, a payload byte restarts the idle close, a state change
    /// stops what the new state does not run, and a `Timers` delta sets the
    /// block — each set remainder current as of that delta.
    #[test]
    fn the_transitions_keep_the_timers() {
        let mut v = Vault {
            backend: 1,
            ..Vault::default()
        };
        let mut st = Box::new(initial(&mut v));
        st.idle_ms = 20_000;
        st.idle_rem_ms = 3_000;
        let (rem, una) = (ts_timer_remainders(&st), st.snd_una);
        tx(&mut st, 200);
        assert_eq!((st.retx_rem_ms, st.idle_rem_ms), (200, 20_000));
        assert_eq!(md_timers_set(&rem, una, &st, MdKind::TxRecord), 0b11);
        // A second record: the running timer is not restarted.
        st.retx_rem_ms = 120;
        let rem = ts_timer_remainders(&st);
        tx(&mut st, 50);
        assert_eq!(st.retx_rem_ms, 120);
        assert_eq!(md_timers_set(&rem, st.snd_una, &st, MdKind::TxRecord), 0b10);
        // Part acknowledged: restarted at the interval; all of it: stopped.
        st.retx_rem_ms = 30;
        let (rem, una) = (ts_timer_remainders(&st), st.snd_una);
        let to = st.snd_una + 100;
        peer_ack(&mut st, to);
        assert_eq!(st.retx_rem_ms, 200);
        assert_eq!(md_timers_set(&rem, una, &st, MdKind::PeerAck) & 1, 1);
        let end = st.send_end();
        peer_ack(&mut st, end);
        assert_eq!(st.retx_rem_ms, 0);
        // The peer's FIN: CLOSE-WAIT runs no idle close.
        fin(&mut st, MD_DIR_IN);
        assert_eq!((st.tcp, st.idle_rem_ms), (TsTcp::CloseWait, 0));
        let mut t = MdTimers::of(&st);
        t.closewait_rem_ms = 4_000;
        timers(&mut st, &t).unwrap();
        assert_eq!(st.closewait_rem_ms, 4_000);
        let mut wrong = t;
        wrong.timewait_rem_ms = 1;
        assert_eq!(timers(&mut st, &wrong), Err(CkptError::SequenceImpossible));
        // Our FIN: LAST-ACK runs the closing bound, not CLOSE-WAIT's.
        st.close_notify_sent = true;
        fin(&mut st, MD_DIR_OUT);
        assert_eq!((st.tcp, st.closewait_rem_ms), (TsTcp::LastAck, 0));
        let mut t = MdTimers::of(&st);
        t.closing_rem_ms = 12_000;
        let rem = ts_timer_remainders(&st);
        timers(&mut st, &t).unwrap();
        assert_eq!(md_timers_set(&rem, st.snd_una, &st, MdKind::Timers), 0x3F);
        let mut out = vec![0u8; TS_CKPT_MAX];
        let n = ts_encode(&st, &mut out).unwrap();
        let mut back = Box::new(TsState::zero());
        ts_decode(&out[..n], &mut back).unwrap();
        assert_eq!(back.closing_rem_ms, 12_000);
    }

    /// TIME-WAIT is a state the record carries: our FIN acknowledged, the
    /// peer's received, its quiet period's remainder set by the state's
    /// timers — and CLOSING's bound stops when it gets there.
    #[test]
    fn time_wait_is_carried_with_its_remainder() {
        let mut v = Vault {
            backend: 1,
            ..Vault::default()
        };
        // FIN-WAIT-2, then the peer's FIN.
        let mut st = Box::new(initial(&mut v));
        st.close_notify_sent = true;
        fin(&mut st, MD_DIR_OUT);
        let end = st.send_end();
        peer_ack(&mut st, end);
        assert_eq!(st.tcp, TsTcp::FinWait2);
        fin(&mut st, MD_DIR_IN);
        assert_eq!(st.tcp, TsTcp::TimeWait);
        let mut t = MdTimers::of(&st);
        t.timewait_rem_ms = 1_650;
        timers(&mut st, &t).unwrap();
        let mut out = vec![0u8; TS_CKPT_MAX];
        let n = ts_encode(&st, &mut out).unwrap();
        let mut back = Box::new(TsState::zero());
        ts_decode(&out[..n], &mut back).unwrap();
        assert_eq!((back.tcp, back.timewait_rem_ms), (TsTcp::TimeWait, 1_650));
        // Simultaneous close: CLOSING's bound, then our FIN acknowledged.
        let mut st = Box::new(initial(&mut v));
        st.close_notify_sent = true;
        fin(&mut st, MD_DIR_OUT);
        fin(&mut st, MD_DIR_IN);
        assert_eq!(st.tcp, TsTcp::Closing);
        let mut t = MdTimers::of(&st);
        t.closing_rem_ms = 9_000;
        timers(&mut st, &t).unwrap();
        let end = st.send_end();
        peer_ack(&mut st, end);
        assert_eq!((st.tcp, st.closing_rem_ms), (TsTcp::TimeWait, 0));
    }
}
