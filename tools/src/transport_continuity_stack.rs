//! The `transport_continuity` module's provider (`TcStack`,
//! `modules/foundation/transport_continuity/stack.rs`) mounted for the host
//! tests, over the same SDK sources the module includes.
//!
//! The provider's per-layer side is played here by an `ip` and a `tls` that
//! answer the session control continuity commands as the modules do — the
//! primary's export as CHECKPOINT_BEGIN / NEXT* / COMMIT then CR_CUT, the
//! standby's import into a shadow, ARM and ACTIVATE — over FXTC and CT_TLS
//! records laid out as `ip` and `tls` write them. The graph-level migration
//! over the real modules is `tests/host/transport_continuity_move.sh`.
#![allow(
    dead_code,
    reason = "the contract and core are mounted whole; the bridge reaches a part"
)]

#[path = "../../modules/sdk/contracts/net/session_ctrl.rs"]
mod sc;

include!("../../modules/sdk/crypto/sha256.rs");
include!("../../modules/sdk/contracts/net/transport_continuity.rs");
include!("../../modules/sdk/cores/transport_continuity.rs");
include!("../../modules/sdk/cores/session_handoff.rs");
include!("../../modules/foundation/transport_continuity/stack.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const VIP: [u8; 4] = [10, 77, 9, 1];
    const CLIENT: [u8; 4] = [10, 77, 5, 2];
    const PORT: u16 = 8443;
    const CPORT: u16 = 40_000;
    const EPOCH: u32 = 1;
    const ANCHOR_A: [u8; 8] = [0xA1; 8];
    const ANCHOR_B: [u8; 8] = [0xB2; 8];
    const CONN: u16 = 3;

    fn flow() -> [u8; 16] {
        let mut f = [0u8; 16];
        f[..4].copy_from_slice(&VIP);
        f[4..8].copy_from_slice(&CLIENT);
        f[8..10].copy_from_slice(&PORT.to_be_bytes());
        f[10..12].copy_from_slice(&CPORT.to_be_bytes());
        f
    }

    // ── the halves, as `ip` and `tls` lay them out ───────────────────────

    fn tcp_half(una: u32, nxt: u32) -> TcpHalf {
        TcpHalf {
            state: 1,
            local_ip: u32::from_be_bytes(VIP),
            remote_ip: u32::from_be_bytes(CLIENT),
            local_port: PORT,
            remote_port: CPORT,
            prefix_len: 24,
            iss: una.wrapping_sub(2000),
            snd_una: una,
            snd_nxt: nxt,
            snd_wnd: 64_000,
            snd_wl1: 77_000,
            snd_wl2: una,
            rcv_nxt: 80_000,
            rcv_wnd: 0,
            cwnd: 14_600,
            ssthresh: u16::MAX,
            dup_acks: 0,
            in_recovery: 0,
            recover_seq: 0,
            srtt: 40,
            rttvar: 12,
            rto: 1000,
            retx_rem: 0,
            tw_rem: 0,
            idle_rem: 0,
            cw_rem: 0,
            closing_rem: 0,
            idle_period: 0,
            delivered: 2999,
            consumed: 2999,
            ooo_count: 1,
            ooo: {
                let mut o = [TsOoo {
                    seq: 0,
                    len: 0,
                    bytes: [0; TS_OOO_SEG],
                }; TS_OOO_MAX];
                o[0].seq = 80_100;
                o[0].len = 3;
                o[0].bytes[..3].copy_from_slice(b"ooo");
                o
            },
            v6: false,
            local_ip6: [0; 16],
            remote_ip6: [0; 16],
        }
    }

    /// A TLS application record of `n` bytes of body (header included).
    fn record(n: usize, fill: u8) -> Vec<u8> {
        let mut r = vec![23, 3, 3];
        r.extend_from_slice(&(n as u16).to_be_bytes());
        r.extend(std::iter::repeat_n(fill, n));
        r
    }

    struct TlsLayout {
        recv: Vec<u8>,
        retx: Vec<u8>,
        retx_base: u32,
        anchored: bool,
        write_seq: u64,
        emitted: u64,
        out_bytes: u64,
        consumer_cursor: u64,
        cursor_at: u64,
        in_bytes: u64,
        key_update: u8,
        peer_block: [u8; CT_PEER_LEN],
        sealed: [u8; TCS_SEALED_LEN],
    }

    fn tls_layout() -> TlsLayout {
        TlsLayout {
            recv: vec![23, 3, 3, 0, 40, 1, 2, 3],
            retx: Vec::new(),
            retx_base: 0,
            anchored: false,
            write_seq: 9,
            emitted: 9,
            out_bytes: 77,
            consumer_cursor: 0x5150,
            cursor_at: 1234,
            in_bytes: 1200,
            key_update: 0,
            peer_block: peer_block_v4(),
            sealed: [0x5E; TCS_SEALED_LEN],
        }
    }

    /// A CT_TLS record, field for field as `tls`'s `encode_checkpoint`.
    fn ct_tls(t: &TlsLayout) -> Vec<u8> {
        let mut r = vec![1u8];
        r.extend_from_slice(&0x0304u16.to_le_bytes());
        r.extend_from_slice(&TC_TLS_CHACHA20_POLY1305_SHA256.to_le_bytes());
        r.push(1);
        r.extend_from_slice(&CONN.to_le_bytes());
        r.push(0);
        r.extend_from_slice(&[0; 16]);
        r.push(0);
        r.extend_from_slice(&[0; 64]);
        r.push(0);
        r.push(0);
        r.extend_from_slice(&t.peer_block);
        r.extend_from_slice(&[0x48; 48]);
        r.extend_from_slice(&0u32.to_le_bytes());
        r.extend_from_slice(&0u32.to_le_bytes());
        // Sealed at the epochs it names.
        r.extend_from_slice(&0u32.to_le_bytes());
        r.extend_from_slice(&0u32.to_le_bytes());
        r.extend_from_slice(&5u64.to_le_bytes());
        r.extend_from_slice(&t.write_seq.to_le_bytes());
        r.push(t.key_update);
        r.extend_from_slice(&[0, 0, 0]);
        r.extend_from_slice(&4u64.to_le_bytes());
        r.extend_from_slice(&t.emitted.to_le_bytes());
        // The consumer's clear bytes through the last record (its horizon).
        r.extend_from_slice(&t.out_bytes.to_le_bytes());
        // The cursor the consumer's last acknowledgement carried.
        r.extend_from_slice(&t.consumer_cursor.to_le_bytes());
        // Its clear byte, and the clear bytes of the delivered records.
        r.extend_from_slice(&t.cursor_at.to_le_bytes());
        r.extend_from_slice(&t.in_bytes.to_le_bytes());
        let expected = if t.recv.len() >= 5 {
            u32::from(u16::from_be_bytes([t.recv[3], t.recv[4]]))
        } else {
            0
        };
        r.extend_from_slice(&expected.to_le_bytes());
        r.extend_from_slice(&(t.recv.len() as u32).to_le_bytes());
        r.extend_from_slice(&t.retx_base.to_le_bytes());
        r.push(u8::from(t.anchored));
        r.extend_from_slice(&(t.retx.len() as u16).to_le_bytes());
        r.extend_from_slice(&(TCS_SEALED_LEN as u16).to_le_bytes());
        // A primary's export carries no deliveries.
        r.push(0);
        r.extend_from_slice(&0u32.to_le_bytes());
        r.extend_from_slice(&t.recv);
        r.extend_from_slice(&t.retx);
        r.extend_from_slice(&t.sealed);
        r
    }

    /// `tls`'s peer block for a server session whose transport peer is
    /// 10.0.0.9:51000 and which holds no peer credential: no requester tag,
    /// the result `NO_CREDENTIAL`, every other byte zero.
    fn peer_block_v4() -> [u8; CT_PEER_LEN] {
        let mut b = [0u8; CT_PEER_LEN];
        b[0] = 4;
        b[1..5].copy_from_slice(&[10, 0, 0, 9]);
        b[17..19].copy_from_slice(&51000u16.to_le_bytes());
        b[19 + 2] = 1;
        b
    }

    fn wrapped(th: &TlsHalf, rec: &[u8]) -> TcsWrapped {
        let mut w = TcsWrapped::empty();
        w.flow_id = flow();
        w.tls_flow[..2].copy_from_slice(&CONN.to_le_bytes());
        w.layer_epoch = EPOCH;
        w.sealed_read_epoch = th.sealed_read_epoch;
        w.sealed_write_epoch = th.sealed_write_epoch;
        w.peer_block = th.peer_block;
        w.exporter_ctx = th.exporter_ctx;
        w.sealed
            .copy_from_slice(&rec[th.sealed_at..th.sealed_at + TCS_SEALED_LEN]);
        w
    }

    fn carried() -> TcsCarried {
        TcsCarried {
            flow_id: flow(),
            service_id: [0x5A; 16],
            flow_epoch: EPOCH,
            mirror_generation: 1,
            session_epoch: 1,
            route_generation: 7,
            binding_epoch: 1,
            local_addr_gen: 0,
            iface: 0,
        }
    }

    fn compose(tcp: &TcpHalf, t: &TlsLayout) -> Result<Box<TcsState>, TcsRefuse> {
        let rec = ct_tls(t);
        let th = ct_tls_decode(&rec).expect("ct_tls");
        let mut st = Box::new(TcsState::zero());
        tcs_compose(tcp, &th, &rec, &wrapped(&th, &rec), &carried(), &mut st).map(|()| st)
    }

    // ── compose and decompose ────────────────────────────────────────────

    #[test]
    fn the_two_halves_are_one_canonical_record_and_come_back_as_they_were() {
        let tcp = tcp_half(5000, 5000);
        let mut fx = [0u8; FXTC_MAX];
        let n = fxtc_encode(&tcp, &mut fx).expect("fxtc");
        let mut back = tcp;
        fxtc_decode(&fx[..n], &mut back).expect("decode");
        assert_eq!(back, tcp, "FXTC round trip");

        let t = tls_layout();
        let st = compose(&tcp, &t).expect("compose");
        ts_validate(&st).expect("a valid record");
        assert_eq!(st.flow_id, flow());
        assert_eq!(&st.service_ip[..4], &VIP);
        assert_eq!(&st.client_ip[..4], &CLIENT);
        assert_eq!(
            (st.read_epoch, st.write_epoch),
            (3, 3),
            "the record numbers epoch 3 first"
        );
        assert_eq!(st.irs, 80_000 - 1 - 2999, "IRS from the delivered count");
        assert_eq!(st.recv_len as usize, t.recv.len());
        assert_eq!(st.ooo_count, 1);
        assert_eq!((st.delivery_acked, st.next_delivery), (4, 5));
        assert_eq!(st.next_production, 10);
        assert_eq!(st.read_key.backend, TCS_VAULT_BACKEND);

        // Decomposed: the TCP half `ip` imports, and the CT_TLS record `tls`
        // imports, byte for byte in everything the connection runs on.
        let mut h = tcp;
        tcs_tcp_half(&st, &mut h);
        for (a, b) in [
            (h.snd_una, tcp.snd_una),
            (h.snd_nxt, tcp.snd_nxt),
            (h.rcv_nxt, tcp.rcv_nxt),
            (h.iss, tcp.iss),
            (h.snd_wl1, tcp.snd_wl1),
            (h.delivered, tcp.delivered),
        ] {
            assert_eq!(a, b);
        }
        assert_eq!((h.srtt, h.rttvar, h.cwnd), (tcp.srtt, tcp.rttvar, tcp.cwnd));
        assert_eq!(h.ooo[0].seq, tcp.ooo[0].seq);
        let rec = ct_tls(&t);
        let th = ct_tls_decode(&rec).expect("ct_tls");
        let w = wrapped(&th, &rec);
        let mut out = [0u8; CT_TLS_MAX];
        let m = ct_tls_encode(&st, &w, &mut out).expect("encode");
        let th2 = ct_tls_decode(&out[..m]).expect("decode");
        assert_eq!(
            (th2.read_seq, th2.write_seq, th2.read_epoch, th2.write_epoch),
            (th.read_seq, th.write_seq, th.read_epoch, th.write_epoch),
            "the sequences and epochs the seal's AAD binds"
        );
        assert_eq!(
            &out[th2.sealed_at..m],
            &rec[th.sealed_at..],
            "the sealed set, untouched"
        );
        assert_eq!(
            &out[th2.recv_at..th2.recv_at + th2.recv_len as usize],
            &t.recv[..]
        );
        assert_eq!(
            (th2.recv_expected, th2.delivered_in, th2.emitted_out),
            (40, 4, 9)
        );
    }

    #[test]
    fn bytes_in_flight_come_from_the_retransmit_window_as_whole_records() {
        // Two records retained, the first partly acknowledged.
        let (r1, r2) = (record(30, 1), record(50, 2));
        let base = 9_000u32;
        let mut t = tls_layout();
        t.retx = [r1.clone(), r2.clone()].concat();
        t.retx_base = base;
        t.anchored = true;
        let una = base + 10;
        let nxt = base + t.retx.len() as u32;
        let st = compose(&tcp_half(una, nxt), &t).expect("compose");
        assert_eq!(st.send_len as u32, nxt - una);
        assert_eq!(&st.send[..usize::from(st.send_len)], &t.retx[10..]);
        let recs = st.tx_records();
        assert_eq!(recs.len(), 2);
        assert_eq!((recs[0].tcp_seq, recs[0].len), (base, r1.len() as u16));
        assert_eq!(recs[1].tcp_seq, base + r1.len() as u32);
        assert_eq!((recs[0].record_seq, recs[1].record_seq), (7, 8));
        assert_eq!((recs[0].production_id, recs[1].production_id), (8, 9));

        // An unanchored window cannot be placed in sequence space.
        t.anchored = false;
        assert_eq!(
            compose(&tcp_half(una, nxt), &t).unwrap_err(),
            TcsRefuse::SendRange
        );
        // Nor can one that does not end where SND.NXT does.
        t.anchored = true;
        assert_eq!(
            compose(&tcp_half(una, nxt + 1), &t).unwrap_err(),
            TcsRefuse::SendRange
        );
        // With nothing in flight, what the window still holds is acknowledged.
        assert!(compose(&tcp_half(nxt, nxt), &t).is_ok());
    }

    #[test]
    fn states_the_record_does_not_represent_are_refused_not_approximated() {
        // Our own close (FIN-WAIT-1) does not move.
        let mut tcp = tcp_half(5000, 5000);
        tcp.state = 3;
        assert_eq!(
            compose(&tcp, &tls_layout()).unwrap_err(),
            TcsRefuse::Unsupported
        );
        let mut t = tls_layout();
        t.key_update = 1;
        assert_eq!(
            compose(&tcp_half(5000, 5000), &t).unwrap_err(),
            TcsRefuse::Unsupported
        );
        let mut t = tls_layout();
        t.recv = vec![0; TS_RECV_MAX + 1];
        assert_eq!(
            compose(&tcp_half(5000, 5000), &t).unwrap_err(),
            TcsRefuse::Unsupported
        );
        // A record the halves would not import whole.
        let mut st = compose(&tcp_half(5000, 5000), &tls_layout()).expect("compose");
        let rec = ct_tls(&tls_layout());
        let th = ct_tls_decode(&rec).expect("ct_tls");
        let w = wrapped(&th, &rec);
        assert!(tcs_importable(&st, &w).is_ok());
        let mut other = w;
        other.sealed[0] ^= 1;
        assert_eq!(
            tcs_importable(&st, &other).unwrap_err(),
            TcsRefuse::Mismatch
        );
        st.deliv_count = 1;
        assert_eq!(tcs_importable(&st, &w).unwrap_err(), TcsRefuse::Unsupported);
    }

    #[test]
    fn a_half_closed_connection_is_one_record_and_comes_back_half_closed() {
        // The peer's FIN (CLOSE-WAIT at `ip`, one sequence number past what
        // it delivered) and its close_notify (CT_TLS bit 1, and its FIN bit
        // 2, at `tls`).
        let mut tcp = tcp_half(5000, 5000);
        tcp.state = 2;
        tcp.delivered -= 1;
        let mut rec = ct_tls(&tls_layout());
        let th = ct_tls_decode(&rec).expect("ct_tls");
        let cn = 1 + 2 + 2 + 1 + 2 + 17 + 65 + 1 + 1 + CT_PEER_LEN + 48 + 16 + 16 + 1;
        rec[cn] = 6;
        let th2 = ct_tls_decode(&rec).expect("half-closed ct_tls");
        assert_eq!(th2.close_notify, 6);
        let mut st = Box::new(TcsState::zero());
        tcs_compose(&tcp, &th2, &rec, &wrapped(&th, &rec), &carried(), &mut st)
            .expect("CLOSE-WAIT composes");
        assert_eq!(
            (st.tcp, st.fin_rcvd, st.close_notify_rcvd),
            (TsTcp::CloseWait, true, true)
        );
        assert_eq!(
            st.irs,
            80_000 - 1 - tcp.delivered - 1,
            "the FIN's sequence number"
        );
        let w = wrapped(&th, &rec);
        tcs_importable(&st, &w).expect("a half-closed record imports");
        let mut back = tcp;
        tcs_tcp_half(&st, &mut back);
        assert_eq!(
            (back.state, back.delivered, back.rcv_nxt),
            (2, tcp.delivered, 80_000)
        );
        let mut out = vec![0u8; CT_TLS_MAX];
        let n = ct_tls_encode(&st, &w, &mut out).expect("ct_tls");
        assert_eq!(ct_tls_decode(&out[..n]).expect("decodes").close_notify, 6);
        // Our own close moves too (below); a transport close forwarded
        // before our close_notify is not a state `tls` makes.
        rec[cn] = 8;
        assert!(
            ct_tls_decode(&rec).is_err(),
            "a FIN of ours before our close_notify"
        );
        rec[cn] = 0x10;
        assert!(ct_tls_decode(&rec).is_err(), "an unknown bit");
    }

    /// An IPv6 connection (FXTC's IPv6 layout: the IPv4 fields zero, the two
    /// addresses after the reorder slots) is one record of family 6 whose
    /// addresses are the connection's own, and comes back as the same
    /// IPv6 half; its flow is named by `tc_flow_id_v6`, which `ip`
    /// computes the same way.
    #[test]
    fn an_ipv6_connection_is_one_record_of_family_six() {
        let vip6: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64,
        ];
        let cli6: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09,
        ];
        let mut tcp = tcp_half(5000, 5000);
        tcp.local_ip = 0;
        tcp.remote_ip = 0;
        (tcp.v6, tcp.local_ip6, tcp.remote_ip6) = (true, vip6, cli6);
        let mut b = vec![0u8; FXTC_MAX + 32];
        let n = fxtc_encode(&tcp, &mut b).expect("fxtc");
        assert_eq!(b[4], 2, "the IPv6 layout");
        let mut back = tcp;
        (back.v6, back.local_ip6, back.remote_ip6) = (false, [0; 16], [0; 16]);
        fxtc_decode(&b[..n], &mut back).expect("decodes");
        assert_eq!(
            (back.v6, back.local_ip6, back.remote_ip6),
            (true, vip6, cli6)
        );
        // An IPv6 record that also names IPv4 addresses is refused.
        let mut bad = b[..n].to_vec();
        bad[9] = 1;
        assert!(fxtc_decode(&bad, &mut back).is_err());
        // The record names no owner: the reserved u16 is zero.
        assert_eq!(&b[18..20], &[0, 0]);
        let mut owned = b[..n].to_vec();
        owned[18] = 6;
        assert_eq!(fxtc_decode(&owned, &mut back), Err(CkptError::Reserved));
        let rec = ct_tls(&tls_layout());
        let th = ct_tls_decode(&rec).expect("ct_tls");
        let mut st = Box::new(TcsState::zero());
        tcs_compose(&tcp, &th, &rec, &wrapped(&th, &rec), &carried(), &mut st)
            .expect("an IPv6 connection composes");
        assert_eq!((st.family, st.service_ip, st.client_ip), (6, vip6, cli6));
        ts_validate(&st).expect("validates");
        tcs_importable(&st, &wrapped(&th, &rec)).expect("imports");
        let mut half = tcp;
        (half.v6, half.local_ip6, half.remote_ip6) = (false, [0; 16], [0; 16]);
        tcs_tcp_half(&st, &mut half);
        assert_eq!(
            (
                half.v6,
                half.local_ip6,
                half.remote_ip6,
                half.local_ip,
                half.remote_ip
            ),
            (true, vip6, cli6, 0, 0)
        );
        // The flow identity: pinned, so `ip`'s digest is held to it.
        let f = tc_flow_id_v6(&vip6, &cli6, PORT, CPORT);
        assert_eq!(f[0], 0xF6);
        assert_eq!(f, tc_flow_id_v6(&vip6, &cli6, PORT, CPORT));
        assert_ne!(f, tc_flow_id_v6(&cli6, &vip6, PORT, CPORT));
    }

    /// Each record has its layout bytes and no others: FXTC 1 (IPv4) and
    /// 2 (IPv6), CT_TLS 1.
    #[test]
    fn a_record_of_any_other_layout_is_refused() {
        let tcp = tcp_half(5000, 5000);
        let mut b = vec![0u8; FXTC_MAX + 32];
        let n = fxtc_encode(&tcp, &mut b).expect("fxtc");
        assert_eq!(b[4], 1, "the IPv4 layout");
        let mut back = tcp;
        for layout in [0u8, 3, 4, 0xFF] {
            let mut r = b[..n].to_vec();
            r[4] = layout;
            assert_eq!(
                fxtc_decode(&r, &mut back),
                Err(CkptError::Version),
                "FXTC {layout}"
            );
        }
        let rec = ct_tls(&tls_layout());
        assert_eq!(rec[0], 1);
        for layout in [0u8, 2, 4, 0xFF] {
            let mut r = rec.clone();
            r[0] = layout;
            assert_eq!(
                ct_tls_decode(&r).err(),
                Some(CkptError::Version),
                "CT_TLS {layout}"
            );
        }
    }

    /// The labels this bridge binds at pairing are byte for byte the ones
    /// `ip` and `tls` bind, so a pair of the three agrees on one digest.
    #[test]
    fn the_pairing_labels_are_the_layers_own() {
        let ip = include_str!("../../modules/foundation/ip/continuity.rs");
        let tls = include_str!("../../modules/foundation/tls/continuity.rs");
        let fxtc = core::str::from_utf8(&TCS_FXTC_LABEL).expect("ascii");
        let ct = core::str::from_utf8(&TCS_CT_TLS_LABEL).expect("ascii");
        assert!(
            ip.contains(&format!("const TCP_CODEC_LAYOUT: &[u8] = b\"{fxtc}\";")),
            "ip's TCP_CODEC_LAYOUT is TCS_FXTC_LABEL"
        );
        assert!(
            tls.contains(&format!(
                "const TLS_CODEC_LABEL: [u8; {}] = *b\"{ct}\";",
                ct.len()
            )),
            "tls's TLS_CODEC_LABEL is TCS_CT_TLS_LABEL"
        );
    }

    /// Our own close: the consumer closed, `tls` sealed its close_notify
    /// (CT_TLS bit 0) and, once the alert went, `ip` sent its FIN (bit 3).
    /// Every closing state of ours is one record and comes back the same:
    /// FIN-WAIT-1 and LAST-ACK with the FIN in flight, FIN-WAIT-2 with it
    /// acknowledged, CLOSING with both FINs; ESTABLISHED with the alert
    /// sealed and the transport close not yet forwarded.
    #[test]
    fn our_own_close_is_one_record_in_every_closing_state() {
        let cn = 1 + 2 + 2 + 1 + 2 + 17 + 65 + 1 + 1 + CT_PEER_LEN + 48 + 16 + 16 + 1;
        // (ip state, close_notify byte, TsTcp, FIN in flight, peer FIN)
        let cases = [
            (1u8, 1u8, TsTcp::Established, false, false),
            (3, 9, TsTcp::FinWait1, true, false),
            (4, 9, TsTcp::FinWait2, false, false),
            (5, 9 | 6, TsTcp::Closing, true, true),
            (6, 9 | 6, TsTcp::LastAck, true, true),
            (7, 9 | 6, TsTcp::TimeWait, false, true),
        ];
        for (state, bits, tcp_state, fin_out, peer_fin) in cases {
            let mut tcp = tcp_half(5000, 5000);
            tcp.state = state;
            // The timer the state runs, as `ip` exports it (ticks): the idle
            // close in ESTABLISHED (a minute's period, 42 s left), the
            // closing bound, TIME-WAIT.
            tcp.idle_period = 1200;
            match state {
                1 => tcp.idle_rem = 840,
                5 | 6 => tcp.closing_rem = 200,
                7 => tcp.tw_rem = 30,
                _ => {}
            }
            if peer_fin {
                tcp.delivered -= 1;
            }
            if fin_out {
                // The FIN is the sequence number past the bytes in flight.
                tcp.snd_nxt = tcp.snd_nxt.wrapping_add(1);
            }
            let mut rec = ct_tls(&tls_layout());
            let th = ct_tls_decode(&rec).expect("ct_tls");
            rec[cn] = bits;
            let th2 = ct_tls_decode(&rec).expect("closing ct_tls");
            let mut st = Box::new(TcsState::zero());
            tcs_compose(&tcp, &th2, &rec, &wrapped(&th, &rec), &carried(), &mut st)
                .unwrap_or_else(|e| panic!("state {state} composes: {e:?}"));
            assert_eq!(
                (st.tcp, st.fin_queued, st.fin_rcvd, st.close_notify_sent),
                (tcp_state, fin_out, peer_fin, true),
                "state {state}"
            );
            ts_validate(&st).unwrap_or_else(|e| panic!("state {state} validates: {e:?}"));
            // Each remainder crosses field for field, in milliseconds.
            assert_eq!(
                (
                    st.idle_ms,
                    st.idle_rem_ms,
                    st.closing_rem_ms,
                    st.timewait_rem_ms,
                    st.retx_rem_ms
                ),
                match state {
                    1 => (60_000, 42_000, 0, 0, 0),
                    5 | 6 => (60_000, 0, 10_000, 0, 0),
                    7 => (60_000, 0, 0, 1_500, 0),
                    _ => (60_000, 0, 0, 0, 0),
                },
                "state {state}'s timers"
            );
            let w = wrapped(&th, &rec);
            tcs_importable(&st, &w).unwrap_or_else(|e| panic!("state {state} imports: {e:?}"));
            let mut back = tcp;
            tcs_tcp_half(&st, &mut back);
            assert_eq!(
                (back.state, back.snd_nxt, back.delivered, back.rcv_nxt),
                (state, tcp.snd_nxt, tcp.delivered, tcp.rcv_nxt),
                "state {state} decomposes"
            );
            assert_eq!(
                (
                    back.idle_period,
                    back.idle_rem,
                    back.closing_rem,
                    back.tw_rem
                ),
                (tcp.idle_period, tcp.idle_rem, tcp.closing_rem, tcp.tw_rem),
                "state {state}'s timers decompose"
            );
            let mut out = vec![0u8; CT_TLS_MAX];
            let n = ct_tls_encode(&st, &w, &mut out).expect("ct_tls");
            assert_eq!(
                ct_tls_decode(&out[..n]).expect("decodes").close_notify,
                bits
            );
            // A FIN of ours without our close_notify is not one `tls` makes.
            if state >= 3 {
                rec[cn] = bits & 6;
                let th3 = ct_tls_decode(&rec).expect("ct_tls");
                let mut st3 = Box::new(TcsState::zero());
                assert_eq!(
                    tcs_compose(&tcp, &th3, &rec, &wrapped(&th, &rec), &carried(), &mut st3),
                    Err(TcsRefuse::Unsupported)
                );
            }
        }
    }

    /// The connection's output horizon (the consumer's clear bytes through
    /// the last record, `net_proto::MSG_HORIZON`) is part of the record:
    /// `tls`'s half carries it in, the record carries it back out to the
    /// standby's `tls`, and a record out moves it only forward.
    #[test]
    fn the_output_horizon_is_one_field_of_the_record_both_ways() {
        let tcp = tcp_half(5000, 5000);
        let rec = ct_tls(&tls_layout());
        let th = ct_tls_decode(&rec).expect("ct_tls");
        assert_eq!(th.out_bytes, 77);
        let w = wrapped(&th, &rec);
        let mut st = Box::new(TcsState::zero());
        tcs_compose(&tcp, &th, &rec, &w, &carried(), &mut st).expect("composes");
        assert_eq!(st.out_bytes, 77);
        let mut back = vec![0u8; CT_TLS_MAX];
        let n = ct_tls_encode(&st, &w, &mut back).expect("encodes");
        let again = ct_tls_decode(&back[..n]).expect("decodes");
        assert_eq!(again.out_bytes, 77);
        // So is the consumer's cursor (`net_proto::CMD_DELIVERED`), opaque.
        assert_eq!((th.consumer_cursor, st.consumer_cursor), (0x5150, 0x5150));
        assert_eq!(again.consumer_cursor, 0x5150);
        // With its clear byte, and where the unconsumed deliveries start.
        assert_eq!(
            (th.cursor_at, st.cursor_at, again.cursor_at),
            (1234, 1234, 1234)
        );
        assert_eq!(
            (th.in_bytes, st.in_bytes, again.in_bytes),
            (1200, 1200, 1200)
        );
        // A record out carries it forward, never back.
        let ct = record(25, 9);
        let mut p = vec![0u8; 64 + ct.len()];
        let m = md_tx_record(
            &mut p,
            st.next_production,
            st.write_epoch,
            st.write_seq,
            &ct,
            70,
        )
        .expect("payload");
        let mut scratch = Box::new(TcsState::zero());
        let mut low = st.clone();
        assert!(md_apply(&mut low, &mut scratch, MdKind::TxRecord, &p[..m]).is_err());
        let m = md_tx_record(
            &mut p,
            st.next_production,
            st.write_epoch,
            st.write_seq,
            &ct,
            102,
        )
        .expect("payload");
        md_apply(&mut st, &mut scratch, MdKind::TxRecord, &p[..m]).expect("applies");
        assert_eq!(st.out_bytes, 102);
    }

    #[test]
    fn a_client_session_is_one_record_and_comes_back_as_the_client() {
        // This host opened the connection: `tls` is the client (role 0), and
        // `ip`'s local end is the client's.
        let tcp = tcp_half(5000, 5000);
        let mut rec = ct_tls(&tls_layout());
        rec[5] = 0;
        let th = ct_tls_decode(&rec).expect("ct_tls");
        let w = wrapped(&th, &rec);
        let mut st = Box::new(TcsState::zero());
        tcs_compose(&tcp, &th, &rec, &w, &carried(), &mut st).expect("a client session");
        assert!(st.local_client);
        assert_eq!(&st.client_ip[..4], &VIP, "our end, the client's");
        assert_eq!((st.client_port, st.service_port), (PORT, CPORT));
        assert_eq!(&st.service_ip[..4], &CLIENT);
        let mut out = vec![0u8; TS_CKPT_MAX];
        ts_encode(&st, &mut out).expect("a record");
        assert_eq!(
            u16::from_le_bytes([out[6], out[7]]) & TS_FLAG_CLIENT,
            TS_FLAG_CLIENT
        );
        // Decomposed, the halves are this host's again: ip's local end, tls's
        // client role.
        let mut back = tcp;
        tcs_tcp_half(&st, &mut back);
        assert_eq!(
            (
                back.local_ip,
                back.local_port,
                back.remote_ip,
                back.remote_port
            ),
            (tcp.local_ip, tcp.local_port, tcp.remote_ip, tcp.remote_port)
        );
        let mut ct = vec![0u8; CT_TLS_MAX];
        let m = ct_tls_encode(&st, &w, &mut ct).expect("ct_tls");
        assert_eq!(ct_tls_decode(&ct[..m]).expect("decodes").role, 0);
    }

    #[test]
    fn a_fin_under_crash_continuity_crosses_as_a_deferred_fin() {
        // Nothing out of order: the peer's FIN follows its last byte.
        let mut tcp = tcp_half(5000, 5000);
        tcp.ooo_count = 0;
        let (mut a, mut b, ha, hb) = crash_paired_tcp(&tcp);
        let tf = tls_flow();
        // `ip` reports the peer's FIN after 37 more bytes, before `tls` has
        // the bytes: the Fin waits for them.
        let mut rx = 80_000u32.to_le_bytes().to_vec();
        rx.extend_from_slice(&37u16.to_le_bytes());
        rx.extend_from_slice(&80_038u32.to_le_bytes());
        rx.push(1);
        a.feed_half(
            TcsPort::Ip,
            &half_delta(&flow(), 1, sc::DELTA_TCP_RECV, &rx),
        );
        assert!(a.deltas().is_empty(), "nothing before the bytes");
        let mut whole = tls_layout().recv;
        whole.extend(std::iter::repeat_n(0xAB, 45 - whole.len()));
        let mut rb = (whole.len() as u32).to_le_bytes().to_vec();
        rb.extend_from_slice(&whole);
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 1, sc::DELTA_TLS_RECV_BYTES, &rb),
        );
        // `ip`'s CLOSE-WAIT timers: its CLOSE-WAIT bound runs, 5 s left.
        let mut tm = vec![2u8];
        tm.extend_from_slice(&[0xE8, 0x03, 40, 0, 12, 0, 0x08, 0x39, 0xFF, 0xFF]);
        for rem in [0u32, 0, 0, 5_000, 0, 0] {
            tm.extend_from_slice(&rem.to_le_bytes());
        }
        a.feed_half(
            TcsPort::Ip,
            &half_delta(&flow(), 2, sc::DELTA_TCP_TIMERS, &tm),
        );
        let evs = a.events();
        let aborts: Vec<_> = evs
            .iter()
            .filter(|(t, p)| *t == tc_evt::STATUS && p[0] == tc_op::ABORT)
            .collect();
        assert!(aborts.is_empty(), "pairing ended: {aborts:?}");
        let d: Vec<Vec<u8>> = evs
            .into_iter()
            .filter(|(t, _)| *t == tc_evt::DELTA)
            .map(|(_, p)| p[8..].to_vec())
            .collect();
        let kinds: Vec<MdKind> = d
            .iter()
            .map(|f| md_parse(f).expect("a delta").0.kind)
            .collect();
        assert_eq!(kinds, vec![MdKind::RxSegment, MdKind::Fin, MdKind::Timers]);
        assert!(a.p.flow(&flow()).expect("a").mirroring, "the pairing holds");
        assert_eq!(relay(&mut b, &hb, &d), 3);
        a.op(tc_op::DELTA_ACK, &[&ha[..], &3u64.to_le_bytes()].concat());
        assert_eq!(a.ip.acks.last(), Some(&2), "the ACK of the FIN released");
        let st = b.p.flow(&flow()).expect("b").st;
        assert_eq!(
            (st.tcp, st.fin_rcvd, st.rcv_nxt, st.closewait_rem_ms),
            (TsTcp::CloseWait, true, 80_038, 5_000)
        );
        // The standby arms `ip` in CLOSE-WAIT, with what remained of its
        // bound (at most that: the time since the delta is charged).
        drop(a);
        b.op(tc_op::EMISSION_ARM, &hb);
        assert_eq!(b.status(tc_op::EMISSION_ARM).status, tc_st::OK);
        let mut h = tcp_half(0, 0);
        fxtc_decode(&b.ip.imported.clone().expect("fxtc"), &mut h).expect("fxtc");
        assert_eq!((h.state, h.rcv_nxt), (2, 80_038));
        assert!(
            h.cw_rem > 0 && h.cw_rem <= 100,
            "CLOSE-WAIT's remainder: {}",
            h.cw_rem
        );
        let th = ct_tls_decode(&b.tls.imported.clone().expect("ct_tls")).expect("ct_tls");
        assert_eq!(th.close_notify & 4, 4, "tls is told the peer's FIN");
    }

    // ── the provider over a modelled ip and tls ──────────────────────────

    /// One host's `ip` and `tls`, answering per-layer continuity commands
    /// as the modules do. A primary holds `live` records; a standby imports
    /// into `shadow`.
    #[derive(Default)]
    struct Layer {
        live: Option<Vec<u8>>,
        shadow: Vec<u8>,
        imported: Option<Vec<u8>>,
        armed: bool,
        activated: Option<(u32, u32, Option<u16>)>,
        retired: bool,
        sent: VecDeque<Vec<u8>>,
        ip: bool,
        /// The profile the bridge paired this half under.
        profile: u8,
        /// Bytes in flight a quiesce reports (drained all the same).
        in_flight: u32,
        /// `CONTINUITY{CHECKPOINT_COMMITTED}` bodies relayed to this half,
        /// DELTA_ACK numbers, ABORT reasons, tombstones `[flow][epoch][ttl]`.
        committed: Vec<Vec<u8>>,
        acks: Vec<u32>,
        aborts: Vec<u8>,
        /// The epoch each ABORT named.
        abort_epochs: Vec<u32>,
        /// What ACTIVATE is answered other than `STATUS_OK`, if anything.
        activate_refuse: Option<u8>,
        tombs: Vec<Vec<u8>>,
        /// What a tombstone is answered (`STATUS_*`).
        tomb_status: u8,
        /// Custody commands `[flow][epoch][op][body]`, and what the vault
        /// answers them (`STATUS_*`, `custody::why`).
        custody: Vec<Vec<u8>>,
        custody_refuse: Option<(u8, u8)>,
    }

    /// Custody evidence as `tls` assembles it over `challenge`: an `FXHA`
    /// record for a fresh P-256 agreement key, the key, its signer, a
    /// signature (whose verification is the vault's, not modelled here).
    fn evidence(challenge: &[u8]) -> Vec<u8> {
        use tc_custody::*;
        let mut rec = vec![0u8; RECORD_LEN];
        rec[..4].copy_from_slice(&R_MAGIC);
        rec[R_CHALLENGE..R_CHALLENGE + 32].copy_from_slice(&challenge[..32]);
        rec[R_COMPOSITION..R_COMPOSITION + 32].copy_from_slice(&[0xC0; 32]);
        rec[R_SUITE..R_SUITE + 2].copy_from_slice(&SUITE_P256.to_le_bytes());
        rec[R_USAGE..R_USAGE + 4].copy_from_slice(&(USAGE_AGREE | 1 << 3).to_le_bytes());
        let mut recipient = vec![0x04u8];
        recipient.extend_from_slice(&[0x11; 64]);
        rec[R_THUMBPRINT..R_THUMBPRINT + 32].copy_from_slice(&sha256(&recipient));
        let mut e = rec;
        e.extend_from_slice(&recipient);
        e.push(0x04);
        e.extend_from_slice(&[0x22; 64]);
        e.extend_from_slice(&64u16.to_le_bytes());
        e.extend_from_slice(&[0x33; 64]);
        e
    }

    fn sc_frame(t: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![t];
        f.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        f.extend_from_slice(payload);
        f
    }

    impl Layer {
        fn reply(&mut self, flow: &[u8], epoch: u32, record: u8, status: u8, body: &[u8]) {
            let mut p = flow.to_vec();
            p.extend_from_slice(&epoch.to_le_bytes());
            p.push(record);
            p.push(status);
            p.extend_from_slice(body);
            self.sent.push_back(sc_frame(sc::MSG_SC_CONTINUITY, &p));
        }

        fn command(&mut self, f: &[u8]) {
            let (t, p) = (f[0], &f[3..]);
            let flow = &p[..16];
            let epoch = u32::from_le_bytes(p[16..20].try_into().expect("epoch"));
            match t {
                sc::CMD_SC_PAIR_PREPARE => {
                    self.profile = p[21];
                    let body: Vec<u8> = if self.live.is_some() {
                        let mut b = vec![p[20], p[21], 0, 0];
                        if self.ip {
                            b.extend_from_slice(&CONN.to_le_bytes());
                        }
                        b
                    } else {
                        vec![p[20], p[21], 0, 0]
                    };
                    self.reply(flow, epoch, sc::CR_PAIR_PREPARED, sc::STATUS_OK, &body);
                }
                sc::CMD_SC_QUIESCE_BEGIN | sc::CMD_SC_QUIESCE_STATUS => {
                    let mut b = vec![1u8];
                    b.extend_from_slice(&self.in_flight.to_le_bytes());
                    b.extend_from_slice(&0u32.to_le_bytes());
                    self.reply(flow, epoch, sc::CR_QUIESCED, sc::STATUS_OK, &b);
                }
                sc::MSG_SC_CONTINUITY => self.committed.push(p.to_vec()),
                sc::CMD_SC_DELTA_ACK => self
                    .acks
                    .push(u32::from_le_bytes(p[24..28].try_into().expect("no"))),
                sc::CMD_SC_CUSTODY => {
                    self.custody.push(p.to_vec());
                    let (op, body) = (p[20], &p[21..]);
                    if let Some((st, why)) = self.custody_refuse {
                        return self.reply(flow, epoch, sc::CR_CUSTODY, st, &[op, why]);
                    }
                    let mut b = vec![op, 0];
                    match op {
                        sc::custody::ATTEST => b.extend_from_slice(&evidence(body)),
                        sc::custody::WRAP => b.extend_from_slice(&[0xAB; sc::custody::WRAPPED_LEN]),
                        _ => {}
                    }
                    self.reply(flow, epoch, sc::CR_CUSTODY, sc::STATUS_OK, &b);
                }
                TCS_IP_TOMBSTONE => {
                    self.tombs.push(p.to_vec());
                    let st = self.tomb_status;
                    self.reply(flow, epoch, sc::CR_RETIRED, st, &[]);
                }
                sc::CMD_SC_CUT_EXPORT => {
                    let rec = self.live.clone().expect("a live connection");
                    let d = sha256(&rec);
                    let mut b = flow.to_vec();
                    b.extend_from_slice(&epoch.to_le_bytes());
                    b.extend_from_slice(&1u32.to_le_bytes());
                    b.extend_from_slice(&(rec.len() as u32).to_le_bytes());
                    b.extend_from_slice(&d);
                    self.sent
                        .push_back(sc_frame(sc::CMD_SC_CHECKPOINT_BEGIN, &b));
                    for (k, c) in rec.chunks(sc::CHECKPOINT_CHUNK_MAX).enumerate() {
                        let mut b = flow.to_vec();
                        b.extend_from_slice(&epoch.to_le_bytes());
                        b.extend_from_slice(&1u32.to_le_bytes());
                        b.extend_from_slice(&((k * sc::CHECKPOINT_CHUNK_MAX) as u32).to_le_bytes());
                        b.extend_from_slice(c);
                        self.sent
                            .push_back(sc_frame(sc::CMD_SC_CHECKPOINT_NEXT, &b));
                    }
                    let mut b = flow.to_vec();
                    b.extend_from_slice(&epoch.to_le_bytes());
                    b.extend_from_slice(&1u32.to_le_bytes());
                    b.extend_from_slice(&handoff_crc32(&rec).to_le_bytes());
                    self.sent
                        .push_back(sc_frame(sc::CMD_SC_CHECKPOINT_COMMIT, &b));
                    self.reply(flow, epoch, sc::CR_CUT, sc::STATUS_OK, &[0; 43]);
                }
                sc::CMD_SC_CHECKPOINT_BEGIN => {
                    self.shadow.clear();
                    self.reply(flow, epoch, sc::CR_CHECKPOINT_ACK, sc::STATUS_OK, &[0; 8]);
                }
                sc::CMD_SC_CHECKPOINT_NEXT => {
                    self.shadow.extend_from_slice(&p[28..]);
                    self.reply(flow, epoch, sc::CR_CHECKPOINT_ACK, sc::STATUS_OK, &[0; 8]);
                }
                sc::CMD_SC_CHECKPOINT_COMMIT => {
                    let ok = handoff_crc32(&self.shadow).to_le_bytes() == p[24..28];
                    self.imported = ok.then(|| self.shadow.clone());
                    let st = if ok {
                        sc::STATUS_OK
                    } else {
                        sc::STATUS_CORRUPT
                    };
                    self.reply(flow, epoch, sc::CR_CHECKPOINT_COMMITTED, st, &[0; 36]);
                }
                sc::CMD_SC_CUT_IMPORT => {
                    let ok = self.imported.as_ref().map(|r| sha256(r)[..] == p[24..56]);
                    let st = if ok == Some(true) {
                        sc::STATUS_OK
                    } else {
                        sc::STATUS_CORRUPT
                    };
                    self.reply(flow, epoch, sc::CR_IMPORTED, st, &[0; 8]);
                }
                sc::CMD_SC_EMISSION_ARM => {
                    self.armed = self.imported.is_some();
                    let st = if self.armed {
                        sc::STATUS_OK
                    } else {
                        sc::STATUS_NOT_READY
                    };
                    self.reply(flow, epoch, sc::CR_ARMED, st, &[0]);
                }
                sc::CMD_SC_ACTIVATE => {
                    if let Some(st) = self.activate_refuse {
                        return self.reply(flow, epoch, sc::CR_ACTIVATED, st, &[0; 6]);
                    }
                    let fence = u32::from_le_bytes(p[20..24].try_into().expect("fence"));
                    let conn = (p.len() == 26).then(|| u16::from_le_bytes([p[24], p[25]]));
                    self.activated = Some((epoch, fence, conn));
                    let mut b = epoch.to_le_bytes().to_vec();
                    b.extend_from_slice(&9u16.to_le_bytes());
                    self.reply(flow, epoch, sc::CR_ACTIVATED, sc::STATUS_OK, &b);
                }
                sc::CMD_SC_RETIRE => {
                    self.retired = true;
                    self.reply(flow, epoch, sc::CR_RETIRED, sc::STATUS_OK, &[]);
                }
                sc::CMD_SC_ABORT => {
                    self.aborts.push(p[20]);
                    self.abort_epochs.push(epoch);
                    self.reply(flow, epoch, sc::CR_ABORTED, sc::STATUS_OK, &[p[20]])
                }
                _ => {}
            }
        }
    }

    /// What the provider queued, by port.
    #[derive(Default)]
    struct Ports {
        evt: VecDeque<Vec<u8>>,
        ip: VecDeque<Vec<u8>>,
        tls: VecDeque<Vec<u8>>,
        key: VecDeque<Vec<u8>>,
        auth: VecDeque<Vec<u8>>,
        unwired_auth: bool,
    }

    impl TcsOut for Ports {
        fn send(&mut self, port: TcsPort, frame: &[u8]) -> bool {
            let q = match port {
                TcsPort::Evt => &mut self.evt,
                TcsPort::Ip => &mut self.ip,
                TcsPort::Tls => &mut self.tls,
                TcsPort::Key => &mut self.key,
                TcsPort::Auth if self.unwired_auth => return false,
                TcsPort::Auth => &mut self.auth,
            };
            q.push_back(frame.to_vec());
            true
        }
    }

    struct Host {
        p: Box<TcStack>,
        out: Ports,
        ip: Layer,
        tls: Layer,
        now: u64,
    }

    /// Zeroed heap memory as a `T`, built in place: a provider is larger
    /// than a test thread's stack.
    ///
    /// # Safety
    /// All-zero bytes must be a value of `T`, as they are for each type the
    /// tests below hold to it.
    #[expect(
        clippy::unnecessary_box_returns,
        reason = "the value is built in heap memory: it is larger than a test thread's stack"
    )]
    unsafe fn zeroed<T>() -> Box<T> {
        // SAFETY: the caller's.
        unsafe { Box::<T>::new_zeroed().assume_init() }
    }

    /// A provider as the module initialises one: zeroed in place, its
    /// anchor written.
    fn boxed_stack(anchor: [u8; 8]) -> Box<TcStack> {
        // SAFETY: `an_unpaired_provider_is_zeroed_memory`.
        let mut b = unsafe { zeroed::<TcStack>() };
        b.anchor_id = anchor;
        b
    }

    /// The module initialises its provider by zeroing it: all-zero memory
    /// is the empty provider, every flow slot the unpaired flow and the
    /// scratch record the zero state, field for field.
    #[test]
    fn an_unpaired_provider_is_zeroed_memory() {
        static EMPTY_STACK: TcStack = TcStack::new([0; 8]);
        static EMPTY_FLOW: TcsFlow = TcsFlow::empty();
        static ZERO_STATE: TcsState = TcsState::zero();
        static EMPTY_HALF: TcsHalfStream = TcsHalfStream::empty();
        static EMPTY_WRAPPED: TcsWrapped = TcsWrapped::empty();
        // SAFETY: each comparison below is the claim; a byte pattern that is
        // not a value of the type would fail it.
        unsafe {
            assert!(*zeroed::<TcStack>() == EMPTY_STACK);
            assert!(*zeroed::<TcsFlow>() == EMPTY_FLOW);
            assert!(*zeroed::<TcsState>() == ZERO_STATE);
            assert!(*zeroed::<TcsHalfStream>() == EMPTY_HALF);
            assert!(*zeroed::<TcsWrapped>() == EMPTY_WRAPPED);
        }
        // What the zero values mean: unpaired, idle, nothing pending, no
        // handle issued, no delta applied.
        let f = &EMPTY_FLOW;
        assert!(!f.live && f.role == TcRole::Standby && f.mode == TcMode::PlannedOnly);
        assert!(f.step == TcsStep::Idle && !f.fin_held && f.order.applied() == 0);
        assert!(f.ip.last == 0 && f.ip.pend[0].cond == TcsCond::Free);
        assert_eq!(EMPTY_STACK.last_gen, 0);
        assert!(!EMPTY_STACK.tcp_half.v6);
    }

    impl Host {
        fn new(anchor: [u8; 8]) -> Self {
            Self {
                p: boxed_stack(anchor),
                out: Ports::default(),
                ip: Layer {
                    ip: true,
                    ..Layer::default()
                },
                tls: Layer::default(),
                now: 1_000,
            }
        }

        /// Move every frame between the provider and its layers until quiet.
        fn settle(&mut self) {
            loop {
                let mut moved = false;
                while let Some(f) = self.out.ip.pop_front() {
                    self.ip.command(&f);
                    moved = true;
                }
                while let Some(f) = self.out.tls.pop_front() {
                    self.tls.command(&f);
                    moved = true;
                }
                while let Some(f) = self.ip.sent.pop_front() {
                    self.p.layer(TcsPort::Ip, &f, self.now, &mut self.out);
                    moved = true;
                }
                while let Some(f) = self.tls.sent.pop_front() {
                    self.p.layer(TcsPort::Tls, &f, self.now, &mut self.out);
                    moved = true;
                }
                if !moved {
                    return;
                }
            }
        }

        fn op(&mut self, op: u8, payload: &[u8]) {
            let f = sc_frame(op, payload);
            self.p.ctl(&f, self.now, &mut self.out);
            self.settle();
        }

        fn events(&mut self) -> Vec<(u8, Vec<u8>)> {
            self.out
                .evt
                .drain(..)
                .map(|f| (f[0], f[3..].to_vec()))
                .collect()
        }

        fn status(&mut self, op: u8) -> TcStatus {
            let evs = self.events();
            let s = evs
                .iter()
                .find(|(t, p)| *t == tc_evt::STATUS && p[0] == op)
                .unwrap_or_else(|| panic!("no STATUS for op {op}: {evs:?}"));
            TcStatus::decode(&s.1).expect("status")
        }
    }

    fn pair(role: TcRole, mode: TcMode) -> Vec<u8> {
        let mut b = [0u8; TC_PAIR_LEN];
        TcPair {
            flow_id: flow(),
            flow_epoch: EPOCH,
            role,
            mode,
            transport: TcTransport::TcpTls,
            mirror_generation: 1,
            service_id: [0x5A; 16],
        }
        .encode(&mut b);
        [&[0u8; 8][..], &b].concat()
    }

    fn handle_of(s: &TcStatus) -> [u8; 8] {
        let mut h = [0u8; 8];
        s.handle.put(&mut h);
        h
    }

    fn token(flow: [u8; 16], epoch: u32, anchor: [u8; 8], fence: u32, cap: [u8; 16]) -> Vec<u8> {
        let mut t = [0u8; TC_FLOW_TOKEN_LEN];
        TcFlowToken {
            flow_id: flow,
            epoch,
            anchor,
            fence_gen: fence,
            capability: cap,
        }
        .encode(&mut t);
        t.to_vec()
    }

    /// A primary holding the connection (both halves live) and a prepared
    /// standby; the primary's checkpoint taken after its quiesce and
    /// carried to the standby with the wrapped object. Returns both hosts
    /// and their handles.
    fn moved_to_armed() -> (Host, Host, [u8; 8], [u8; 8]) {
        let mut a = Host::new(ANCHOR_A);
        let mut b = Host::new(ANCHOR_B);
        let mut fx = [0u8; FXTC_MAX];
        let n = fxtc_encode(&tcp_half(5000, 5000), &mut fx).expect("fxtc");
        a.ip.live = Some(fx[..n].to_vec());
        a.tls.live = Some(ct_tls(&tls_layout()));

        a.op(
            tc_op::PAIR_PREPARE,
            &pair(TcRole::Primary, TcMode::PlannedOnly),
        );
        let s = a.status(tc_op::PAIR_PREPARE);
        assert_eq!(s.status, tc_st::OK);
        let ha = handle_of(&s);
        b.op(
            tc_op::PAIR_PREPARE,
            &pair(TcRole::Standby, TcMode::PlannedOnly),
        );
        let s = b.status(tc_op::PAIR_PREPARE);
        assert_eq!(s.status, tc_st::OK);
        let hb = handle_of(&s);

        a.op(tc_op::QUIESCE_BEGIN, &ha);
        assert_eq!(a.status(tc_op::QUIESCE_BEGIN).status, tc_st::OK);
        a.op(tc_op::QUIESCE_STATUS, &ha);
        assert_eq!(a.status(tc_op::QUIESCE_STATUS).value, 1);

        a.op(
            tc_op::CHECKPOINT_BEGIN,
            &[&ha[..], &1u64.to_le_bytes()].concat(),
        );
        let evs = a.events();
        let chunks: Vec<_> = evs.iter().filter(|(t, _)| *t == tc_evt::CHUNK).collect();
        assert!(!chunks.is_empty());
        let key = a
            .out
            .key
            .pop_front()
            .expect("the wrapped object on the custody path");
        b.p.wrapped_in(&key);
        for (_, c) in chunks {
            b.op(tc_op::CHECKPOINT_NEXT, &[&hb[..], &c[8..]].concat());
        }
        b.op(
            tc_op::CHECKPOINT_COMMIT,
            &[&hb[..], &1u64.to_le_bytes()].concat(),
        );
        let evs = b.events();
        assert!(evs.iter().any(|(t, _)| *t == tc_evt::APPLIED), "{evs:?}");

        a.op(tc_op::CUT_EXPORT, &ha);
        let evs = a.events();
        let cut = evs.iter().find(|(t, _)| *t == tc_evt::CUT).expect("cut");
        b.op(tc_op::CUT_IMPORT, &[&hb[..], &cut.1[8..]].concat());
        assert_eq!(b.status(tc_op::CUT_IMPORT).status, tc_st::OK);

        b.op(tc_op::EMISSION_ARM, &hb);
        assert_eq!(b.status(tc_op::EMISSION_ARM).status, tc_st::OK);
        (a, b, ha, hb)
    }

    #[test]
    fn a_planned_move_imports_both_halves_and_activates_on_the_authoritys_verdict() {
        let (mut a, mut b, ha, hb) = moved_to_armed();
        // Both halves arrived at the standby's modules, silent.
        assert!(b.ip.armed && b.tls.armed);
        let ip_rec = b.ip.imported.clone().expect("ip imported");
        let mut h = tcp_half(0, 0);
        fxtc_decode(&ip_rec, &mut h).expect("fxtc");
        assert_eq!((h.snd_una, h.rcv_nxt), (5000, 80_000));
        let tls_rec = b.tls.imported.clone().expect("tls imported");
        let th = ct_tls_decode(&tls_rec).expect("ct_tls");
        let orig = ct_tls(&tls_layout());
        let to = ct_tls_decode(&orig).expect("ct_tls");
        assert_eq!(
            &tls_rec[th.sealed_at..],
            &orig[to.sealed_at..],
            "the sealed set as sealed"
        );
        assert_eq!(
            th.peer_block, to.peer_block,
            "the transport peer, requester tag and peer identity, as they were"
        );
        assert_eq!(
            th.exporter_ctx, to.exporter_ctx,
            "identity carried by the wrapped object"
        );

        // The token check goes to the authority, and only its verdict
        // activates.
        let cap = [0xCA; 16];
        let body = [&hb[..], &2u32.to_le_bytes(), &1u32.to_le_bytes(), &cap].concat();
        b.op(tc_op::ACTIVATE, &body);
        let req = b.out.auth.pop_front().expect("token check");
        assert_eq!(req[0], TCS_MSG_TOKEN_CHECK);
        assert_eq!(
            req[3..],
            token(flow(), 2, ANCHOR_B, 1, cap)[..],
            "rebuilt for its own anchor"
        );
        assert!(
            b.ip.activated.is_none(),
            "nothing activates before the verdict"
        );
        let mut v = sc_frame(TCS_MSG_TOKEN_VERDICT, &[&req[3..], &[0][..]].concat());
        // A verdict on the anchor's port is not the authority's.
        b.p.ctl(&v, b.now, &mut b.out);
        b.settle();
        assert!(b.ip.activated.is_none());
        v[3 + TC_FLOW_TOKEN_LEN] = 0;
        b.p.verdict_in(&v, b.now, &mut b.out);
        b.settle();
        assert_eq!(b.status(tc_op::ACTIVATE).status, tc_st::OK);
        assert_eq!(b.ip.activated, Some((2, 1, None)));
        assert_eq!(
            b.tls.activated,
            Some((2, 1, Some(9))),
            "tls bound to ip's connection"
        );
        let f = b.p.flow(&flow()).expect("flow");
        assert!(f.active && f.role == TcRole::Primary && f.layer_epoch == 2);

        a.op(tc_op::RETIRE, &ha);
        assert_eq!(a.status(tc_op::RETIRE).status, tc_st::OK);
        assert!(a.ip.retired && a.tls.retired);
        assert!(
            a.p.flow(&flow()).is_none(),
            "nothing kept for a retired flow"
        );
    }

    #[test]
    fn activation_fails_closed() {
        let (_a, mut b, _ha, hb) = moved_to_armed();
        let act = |epoch: u32, fence: u32| {
            [
                &hb[..],
                &epoch.to_le_bytes(),
                &fence.to_le_bytes(),
                &[0xCA; 16],
            ]
            .concat()
        };
        b.op(tc_op::ACTIVATE, &act(2, 0));
        let s = b.status(tc_op::ACTIVATE);
        assert_eq!(
            (s.status, s.reason),
            (tc_st::UNAUTHORIZED, tc_act::NO_FENCE)
        );
        b.op(tc_op::ACTIVATE, &act(1, 1));
        let s = b.status(tc_op::ACTIVATE);
        assert_eq!(
            (s.status, s.reason),
            (tc_st::UNAUTHORIZED, tc_act::EPOCH_NOT_HIGHER)
        );
        // The authority refuses: its code is the reason.
        b.op(tc_op::ACTIVATE, &act(2, 1));
        let req = b.out.auth.pop_front().expect("token check");
        let v = sc_frame(TCS_MSG_TOKEN_VERDICT, &[&req[3..], &[0x21][..]].concat());
        b.p.verdict_in(&v, b.now, &mut b.out);
        let s = b.status(tc_op::ACTIVATE);
        assert_eq!((s.status, s.reason), (tc_st::UNAUTHORIZED, 0x21));
        assert!(b.ip.activated.is_none());
        // No authority wired: nothing activates.
        b.out.unwired_auth = true;
        b.op(tc_op::ACTIVATE, &act(2, 1));
        assert_eq!(b.status(tc_op::ACTIVATE).status, tc_st::UNAUTHORIZED);
        assert!(b.ip.activated.is_none());
    }

    #[test]
    fn a_tls_refusal_after_ip_activated_resets_the_connection_ip_took() {
        let (_a, mut b, _ha, hb) = moved_to_armed();
        b.tls.activate_refuse = Some(sc::STATUS_NOT_READY);
        let body = [
            &hb[..],
            &2u32.to_le_bytes(),
            &1u32.to_le_bytes(),
            &[0xCA; 16],
        ]
        .concat();
        b.op(tc_op::ACTIVATE, &body);
        let req = b.out.auth.pop_front().expect("token check");
        let v = sc_frame(TCS_MSG_TOKEN_VERDICT, &[&req[3..], &[0][..]].concat());
        b.p.verdict_in(&v, b.now, &mut b.out);
        b.settle();
        assert_eq!(b.status(tc_op::ACTIVATE).status, tc_st::NOT_READY);
        assert_eq!(b.ip.activated, Some((2, 1, None)), "ip took the connection");
        // ip resets what it activated at the new epoch; tls lets go of the
        // shadow it still holds at the old one, and ends at the new one a
        // session it activated after all.
        assert_eq!(b.ip.abort_epochs, vec![2]);
        assert_eq!(b.tls.abort_epochs, vec![1, 2]);
        assert_eq!(b.p.counters.unwound, 1);
        let f = b.p.flow(&flow()).expect("flow");
        assert!(!f.armed && !f.active, "nothing left to activate");
        // A retry does not reach the layers again.
        b.tls.activate_refuse = None;
        b.op(tc_op::ACTIVATE, &body);
        assert_ne!(b.status(tc_op::ACTIVATE).status, tc_st::OK);
        assert!(b.tls.activated.is_none());
    }

    #[test]
    fn an_activation_ip_never_answers_is_undone_at_both_epochs() {
        let (_a, mut b, _ha, hb) = moved_to_armed();
        let body = [
            &hb[..],
            &2u32.to_le_bytes(),
            &1u32.to_le_bytes(),
            &[0xCA; 16],
        ]
        .concat();
        b.op(tc_op::ACTIVATE, &body);
        let req = b.out.auth.pop_front().expect("token check");
        let v = sc_frame(TCS_MSG_TOKEN_VERDICT, &[&req[3..], &[0][..]].concat());
        b.p.verdict_in(&v, b.now, &mut b.out);
        // ip activates, but its answer is late past the operation's deadline.
        while let Some(f) = b.out.ip.pop_front() {
            b.ip.command(&f);
        }
        let late: Vec<_> = b.ip.sent.drain(..).collect();
        assert_eq!(b.ip.activated, Some((2, 1, None)), "ip took the connection");
        b.now += TCS_JOB_MS + 1;
        b.p.poll(b.now, &mut b.out);
        b.settle();
        assert_eq!(b.status(tc_op::ACTIVATE).status, tc_st::NOT_READY);
        // ip resets what it may have activated at the new epoch and drops
        // a shadow it may still hold at the old one; tls lets go of its own.
        assert_eq!(b.ip.abort_epochs, vec![2, 1]);
        assert_eq!(b.tls.abort_epochs, vec![1, 2]);
        assert!(b.tls.activated.is_none(), "tls was never asked");
        assert_eq!(b.p.counters.unwound, 1);
        // The late answer changes nothing.
        for f in late {
            b.p.layer(TcsPort::Ip, &f, b.now, &mut b.out);
        }
        b.settle();
        assert!(b.tls.activated.is_none());
        let f = b.p.flow(&flow()).expect("flow");
        assert!(!f.armed && !f.active, "nothing left to activate");
    }

    #[test]
    fn an_activation_ip_refuses_is_not_unwound() {
        let (_a, mut b, _ha, hb) = moved_to_armed();
        b.ip.activate_refuse = Some(sc::STATUS_NOT_READY);
        let body = [
            &hb[..],
            &2u32.to_le_bytes(),
            &1u32.to_le_bytes(),
            &[0xCA; 16],
        ]
        .concat();
        b.op(tc_op::ACTIVATE, &body);
        let req = b.out.auth.pop_front().expect("token check");
        let v = sc_frame(TCS_MSG_TOKEN_VERDICT, &[&req[3..], &[0][..]].concat());
        b.p.verdict_in(&v, b.now, &mut b.out);
        b.settle();
        assert_eq!(b.status(tc_op::ACTIVATE).status, tc_st::NOT_READY);
        assert!(b.ip.abort_epochs.is_empty() && b.tls.abort_epochs.is_empty());
        assert_eq!(b.p.counters.unwound, 0);
        assert!(
            b.p.flow(&flow()).expect("flow").armed,
            "still armed: a retry may go"
        );
    }

    #[test]
    fn an_unarmed_shadow_or_a_missing_object_does_not_activate_or_import() {
        let mut b = Host::new(ANCHOR_B);
        b.op(
            tc_op::PAIR_PREPARE,
            &pair(TcRole::Standby, TcMode::PlannedOnly),
        );
        let hb = handle_of(&b.status(tc_op::PAIR_PREPARE));
        let body = [&hb[..], &2u32.to_le_bytes(), &1u32.to_le_bytes(), &[0; 16]].concat();
        b.op(tc_op::ACTIVATE, &body);
        let s = b.status(tc_op::ACTIVATE);
        assert_eq!(
            (s.status, s.reason),
            (tc_st::UNAUTHORIZED, tc_act::NOT_ARMED)
        );
        b.op(tc_op::EMISSION_ARM, &hb);
        assert_eq!(b.status(tc_op::EMISSION_ARM).status, tc_st::NOT_READY);

        // A checkpoint whose wrapped object never arrived names keys this
        // host does not hold.
        let (mut a, _b, ha, _) = moved_to_armed();
        let mut c = Host::new(ANCHOR_B);
        c.op(
            tc_op::PAIR_PREPARE,
            &pair(TcRole::Standby, TcMode::PlannedOnly),
        );
        let hc = handle_of(&c.status(tc_op::PAIR_PREPARE));
        a.op(
            tc_op::CHECKPOINT_BEGIN,
            &[&ha[..], &2u64.to_le_bytes()].concat(),
        );
        for (t, p) in a.events() {
            if t == tc_evt::CHUNK {
                c.op(tc_op::CHECKPOINT_NEXT, &[&hc[..], &p[8..]].concat());
            }
        }
        c.op(
            tc_op::CHECKPOINT_COMMIT,
            &[&hc[..], &2u64.to_le_bytes()].concat(),
        );
        let evs = c.events();
        let rej = evs
            .iter()
            .find(|(t, _)| *t == tc_evt::REJECTED)
            .expect("rejected");
        assert_eq!(rej.1[8], tc_rej::KEYS);
    }

    #[test]
    fn what_the_halves_cannot_enforce_is_refused_by_name() {
        let (mut a, mut b, ha, hb) = moved_to_armed();
        // A planned pairing carries no delta stream to acknowledge.
        a.op(tc_op::DELTA_ACK, &[&ha[..], &[0; 8][..]].concat());
        assert_eq!(a.status(tc_op::DELTA_ACK).status, tc_st::UNSUPPORTED);
        // A tombstone is the null handle's.
        let mut tomb = hb.to_vec();
        tomb.extend_from_slice(&flow());
        tomb.extend_from_slice(&[0; 8]);
        b.op(tc_op::TOMBSTONE, &tomb);
        assert_eq!(b.status(tc_op::TOMBSTONE).status, tc_st::INVALID);
        assert!(b.ip.tombs.is_empty());
        let caps = b.p.capabilities();
        for cap in [
            tc_cap::HORIZON_GATE,
            tc_cap::EMISSION_DISABLE,
            tc_cap::RESET_SUPPRESSION,
            tc_cap::FLOW_IMPORT_ARM,
        ] {
            assert_ne!(caps & cap, 0);
        }
        assert_ne!(caps & tc_cap::VAULT_TRANSFER, 0, "CUSTODY_*");
        assert_eq!(caps & tc_cap::REMOTE_CHANNEL, 0);
        // A stale handle is refused before anything moves.
        let mut stale = hb;
        stale[4] ^= 0xFF;
        b.op(tc_op::EMISSION_ARM, &stale);
        assert_eq!(b.status(tc_op::EMISSION_ARM).status, tc_st::STALE_HANDLE);
    }

    /// An anchor's TOMBSTONE, for a flow this host may never have held, is
    /// `ip`'s to install: the per-layer command, and its answer.
    #[test]
    fn a_tombstone_for_a_flow_never_held_is_installed_by_ip() {
        let mut h = Host::new(ANCHOR_B);
        let mut tomb = vec![0u8; 8];
        tomb.extend_from_slice(&flow());
        tomb.extend_from_slice(&EPOCH.to_le_bytes());
        tomb.extend_from_slice(&30_000u32.to_le_bytes());
        h.op(tc_op::TOMBSTONE, &tomb);
        let s = h.status(tc_op::TOMBSTONE);
        assert_eq!((s.status, s.value, s.flow_id), (tc_st::OK, 1, flow()));
        let t = h.ip.tombs.pop().expect("ip's tombstone command");
        assert_eq!(&t[..16], &flow());
        assert_eq!(&t[20..24], &30_000u32.to_le_bytes(), "the ttl as asked");
        assert!(h.tls.tombs.is_empty(), "the reset is ip's to suppress");
        // A table full of live tombstones refuses the next.
        h.ip.tomb_status = sc::STATUS_NO_CAPACITY;
        h.op(tc_op::TOMBSTONE, &tomb);
        assert_eq!(h.status(tc_op::TOMBSTONE).status, tc_st::CAPACITY);
        // And an `ip` that never answers fails it.
        let f = sc_frame(tc_op::TOMBSTONE, &tomb);
        h.p.ctl(&f, h.now, &mut h.out);
        h.out.ip.clear();
        h.p.poll(h.now + TCS_JOB_MS, &mut h.out);
        assert_eq!(h.status(tc_op::TOMBSTONE).status, tc_st::NOT_READY);
    }

    /// A quiesce waits for the halves to drain, not for the peer: bytes in
    /// flight are in `tls`'s anchored window, and the cut carries them.
    #[test]
    fn a_quiesce_does_not_wait_for_bytes_in_flight() {
        let mut a = Host::new(ANCHOR_A);
        let mut t = tls_layout();
        t.retx = record(300, 7);
        t.retx_base = 5000;
        t.anchored = true;
        let nxt = 5000 + t.retx.len() as u32;
        let mut fx = [0u8; FXTC_MAX];
        let n = fxtc_encode(&tcp_half(5000, nxt), &mut fx).expect("fxtc");
        a.ip.live = Some(fx[..n].to_vec());
        a.ip.in_flight = nxt - 5000;
        a.tls.live = Some(ct_tls(&t));
        a.op(
            tc_op::PAIR_PREPARE,
            &pair(TcRole::Primary, TcMode::PlannedOnly),
        );
        let ha = handle_of(&a.status(tc_op::PAIR_PREPARE));
        a.op(tc_op::QUIESCE_STATUS, &ha);
        assert_eq!(a.status(tc_op::QUIESCE_STATUS).value, 1, "quiescent");
        a.op(
            tc_op::CHECKPOINT_BEGIN,
            &[&ha[..], &1u64.to_le_bytes()].concat(),
        );
        assert_eq!(a.status(tc_op::CHECKPOINT_BEGIN).status, tc_st::OK);
        let st = a.p.flow(&flow()).expect("flow").st;
        assert_eq!(
            (
                st.snd_una,
                st.send_end(),
                &st.send[..usize::from(st.send_len)]
            ),
            (5000, nxt, &t.retx[..]),
            "the bytes in flight, from the window"
        );
    }

    #[test]
    fn the_standby_applies_ordered_deltas_and_key_updates_of_the_object_it_holds() {
        let mut a = Host::new(ANCHOR_A);
        let mut b = Host::new(ANCHOR_B);
        let mut fx = [0u8; FXTC_MAX];
        let n = fxtc_encode(&tcp_half(5000, 5000), &mut fx).expect("fxtc");
        a.ip.live = Some(fx[..n].to_vec());
        a.tls.live = Some(ct_tls(&tls_layout()));
        a.op(
            tc_op::PAIR_PREPARE,
            &pair(TcRole::Primary, TcMode::PlannedOnly),
        );
        let ha = handle_of(&a.status(tc_op::PAIR_PREPARE));
        b.op(
            tc_op::PAIR_PREPARE,
            &pair(TcRole::Standby, TcMode::PlannedOnly),
        );
        let hb = handle_of(&b.status(tc_op::PAIR_PREPARE));
        a.op(
            tc_op::CHECKPOINT_BEGIN,
            &[&ha[..], &1u64.to_le_bytes()].concat(),
        );
        let evs = a.events();
        b.p.wrapped_in(&a.out.key.pop_front().expect("object"));
        let mut chain = [0u8; 32];
        for (t, p) in &evs {
            if *t == tc_evt::CHUNK {
                let (hd, _) = ckpt_parse_chunk(&p[8..]).expect("chunk");
                chain = hd.chain;
                b.op(tc_op::CHECKPOINT_NEXT, &[&hb[..], &p[8..]].concat());
            }
        }
        b.op(
            tc_op::CHECKPOINT_COMMIT,
            &[&hb[..], &1u64.to_le_bytes()].concat(),
        );
        b.events();

        // The primary's next transition as a delta: the peer's bytes in.
        let delta = |seq: u64, prev: [u8; 32], kind: MdKind, payload: &[u8]| {
            let mut h = MdHdr {
                kind,
                flow_id: flow(),
                flow_epoch: EPOCH,
                mirror_generation: 1,
                base_checkpoint: 1,
                seq,
                prev,
                payload_len: 0,
                digest: [0; 32],
            };
            let mut out = [0u8; MD_FRAME_MAX];
            let n = md_encode(&mut h, payload, &mut out).expect("delta");
            (out[..n].to_vec(), h.digest)
        };
        let mut p = [0u8; 64];
        let k = md_rx_segment(&mut p, 80_000, b"more").expect("payload");
        let (d1, dig1) = delta(1, chain, MdKind::RxSegment, &p[..k]);
        b.op(tc_op::DELTA_APPLY, &[&hb[..], &d1].concat());
        let evs = b.events();
        assert!(evs
            .iter()
            .any(|(t, p)| *t == tc_evt::APPLIED && p[16..24] == 1u64.to_le_bytes()));
        assert_eq!(b.p.flow(&flow()).expect("flow").st.rcv_nxt, 80_004);

        let held = b.p.flow(&flow()).expect("flow").st;
        // A KeyUpdate naming the next secret of the object this standby
        // holds: applied, and derived by `tls` when the halves are imported.
        let r = TsVaultRef {
            backend: TCS_VAULT_BACKEND,
            purpose: TS_VAULT_READ,
            object: held.read_key.object,
            generation: EPOCH,
            epoch: 4,
        };
        let mut q = [0u8; 54];
        let k = md_key_update(&mut q, MD_DIR_IN, 4, &r, &held.wrapped_digest, false).expect("ku");
        let (d2, dig2) = delta(2, dig1, MdKind::KeyUpdate, &q[..k]);
        b.op(tc_op::DELTA_APPLY, &[&hb[..], &d2].concat());
        let evs = b.events();
        assert!(
            evs.iter()
                .any(|(t, p)| *t == tc_evt::APPLIED && p[16..24] == 2u64.to_le_bytes()),
            "{evs:?}"
        );
        let st = b.p.flow(&flow()).expect("flow").st;
        assert_eq!((st.read_epoch, st.read_seq, st.read_key), (4, 0, r));
        // One naming another object is not this standby's to derive.
        let mut r2 = r;
        r2.epoch = 5;
        let k = md_key_update(&mut q, MD_DIR_IN, 5, &r2, &[0; 32], false).expect("ku");
        let (d3, _) = delta(3, dig2, MdKind::KeyUpdate, &q[..k]);
        b.op(tc_op::DELTA_APPLY, &[&hb[..], &d3].concat());
        let evs = b.events();
        let rej = evs
            .iter()
            .find(|(t, _)| *t == tc_evt::REJECTED)
            .expect("rejected");
        assert_eq!(rej.1[8], tc_rej::DERIVE);
        b.op(tc_op::EMISSION_ARM, &hb);
        assert_eq!(b.status(tc_op::EMISSION_ARM).status, tc_st::NOT_READY);
    }

    // ── crash continuity: the halves' deltas as one stream ───────────────

    /// A per-layer DELTA_APPLY from a half: `[flow][epoch][gen][no][prev]
    /// [kind][body]` (the bridge trusts the half's own chain).
    fn half_delta(flow: &[u8; 16], no: u32, kind: u8, body: &[u8]) -> Vec<u8> {
        let mut p = flow.to_vec();
        p.extend_from_slice(&EPOCH.to_le_bytes());
        p.extend_from_slice(&1u32.to_le_bytes());
        p.extend_from_slice(&no.to_le_bytes());
        p.extend_from_slice(&[0; 32]);
        p.push(kind);
        p.extend_from_slice(body);
        sc_frame(sc::CMD_SC_DELTA_APPLY, &p)
    }

    fn tls_flow() -> [u8; 16] {
        let mut f = [0u8; 16];
        f[..2].copy_from_slice(&CONN.to_le_bytes());
        f
    }

    impl Host {
        fn feed_half(&mut self, port: TcsPort, frame: &[u8]) {
            self.p.layer(port, frame, self.now, &mut self.out);
            self.settle();
        }

        /// The deltas emitted since the last call.
        fn deltas(&mut self) -> Vec<Vec<u8>> {
            self.events()
                .into_iter()
                .filter(|(t, _)| *t == tc_evt::DELTA)
                .map(|(_, p)| p[8..].to_vec())
                .collect()
        }
    }

    /// Relay `deltas` to the standby; the highest sequence it applied.
    fn relay(b: &mut Host, hb: &[u8; 8], deltas: &[Vec<u8>]) -> u64 {
        let mut top = 0;
        for d in deltas {
            b.op(tc_op::DELTA_APPLY, &[&hb[..], d].concat());
            for (t, p) in b.events() {
                assert_ne!(t, tc_evt::REJECTED, "the standby refused a delta: {p:?}");
                if t == tc_evt::APPLIED {
                    top = u64::from_le_bytes(p[16..24].try_into().expect("seq"));
                }
            }
        }
        top
    }

    /// A crash-continuous primary, quiesced and checkpointed, and a standby
    /// holding the checkpoint; mirroring is live.
    fn crash_paired() -> (Host, Host, [u8; 8], [u8; 8]) {
        crash_paired_tcp(&tcp_half(5000, 5000))
    }

    fn crash_paired_tcp(tcp: &TcpHalf) -> (Host, Host, [u8; 8], [u8; 8]) {
        let mut a = Host::new(ANCHOR_A);
        let mut b = Host::new(ANCHOR_B);
        let mut fx = [0u8; FXTC_MAX];
        let n = fxtc_encode(tcp, &mut fx).expect("fxtc");
        a.ip.live = Some(fx[..n].to_vec());
        a.tls.live = Some(ct_tls(&tls_layout()));
        a.op(
            tc_op::PAIR_PREPARE,
            &pair(TcRole::Primary, TcMode::CrashContinuous),
        );
        let s = a.status(tc_op::PAIR_PREPARE);
        assert_eq!(s.status, tc_st::OK);
        let ha = handle_of(&s);
        assert_eq!(
            (a.ip.profile, a.tls.profile),
            (sc::PROFILE_CRASH_CONTINUOUS, sc::PROFILE_CRASH_CONTINUOUS),
            "both halves paired strict"
        );
        b.op(
            tc_op::PAIR_PREPARE,
            &pair(TcRole::Standby, TcMode::CrashContinuous),
        );
        let hb = handle_of(&b.status(tc_op::PAIR_PREPARE));
        a.op(tc_op::QUIESCE_BEGIN, &ha);
        a.op(tc_op::QUIESCE_STATUS, &ha);
        assert_eq!(a.status(tc_op::QUIESCE_STATUS).value, 1);
        a.op(
            tc_op::CHECKPOINT_BEGIN,
            &[&ha[..], &1u64.to_le_bytes()].concat(),
        );
        let evs = a.events();
        assert!(evs.iter().any(|(t, p)| *t == tc_evt::STATUS
            && p[0] == tc_op::CHECKPOINT_BEGIN
            && p[1] == tc_st::OK));
        b.p.wrapped_in(&a.out.key.pop_front().expect("object"));
        for (t, p) in &evs {
            if *t == tc_evt::CHUNK {
                b.op(tc_op::CHECKPOINT_NEXT, &[&hb[..], &p[8..]].concat());
            }
        }
        b.op(
            tc_op::CHECKPOINT_COMMIT,
            &[&hb[..], &1u64.to_le_bytes()].concat(),
        );
        assert!(b.events().iter().any(|(t, _)| *t == tc_evt::APPLIED));
        // Each half learned its checkpoint is held, which starts (and, strict,
        // unquiesces) its own stream.
        for (half, rec) in [(&a.ip, a.ip.live.clone()), (&a.tls, a.tls.live.clone())] {
            let c = half.committed.last().expect("CHECKPOINT_COMMITTED relayed");
            assert_eq!((c[20], c[21]), (sc::CR_CHECKPOINT_COMMITTED, sc::STATUS_OK));
            assert_eq!(&c[22..26], &1u32.to_le_bytes(), "the half's generation");
            assert_eq!(
                &c[26..58],
                &sha256(&rec.expect("record"))[..],
                "its record's digest"
            );
        }
        (a, b, ha, hb)
    }

    #[test]
    fn crash_continuous_halves_become_one_stream_under_the_horizon_gate() {
        let (mut a, mut b, ha, hb) = crash_paired();
        let tf = tls_flow();
        // In: the rest of the partial record arrives (tls RECV_BYTES, and
        // ip's receive transition), then the record is opened.
        let mut whole = tls_layout().recv;
        whole.extend(std::iter::repeat_n(0xAB, 45 - whole.len()));
        let mut rb = (whole.len() as u32).to_le_bytes().to_vec();
        rb.extend_from_slice(&whole);
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 1, sc::DELTA_TLS_RECV_BYTES, &rb),
        );
        let mut rx = 80_000u32.to_le_bytes().to_vec();
        rx.extend_from_slice(&37u16.to_le_bytes());
        rx.extend_from_slice(&80_037u32.to_le_bytes());
        rx.push(0);
        a.feed_half(
            TcsPort::Ip,
            &half_delta(&flow(), 1, sc::DELTA_TCP_RECV, &rx),
        );
        let mut ri = 0u32.to_le_bytes().to_vec();
        ri.extend_from_slice(&6u64.to_le_bytes());
        ri.extend_from_slice(&0u32.to_le_bytes());
        ri.extend_from_slice(&0u32.to_le_bytes());
        ri.push(23);
        ri.extend_from_slice(&5u16.to_le_bytes());
        ri.extend_from_slice(b"hello");
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 2, sc::DELTA_TLS_RECORD_IN, &ri),
        );
        let d = a.deltas();
        assert_eq!(d.len(), 2, "RxSegment, RxRecord");
        assert!(
            a.ip.acks.is_empty() && a.tls.acks.is_empty(),
            "nothing released before the standby holds it"
        );
        assert_eq!(relay(&mut b, &hb, &d), 2);
        let st = b.p.flow(&flow()).expect("flow").st;
        assert_eq!((st.rcv_nxt, st.recv_len, st.read_seq), (80_037, 0, 6));
        assert_eq!(st.deliveries()[0].id, 5);
        assert_eq!(&st.deliveries()[0].bytes[..5], b"hello");

        // The receive horizon: the ACK ip may show, and the delivery tls
        // may make, follow the standby's acknowledgements one by one.
        a.op(tc_op::DELTA_ACK, &[&ha[..], &1u64.to_le_bytes()].concat());
        assert_eq!((a.ip.acks.clone(), a.tls.acks.clone()), (vec![1], vec![1]));
        let hz = a
            .events()
            .into_iter()
            .find(|(t, _)| *t == tc_evt::HORIZON)
            .expect("horizon");
        assert_eq!(&hz.1[8..16], &1u64.to_le_bytes());
        assert_eq!(&hz.1[16..20], &80_037u32.to_le_bytes(), "rx limit");
        a.op(tc_op::DELTA_ACK, &[&ha[..], &2u64.to_le_bytes()].concat());
        assert_eq!(a.tls.acks, vec![1, 2], "the delivery released");

        // Out: a record, its segment, the peer's acknowledgement, and the
        // worker's consumption of the delivery.
        let rec = record(25, 9);
        let mut ro = 0u32.to_le_bytes().to_vec();
        ro.extend_from_slice(&9u64.to_le_bytes());
        ro.extend_from_slice(&(rec.len() as u16).to_le_bytes());
        ro.extend_from_slice(&rec);
        // The consumer's clear bytes through it.
        ro.extend_from_slice(&(77u64 + 100).to_le_bytes());
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 3, sc::DELTA_TLS_RECORD_OUT, &ro),
        );
        let mut sd = 5000u32.to_le_bytes().to_vec();
        sd.extend_from_slice(&(rec.len() as u16).to_le_bytes());
        sd.push(0);
        a.feed_half(
            TcsPort::Ip,
            &half_delta(&flow(), 2, sc::DELTA_TCP_SEND, &sd),
        );
        let d = a.deltas();
        assert_eq!(d.len(), 1, "TxRecord");
        assert_eq!(
            a.ip.acks,
            vec![1],
            "the segment waits for the record's horizon"
        );
        assert_eq!(relay(&mut b, &hb, &d), 3);
        a.op(tc_op::DELTA_ACK, &[&ha[..], &3u64.to_le_bytes()].concat());
        assert_eq!(
            (a.ip.acks.clone(), a.tls.acks.clone()),
            (vec![1, 2], vec![1, 2, 3])
        );
        let end = 5000 + rec.len() as u32;
        let mut ack = end.to_le_bytes().to_vec();
        ack.extend_from_slice(&64_000u16.to_le_bytes());
        ack.extend_from_slice(&14_600u16.to_le_bytes());
        ack.extend_from_slice(&u16::MAX.to_le_bytes());
        a.feed_half(
            TcsPort::Ip,
            &half_delta(&flow(), 3, sc::DELTA_TCP_ACKED, &ack),
        );
        // The consumer stands past the fifth delivery's end, and never
        // behind where it stood.
        let (in_new, at) = {
            let st = a.p.flow(&flow()).expect("a").st;
            let in_new = st.in_bytes
                + st.deliveries()
                    .iter()
                    .filter(|d| d.id <= 5)
                    .map(|d| u64::from(d.len))
                    .sum::<u64>();
            (in_new, in_new.max(st.cursor_at) + 7)
        };
        a.feed_half(
            TcsPort::Tls,
            &half_delta(
                &tf,
                4,
                TCS_TLS_DELIVERED,
                &[
                    5u64.to_le_bytes(),
                    0xC0_FFEEu64.to_le_bytes(),
                    at.to_le_bytes(),
                ]
                .concat(),
            ),
        );
        let d = a.deltas();
        assert_eq!(d.len(), 2, "PeerAck, DeliveryAck");
        assert_eq!(relay(&mut b, &hb, &d), 5);
        a.op(tc_op::DELTA_ACK, &[&ha[..], &5u64.to_le_bytes()].concat());
        assert_eq!(
            (a.ip.acks.clone(), a.tls.acks.clone()),
            (vec![1, 2, 3], vec![1, 2, 3, 4])
        );

        // The standby holds exactly the primary's record.
        let mut r1 = [0u8; TS_CKPT_MAX];
        let mut r2 = [0u8; TS_CKPT_MAX];
        let sa = a.p.flow(&flow()).expect("a").st;
        let sb = b.p.flow(&flow()).expect("b").st;
        assert_eq!(tc_state_digest(&sa, &mut r1), tc_state_digest(&sb, &mut r2));
        assert_eq!((sb.snd_una, sb.send_len, sb.deliv_count), (end, 0, 0));
        assert_eq!(
            (sb.delivery_acked, sb.consumer_cursor, sb.cursor_at),
            (5, 0xC0_FFEE, at),
            "the consumer's cursor and its byte ride its acknowledgement"
        );
        assert_eq!(sb.in_bytes, in_new, "the five deliveries' bytes, whole");
        // A quiesce now is covered: nothing journaled.
        a.op(tc_op::QUIESCE_STATUS, &ha);
        assert_eq!(a.status(tc_op::QUIESCE_STATUS).value, 1);

        // The primary crashes. The standby, which only ever had the
        // checkpoint and the deltas, arms both halves from them.
        drop(a);
        b.op(tc_op::EMISSION_ARM, &hb);
        assert_eq!(b.status(tc_op::EMISSION_ARM).status, tc_st::OK);
        let mut h = tcp_half(0, 0);
        fxtc_decode(&b.ip.imported.clone().expect("ip"), &mut h).expect("fxtc");
        assert_eq!((h.snd_una, h.snd_nxt, h.rcv_nxt), (end, end, 80_037));
        let th = ct_tls_decode(&b.tls.imported.clone().expect("tls")).expect("ct_tls");
        assert_eq!(
            (th.read_seq, th.write_seq, th.recv_len, th.retx_len),
            (6, 10, 0, 0)
        );
        assert_eq!((th.delivered_in, th.emitted_out), (5, 10));
        assert_eq!(
            (th.consumer_cursor, th.cursor_at, th.in_bytes),
            (0xC0_FFEE, at, in_new),
            "and reaches the standby's tls in CT_TLS"
        );
    }

    /// Bring the checkpoint's partial record in whole and open it ("hello"),
    /// then a second record of `plain` bytes of plaintext: the tls
    /// RECV_BYTES, ip RECV and tls RECORD_IN deltas a primary's halves send.
    fn receive_two_records(a: &mut Host, plain: usize) {
        receive_two_records_as(a, (23, b"hello"), plain);
    }

    /// As `receive_two_records`, the first record opening to `first`
    /// (`(inner type, plaintext)`).
    fn receive_two_records_as(a: &mut Host, first: (u8, &[u8]), plain: usize) {
        let tf = tls_flow();
        let mut whole = tls_layout().recv;
        whole.extend(std::iter::repeat_n(0xAB, 45 - whole.len()));
        let mut rb = (whole.len() as u32).to_le_bytes().to_vec();
        rb.extend_from_slice(&whole);
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 1, sc::DELTA_TLS_RECV_BYTES, &rb),
        );
        let ip_recv = |seq: u32, len: u16| {
            let mut rx = seq.to_le_bytes().to_vec();
            rx.extend_from_slice(&len.to_le_bytes());
            rx.extend_from_slice(&seq.wrapping_add(u32::from(len)).to_le_bytes());
            rx.push(0);
            rx
        };
        a.feed_half(
            TcsPort::Ip,
            &half_delta(&flow(), 1, sc::DELTA_TCP_RECV, &ip_recv(80_000, 37)),
        );
        let record_in = |seq: u64, ctype: u8, pt: &[u8]| {
            let mut ri = 0u32.to_le_bytes().to_vec();
            ri.extend_from_slice(&seq.to_le_bytes());
            ri.extend_from_slice(&0u32.to_le_bytes());
            ri.extend_from_slice(&0u32.to_le_bytes());
            ri.push(ctype);
            ri.extend_from_slice(&(pt.len() as u16).to_le_bytes());
            ri.extend_from_slice(pt);
            ri
        };
        a.feed_half(
            TcsPort::Tls,
            &half_delta(
                &tf,
                2,
                sc::DELTA_TLS_RECORD_IN,
                &record_in(6, first.0, first.1),
            ),
        );
        // The second record: header, then its protected body.
        let body = plain + 17;
        let mut rec = vec![23u8, 3, 3];
        rec.extend_from_slice(&(body as u16).to_be_bytes());
        rec.extend(std::iter::repeat_n(0x5C, body));
        let mut rb = (rec.len() as u32).to_le_bytes().to_vec();
        rb.extend_from_slice(&rec);
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 3, sc::DELTA_TLS_RECV_BYTES, &rb),
        );
        a.feed_half(
            TcsPort::Ip,
            &half_delta(
                &flow(),
                2,
                sc::DELTA_TCP_RECV,
                &ip_recv(80_037, rec.len() as u16),
            ),
        );
        let pt: Vec<u8> = (0..plain).map(|i| (i % 253) as u8).collect();
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 4, sc::DELTA_TLS_RECORD_IN, &record_in(7, 23, &pt)),
        );
    }

    /// Application data after the peer's close_notify is not handed up
    /// (RFC 8446 §6.1): the record is consumed, but it is no delivery on
    /// either side.
    #[test]
    fn data_after_the_peers_close_notify_is_no_delivery() {
        let (mut a, mut b, _ha, hb) = crash_paired();
        let before = a.p.flow(&flow()).expect("flow").st.next_delivery;
        receive_two_records_as(&mut a, (21, &[1, 0]), 100);
        assert_eq!(a.p.counters.mirrors_lost, 0, "the stream carries it");
        let sa = a.p.flow(&flow()).expect("a").st;
        assert!(sa.close_notify_rcvd);
        assert_eq!((sa.deliv_count, sa.next_delivery), (0, before));
        let d = a.deltas();
        assert_eq!(relay(&mut b, &hb, &d), d.len() as u64);
        let sb = b.p.flow(&flow()).expect("b").st;
        assert_eq!((sb.deliv_count, sb.next_delivery), (0, before));
        assert_eq!(sb.read_seq, sa.read_seq);
    }

    #[test]
    fn a_whole_record_crosses_as_one_delta_each_way() {
        // A record of 2^14 bytes of plaintext crosses as one RxRecord, and
        // the standby holds it as one delivery, byte for byte.
        let (mut a, mut b, ha, hb) = crash_paired();
        receive_two_records(&mut a, 16_384);
        let d = a.deltas();
        assert_eq!(d.len(), 4, "RxSegment, RxRecord, RxSegment, RxRecord");
        for f in &d {
            md_parse(f).expect("a delta");
        }
        assert_eq!(relay(&mut b, &hb, &d), 4);
        let st = b.p.flow(&flow()).expect("flow").st;
        assert_eq!(st.deliv_count, 2);
        let big = &st.deliveries()[1];
        assert_eq!(usize::from(big.len), 16_384);
        assert!(big.bytes[..16_384]
            .iter()
            .enumerate()
            .all(|(i, x)| *x == (i % 253) as u8));
        a.op(tc_op::DELTA_ACK, &[&ha[..], &4u64.to_le_bytes()].concat());
        assert_eq!(a.tls.acks.last(), Some(&4), "every transition released");
        assert_eq!(a.p.counters.mirrors_lost, 0);

        // An outbound record of 1 500 bytes: one TxRecord.
        let rec = record(1495, 9);
        let mut ro = 0u32.to_le_bytes().to_vec();
        ro.extend_from_slice(&9u64.to_le_bytes());
        ro.extend_from_slice(&(rec.len() as u16).to_le_bytes());
        ro.extend_from_slice(&rec);
        // The consumer's clear bytes through it.
        ro.extend_from_slice(&(77u64 + 100).to_le_bytes());
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tls_flow(), 5, sc::DELTA_TLS_RECORD_OUT, &ro),
        );
        let d = a.deltas();
        assert_eq!(d.len(), 1);
        assert_eq!(relay(&mut b, &hb, &d), 5);
    }

    #[test]
    fn a_transition_the_stream_cannot_carry_ends_the_pairing_not_the_connection() {
        let tf = tls_flow();
        // A gap in a half's numbering.
        let (mut a, _b, ha, _hb) = crash_paired();
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 2, sc::DELTA_TLS_RETX_ACK, &[0; 8]),
        );
        let s = a.status(tc_op::ABORT);
        assert_eq!(
            (s.status, s.reason),
            (tc_st::UNSUPPORTED, tcs_why::MIRROR | tcs_lost::GAP)
        );
        assert_eq!(
            (a.ip.aborts.clone(), a.tls.aborts.clone()),
            (vec![sc::ABORT_MIRROR_LOST], vec![sc::ABORT_MIRROR_LOST])
        );
        assert_eq!(a.p.counters.mirrors_lost, 1);
        assert!(
            a.p.flow(&flow()).expect("still paired").live,
            "the connection runs on"
        );
        a.op(tc_op::DELTA_ACK, &[&ha[..], &1u64.to_le_bytes()].concat());
        assert_eq!(a.status(tc_op::DELTA_ACK).status, tc_st::UNSUPPORTED);

        // A key update into an epoch the record is not one short of.
        let (mut a, _b, _ha, _hb) = crash_paired();
        let mut ku = vec![1u8];
        ku.extend_from_slice(&2u32.to_le_bytes());
        ku.extend_from_slice(&[0; 3]);
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 1, sc::DELTA_TLS_KEY_UPDATE, &ku),
        );
        assert_eq!(
            a.status(tc_op::ABORT).reason,
            tcs_why::MIRROR | tcs_lost::DIVERGED
        );

        // Plaintext tls did not carry.
        let (mut a, _b, _ha, _hb) = crash_paired();
        let mut ri = 0u32.to_le_bytes().to_vec();
        ri.extend_from_slice(&6u64.to_le_bytes());
        ri.extend_from_slice(&[0; 8]);
        ri.extend_from_slice(&[0xFF, 0, 0]);
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 1, sc::DELTA_TLS_RECORD_IN, &ri),
        );
        assert_eq!(
            a.status(tc_op::ABORT).reason,
            tcs_why::MIRROR | tcs_lost::UNREPRESENTABLE
        );

        // A half that ends its own pairing.
        let (mut a, _b, _ha, _hb) = crash_paired();
        let mut p = tf.to_vec();
        p.extend_from_slice(&EPOCH.to_le_bytes());
        p.extend_from_slice(&[sc::CR_ABORTED, sc::STATUS_OK, sc::ABORT_MIRROR_LOST]);
        a.feed_half(TcsPort::Tls, &sc_frame(sc::MSG_SC_CONTINUITY, &p));
        assert_eq!(
            a.status(tc_op::ABORT).reason,
            tcs_why::MIRROR | tcs_lost::LAYER
        );
    }

    #[test]
    fn a_delivery_the_worker_never_consumed_is_carried_to_the_standby_s_tls() {
        let (mut a, mut b, _ha, hb) = crash_paired();
        let tf = tls_flow();
        let mut whole = tls_layout().recv;
        whole.extend(std::iter::repeat_n(0xAB, 45 - whole.len()));
        let mut rb = (whole.len() as u32).to_le_bytes().to_vec();
        rb.extend_from_slice(&whole);
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 1, sc::DELTA_TLS_RECV_BYTES, &rb),
        );
        let mut ri = 0u32.to_le_bytes().to_vec();
        ri.extend_from_slice(&6u64.to_le_bytes());
        ri.extend_from_slice(&[0; 8]);
        ri.push(23);
        ri.extend_from_slice(&2u16.to_le_bytes());
        ri.extend_from_slice(b"hi");
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 2, sc::DELTA_TLS_RECORD_IN, &ri),
        );
        let d = a.deltas();
        relay(&mut b, &hb, &d);
        let st = b.p.flow(&flow()).expect("b").st;
        assert_eq!((st.deliv_count, st.delivery_acked), (1, 4));
        // The worker never said it consumed it: the standby's `tls` is handed
        // it in the CT_TLS it imports, after the consumed cursor,
        // to hand its own worker again.
        b.op(tc_op::EMISSION_ARM, &hb);
        assert_eq!(b.status(tc_op::EMISSION_ARM).status, tc_st::OK);
        let rec = b.tls.imported.clone().expect("tls");
        let th = ct_tls_decode(&rec).expect("ct_tls");
        assert_eq!((th.deliv_count, th.deliv_len, th.delivered_in), (1, 4, 4));
        assert_eq!(&rec[th.deliv_at..th.sealed_at], &[2, 0, b'h', b'i']);

        // Past what `tls` hands its worker again it is refused, not dropped.
        let mut big = Box::new(st);
        big.deliv_count = 5;
        big.next_delivery = big.delivery_acked + 6;
        for k in 0..5 {
            big.deliv[k].id = big.delivery_acked + 1 + k as u64;
            big.deliv[k].len = 16_384;
        }
        let wr = b.p.flow(&flow()).expect("b").wrapped;
        const { assert!(5 * (2 + 16_384) > TCS_REDELIVER_MAX) };
        assert_eq!(tcs_importable(&big, &wr), Err(TcsRefuse::Unsupported));
        // Ids that do not follow the consumed cursor are refused too.
        let mut gap = Box::new(st);
        gap.deliv[0].id += 1;
        gap.next_delivery += 1;
        assert_eq!(tcs_importable(&gap, &wr), Err(TcsRefuse::Unsupported));
    }

    #[test]
    fn emission_disable_cuts_the_connection_off_at_both_modules() {
        let (mut a, _b, ha, _hb) = moved_to_armed();
        a.op(tc_op::EMISSION_DISABLE, &ha);
        let s = a.status(tc_op::EMISSION_DISABLE);
        assert_eq!(
            (s.status, s.value),
            (tc_st::OK, 1),
            "the custody generation"
        );
        assert!(
            a.ip.retired && a.tls.retired,
            "nothing left that could emit"
        );
        // A retry reports the same cutoff; RETIRE then only drops the pairing.
        a.ip.retired = false;
        a.op(tc_op::EMISSION_DISABLE, &ha);
        assert_eq!(a.status(tc_op::EMISSION_DISABLE).value, 1);
        a.op(tc_op::RETIRE, &ha);
        assert_eq!(a.status(tc_op::RETIRE).status, tc_st::OK);
        assert!(!a.ip.retired, "no second per-layer retire");
        assert!(a.p.flow(&flow()).is_none());
    }

    #[test]
    fn a_cut_holds_only_if_nothing_moved_since_the_checkpoint() {
        let (mut a, _b, ha, _hb) = moved_to_armed();
        // The peer acknowledged one more byte at the primary's ip.
        let mut fx = [0u8; FXTC_MAX];
        let mut moved = tcp_half(5000, 5000);
        moved.rcv_nxt += 1;
        moved.delivered += 1;
        let n = fxtc_encode(&moved, &mut fx).expect("fxtc");
        a.ip.live = Some(fx[..n].to_vec());
        a.op(tc_op::CUT_EXPORT, &ha);
        assert_eq!(a.status(tc_op::CUT_EXPORT).status, tc_st::NOT_READY);
    }

    #[test]
    fn a_layer_that_never_answers_fails_the_operation() {
        let mut a = Host::new(ANCHOR_A);
        let f = sc_frame(
            tc_op::PAIR_PREPARE,
            &pair(TcRole::Primary, TcMode::PlannedOnly),
        );
        a.p.ctl(&f, a.now, &mut a.out);
        a.out.ip.clear();
        a.p.poll(a.now + TCS_JOB_MS, &mut a.out);
        assert_eq!(a.status(tc_op::PAIR_PREPARE).status, tc_st::NOT_READY);
        assert!(a.p.flow(&flow()).is_none());
        assert_eq!(a.p.counters.timeouts, 1);
    }

    // ── KeyUpdate under crash continuity ─────────────────────────────────

    /// `tls`'s KEY_UPDATE delta: `[direction][epoch][sealed_len][sealed]`.
    /// `tls`'s KEY_UPDATE delta: a read rotation ends `[owed]`, here none.
    fn ku_delta(dir: u8, epoch: u32) -> Vec<u8> {
        let mut b = vec![dir];
        b.extend_from_slice(&epoch.to_le_bytes());
        b.extend_from_slice(&(TCS_SEALED_LEN as u16).to_le_bytes());
        b.extend_from_slice(&[0x77; TCS_SEALED_LEN]);
        if dir == 1 {
            b.push(0);
        }
        b
    }

    #[test]
    fn a_key_update_under_crash_continuity_moves_by_reference_and_is_derived_at_import() {
        let (mut a, mut b, ha, hb) = crash_paired();
        let tf = tls_flow();
        let held = a.p.flow(&flow()).expect("flow").st;
        // The peer's KeyUpdate (read, into tls epoch 1), then ours (write).
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 1, sc::DELTA_TLS_KEY_UPDATE, &ku_delta(1, 1)),
        );
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 2, sc::DELTA_TLS_KEY_UPDATE, &ku_delta(0, 1)),
        );
        assert!(
            a.p.flow(&flow()).expect("flow").mirroring,
            "the pairing holds"
        );
        let d = a.deltas();
        assert_eq!(d.len(), 2, "two KeyUpdates");
        for (k, f) in d.iter().enumerate() {
            let (hd, payload) = md_parse(f).expect("delta");
            assert_eq!(hd.kind, MdKind::KeyUpdate);
            // No secret: a reference into the object the standby holds, and
            // that object's digest unchanged.
            // An inbound one then says whether the peer asked for ours.
            assert_eq!(payload.len(), 1 + 4 + 16 + 32 + usize::from(k == 0));
            assert_eq!(&payload[21..53], &held.wrapped_digest[..]);
            assert_eq!(payload[0], if k == 0 { MD_DIR_IN } else { MD_DIR_OUT });
        }
        assert!(a.tls.acks.is_empty(), "the barrier waits for the standby");
        assert_eq!(relay(&mut b, &hb, &d), 2);
        a.op(tc_op::DELTA_ACK, &[&ha[..], &2u64.to_le_bytes()].concat());
        assert_eq!(a.tls.acks, vec![2], "released once held");
        let st = b.p.flow(&flow()).expect("b").st;
        assert_eq!((st.read_epoch, st.write_epoch), (4, 4));

        // The primary crashes; the standby's tls is handed a record past its
        // sealed set by one KeyUpdate each way, to derive at import.
        drop(a);
        b.op(tc_op::EMISSION_ARM, &hb);
        assert_eq!(b.status(tc_op::EMISSION_ARM).status, tc_st::OK);
        let th = ct_tls_decode(&b.tls.imported.clone().expect("tls")).expect("ct_tls");
        assert_eq!(
            (
                th.read_epoch,
                th.write_epoch,
                th.sealed_read_epoch,
                th.sealed_write_epoch
            ),
            (1, 1, 0, 0)
        );
        assert_eq!((th.read_seq, th.write_seq), (0, 0));
    }

    #[test]
    fn the_answer_to_a_key_update_a_crashed_primary_owed_is_carried_to_the_standby() {
        // The peer asked for ours; the primary rotated its read keys and
        // crashed before its own KeyUpdate. The inbound KeyUpdate delta says
        // the answer is owed, the standby's record holds it, and the CT_TLS
        // its tls imports carries it (key_update bit 1), so that tls answers
        // before anything else.
        let (mut a, mut b, ha, hb) = crash_paired();
        let tf = tls_flow();
        let mut ku = ku_delta(1, 1);
        *ku.last_mut().expect("owed") = 1;
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 1, sc::DELTA_TLS_KEY_UPDATE, &ku),
        );
        let d = a.deltas();
        assert_eq!(d.len(), 1);
        let (_, payload) = md_parse(&d[0]).expect("a delta");
        assert_eq!(payload.len(), 1 + 4 + 16 + 32 + 1, "the requested byte");
        assert_eq!(payload[53], 1);
        assert_eq!(relay(&mut b, &hb, &d), 1);
        a.op(tc_op::DELTA_ACK, &[&ha[..], &1u64.to_le_bytes()].concat());
        assert!(b.p.flow(&flow()).expect("b").st.key_update_owed);
        drop(a);
        b.op(tc_op::EMISSION_ARM, &hb);
        assert_eq!(b.status(tc_op::EMISSION_ARM).status, tc_st::OK);
        let rec = b.tls.imported.clone().expect("tls");
        let th = ct_tls_decode(&rec).expect("ct_tls");
        assert_eq!(th.key_update, 2, "the answer owed");
        assert_eq!((th.read_epoch, th.write_epoch), (1, 0));

        // Answered (our write rotation), it is no longer owed.
        let (mut a, mut b, _ha, hb) = crash_paired();
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 1, sc::DELTA_TLS_KEY_UPDATE, &ku),
        );
        let ours = ku_delta(0, 1);
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 2, sc::DELTA_TLS_KEY_UPDATE, &ours),
        );
        let d = a.deltas();
        assert_eq!(relay(&mut b, &hb, &d), 2);
        assert!(!b.p.flow(&flow()).expect("b").st.key_update_owed);

        // A read rotation without its `[owed]`, or an owed byte past 1, is
        // not a delta `tls` writes: the pairing ends.
        for bad in [ku_delta(1, 1)[..7 + TCS_SEALED_LEN].to_vec(), {
            let mut k = ku_delta(1, 1);
            *k.last_mut().expect("owed") = 2;
            k
        }] {
            let (mut a, _b, _ha, _hb) = crash_paired();
            a.feed_half(
                TcsPort::Tls,
                &half_delta(&tf, 1, sc::DELTA_TLS_KEY_UPDATE, &bad),
            );
            assert_eq!(
                a.status(tc_op::ABORT).reason,
                tcs_why::MIRROR | tcs_lost::DIVERGED
            );
        }
    }

    #[test]
    fn key_updates_past_what_tls_derives_forward_end_the_pairing() {
        let (mut a, _b, _ha, _hb) = crash_paired();
        let tf = tls_flow();
        for k in 0..=TCS_DERIVE_MAX {
            a.feed_half(
                TcsPort::Tls,
                &half_delta(&tf, k + 1, sc::DELTA_TLS_KEY_UPDATE, &ku_delta(1, k + 1)),
            );
            let no = u64::from(k + 1);
            let ha = handle_of(&TcStatus {
                op: 0,
                status: 0,
                reason: 0,
                handle: a.p.flow(&flow()).expect("flow").handle,
                value: 0,
                flow_id: flow(),
            });
            a.op(tc_op::DELTA_ACK, &[&ha[..], &no.to_le_bytes()].concat());
        }
        assert_eq!(
            a.status(tc_op::ABORT).reason,
            tcs_why::MIRROR | tcs_lost::UNREPRESENTABLE
        );
    }

    // ── custody: vault-to-vault transfer of the continuity key ───────────

    fn custody_op(h: &[u8; 8], body: &[u8]) -> Vec<u8> {
        [&h[..], body].concat()
    }

    #[test]
    fn the_continuity_key_moves_vault_to_vault_on_the_authority_s_verdict() {
        let (mut a, mut b, ha, hb) = crash_paired();
        assert_ne!(a.p.capabilities() & tc_cap::VAULT_TRANSFER, 0);
        let challenge = [0xC4u8; 32];

        // The standby's vault attests a fresh recipient over the challenge.
        b.op(tc_op::CUSTODY_ATTEST, &custody_op(&hb, &challenge));
        let evs = b.events();
        let ev = evs
            .iter()
            .find(|(t, _)| *t == tc_evt::CUSTODY)
            .expect("evidence")
            .1
            .clone();
        assert_eq!(ev[8], tc_custody::EVIDENCE);
        let evidence = ev[9..].to_vec();
        assert!(TcCustodyEvidence::check(&evidence, &challenge).is_ok());
        let cmd = b.tls.custody.last().expect("attest").clone();
        assert_eq!(
            &cmd[..16],
            &flow()[..],
            "the recipient is named by the record's flow"
        );
        assert_eq!((cmd[20], &cmd[21..]), (sc::custody::ATTEST, &challenge[..]));

        // Evidence for another transfer's challenge is refused by the
        // provider before the authority is asked.
        a.op(
            tc_op::CUSTODY_WRAP,
            &custody_op(&ha, &[&[0u8; 32][..], &evidence].concat()),
        );
        let s = a.status(tc_op::CUSTODY_WRAP);
        assert_eq!(
            (s.status, s.reason),
            (tc_st::INVALID, tc_custody::why::CHALLENGE)
        );
        assert!(a.out.auth.is_empty());

        // The authority refuses: nothing is wrapped.
        let body = [&challenge[..], &evidence].concat();
        a.op(tc_op::CUSTODY_WRAP, &custody_op(&ha, &body));
        let ask = a.out.auth.pop_front().expect("custody check");
        assert_eq!(ask[0], TCS_MSG_CUSTODY_CHECK);
        assert_eq!(&ask[3..19], &flow()[..]);
        assert_eq!(&ask[23..55], &challenge[..]);
        assert_eq!(&ask[55..], &evidence[..]);
        let mut v = vec![TCS_MSG_CUSTODY_VERDICT, 49, 0];
        v.extend_from_slice(&flow());
        v.extend_from_slice(&sha256(&evidence));
        v.push(0x21);
        a.p.verdict_in(&v, a.now, &mut a.out);
        a.settle();
        let s = a.status(tc_op::CUSTODY_WRAP);
        assert_eq!((s.status, s.reason), (tc_st::UNAUTHORIZED, 0x21));
        assert!(a.tls.custody.is_empty(), "the vault was never asked");

        // The authority accepts: the primary's vault wraps to the recipient.
        a.op(tc_op::CUSTODY_WRAP, &custody_op(&ha, &body));
        let _ = a.out.auth.pop_front().expect("custody check");
        let n = v.len();
        v[n - 1] = 0;
        a.p.verdict_in(&v, a.now, &mut a.out);
        a.settle();
        let cmd = a.tls.custody.last().expect("wrap").clone();
        assert_eq!(&cmd[..16], &tls_flow()[..], "the session tls holds");
        assert_eq!(cmd[20], sc::custody::WRAP);
        assert_eq!(&cmd[21..], &body[..]);
        let evs = a.events();
        let w = evs
            .iter()
            .find(|(t, _)| *t == tc_evt::CUSTODY)
            .expect("wrapped")
            .1
            .clone();
        assert_eq!(w[8], tc_custody::WRAPPED);
        let wrapped = w[9..].to_vec();
        assert_eq!(wrapped.len(), tc_custody::WRAPPED_LEN);
        assert!(evs.iter().any(|(t, p)| *t == tc_evt::STATUS
            && p[0] == tc_op::CUSTODY_WRAP
            && p[1] == tc_st::OK));

        // The standby's vault unwraps it, for the session the wrapped
        // object names.
        b.op(tc_op::CUSTODY_UNWRAP, &custody_op(&hb, &wrapped));
        assert_eq!(b.status(tc_op::CUSTODY_UNWRAP).status, tc_st::OK);
        let cmd = b.tls.custody.last().expect("unwrap").clone();
        assert_eq!(&cmd[..16], &tls_flow()[..]);
        assert_eq!(cmd[20], sc::custody::UNWRAP);
        assert_eq!(&cmd[21..37], &flow()[..], "the recipient's name");
        assert_eq!(&cmd[37..], &wrapped[..]);
        assert!(b.p.flow(&flow()).expect("b").key_unwrapped);

        // A vault that will not open it: the standby says so by name.
        b.tls.custody_refuse = Some((sc::STATUS_CORRUPT, sc::custody::why::VAULT));
        b.op(tc_op::CUSTODY_UNWRAP, &custody_op(&hb, &wrapped));
        let s = b.status(tc_op::CUSTODY_UNWRAP);
        assert_eq!(
            (s.status, s.reason),
            (tc_st::INVALID, tc_custody::why::VAULT)
        );
    }

    #[test]
    fn custody_operations_belong_to_their_roles_and_to_a_held_object() {
        let mut a = Host::new(ANCHOR_A);
        let mut b = Host::new(ANCHOR_B);
        let mut fx = [0u8; FXTC_MAX];
        let n = fxtc_encode(&tcp_half(5000, 5000), &mut fx).expect("fxtc");
        a.ip.live = Some(fx[..n].to_vec());
        a.tls.live = Some(ct_tls(&tls_layout()));
        a.op(
            tc_op::PAIR_PREPARE,
            &pair(TcRole::Primary, TcMode::PlannedOnly),
        );
        let ha = handle_of(&a.status(tc_op::PAIR_PREPARE));
        b.op(
            tc_op::PAIR_PREPARE,
            &pair(TcRole::Standby, TcMode::PlannedOnly),
        );
        let hb = handle_of(&b.status(tc_op::PAIR_PREPARE));
        // A primary does not attest; a standby does not wrap.
        a.op(tc_op::CUSTODY_ATTEST, &custody_op(&ha, &[0; 32]));
        assert_eq!(a.status(tc_op::CUSTODY_ATTEST).status, tc_st::INVALID);
        b.op(tc_op::CUSTODY_WRAP, &custody_op(&hb, &[0; 32]));
        assert_eq!(b.status(tc_op::CUSTODY_WRAP).status, tc_st::INVALID);
        // Unwrapping before the wrapped object names the session: not yet.
        b.op(
            tc_op::CUSTODY_UNWRAP,
            &custody_op(&hb, &[0xAB; tc_custody::WRAPPED_LEN]),
        );
        assert_eq!(b.status(tc_op::CUSTODY_UNWRAP).status, tc_st::NOT_READY);
        // Evidence that does not parse.
        a.op(tc_op::CUSTODY_WRAP, &custody_op(&ha, &[0; 40]));
        let s = a.status(tc_op::CUSTODY_WRAP);
        assert_eq!(
            (s.status, s.reason),
            (tc_st::INVALID, tc_custody::why::EVIDENCE)
        );
        // A persisted recipient is not an ephemeral one.
        let ch = [7u8; 32];
        let mut ev = evidence(&ch);
        ev[tc_custody::R_PERSISTED] = 1;
        a.op(
            tc_op::CUSTODY_WRAP,
            &custody_op(&ha, &[&ch[..], &ev].concat()),
        );
        let s = a.status(tc_op::CUSTODY_WRAP);
        assert_eq!(
            (s.status, s.reason),
            (tc_st::INVALID, tc_custody::why::RECIPIENT)
        );
    }

    // ── full tables hold; they do not end the pairing ────────────────────

    /// `tls`'s RECORD_OUT of a `ct_len`-byte record at write sequence `seq`.
    fn record_out(seq: u64, ct_len: usize, out_bytes: u64) -> Vec<u8> {
        let rec = record(ct_len - 5, 7);
        let mut ro = 0u32.to_le_bytes().to_vec();
        ro.extend_from_slice(&seq.to_le_bytes());
        ro.extend_from_slice(&(rec.len() as u16).to_le_bytes());
        ro.extend_from_slice(&rec);
        ro.extend_from_slice(&out_bytes.to_le_bytes());
        ro
    }

    /// `ip`'s ACKED: the peer acknowledged through `una`.
    fn acked(una: u32) -> Vec<u8> {
        let mut b = una.to_le_bytes().to_vec();
        b.extend_from_slice(&64_000u16.to_le_bytes());
        b.extend_from_slice(&14_600u16.to_le_bytes());
        b.extend_from_slice(&u16::MAX.to_le_bytes());
        b
    }

    impl Host {
        /// Offer a half's frame as the module does: taken only when
        /// `layer_room` says so. Whether it was.
        fn offer(&mut self, port: TcsPort, frame: &[u8]) -> bool {
            if !self.p.layer_room(port, frame, &self.out) {
                return false;
            }
            self.feed_half(port, frame);
            true
        }

        fn lost(&mut self) -> Option<TcStatus> {
            let evs: Vec<_> = self.out.evt.iter().cloned().collect();
            evs.iter().find_map(|f| {
                (f[0] == tc_evt::STATUS && f[3] == tc_op::ABORT)
                    .then(|| TcStatus::decode(&f[3..]).expect("status"))
            })
        }
    }

    /// Small records written faster than the peer acknowledges them: more
    /// than `TS_TXREC_MAX` would stand. The provider takes the record that
    /// would be the 33rd only once `ip`'s acknowledgement freed a slot — it
    /// waits on `tls`'s port meanwhile — and the pairing holds throughout.
    #[test]
    fn a_full_outbound_table_holds_the_record_until_the_peer_acknowledges() {
        let (mut a, _b, ha, _hb) = crash_paired();
        let tf = tls_flow();
        let mut seq = 9u64;
        for no in 1..=TS_TXREC_MAX as u32 {
            let f = half_delta(
                &tf,
                no,
                sc::DELTA_TLS_RECORD_OUT,
                &record_out(seq, 26, 77 + seq),
            );
            assert!(a.offer(TcsPort::Tls, &f), "record {no} taken");
            a.op(
                tc_op::DELTA_ACK,
                &[&ha[..], &u64::from(no).to_le_bytes()].concat(),
            );
            seq += 1;
        }
        let st = a.p.flow(&flow()).expect("a").st;
        assert_eq!(usize::from(st.tx_count), TS_TXREC_MAX);
        let next = half_delta(
            &tf,
            TS_TXREC_MAX as u32 + 1,
            sc::DELTA_TLS_RECORD_OUT,
            &record_out(seq, 26, 77 + seq),
        );
        for _ in 0..3 {
            assert!(!a.offer(TcsPort::Tls, &next), "the 33rd waits on its port");
        }
        assert!(a.p.counters.layer_holds >= 3);
        assert!(a.lost().is_none(), "the pairing holds");
        // The peer acknowledges the first two records: one frees a slot.
        a.feed_half(
            TcsPort::Ip,
            &half_delta(&flow(), 1, sc::DELTA_TCP_ACKED, &acked(5000 + 2 * 26)),
        );
        assert!(a.offer(TcsPort::Tls, &next), "taken once a slot is free");
        let st = a.p.flow(&flow()).expect("a").st;
        assert_eq!(usize::from(st.tx_count), TS_TXREC_MAX - 1);
        assert!(a.lost().is_none());
        assert!(a.p.flow(&flow()).expect("a").mirroring);
    }

    /// The horizon gate's journal (`TCS_GATE_J`) fills when the standby is
    /// slow: the halves' next frames wait until its acknowledgement returns
    /// credits, where a full journal once ended the pairing.
    #[test]
    fn a_full_gate_journal_holds_both_halves_until_the_standby_acknowledges() {
        let (mut a, _b, ha, _hb) = crash_paired();
        let tf = tls_flow();
        let mut seq = 9u64;
        let mut no = 1u32;
        let mut una = 5000u32;
        // Record, then the peer's acknowledgement of it: two deltas each,
        // the outbound table never full, nothing acknowledged by the standby.
        while a.p.flow(&flow()).expect("a").gate.credits() >= TCS_FRAME_DELTAS {
            let f = half_delta(
                &tf,
                no,
                sc::DELTA_TLS_RECORD_OUT,
                &record_out(seq, 26, 77 + seq),
            );
            assert!(a.offer(TcsPort::Tls, &f));
            una += 26;
            let g = half_delta(&flow(), no, sc::DELTA_TCP_ACKED, &acked(una));
            if !a.offer(TcsPort::Ip, &g) {
                break;
            }
            no += 1;
            seq += 1;
        }
        let credits = a.p.flow(&flow()).expect("a").gate.credits();
        assert!(
            credits < TCS_FRAME_DELTAS,
            "the journal is full ({credits})"
        );
        let f = half_delta(
            &tf,
            no + 1,
            sc::DELTA_TLS_RECORD_OUT,
            &record_out(seq + 1, 26, 99),
        );
        assert!(!a.p.layer_room(TcsPort::Tls, &f, &a.out), "tls waits");
        assert!(a.lost().is_none(), "the pairing holds");
        let top = a.p.flow(&flow()).expect("a").delta_seq;
        a.op(tc_op::DELTA_ACK, &[&ha[..], &top.to_le_bytes()].concat());
        assert_eq!(a.p.flow(&flow()).expect("a").gate.credits(), TCS_GATE_J);
        assert!(
            a.p.layer_room(TcsPort::Tls, &f, &a.out),
            "taken once acknowledged"
        );
        assert!(a.p.flow(&flow()).expect("a").mirroring);
    }

    /// A half's queue of deltas waiting on their horizons (`TCS_PEND`) fills
    /// with `ip`'s receive transitions whose bytes `tls` has not mirrored
    /// yet: `ip`'s next frame waits, the pairing holds, and `tls`'s bytes
    /// (on the other port) settle the queue.
    #[test]
    fn a_full_half_queue_holds_that_half() {
        let (mut a, _b, _ha, _hb) = crash_paired();
        let mut at = 80_000u32;
        for no in 1..=TCS_PEND as u32 {
            let mut rx = at.to_le_bytes().to_vec();
            rx.extend_from_slice(&1u16.to_le_bytes());
            rx.extend_from_slice(&(at + 1).to_le_bytes());
            rx.push(0);
            assert!(a.offer(
                TcsPort::Ip,
                &half_delta(&flow(), no, sc::DELTA_TCP_RECV, &rx)
            ));
            at += 1;
        }
        assert_eq!(a.p.flow(&flow()).expect("a").ip.pend_n, TCS_PEND);
        let mut rx = at.to_le_bytes().to_vec();
        rx.extend_from_slice(&1u16.to_le_bytes());
        rx.extend_from_slice(&(at + 1).to_le_bytes());
        rx.push(0);
        let next = half_delta(&flow(), TCS_PEND as u32 + 1, sc::DELTA_TCP_RECV, &rx);
        assert!(!a.offer(TcsPort::Ip, &next), "ip waits");
        assert!(a.lost().is_none(), "the pairing holds");
        // `tls` is not held by `ip`'s queue.
        let tf = tls_flow();
        let f = half_delta(&tf, 1, sc::DELTA_TLS_RECORD_OUT, &record_out(9, 26, 86));
        assert!(a.p.layer_room(TcsPort::Tls, &f, &a.out));
    }

    /// Ports whose event queue has `evt_room` bytes free.
    struct Tight {
        inner: Ports,
        evt_room: usize,
    }

    impl TcsOut for Tight {
        fn send(&mut self, port: TcsPort, frame: &[u8]) -> bool {
            self.inner.send(port, frame)
        }
        fn room(&self, port: TcsPort) -> usize {
            if port == TcsPort::Evt {
                self.evt_room
            } else {
                usize::MAX
            }
        }
    }

    /// The anchor stops draining its events: a half's frame is not taken
    /// while the event queue lacks room for what it can become, and is the
    /// moment there is.
    #[test]
    fn a_full_event_queue_holds_the_halves() {
        let (a, _b, _ha, _hb) = crash_paired();
        let mut p = a.p;
        let tf = tls_flow();
        let f = half_delta(&tf, 1, sc::DELTA_TLS_RECORD_OUT, &record_out(9, 26, 86));
        let mut out = Tight {
            inner: Ports::default(),
            evt_room: TCS_FRAME_EVT - 1,
        };
        assert!(!p.layer_room(TcsPort::Tls, &f, &out));
        assert!(!p.layer_room(
            TcsPort::Ip,
            &half_delta(&flow(), 1, sc::DELTA_TCP_ACKED, &acked(5000)),
            &out
        ));
        out.evt_room = TCS_FRAME_EVT;
        assert!(p.layer_room(TcsPort::Tls, &f, &out));
        p.layer(TcsPort::Tls, &f, 1_000, &mut out);
        assert_eq!(p.flow(&flow()).expect("a").delta_seq, 1);
        assert!(p.flow(&flow()).expect("a").mirroring);
    }

    /// A layer that does not hold to the strict bounds anyway: the delta
    /// past the record's table ends the pairing named `BOUNDS`, not
    /// DIVERGED, with the record's tables as the STATUS value.
    #[test]
    fn a_delta_past_a_bound_is_reported_as_bounds_with_its_tables() {
        let (mut a, _b, ha, _hb) = crash_paired();
        let tf = tls_flow();
        let mut seq = 9u64;
        for no in 1..=TS_TXREC_MAX as u32 {
            a.feed_half(
                TcsPort::Tls,
                &half_delta(
                    &tf,
                    no,
                    sc::DELTA_TLS_RECORD_OUT,
                    &record_out(seq, 26, 77 + seq),
                ),
            );
            a.op(
                tc_op::DELTA_ACK,
                &[&ha[..], &u64::from(no).to_le_bytes()].concat(),
            );
            seq += 1;
        }
        // Past the provider's own hold, as a module that ignored it would.
        a.feed_half(
            TcsPort::Tls,
            &half_delta(
                &tf,
                TS_TXREC_MAX as u32 + 1,
                sc::DELTA_TLS_RECORD_OUT,
                &record_out(seq, 26, 77 + seq),
            ),
        );
        let s = a.lost().expect("the pairing ended");
        assert_eq!(s.reason, tcs_why::MIRROR | tcs_lost::BOUNDS);
        assert_eq!(s.value & 0xFF, MdKind::TxRecord as u64, "the delta's kind");
        assert_eq!(
            (s.value >> 8) & 0xFF,
            TS_TXREC_MAX as u64,
            "the outbound table, full"
        );
        assert_eq!(
            (s.value >> 32) & 0xFFFF,
            TS_TXREC_MAX as u64 * 26,
            "the send buffer"
        );
        assert_eq!(
            a.p.counters.last_refusal,
            tcs_why::MIRROR | tcs_lost::BOUNDS
        );
        assert!(!a.p.flow(&flow()).expect("a").mirroring);
    }

    // ── the flow's end ───────────────────────────────────────────────────

    fn reset_body(dir: u8, seq: u32, ack: u32) -> Vec<u8> {
        let mut b = vec![dir];
        b.extend_from_slice(&seq.to_le_bytes());
        b.extend_from_slice(&ack.to_le_bytes());
        b
    }

    /// Relay `deltas` to the standby; everything it reported.
    fn relay_all(b: &mut Host, hb: &[u8; 8], deltas: &[Vec<u8>]) -> Vec<(u8, Vec<u8>)> {
        let mut evs = Vec::new();
        for d in deltas {
            b.op(tc_op::DELTA_APPLY, &[&hb[..], d].concat());
            evs.extend(b.events());
        }
        evs
    }

    fn ended(evs: &[(u8, Vec<u8>)]) -> Option<(u8, u8)> {
        evs.iter()
            .find(|(t, _)| *t == tc_evt::ENDED)
            .map(|(_, p)| (p[8], p[9]))
    }

    fn aborted(evs: &[(u8, Vec<u8>)]) -> bool {
        evs.iter()
            .any(|(t, p)| *t == tc_evt::STATUS && p[0] == tc_op::ABORT)
    }

    fn kinds(evs: &[(u8, Vec<u8>)]) -> Vec<MdKind> {
        evs.iter()
            .filter(|(t, _)| *t == tc_evt::DELTA)
            .map(|(_, p)| md_parse(&p[8..]).expect("a delta").0.kind)
            .collect()
    }

    /// The peer resets a crash-continuous connection: `ip`'s reset becomes the
    /// `Reset` delta and the flow's end — not the pairing's loss — at both
    /// ends. The standby lets its shadow go, keeps the flow's tombstone, and
    /// refuses to arm, activate or import it, by name; RETIRE and ABORT let
    /// the slots go.
    #[test]
    fn the_peers_reset_ends_the_flow_at_both_ends_not_the_pairing() {
        let (mut a, mut b, ha, hb) = crash_paired();
        a.feed_half(
            TcsPort::Ip,
            &half_delta(
                &flow(),
                1,
                sc::DELTA_TCP_RESET,
                &reset_body(MD_DIR_IN, 80_000, 5000),
            ),
        );
        let evs = a.events();
        assert_eq!(kinds(&evs), vec![MdKind::Reset]);
        assert_eq!(ended(&evs), Some((tc_end::RESET, MD_DIR_IN)), "{evs:?}");
        assert!(!aborted(&evs), "a reset is no loss of the pairing");
        assert!(a.ip.aborts.is_empty() && a.tls.aborts.is_empty());
        let fa = a.p.flow(&flow()).expect("a");
        assert!(fa.ended && !fa.mirroring);
        let ds: Vec<Vec<u8>> = evs
            .iter()
            .filter(|(t, _)| *t == tc_evt::DELTA)
            .map(|(_, p)| p[8..].to_vec())
            .collect();

        let bev = relay_all(&mut b, &hb, &ds);
        assert!(bev.iter().any(|(t, _)| *t == tc_evt::APPLIED), "{bev:?}");
        assert_eq!(ended(&bev), Some((tc_end::RESET, MD_DIR_IN)));
        assert_eq!(b.p.flow(&flow()).expect("b").st.tcp, TsTcp::Reset);
        // ip's shadow goes, the flow's tombstone stays.
        assert_eq!(b.ip.aborts.len(), 1);
        assert_eq!(b.ip.tombs.len(), 1);
        assert_eq!(&b.ip.tombs[0][..16], &flow()[..]);
        assert_eq!(
            u32::from_le_bytes(b.ip.tombs[0][20..24].try_into().expect("ttl")),
            5_000
        );
        for (op, body) in [
            (tc_op::EMISSION_ARM, hb.to_vec()),
            (
                tc_op::ACTIVATE,
                [
                    &hb[..],
                    &2u32.to_le_bytes(),
                    &1u32.to_le_bytes(),
                    &[0xCA; 16],
                ]
                .concat(),
            ),
            (
                tc_op::CUT_IMPORT,
                [&hb[..], &[0u8; TC_CUT_LEN][..]].concat(),
            ),
        ] {
            b.op(op, &body);
            let s = b.status(op);
            assert_eq!(
                (s.status, s.reason),
                (tc_st::UNSUPPORTED, tcs_why::ENDED),
                "op {op} on an ended flow"
            );
        }
        assert!(!b.ip.armed && b.ip.activated.is_none() && b.out.auth.is_empty());
        b.op(tc_op::ABORT, &hb);
        assert_eq!(b.status(tc_op::ABORT).status, tc_st::OK);
        assert!(b.p.flow(&flow()).is_none(), "the standby's slot is free");
        a.op(tc_op::RETIRE, &ha);
        assert_eq!(a.status(tc_op::RETIRE).status, tc_st::OK);
        assert!(!a.ip.retired, "nothing left at ip to retire");
        assert!(a.p.flow(&flow()).is_none());
    }

    /// Our reset: `ip` holds the RST at the send horizon, so its delta's
    /// acknowledgement — the standby holding the `Reset` — is what releases
    /// it, and the flow's end is reported then.
    #[test]
    fn our_reset_is_released_only_once_the_standby_holds_it() {
        let (mut a, mut b, ha, hb) = crash_paired();
        a.feed_half(
            TcsPort::Ip,
            &half_delta(
                &flow(),
                1,
                sc::DELTA_TCP_RESET,
                &reset_body(MD_DIR_OUT, 5000, 80_000),
            ),
        );
        let evs = a.events();
        assert_eq!(kinds(&evs), vec![MdKind::Reset]);
        assert_eq!(ended(&evs), None, "not before the standby holds it");
        assert!(a.ip.acks.is_empty(), "the RST waits");
        let ds: Vec<Vec<u8>> = evs
            .iter()
            .filter(|(t, _)| *t == tc_evt::DELTA)
            .map(|(_, p)| p[8..].to_vec())
            .collect();
        let bev = relay_all(&mut b, &hb, &ds);
        assert_eq!(ended(&bev), Some((tc_end::RESET, MD_DIR_OUT)));
        let top = bev
            .iter()
            .filter(|(t, _)| *t == tc_evt::APPLIED)
            .map(|(_, p)| u64::from_le_bytes(p[16..24].try_into().expect("seq")))
            .max()
            .expect("applied");
        a.op(tc_op::DELTA_ACK, &[&ha[..], &top.to_le_bytes()].concat());
        assert_eq!(a.ip.acks.last(), Some(&1), "the RST released");
        let evs = a.events();
        assert_eq!(ended(&evs), Some((tc_end::RESET, MD_DIR_OUT)));
        assert!(!aborted(&evs));
        // A late acknowledgement of an ended flow is no one's.
        a.op(tc_op::DELTA_ACK, &[&ha[..], &top.to_le_bytes()].concat());
        assert!(a.events().is_empty());
    }

    /// A connection that completes its close ends its flow; and a `tls` that
    /// ends its half while `ip` never says how is reported closed once `ip`
    /// had its time.
    #[test]
    fn a_completed_close_ends_the_flow() {
        let (mut a, _b, _ha, _hb) = crash_paired();
        a.feed_half(
            TcsPort::Ip,
            &half_delta(&flow(), 1, sc::DELTA_TCP_CLOSED, &[]),
        );
        let evs = a.events();
        assert_eq!(ended(&evs), Some((tc_end::CLOSED, 0)));
        assert!(kinds(&evs).is_empty() && !aborted(&evs));

        let (mut a, _b, _ha, _hb) = crash_paired();
        let mut p = tls_flow().to_vec();
        p.extend_from_slice(&EPOCH.to_le_bytes());
        p.extend_from_slice(&[sc::CR_ENDED, sc::STATUS_OK, sc::END_TRANSPORT]);
        a.feed_half(TcsPort::Tls, &sc_frame(sc::MSG_SC_CONTINUITY, &p));
        let evs = a.events();
        assert_eq!(ended(&evs), None, "ip's end is awaited");
        assert!(!aborted(&evs), "tls's end is no loss");
        a.now += TCS_JOB_MS + 1;
        a.p.poll(a.now, &mut a.out);
        a.settle();
        let evs = a.events();
        assert_eq!(ended(&evs), Some((tc_end::CLOSED, 0)));
        assert!(!aborted(&evs));
    }

    /// A layer that abandons its pairing says why, and the STATUS that ends
    /// the pairing carries it: the layer in the value's second byte, its
    /// reason in the first.
    #[test]
    fn a_layer_that_abandons_its_pairing_names_why() {
        for reason in [
            sc::ABORT_TXREC_CAP,
            sc::ABORT_REDELIVER_CAP,
            sc::ABORT_HORIZON_BUDGET,
            sc::ABORT_MIRROR_LOST,
        ] {
            let (mut a, _b, _ha, _hb) = crash_paired();
            let mut p = tls_flow().to_vec();
            p.extend_from_slice(&EPOCH.to_le_bytes());
            p.extend_from_slice(&[sc::CR_ABORTED, sc::STATUS_OK, reason]);
            a.feed_half(TcsPort::Tls, &sc_frame(sc::MSG_SC_CONTINUITY, &p));
            let s = a.status(tc_op::ABORT);
            assert_eq!(
                (s.status, s.reason, s.value),
                (
                    tc_st::UNSUPPORTED,
                    tcs_why::MIRROR | tcs_lost::LAYER,
                    u64::from(sc::CT_TLS) << 8 | u64::from(reason)
                ),
                "reason {reason}"
            );
        }
    }

    /// A crash-continuous standby charges each timer the time since its
    /// remainder was current — the checkpoint's commit, or the delta that set
    /// it — and imports what remains, not a restarted timer. `ip`'s timers
    /// for a state the record reaches later (the peer's FIN deferred) wait
    /// for it.
    #[test]
    fn a_standby_imports_each_timer_at_what_remains_of_it() {
        let mut tcp = tcp_half(5000, 5000);
        tcp.ooo_count = 0;
        tcp.idle_period = 1200;
        tcp.idle_rem = 1000;
        let (mut a, mut b, _ha, hb) = crash_paired_tcp(&tcp);
        let st = b.p.flow(&flow()).expect("b").st;
        assert_eq!((st.idle_ms, st.idle_rem_ms), (60_000, 50_000));
        // 20 s pass at the standby; nothing sets the idle close again.
        b.now += 20_000;
        // `ip`'s timers as the peer's FIN arrives with 37 bytes the record
        // does not hold yet: CLOSE-WAIT's, held for the FIN.
        let mut rx = 80_000u32.to_le_bytes().to_vec();
        rx.extend_from_slice(&37u16.to_le_bytes());
        rx.extend_from_slice(&80_038u32.to_le_bytes());
        rx.push(1);
        a.feed_half(
            TcsPort::Ip,
            &half_delta(&flow(), 1, sc::DELTA_TCP_RECV, &rx),
        );
        let mut tm = vec![2u8];
        tm.extend_from_slice(&[0xE8, 0x03, 40, 0, 12, 0, 0x08, 0x39, 0xFF, 0xFF]);
        for rem in [0u32, 60_000, 0, 4_000, 0, 0] {
            tm.extend_from_slice(&rem.to_le_bytes());
        }
        a.feed_half(
            TcsPort::Ip,
            &half_delta(&flow(), 2, sc::DELTA_TCP_TIMERS, &tm),
        );
        assert!(
            a.deltas().is_empty(),
            "nothing before the bytes before the FIN"
        );
        let tf = tls_flow();
        let mut whole = tls_layout().recv;
        whole.extend(std::iter::repeat_n(0xAB, 45 - whole.len()));
        let mut rb = (whole.len() as u32).to_le_bytes().to_vec();
        rb.extend_from_slice(&whole);
        a.feed_half(
            TcsPort::Tls,
            &half_delta(&tf, 1, sc::DELTA_TLS_RECV_BYTES, &rb),
        );
        let ds = a.deltas();
        let k: Vec<MdKind> = ds
            .iter()
            .map(|f| md_parse(f).expect("a delta").0.kind)
            .collect();
        assert_eq!(k, vec![MdKind::RxSegment, MdKind::Fin, MdKind::Timers]);
        relay(&mut b, &hb, &ds);
        let st = b.p.flow(&flow()).expect("b").st;
        assert_eq!(
            (st.tcp, st.closewait_rem_ms, st.idle_rem_ms),
            (TsTcp::CloseWait, 4_000, 0)
        );
        // 1.5 s more, then the standby arms: CLOSE-WAIT's bound has 2.5 s
        // left — 50 ticks — not its whole length.
        b.now += 1_500;
        b.op(tc_op::EMISSION_ARM, &hb);
        assert_eq!(b.status(tc_op::EMISSION_ARM).status, tc_st::OK);
        let mut h = tcp_half(0, 0);
        fxtc_decode(&b.ip.imported.clone().expect("fxtc"), &mut h).expect("fxtc");
        assert_eq!((h.state, h.cw_rem, h.idle_period), (2, 50, 1200));
        // A remainder that ran out is due, never disarmed.
        let (_a, mut b, _ha, hb) = crash_paired_tcp(&tcp);
        b.now += 100_000;
        b.op(tc_op::EMISSION_ARM, &hb);
        assert_eq!(b.status(tc_op::EMISSION_ARM).status, tc_st::OK);
        let mut h = tcp_half(0, 0);
        fxtc_decode(&b.ip.imported.clone().expect("fxtc"), &mut h).expect("fxtc");
        assert_eq!(h.idle_rem, 1, "due at once");
    }
}
