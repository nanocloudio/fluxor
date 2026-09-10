//! Host mount + tests for the reusable continuity/protocol cores
//! The core sources live in
//! `modules/sdk/cores/` and are `include!`d by modules; path-mounting
//! them here means the host tests exercise byte-for-byte the same
//! logic the device runs — the same pattern as `wire.rs` /
//! `genstore_wire.rs`.

#[allow(
    dead_code,
    reason = "host tests reach a subset; device consumers use the rest"
)]
#[path = "../../modules/sdk/cores/nonce_reservation.rs"]
pub mod nonce_reservation;

#[allow(
    dead_code,
    reason = "host tests reach a subset; device consumers use the rest"
)]
#[path = "../../modules/sdk/cores/session_handoff.rs"]
pub mod session_handoff;

#[allow(
    dead_code,
    reason = "host tests reach a subset; device consumers use the rest"
)]
#[path = "../../modules/sdk/cores/protocol_timer.rs"]
pub mod protocol_timer;

#[cfg(test)]
mod tests {
    use super::nonce_reservation::{NonceReservation, ReservationError};
    use super::protocol_timer::ProtocolTimers;
    use super::session_handoff::{
        handoff_crc32, HandoffExport, HandoffImport, HANDOFF_CORRUPT, HANDOFF_NOT_READY,
        HANDOFF_NO_CAPACITY, HANDOFF_OK,
    };

    // ── nonce_reservation: base emit discipline ──────────────────

    #[test]
    fn reservation_no_emission_before_grant() {
        let mut r = NonceReservation::new();
        assert_eq!(r.next_value(), None, "unreserved emission must stall");
    }

    #[test]
    fn reservation_emits_within_block_then_stalls() {
        let mut r = NonceReservation::new();
        r.grant(1, 0, 4).unwrap();
        assert_eq!(r.next_value(), Some(0));
        assert_eq!(r.next_value(), Some(1));
        assert_eq!(r.next_value(), Some(2));
        assert_eq!(r.next_value(), Some(3));
        // Block dry, nothing staged: emit-path stall (§13.7.7).
        assert_eq!(r.next_value(), None);
    }

    #[test]
    fn reservation_refill_ahead_promotes_pending() {
        let mut r = NonceReservation::new();
        r.grant(1, 0, 2).unwrap();
        assert!(r.needs_refill(4), "low active block should ask for refill");
        r.grant(1, 2, 8).unwrap();
        assert!(
            !r.needs_refill(4),
            "pending block staged — no refill needed"
        );
        // Drain across the block boundary without a stall.
        let vals: Vec<u64> = std::iter::from_fn(|| r.next_value()).collect();
        assert_eq!(vals, (0..10).collect::<Vec<u64>>());
    }

    #[test]
    fn reservation_rejects_third_outstanding_block() {
        let mut r = NonceReservation::new();
        r.grant(1, 0, 4).unwrap();
        r.grant(1, 4, 4).unwrap();
        assert_eq!(r.grant(1, 8, 4), Err(ReservationError::Busy));
    }

    // ── nonce_reservation: identity space is never re-handed out ──

    #[test]
    fn reservation_rejects_overlapping_grant() {
        let mut r = NonceReservation::new();
        r.grant(1, 0, 100).unwrap();
        // Even after draining a few values, an overlapping grant is a
        // re-hand-out of live identity space.
        let _ = r.next_value();
        assert_eq!(r.grant(1, 50, 10), Err(ReservationError::Overlap));
        assert_eq!(r.grant(2, 99, 10), Err(ReservationError::Overlap));
        // At exactly high-water is fine.
        assert!(r.grant(1, 100, 10).is_ok());
    }

    #[test]
    fn reservation_abandoned_tail_is_wasted_not_reused() {
        let mut r = NonceReservation::new();
        r.grant(1, 0, 100).unwrap();
        assert_eq!(r.next_value(), Some(0));
        // Epoch bump (takeover happened elsewhere; this instance is the
        // stale survivor being re-granted). The old block's unused tail
        // (1..100) must not come back: the new grant starts at 100+.
        assert_eq!(r.grant(2, 10, 10), Err(ReservationError::Overlap));
        r.grant(2, 100, 10).unwrap();
        assert_eq!(r.next_value(), Some(100));
    }

    // ── nonce_reservation: R2 epoch fencing ──────────────────────

    #[test]
    fn reservation_rejects_stale_epoch_grant() {
        let mut r = NonceReservation::new();
        r.grant(5, 0, 4).unwrap();
        assert_eq!(r.grant(4, 100, 4), Err(ReservationError::StaleEpoch));
        assert_eq!(r.epoch(), 5);
    }

    #[test]
    fn reservation_epoch_bump_drops_outstanding_blocks() {
        let mut r = NonceReservation::new();
        r.grant(1, 0, 4).unwrap();
        r.grant(1, 4, 4).unwrap();
        // Epoch fence: stale-epoch blocks must never emit again.
        r.grant(2, 8, 4).unwrap();
        assert_eq!(r.epoch(), 2);
        assert_eq!(r.next_value(), Some(8), "old-epoch values 0..8 fenced out");
    }

    #[test]
    fn reservation_unsafe_recovery_voids_blocks_until_epoch_bump() {
        let mut r = NonceReservation::new();
        r.grant(3, 0, 100).unwrap();
        assert_eq!(r.next_value(), Some(0));
        // Forced/unsafe quorum recovery on the directory (R2): all
        // outstanding blocks are void.
        r.void_outstanding();
        assert!(r.is_voided());
        assert_eq!(r.next_value(), None, "voided state must not emit");
        // A same-epoch grant could be a re-hand-out from the lost log
        // tail — refuse until the epoch bumps.
        assert_eq!(r.grant(3, 100, 10), Err(ReservationError::EpochNotBumped));
        r.grant(4, 100, 10).unwrap();
        assert!(!r.is_voided());
        assert_eq!(r.next_value(), Some(100));
    }

    #[test]
    fn reservation_takeover_resumes_strictly_ahead() {
        // Directory's view: dead anchor held blocks up to exclusive
        // end 200 at epoch 7. Takeover resumes at epoch 8 with floor
        // 200 — nothing the dead host could have emitted is reachable.
        let mut r = NonceReservation::resume(8, 200);
        assert_eq!(r.next_value(), None);
        assert_eq!(r.grant(8, 150, 10), Err(ReservationError::Overlap));
        r.grant(8, 200, 10).unwrap();
        assert_eq!(r.next_value(), Some(200));
    }

    #[test]
    fn reservation_rejects_zero_len_and_space_overflow() {
        let mut r = NonceReservation::new();
        assert_eq!(r.grant(1, 0, 0), Err(ReservationError::ZeroLen));
        assert_eq!(
            r.grant(1, u64::MAX - 1, 4),
            Err(ReservationError::SpaceExhausted)
        );
    }

    // ── session_handoff: export walk ─────────────────────────────

    #[test]
    fn handoff_export_walks_blob_in_capped_chunks() {
        let blob: Vec<u8> = (0..=255u8).collect();
        let mut exp = HandoffExport::new(blob.len() as u32);
        let mut chunks = Vec::new();
        while let Some((off, len)) = exp.next_chunk(100) {
            chunks.push((off, len));
            exp.advance(len);
        }
        assert!(exp.done());
        assert_eq!(chunks, vec![(0, 100), (100, 100), (200, 56)]);
    }

    #[test]
    fn handoff_roundtrip_export_import_ok() {
        let blob: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let crc = handoff_crc32(&blob);

        let mut dest = vec![0u8; 4096];
        let mut imp = HandoffImport::new();
        assert_eq!(imp.begin(blob.len() as u32, dest.len() as u32), HANDOFF_OK);

        let mut exp = HandoffExport::new(blob.len() as u32);
        while let Some((off, len)) = exp.next_chunk(128) {
            let data = &blob[off as usize..(off + len) as usize];
            assert_eq!(imp.chunk(off, data, &mut dest), HANDOFF_OK);
            exp.advance(len);
        }
        assert_eq!(imp.end(crc), HANDOFF_OK);
        assert!(imp.complete());
        assert_eq!(&dest[..blob.len()], &blob[..]);
    }

    #[test]
    fn handoff_import_rejects_capacity_overrun() {
        let mut imp = HandoffImport::new();
        assert_eq!(imp.begin(5000, 4096), HANDOFF_NO_CAPACITY);
        assert!(!imp.complete());
    }

    #[test]
    fn handoff_import_rejects_gap_and_crc_mismatch() {
        let blob = vec![7u8; 300];
        let mut dest = vec![0u8; 512];

        // Gap: second chunk skips bytes.
        let mut imp = HandoffImport::new();
        assert_eq!(imp.begin(300, 512), HANDOFF_OK);
        assert_eq!(imp.chunk(0, &blob[..100], &mut dest), HANDOFF_OK);
        assert_eq!(imp.chunk(150, &blob[150..250], &mut dest), HANDOFF_CORRUPT);

        // CRC mismatch on END.
        let mut imp = HandoffImport::new();
        assert_eq!(imp.begin(300, 512), HANDOFF_OK);
        assert_eq!(imp.chunk(0, &blob[..300], &mut dest), HANDOFF_OK);
        assert_eq!(imp.end(handoff_crc32(&blob) ^ 1), HANDOFF_CORRUPT);
    }

    #[test]
    fn handoff_import_requires_begin_first() {
        let mut dest = vec![0u8; 16];
        let mut imp = HandoffImport::new();
        assert_eq!(imp.chunk(0, &[1, 2, 3], &mut dest), HANDOFF_NOT_READY);
        assert_eq!(imp.end(0), HANDOFF_NOT_READY);
    }

    #[test]
    fn handoff_crc32_matches_ieee_vector() {
        // Standard IEEE 802.3 check value for "123456789".
        assert_eq!(handoff_crc32(b"123456789"), 0xCBF4_3926);
    }

    // ── protocol_timer ───────────────────────────────────────────

    #[test]
    fn timers_nearest_and_expiry_order() {
        let mut t: ProtocolTimers<4> = ProtocolTimers::new();
        assert_eq!(t.nearest(), None);
        t.arm(0, 500); // keepalive
        t.arm(1, 200); // retransmit
        t.arm(2, 900);
        assert_eq!(t.nearest(), Some(200));

        // Nothing due yet.
        assert_eq!(t.pop_expired(100), None);
        // Both 200 and 500 due: earliest first, one per call.
        assert_eq!(t.pop_expired(600), Some(1));
        assert_eq!(t.pop_expired(600), Some(0));
        assert_eq!(t.pop_expired(600), None);
        assert_eq!(t.nearest(), Some(900));
    }

    #[test]
    fn timers_cancel_and_rearm() {
        let mut t: ProtocolTimers<2> = ProtocolTimers::new();
        t.arm(0, 100);
        t.cancel(0);
        assert_eq!(t.pop_expired(1000), None);
        t.arm(0, 100);
        t.arm(0, 300); // re-arm replaces
        assert_eq!(t.pop_expired(200), None);
        assert_eq!(t.pop_expired(300), Some(0));
    }

    #[test]
    fn timers_shift_rebases_for_import() {
        let mut t: ProtocolTimers<2> = ProtocolTimers::new();
        t.arm(0, 1_000);
        t.arm(1, 2_000);
        // Import onto a host whose monotonic clock is 10ms ahead.
        t.shift(10_000);
        assert_eq!(t.deadline(0), Some(11_000));
        assert_eq!(t.deadline(1), Some(12_000));
        t.shift(-11_500);
        assert_eq!(t.deadline(0), Some(0), "saturates, no wrap");
        assert_eq!(t.deadline(1), Some(500));
    }

    #[test]
    fn timers_out_of_range_slot_is_ignored() {
        let mut t: ProtocolTimers<2> = ProtocolTimers::new();
        t.arm(5, 100);
        assert_eq!(t.nearest(), None);
        assert!(!t.is_armed(5));
    }
}
