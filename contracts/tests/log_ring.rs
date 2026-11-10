//! `fluxor_contracts::log_ring`: the owner-log record and ring format, the gap
//! cursor, and the ring algorithm shared by the writer and the reader.

use fluxor_contracts::log_ring::*;

fn sample(seq: u64, module: &[u8], message: &[u8]) -> LogRecord {
    LogRecord {
        owner_uid: [0xAB; 16],
        owner_generation: 7,
        plan_generation: 42,
        timestamp_unix_ms: 1_700_000_000_000,
        seq,
        module: module.to_vec(),
        message: message.to_vec(),
    }
}

#[test]
fn record_round_trips() {
    let rec = sample(3, b"ip", b"[ip] hello world");
    let framed = rec.encode();
    assert_eq!(framed.len(), rec.framed_len());
    match decode_record(&framed) {
        RecordDecode::Ok(got, consumed) => {
            assert_eq!(got, rec);
            assert_eq!(consumed, framed.len());
        }
        other => panic!("expected Ok, got {other:?}"),
    }
}

#[test]
fn record_with_no_module_round_trips() {
    let rec = sample(1, b"", b"off-step line");
    let framed = rec.encode();
    match decode_record(&framed) {
        RecordDecode::Ok(got, _) => {
            assert!(got.module.is_empty());
            assert_eq!(got.message, b"off-step line");
        }
        other => panic!("expected Ok, got {other:?}"),
    }
}

#[test]
fn tampered_payload_is_detected_as_torn() {
    let mut framed = sample(5, b"tls", b"secret").encode();
    // Flip a byte in the payload; the per-record CRC must catch it.
    let last = framed.len() - 1;
    framed[last] ^= 0xFF;
    match decode_record(&framed) {
        RecordDecode::Torn { consumed } => assert_eq!(consumed, framed.len()),
        other => panic!("expected Torn, got {other:?}"),
    }
}

#[test]
fn truncated_frame_is_incomplete() {
    let framed = sample(1, b"m", b"body").encode();
    // Drop the last byte — a crash-recovery scan must stop, not misread.
    assert_eq!(
        decode_record(&framed[..framed.len() - 1]),
        RecordDecode::Incomplete
    );
    assert_eq!(decode_record(&[]), RecordDecode::Incomplete);
    assert_eq!(decode_record(&[0, 0, 0]), RecordDecode::Incomplete);
}

#[test]
fn oversized_length_prefix_is_incomplete_not_panic() {
    // A torn header claiming a huge payload must not index out of bounds.
    let mut framed = vec![0u8; RECORD_FRAME_OVERHEAD];
    framed[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode_record(&framed), RecordDecode::Incomplete);
}

#[test]
fn header_round_trips_and_crc_guards() {
    let header = RingHeader {
        version: RING_FORMAT_VERSION,
        capacity: 65536,
        oldest_seq: 10,
        next_seq: 40,
        head_off: 128,
        tail_off: 900,
    };
    let bytes = header.encode();
    assert_eq!(bytes.len(), HEADER_LEN);
    assert_eq!(RingHeader::decode(&bytes), Some(header));

    // Corrupt one header byte → rejected.
    let mut corrupt = bytes;
    corrupt[10] ^= 0x01;
    assert_eq!(RingHeader::decode(&corrupt), None);

    // Wrong magic → rejected.
    let mut bad_magic = header.encode();
    bad_magic[0] = b'X';
    assert_eq!(RingHeader::decode(&bad_magic), None);
}

#[test]
fn cursor_reports_no_gap_for_contiguous_stream() {
    let mut cursor = GapCursor::new();
    assert_eq!(cursor.observe(0), None);
    assert_eq!(cursor.observe(1), None);
    assert_eq!(cursor.observe(2), None);
}

#[test]
fn cursor_reports_dropped_count_on_wrap() {
    let mut cursor = GapCursor::new();
    assert_eq!(cursor.observe(0), None);
    // Records 1..=4 were evicted before this reader saw them.
    assert_eq!(cursor.observe(5), Some(LogsTruncated { dropped: 4 }));
    assert_eq!(cursor.observe(6), None);
}

#[test]
fn two_cursors_at_different_positions_see_their_own_gaps() {
    // The same record stream, two readers: one caught up, one lagging.
    let caught_up = {
        let mut c = GapCursor::resume_after(9);
        c.observe(10)
    };
    let lagging = {
        let mut c = GapCursor::resume_after(2);
        c.observe(10)
    };
    assert_eq!(caught_up, None);
    assert_eq!(lagging, Some(LogsTruncated { dropped: 7 }));
}

#[test]
fn cursor_ignores_out_of_order_or_duplicate_seq() {
    let mut cursor = GapCursor::new();
    assert_eq!(cursor.observe(5), None);
    // A stale/duplicate seq must not move the cursor backwards or invent a gap.
    assert_eq!(cursor.observe(5), None);
    assert_eq!(cursor.observe(3), None);
    assert_eq!(cursor.observe(6), None);
}

// ── Ring algorithm ──────────────────────────────────────────────────────

/// Frame a record whose message is `msg` and whose seq is the ring's next.
fn framed(seq: u64, msg: &[u8]) -> Vec<u8> {
    sample(seq, b"m", msg).encode()
}

#[test]
fn ring_round_trips_records_in_order() {
    let cap = 4096;
    let mut buf = vec![0u8; cap];
    let mut ring = RingState::new(cap);

    for i in 0..5u64 {
        let frame = framed(i, &[b'a' + i as u8; 10]);
        assert_eq!(
            ring.push(&mut buf, &frame),
            0,
            "no eviction, plenty of room"
        );
    }
    assert_eq!(ring.next_seq(), 5);
    assert_eq!(ring.oldest_seq(), 0);

    let records = ring.frames(&buf);
    assert_eq!(records.len(), 5);
    for (i, rec) in records.iter().enumerate() {
        assert_eq!(rec.seq, i as u64);
        assert_eq!(rec.message, vec![b'a' + i as u8; 10]);
    }
}

#[test]
fn ring_evicts_oldest_on_wrap_and_reports_drops() {
    // Size the ring so only ~3 records fit; pushing 6 must evict the first 3.
    let one = framed(0, &[b'x'; 20]).len();
    let cap = one * 3 + 4; // room for 3 frames, not 4
    let mut buf = vec![0u8; cap];
    let mut ring = RingState::new(cap);

    let mut total_dropped = 0u64;
    for i in 0..6u64 {
        total_dropped += ring.push(&mut buf, &framed(i, &[b'x'; 20]));
    }
    // 6 pushed, ~3 retained → ~3 dropped.
    assert!(total_dropped >= 1, "wrap must evict");
    assert_eq!(ring.next_seq(), 6);
    assert_eq!(ring.oldest_seq(), total_dropped);

    let records = ring.frames(&buf);
    // Retained records are the most recent, contiguous, in order.
    assert_eq!(records.len() as u64, 6 - total_dropped);
    assert_eq!(records.first().unwrap().seq, total_dropped);
    assert_eq!(records.last().unwrap().seq, 5);

    // A reader that saw seq 0 then resumes sees exactly the eviction gap.
    let mut cursor = GapCursor::resume_after(0);
    let first_retained = records.first().unwrap().seq;
    let gap = cursor.observe(first_retained);
    if first_retained > 1 {
        assert_eq!(
            gap,
            Some(LogsTruncated {
                dropped: first_retained - 1
            })
        );
    }
}

#[test]
fn ring_handles_records_straddling_the_wrap_boundary() {
    // Choose a capacity that is NOT a multiple of the frame size, so once
    // the ring wraps, subsequent frames span the physical boundary.
    let frame_len = framed(0, &[b'z'; 17]).len();
    let cap = frame_len * 4 + frame_len / 2; // deliberately off-aligned
    let mut buf = vec![0u8; cap];
    let mut ring = RingState::new(cap);

    // Push enough to force multiple wraps.
    for i in 0..40u64 {
        ring.push(&mut buf, &framed(i, &[b'z'; 17]));
    }

    // Every retained record must decode intact despite straddling the wrap.
    let records = ring.frames(&buf);
    assert!(!records.is_empty());
    for rec in &records {
        assert_eq!(rec.message, vec![b'z'; 17]);
        assert_eq!(rec.module, b"m");
    }
    // Seqs are contiguous and end at the last pushed.
    assert_eq!(records.last().unwrap().seq, 39);
    for pair in records.windows(2) {
        assert_eq!(pair[1].seq, pair[0].seq + 1);
    }
}

#[test]
fn ring_header_snapshot_round_trips_through_the_format() {
    let cap = 2048;
    let mut buf = vec![0u8; cap];
    let mut ring = RingState::new(cap);
    for i in 0..7u64 {
        ring.push(&mut buf, &framed(i, b"payload"));
    }
    let header = ring.header();
    let encoded = header.encode();
    assert_eq!(RingHeader::decode(&encoded), Some(header));
    assert_eq!(header.next_seq, 7);
    assert_eq!(header.capacity, cap as u64);
}

#[test]
fn reader_reconstructs_records_from_header_and_ring_bytes() {
    // Simulate the reader path: a ring is filled (with eviction), its header
    // snapshotted, and a fresh reader recovers the retained records from the
    // header + raw bytes alone — no live `used`.
    let frame_len = framed(0, &[b'k'; 12]).len();
    let cap = frame_len * 3 + 3;
    let mut buf = vec![0u8; cap];
    let mut ring = RingState::new(cap);
    for i in 0..8u64 {
        ring.push(&mut buf, &framed(i, &[b'k'; 12]));
    }
    let header = ring.header();

    let recovered = read_ring_records(&buf, &header);
    let live = ring.frames(&buf);
    assert_eq!(recovered.len(), live.len());
    for (a, b) in recovered.iter().zip(live.iter()) {
        assert_eq!(a.seq, b.seq);
        assert_eq!(a.message, b.message);
    }
    assert_eq!(recovered.last().unwrap().seq, 7);
}

#[test]
fn reader_on_empty_ring_returns_nothing() {
    let cap = 512;
    let buf = vec![0u8; cap];
    let ring = RingState::new(cap);
    assert!(read_ring_records(&buf, &ring.header()).is_empty());
}

#[test]
fn ring_drops_a_record_larger_than_capacity_without_corrupting_state() {
    let cap = 64;
    let mut buf = vec![0u8; cap];
    let mut ring = RingState::new(cap);
    ring.push(&mut buf, &framed(0, b"small"));
    // A frame bigger than the whole ring is dropped whole WITHOUT
    // consuming a seq: the header's retained window is the contiguous
    // range [oldest_seq, next_seq), so `next_seq - oldest_seq` must stay
    // equal to the retained record count or a header-driven reader walks
    // past the tail into stale bytes.
    let huge = framed(1, &vec![b'q'; cap * 2]);
    assert_eq!(
        ring.push(&mut buf, &huge),
        1,
        "the incoming record is the drop"
    );
    assert_eq!(ring.next_seq(), 1, "no seq consumed for an unstored record");
    assert_eq!(ring.oldest_seq(), 0);
    // The small record survives; the huge one never landed.
    let records = ring.frames(&buf);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].message, b"small");
}

#[test]
fn header_reader_stays_consistent_after_oversized_drop_mid_stream() {
    // An oversized push into a NON-EMPTY ring must leave the persisted
    // header view identical to the live view. Advancing next_seq without
    // storing a frame would make read_ring_records walk one frame too far
    // and return stale CRC-valid bytes from an earlier lap at the tail.
    let frame_len = framed(0, &[b'x'; 20]).len();
    let cap = frame_len * 3 + 4;
    let mut buf = vec![0u8; cap];
    let mut ring = RingState::new(cap);

    // Wrap a few times so the buffer is full of old lap bytes.
    let mut seq = 0u64;
    for _ in 0..7 {
        ring.push(&mut buf, &framed(seq, &[b'x'; 20]));
        seq += 1;
    }
    // Oversized record into the non-empty ring.
    ring.push(&mut buf, &framed(seq, &vec![b'q'; cap * 2]));
    // The seq was not consumed — reuse it for the next stored record.
    ring.push(&mut buf, &framed(seq, &[b'y'; 20]));

    let live = ring.frames(&buf);
    let persisted = read_ring_records(&buf, &ring.header());
    assert_eq!(
        live.len() as u64,
        ring.next_seq() - ring.oldest_seq(),
        "retained window must stay contiguous"
    );
    assert_eq!(persisted.len(), live.len());
    for (a, b) in persisted.iter().zip(live.iter()) {
        assert_eq!((a.seq, &a.message), (b.seq, &b.message));
    }
    assert_eq!(persisted.last().unwrap().message, vec![b'y'; 20]);
}
