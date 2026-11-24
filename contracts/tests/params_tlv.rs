//! The params TLV merge, as the kernel and a module amend a compiled blob.

use fluxor_contracts::params_tlv::{
    merge_overrides, merge_room, terminator_at, walk_declared, TLV_END, TLV_MAGIC, TLV_VERSION,
};

fn declared(blob: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    walk_declared(blob, |t, v| out.push((t, v.to_vec())));
    out
}

#[test]
fn an_empty_buffer_gets_a_header_the_entries_and_a_terminator() {
    let mut buf = [0u8; 16];
    let m = merge_overrides(&mut buf, 0, [(1u8, &[7u8, 8][..])].into_iter());
    assert_eq!(m.dropped, 0);
    assert_eq!(
        &buf[..m.len],
        &[TLV_MAGIC, TLV_VERSION, 6, 0, 1, 2, 7, 8, TLV_END, 0][..]
    );
    assert_eq!(declared(&buf[..m.len]), vec![(1, vec![7, 8])]);
}

#[test]
fn overrides_land_before_the_terminator_and_keep_what_follows_it() {
    // A basic entry, the terminator, and two bytes of extended section.
    let blob = [
        TLV_MAGIC,
        TLV_VERSION,
        3,
        0,
        2,
        1,
        9,
        TLV_END,
        0,
        0xAA,
        0xBB,
    ];
    let mut buf = [0u8; 32];
    buf[..blob.len()].copy_from_slice(&blob);
    let m = merge_overrides(&mut buf, blob.len(), [(3u8, &[5u8][..])].into_iter());
    assert_eq!(
        &buf[..m.len],
        &[
            TLV_MAGIC,
            TLV_VERSION,
            8,
            0,
            2,
            1,
            9,
            3,
            1,
            5,
            TLV_END,
            0,
            0xAA,
            0xBB
        ][..]
    );
    assert_eq!(terminator_at(&buf, m.len), Some(10));
    assert_eq!(declared(&buf[..m.len]), vec![(2, vec![9]), (3, vec![5])]);
}

#[test]
fn what_does_not_fit_is_dropped_and_counted() {
    let mut buf = [0u8; 9];
    let big = [1u8; 4];
    let m = merge_overrides(
        &mut buf,
        0,
        [(1u8, &[1u8][..]), (2u8, &big[..])].into_iter(),
    );
    assert_eq!(m.dropped, 1);
    assert_eq!(declared(&buf[..m.len]), vec![(1, vec![1])]);
    assert!(merge_room(2, 5) >= 9 + 4);
}

#[test]
fn a_blob_of_another_encoding_and_an_end_tag_are_left_alone() {
    let mut other = [0x00u8, 0x02, 0, 0, 0, 0];
    let m = merge_overrides(&mut other, 6, [(1u8, &[1u8][..])].into_iter());
    assert_eq!((m.len, m.dropped), (6, 1));
    assert_eq!(other, [0x00, 0x02, 0, 0, 0, 0]);

    let mut buf = [0u8; 16];
    let m = merge_overrides(
        &mut buf,
        0,
        [(TLV_END, &[][..]), (1u8, &[1u8][..])].into_iter(),
    );
    assert_eq!(
        m.dropped, 2,
        "an END-tagged override, and every one after it"
    );

    let mut tiny = [0u8; 3];
    let m = merge_overrides(&mut tiny, 3, [(1u8, &[1u8][..])].into_iter());
    assert_eq!((m.len, m.dropped), (3, 1));
}

#[test]
fn a_truncated_blob_walks_no_further_than_its_bytes() {
    let blob = [TLV_MAGIC, TLV_VERSION, 0, 0, 1, 5, 1, 2];
    assert!(declared(&blob).is_empty());
    assert!(declared(&[TLV_MAGIC]).is_empty());
}
