//! The state arena's carve rules (`fluxor_contracts::state_arena`): what an
//! allocation takes from the state arena and the isolated-module arena, and
//! how a heap native's seat scales with its params.
//!
//! Run with:
//!   cargo test -p fluxor-contracts --test state_arena

use fluxor_contracts::state_arena::*;

#[test]
fn a_carve_is_the_size_and_its_canary_rounded_to_eight() {
    assert_eq!(carve_bytes(0), Some(8));
    assert_eq!(carve_bytes(4), Some(8));
    assert_eq!(carve_bytes(5), Some(16));
    assert_eq!(carve_bytes(8), Some(16));
    assert_eq!(carve_bytes(64), Some(72));
    assert_eq!(carve_bytes(320), Some(328));
    assert_eq!(carve_bytes(24_768), Some(24_776));
    assert_eq!(carve_bytes(usize::MAX - 3), None);
}

#[test]
fn an_isolated_carve_is_whole_pages() {
    assert_eq!(iso_carve_bytes(0), Some(4096));
    assert_eq!(iso_carve_bytes(4092), Some(4096));
    assert_eq!(iso_carve_bytes(4093), Some(8192));
}

#[test]
fn a_heap_seat_scales_by_its_params() {
    // [FE 01 len] [10: width=320] [11: height=200] [12: bytes=5000] [FF]
    let params = [
        0xFE, 0x01, 15, 0, 10, 2, 0x40, 0x01, 11, 2, 0xC8, 0x00, 12, 4, 0x88, 0x13, 0, 0, 0xFF, 0,
    ];
    assert_eq!(heap_seat_bytes(&[100, 0, 0, 0, 0, 0], &params), Some(100));
    assert_eq!(
        heap_seat_bytes(&[100, 4, 10, 11, 0, 0], &params),
        Some(100 + 4 * 320 * 200)
    );
    assert_eq!(heap_seat_bytes(&[100, 0, 0, 0, 12, 7], &params), Some(5100));
    // An absent param takes its default.
    assert_eq!(heap_seat_bytes(&[100, 0, 0, 0, 13, 7], &params), Some(107));
}

#[test]
fn an_elastic_heap_commits_its_first_segment() {
    const Q: usize = 64 * 1024;
    // A small cap is committed whole: the quantum is past it.
    assert_eq!(first_heap_segment(4096, 8, Q), 4096);
    assert_eq!(first_heap_segment(4100, 8, Q), 4096);
    // A cap past 128 quanta commits an eighth-of-a-segment's share.
    assert_eq!(first_heap_segment(16 * 1024 * 1024, 8, Q), 128 * 1024);
    assert_eq!(first_heap_segment(1024 * 1024, 8, Q), Q);
    // One segment: the whole cap.
    assert_eq!(first_heap_segment(1024 * 1024, 1, Q), 1024 * 1024);
    // Too small to hold a block: no heap.
    assert_eq!(first_heap_segment(16, 8, Q), 0);
}
