//! `fluxor agent logs` reader core — the owner-filtered log stream the CLI
//! prints.
//!
//! Locates an owner's per-owner log ring file(s) under the runtime's `logs/`
//! sidecar directory, decodes them through the shared
//! [`fluxor_contracts::log_ring`] format, merges across generations, and renders
//! the owner-filtered stream with per-cursor `LogsTruncated` markers. Pure and
//! file-system-only — no dependency on a live runtime — so it is unit-tested
//! against synthetic ring files built with the same format the runtime writer
//! will emit.

use std::path::{Path, PathBuf};

use fluxor_contracts::log_ring::{read_ring_records, GapCursor, LogRecord, RingHeader, HEADER_LEN};

/// The all-zero UID names owner 0 (platform / system records), addressed on the
/// CLI by the reserved literal `system`. A workload UID is never all-zero
/// (validation rejects it), so this is unambiguous.
pub const SYSTEM_UID: [u8; 16] = [0u8; 16];

/// Parse an `--owner-uid` value: 32 hex chars (dashes allowed, as Kubernetes
/// UIDs carry them) or the reserved literal `system`.
pub fn parse_owner_uid(value: &str) -> Option<[u8; 16]> {
    if value.eq_ignore_ascii_case("system") {
        return Some(SYSTEM_UID);
    }
    let hex: String = value.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut uid = [0u8; 16];
    for (i, byte) in uid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(uid)
}

/// Lowercase-hex encoding of a UID, matching the ring file name convention
/// `<owner_uid>.<slot>.<owner_generation>.ring`.
pub fn uid_hex(uid: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in uid {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Ring files under `logs_dir` belonging to `uid`, i.e. named
/// `<uid_hex>.<slot>.<gen>.ring`. There is at most one live plus one retained
/// file per UID — the current generation's ring plus the retained previous
/// one — but the reader tolerates any number.
pub fn ring_files_for(logs_dir: &Path, uid: &[u8; 16]) -> Vec<PathBuf> {
    let prefix = format!("{}.", uid_hex(uid));
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(logs_dir) else {
        return files;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with(&prefix) && name.ends_with(".ring") {
            files.push(entry.path());
        }
    }
    files.sort();
    files
}

/// Decode one ring file into its retained records (oldest first). A file that is
/// truncated, has a torn header, or is shorter than `HEADER_LEN + capacity` is
/// treated as empty rather than an error — a crash-truncated ring is a loss, not
/// a failure.
pub fn read_ring_file(path: &Path) -> Vec<LogRecord> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    if bytes.len() < HEADER_LEN {
        return Vec::new();
    }
    let Some(header) = RingHeader::decode(&bytes[..HEADER_LEN]) else {
        return Vec::new();
    };
    let ring_start = HEADER_LEN;
    let ring_end = match ring_start.checked_add(header.capacity as usize) {
        Some(end) if end <= bytes.len() => end,
        _ => return Vec::new(),
    };
    read_ring_records(&bytes[ring_start..ring_end], &header)
}

/// All of an owner's records across its ring files, ordered by
/// `(owner_generation, seq)` — the total order a reader sees: earlier
/// generations (retained files) before the live one, and by `seq` within each.
pub fn read_owner_records(logs_dir: &Path, uid: &[u8; 16]) -> Vec<LogRecord> {
    let mut records: Vec<LogRecord> = Vec::new();
    for file in ring_files_for(logs_dir, uid) {
        records.extend(read_ring_file(&file));
    }
    records.sort_by(|a, b| {
        a.owner_generation
            .cmp(&b.owner_generation)
            .then(a.seq.cmp(&b.seq))
    });
    records
}

/// Retrieval filters mirroring the CLI flags.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogFilter {
    /// Keep records at or after this wall-clock millisecond (`--since`).
    pub since_ms: Option<u64>,
    /// Keep only the last N records after all other filtering (`--tail`).
    pub tail: Option<usize>,
}

/// Apply `--since` then `--tail` to an ordered record slice.
pub fn apply_filter(records: &[LogRecord], filter: &LogFilter) -> Vec<LogRecord> {
    let mut kept: Vec<LogRecord> = records
        .iter()
        .filter(|r| {
            filter
                .since_ms
                .map(|s| r.timestamp_unix_ms >= s)
                .unwrap_or(true)
        })
        .cloned()
        .collect();
    if let Some(tail) = filter.tail {
        if kept.len() > tail {
            kept.drain(..kept.len() - tail);
        }
    }
    kept
}

/// Persistent line renderer: synthesizes a `[LogsTruncated dropped=N]` line
/// whenever a `seq` gap appears **within a generation**. Gaps are tracked per
/// cursor, and `seq` restarts at each new owner generation, so a generation
/// boundary is a fresh sequence — never a gap. Holds its gap state across
/// calls so follow-mode polls form ONE continuous stream — a wrap between two
/// polls is still reported exactly once.
#[derive(Debug, Default)]
pub struct LineRenderer {
    cursor: GapCursor,
    current_gen: Option<u32>,
}

impl LineRenderer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Render `records` (ordered by `(generation, seq)`) into output lines,
    /// advancing the persistent gap state. Message bytes emit as UTF-8 (lossy).
    pub fn render(&mut self, records: &[LogRecord]) -> Vec<String> {
        let mut lines = Vec::new();
        for rec in records {
            // A new generation restarts the seq space; reset the gap cursor so
            // the jump from one generation's last seq to the next's seq 0 is
            // not a gap.
            if self.current_gen != Some(rec.owner_generation) {
                self.cursor = GapCursor::new();
                self.current_gen = Some(rec.owner_generation);
            }
            if let Some(gap) = self.cursor.observe(rec.seq) {
                lines.push(format!("[LogsTruncated dropped={}]", gap.dropped));
            }
            lines.push(String::from_utf8_lossy(&rec.message).into_owned());
        }
        lines
    }
}

/// One-shot rendering of an ordered record slice (the non-follow path).
pub fn render_lines(records: &[LogRecord]) -> Vec<String> {
    LineRenderer::new().render(records)
}

/// Follow-mode position: which records a reader has already been handed.
/// Each poll re-reads the whole retained set (the writer rewrites the ring
/// file as a consistent snapshot every ~100 ms; a torn mid-write read simply
/// yields fewer valid records and the next poll catches up), and `take_new`
/// returns only records strictly after the cursor, ordered by
/// `(owner_generation, seq)`.
#[derive(Debug, Default)]
pub struct FollowCursor {
    /// Highest `(owner_generation, seq)` delivered so far.
    position: Option<(u32, u64)>,
}

impl FollowCursor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start past everything in `records` — `--follow` without `--tail` begins
    /// at the live tail rather than replaying history (kubectl semantics).
    pub fn at_end_of(records: &[LogRecord]) -> Self {
        FollowCursor {
            position: records.last().map(|r| (r.owner_generation, r.seq)),
        }
    }

    /// The records in `records` (ordered by `(generation, seq)`) strictly after
    /// the cursor; advances the cursor past them.
    pub fn take_new(&mut self, records: &[LogRecord]) -> Vec<LogRecord> {
        let fresh: Vec<LogRecord> = records
            .iter()
            .filter(|r| match self.position {
                None => true,
                Some((gen, seq)) => (r.owner_generation, r.seq) > (gen, seq),
            })
            .cloned()
            .collect();
        if let Some(last) = fresh.last() {
            self.position = Some((last.owner_generation, last.seq));
        }
        fresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxor_contracts::log_ring::RingState;

    /// Build a ring file on disk for `uid`/`slot`/`generation` containing the
    /// given messages (seq 0..n), exactly as the runtime writer will.
    fn write_ring_file(
        dir: &Path,
        uid: [u8; 16],
        slot: u16,
        generation: u32,
        messages: &[&[u8]],
    ) -> PathBuf {
        let cap = 4096usize;
        let mut buf = vec![0u8; cap];
        let mut ring = RingState::new(cap);
        for (i, msg) in messages.iter().enumerate() {
            let rec = LogRecord {
                owner_uid: uid,
                owner_generation: generation,
                plan_generation: 1,
                timestamp_unix_ms: 1000 + i as u64,
                seq: i as u64,
                module: b"m".to_vec(),
                message: msg.to_vec(),
            };
            ring.push(&mut buf, &rec.encode());
        }
        let mut file_bytes = Vec::new();
        file_bytes.extend_from_slice(&ring.header().encode());
        file_bytes.extend_from_slice(&buf);
        let path = dir.join(format!("{}.{slot}.{generation}.ring", uid_hex(&uid)));
        std::fs::write(&path, &file_bytes).expect("write ring file");
        path
    }

    #[test]
    fn parses_uid_hex_dashes_and_system() {
        assert_eq!(parse_owner_uid("system"), Some(SYSTEM_UID));
        let uid = parse_owner_uid("0011223344556677-8899aabbccddeeff").unwrap();
        assert_eq!(uid[0], 0x00);
        assert_eq!(uid[15], 0xff);
        assert_eq!(uid_hex(&uid), "00112233445566778899aabbccddeeff");
        assert!(parse_owner_uid("tooshort").is_none());
        assert!(parse_owner_uid("zz112233445566778899aabbccddeeff").is_none());
    }

    #[test]
    fn reads_only_the_requested_owners_files() {
        let dir = tempfile::tempdir().unwrap();
        let a = [0xAA; 16];
        let b = [0xBB; 16];
        write_ring_file(dir.path(), a, 1, 1, &[b"a-one", b"a-two"]);
        write_ring_file(dir.path(), b, 2, 1, &[b"b-one"]);

        let recs = read_owner_records(dir.path(), &a);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].message, b"a-one");
        assert_eq!(recs[1].message, b"a-two");
        // Owner B's record must never appear under owner A.
        assert!(recs.iter().all(|r| r.owner_uid == a));
    }

    #[test]
    fn merges_generations_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let uid = [0xCC; 16];
        // A retained older generation and a live newer one.
        write_ring_file(dir.path(), uid, 3, 1, &[b"gen1-a", b"gen1-b"]);
        write_ring_file(dir.path(), uid, 3, 2, &[b"gen2-a"]);
        let recs = read_owner_records(dir.path(), &uid);
        let lines = render_lines(&recs);
        assert_eq!(lines, vec!["gen1-a", "gen1-b", "gen2-a"]);
    }

    #[test]
    fn renders_gap_marker_within_a_generation_only() {
        // Two generations; the first lost records mid-stream (seq 1..3 evicted),
        // the second is clean. The gap belongs to gen 1; the gen boundary is not
        // a gap.
        let uid = [0xDD; 16];
        let recs = vec![
            LogRecord {
                owner_uid: uid,
                owner_generation: 1,
                plan_generation: 1,
                timestamp_unix_ms: 1,
                seq: 0,
                module: vec![],
                message: b"g1-first".to_vec(),
            },
            LogRecord {
                owner_uid: uid,
                owner_generation: 1,
                plan_generation: 1,
                timestamp_unix_ms: 2,
                seq: 4,
                module: vec![],
                message: b"g1-after-gap".to_vec(),
            },
            LogRecord {
                owner_uid: uid,
                owner_generation: 2,
                plan_generation: 2,
                timestamp_unix_ms: 3,
                seq: 0,
                module: vec![],
                message: b"g2-first".to_vec(),
            },
        ];
        let lines = render_lines(&recs);
        assert_eq!(
            lines,
            vec![
                "g1-first".to_string(),
                "[LogsTruncated dropped=3]".to_string(),
                "g1-after-gap".to_string(),
                "g2-first".to_string(),
            ]
        );
    }

    #[test]
    fn since_and_tail_filters() {
        let uid = [0xEE; 16];
        let recs: Vec<LogRecord> = (0..5u64)
            .map(|i| LogRecord {
                owner_uid: uid,
                owner_generation: 1,
                plan_generation: 1,
                timestamp_unix_ms: 100 + i,
                seq: i,
                module: vec![],
                message: format!("line{i}").into_bytes(),
            })
            .collect();

        let since = apply_filter(
            &recs,
            &LogFilter {
                since_ms: Some(103),
                tail: None,
            },
        );
        assert_eq!(render_lines(&since), vec!["line3", "line4"]);

        let tail = apply_filter(
            &recs,
            &LogFilter {
                since_ms: None,
                tail: Some(2),
            },
        );
        assert_eq!(render_lines(&tail), vec!["line3", "line4"]);
    }

    #[test]
    fn missing_logs_dir_yields_no_records() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("logs");
        assert!(read_owner_records(&missing, &[0x11; 16]).is_empty());
    }

    fn rec(generation: u32, seq: u64, msg: &str) -> LogRecord {
        LogRecord {
            owner_uid: [0x77; 16],
            owner_generation: generation,
            plan_generation: 1,
            timestamp_unix_ms: seq,
            seq,
            module: vec![],
            message: msg.as_bytes().to_vec(),
        }
    }

    #[test]
    fn follow_cursor_yields_only_new_records_across_polls() {
        let mut cursor = FollowCursor::new();
        // Poll 1: two records.
        let poll1 = vec![rec(1, 0, "a"), rec(1, 1, "b")];
        let fresh = cursor.take_new(&poll1);
        assert_eq!(fresh.len(), 2);
        // Poll 2: same snapshot re-read → nothing new.
        assert!(cursor.take_new(&poll1).is_empty());
        // Poll 3: one appended record → exactly it.
        let poll3 = vec![rec(1, 0, "a"), rec(1, 1, "b"), rec(1, 2, "c")];
        let fresh = cursor.take_new(&poll3);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].message, b"c");
    }

    #[test]
    fn follow_cursor_survives_eviction_and_generation_rollover() {
        let mut cursor = FollowCursor::new();
        cursor.take_new(&[rec(1, 0, "a"), rec(1, 1, "b")]);
        // Ring wrapped: seqs 2..=4 evicted before this poll read them, and a
        // re-admission started generation 2. Both the tail of gen 1 and gen 2
        // are new; nothing already delivered repeats.
        let poll = vec![rec(1, 5, "f"), rec(2, 0, "g2-a")];
        let fresh = cursor.take_new(&poll);
        assert_eq!(fresh.len(), 2);
        assert_eq!(fresh[0].seq, 5);
        assert_eq!(fresh[1].owner_generation, 2);
        // The persistent renderer reports the eviction gap exactly once,
        // and treats the generation boundary as a boundary, not a gap.
        let mut renderer = LineRenderer::new();
        renderer.render(&[rec(1, 0, "a"), rec(1, 1, "b")]);
        let lines = renderer.render(&fresh);
        assert_eq!(
            lines,
            vec![
                "[LogsTruncated dropped=3]".to_string(),
                "f".to_string(),
                "g2-a".to_string(),
            ]
        );
    }

    #[test]
    fn follow_starts_at_the_live_tail() {
        let history = vec![rec(1, 0, "old-a"), rec(1, 1, "old-b")];
        let mut cursor = FollowCursor::at_end_of(&history);
        // Nothing from history replays…
        assert!(cursor.take_new(&history).is_empty());
        // …but the next appended record streams.
        let now = vec![rec(1, 0, "old-a"), rec(1, 1, "old-b"), rec(1, 2, "new")];
        let fresh = cursor.take_new(&now);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].message, b"new");
    }

    #[test]
    fn torn_ring_file_is_treated_as_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let uid = [0x22; 16];
        let path = write_ring_file(dir.path(), uid, 1, 1, &[b"present"]);
        // Corrupt the header magic — reader must degrade to empty, not panic.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] = b'X';
        std::fs::write(&path, &bytes).unwrap();
        assert!(read_ring_file(&path).is_empty());
    }
}
