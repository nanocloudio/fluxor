//! Levenshtein-distance helper used for "did you mean…?" hints
//! across multiple CLI error sites.
//!
//! Originally landed in `tools/src/target.rs` for unknown-target
//! suggestions. Moved here when `tools/src/manifest.rs` needed the
//! same lookup for unknown content_type hints — manifest is part
//! of the library crate (`tools/src/lib.rs`) while target lives in
//! the binary crate, so a shared library module is the only place
//! both can reach.
//!
//! Cost: O(n × |needle|²) per call. Used against small candidate
//! lists (12 targets, 8 stacks, 33 content_types), so well under a
//! microsecond. No allocations beyond the two rolling-buffer
//! `Vec<usize>`s.

/// Return the candidate from `haystack` whose Levenshtein distance
/// to `needle` is minimal AND `≤ max_distance`. `None` when no
/// candidate is within the threshold. Distance cap keeps the
/// suggestion sensible: a totally unrelated typo gets no hint.
pub fn closest_match(needle: &str, haystack: &[String], max_distance: usize) -> Option<String> {
    let mut best: Option<(usize, &String)> = None;
    for candidate in haystack {
        let d = levenshtein(needle, candidate);
        if d <= max_distance {
            match best {
                Some((bd, _)) if d >= bd => {}
                _ => best = Some((d, candidate)),
            }
        }
    }
    best.map(|(_, s)| s.clone())
}

/// Bare-bones Levenshtein with byte-level distance. Fine for the
/// short ASCII names this is used on; no grapheme nuance needed.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for (i, &ac) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &bc) in b.iter().enumerate() {
            let cost = if ac == bc { 0 } else { 1 };
            curr[j + 1] =
                std::cmp::min(std::cmp::min(curr[j] + 1, prev[j + 1] + 1), prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levenshtein_distance_basics() {
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("a", ""), 1);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("pic2w", "pico2w"), 1);
        assert_eq!(levenshtein("cm", "cm5"), 1);
        assert_eq!(levenshtein("pico", "pico2w"), 2);
    }

    #[test]
    fn closest_match_picks_one_character_typo() {
        let targets: Vec<String> = ["pico2w", "pico", "cm5", "linux"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(closest_match("pic2w", &targets, 3), Some("pico2w".into()));
    }

    #[test]
    fn closest_match_returns_none_when_no_candidate_within_threshold() {
        let targets: Vec<String> = ["pico2w", "cm5", "linux"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(closest_match("totally_unrelated", &targets, 3).is_none());
    }

    #[test]
    fn closest_match_handles_empty_haystack() {
        assert!(closest_match("anything", &[], 3).is_none());
    }

    #[test]
    fn closest_match_picks_first_at_tied_distance() {
        // Ties: first-wins is the documented behaviour (Vec
        // iteration order). Pinned here so a future change to
        // the resolution gets a heads-up.
        let targets: Vec<String> = ["xyz", "yyz"].iter().map(|s| s.to_string()).collect();
        assert_eq!(closest_match("zzz", &targets, 3), Some("xyz".into()));
    }
}
