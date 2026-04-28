// QUIC ACK range tracker (RFC 9000 §19.3, §13).
//
// QUIC ACKs encode a list of contiguous packet-number ranges that the
// receiver has acknowledged. The receiver maintains a small set of
// "ranges of received packet numbers" and condenses them on emit.
//
// This implementation keeps a fixed-size ring of disjoint, sorted
// ranges. New packet numbers either extend an existing range or
// allocate a new one. When the ring is full, the oldest range is
// dropped — overflow is rare in practice because ACKs are emitted
// frequently and the peer's window is bounded.
//
// Per-packet-number-space tracking (Initial / Handshake / 1-RTT) is
// the caller's responsibility — instantiate one `AckTracker` per space.

pub const MAX_ACK_RANGES: usize = 8;

#[derive(Clone, Copy)]
pub struct AckRange {
    pub low: u64,
    pub high: u64, // inclusive
}

pub struct AckTracker {
    /// Ranges sorted descending by `high` so the largest acknowledged
    /// (the one ACK frames lead with) is always `ranges[0]`.
    pub ranges: [AckRange; MAX_ACK_RANGES],
    pub count: u8,
    /// Wall-clock millis when the largest acknowledged was received,
    /// used by the peer to compute RTT (RFC 9002 §5.3).
    pub largest_ack_recv_ms: u64,
    /// Whether an ACK frame is owed on the next emission opportunity.
    pub ack_pending: bool,
}

impl AckTracker {
    pub const fn new() -> Self {
        Self {
            ranges: [AckRange { low: 0, high: 0 }; MAX_ACK_RANGES],
            count: 0,
            largest_ack_recv_ms: 0,
            ack_pending: false,
        }
    }

    pub fn record(&mut self, pn: u64, now_ms: u64) {
        // Either extend an existing range or insert a new one. Ranges
        // are kept sorted descending by `high`; this scan is bounded
        // by MAX_ACK_RANGES so it's effectively constant time.
        let n = self.count as usize;
        let mut i = 0;
        while i < n {
            let r = &mut self.ranges[i];
            if pn >= r.low && pn <= r.high {
                return; // Duplicate.
            }
            if pn == r.high.wrapping_add(1) {
                r.high = pn;
                self.coalesce(i);
                self.bump_largest(now_ms);
                self.ack_pending = true;
                return;
            }
            if pn.wrapping_add(1) == r.low {
                r.low = pn;
                self.coalesce(i);
                self.bump_largest(now_ms);
                self.ack_pending = true;
                return;
            }
            if pn > r.high {
                self.insert_at(i, AckRange { low: pn, high: pn });
                self.bump_largest(now_ms);
                self.ack_pending = true;
                return;
            }
            i += 1;
        }
        // pn is below every existing range or set is empty — append.
        if (self.count as usize) < MAX_ACK_RANGES {
            self.ranges[self.count as usize] = AckRange { low: pn, high: pn };
            self.count += 1;
        } else {
            // Drop oldest (lowest) range; insert at end.
            self.ranges[MAX_ACK_RANGES - 1] = AckRange { low: pn, high: pn };
        }
        self.bump_largest(now_ms);
        self.ack_pending = true;
    }

    fn bump_largest(&mut self, now_ms: u64) {
        if self.count == 0 {
            return;
        }
        // After insert_at / append, ranges[0] should be the highest.
        // Coalesce may have changed indices; re-sort by high desc with
        // a single pass (insertion sort, max 8 elements).
        let n = self.count as usize;
        let mut i = 1;
        while i < n {
            let mut j = i;
            while j > 0 && self.ranges[j].high > self.ranges[j - 1].high {
                self.ranges.swap(j, j - 1);
                j -= 1;
            }
            i += 1;
        }
        self.largest_ack_recv_ms = now_ms;
    }

    fn coalesce(&mut self, idx: usize) {
        // After extending range `idx`, see if it now touches its
        // neighbors and merge. Ranges are sorted descending by `high`,
        // so `ranges[idx + 1]` is the *lower* neighbor and
        // `ranges[idx - 1]` is the *higher* neighbor.
        let n = self.count as usize;
        if idx + 1 < n
            && self.ranges[idx + 1].high.wrapping_add(1) == self.ranges[idx].low
        {
            // Lower neighbor's high abuts our low → fold it into us.
            self.ranges[idx].low = self.ranges[idx + 1].low;
            self.remove_at(idx + 1);
        }
        if idx > 0
            && self.ranges[idx].high.wrapping_add(1) == self.ranges[idx - 1].low
        {
            // Our high abuts higher neighbor's low → fold us into it.
            self.ranges[idx - 1].low = self.ranges[idx].low;
            self.remove_at(idx);
        }
    }

    fn insert_at(&mut self, idx: usize, r: AckRange) {
        let n = self.count as usize;
        let max = MAX_ACK_RANGES;
        let dst_end = if n + 1 > max { max } else { n + 1 };
        let mut k = dst_end - 1;
        while k > idx {
            self.ranges[k] = self.ranges[k - 1];
            k -= 1;
        }
        self.ranges[idx] = r;
        if n < max {
            self.count += 1;
        }
    }

    fn remove_at(&mut self, idx: usize) {
        let n = self.count as usize;
        let mut k = idx;
        while k + 1 < n {
            self.ranges[k] = self.ranges[k + 1];
            k += 1;
        }
        if self.count > 0 {
            self.count -= 1;
        }
    }

    pub fn largest_ack(&self) -> Option<u64> {
        if self.count == 0 {
            None
        } else {
            Some(self.ranges[0].high)
        }
    }
}
