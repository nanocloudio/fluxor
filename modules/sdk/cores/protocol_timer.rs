// protocol_timer_core — nearest-deadline tracking for portability-
// sensitive protocol modules (rfc_protocols.md §12, §15.1).
//
// Protocol timing state (retransmit timers, keepalive windows, pacing
// cadence) must be explicit so it can be preserved and observed across
// handoff (§12.3). This core keeps a small fixed set of monotonic-
// microsecond deadlines, answers "what is my nearest wake deadline?"
// for the kernel's deadline-wake registration (§12.2), and pops
// expired slots one at a time so a `module_step` can service them.
//
// Being plain `#[repr(C)]` data, the whole timer set is part of the
// module's opaque state blob — exporting the state exports the timers
// (importers rebase with `shift`, since monotonic time is host-local).
//
// `no_std`, zero-alloc. `N` is the module's own slot count; slots are
// module-defined (e.g. slot 0 = keepalive, slot 1 = retransmit).

/// Fixed-capacity deadline set. All times are monotonic microseconds
/// as returned by the platform time source.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ProtocolTimers<const N: usize> {
    at_us: [u64; N],
    armed: [bool; N],
}

impl<const N: usize> Default for ProtocolTimers<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ProtocolTimers<N> {
    pub const fn new() -> Self {
        ProtocolTimers {
            at_us: [0; N],
            armed: [false; N],
        }
    }

    /// Arm `slot` to fire at absolute time `at_us`. Re-arming an armed
    /// slot replaces its deadline. Out-of-range slots are ignored.
    pub fn arm(&mut self, slot: usize, at_us: u64) {
        if slot < N {
            self.at_us[slot] = at_us;
            self.armed[slot] = true;
        }
    }

    /// Disarm `slot`.
    pub fn cancel(&mut self, slot: usize) {
        if slot < N {
            self.armed[slot] = false;
        }
    }

    #[inline]
    pub fn is_armed(&self, slot: usize) -> bool {
        slot < N && self.armed[slot]
    }

    /// Deadline of `slot`, if armed.
    pub fn deadline(&self, slot: usize) -> Option<u64> {
        if self.is_armed(slot) {
            Some(self.at_us[slot])
        } else {
            None
        }
    }

    /// The earliest armed deadline — what a module registers as its
    /// kernel wake deadline. `None` when nothing is armed.
    pub fn nearest(&self) -> Option<u64> {
        let mut best: Option<u64> = None;
        let mut i = 0;
        while i < N {
            if self.armed[i] {
                best = Some(match best {
                    Some(b) if b <= self.at_us[i] => b,
                    _ => self.at_us[i],
                });
            }
            i += 1;
        }
        best
    }

    /// Pop ONE expired slot (earliest deadline first): disarms it and
    /// returns its index. Call in a loop to service everything due.
    /// Ties resolve to the lowest slot index for determinism.
    pub fn pop_expired(&mut self, now_us: u64) -> Option<usize> {
        let mut best: Option<(u64, usize)> = None;
        let mut i = 0;
        while i < N {
            if self.armed[i] && self.at_us[i] <= now_us {
                let better = match best {
                    Some((t, _)) => self.at_us[i] < t,
                    None => true,
                };
                if better {
                    best = Some((self.at_us[i], i));
                }
            }
            i += 1;
        }
        if let Some((_, slot)) = best {
            self.armed[slot] = false;
            return Some(slot);
        }
        None
    }

    /// Rebase every armed deadline by a signed microsecond delta —
    /// used after import on a host with a different monotonic origin
    /// (§12.3: preserve retransmit/keepalive cadence across handoff).
    /// Deadlines saturate at the u64 bounds rather than wrapping.
    pub fn shift(&mut self, delta_us: i64) {
        let mut i = 0;
        while i < N {
            if self.armed[i] {
                self.at_us[i] = if delta_us >= 0 {
                    self.at_us[i].saturating_add(delta_us as u64)
                } else {
                    self.at_us[i].saturating_sub(delta_us.unsigned_abs())
                };
            }
            i += 1;
        }
    }
}
