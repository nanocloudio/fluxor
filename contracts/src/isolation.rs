//! The isolation region planner: one pure function, shared by the composer
//! and the kernel, that turns what a gated module may touch into the regions
//! a target's protection unit can express.
//!
//! The planner **fails rather than approximates**. A span that the model
//! cannot draw exactly, spans that overlap, or more regions than the budget
//! is an error, never a larger region that happens to reach something else.
//! The composer runs it to refuse a graph before it is built; the kernel runs
//! it at load, against the addresses it actually allocated, as the backstop.

/// How a target's protection unit draws a region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionModel {
    /// ARMv8-M PMSAv8: base and limit at 32-byte granularity, no size or
    /// alignment constraint beyond that; regions may not overlap.
    Pmsav8 { regions: u8 },
    /// ARMv6-M / ARMv7-M PMSAv7: a power-of-two size of at least 256 bytes,
    /// aligned to its size, split into eight subregions that can each be
    /// disabled; a higher-numbered region wins where two overlap.
    Pmsav7 { regions: u8 },
    /// An MMU with 4 KiB pages: any page-aligned span, no region budget.
    Pages,
}

/// What a module may do with a span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Read and execute: code, the gateway's veneers.
    ReadExec,
    /// Read and write, never execute: state, heap, stack.
    ReadWrite,
    /// Device registers: read and write, never execute, device ordering.
    Device,
    /// No access at all: a stack guard. Planned after everything else so a
    /// model whose later regions win (PMSAv7) lets it cut into a larger one.
    Guard,
}

/// A span of memory a gated module may touch, and how.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub base: u64,
    pub len: u64,
    pub access: Access,
}

/// One region the protection unit is programmed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    /// First byte the region spans (for PMSAv7, the size-aligned base).
    pub base: u64,
    /// Bytes the region spans (for PMSAv7, the power-of-two size).
    pub size: u64,
    /// PMSAv7 subregion-disable bits (bit n disables eighth n); 0 elsewhere.
    pub srd: u8,
    pub access: Access,
}

impl Region {
    const NONE: Region = Region {
        base: 0,
        size: 0,
        srd: 0,
        access: Access::Guard,
    };

    /// Whether byte `addr` is reachable through this region.
    pub fn covers(&self, addr: u64) -> bool {
        if addr < self.base || addr >= self.base + self.size {
            return false;
        }
        if self.srd == 0 {
            return true;
        }
        let eighth = self.size / 8;
        let n = (addr - self.base) / eighth;
        self.srd & (1 << n) == 0
    }
}

/// Most regions any supported model has per core.
pub const MAX_REGIONS: usize = 16;

/// A module's regions, in the order they are programmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionPlan {
    regions: [Region; MAX_REGIONS],
    count: usize,
}

impl RegionPlan {
    pub fn regions(&self) -> &[Region] {
        &self.regions[..self.count]
    }

    fn push(&mut self, r: Region) -> Result<(), PlanError> {
        if self.count == MAX_REGIONS {
            return Err(PlanError::OverBudget {
                need: self.count + 1,
                have: MAX_REGIONS,
            });
        }
        self.regions[self.count] = r;
        self.count += 1;
        Ok(())
    }
}

/// Why a span set cannot be planned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// A span has no bytes.
    Empty { index: usize },
    /// A span's bounds cannot be drawn exactly under the model.
    Unexpressible { index: usize },
    /// Two spans overlap (a guard may overlap only on a model that allows it).
    Overlap { a: usize, b: usize },
    /// More regions than the model has.
    OverBudget { need: usize, have: usize },
}

/// Plan the regions for `spans` under `model`.
pub fn region_plan(spans: &[Span], model: RegionModel) -> Result<RegionPlan, PlanError> {
    let mut plan = RegionPlan {
        regions: [Region::NONE; MAX_REGIONS],
        count: 0,
    };
    for (i, s) in spans.iter().enumerate() {
        if s.len == 0 {
            return Err(PlanError::Empty { index: i });
        }
        if s.base.checked_add(s.len).is_none() {
            return Err(PlanError::Unexpressible { index: i });
        }
    }
    for a in 0..spans.len() {
        for b in a + 1..spans.len() {
            let (x, y) = (spans[a], spans[b]);
            let overlap = x.base < y.base + y.len && y.base < x.base + x.len;
            let guard_cut = matches!(model, RegionModel::Pmsav7 { .. })
                && (x.access == Access::Guard || y.access == Access::Guard);
            if overlap && !guard_cut {
                return Err(PlanError::Overlap { a, b });
            }
        }
    }
    // Guards last: on PMSAv7 the higher-numbered region wins.
    let ordered = spans
        .iter()
        .enumerate()
        .filter(|(_, s)| s.access != Access::Guard)
        .chain(
            spans
                .iter()
                .enumerate()
                .filter(|(_, s)| s.access == Access::Guard),
        );
    for (i, s) in ordered {
        match model {
            RegionModel::Pages => {
                if !s.base.is_multiple_of(4096) || !s.len.is_multiple_of(4096) {
                    return Err(PlanError::Unexpressible { index: i });
                }
                plan.push(Region {
                    base: s.base,
                    size: s.len,
                    srd: 0,
                    access: s.access,
                })?;
            }
            RegionModel::Pmsav8 { .. } => {
                if !s.base.is_multiple_of(32) || !s.len.is_multiple_of(32) {
                    return Err(PlanError::Unexpressible { index: i });
                }
                plan.push(Region {
                    base: s.base,
                    size: s.len,
                    srd: 0,
                    access: s.access,
                })?;
            }
            RegionModel::Pmsav7 { .. } => {
                let r = pmsav7_region(s).ok_or(PlanError::Unexpressible { index: i })?;
                plan.push(r)?;
            }
        }
    }
    let budget = match model {
        RegionModel::Pmsav8 { regions } | RegionModel::Pmsav7 { regions } => regions as usize,
        RegionModel::Pages => usize::MAX,
    };
    if plan.count > budget {
        return Err(PlanError::OverBudget {
            need: plan.count,
            have: budget,
        });
    }
    Ok(plan)
}

/// The PMSAv7 region that covers exactly `s`, or `None`: the smallest
/// power-of-two size, aligned, whose enabled eighths are exactly the span.
fn pmsav7_region(s: &Span) -> Option<Region> {
    let end = s.base + s.len;
    let mut size: u64 = 256;
    while size <= 1 << 32 {
        let base = s.base & !(size - 1);
        if end <= base + size {
            let eighth = size / 8;
            if (s.base - base).is_multiple_of(eighth) && (end - base).is_multiple_of(eighth) {
                let first = (s.base - base) / eighth;
                let last = (end - base) / eighth; // exclusive
                let mut srd = 0u8;
                for n in 0..8 {
                    if n < first || n >= last {
                        srd |= 1 << n;
                    }
                }
                return Some(Region {
                    base,
                    size,
                    srd,
                    access: s.access,
                });
            }
            // A larger region only has coarser eighths; it cannot do better.
            return None;
        }
        size <<= 1;
    }
    None
}

/// The smallest allocation of at least `len` bytes that a single region of
/// `model` can cover exactly, and the alignment it must be placed at: what
/// the loader allocates a gated module's private region as.
pub fn private_region_shape(len: u64, model: RegionModel) -> (u64, u64) {
    match model {
        RegionModel::Pages => (len.div_ceil(4096) * 4096, 4096),
        RegionModel::Pmsav8 { .. } => (len.div_ceil(32) * 32, 32),
        RegionModel::Pmsav7 { .. } => {
            // A power-of-two region of size S covers any whole number of its
            // eighths from its base, so the allocation is `len` rounded up to
            // an eighth of the smallest S that holds it, aligned to S.
            let mut size: u64 = 256;
            while size < len {
                size <<= 1;
            }
            let eighth = size / 8;
            (len.div_ceil(eighth) * eighth, size)
        }
    }
}
