//! Drawing a retained frame: the records from FRAME through COMMIT, walked
//! once per band.

use super::band::Band;
use super::paint::Painter;
use super::source::{Resources, Surfaces};
use fluxor_abi::contracts::video_draw::{parse, PRect, Parse, Record, KIND_BAND};

/// The part of `a` inside `b`; `None` when they do not meet.
pub fn intersect(a: PRect, b: PRect) -> Option<PRect> {
    let x0 = a.x.max(b.x);
    let y0 = a.y.max(b.y);
    let x1 = (u32::from(a.x) + u32::from(a.w)).min(u32::from(b.x) + u32::from(b.w));
    let y1 = (u32::from(a.y) + u32::from(a.h)).min(u32::from(b.y) + u32::from(b.h));
    if u32::from(x0) >= x1 || u32::from(y0) >= y1 {
        return None;
    }
    Some(PRect {
        x: x0,
        y: y0,
        w: (x1 - u32::from(x0)) as u16,
        h: (y1 - u32::from(y0)) as u16,
    })
}

/// One record of an indexed frame: where it is, the rows it can paint, and
/// how many of the records after it belong to it.
///
/// A drawing record's rows are those it paints. A SAVE's are the rows of
/// everything up to its RESTORE, and `skip` counts the records through
/// that RESTORE, so a band the group does not reach passes over all of it:
/// the state after the RESTORE is the state before the SAVE. A BAND's are
/// its own rows and `skip` counts the records up to the next BAND. Any
/// other record is visited whenever the walk reaches it.
#[derive(Clone, Copy)]
pub struct Entry {
    at_lo: u16,
    at_hi: u16,
    first: u16,
    end: u16,
    skip: u16,
}

impl Entry {
    /// An empty slot, to build the table an `Index` borrows.
    pub const EMPTY: Entry = Entry {
        at_lo: 0,
        at_hi: 0,
        first: 0,
        end: 0,
        skip: 0,
    };

    fn at(&self) -> usize {
        usize::from(self.at_lo) | usize::from(self.at_hi) << 16
    }
}

/// Rows `first..end` as an entry holds them: clamped to what a `u16` row
/// number reaches, and `(0, 0)` when empty.
fn row_pair(first: i32, end: i32) -> (u16, u16) {
    let first = first.max(0);
    let end = end.min(i32::from(u16::MAX));
    if first >= end {
        (0, 0)
    } else {
        (first as u16, end as u16)
    }
}

/// SAVE groups an index follows at once; a SAVE nested deeper is a record
/// like any other, visited whenever the walk reaches it.
const OPEN_GROUPS: usize = 16;

/// The rows of a retained frame's records, built once when the frame is
/// presented, so that drawing a band visits the records that reach it
/// instead of every record.
///
/// The index covers the records that fit its table, from FRAME on; a frame
/// with more records is walked record by record from where the index
/// ends. An index over no entries makes every band walk the whole frame.
pub struct Index<'m> {
    entries: &'m mut [Entry],
    len: usize,
    /// The frame offset the index ends at: the first record it does not
    /// hold.
    covered: usize,
    /// The region the frame's first drawing record paints whole and
    /// opaque.
    backdrop: Option<PRect>,
}

impl<'m> Index<'m> {
    /// An index over `entries`, holding nothing yet.
    pub fn new(entries: &'m mut [Entry]) -> Self {
        Index {
            entries,
            len: 0,
            covered: 0,
            backdrop: None,
        }
    }

    /// The region every pixel of which the frame's first operation paints
    /// with one opaque colour: its damage, when the frame is unbanded and
    /// begins with an opaque FILL_RECT over all of it. A band inside this
    /// region needs no clearing before `replay`: nothing it held shows.
    /// `None` for any other frame, and for a frame the index does not
    /// hold.
    pub fn backdrop(&self) -> Option<PRect> {
        self.backdrop
    }

    /// Records the index holds.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Forget the frame.
    pub fn clear(&mut self) {
        self.len = 0;
        self.covered = 0;
        self.backdrop = None;
    }

    /// Index `frame` (one frame's records, FRAME first), drawn with
    /// `resources`. One walk over the records.
    pub fn build<R: Resources>(&mut self, frame: &[u8], painter: &mut Painter<'_>, resources: &R) {
        self.clear();
        let cap = self.entries.len().min(usize::from(u16::MAX));
        let mut open = [0u16; OPEN_GROUPS];
        let mut depth = 0usize;
        // SAVEs the painter or `open` has no room for.
        let mut loose = 0usize;
        let mut band: Option<usize> = None;
        let mut damage = None;
        let mut at = 0usize;
        while let Some(rest) = frame.get(at..) {
            let Parse::Record { record, consumed } = parse(rest, usize::MAX) else {
                break;
            };
            if matches!(record, Record::Commit { .. }) || self.len >= cap {
                break;
            }
            let i = self.len;
            // The rows of the record itself; `None` for one visited
            // whenever the walk reaches it.
            let mut rows: Option<(u16, u16)> = None;
            match record {
                Record::Frame { damage: d, .. } => {
                    damage = Some(d);
                    painter.begin(d);
                    depth = 0;
                    loose = 0;
                    band = None;
                }
                Record::Band { y, rows: h } => {
                    // The state resets: every group still open ends here.
                    self.close(&open[..depth], band.take(), i);
                    depth = 0;
                    loose = 0;
                    let part = damage.and_then(|d| {
                        intersect(
                            d,
                            PRect {
                                x: d.x,
                                y,
                                w: d.w,
                                h,
                            },
                        )
                    });
                    painter.begin(part.unwrap_or(PRect {
                        x: 0,
                        y: 0,
                        w: 0,
                        h: 0,
                    }));
                    rows = Some(match part {
                        Some(p) => row_pair(i32::from(p.y), i32::from(p.y) + i32::from(p.h)),
                        None => (0, 0),
                    });
                    band = Some(i);
                }
                Record::Save => {
                    let before = painter.saved();
                    painter.state(&record);
                    if painter.saved() > before && depth < OPEN_GROUPS {
                        open[depth] = i as u16;
                        depth += 1;
                        rows = Some((0, 0));
                    } else {
                        loose += 1;
                    }
                }
                Record::Restore => {
                    painter.state(&record);
                    if loose > 0 {
                        loose -= 1;
                    } else if depth > 0 {
                        depth -= 1;
                        let g = usize::from(open[depth]);
                        if let Some(e) = self.entries.get_mut(g) {
                            e.skip = (i - g) as u16;
                        }
                    }
                }
                _ => {
                    if !painter.state(&record) {
                        // The record straight after FRAME.
                        if i == 1 {
                            self.backdrop = damage.filter(|d| painter.covers(&record, *d));
                        }
                        let (first, end) = painter.rows_of(&record, resources).unwrap_or((0, 0));
                        let own = row_pair(first, end);
                        rows = Some(own);
                        // Every open group reaches what this record does.
                        if own.0 < own.1 {
                            for g in open.iter().take(depth) {
                                if let Some(e) = self.entries.get_mut(usize::from(*g)) {
                                    if e.first >= e.end {
                                        (e.first, e.end) = own;
                                    } else {
                                        e.first = e.first.min(own.0);
                                        e.end = e.end.max(own.1);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            let (first, end) = rows.unwrap_or((0, u16::MAX));
            let Some(slot) = self.entries.get_mut(i) else {
                break;
            };
            *slot = Entry {
                at_lo: at as u16,
                at_hi: (at >> 16) as u16,
                first,
                end,
                skip: 0,
            };
            self.len = i + 1;
            at += consumed;
        }
        // A group the index ends inside is visited whenever it is reached:
        // the records after the index are walked one by one, in its state.
        for g in open.iter().take(depth) {
            if let Some(e) = self.entries.get_mut(usize::from(*g)) {
                e.first = 0;
                e.end = u16::MAX;
                e.skip = 0;
            }
        }
        self.close(&[], band, self.len);
        self.covered = at;
    }

    /// End the groups in `open` and the band begun at entry `band`, at
    /// entry `end`: an unreached one passes over every entry before `end`.
    fn close(&mut self, open: &[u16], band: Option<usize>, end: usize) {
        for g in open.iter().map(|g| usize::from(*g)).chain(band) {
            if let Some(e) = self.entries.get_mut(g) {
                e.skip = (end - 1).saturating_sub(g) as u16;
            }
        }
    }
}

/// What the walk of a frame carries from record to record.
struct Walk {
    region: PRect,
    damage: Option<PRect>,
    drawing: bool,
}

impl Walk {
    /// Take one record: whether the walk goes on.
    fn take<R: Resources, S: Surfaces>(
        &mut self,
        record: &Record<'_>,
        painter: &mut Painter<'_>,
        band: &mut Band<'_>,
        resources: &R,
        surfaces: &S,
    ) -> bool {
        match *record {
            Record::Frame { damage: d, .. } => {
                self.damage = Some(d);
                self.drawing = begin(painter, d, self.region);
            }
            Record::Band { y, rows } => {
                self.drawing = match self.damage {
                    Some(d) => {
                        let rows = PRect {
                            x: d.x,
                            y,
                            w: d.w,
                            h: rows,
                        };
                        intersect(d, rows).is_some_and(|part| begin(painter, part, self.region))
                    }
                    None => false,
                };
            }
            Record::Commit { .. } => return false,
            _ if self.drawing => painter.apply(band, record, resources, surfaces),
            _ => {}
        }
        true
    }
}

/// Draw the part of `frame` that falls in `band`.
///
/// `frame` is one frame's records, FRAME first, and `index` the index
/// built over it. The band is drawn over as it stands: a consumer that
/// retains no pixels clears it first. Rows of any height give the same
/// pixels as the whole frame drawn at once, and the index changes no
/// pixel: it only names the records a band need not visit. In a banded
/// frame only the BANDs that reach the band's rows are drawn, each from
/// the state its BAND record resets to.
///
/// The walk stops at COMMIT, at the end of `frame`, or at a record that
/// does not parse.
pub fn replay<R: Resources, S: Surfaces>(
    frame: &[u8],
    index: &Index<'_>,
    painter: &mut Painter<'_>,
    band: &mut Band<'_>,
    resources: &R,
    surfaces: &S,
) {
    let (b0, b1) = band.row_span();
    let mut walk = Walk {
        region: band.region(),
        damage: None,
        drawing: false,
    };
    let entries = index.entries.get(..index.len).unwrap_or(&[]);
    let mut i = 0usize;
    while let Some(e) = entries.get(i) {
        if i32::from(e.end) <= b0 || i32::from(e.first) >= b1 {
            // Not reached. Passing over a BAND leaves nothing to draw
            // until the next one.
            if frame.get(e.at()) == Some(&KIND_BAND) {
                walk.drawing = false;
            }
            i += 1 + usize::from(e.skip);
            continue;
        }
        i += 1;
        let Some(rest) = frame.get(e.at()..) else {
            return;
        };
        let Parse::Record { record, .. } = parse(rest, usize::MAX) else {
            return;
        };
        if !walk.take(&record, painter, band, resources, surfaces) {
            return;
        }
    }
    let mut at = index.covered;
    while let Some(rest) = frame.get(at..) {
        let Parse::Record { record, consumed } = parse(rest, usize::MAX) else {
            break;
        };
        at += consumed;
        if !walk.take(&record, painter, band, resources, surfaces) {
            break;
        }
    }
}

/// Reset `painter` to `clip`; whether anything of it lies in `region`.
fn begin(painter: &mut Painter<'_>, clip: PRect, region: PRect) -> bool {
    painter.begin(clip);
    intersect(clip, region).is_some()
}

/// The pixels of `frame` that SURFACE records naming an input in `inputs`
/// (bit `i` for input `i`) can paint: the box around every such record's
/// destination, inside its clip rectangle and the `width × height`
/// surface. `None` when no record names one, or none reaches the surface.
/// This is what a consumer repaints when one of those inputs commits a
/// frame.
pub fn surface_reach(
    frame: &[u8],
    painter: &mut Painter<'_>,
    inputs: u32,
    width: u16,
    height: u16,
) -> Option<PRect> {
    let surface = PRect {
        x: 0,
        y: 0,
        w: width,
        h: height,
    };
    let mut damage = None;
    let mut found: Option<(u32, u32, u32, u32)> = None;
    let mut at = 0usize;
    while let Some(rest) = frame.get(at..) {
        let Parse::Record { record, consumed } = parse(rest, usize::MAX) else {
            break;
        };
        at += consumed;
        match record {
            Record::Frame { damage: d, .. } => {
                damage = Some(d);
                painter.begin(d);
            }
            Record::Band { y, rows } => {
                if let Some(d) = damage {
                    let rows = PRect {
                        x: d.x,
                        y,
                        w: d.w,
                        h: rows,
                    };
                    painter.begin(intersect(d, rows).unwrap_or(PRect {
                        x: 0,
                        y: 0,
                        w: 0,
                        h: 0,
                    }));
                }
            }
            Record::Commit { .. } => break,
            Record::Surface { input, dst, .. }
                if input < 32 && inputs & (1 << input) != 0 && dst.w > 0 && dst.h > 0 =>
            {
                let shape = painter.placed(&dst);
                if shape.is_empty() {
                    continue;
                }
                let (c0, c1) = shape.columns();
                let (r0, r1) = shape.rows();
                let x0 = c0.max(0) as u32;
                let y0 = r0.max(0) as u32;
                let x1 = (c1.max(0) as u32).min(u32::from(width));
                let y1 = (r1.max(0) as u32).min(u32::from(height));
                if x0 >= x1 || y0 >= y1 {
                    continue;
                }
                found = Some(match found {
                    Some((a, b, c, d)) => (a.min(x0), b.min(y0), c.max(x1), d.max(y1)),
                    None => (x0, y0, x1, y1),
                });
            }
            _ => {
                painter.state(&record);
            }
        }
    }
    let (x0, y0, x1, y1) = found?;
    intersect(
        surface,
        PRect {
            x: x0 as u16,
            y: y0 as u16,
            w: (x1 - x0) as u16,
            h: (y1 - y0) as u16,
        },
    )
}
