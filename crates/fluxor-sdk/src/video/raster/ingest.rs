//! The stream side of a consumer that retains records: bytes in, the last
//! committed frame's records and its resources out.

use super::paint::Painter;
use super::replay::Index;
use super::resources::Store;
use fluxor_abi::contracts::video_draw::{
    parse, resync, Admitted, Fault, Parse, Record, Sequence, HEADER,
};

/// What `Ingest::advance` reached.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The buffered bytes end inside a record: read more.
    NeedMore,
    /// A stream opened. The retained frame and every resource of the last
    /// stream are gone: the consumer presents opaque black until the next
    /// `Committed`.
    Opened,
    /// A frame committed and waits for `Ingest::present`. Nothing more is
    /// taken from the stream until then.
    Committed,
    /// The stream closed; the retained frame stays.
    Ended,
    /// The stream faulted at byte `offset`. The frame in progress is
    /// discarded, the retained frame stays, and bytes are skipped to the
    /// next STREAM record.
    Faulted { fault: Fault, offset: u64 },
}

/// A draw stream's reader. It keeps a carry buffer, admits every record
/// through `Sequence`, files resource bytes in a `Store`, and retains two
/// frames of records: the one being presented, with the index of its
/// records' rows, and the one arriving.
pub struct Ingest<'m> {
    sequence: Sequence<'m>,
    store: Store<'m>,
    carry: &'m mut [u8],
    head: usize,
    tail: usize,
    frames: [&'m mut [u8]; 2],
    lens: [usize; 2],
    index: Index<'m>,
    current: usize,
    retained: bool,
    pending: bool,
    lost: bool,
    skip: usize,
    offset: u64,
    faults: u32,
    extent: (u16, u16),
}

/// File one admitted record: resource bytes into `store`, frame records
/// (`raw`, the record as it arrived) onto the end of `staging`.
fn file(
    sequence: &mut Sequence<'_>,
    store: &mut Store<'_>,
    staging: &mut [u8],
    staged: &mut usize,
    record: &Record<'_>,
    raw: &[u8],
) -> Result<Admitted, Fault> {
    let admitted = sequence.admit(record, raw.len())?;
    let mut retain = |fresh: bool| {
        let at = if fresh { 0 } else { *staged };
        match staging.get_mut(at..at + raw.len()) {
            Some(dst) => {
                dst.copy_from_slice(raw);
                *staged = at + raw.len();
                Ok(())
            }
            None => Err(Fault::FrameTooLarge),
        }
    };
    match (admitted, record) {
        (Admitted::Stream, _) => store.clear(),
        (Admitted::End, _) => {}
        (Admitted::ResourceComplete { id }, Record::ResData { offset, bytes, .. }) => {
            let verdict = if store.data(id, *offset, bytes) {
                store.complete(id)
            } else {
                None
            };
            sequence.resolve(id, verdict)?;
        }
        (Admitted::ResourceReferenced { id }, Record::ResRef(r)) => {
            let verdict = store.reference(r);
            sequence.resolve(id, verdict)?;
        }
        (Admitted::ResourceComplete { id } | Admitted::ResourceReferenced { id }, _) => {
            sequence.resolve(id, None)?;
        }
        (Admitted::Commit, _) => retain(false)?,
        (Admitted::Record, Record::ResDef(def)) => {
            if !store.define(def) {
                return Err(Fault::ResourceLimit);
            }
        }
        (Admitted::Record, Record::ResData { id, offset, bytes }) => {
            if !store.data(*id, *offset, bytes) {
                return Err(Fault::ResourceData);
            }
        }
        (Admitted::Record, Record::ResDrop { .. }) => {}
        (Admitted::Record, Record::Frame { .. }) => retain(true)?,
        (Admitted::Record, _) => retain(false)?,
    }
    Ok(admitted)
}

impl<'m> Ingest<'m> {
    /// A reader over `sequence` and `store`, with a carry buffer (as large
    /// as the largest record the consumer takes), two frame buffers (each
    /// the `frame_bytes` the sequence's limits state) and the index the
    /// retained frame's records are filed in.
    pub fn new(
        sequence: Sequence<'m>,
        store: Store<'m>,
        carry: &'m mut [u8],
        frames: [&'m mut [u8]; 2],
        index: Index<'m>,
    ) -> Self {
        Ingest {
            sequence,
            store,
            carry,
            head: 0,
            tail: 0,
            frames,
            lens: [0; 2],
            index,
            current: 0,
            retained: false,
            pending: false,
            lost: false,
            skip: 0,
            offset: 0,
            faults: 0,
            extent: (0, 0),
        }
    }

    /// Room for stream bytes: read into the front of it, then `filled`.
    /// Empty while a committed frame waits for `present`, and until the
    /// store's held byte strings are hashed.
    pub fn space(&mut self) -> &mut [u8] {
        if self.pending || !self.store.prepared() {
            return &mut [];
        }
        if self.head > 0 {
            super::shift_down(self.carry, self.head, self.tail - self.head, 0);
            self.tail -= self.head;
            self.head = 0;
        }
        &mut self.carry[self.tail..]
    }

    /// `n` bytes were read into `space`.
    pub fn filled(&mut self, n: usize) {
        self.tail = (self.tail + n).min(self.carry.len());
    }

    /// Hash up to `budget` bytes of the store's held byte strings: whether
    /// the reader is ready to take a stream.
    pub fn prepare(&mut self, budget: usize) -> bool {
        self.store.prepare(budget)
    }

    /// Take records from the buffered bytes until one is worth reporting.
    pub fn advance(&mut self) -> Event {
        loop {
            if self.pending {
                return Event::Committed;
            }
            if self.skip > 0 {
                let drop = self.skip.min(self.tail - self.head);
                self.consume(drop);
                self.skip -= drop;
                if self.skip > 0 {
                    return Event::NeedMore;
                }
            }
            if self.lost {
                let r = resync(&self.carry[self.head..self.tail]);
                self.consume(r.discard);
                self.skip = r.skip_more;
                if !r.at_stream {
                    return Event::NeedMore;
                }
                self.lost = false;
            }
            let at = self.offset;
            let buffered = &self.carry[self.head..self.tail];
            let (record, consumed) = match parse(buffered, self.carry.len()) {
                Parse::NeedMore => return Event::NeedMore,
                Parse::Fault(fault) => return self.fault(fault, at),
                Parse::Record { record, consumed } => (record, consumed),
            };
            let staging = 1 - self.current;
            let filed = file(
                &mut self.sequence,
                &mut self.store,
                self.frames[staging],
                &mut self.lens[staging],
                &record,
                &buffered[..consumed],
            );
            let stream = match record {
                Record::Stream(s) => Some((s.width, s.height)),
                _ => None,
            };
            let admitted = match filed {
                Ok(admitted) => admitted,
                Err(fault) => return self.fault(fault, at),
            };
            self.consume(consumed);
            match admitted {
                Admitted::Stream => {
                    self.retained = false;
                    self.lens = [0; 2];
                    self.index.clear();
                    self.extent = stream.unwrap_or((0, 0));
                    return Event::Opened;
                }
                Admitted::Commit => {
                    self.pending = true;
                    return Event::Committed;
                }
                Admitted::End => return Event::Ended,
                _ => {}
            }
        }
    }

    fn consume(&mut self, n: usize) {
        self.head += n;
        self.offset += n as u64;
        if self.head == self.tail {
            self.head = 0;
            self.tail = 0;
        }
    }

    /// Count a fault, drop the frame in progress, and skip the faulted
    /// record by its own length before looking for the next STREAM.
    fn fault(&mut self, fault: Fault, offset: u64) -> Event {
        self.faults = self.faults.wrapping_add(1);
        self.lens[1 - self.current] = 0;
        self.lost = true;
        let buffered = self.tail - self.head;
        if buffered >= HEADER {
            let h = self.head;
            let len = u16::from_le_bytes([self.carry[h + 2], self.carry[h + 3]]);
            let total = HEADER + usize::from(len);
            let drop = total.min(buffered);
            self.consume(drop);
            self.skip = total - drop;
        }
        Event::Faulted { fault, offset }
    }

    /// Make the committed frame the retained one, index its records
    /// (`painter` walks them once), and release the resources the stream
    /// dropped that it does not draw with. Whether a frame was waiting.
    pub fn present(&mut self, painter: &mut Painter<'_>) -> bool {
        if !self.pending {
            return false;
        }
        self.pending = false;
        self.current = 1 - self.current;
        self.retained = true;
        for id in 0..self.store.ids().min(usize::from(u16::MAX)) {
            if self.sequence.resource(id as u16).is_none() {
                self.store.release(id as u16);
            }
        }
        let frame = self.frames[self.current]
            .get(..self.lens[self.current])
            .unwrap_or(&[]);
        self.index.build(frame, painter, &self.store);
        true
    }

    /// The retained frame's records, FRAME through COMMIT, and their
    /// index: what `replay` draws.
    pub fn frame(&self) -> Option<(&[u8], &Index<'m>)> {
        if self.retained {
            let records = self.frames[self.current].get(..self.lens[self.current])?;
            Some((records, &self.index))
        } else {
            None
        }
    }

    /// The surface extent of the stream the retained frame, or the frame
    /// arriving, belongs to: `(width, height)`.
    pub fn extent(&self) -> (u16, u16) {
        self.extent
    }

    /// Whether a committed frame waits for `present`.
    pub fn committed(&self) -> bool {
        self.pending
    }

    /// The resources the retained frame draws with.
    pub fn store(&self) -> &Store<'m> {
        &self.store
    }

    /// The stream rules in force.
    pub fn sequence(&self) -> &Sequence<'m> {
        &self.sequence
    }

    /// Streams faulted since construction.
    pub fn faults(&self) -> u32 {
        self.faults
    }

    /// Bytes of the stream consumed since construction.
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

/// What each fault is called in a diagnostic, in the order `fault_text`
/// numbers them, each ended by a NUL.
static FAULT_TEXT: [u8; 471] = *b"unknown kind\0flags\0length\0reserved byte\0\
record larger than the read buffer\0value\0geometry\0resource definition\0\
record out of position\0stream past this instance's limits\0generation\0revision\0\
damage\0damage is not the whole surface\0band\0RESTORE on an empty stack\0\
SAVE past max_depth\0rounded clips past max_depth\0fx overflow\0\
operation or format not admitted\0resource limit\0resource data\0resource not usable\0\
glyph index\0pixmap source\0surface input\0frame larger than frame_bytes\0";

/// A fault's name for the one diagnostic a consumer emits when it refuses
/// a stream.
pub fn fault_text(fault: Fault) -> &'static [u8] {
    use Fault as F;
    let nth: usize = match fault {
        F::UnknownKind => 0,
        F::BadFlags => 1,
        F::BadLen => 2,
        F::Reserved => 3,
        F::Oversize => 4,
        F::BadValue => 5,
        F::BadGeometry => 6,
        F::BadResource => 7,
        F::OutOfPosition => 8,
        F::StreamLimit => 9,
        F::Generation => 10,
        F::Revision => 11,
        F::BadDamage => 12,
        F::PartialDamage => 13,
        F::BadBand => 14,
        F::StackUnderflow => 15,
        F::StackOverflow => 16,
        F::ClipOverflow => 17,
        F::FxOverflow => 18,
        F::NotAdmitted => 19,
        F::ResourceLimit => 20,
        F::ResourceData => 21,
        F::ResourceUnusable => 22,
        F::GlyphIndex => 23,
        F::PixmapSource => 24,
        F::SurfaceInput => 25,
        F::FrameTooLarge => 26,
    };
    let mut start = 0usize;
    let mut seen = 0usize;
    for (i, b) in FAULT_TEXT.iter().enumerate() {
        if *b == 0 {
            if seen == nth {
                return FAULT_TEXT.get(start..i).unwrap_or(&[]);
            }
            seen += 1;
            start = i + 1;
        }
    }
    &[]
}
