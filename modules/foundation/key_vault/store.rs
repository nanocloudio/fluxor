// ── The durable store: an FXVS image in two A/B slots ───────────────────
//
// The live image is the newest this instance holds, durable or not. A new
// image goes to the slot not holding the durable one, one block at a time,
// then a flush; only then is its sequence durable. A load scans both slots
// (keeping only a running digest per slot) and fills the image from the
// valid one with the higher sequence, checking it is the slot the scan saw.
//
// Geometry comes from the source: a slot is `image` bytes, a whole number
// of the source's blocks (512 B to 4 KiB). Slot A starts at `start_sector`,
// slot B right after it; the window (`sector_count`, or the rest of the
// source) must hold both. Sectors are 512 bytes whatever the source's block
// size, so a window is named the same on any medium.

/// Largest source block this vault writes whole.
const MAX_BLOCK: u32 = 4096;
/// Bytes per sector, the unit `start_sector` and `sector_count` count in.
const SECTOR: u64 = 512;
/// Pause after a failed write or read before trying again.
const RETRY_MS: u64 = 1000;
/// The tag every read carries (one in flight).
const READ_TAG: u64 = 1;

mod phase {
    pub const OFF: u8 = 0;
    pub const DESCRIBE: u8 = 1;
    pub const SCAN: u8 = 2;
    pub const FILL: u8 = 3;
    pub const RUN: u8 = 4;
    pub const WRITE: u8 = 5;
    pub const WRITTEN: u8 = 6;
    pub const FENCE: u8 = 7;
    pub const BACKOFF: u8 = 8;
    pub const STOPPED: u8 = 9;
}

/// Where a change to the image stands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Durability {
    /// On the medium: survives a power cut.
    Durable,
    /// In the image at this sequence, not yet on the medium.
    Pending(u64),
    /// The image could not take it, or the medium refused the last write.
    Failed,
}

#[repr(C)]
struct Store {
    blk: BlockClient,
    /// The live image, then the bounce block, from the heap.
    region: *mut u8,
    phase: u8,
    /// The phase `BACKOFF` returns to.
    resume: u8,
    /// Slot of the pass or write in progress.
    slot: u8,
    reading: u8,
    /// The slot the newest durable image is in.
    durable_slot: u8,
    /// The last write failed, and none succeeded since.
    fault: u8,
    warned_full: u8,
    loaded: u8,
    bs: u32,
    shift: u32,
    slot_blocks: u32,
    /// Byte offset within the slot of the block in progress.
    off: u32,
    base_lba: u64,
    live_seq: u64,
    durable_seq: u64,
    /// The sequence of the image being written.
    writing: u64,
    wseq: u64,
    ticket: u64,
    until: u64,
    scan: [image::Scan; 2],
    fill: image::Scan,
}

/// Take the image and bounce block and bind the source. False when the
/// heap cannot hold them.
fn store_init(s: &mut State, _blocks: i32) -> bool {
    let len = s.image_len as usize;
    let bounce = len.min(MAX_BLOCK as usize);
    let region = take_table::<u8>(s, len + bounce);
    if region.is_null() {
        return false;
    }
    let st = &mut s.store;
    st.region = region;
    st.durable_slot = 1;
    st.scan = [image::Scan::new(), image::Scan::new()];
    st.fill = image::Scan::new();
    // SAFETY: `region` names `len + bounce` bytes this instance owns for
    // its life; every block read or written lies within it.
    unsafe { st.blk.bind(0, region, len + bounce) };
    st.phase = phase::DESCRIBE;
    true
}

/// The live image.
fn store_image(s: &mut State) -> &mut [u8] {
    if s.store.region.is_null() {
        return &mut [];
    }
    // SAFETY: the first `image_len` bytes of the region are the image.
    unsafe { core::slice::from_raw_parts_mut(s.store.region, s.image_len as usize) }
}

/// The bounce block: `bs` bytes past the image.
fn store_bounce(s: &mut State) -> *mut u8 {
    // SAFETY: the region holds `min(image, 4096) >= bs` bytes past the image.
    unsafe { s.store.region.add(s.image_len as usize) }
}

/// Whether the image is loaded.
fn store_ready(s: &State) -> bool {
    s.store.loaded != 0
}

fn store_live_seq(s: &State) -> u64 {
    s.store.live_seq
}

/// Where a change made at `seq` stands.
fn store_durability(s: &State, seq: u64) -> Durability {
    if seq <= s.store.durable_seq {
        Durability::Durable
    } else if s.store.fault != 0 {
        Durability::Failed
    } else {
        Durability::Pending(seq)
    }
}

/// Put `blob` under `name` (`Some`) or remove `name` (`None`).
fn store_write(s: &mut State, name: &[u8], put: Option<&[u8]>) -> Durability {
    if !store_ready(s) {
        return Durability::Failed;
    }
    match image::change(store_image(s), name, put) {
        image::Change::Changed(seq) => {
            s.store.live_seq = seq;
            store_durability(s, seq)
        }
        image::Change::Unchanged => store_durability(s, s.store.live_seq),
        image::Change::Full => {
            if s.store.warned_full == 0 {
                s.store.warned_full = 1;
                log_n(
                    s,
                    2,
                    b"[key_vault] store image full: a record was not kept, image bytes=",
                    s.image_len,
                );
            }
            Durability::Failed
        }
    }
}

fn store_stop(s: &mut State, why: &[u8]) {
    log(s, 1, why);
    s.store.phase = phase::STOPPED;
}

/// Wait `RETRY_MS`, then go to `resume`, with a fresh client.
fn store_back_off(s: &mut State, resume: u8) {
    // SAFETY: the client and table are this instance's.
    unsafe { s.store.blk.reset(&*s.syscalls) };
    s.store.reading = 0;
    s.store.resume = resume;
    s.store.until = now_ms(s) + RETRY_MS;
    s.store.phase = phase::BACKOFF;
}

/// Start a load over: both slots scanned again.
fn store_rescan(s: &mut State) {
    let st = &mut s.store;
    st.scan = [image::Scan::new(), image::Scan::new()];
    st.fill = image::Scan::new();
    st.slot = 0;
    st.off = 0;
    st.phase = phase::SCAN;
}

/// The source's geometry, checked against the parameters.
fn store_describe(s: &mut State) {
    // SAFETY: the client and table are this instance's.
    match unsafe { s.store.blk.describe(&*s.syscalls) } {
        0 => {}
        E_AGAIN => return,
        _ => return store_stop(s, b"[key_vault] the blocks source answers no DESCRIBE"),
    }
    let bs = s.store.blk.block_size();
    let flags = s.store.blk.flags();
    if !(512..=MAX_BLOCK).contains(&bs) || !bs.is_power_of_two() {
        return store_stop(s, b"[key_vault] source block size outside 512..4096");
    }
    if flags & blk::describe::F_WRITE == 0 || flags & blk::describe::F_ASYNC == 0 {
        return store_stop(
            s,
            b"[key_vault] source does not queue writes (F_WRITE, F_ASYNC)",
        );
    }
    let shift = bs.trailing_zeros();
    if s.image_len & (bs - 1) != 0 {
        return store_stop(
            s,
            b"[key_vault] image is not a whole number of source blocks",
        );
    }
    let start = u64::from(s.start_sector) * SECTOR;
    if start & u64::from(bs - 1) != 0 {
        return store_stop(s, b"[key_vault] start_sector is not on a source block");
    }
    let total = s.store.blk.block_count().saturating_mul(u64::from(bs));
    let window = if s.sector_count != 0 {
        u64::from(s.sector_count) * SECTOR
    } else {
        total.saturating_sub(start)
    };
    if start + window > total || window < 2 * u64::from(s.image_len) {
        return store_stop(s, b"[key_vault] the window does not hold two slots");
    }
    let st = &mut s.store;
    st.bs = bs;
    st.shift = shift;
    st.slot_blocks = s.image_len >> shift;
    st.base_lba = start >> shift;
    store_rescan(s);
}

fn store_lba(s: &State) -> u64 {
    let st = &s.store;
    st.base_lba + u64::from(st.slot) * u64::from(st.slot_blocks) + u64::from(st.off >> st.shift)
}

/// One step of a load pass: one block read and fed in.
fn store_load_step(s: &mut State) {
    if s.store.reading == 0 {
        let at = store_lba(s);
        let buf = store_bounce(s);
        // SAFETY: `buf` lies in the bound region, `bs` bytes long.
        match unsafe { s.store.blk.submit_read(&*s.syscalls, at, 1, buf, READ_TAG) } {
            0 => s.store.reading = 1,
            E_AGAIN => {}
            _ => store_back_off(s, phase::DESCRIBE),
        }
        return;
    }
    // SAFETY: the client and table are this instance's.
    unsafe { s.store.blk.reap(&*s.syscalls) };
    let Some((_, status)) = s.store.blk.take_read() else {
        return;
    };
    s.store.reading = 0;
    if status < 0 {
        log_n(
            s,
            2,
            b"[key_vault] store read failed, loading again errno=",
            status.unsigned_abs(),
        );
        store_back_off(s, phase::DESCRIBE);
        return;
    }
    let bs = s.store.bs as usize;
    let off = s.store.off as usize;
    let len = s.image_len as usize;
    // SAFETY: the bounce block holds the `bs` bytes just read.
    let piece = unsafe { core::slice::from_raw_parts(store_bounce(s), bs) };
    let slot = usize::from(s.store.slot);
    if s.store.phase == phase::FILL {
        if !s.store.fill.feed(len, off, piece) {
            store_rescan(s);
            return;
        }
        store_image(s)[off..off + bs].copy_from_slice(piece);
    } else if !s.store.scan[slot].feed(len, off, piece) {
        store_rescan(s);
        return;
    }
    s.store.off += s.store.bs;
    if s.store.off < s.image_len {
        return;
    }
    s.store.off = 0;
    if s.store.phase == phase::FILL {
        let st = &s.store;
        let want = &st.scan[slot];
        if st.fill.seq.is_none() || st.fill.seq != want.seq || st.fill.digest != want.digest {
            // The slot is not what the scan saw: start over.
            store_rescan(s);
            return;
        }
        let seq = st.fill.seq.unwrap_or(0);
        let st = &mut s.store;
        st.live_seq = seq;
        st.durable_seq = seq;
        st.durable_slot = slot as u8;
        st.fault = 0;
        st.loaded = 1;
        st.phase = phase::RUN;
        log_n(s, 3, b"[key_vault] store loaded: seq ", seq as u32);
    } else if slot == 0 {
        s.store.slot = 1;
    } else {
        store_decide(s);
    }
}

/// Both slots scanned: fill from the newer valid one, or start empty.
fn store_decide(s: &mut State) {
    match image::choose(&s.store.scan[0], &s.store.scan[1]) {
        Some(slot) => {
            s.store.slot = slot;
            s.store.off = 0;
            s.store.fill = image::Scan::new();
            s.store.phase = phase::FILL;
        }
        None => {
            // Never written: an empty store, readable as empty, and no
            // write is due until a record is.
            image::format(store_image(s), 0);
            let st = &mut s.store;
            st.live_seq = 0;
            st.durable_seq = 0;
            st.durable_slot = 1;
            st.fault = 0;
            st.loaded = 1;
            st.phase = phase::RUN;
            log(s, 3, b"[key_vault] store empty: no image in either slot");
        }
    }
}

/// Start writing the live image when it is newer than the durable one.
fn store_run(s: &mut State) {
    if s.store.live_seq <= s.store.durable_seq {
        return;
    }
    let st = &mut s.store;
    st.writing = st.live_seq;
    st.slot = 1 - st.durable_slot;
    st.off = 0;
    st.phase = phase::WRITE;
    store_write_step(s);
}

/// Copy the image's next block and submit its write.
fn store_write_step(s: &mut State) {
    if s.store.live_seq != s.store.writing {
        // A newer image: start it from its beginning (same slot).
        s.store.phase = phase::RUN;
        return store_run(s);
    }
    let bs = s.store.bs as usize;
    let off = s.store.off as usize;
    let bounce = store_bounce(s);
    // SAFETY: the image's block at `off` and the bounce block are disjoint
    // `bs`-byte spans of the region.
    unsafe { core::ptr::copy_nonoverlapping(s.store.region.add(off), bounce, bs) };
    let at = store_lba(s);
    // SAFETY: `bounce` lies in the bound region, `bs` bytes long.
    match unsafe { s.store.blk.submit_write(&*s.syscalls, at, 1, bounce) } {
        0 => {
            s.store.wseq = s.store.blk.last_seq();
            s.store.phase = phase::WRITTEN;
        }
        E_AGAIN => {}
        rc => store_fail_write(s, rc),
    }
}

fn store_fail_write(s: &mut State, rc: i32) {
    if s.store.fault == 0 {
        log_n(
            s,
            2,
            b"[key_vault] store write failed (keys made since wait), errno=",
            rc.unsigned_abs(),
        );
    }
    s.store.fault = 1;
    store_back_off(s, phase::RUN);
}

fn store_written(s: &mut State) {
    // SAFETY: the client and table are this instance's.
    unsafe { s.store.blk.reap(&*s.syscalls) };
    match s.store.blk.write_state(s.store.wseq) {
        1 => return,
        0 => {}
        rc => return store_fail_write(s, rc),
    }
    s.store.off += s.store.bs;
    if s.store.off < s.image_len {
        s.store.phase = phase::WRITE;
        return store_write_step(s);
    }
    s.store.ticket = s.store.blk.flush_submit();
    s.store.phase = phase::FENCE;
    store_fence(s);
}

fn store_fence(s: &mut State) {
    let ticket = s.store.ticket;
    // SAFETY: the client and table are this instance's.
    match unsafe { s.store.blk.fence_poll(&*s.syscalls, ticket) } {
        1 => {}
        0 => {
            let st = &mut s.store;
            if st.writing > st.durable_seq {
                st.durable_seq = st.writing;
                st.durable_slot = st.slot;
            }
            st.fault = 0;
            st.phase = phase::RUN;
            store_run(s);
        }
        rc => store_fail_write(s, rc),
    }
}

/// The store's own work, each step.
fn store_step(s: &mut State) {
    match s.store.phase {
        phase::DESCRIBE => store_describe(s),
        phase::SCAN | phase::FILL => store_load_step(s),
        phase::RUN => store_run(s),
        phase::WRITE => store_write_step(s),
        phase::WRITTEN => store_written(s),
        phase::FENCE => store_fence(s),
        phase::BACKOFF => {
            if now_ms(s) >= s.store.until {
                let resume = s.store.resume;
                s.store.phase = resume;
            }
        }
        phase::OFF | phase::STOPPED => {}
        _ => {}
    }
}
