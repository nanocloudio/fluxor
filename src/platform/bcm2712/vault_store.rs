//! The key vault's durable store on a bare-metal Pi 5: sealed blobs on the
//! NVMe, in the External backing space's reserved pages
//! (`backing_store::RESERVED_EXTERNAL_PAGES`), written through the kernel's
//! synchronous backing provider (the `nvme` module's page I/O).
//!
//! Two slots of [`SLOT_PAGES`] pages, A/B: a write builds the whole new image
//! in RAM, writes it to the slot not in use, flushes, and only then makes it
//! the live one — so a power cut at any point leaves the previous image whole.
//! Each image carries a sequence number and a SHA-256 over itself; a boot
//! reads both slots and takes the valid one with the higher sequence.
//!
//! It holds only what the vault has already sealed — with the key derived
//! from the board's OTP (`bcm_seal`); a board whose OTP holds no device key
//! cannot seal, so its vault writes nothing here. No key ever lives beside
//! the blobs it protects.
//!
//! The store is readable once the backing provider is up and an image has
//! been read (or a fresh one formatted and written): until then
//! [`ready`] is false, and the vault answers a labelled open `EAGAIN` rather
//! than read an unreadable store as empty.

use core::sync::atomic::{AtomicBool, Ordering};

use fluxor::kernel::backing_provider as bp;
use fluxor::kernel::security::crypto::sha256::Sha256;

/// Pages per slot, 4 KiB each.
pub const SLOT_PAGES: usize = 4;
const PAGE: usize = 4096;
pub const IMAGE: usize = SLOT_PAGES * PAGE;
const _: () = assert!(
    2 * SLOT_PAGES as u32 <= fluxor::kernel::mem::backing::backing_store::RESERVED_EXTERNAL_PAGES
);

const MAGIC: &[u8; 4] = b"FXVS";
const VERSION: u8 = 1;
// Header: magic 0..4, version 4, seq 8..16, count 16..18, body_len 20..24,
// digest 56..88; records from HEADER.
const SEQ: usize = 8;
const COUNT: usize = 16;
const BODY_LEN: usize = 20;
const DIGEST: usize = 56;
const HEADER: usize = 96;

#[repr(C, align(4096))]
struct Buf([u8; IMAGE]);

/// The live image, and the slot it lives in.
static mut LIVE: Buf = Buf([0; IMAGE]);
/// Scratch for reading a slot and for building the next image.
static mut WORK: Buf = Buf([0; IMAGE]);
static mut LIVE_SLOT: u8 = 0;
static LOADED: AtomicBool = AtomicBool::new(false);
static LOCK: AtomicBool = AtomicBool::new(false);

struct Held;
impl Drop for Held {
    fn drop(&mut self) {
        LOCK.store(false, Ordering::Release);
    }
}
/// The store is touched from whichever core calls the vault.
fn lock() -> Held {
    while LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    Held
}

fn page_io(op: u32, slot: u8, page: usize, buf: *mut u8) -> bool {
    let mut arg = [0u8; 16];
    // arena_base_page 0: the reserved pages; vpage = the slot's page.
    let vpage = (slot as u32) * SLOT_PAGES as u32 + page as u32;
    arg[4..8].copy_from_slice(&vpage.to_le_bytes());
    arg[8..16].copy_from_slice(&(buf as u64).to_le_bytes());
    bp::dispatch_patient(op, arg.as_mut_ptr(), arg.len()) >= 0
}

fn digest_of(img: &[u8; IMAGE]) -> [u8; 32] {
    let body = u32::from_le_bytes([
        img[BODY_LEN],
        img[BODY_LEN + 1],
        img[BODY_LEN + 2],
        img[BODY_LEN + 3],
    ]) as usize;
    let mut h = Sha256::new();
    h.update(&img[..DIGEST]);
    h.update(&img[HEADER..HEADER + body.min(IMAGE - HEADER)]);
    h.finalize()
}

fn valid(img: &[u8; IMAGE]) -> Option<u64> {
    if &img[0..4] != MAGIC || img[4] != VERSION {
        return None;
    }
    let body = u32::from_le_bytes([
        img[BODY_LEN],
        img[BODY_LEN + 1],
        img[BODY_LEN + 2],
        img[BODY_LEN + 3],
    ]) as usize;
    if body > IMAGE - HEADER || digest_of(img) != img[DIGEST..DIGEST + 32] {
        return None;
    }
    let mut s = [0u8; 8];
    s.copy_from_slice(&img[SEQ..SEQ + 8]);
    Some(u64::from_le_bytes(s))
}

/// Write `WORK` to the slot not live, flush, and make it live.
unsafe fn commit() -> bool {
    let work = &mut *core::ptr::addr_of_mut!(WORK);
    let d = digest_of(&work.0);
    work.0[DIGEST..DIGEST + 32].copy_from_slice(&d);
    let target = 1 - LIVE_SLOT;
    for p in 0..SLOT_PAGES {
        if !page_io(
            bp::op::WRITE_PAGE,
            target,
            p,
            work.0.as_mut_ptr().add(p * PAGE),
        ) {
            return false;
        }
    }
    if bp::dispatch_patient(bp::op::FLUSH, core::ptr::null_mut(), 0) < 0 {
        return false;
    }
    let live = &mut *core::ptr::addr_of_mut!(LIVE);
    live.0.copy_from_slice(&work.0);
    LIVE_SLOT = target;
    true
}

/// Read both slots and keep the newest valid image; format a fresh one when
/// neither is. True once the store is readable.
unsafe fn load() -> bool {
    if !bp::ready() {
        return false;
    }
    let work = &mut *core::ptr::addr_of_mut!(WORK);
    let live = &mut *core::ptr::addr_of_mut!(LIVE);
    let mut best: Option<(u8, u64)> = None;
    for slot in 0..2u8 {
        for p in 0..SLOT_PAGES {
            if !page_io(
                bp::op::READ_PAGE,
                slot,
                p,
                work.0.as_mut_ptr().add(p * PAGE),
            ) {
                return false; // the medium cannot be read yet
            }
        }
        if let Some(seq) = valid(&work.0) {
            if best.map(|(_, b)| seq > b).unwrap_or(true) {
                best = Some((slot, seq));
                live.0.copy_from_slice(&work.0);
            }
        }
    }
    if let Some((slot, _)) = best {
        LIVE_SLOT = slot;
        return true;
    }
    // Never formatted (or neither slot holds an image): an empty store. It
    // is readable as empty — no write is needed until a blob is.
    live.0.fill(0);
    live.0[0..4].copy_from_slice(MAGIC);
    live.0[4] = VERSION;
    LIVE_SLOT = 1; // so the first commit lands in slot 0
    true
}

/// Is the store readable? Tries to read (or format) it the first time the
/// backing provider is up.
pub fn ready() -> bool {
    if LOADED.load(Ordering::Acquire) {
        return true;
    }
    let _h = lock();
    if LOADED.load(Ordering::Acquire) {
        return true;
    }
    // SAFETY: under the lock; the statics are this module's alone.
    let ok = unsafe { load() };
    if ok {
        LOADED.store(true, Ordering::Release);
    }
    ok
}

/// Walk `img`'s records: `(offset of the record, name, blob)`.
fn records(img: &[u8; IMAGE], mut f: impl FnMut(usize, &[u8], &[u8]) -> bool) {
    let count = u16::from_le_bytes([img[COUNT], img[COUNT + 1]]) as usize;
    let mut at = HEADER;
    for _ in 0..count {
        let Some(&nl) = img.get(at) else { return };
        let nl = nl as usize;
        let Some(name) = img.get(at + 1..at + 1 + nl) else {
            return;
        };
        let Some(bl) = img.get(at + 1 + nl..at + 3 + nl) else {
            return;
        };
        let bl = u16::from_le_bytes([bl[0], bl[1]]) as usize;
        let Some(blob) = img.get(at + 3 + nl..at + 3 + nl + bl) else {
            return;
        };
        if !f(at, name, blob) {
            return;
        }
        at += 3 + nl + bl;
    }
}

/// `HalOps::seal_blob_read`.
pub fn read(name: &[u8], out: &mut [u8]) -> Option<usize> {
    if !LOADED.load(Ordering::Acquire) {
        return None;
    }
    let _h = lock();
    let mut got = None;
    // SAFETY: under the lock.
    unsafe {
        let live = &*core::ptr::addr_of!(LIVE);
        records(&live.0, |_, n, b| {
            if n == name {
                if b.len() <= out.len() {
                    out[..b.len()].copy_from_slice(b);
                    got = Some(b.len());
                }
                return false;
            }
            true
        });
    }
    got
}

/// Build the next image in `WORK`: every record of the live one but `name`'s,
/// then `put` when given. False when it would not fit.
unsafe fn rebuild(name: &[u8], put: Option<&[u8]>) -> bool {
    let live = &*core::ptr::addr_of!(LIVE);
    let work = &mut *core::ptr::addr_of_mut!(WORK);
    work.0[..HEADER].copy_from_slice(&live.0[..HEADER]);
    let mut at = HEADER;
    let mut count = 0u16;
    let mut fits = true;
    let mut add = |w: &mut [u8; IMAGE], n: &[u8], b: &[u8]| {
        let need = 3 + n.len() + b.len();
        if n.len() > 255 || b.len() > u16::MAX as usize || at + need > IMAGE {
            fits = false;
            return;
        }
        w[at] = n.len() as u8;
        w[at + 1..at + 1 + n.len()].copy_from_slice(n);
        w[at + 1 + n.len()..at + 3 + n.len()].copy_from_slice(&(b.len() as u16).to_le_bytes());
        w[at + 3 + n.len()..at + need].copy_from_slice(b);
        at += need;
        count += 1;
    };
    records(&live.0, |_, n, b| {
        if n != name {
            add(&mut work.0, n, b);
        }
        true
    });
    if let Some(b) = put {
        add(&mut work.0, name, b);
    }
    let mut seq = [0u8; 8];
    seq.copy_from_slice(&live.0[SEQ..SEQ + 8]);
    let next = u64::from_le_bytes(seq).wrapping_add(1);
    work.0[SEQ..SEQ + 8].copy_from_slice(&next.to_le_bytes());
    work.0[COUNT..COUNT + 2].copy_from_slice(&count.to_le_bytes());
    work.0[BODY_LEN..BODY_LEN + 4].copy_from_slice(&((at - HEADER) as u32).to_le_bytes());
    work.0[at..].fill(0);
    fits
}

/// `HalOps::seal_blob_write`: true once the blob would survive a power cut.
pub fn write(name: &[u8], blob: &[u8]) -> bool {
    if !LOADED.load(Ordering::Acquire) {
        return false;
    }
    let _h = lock();
    // SAFETY: under the lock.
    unsafe { rebuild(name, Some(blob)) && commit() }
}

/// `HalOps::seal_blob_delete`: true when no blob remains.
pub fn delete(name: &[u8]) -> bool {
    if !LOADED.load(Ordering::Acquire) {
        return false;
    }
    let _h = lock();
    // SAFETY: under the lock.
    unsafe {
        let live = &*core::ptr::addr_of!(LIVE);
        let mut present = false;
        records(&live.0, |_, n, _| {
            if n == name {
                present = true;
                return false;
            }
            true
        });
        if !present {
            return true;
        }
        rebuild(name, None) && commit()
    }
}
