//! The key vault's durable store when a graph wires a `vault_store` module:
//! one implementation for every board, over whatever `storage.block` source
//! the graph names (`abi::internal::vault_store` is the wire contract).
//!
//! The persisted records are one image, `FXVS` v1, kept here in RAM:
//!
//! ```text
//! [0..4]   "FXVS"            [4]      version 1
//! [8..16]  seq (u64)         [16..18] record count (u16)
//! [20..24] body length (u32) [56..88] SHA-256 over [0..56] ‖ body
//! [96..]   body: per record [name_len:u8][name][blob_len:u16][blob]
//! ```
//!
//! Bytes between the fields, and after the body, are zero.
//!
//! The module writes each new image to the slot not holding the durable one,
//! flushes, and reports it; only then is it the slot a boot trusts. A boot
//! scans both slots and loads the valid image with the higher sequence. A
//! change is therefore durable when an image at or after its sequence has
//! been reported, and the vault answers `EAGAIN` until then.
//!
//! Every record handed in here is what the vault already sealed — or, under
//! seal mode `NONE`, a record marked readable; this file never decides which.

use crate::abi::errno::{EAGAIN, EBUSY, EINVAL, EIO, ENOSYS};
use crate::abi::internal::vault_store as wire;
use crate::kernel::security::crypto::sha256::Sha256;
use portable_atomic::{AtomicBool, Ordering};

/// Largest image: 16 KiB where RAM allows, 8 KiB on an RP2350, 4 KiB on an
/// RP2040, whose static RAM ceiling (`ram_static_max_kb`) has no room for
/// more beside the graph's state. A device key and its certificate are about
/// 1 KiB of records.
#[cfg(any(target_arch = "aarch64", feature = "host-linux"))]
pub const MAX_IMAGE: usize = 16 * 1024;
#[cfg(all(
    not(any(target_arch = "aarch64", feature = "host-linux")),
    not(feature = "chip-rp2040")
))]
pub const MAX_IMAGE: usize = 8 * 1024;
#[cfg(all(
    not(any(target_arch = "aarch64", feature = "host-linux")),
    feature = "chip-rp2040"
))]
pub const MAX_IMAGE: usize = 4 * 1024;

const MAGIC: &[u8; 4] = b"FXVS";
const VERSION: u8 = 1;
const SEQ: usize = 8;
const COUNT: usize = 16;
const BODY_LEN: usize = 20;
const DIGEST: usize = 56;
const HEADER: usize = 96;

/// Slots an image alternates between: A (0) and B (1).
const SLOTS: u8 = 2;

#[repr(C, align(8))]
struct Buf([u8; MAX_IMAGE]);

/// The live image: the newest the vault holds, durable or not.
static mut LIVE: Buf = Buf([0; MAX_IMAGE]);

/// What a scan pass learned about one slot.
#[derive(Clone)]
struct Scan {
    sha: Sha256,
    header: [u8; HEADER],
    /// Bytes of the slot seen so far.
    got: usize,
    /// `Some(seq)` once the slot proved a valid image.
    seq: Option<u64>,
    digest: [u8; 32],
}

impl Scan {
    const fn new() -> Self {
        Scan {
            sha: Sha256::new(),
            header: [0; HEADER],
            got: 0,
            seq: None,
            digest: [0; 32],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// No module has attached.
    Detached,
    Scanning,
    /// Filling `LIVE` from this slot.
    Filling(u8),
    Ready,
}

struct Store {
    /// The graph carries a `vault_store`: the platform's own store is not
    /// the vault's, and nothing is answered until this one loads.
    expected: bool,
    phase: Phase,
    /// Scheduler slot and occupancy of the attached instance.
    owner: (usize, u32),
    image_len: usize,
    seal: u8,
    scan: [Scan; 2],
    /// The fill pass's digest and progress.
    fill: Scan,
    /// The slot the newest durable image is in.
    durable_slot: u8,
    /// Sequence of the image in `LIVE`.
    live_seq: u64,
    /// Highest sequence the module reported durable.
    durable_seq: u64,
    /// The last write the module reported failed, and none succeeded since.
    fault: bool,
    /// The write `PENDING` last named: its sequence and slot.
    writing: (u64, u8),
    /// The image-full warning was logged.
    warned_full: bool,
}

static mut STORE: Store = Store {
    expected: false,
    phase: Phase::Detached,
    owner: (usize::MAX, 0),
    image_len: 0,
    seal: wire::seal::HARDWARE,
    scan: [Scan::new(), Scan::new()],
    fill: Scan::new(),
    durable_slot: 1,
    live_seq: 0,
    durable_seq: 0,
    fault: false,
    writing: (0, 0),
    warned_full: false,
};

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

/// # Safety
/// Under [`lock`].
unsafe fn store() -> &'static mut Store {
    &mut *core::ptr::addr_of_mut!(STORE)
}

/// # Safety
/// Under [`lock`].
unsafe fn live() -> &'static mut [u8; MAX_IMAGE] {
    &mut (*core::ptr::addr_of_mut!(LIVE)).0
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut s = [0u8; 8];
    s.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(s)
}

// ── What the vault asks ─────────────────────────────────────────────────

/// What a change to the image achieved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Durability {
    /// On the medium: survives a power cut.
    Durable,
    /// In the image at this sequence, not yet on the medium.
    Pending(u64),
    /// The image could not take it, or the medium refused the last write.
    Failed,
}

/// Whether the graph being prepared carries a `vault_store`: said before any
/// module runs, so the vault answers `EAGAIN` until it loads rather than
/// treat the platform's store, or none, as the vault's.
pub fn expect(carried: bool) {
    let _h = lock();
    // SAFETY: under the lock.
    unsafe {
        let s = store();
        s.expected = carried;
        if !carried {
            // A graph without one: its keys are not this store's to keep,
            // and the image it held does not stay in RAM.
            s.phase = Phase::Detached;
            s.owner = (usize::MAX, 0);
            s.writing = (0, 0);
            live().fill(0);
        }
    }
}

/// Whether this store is the vault's: a graph carries one.
pub fn active() -> bool {
    let _h = lock();
    // SAFETY: under the lock.
    unsafe {
        let s = store();
        s.expected || s.phase != Phase::Detached
    }
}

/// Whether the image is loaded and readable.
pub fn ready() -> bool {
    let _h = lock();
    // SAFETY: under the lock.
    unsafe { store().phase == Phase::Ready }
}

/// Whether records are kept readable (`seal::NONE`).
pub fn clear() -> bool {
    let _h = lock();
    // SAFETY: under the lock.
    unsafe {
        let s = store();
        s.phase != Phase::Detached && s.seal == wire::seal::NONE
    }
}

/// Where a change made at `seq` stands.
pub fn durability(seq: u64) -> Durability {
    let _h = lock();
    // SAFETY: under the lock.
    unsafe { durability_of(store(), seq) }
}

fn durability_of(s: &Store, seq: u64) -> Durability {
    if seq <= s.durable_seq {
        Durability::Durable
    } else if s.fault {
        Durability::Failed
    } else {
        Durability::Pending(seq)
    }
}

/// Where the whole image stands: what a record read from it is worth.
pub fn image_durability() -> Durability {
    let _h = lock();
    // SAFETY: under the lock.
    unsafe {
        let s = store();
        durability_of(s, s.live_seq)
    }
}

/// Sequence of the image the vault holds now.
pub fn live_seq() -> u64 {
    let _h = lock();
    // SAFETY: under the lock.
    unsafe { store().live_seq }
}

/// Walk `img`'s records: `(offset, name, blob)`; `f` returns false to stop.
fn records(img: &[u8], mut f: impl FnMut(usize, &[u8], &[u8]) -> bool) {
    let count = u16::from_le_bytes([img[COUNT], img[COUNT + 1]]) as usize;
    let end = HEADER + (u32_at(img, BODY_LEN) as usize).min(img.len() - HEADER);
    let mut at = HEADER;
    for _ in 0..count {
        let Some(&nl) = img.get(at) else { return };
        let nl = nl as usize;
        if at + 3 + nl > end {
            return;
        }
        let name = &img[at + 1..at + 1 + nl];
        let bl = u16::from_le_bytes([img[at + 1 + nl], img[at + 2 + nl]]) as usize;
        if at + 3 + nl + bl > end {
            return;
        }
        let blob = &img[at + 3 + nl..at + 3 + nl + bl];
        if !f(at, name, blob) {
            return;
        }
        at += 3 + nl + bl;
    }
}

/// The record filed under `name`, copied to `out`. `None` when absent, too
/// large for `out`, or the image is not loaded.
pub fn read(name: &[u8], out: &mut [u8]) -> Option<usize> {
    let _h = lock();
    // SAFETY: under the lock.
    unsafe {
        let s = store();
        if s.phase != Phase::Ready {
            return None;
        }
        let img = &live()[..s.image_len];
        let mut got = None;
        records(img, |_, n, b| {
            if n == name {
                if b.len() <= out.len() {
                    out[..b.len()].copy_from_slice(b);
                    got = Some(b.len());
                }
                return false;
            }
            true
        });
        got
    }
}

/// Put `blob` under `name` (`Some`) or remove `name` (`None`) in the image.
/// The image only changes when the result fits.
///
/// # Safety
/// Under [`lock`], the store ready.
unsafe fn change(s: &mut Store, name: &[u8], put: Option<&[u8]>) -> Durability {
    let img = &mut live()[..s.image_len];
    let body = (u32_at(img, BODY_LEN) as usize).min(s.image_len - HEADER);
    let mut old: Option<(usize, usize)> = None;
    records(img, |at, n, b| {
        if n == name {
            old = Some((at, 3 + n.len() + b.len()));
            return false;
        }
        true
    });
    if old.is_none() && put.is_none() {
        // Nothing to remove: what the medium holds already lacks it once
        // the image it holds is current.
        return durability_of(s, s.live_seq);
    }
    let add = put.map_or(0, |b| 3 + name.len() + b.len());
    if name.len() > u8::MAX as usize || put.is_some_and(|b| b.len() > u16::MAX as usize) {
        return Durability::Failed;
    }
    let new_body = body - old.map_or(0, |(_, l)| l) + add;
    if HEADER + new_body > s.image_len {
        if !s.warned_full {
            s.warned_full = true;
            log::warn!(
                "[vault] store image full ({} bytes): a record was not kept",
                s.image_len
            );
        }
        return Durability::Failed;
    }
    let mut count = u16::from_le_bytes([img[COUNT], img[COUNT + 1]]);
    if let Some((at, l)) = old {
        img.copy_within(at + l..HEADER + body, at);
        count -= 1;
    }
    let mut at = HEADER + body - old.map_or(0, |(_, l)| l);
    if let Some(b) = put {
        img[at] = name.len() as u8;
        img[at + 1..at + 1 + name.len()].copy_from_slice(name);
        img[at + 1 + name.len()..at + 3 + name.len()]
            .copy_from_slice(&(b.len() as u16).to_le_bytes());
        img[at + 3 + name.len()..at + add].copy_from_slice(b);
        at += add;
        count += 1;
    }
    img[at..].fill(0);
    s.live_seq = s.live_seq.wrapping_add(1);
    img[SEQ..SEQ + 8].copy_from_slice(&s.live_seq.to_le_bytes());
    img[COUNT..COUNT + 2].copy_from_slice(&count.to_le_bytes());
    img[BODY_LEN..BODY_LEN + 4].copy_from_slice(&(new_body as u32).to_le_bytes());
    seal_digest(img);
    durability_of(s, s.live_seq)
}

/// Write the image's digest over its header and body.
fn seal_digest(img: &mut [u8]) {
    let body = (u32_at(img, BODY_LEN) as usize).min(img.len() - HEADER);
    let mut h = Sha256::new();
    h.update(&img[..DIGEST]);
    h.update(&img[HEADER..HEADER + body]);
    let d = h.finalize();
    img[DIGEST..DIGEST + 32].copy_from_slice(&d);
}

/// File `blob` under `name`.
pub fn write(name: &[u8], blob: &[u8]) -> Durability {
    let _h = lock();
    // SAFETY: under the lock.
    unsafe {
        let s = store();
        if s.phase != Phase::Ready {
            return Durability::Failed;
        }
        change(s, name, Some(blob))
    }
}

/// Remove the record under `name`. `Durable` when no record remains on the
/// medium either.
pub fn delete(name: &[u8]) -> Durability {
    let _h = lock();
    // SAFETY: under the lock.
    unsafe {
        let s = store();
        if s.phase != Phase::Ready {
            return Durability::Failed;
        }
        change(s, name, None)
    }
}

// ── What the module asks ────────────────────────────────────────────────

/// The scheduler slot and occupancy of the calling module.
fn caller() -> (usize, u32) {
    use crate::kernel::exec::scheduler;
    let idx = scheduler::current_module_index();
    if idx >= scheduler::MAX_MODULES {
        return (usize::MAX, 0);
    }
    (idx, scheduler::module_slot_generation(idx))
}

/// Dispatch an `abi::internal::vault_store` opcode.
///
/// # Safety
/// `arg` valid for `arg_len` bytes, as each opcode's layout requires.
pub unsafe fn dispatch(op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() {
        return EINVAL;
    }
    let a = core::slice::from_raw_parts_mut(arg, arg_len);
    let _h = lock();
    let s = store();
    let who = caller();
    if op == wire::ATTACH {
        return attach(s, who, a);
    }
    if s.phase == Phase::Detached || s.owner != who {
        return ENOSYS;
    }
    match op {
        wire::LOAD => load(s, a),
        wire::DECIDE => decide(s),
        wire::PENDING => pending(s, a),
        wire::READ => read_image(s, a),
        wire::DONE => done(s, a),
        _ => EINVAL,
    }
}

unsafe fn attach(s: &mut Store, who: (usize, u32), a: &mut [u8]) -> i32 {
    if a.len() < wire::ATTACH_LEN {
        return EINVAL;
    }
    let image = u32_at(a, 0) as usize;
    let seal = a[4];
    if !image.is_multiple_of(512)
        || image < wire::MIN_IMAGE as usize
        || image > MAX_IMAGE
        || (seal != wire::seal::HARDWARE && seal != wire::seal::NONE)
    {
        return EINVAL;
    }
    if s.phase != Phase::Detached {
        // Another live instance is the store. One whose instance is gone (a
        // graph rebuilt) hands the role on.
        let gone = s.owner.0 >= crate::kernel::exec::scheduler::MAX_MODULES
            || crate::kernel::exec::scheduler::module_slot_generation(s.owner.0) != s.owner.1;
        if s.owner != who && !gone {
            return EBUSY;
        }
        if s.phase == Phase::Ready {
            if s.image_len != image || s.seal != seal {
                return EINVAL;
            }
            // Already loaded: the image here is at least as new as either
            // slot, so there is nothing to load.
            s.owner = who;
            s.writing = (0, 0);
            return 1;
        }
    }
    s.owner = who;
    s.image_len = image;
    s.seal = seal;
    s.phase = Phase::Scanning;
    s.scan = [Scan::new(), Scan::new()];
    s.fill = Scan::new();
    if seal == wire::seal::NONE {
        log::warn!("[vault] store kept readable (seal: none): keys on the medium are not sealed");
    }
    0
}

/// Feed `data`, at `offset` of a slot, into `sc`. False when out of order.
fn feed(sc: &mut Scan, image_len: usize, offset: usize, data: &[u8]) -> bool {
    if offset != sc.got || offset + data.len() > image_len {
        return false;
    }
    for (i, &b) in data.iter().enumerate() {
        let p = offset + i;
        if p < HEADER {
            sc.header[p] = b;
        }
    }
    // The digest covers [0..DIGEST) and the body that follows the header.
    let end = offset + data.len();
    if offset < DIGEST {
        let to = end.min(DIGEST);
        sc.sha.update(&data[..to - offset]);
    }
    if end > HEADER {
        // The header is whole by now: it came first.
        let body = (u32_at(&sc.header, BODY_LEN) as usize).min(image_len - HEADER);
        let from = offset.max(HEADER);
        let to = end.min(HEADER + body);
        if to > from {
            sc.sha.update(&data[from - offset..to - offset]);
        }
    }
    sc.got = end;
    if sc.got == image_len {
        let h = &sc.header;
        let body = u32_at(h, BODY_LEN) as usize;
        let digest = sc.sha.clone().finalize();
        sc.digest = digest;
        if &h[0..4] == MAGIC
            && h[4] == VERSION
            && body <= image_len - HEADER
            && digest[..] == h[DIGEST..DIGEST + 32]
        {
            sc.seq = Some(u64_at(h, SEQ));
        }
    }
    true
}

unsafe fn load(s: &mut Store, a: &mut [u8]) -> i32 {
    if a.len() < wire::LOAD_LEN {
        return EINVAL;
    }
    let phase = a[0];
    let slot = a[1];
    let offset = u32_at(a, 4) as usize;
    let ptr = u64_at(a, 8) as usize as *const u8;
    let len = u32_at(a, 16) as usize;
    if slot >= SLOTS || ptr.is_null() || len == 0 {
        return EINVAL;
    }
    let data = core::slice::from_raw_parts(ptr, len);
    match (phase, s.phase) {
        (wire::phase::SCAN, Phase::Scanning) => {
            if offset == 0 {
                s.scan[slot as usize] = Scan::new();
            }
            if feed(&mut s.scan[slot as usize], s.image_len, offset, data) {
                0
            } else {
                EINVAL
            }
        }
        (wire::phase::FILL, Phase::Filling(chosen)) if chosen == slot => {
            if offset == 0 {
                s.fill = Scan::new();
            }
            let image_len = s.image_len;
            if !feed(&mut s.fill, image_len, offset, data) {
                return EINVAL;
            }
            live()[offset..offset + len].copy_from_slice(data);
            if s.fill.got < image_len {
                return 0;
            }
            let want = &s.scan[slot as usize];
            if s.fill.seq.is_none() || s.fill.seq != want.seq || s.fill.digest != want.digest {
                // The slot is not what the scan saw: start over.
                s.phase = Phase::Scanning;
                s.scan = [Scan::new(), Scan::new()];
                return EIO;
            }
            let seq = s.fill.seq.unwrap_or(0);
            s.live_seq = seq;
            s.durable_seq = seq;
            s.durable_slot = slot;
            s.fault = false;
            s.phase = Phase::Ready;
            log::info!("[vault] store loaded: slot {slot} seq {seq}");
            0
        }
        _ => EINVAL,
    }
}

unsafe fn decide(s: &mut Store) -> i32 {
    if s.phase != Phase::Scanning || s.scan[0].got != s.image_len || s.scan[1].got != s.image_len {
        return EINVAL;
    }
    let best = match (s.scan[0].seq, s.scan[1].seq) {
        (Some(a), Some(b)) => Some(if b > a { 1u8 } else { 0 }),
        (Some(_), None) => Some(0),
        (None, Some(_)) => Some(1),
        (None, None) => None,
    };
    match best {
        Some(slot) => {
            s.phase = Phase::Filling(slot);
            s.fill = Scan::new();
            i32::from(slot)
        }
        None => {
            // Never written (or neither slot whole): an empty store. It is
            // readable as empty, and no write is due until a record is.
            let img = &mut live()[..];
            img.fill(0);
            img[0..4].copy_from_slice(MAGIC);
            img[4] = VERSION;
            seal_digest(&mut img[..s.image_len]);
            s.live_seq = 0;
            s.durable_seq = 0;
            // So the first write lands in slot 0.
            s.durable_slot = 1;
            s.fault = false;
            s.phase = Phase::Ready;
            log::info!("[vault] store empty: no image in either slot");
            wire::DECIDE_EMPTY
        }
    }
}

unsafe fn pending(s: &mut Store, a: &mut [u8]) -> i32 {
    if a.len() < wire::PENDING_LEN {
        return EINVAL;
    }
    if s.phase != Phase::Ready {
        return EAGAIN;
    }
    if s.live_seq <= s.durable_seq {
        return 0;
    }
    let slot = 1 - s.durable_slot;
    s.writing = (s.live_seq, slot);
    a[0..8].copy_from_slice(&s.live_seq.to_le_bytes());
    a[8] = slot;
    1
}

unsafe fn read_image(s: &mut Store, a: &mut [u8]) -> i32 {
    if a.len() < wire::READ_LEN {
        return EINVAL;
    }
    let seq = u64_at(a, 0);
    let offset = u32_at(a, 8) as usize;
    let len = u32_at(a, 12) as usize;
    let ptr = u64_at(a, 16) as usize as *mut u8;
    if ptr.is_null() || offset + len > s.image_len {
        return EINVAL;
    }
    if s.phase != Phase::Ready || seq != s.live_seq || s.writing.0 != seq {
        return EAGAIN;
    }
    core::ptr::copy_nonoverlapping(live().as_ptr().add(offset), ptr, len);
    0
}

unsafe fn done(s: &mut Store, a: &mut [u8]) -> i32 {
    if a.len() < wire::DONE_LEN {
        return EINVAL;
    }
    let seq = u64_at(a, 0);
    let status = u32_at(a, 8) as i32;
    if seq != s.writing.0 || seq == 0 {
        return EINVAL;
    }
    if status == 0 {
        if seq > s.durable_seq {
            s.durable_seq = seq;
            s.durable_slot = s.writing.1;
        }
        s.fault = false;
    } else {
        if !s.fault {
            log::warn!(
                "[vault] store write failed (seq {seq}, errno {status}): keys made since wait"
            );
        }
        s.fault = true;
    }
    s.writing = (0, 0);
    0
}

/// Forget the store, as a fresh process would find it. Test-only.
///
/// # Safety
/// No vault call in progress.
pub unsafe fn reset_for_test() {
    let _h = lock();
    let s = store();
    s.expected = false;
    s.phase = Phase::Detached;
    s.owner = (usize::MAX, 0);
    s.image_len = 0;
    s.seal = wire::seal::HARDWARE;
    s.scan = [Scan::new(), Scan::new()];
    s.fill = Scan::new();
    s.durable_slot = 1;
    s.live_seq = 0;
    s.durable_seq = 0;
    s.fault = false;
    s.writing = (0, 0);
    s.warned_full = false;
    live().fill(0);
}
