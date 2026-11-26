// ── Key slots and who holds them ────────────────────────────────────────
//
// A handle names one key for one owner. The vault answers a slot's index;
// the kernel wraps it in a handle whose generation guards a caller's
// staleness. The slot records the module occupancy that created it, so a
// handle is useless to any other module, and every slot-bound op resolves
// its handle through `resolve`, which checks all of that before anything
// touches key material.

/// Most slots an instance may hold: the handle word's index field.
const MAX_HANDLE_SLOTS: usize = 4096;
/// Largest key a slot holds. 32 bytes is a P-256 scalar or a seed; an RSA
/// key lives in the RSA scratch and its slot names the entry.
const MAX_KEY_BYTES: usize = record::MAX_KEY;
/// Longest label.
const MAX_LABEL: usize = record::MAX_LABEL;

/// The slot holds a key.
const FLAG_IN_USE: u8 = 0x01;
/// The key is a durable record and survives a restart. Reported by
/// `DESCRIBE` beside the custody and separate from it: durability and
/// isolation are different properties.
const FLAG_PERSISTED: u8 = 0x02;
/// The key is persisted readable (`seal = none`): whoever holds the medium
/// holds the key.
const FLAG_CLEAR: u8 = 0x08;
/// The key is held by the `key_custody` provider; `data[..4]` is its token
/// handle.
const FLAG_TOKEN: u8 = 0x10;
/// A token key whose owner is gone, waiting for its token handle to be
/// released (`custody_step`).
const FLAG_TOKEN_RELEASE: u8 = 0x20;

/// The realm of a key made by node code: every module the node runs itself.
const NODE_REALM: [u8; 16] = [0; 16];

/// Where a label lives: its owner's module type within its owner's realm.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Scope {
    namespace: u32,
    realm: [u8; 16],
}

impl Scope {
    fn is_node(&self) -> bool {
        self.realm == NODE_REALM
    }
}

/// The module occupancy calling: `[idx u16][0 u16][gen u32]`, as
/// `MODULE_LIVE` takes it, and its type.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Caller {
    occupancy: [u8; 8],
    namespace: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Slot {
    flags: u8,
    key_len: u8,
    /// The key's suite (`key_vault::suite`).
    suite: u16,
    /// Permitted uses, sealed at creation and checked per operation.
    usage: u32,
    label: [u8; MAX_LABEL],
    label_len: u8,
    _pad: [u8; 3],
    /// The owning module occupancy (`Caller::occupancy`).
    occupancy: [u8; 8],
    /// The owner record (`CALLER_OWNER`) of that module, for the owner
    /// release notice.
    owner: [u8; 8],
    namespace: u32,
    realm: [u8; 16],
    data: [u8; MAX_KEY_BYTES],
}

impl Slot {
    fn label_bytes(&self) -> &[u8] {
        &self.label[..usize::from(self.label_len)]
    }

    fn in_use(&self) -> bool {
        self.flags & FLAG_IN_USE != 0
    }

    /// Whether this slot is filed under `label` in `scope`.
    fn filed_as(&self, scope: Scope, label: &[u8]) -> bool {
        self.in_use()
            && self.namespace == scope.namespace
            && self.realm == scope.realm
            && self.label_bytes() == label
    }

    /// Whether this slot permits `want`. An empty mask permits nothing.
    const fn permits(&self, want: u32) -> bool {
        self.usage & want == want
    }
}

/// The slot table.
fn slots(s: &mut State) -> &mut [Slot] {
    // SAFETY: `slots` names `n_slots` entries of this instance's heap, taken
    // at construction; the provider runs one call at a time.
    unsafe { core::slice::from_raw_parts_mut(s.slots, usize::from(s.n_slots)) }
}

/// The calling module, `None` when nobody is calling.
fn caller(s: &State) -> Option<Caller> {
    let mut r = [0u8; 12];
    if query(s, abi::kernel_abi::query_key::CALLER_MODULE, &mut r) != 12 {
        return None;
    }
    let mut occupancy = [0u8; 8];
    occupancy.copy_from_slice(&r[..8]);
    Some(Caller {
        occupancy,
        namespace: u32::from_le_bytes([r[8], r[9], r[10], r[11]]),
    })
}

/// The caller's realm: its owner's uid, the node's for a node-owned module.
fn caller_realm(s: &State) -> Option<[u8; 16]> {
    let mut r = [0u8; 16];
    (query(s, abi::kernel_abi::query_key::CALLER_OWNER_UID, &mut r) == 16).then_some(r)
}

/// The caller's owner record.
fn caller_owner(s: &State) -> [u8; 8] {
    let mut r = [0u8; 8];
    if query(s, abi::kernel_abi::query_key::CALLER_OWNER, &mut r) != 8 {
        r = [0xFF; 8];
    }
    r
}

/// The caller's scope.
fn caller_scope(s: &State) -> Option<(Caller, Scope)> {
    let c = caller(s)?;
    let realm = caller_realm(s)?;
    Some((
        c,
        Scope {
            namespace: c.namespace,
            realm,
        },
    ))
}

/// Whether a module occupancy still stands.
fn occupancy_live(s: &State, occupancy: &[u8; 8]) -> bool {
    let mut r = *occupancy;
    query(s, abi::kernel_abi::query_key::MODULE_LIVE, &mut r) == 1
}

/// Zeroise slot `i`: its key, its jobs and its filing. A token key is kept
/// (`FLAG_TOKEN_RELEASE`) until its token handle is released.
fn zeroise_slot(s: &mut State, i: usize) {
    if i >= usize::from(s.n_slots) {
        return;
    }
    drop_jobs_of(s, i);
    #[cfg(feature = "rsa")]
    rsa_release(s, i);
    let sl = &mut slots(s)[i];
    if sl.flags & FLAG_TOKEN != 0 {
        sl.flags = FLAG_TOKEN_RELEASE;
        sl.label_len = 0;
        sl.occupancy = [0xFF; 8];
        return;
    }
    zeroize(&mut sl.data);
    let generation_free = Slot {
        flags: 0,
        key_len: 0,
        suite: 0,
        usage: 0,
        label: [0; MAX_LABEL],
        label_len: 0,
        _pad: [0; 3],
        occupancy: [0xFF; 8],
        owner: [0xFF; 8],
        namespace: 0,
        realm: NODE_REALM,
        data: [0; MAX_KEY_BYTES],
    };
    *sl = generation_free;
}

/// Zeroise every key whose owning occupancy has ended: no one can use,
/// destroy or reopen it, and a labelled one would keep every later instance
/// of its type out with `EBUSY`.
fn reap_orphans(s: &mut State) {
    for i in 0..usize::from(s.n_slots) {
        let sl = slots(s)[i];
        if sl.in_use() && !occupancy_live(s, &sl.occupancy) {
            zeroise_slot(s, i);
        }
    }
}

/// `OWNER_RELEASED`: every key the released owner's modules hold goes.
fn owner_released(s: &mut State, arg: &[u8]) {
    let Some(rec) = arg.get(..8) else { return };
    for i in 0..usize::from(s.n_slots) {
        let sl = slots(s)[i];
        if sl.in_use() && sl.owner[..] == *rec {
            zeroise_slot(s, i);
        }
    }
    share_owner_released(s);
}

/// First free slot, after reaping the keys of modules that are gone.
fn alloc_slot(s: &mut State) -> Option<usize> {
    reap_orphans(s);
    slots(s).iter().position(|sl| sl.flags == 0)
}

/// Give slot `i` to `c` in `scope` and return what the kernel mints a
/// handle from: its index.
fn mint(s: &mut State, i: usize, c: Caller, scope: Scope) -> i32 {
    let owner = caller_owner(s);
    let sl = &mut slots(s)[i];
    sl.occupancy = c.occupancy;
    sl.owner = owner;
    sl.namespace = scope.namespace;
    sl.realm = scope.realm;
    i as i32
}

/// The slot `handle` names, if the caller may use it: `EINVAL` for
/// something that is not a vault index, `ENOENT` for a key that no longer
/// exists, `EACCES` for another module's key.
fn resolve(s: &mut State, handle: i32) -> Result<usize, i32> {
    if handle < 0 {
        return Err(EINVAL);
    }
    let i = handle as usize;
    if i >= usize::from(s.n_slots) {
        return Err(EINVAL);
    }
    let sl = slots(s)[i];
    if !sl.in_use() {
        return Err(ENOENT);
    }
    // A key whose owner is gone no longer exists, for anyone.
    if !occupancy_live(s, &sl.occupancy) {
        zeroise_slot(s, i);
        return Err(ENOENT);
    }
    match caller(s) {
        Some(c) if c.occupancy == sl.occupancy => Ok(i),
        _ => Err(EACCES),
    }
}

/// Copy `key` into slot `i` and mark it in use last, so a partial fill is
/// never observed.
fn fill_slot(s: &mut State, i: usize, suite: u16, usage: u32, key: &[u8], flags: u8) {
    let sl = &mut slots(s)[i];
    sl.suite = suite;
    sl.usage = usage;
    sl.key_len = key.len() as u8;
    for (j, b) in key.iter().enumerate() {
        // SAFETY: `j` is within `data` (`key.len() <= MAX_KEY_BYTES`).
        unsafe { core::ptr::write_volatile(&raw mut sl.data[j], *b) };
    }
    sl.flags = flags;
}

/// File slot `i` under `label`.
fn label_slot(s: &mut State, i: usize, label: &[u8]) {
    let sl = &mut slots(s)[i];
    sl.label[..label.len()].copy_from_slice(label);
    sl.label_len = label.len() as u8;
}
