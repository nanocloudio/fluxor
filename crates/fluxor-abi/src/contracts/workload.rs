// Contract: workload — platform-neutral isolated-workload surface (class `workload`).
//
// Layer: contracts (public, stable).
//
// One contract for "run an isolated workload with a declared capability
// envelope," realized by two backends chosen by placement, never by the
// consumer:
//   * fmod-graph backend    — MPU/EL0 + owner (bare metal),
//   * host-process backend  — OS process isolation (Linux).
//
// The consumer (e.g. a workload manager) says WHAT to run and THE ENVELOPE, never
// HOW to isolate it or ON WHICH PLATFORM. Consistency rule: the same spec must
// yield the same isolation guarantee on both backends.
//
// ─── Surface layers: native core vs host-backend extensions ────────────
//
// The op surface is two layers, and the layer is part of the contract:
//
//   NATIVE CORE (every backend implements; the Fluxor lifecycle model):
//     CREATE / START / WAIT / SIGNAL(portable subset) / DESTROY / PAUSE /
//     RESUME / LANE / LOOKUP / CAPS / OPTIONS, plus the CREATE header
//     (identity, posture, resource envelope). Native semantics: a
//     workload is an owned execution context with a reversible frozen
//     state; "exit" means the owner is gone; SIG_TERM means drain, SIG_KILL
//     means reclaim. `compute_milli` is the native envelope unit (milli
//     core-equivalents), not an orchestrator convention.
//
//   HOST-PROCESS MECHANICS ARE NOT HERE: command execution, PTY sessions,
//     stdout/stderr drains, and rootfs bundles are one backend's
//     implementation vocabulary. They live in the host-scoped class
//     `abi::platform::linux::host_process`, which takes this contract's
//     handles in its handle slot — registered only where a
//     host platform exists; an unregistered class returns ENOSYS. The
//     `source_kind` byte here defines only the native artifacts
//     (`SOURCE_FMOD_GRAPH = 0`, `SOURCE_FMOD_PACK = 2`); other kinds are
//     backend-defined.
//
// A CREATE has two parts:
//   * the header — typed portable fields: identity, posture,
//     resource envelope. Every backend maps them. A workload's network is
//     the node's net provider's to realize, told by the node agent.
//   * the options — a backend-opaque envelope (the trailing TLV section):
//     hardening knobs with no portable meaning. fluxor defines only the
//     envelope MECHANISM — it validates shape and routes a namespace to the
//     matching backend, and never enumerates keys. So this contract names zero
//     platform concepts (`seccomp`/`caps`/`selinux` are vocabulary in the Linux
//     backend's own docs, not here).
//
// Load-bearing invariant: the header alone must fully establish the isolation
// guarantee; the options envelope may only refine WITHIN the declared posture.
// A backend that ignores the entire envelope still yields a correctly-isolated
// workload at the requested posture.
//
// Handle hygiene (normative): a workload starts holding only what it was
// granted. Nothing the node holds — no open file, socket, listener or other
// handle of the runtime's — reaches a workload unless the spec grants it; a
// backend that starts a workload as a host process passes it its granted
// stdio and nothing else.
//
// Handle binding (normative): a workload acts for the owner whose module
// created it. Every op that takes its handle — START, WAIT, SIGNAL, PAUSE,
// RESUME, DESTROY, LANE, and a host class's ops that carry the handle —
// and LOOKUP and DESTROY by identity answer a caller of any other owner
// `EACCES`. A caller acting with the node's authority (the node agent, or
// an owner admitted with it) acts on every workload. The binding is the
// owner's, not one module's, so a module of that owner that lost its handle
// recovers it with LOOKUP; LOOKUP never moves it. A CREATE being staged is
// the owner's that began it: only that owner (or the node's authority)
// continues it, finds it with LOOKUP or abandons it with DESTROY by
// identity — another owner is answered `EACCES` — and the workload it ends
// in is that owner's, whichever caller sends the call that finishes it.

/// `CREATE` — admit and instantiate a workload from a spec (below); returns a
/// tagged `WorkloadHandle` fd, or a negative errno. The caller must hold the
/// `workload.create` grant.
/// Identity in the spec is mapped to an owner before any backend mechanism
/// runs. The null identity names no one and is refused
/// (`EINVAL`). One identity is one workload: a `CREATE` for an identity that
/// already has a live workload answers `EEXIST`.
///
/// A graph backend stages a subgraph a few modules per call: `CREATE`
/// answers `EINPROGRESS` until the last module is in, and the caller asks
/// again each step with the same spec, byte for byte, until it gets the
/// handle. The backend works from its own copy of the subgraph and never
/// writes into the spec. While one `CREATE` is being staged, any other
/// spec, for its identity or another, answers `EBUSY` — another owner's
/// `CREATE` for the staged identity answers `EACCES`; [`LOOKUP`] finds the
/// staged identity and [`DESTROY`] by identity abandons it.
pub use super::super::registry::workload::CREATE;

/// `START` — release the create/start barrier so the workload begins executing.
/// `handle` = the `WorkloadHandle`. Returns `0` or a negative errno.
pub use super::super::registry::workload::START;

/// `WAIT` — poll terminal state. `out` (>= 5 bytes) = `[state:u8][code:i32 LE]`
/// where `state` is [`STATE_RUNNING`]/[`STATE_EXITED`]/[`STATE_SIGNALLED`] and
/// `code` is the exit code (EXITED) or terminating signal (SIGNALLED).
/// Non-blocking; repeat calls return the cached terminal state once observed.
pub use super::super::registry::workload::WAIT;

/// `SIGNAL` — deliver a signal/stop request. `arg` = `[signo:u32 LE]`
/// (portable subset: `TERM`/`KILL`; a backend maps to its mechanism). Returns
/// `0` or a negative errno.
pub use super::super::registry::workload::SIGNAL;

/// `DESTROY` — stop (graceful → forced), reap, release the owner and any
/// backend resources (isolation region, arena). Idempotent. Returns `0`.
///
/// With `handle = -1` and `arg` = the 16-byte identity, destroys by identity:
/// a live workload as above, or a `CREATE` still being staged, which is rolled
/// back. `ENOENT` when nothing carries the identity.
pub use super::super::registry::workload::DESTROY;

// The host-process mechanics (exec, PTY, read) are the `host_process`
// contract, `abi::platform::linux::host_process`.

/// `LANE` — one of the caller's own lanes into a workload it staged from an
/// fmod graph: an edge of its composed graph whose endpoint is the caller
/// (kind 4).
/// `handle` = the workload; `arg` = `[key:u8][dir:u8]` ([`lane::ARG_LEN`]):
/// the edge's `Endpoint` key and [`lane::TO_CALLER`] (the channel the caller
/// reads for the key's edge into it) or [`lane::FROM_CALLER`] (the one it
/// writes for the key's edge out of it). Returns that channel's handle;
/// `ENOENT` for a key or direction the graph does not have.
pub use super::super::registry::workload::LANE;

/// [`LANE`]'s argument.
pub mod lane {
    /// `[key:u8][dir:u8]`.
    pub const ARG_LEN: usize = 2;
    /// The channel the caller reads: the key's edge into it.
    pub const TO_CALLER: u8 = 0;
    /// The channel the caller writes: the key's edge out of it.
    pub const FROM_CALLER: u8 = 1;
}
/// `PAUSE` — freeze a workload (reversible; not a terminal state). Each
/// backend realizes it with its own freeze mechanism (host-process: the
/// process freezer; metal: its own quiesce). Idempotent: PAUSE on a paused
/// workload returns status 0; PAUSE on a terminal workload is a state error.
/// Advertised via [`caps::PAUSE`].
pub use super::super::registry::workload::PAUSE;
/// `RESUME` — thaw a paused workload, see [`PAUSE`]. Idempotent: RESUME on a
/// running workload returns status 0.
pub use super::super::registry::workload::RESUME;
/// Most caller lanes one workload holds.
pub const MAX_CALLER_LANES: usize = 8;

/// The workload's environment: an options entry on [`CREATE`], namespace
/// [`env::NS`], key [`env::KEY`], value `NAME=VALUE` (the name up to the
/// first `=`, never empty; the value may be empty), repeatable, a later
/// entry for a name replacing an earlier one. A backend that realizes it
/// lists it in [`OPTIONS`]; one that does not answers a required entry
/// `ENOSYS`.
///
/// A host process takes the entries into its environment, over the source's
/// own; the host-process backend lists the entry in [`OPTIONS`]. A graph
/// workload (`SOURCE_FMOD_GRAPH`, `SOURCE_FMOD_PACK`) has no environment of
/// its own and the graph backend lists no options entry: its creator binds
/// the values into the modules' params before `CREATE`
/// (`fluxor_contracts::graph::env_bind`), and the backend refuses an add that
/// still carries an env bind record (`EINVAL`).
pub mod env {
    pub const NS: &[u8] = b"env";
    pub const KEY: &[u8] = b"var";
}

/// A volume lent to a host-process workload: an options entry on [`CREATE`],
/// namespace [`volume::NS`], key [`volume::KEY`], value `<src>\0<dst>\0<ro>`
/// — `src` an absolute host directory, `dst` the path the workload names it
/// by, `ro` `1` (read-only) or `0` (left out with its `\0`: writable).
/// Repeatable, at most [`volume::MAX`] per workload.
///
/// A host process has `src` bind-mounted at `dst` in its root; on a
/// read-only volume nothing is created, written, renamed or removed. A
/// volume is lent, not owned: what it holds is never charged to the owner's
/// storage line, and the owner's release leaves it as it was. A graph
/// workload is lent volumes by the node's workload `fs` layer, not by its
/// `CREATE`: the graph backend does not list this entry in [`OPTIONS`] and
/// answers a required one `ENOSYS`, so a consumer marks every volume
/// required.
pub mod volume {
    pub const NS: &[u8] = b"mount";
    pub const KEY: &[u8] = b"bind";
    /// Most volumes one workload is lent.
    pub const MAX: usize = 16;
}

/// An endpoint a graph workload's owner may listen on: an options entry on
/// [`CREATE`], namespace [`endpoint::NS`], key [`endpoint::KEY`], value
/// `[protocol u8][port u16 LE]` (`protocol` an IP protocol number,
/// `net_proto::grant::PROTO_TCP` or `PROTO_UDP`; `port` nonzero).
/// Repeatable, at most `net_proto::grant::MAX_ADMITTED_ENDPOINTS` per
/// workload, each once.
///
/// The entries are the owner's `net.endpoint` grants (`OWNER_GRANTS`): a
/// workload's lane listens on a port only where its owner holds one, so a
/// graph workload created with none listens nowhere. The creator grants
/// them, so only a creator acting with the node's authority may (`EACCES`
/// otherwise).
///
/// An endpoint is leased on the addresses its owner can listen on. An
/// owner created without [`own_address`] may listen on the node's shared
/// addresses, so its endpoints are exclusive among all such owners: one
/// that another live owner without [`own_address`] holds (by its admission
/// or by the committed plan) is `EEXIST`. An owner created with
/// [`own_address`] listens on its own addresses alone, so its endpoints
/// collide with no other owner's.
///
/// The graph backend lists the entry in [`OPTIONS`]; the host-process
/// backend does not (a host process's sockets are the host's, not a lane's)
/// and answers a required one `ENOSYS`, so a creator marks every endpoint
/// required.
pub mod endpoint {
    pub const NS: &[u8] = b"net";
    pub const KEY: &[u8] = b"endpoint";
    /// Bytes of an entry's value.
    pub const LEN: usize = 3;
}

/// The graph workload's owner listens on addresses of its own only: an
/// options entry on [`CREATE`], namespace [`own_address::NS`], key
/// [`own_address::KEY`], empty value, at most once. A creator that gives
/// the workload an address of its own (`net::identity`'s `ADDR_ADD`, after
/// the `CREATE` and before `START`) states it here.
///
/// The owner's grants then carry `net_proto::grant::OWN_ADDRESS`. A network
/// stack anchors its listens at the owner's own addresses and refuses
/// (`EADDRNOTAVAIL`) a listen while it holds none, so its [`endpoint`]s are
/// no lease on the node's shared addresses. Only a creator acting with the
/// node's authority may give it (`EACCES` otherwise). The graph backend
/// lists the entry in [`OPTIONS`]; the host-process backend does not and
/// answers a required one `ENOSYS`.
pub mod own_address {
    pub const NS: &[u8] = b"net";
    pub const KEY: &[u8] = b"own_address";
}

/// `CAPS` — backend capability discovery. `handle = -1` (or a bound handle);
/// `arg` out is exactly 4 bytes, the `u32` LE [`caps`] word; no `data`.
/// Returns 0. Every backend implements it; `ENOSYS` from `CAPS` means there
/// is no backend.
pub use super::super::registry::workload::CAPS;

/// `OPTIONS` — the options `(namespace, key)` entries the backend realizes,
/// which a caller consults *before* flagging an entry required. `handle =
/// -1`; no `arg`; `data` out receives the directory
///   `[ns_count:u16] then ns_count × ([ns_len:u8][ns bytes][key_count:u16]
///    then key_count × ([key_len:u8][key bytes]))`.
/// Returns its length, or `ERANGE` when `data` cannot hold it.
pub use super::super::registry::workload::OPTIONS;

// ---- posture ladder — header `posture` field values ----

// The posture is the isolation: a backend whose source also says whether
// the workload is isolated (a backend-defined source kind may) refuses
// (`EINVAL`) a source that disagrees with the posture — isolation asked for
// at `POSTURE_SHARED`, or none at `POSTURE_ISOLATED` or above — rather than
// let either one decide alone.

/// No isolation — same address space / null sandbox (PROC semantics).
pub const POSTURE_SHARED: u8 = 0;
/// Memory + resource isolation, realized by the platform's strongest
/// available protection mechanism. On a metal node (the graph backend) it
/// means exactly: each module the workload brings runs unprivileged under
/// its own translation regime (an EL0 page table and ASID, or an MPU
/// region), with no access to the kernel's or another owner's memory,
/// reaching the kernel only through the gateway, and a step that runs past
/// its deadline is forced out and faulted. It does not cover cache or timing
/// side channels or memory bandwidth, and not a provider the workload
/// composes from the node's own image (`workload_instantiable`): that code is
/// the node's, runs privileged and is not contained — a hang inside it is
/// the node's fault, as for any node module. A workload that keeps faulting
/// is restarted under the node's fault backoff, so its availability is
/// bounded by its deadline times its restart rate. A metal backend realizes
/// a `SHARED` request at this posture (a posture is a floor).
pub const POSTURE_ISOLATED: u8 = 1;
/// `isolated` + reduced attack surface (Linux: reduced syscall + privilege
/// surface; metal: strongest isolation-region config). Backend refinements
/// are options entries. A backend advertises it in [`CAPS`] only where it realizes
/// it; a request that widens the reduced surface back out (an opt-out a
/// backend's source offers for a privileged workload) is `EINVAL` at this
/// posture.
pub const POSTURE_HARDENED: u8 = 2;

// ---- source kind — header `source_kind`; backend is placement-resolved ----

/// A fluxor graph/fmod artifact — resolves to the MPU/EL0 backend on a metal
/// node.
pub const SOURCE_FMOD_GRAPH: u8 = 0;

/// A fluxor graph that brings its own modules: `.fmod`s the node's firmware image
/// does not hold, staged as the workload's own code for as long as it lives.
/// The source section is a [`PackRef`] header, `pin_count` 32-byte SHA-256
/// pins, then the composed graph whose modules resolve in the pack first and
/// the node's image second.
///
/// The pack is an FXMT module table (`fluxor build`'s modules blob), the
/// call's `data`, copied during CREATE. Every module in it is admitted only
/// when its full `.fmod` bytes hash to one of the pins — the digest an OCI
/// layer is addressed by — or it carries a signature the node's signing root
/// verifies; otherwise CREATE fails `EACCES`. A kernel built to enforce
/// signatures requires a valid signature of every module it loads, a pinned
/// one included. A node without code space for packs answers `ENOSYS`; a
/// pack past it `E2BIG` or `ENOMEM`.
pub const SOURCE_FMOD_PACK: u8 = 2;

/// The head of a [`SOURCE_FMOD_PACK`] source section, little-endian:
/// ```text
/// off  size  field
///   0    2   pin_count   SHA-256 pins that follow, 32 bytes each
///   2    2   0
/// ```
/// Then `pin_count * 32` pin bytes, then the composed graph. The module table
/// itself is the CREATE call's `data`.
pub mod pack_ref {
    pub const SIZE: usize = 4;
    pub const PIN_COUNT: usize = 0;
    pub const PIN_SIZE: usize = 32;
}

/// `LOOKUP` — the workload an identity names, for a caller that lost its
/// handle (a restart mid-`CREATE`, or after it). `handle = -1`; `arg` is the
/// 16-byte identity, and on success it receives `[slot:u16 LE][generation:u32
/// LE]` of the owner. Returns the tagged `WorkloadHandle`, `EINPROGRESS` when
/// the identity's `CREATE` is still being staged (continue it with the same
/// spec, or abandon it with [`DESTROY`] by identity), or `ENOENT`.
pub use super::super::registry::workload::LOOKUP;

/// `OWNERS` — the node's owner facts: every workload owner the kernel holds
/// and every drained one the applied owner plan still lists, as fixed binary
/// records (layout in [`owners`]). `handle = -1`, no `arg`; `data` out =
/// the answer. Returns its length, `ERANGE` when `data` cannot hold it,
/// `EACCES` for a caller not acting with the node's authority. The same
/// read on every target: rendering, history and retention are the reader's.
pub use super::super::registry::workload::OWNERS;

/// The [`OWNERS`] answer, little-endian: a [`owners::HEADER_LEN`]-byte head
/// `[count:u16][record_len:u16][_:u32][plan_generation:u64]
/// [plan_digest:32]`, then `count` records of `record_len` bytes, by owner
/// slot. A reader takes `record_len` from the head and the fields it knows
/// from each record's front.
pub mod owners {
    /// Bytes of the answer's head.
    pub const HEADER_LEN: usize = 48;
    /// Bytes of one record.
    pub const RECORD_LEN: usize = 64;

    /// Head: the record count, `u16`.
    pub const H_COUNT: usize = 0;
    /// Head: the record length, `u16`.
    pub const H_RECORD_LEN: usize = 2;
    /// Head: the generation of the owner plan last applied, `u64` (0: none).
    pub const H_PLAN_GENERATION: usize = 8;
    /// Head: that plan's digest, 32 bytes.
    pub const H_PLAN_DIGEST: usize = 16;

    /// The owner's identity, 16 bytes.
    pub const UID: usize = 0;
    /// Its owner slot, `u16`.
    pub const SLOT: usize = 16;
    /// Its state, `u8` (`STATE_*`).
    pub const STATE: usize = 18;
    /// The fault kind of its most recent terminated module, `u8` (0: none).
    pub const FAULT_KIND: usize = 19;
    /// Its owner generation, `u32`.
    pub const GENERATION: usize = 20;
    /// Modules the owner stamps, `u16`.
    pub const MODULES: usize = 24;
    /// Of those, instantiated, `u16`.
    pub const LOADED: usize = 26;
    /// Of those, ended cleanly, `u16`.
    pub const FINISHED: usize = 28;
    /// Of those, terminated by the fault policy, `u16`.
    pub const TERMINATED: usize = 30;
    /// Of those, faulted and being retried by the fault policy, `u16`.
    pub const RECOVERING: usize = 32;
    /// How a drain ended, `u8` (`DRAIN_*`).
    pub const DRAIN: usize = 34;
    /// How many times this kernel instantiated the owner's modules, `u32`:
    /// 1 for its first activation, one more for each rebuild that
    /// instantiates them again.
    pub const ACTIVATIONS: usize = 36;
    /// When its most recent terminated module faulted, ms of kernel uptime,
    /// `u64` (0: none).
    pub const FAULT_MS: usize = 40;
    /// The drain deadline the plan's revocation states, unix seconds, `u64`
    /// (0: not revoked).
    pub const DRAIN_DEADLINE: usize = 48;
    /// When the kernel freed the drained owner, unix seconds of the clock
    /// the platform drives the drain with, `u64` (0: not freed by a drain
    /// this kernel ran).
    pub const DRAINED_AT: usize = 56;

    /// `STATE`: running.
    pub const STATE_ACTIVE: u8 = 0;
    /// `STATE`: draining before its revocation; admits nothing new.
    pub const STATE_DRAINING: u8 = 1;
    /// `STATE`: paused (reversible).
    pub const STATE_PAUSED: u8 = 2;
    /// `STATE`: drained and freed; the record stays while the plan lists
    /// the revocation.
    pub const STATE_GONE: u8 = 3;

    /// `FAULT_KIND`: no module terminated.
    pub const FAULT_NONE: u8 = 0;
    /// `FAULT_KIND`: a step overran its deadline.
    pub const FAULT_TIMEOUT: u8 = 1;
    /// `FAULT_KIND`: a step returned an error.
    pub const FAULT_STEP_ERROR: u8 = 2;
    /// `FAULT_KIND`: a module faulted on memory protection.
    pub const FAULT_MPU: u8 = 4;
    /// `FAULT_KIND`: a module did not drain within its deadline.
    pub const FAULT_DRAIN_TIMEOUT: u8 = 5;

    /// `DRAIN`: not drained.
    pub const DRAIN_NONE: u8 = 0;
    /// `DRAIN`: freed once every module it stamps ended and its edges ran
    /// dry.
    pub const DRAIN_QUIESCED: u8 = 1;
    /// `DRAIN`: freed at the deadline, still running.
    pub const DRAIN_DEADLINE_PASSED: u8 = 2;
    /// `DRAIN`: freed without a drain this kernel ran: a rebuild dropped it
    /// mid-drain, or this kernel never held it (it started after the owner
    /// was revoked).
    pub const DRAIN_FORFEITED: u8 = 3;

    /// One record, read.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
    pub struct Record {
        pub uid: [u8; 16],
        pub slot: u16,
        pub state: u8,
        pub fault_kind: u8,
        pub generation: u32,
        pub modules: u16,
        pub loaded: u16,
        pub finished: u16,
        pub terminated: u16,
        pub recovering: u16,
        pub drain: u8,
        pub activations: u32,
        pub fault_ms: u64,
        pub drain_deadline: u64,
        pub drained_at: u64,
    }

    fn u16_at(b: &[u8], o: usize) -> u16 {
        u16::from_le_bytes([b[o], b[o + 1]])
    }
    fn u32_at(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
    }
    fn u64_at(b: &[u8], o: usize) -> u64 {
        let mut v = [0u8; 8];
        v.copy_from_slice(&b[o..o + 8]);
        u64::from_le_bytes(v)
    }

    impl Record {
        /// Write the record into `out`'s first [`RECORD_LEN`] bytes; `false`
        /// when `out` is shorter.
        pub fn write(&self, out: &mut [u8]) -> bool {
            let Some(b) = out.get_mut(..RECORD_LEN) else {
                return false;
            };
            b.fill(0);
            b[UID..UID + 16].copy_from_slice(&self.uid);
            b[SLOT..SLOT + 2].copy_from_slice(&self.slot.to_le_bytes());
            b[STATE] = self.state;
            b[FAULT_KIND] = self.fault_kind;
            b[GENERATION..GENERATION + 4].copy_from_slice(&self.generation.to_le_bytes());
            for (o, v) in [
                (MODULES, self.modules),
                (LOADED, self.loaded),
                (FINISHED, self.finished),
                (TERMINATED, self.terminated),
                (RECOVERING, self.recovering),
            ] {
                b[o..o + 2].copy_from_slice(&v.to_le_bytes());
            }
            b[DRAIN] = self.drain;
            b[ACTIVATIONS..ACTIVATIONS + 4].copy_from_slice(&self.activations.to_le_bytes());
            for (o, v) in [
                (FAULT_MS, self.fault_ms),
                (DRAIN_DEADLINE, self.drain_deadline),
                (DRAINED_AT, self.drained_at),
            ] {
                b[o..o + 8].copy_from_slice(&v.to_le_bytes());
            }
            true
        }

        /// Read a record from `b`'s first [`RECORD_LEN`] bytes.
        pub fn read(b: &[u8]) -> Option<Record> {
            let b = b.get(..RECORD_LEN)?;
            let mut uid = [0u8; 16];
            uid.copy_from_slice(&b[UID..UID + 16]);
            Some(Record {
                uid,
                slot: u16_at(b, SLOT),
                state: b[STATE],
                fault_kind: b[FAULT_KIND],
                generation: u32_at(b, GENERATION),
                modules: u16_at(b, MODULES),
                loaded: u16_at(b, LOADED),
                finished: u16_at(b, FINISHED),
                terminated: u16_at(b, TERMINATED),
                recovering: u16_at(b, RECOVERING),
                drain: b[DRAIN],
                activations: u32_at(b, ACTIVATIONS),
                fault_ms: u64_at(b, FAULT_MS),
                drain_deadline: u64_at(b, DRAIN_DEADLINE),
                drained_at: u64_at(b, DRAINED_AT),
            })
        }
    }

    /// The answer's head, read: `(count, record_len, plan_generation,
    /// plan_digest)`. `None` when `b` is shorter than the head, a record is
    /// shorter than [`RECORD_LEN`], or the records overrun `b`.
    pub fn read_head(b: &[u8]) -> Option<(usize, usize, u64, [u8; 32])> {
        let h = b.get(..HEADER_LEN)?;
        let count = usize::from(u16_at(h, H_COUNT));
        let len = usize::from(u16_at(h, H_RECORD_LEN));
        if len < RECORD_LEN || HEADER_LEN + count * len > b.len() {
            return None;
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&h[H_PLAN_DIGEST..H_PLAN_DIGEST + 32]);
        Some((count, len, u64_at(h, H_PLAN_GENERATION), digest))
    }

    /// Write the head into `out`'s first [`HEADER_LEN`] bytes.
    pub fn write_head(out: &mut [u8], count: u16, plan_generation: u64, plan_digest: &[u8; 32]) {
        let h = &mut out[..HEADER_LEN];
        h.fill(0);
        h[H_COUNT..H_COUNT + 2].copy_from_slice(&count.to_le_bytes());
        h[H_RECORD_LEN..H_RECORD_LEN + 2].copy_from_slice(&(RECORD_LEN as u16).to_le_bytes());
        h[H_PLAN_GENERATION..H_PLAN_GENERATION + 8].copy_from_slice(&plan_generation.to_le_bytes());
        h[H_PLAN_DIGEST..H_PLAN_DIGEST + 32].copy_from_slice(plan_digest);
    }
}
// Every other source kind is backend-defined (the linux host-process source kind is
// `abi::platform::linux::host_process::SOURCE_HOST_PROCESS`).

// ---- WAIT state byte ----
pub const STATE_RUNNING: u8 = 0;
pub const STATE_EXITED: u8 = 1;
pub const STATE_SIGNALLED: u8 = 2;
/// Frozen by [`PAUSE`]; live, not terminal. A consumer's status loop must
/// treat it as live — only EXITED/SIGNALLED latch. After [`RESUME`], the
/// next WAIT poll reflects RUNNING.
pub const STATE_PAUSED: u8 = 3;

// ---- portable signal subset (SIGNAL `signo`) ----
/// Request graceful termination.
pub const SIG_TERM: u32 = 1;
/// Force kill.
pub const SIG_KILL: u32 = 2;

/// Fixed size of the `CREATE` typed header, in bytes. The source-ref and
/// options sections follow at this offset.
///
/// Layout (all little-endian):
/// ```text
/// off  size  field
///   0    16  identity        owner_uid: the one owner the workload runs as
///  16     1  posture         POSTURE_*
///  17     1  source_kind     SOURCE_*
///  18     1  storage         STORAGE_* — whether the owner holds a storage
///                            line
///  19     1  0
///  20     4  compute_milli   milli core-equivalents (0 = unlimited)
///  24     8  memory_bytes    memory quota           (0 = unlimited)
///  32     4  max_tasks       max concurrent tasks   (0 = unlimited)
///  36     2  io_weight       relative IO share 1..=10000 (0 = unset)
///  38     2  0
///  40     2  source_ref_len  bytes of source-ref section that follows
///  42     2  0
///  44     4  options_len     bytes of the TLV options envelope (last section)
///  48     8  storage_bytes   the storage line's cap: the bytes the workload
///                            may hold through the node's workload `fs` layer
///                            (0 = uncapped)
/// ```
/// Then: `source_ref[source_ref_len]`, `options[options_len]` (the TLV
/// envelope, [`opt`]). Bytes past the options are refused.
///
/// The header names no network: a workload's address and the name service
/// it asks are given by the node agent to the node's net provider
/// (`net::identity`'s `ADDR_ADD` and `OWNER_RESOLVER` on its `addr_ctl`)
/// before `START`, and the endpoints it may listen on are its creator's
/// [`endpoint`] options.
pub const CREATE_HEADER_SIZE: usize = 56;

/// A `CREATE` header, read: [`CreateHeader::parse`] is the one reader every
/// backend and tool uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateHeader {
    pub identity: [u8; 16],
    pub posture: u8,
    pub source_kind: u8,
    pub storage: u8,
    pub compute_milli: u32,
    pub memory_bytes: u64,
    pub max_tasks: u32,
    pub io_weight: u16,
    pub source_ref_len: u16,
    pub options_len: u32,
    pub storage_bytes: u64,
}

impl CreateHeader {
    /// The header of `spec` and where its sections lie: `(header, source
    /// range, options range)`. `None` for a spec shorter than its header or
    /// its sections, one with a reserved byte set, or bytes past the
    /// options.
    pub fn parse(spec: &[u8]) -> Option<(Self, core::ops::Range<usize>, core::ops::Range<usize>)> {
        let h = spec.get(..CREATE_HEADER_SIZE)?;
        let u16_at = |o: usize| u16::from_le_bytes([h[o], h[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]);
        let u64_at = |o: usize| u64::from(u32_at(o)) | (u64::from(u32_at(o + 4)) << 32);
        if h[19] != 0 || u16_at(38) != 0 || u16_at(42) != 0 {
            return None;
        }
        let mut identity = [0u8; 16];
        identity.copy_from_slice(&h[..16]);
        let hdr = Self {
            identity,
            posture: h[16],
            source_kind: h[17],
            storage: h[18],
            compute_milli: u32_at(20),
            memory_bytes: u64_at(24),
            max_tasks: u32_at(32),
            io_weight: u16_at(36),
            source_ref_len: u16_at(40),
            options_len: u32_at(44),
            storage_bytes: u64_at(48),
        };
        let src = CREATE_HEADER_SIZE..CREATE_HEADER_SIZE + usize::from(hdr.source_ref_len);
        let opts = src.end..src.end.checked_add(hdr.options_len as usize)?;
        if opts.end != spec.len() {
            return None;
        }
        Some((hdr, src, opts))
    }

    /// The header's bytes.
    pub fn write(&self, out: &mut [u8; CREATE_HEADER_SIZE]) {
        out.fill(0);
        out[..16].copy_from_slice(&self.identity);
        out[16] = self.posture;
        out[17] = self.source_kind;
        out[18] = self.storage;
        out[20..24].copy_from_slice(&self.compute_milli.to_le_bytes());
        out[24..32].copy_from_slice(&self.memory_bytes.to_le_bytes());
        out[32..36].copy_from_slice(&self.max_tasks.to_le_bytes());
        out[36..38].copy_from_slice(&self.io_weight.to_le_bytes());
        out[40..42].copy_from_slice(&self.source_ref_len.to_le_bytes());
        out[44..48].copy_from_slice(&self.options_len.to_le_bytes());
        out[48..56].copy_from_slice(&self.storage_bytes.to_le_bytes());
    }
}

/// Storage line values (`storage`). A workload reaches the node's storage
/// only through the node graph's workload-scoped `fs` layer (`owner_fs`), which
/// roots it beneath a directory of its own and charges what it holds to the
/// owner's storage line (`resource::OWNER_LINE_STORAGE`). Any other value is
/// `EINVAL`.
///
/// A storage line installed, capped at `storage_bytes`. The default.
pub const STORAGE_OWN_ROOT: u8 = 0;
/// No storage line: the workload layer's every charge for the workload is
/// refused (`EACCES`), so it makes no root. What it keeps, it keeps in a
/// provider of its own.
pub const STORAGE_NONE: u8 = 1;

/// TLV options envelope. fluxor validates this shape and routes a whole
/// namespace to the matching backend **without interpreting keys**. Entry:
/// ```text
/// [ns_len:u8][ns bytes][key_len:u8][key bytes][flags:u8][val_len:u16 LE][val bytes]
/// ```
/// `flags` bit 0 = [`OPT_REQUIRED`]. A *required* entry whose (namespace, key)
/// the target backend does not advertise via [`OPTIONS`] **fails admission**
/// (`ENOSYS`) — never silently dropped. Advisory entries a
/// backend does not understand are ignored.
pub mod opt {
    /// The entry is required: fail `CREATE` if the backend cannot honor it.
    pub const OPT_REQUIRED: u8 = 0x01;

    /// One options entry.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Entry<'a> {
        pub ns: &'a [u8],
        pub key: &'a [u8],
        pub flags: u8,
        pub val: &'a [u8],
    }

    impl Entry<'_> {
        /// Whether the entry is [`OPT_REQUIRED`].
        pub fn required(&self) -> bool {
            self.flags & OPT_REQUIRED != 0
        }
    }

    /// The entries of an options envelope, in order: the one parser of the
    /// envelope. An entry that overruns the envelope yields `Err(())` and
    /// ends the walk.
    pub fn iter(opts: &[u8]) -> Iter<'_> {
        Iter { opts, at: 0 }
    }

    /// See [`iter`].
    pub struct Iter<'a> {
        opts: &'a [u8],
        at: usize,
    }

    impl<'a> Iter<'a> {
        fn entry(&self) -> Option<(Entry<'a>, usize)> {
            let (o, at) = (self.opts, self.at);
            let ns_len = usize::from(*o.get(at)?);
            let ns = o.get(at + 1..at + 1 + ns_len)?;
            let k = at + 1 + ns_len;
            let key_len = usize::from(*o.get(k)?);
            let key = o.get(k + 1..k + 1 + key_len)?;
            let f = k + 1 + key_len;
            let flags = *o.get(f)?;
            let vl = usize::from(u16::from_le_bytes([*o.get(f + 1)?, *o.get(f + 2)?]));
            let val = o.get(f + 3..f + 3 + vl)?;
            Some((
                Entry {
                    ns,
                    key,
                    flags,
                    val,
                },
                f + 3 + vl,
            ))
        }
    }

    impl<'a> Iterator for Iter<'a> {
        type Item = Result<Entry<'a>, ()>;
        fn next(&mut self) -> Option<Self::Item> {
            if self.at >= self.opts.len() {
                return None;
            }
            match self.entry() {
                Some((e, next)) => {
                    self.at = next;
                    Some(Ok(e))
                }
                None => {
                    self.at = self.opts.len();
                    Some(Err(()))
                }
            }
        }
    }

    /// Write one entry into `out` at `at`; the offset past it, or `None`
    /// when it does not fit or a field passes its width.
    pub fn put(out: &mut [u8], at: usize, e: &Entry<'_>) -> Option<usize> {
        let ns_len = u8::try_from(e.ns.len()).ok()?;
        let key_len = u8::try_from(e.key.len()).ok()?;
        let vl = u16::try_from(e.val.len()).ok()?;
        let end = at + 1 + e.ns.len() + 1 + e.key.len() + 3 + e.val.len();
        let b = out.get_mut(at..end)?;
        b[0] = ns_len;
        b[1..1 + e.ns.len()].copy_from_slice(e.ns);
        let k = 1 + e.ns.len();
        b[k] = key_len;
        b[k + 1..k + 1 + e.key.len()].copy_from_slice(e.key);
        let f = k + 1 + e.key.len();
        b[f] = e.flags;
        b[f + 1..f + 3].copy_from_slice(&vl.to_le_bytes());
        b[f + 3..].copy_from_slice(e.val);
        Some(end)
    }
}

/// [`CAPS`] bits. One `u32` of four bytes: the postures realized (bits
/// 0..=7, bit `p` for posture `p`), the source kinds accepted (bits 8..=15,
/// bit `8 + k` for kind `k`; kinds past the native ones are backend-defined),
/// the optional ops (bits 16..=23) and the header network fields realized
/// (bits 24..=31).
pub mod caps {
    /// The bit for posture `p` ([`super::POSTURE_SHARED`] …).
    pub const fn posture(p: u8) -> u32 {
        if p < 8 {
            1 << p
        } else {
            0
        }
    }
    /// The bit for source kind `k` ([`super::SOURCE_FMOD_GRAPH`] …).
    pub const fn source_kind(k: u8) -> u32 {
        if k < 8 {
            1 << (8 + k)
        } else {
            0
        }
    }

    pub const POSTURE_SHARED: u32 = posture(super::POSTURE_SHARED);
    pub const POSTURE_ISOLATED: u32 = posture(super::POSTURE_ISOLATED);
    pub const POSTURE_HARDENED: u32 = posture(super::POSTURE_HARDENED);

    pub const SOURCE_FMOD_GRAPH: u32 = source_kind(super::SOURCE_FMOD_GRAPH);
    pub const SOURCE_FMOD_PACK: u32 = source_kind(super::SOURCE_FMOD_PACK);

    // Optional ops beyond the mandatory create/start/wait/signal/destroy
    // set. SIGNAL itself is mandatory to *accept*; its bit asserts
    // real-signal delivery semantics.
    /// SIGNAL is delivered by the backend's real signal mechanism,
    /// not merely recorded as a stop request.
    pub const SIGNAL: u32 = 1 << 16;
    /// Backend implements the [`super::PAUSE`]/[`super::RESUME`] pair. The
    /// bit claims the backend can freeze AT ALL; a specific workload whose
    /// freeze mechanism could not be set up may still return `ENOSYS`.
    pub const PAUSE: u32 = 1 << 17;
    /// Backend answers [`super::LOOKUP`] and [`super::DESTROY`] by identity,
    /// and its `CREATE` may answer `EINPROGRESS` between batches.
    pub const LOOKUP: u32 = 1 << 18;
}
