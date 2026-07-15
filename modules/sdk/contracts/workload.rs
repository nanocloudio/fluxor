// Contract: workload — platform-neutral isolated-workload surface (class 0x1A).
//
// Layer: contracts (public, stable). See `.context/fluxor_nanocloud.md`.
//
// One contract for "run an isolated workload with a declared capability
// envelope," realized by two backends chosen by placement, never by the
// consumer:
//   * fmod-graph backend    — MPU/EL0 + owner/lease (bare metal),
//   * host-process backend  — namespaces/cgroups/veth (Linux).
//
// The consumer (e.g. a kubelet fmod) says WHAT to run and THE ENVELOPE, never
// HOW to isolate it or ON WHICH PLATFORM. Consistency rule: the same spec must
// yield the same isolation guarantee on both backends.
//
// Two tiers (RFC §5):
//   * Tier 1 — typed portable fields (the CREATE header): identity, posture,
//     resource envelope, network endpoints. Every backend maps them.
//   * Tier 2 — a backend-opaque options envelope (the trailing TLV section):
//     hardening knobs with no portable meaning. fluxor defines only the
//     envelope MECHANISM — it validates shape and routes a namespace to the
//     matching backend, and never enumerates keys. So this contract names zero
//     platform concepts (`seccomp`/`caps`/`selinux` are vocabulary in the Linux
//     backend's own docs, not here).
//
// Load-bearing invariant (RFC §5.3): Tier 1 alone must fully establish the
// isolation guarantee; the Tier-2 envelope may only refine WITHIN the declared
// posture. A backend that ignores the entire envelope still yields a
// correctly-isolated workload at the requested posture.

/// `CREATE` — admit and instantiate a workload from a spec (below); returns a
/// tagged `WorkloadHandle` fd, or a negative errno. The caller must hold the
/// workload-admit grant (`requires_contract = "workload"` + `platform_raw`).
/// Identity in the spec is mapped to an owner and lease-gated before any
/// backend mechanism runs.
pub const CREATE: u32 = 0x1A00;

/// `START` — release the create/start barrier so the workload begins executing.
/// `handle` = the `WorkloadHandle`. Returns `0` or a negative errno.
pub const START: u32 = 0x1A01;

/// `WAIT` — poll terminal state. `out` (>= 5 bytes) = `[state:u8][code:i32 LE]`
/// where `state` is [`STATE_RUNNING`]/[`STATE_EXITED`]/[`STATE_SIGNALLED`] and
/// `code` is the exit code (EXITED) or terminating signal (SIGNALLED).
/// Non-blocking; repeat calls return the cached terminal state once observed.
pub const WAIT: u32 = 0x1A02;

/// `SIGNAL` — deliver a signal/stop request. `arg` = `[signo:u32 LE]`
/// (portable subset: `TERM`/`KILL`; a backend maps to its mechanism). Returns
/// `0` or a negative errno.
pub const SIGNAL: u32 = 0x1A03;

/// `DESTROY` — stop (graceful → forced), reap, release the owner/lease and any
/// backend resources (cgroup, netns, arena). Idempotent. Returns `0`.
pub const DESTROY: u32 = 0x1A04;

/// `READ` — drain merged workload stdout/stderr (or the fmod diagnostic
/// stream) into `out`. Returns bytes read (`0` = none pending), or negative
/// errno. Optional; advertised via [`caps::READ`].
pub const READ: u32 = 0x1A05;

/// `CAPS` (`0x1AFF`) — backend capability discovery. Writes the fixed prefix
/// `[postures:u8][source_kinds:u8][ops:u16 LE]` then a namespace-directory the
/// caller consults *before* flagging a Tier-2 entry required (§5.2 rule 3):
///   `[ns_count:u16] then ns_count × ([ns_len:u8][ns bytes][key_count:u16] then
///    key_count × ([key_len:u8][key bytes]))`.
/// `postures`/`source_kinds`/`ops` are bitmaps over the constants below.
pub const CAPS: u32 = 0x1AFF;

// ---- posture ladder (RFC §6) — Tier-1 `posture` field values ----

/// No isolation — same address space / null sandbox (PROC semantics).
pub const POSTURE_SHARED: u8 = 0;
/// Memory + resource isolation (MPU/EL0 on metal; namespaces + cgroup on Linux).
pub const POSTURE_ISOLATED: u8 = 1;
/// `isolated` + reduced attack surface (Linux: seccomp + caps-drop + userns;
/// metal: strongest protection-domain config). Backend refinements are Tier-2.
pub const POSTURE_HARDENED: u8 = 2;

// ---- source kind (RFC §8.1) — Tier-1 `source_kind`; backend is placement-resolved ----

/// A fluxor graph/fmod artifact — resolves to the MPU/EL0 backend on a metal
/// node.
pub const SOURCE_FMOD_GRAPH: u8 = 0;
/// A rootfs bundle artifact — resolves to the host-process backend on Linux.
pub const SOURCE_BUNDLE: u8 = 1;

// ---- WAIT state byte ----
pub const STATE_RUNNING: u8 = 0;
pub const STATE_EXITED: u8 = 1;
pub const STATE_SIGNALLED: u8 = 2;

// ---- portable signal subset (SIGNAL `signo`) ----
/// Request graceful termination.
pub const SIG_TERM: u32 = 1;
/// Force kill.
pub const SIG_KILL: u32 = 2;

/// Fixed size of the `CREATE` typed header, in bytes. The variable-length
/// source-ref, endpoint, and options sections follow at this offset.
///
/// Layout (all little-endian):
/// ```text
/// off  size  field
///   0    16  identity        pod_uid → owner alloc/reuse
///  16     1  posture         POSTURE_*
///  17     1  source_kind     SOURCE_*
///  18     2  _reserved
///  20     4  compute_milli   milli core-equivalents (0 = unlimited)
///  24     8  memory_bytes    memory quota           (0 = unlimited)
///  32     4  max_tasks       max concurrent tasks   (0 = unlimited)
///  36     2  io_weight       relative IO share 1..=10000 (0 = unset)
///  38     2  _reserved
///  40     2  source_ref_len  bytes of source-ref section that follows
///  42     2  endpoint_count  number of NetEndpoint entries after source-ref
///  44     4  options_len     bytes of the Tier-2 TLV envelope (last section)
/// ```
/// Then: `source_ref[source_ref_len]`, `endpoints[endpoint_count]` (each
/// [`NET_ENDPOINT_SIZE`] bytes), `options[options_len]` (TLV, §5.2).
pub const CREATE_HEADER_SIZE: usize = 48;

/// One Tier-1 network endpoint the workload exports (RFC §7): `[proto:u8]
/// [net_iso:u8][port:u16 LE]`. `proto` is a `NET_PROTO_*`; `net_iso` selects
/// [`NET_ISO_SHARED`]/[`NET_ISO_OWN`]. Realized by the owner endpoint-lease
/// machinery (metal → NIC-ring; Linux → netns socket + veth/IPAM).
pub const NET_ENDPOINT_SIZE: usize = 4;

pub const NET_PROTO_TCP: u8 = 6;
pub const NET_PROTO_UDP: u8 = 17;

/// Endpoint shares the host/system network domain.
pub const NET_ISO_SHARED: u8 = 0;
/// Endpoint gets its own network domain/identity (metal lane; Linux netns).
pub const NET_ISO_OWN: u8 = 1;

/// Tier-2 TLV envelope (§5.2). fluxor validates this shape and routes a whole
/// namespace to the matching backend **without interpreting keys**. Entry:
/// ```text
/// [ns_len:u8][ns bytes][key_len:u8][key bytes][flags:u8][val_len:u16 LE][val bytes]
/// ```
/// `flags` bit 0 = [`OPT_REQUIRED`]. A *required* entry whose (namespace, key)
/// the target backend does not advertise via `CAPS` **fails admission**
/// (`ENOSYS`) — never silently dropped (§5.2 rule 2). Advisory entries a
/// backend does not understand are ignored.
pub mod opt {
    /// The entry is required: fail `CREATE` if the backend cannot honor it.
    pub const OPT_REQUIRED: u8 = 0x01;
}

/// `workload` provider capability bitmap. `provider_call(handle, CAPS, out,
/// out_len)` writes the discovery structure documented on [`CAPS`]. These are
/// bit positions within its `postures` / `source_kinds` / `ops` bitmaps.
pub mod caps {
    // `postures` bitmap
    pub const POSTURE_SHARED: u8 = 1 << 0;
    pub const POSTURE_ISOLATED: u8 = 1 << 1;
    pub const POSTURE_HARDENED: u8 = 1 << 2;

    // `source_kinds` bitmap
    pub const SOURCE_FMOD_GRAPH: u8 = 1 << 0;
    pub const SOURCE_BUNDLE: u8 = 1 << 1;

    // `ops` bitmap — optional opcodes beyond the mandatory create/start/wait/
    // signal/destroy set.
    pub const READ: u16 = 1 << 0;
}
