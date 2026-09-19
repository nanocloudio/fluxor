# GPU Contract

Fluxor's GPU surface is one contract with independent compute, raster and
presentation capabilities, shared resource ownership and asynchronous
completion. There is one contract and it is this one: no version field, no
negotiation, no compatibility layer. A graph wired to it runs unchanged against a
provider with no hardware, against WebGPU in a browser, and against
Vulkan on a Linux host — including a Raspberry Pi 5's V3D, headless.

This document is the GPU peer of `av_capability_surface.md` (presentation)
and `protocol_surfaces.md` (net).

Sources: `modules/sdk/wire/gpu_wire.rs` (the contract),
`modules/sdk/cores/gpu_{pack,device,pump,client,replay}.rs` (the portable
half), `contracts/src/vocabulary.rs` (capability facts).

---

## 1. What Fluxor owns, and what it does not

Fluxor owns resource, queue and fence contracts, admission, lifecycle and
bounded execution; the backends; the generic program-pack envelope, binding
validation and artifact identity; completion telemetry; and device sharing,
isolation and recovery.

It owns no application meaning. Tensor shapes, model operators, quantisation,
token sampling, terrain and meshing algorithms, rasteriser semantics, A/V
pacing policy, kernel source and numerical tolerance all belong to the
consumer. The contract frames *generic executable work over generic
resources*: a program pack, buffers and views, a dependency-ordered
submission, a fence, and a structured outcome.

## 2. The split every provider makes

Every GPU backend has two halves.

One owns OS or browser objects: adapters, queues, command encoders, shader
modules, mapped memory. The other decides whether a request is allowed at all,
what a handle means, when an output becomes observable, what a fence is worth,
and what a failure did to the caller's data.

The second half is identical everywhere, so it lives in the shared cores and
every backend gets the same answers. That is not tidiness. The rules that are
easy to get subtly wrong — a stale handle from a dead epoch, a destroy racing
work in flight, a candidate output published after a failure, a result dropped
under backpressure and mistaken for work that never ran — are exactly the
rules that are cheapest to test with no GPU present and most expensive to
debug with one.

| Layer | File | Owns |
|---|---|---|
| Wire | `sdk/wire/gpu_wire.rs` | Envelope, operations, handles, outcomes, capability and arithmetic facts |
| Programs | `sdk/cores/gpu_pack.rs` | Pack manifest, digests, binding declarations, device fit |
| Device | `sdk/cores/gpu_device.rs` | Admission, handle tables, views, sealing, residency, fences, output commit, epochs |
| Pump | `sdk/cores/gpu_pump.rs` | The provider loop: fault latching, chunk assembly, outcome staging, refusal |
| Client | `sdk/cores/gpu_client.rs` | The producer half: handle bookkeeping, correlation, outcome folding |
| Replay | `sdk/cores/gpu_replay.rs` | A deterministic backend with no device |

## 3. Providers

| Provider | Where | Backend | Advertises |
|---|---|---|---|
| `gpu_replay` | `modules/foundation/gpu_replay` | Byte arena, fixture transformation | compute, readback, device reset |
| `linux_gpu` | `src/platform/linux/gpu.rs` (`--features host-gpu`) | wgpu on Vulkan, headless | compute, raster, compute→raster, readback, device reset |
| `wasm_browser_compute` | `src/platform/wasm/gpu_compute.rs` | WebGPU, shared page device | compute, readback |

None of them advertises shared surfaces or preemption, because none implements
them. A capability record is worth nothing if it reports the union of what some
backend could manage.

`linux_gpu` advertises raster because it executes it: pipelines built from the
raster state descriptor below, passes with a colour and an optional depth
attachment, indexed and non-indexed draws, and texture readback in the packed
layout the resource accounting describes. It advertises `COMPUTE_TO_RASTER`
because one buffer carrying both `USAGE_STORAGE` and `USAGE_VERTEX` is one
device buffer with both usages, so a dispatch writes the geometry a later draw
reads with no CPU detour. It advertises `DEVICE_RESET` because the reset polls
the device to quiescence before destroying anything, and reclaims the old
epoch's memory only after that poll returns — which is a demonstration, where
recreating an adapter would have been a hope.

`gpu_replay` exists for two reasons. It is the correctness oracle every other
backend is held to — the same lifetime and fault corpus runs there with no
driver and no asynchronous callbacks, so a failure is a contract bug rather
than a hardware one. And it is a composition that builds on targets with no
GPU at all, so a consumer can develop and regression-test its request/result
lifecycle before any silicon exists. It runs no shaders: a `TARGET_REPLAY`
dispatch adds the program's identity constant to each byte it moves, which is
deterministic, order-sensitive and trivially mirrored by a CPU oracle.

## 4. The envelope

Every record — request and outcome alike — is a 16-byte header plus payload,
little-endian:

```text
  [0..2]   magic   u16  = 0x47F9
  [2..4]   op      u16  request op (< 0x8000) or outcome kind (>= 0x8000)
  [4..8]   len     u32  payload bytes, <= 64 KiB
  [8..16]  corr    u64  caller-chosen correlation, echoed on every outcome
```

The magic is a framing check, not a version. A port carries this contract
because the graph typed its edge `GpuCommand`; a header that fails the check
is a framing fault, and there is no other contract for it to have been.

There is deliberately no owner field. Authority comes from the granted
channel context the record arrived on; a caller-supplied owner number would be
a claim, not a grant.

64 KiB bounds one record. Larger transfers are a run of upload or readback
chunks against explicit offsets, which is what makes a step's work bounded.

## 5. Handles

A handle is opaque and meaningful only to the provider that issued it:

```text
  bits  0..16  index       slot in the provider's table
  bits 16..32  generation  bumped on retirement; never 0 when live
  bits 32..40  kind        buffer / texture / sampler / view / program / …
  bits 40..56  epoch       the device epoch it belongs to
  bits 56..64  reserved    must be zero
```

Copying the number to another process, worker or host is not access: ownership
is checked at every resolution, so a handle that reached another owner by any
route is refused. Cross-owner sharing is a grant — a view with narrower rights
over the same bytes — not a number someone passed on.

Two independent masks, because they answer different questions. **Usage** is a
property of the resource, fixed at creation: what the device was told to make
it capable of. **Rights** are a property of the handle: what this holder may
do with a resource that is already capable. Merging them would make "narrow
this grant" inexpressible.

## 6. Outcomes

Exactly one of these per request:

- `OUT_REJECTED` — terminal. Nothing was admitted; no caller-visible output
  changed, no fence was allocated, no resource was mutated.
- `OUT_ACCEPTED` — admitted, with a fence. Every admitted request gets one,
  including those that finish at admission, so there is one completion rule
  rather than a fast path and a slow path.

An accepted request then reaches exactly one terminal fence outcome inside the
live device epoch: `COMPLETED`, `FAILED`, `CANCELLED` or `DEVICE_LOST`. That
is a per-epoch guarantee over one channel, not a distributed exactly-once
claim.

Terminal outcomes are **retained** until the consumer acknowledges them with
`RELEASE_FENCE`. When the fence pool fills, new work is refused at admission —
results are never dropped to make room, because a dropped result is
indistinguishable from work that never ran.

## 7. Output commit

Accepted work may modify private candidate storage. A consumer cannot observe
it as a valid output until completion publishes it, and a failed or cancelled
request leaves its scratch exactly as unreadable as before it ran.

The rule has one careful exception. Work that *explicitly waits* on the fence
which publishes a candidate may read it: that wait is precisely how a
two-stage pipeline is expressed. Refusing it outright would make dependent
kernels impossible; allowing any reader would leak uncommitted bytes. So an
uncommitted candidate read by a submission must be covered by one of that
submission's declared waits, and readback, copy-source and presentation stay
under the strict rule.

## 8. Dependencies

A submission may only wait on fences that are already live, and its own fence
is allocated after its waits are validated. The wait graph is therefore a DAG
by construction, rather than by a cycle detector that has to be right.

Failure propagates: a fence whose dependency failed fails with
`DEPENDENCY_FAILED`; one whose dependency was cancelled is cancelled with the
`DEPENDENCY` disposition.

## 9. Programs

A pack is the only way an executable reaches a provider. It carries the
artifact plus the facts needed to refuse work the device cannot run: ISA and
revision, toolchain identity, entry point, binding declarations with access
and alignment, workgroup shape, feature and arithmetic requirements, and
memory budgets.

Three separate ideas, kept separate:

- **Artifact digest** — SHA-256 over the artifact bytes. Content identity.
- **Pack identity** — SHA-256 over the whole manifest. What a pipeline cache
  is keyed on, because two packs sharing artifact bytes but declaring
  different binding access are not interchangeable.
- **Trust** — neither. A digest proves the bytes are the bytes someone named;
  it proves nothing about what they do. Admission validates every command and
  binding independently, and a provider that cannot isolate GPU memory does
  not accept arbitrary native artifacts however well signed.

`fluxor gpu pack | inspect | validate | caps` build and check packs offline,
sharing the device's own decoder, so a pack the tool accepts is a pack that
provider accepts. `validate --caps` checks against a capability record the
device actually published, not against a hand-written description of it.

A raster pipeline's `[backend state…]` tail is the `RasterState` descriptor:
colour and depth format, vertex stride, topology, cull mode, front face,
blend, depth comparison and write, and up to sixteen vertex attributes. It is
allocated in the contract rather than per backend for the same reason the
`FORMAT_*` enumeration is — state each provider numbered for itself would make
the raster half unportable, and a consumer could not draw one scene through
two providers. Its decoder refuses what it can check: a depth format in the
colour slot, depth state with no attachment to honour it, an attribute running
past the stride, two attributes at one location, an unallocated format.

A depth attachment is pass-local. Nothing outside a pass names, binds, copies
or reads one back, so `PASS_DEPTH` asks the provider to supply one against the
target's extent instead of the handle table carrying it. A provider that
cannot refuses the flag rather than drawing with the depth test quietly
absent.

WGSL is the portable browser/Linux source path. SPIR-V is not accepted by any
provider here — it needs an exact-version validation story none of them has,
so it is refused rather than half-supported. A direct V3D provider would
accept only precompiled kernel packs and never shader text.

## 10. Arithmetic facts

Four independent questions about each numeric type, because conflating them is
the specific mistake the table exists to prevent:

| Bit | Question |
|---|---|
| `ARITH_STORAGE` | Can it be stored in and loaded from a buffer? |
| `ARITH_COMPUTE` | Is arithmetic on it available in a program? |
| `ARITH_ACCUM` | Can it accumulate without a widening detour? |
| `ARITH_NATIVE` | Is execution native, or an explicitly implemented emulation? |

A u8-packed buffer says nothing about whether the device can do i8
arithmetic. "Supported" says nothing about whether the support is silicon or a
shader emulating it — and a consumer that chose a program on a cost model
emulation invalidates needs to be able to refuse.

BF16, packed INT4 and ternary are listed so they can be **declared absent**,
which is the honest answer until a path exists. On a Pi 5's V3D 7.1, f16 is
declared absent too: the adapter does not report `shader-f16`, and advertising
it because some other Vulkan device has it is exactly the union-of-backends
claim this contract forbids.

## 11. Timing

GPU completion, output publication, present queued and actual display timing
are four different events. A completion carries `COMPLETED_QUEUE_TIMED`
whenever its timing came from conservative queue completion rather than a
per-submit GPU timestamp, and `gpu_nanos` is zero rather than filled with a
CPU submit-to-poll interval. Every provider here reports queue-timed
completions.

## 12. Presentation

Optional and independent. A compute-only graph builds and runs with no canvas,
display server, swapchain, compositor or input stack, and the absence is a
capability refusal rather than a runtime branch: `EXPORT_SURFACE` against a
provider without `FEATURE_SHARED_SURFACE` is rejected with the missing fact.

The `VideoScanout` descriptor carries provider and device epoch, the
authorised view, a producer fence a sink must wait on, extent, stride, format,
colour space, damage bounds, presentation sequence and time context. Its
`transfer` capability fact — `zero_copy`, `readback_copy` or `unproven` —
records what the hand-off actually costs; `unproven` is the honest default and
the only value a provider may declare before it has a measurement.

No provider here advertises `FEATURE_SHARED_SURFACE`. The descriptor and its
lease lifecycle exist and are tested; a sink that imports one does not.

## 13. Budgets

Four classes, kept apart because they bind for different reasons and a single
`MAX_GPU_*` number would hide which one a workload actually hit:

| Class | What binds |
|---|---|
| R1 | Memory bytes — resident, staging, scratch |
| R2 | Identifier and table widths — handles, fences, queue depth, record payload |
| R3 | Hardware limits — allocation size, bindings, alignment, workgroup and grid shape |
| R4 | Rate and deadline — the caller's step budget, not a ledger this contract keeps |

Residency is explicit and never transparent: resident, uploading, evictable,
retired or lost. An in-flight resource is never evicted, and a workload that
cannot fit is refused so the consumer can choose another declared profile.

## 14. Faults and recovery

Cancellation before dispatch releases the reservation; after dispatch it can
only suppress publication, and the disposition says which happened.
Cancellation cannot un-run a dispatch, and reporting otherwise would be a
promise no driver here can keep.

A drain completes on physical quiescence, never on an empty channel. A reset
terminates every outstanding request with `DEVICE_LOST`, bumps the device
epoch, invalidates every handle, fence, surface and pipeline-cache reference,
and only then reclaims memory — a timeout alone frees nothing. Reset is
advertised only where it has been demonstrated: `gpu_replay` clears a byte
arena, which is verified quiescence; the native and browser providers do not
claim it, because recreating an adapter is not a proof.

## 15. Composition

```text
producer ──GpuCommand──▶ provider ──GpuOutcome──▶ producer
```

`gpu.compute` and `gpu.render` carry three compose-time facts — `backend`,
`readback`, `shared_surface` — chosen because they decide whether a graph can
be built at all. The numeric capability record stays a runtime
answer to `QUERY_CAPS`; a compose-time copy of allocation limits and
per-type arithmetic would be a second source of truth that drifts.

## 16. What is not implemented

Named here so nothing above reads as more than it is.

- **Presentation sinks.** The contract carries surface leases and the device
  model validates them. No provider exports one.
- **Browser raster.** `linux_gpu` executes the raster half; the browser
  provider does not yet, so a consumer drawing through both needs the native
  one today.
- **Direct V3D.** Bare-metal V3D does not inherit Linux's GPU services.
  Selecting MMIO, interrupts, power/clock/reset, address translation and cache
  policy needs silicon evidence from pinned sources and a rig, and the kernel
  ABI for a GPU-visible arena is an open decision. There is no offline
  WGSL→QPU compiler, so there is no artifact to submit even if there were a
  driver.
- **HDMI and bare-metal display.** A separate tier, and separately gated:
  whether ARM can program a Pi 5's display directly rather than through
  firmware is a question to answer from board evidence and pinned sources, not
  from assertion.
- **SPIR-V ingestion, subgroups, indirect dispatch, preemption, dma-buf
  export.** No provider advertises any of them.

Compute acceptance does not wait for any of this, and a framebuffer is not GPU
acceleration.
