# Scheduler

Fluxor's scheduler partitions modules into **execution tiers**. Each
tier has fixed execution discipline (cooperative, ISR-driven, polled)
and a fixed API surface (which syscalls are allowed from a module's
step body). The tier is declared on the **domain** that owns the
module — except for the per-module Tier 1c opt-in. See
[../../.context/rfc_isr_tier_surface.md](../../.context/rfc_isr_tier_surface.md)
for the design rationale.

## Tier surface

| Tier | Wire byte (`exec_mode`) | Execution context | Cycle budget | Allowed syscalls | Use cases |
|------|-------------------------|-------------------|--------------|------------------|-----------|
| **0** Cooperative | 0 | Main scheduler loop, 1 ms tick | per-module `step_deadline_us` (default 1 ms) | full (heap, `provider_call`, `channel_*`) | most modules |
| **1a** High-rate cooperative | 1 | Sub-ms timer-driven cooperative tick | per-module `step_deadline_us` | full | audio loops, control loops |
| **1b** Timer ISR | 2 | Polled-timer ISR (BCM2712: soft-polled from scheduler thread; RP: real timer ISR) | `DEFAULT_ISR_BUDGET_CYCLES` (2000 cy ≈ 1 µs on Cortex-A76) | **none from the step body in v1** — see "ISR-tier I/O contract" below | precise-cadence drivers; v1 step bodies do private-state work only |
| **1c** Pre-pass drain | (per-module flag on a Tier 0/1a domain) | Cooperative, called at start of every pass before `domain_exec_order` | combined `MAX_PRE_TICK_BUDGET_US = 5` µs | full (cooperative) | NIC RX/TX, ARP-table drains |
| **2** IRQ-owned | 4 | Per-IRQ ISR (dispatched via `isr_tier2_trampoline` bound through `hal::irq_bind`) | per-module budget | **none from the `module_isr_entry` body in v1** — same bridge-ABI gap as Tier 1b | precise per-IRQ drivers. **Admission landed 2026-06-16**: module must declare `isr_safe = true`, an `irq:` field, and export `module_isr_entry` (the loader extracts it into `isr_entry_fn`; the IRQ dispatches into it, not the cooperative `module_step`) |
| **3** Poll | 3 | Continuous spin with WFE on idle | per-pass `domain_budget_us_limit` | full | tight polling loops |

Wire-byte values are stable: changing the byte mapping would break
already-built `.cfg.bin` blobs. Adding a new tier reserves a fresh
value — the asymmetric ordering (`1b → 2`, `2 → 4`) is a historical
artefact of when each tier landed.

## Where tier is declared

YAML graphs declare tier on the **domain**:

```yaml
execution:
  domains:
    - name: main
      tier: 0          # default
      tick_us: 1000
    - name: audio_isr
      tier: 1b
      tick_us: 23      # ~44.1 kHz timer
modules:
  - name: sample_driver
    type: my_isr_driver        # author-supplied PIC module with
                               # `isr_safe = true` in its manifest
    domain: audio_isr
  - name: nic
    type: rp1_gem
    domain: main
    # `pre_tick_drain = true` is on the module's manifest;
    # no YAML flag needed.
```

The build-time validator
([tools/src/config.rs::validate_isr_tier_admission](../../tools/src/config.rs)
+ [`validate_pre_tick_drain_admission`](../../tools/src/config.rs))
rejects misconfigurations: a module without `isr_safe = true` in its
manifest can't land in a Tier 1b/2 domain; a module with
`pre_tick_drain = true` can't land in a Tier 1b/2/3 domain. A Tier 2
(`isr_owned`) module additionally must declare an `irq:` field and
export `module_isr_entry` in its source — the IRQ dispatches into that
entry point, not the cooperative `module_step`, so a Tier 2 module
missing either is rejected at build time.

## Manifest attestations

Two boolean fields, both author claims (no static enforcement beyond
a NEON-import lint for `isr_safe`):

```toml
# modules/drivers/<your_isr_module>/manifest.toml
isr_safe = true       # legal admission to Tier 1b/2 domain
                      # author attests: no heap, no provider_call,
                      # no channel_read/write, bounded execution.

# modules/drivers/rp1_gem/manifest.toml
pre_tick_drain = true # opt into the Tier 1c pre-pass slot.
                      # cooperative-context constraints apply.
```

The `isr_safe` flag is encoded in bit 2 of the manifest binary's
flags byte; `pre_tick_drain` rides bit 3. Both round-trip through
the `.fmod` file format without a version bump.

The `pre_tick_drain` flag is *also* mirrored into bit 4 of the
config-blob module-entry byte 9 (alongside the 3-bit `domain_id`)
so `prepare_graph` can read it without re-parsing the .fmod
manifest.

## ISR-tier I/O contract (Tier 1b)

The RFC §D7 contract says Tier 1b modules "communicate exclusively
via bridge channels." In v1 of this implementation:

- The kernel allocates bridge ring slots for every edge with an
  ISR-tier endpoint (`scheduler::wire_isr_bridges`), and the
  cooperative side of those edges is drained between PIPE channel
  and bridge ring by `scheduler::pump_isr_bridges` at the end of
  each scheduler pass.
- The bridge slot indices are populated into each Tier 1b module's
  `in_bridges` / `out_bridges` arrays at admission time
  (`scheduler::register_isr_tier_modules_from_graph` →
  `isr_tier::register_tier1b_module`).
- **But there is currently no module-facing ABI to read those slot
  indices from inside the ISR step body.** The kernel-internal
  `bridge_get(slot)` API works (test fixtures use it directly), but
  no PIC SDK helper surfaces it without going through
  `provider_call` — and the runtime gate denies `provider_call` from
  ISR-tier callers per the §D7 contract.

**What this means for v1 ISR step bodies:**
- A Tier 1b module's `module_step` cannot read from its bridges or
  push to its out-bridges through any documented PIC SDK call.
- All I/O between Tier 1b and Tier 0/1a flows through the kernel's
  `pump_isr_bridges` drain (cooperative producer → PIPE → ring →
  ISR consumer; ISR producer → ring → PIPE → cooperative consumer)
  — but the ISR side of that drain happens *outside* the step
  body. The step body sees only its own private state.
- This is enough to admit and dispatch Tier 1b modules whose work
  is private-state-only (counters, hardware register reads via
  inline asm, etc.), but not enough to write a real PWM driver
  that needs to receive duty-cycle updates from a Tier 0 partner.

**Next-step design (out of RFC scope):** extend the kernel/loader
to either (a) pass `in_bridges`/`out_bridges` slot indices to the
module's `module_isr_init` at admission time, or (b) carve a
narrow ISR-safe allow-list in the syscall gate for the bridge
opcodes specifically (`WRITE = 0x0CE0`, `READ = 0x0CE1`,
`POLL = 0x0CE2`, `INFO = 0x0CE3` — see
[`modules/sdk/internal/bridge.rs`](../../modules/sdk/internal/bridge.rs)).
Either path closes the gap; the test-fixture path in
[`scheduler_isr_bridges.rs`](../../tests/harness/tests/scheduler_isr_bridges.rs)
proves the bridge data-flow is wired correctly end-to-end on the
kernel side — only the module-facing API is missing.

## Runtime gates

1. **Build-time admission** —
   [`validate_isr_tier_admission`](../../tools/src/config.rs) +
   [`validate_pre_tick_drain_admission`](../../tools/src/config.rs)
   reject ill-formed graphs before a `.cfg.bin` is emitted.
2. **Cooperative skip** —
   [`step_one_module`](../../src/kernel/scheduler/mod.rs) returns early
   for any module whose domain `exec_mode` is Tier 1b/2 (the ISR
   dispatcher handles them instead). Tier 1c modules are partitioned
   into `domain_pre_tick_order` at graph-prepare time and run from
   the pre-tick loop, not from `domain_exec_order`.
3. **Runtime EACCES gate** —
   [`scheduler::deny_isr_tier_syscall`](../../src/kernel/scheduler/mod.rs)
   rejects every cooperative-only syscall from Tier 1b/2 modules
   with `errno::EACCES`, emitting `MON_PERM_DENIED domain=N mod=M
   op=<syscall>`. The full deny surface:
   - **Channels:** `channel_open`, `channel_read`, `channel_write`,
     `channel_peek`, `channel_poll`.
   - **Providers:** `provider_open`, `provider_call`,
     `provider_query`, `provider_close`. The gate fires at the
     syscall wrapper (before permission/contract checks) so the
     EACCES path is reached before any other diagnostic.
   - **Heap:** `heap_alloc`, `heap_free`, `heap_realloc`. Gated at
     the wrapper so kernel-internal heap callers (which never set
     `current_module` into an ISR-tier slot) are unaffected.

   This is defense in depth — the build-time validator already
   rejects malformed graphs, and the ISR dispatcher sets
   `current_module` before each step so the gate fires correctly
   even for ISR-context syscalls.

## ISR-tier dispatch path

Tier 1b admission:

1. **Build time.** `validate_isr_tier_admission` confirms every
   module in a Tier 1b domain has `isr_safe = true` and runs the
   NEON-import lint against the module's source tree (resolved
   via the same `standard_module_dirs()` + caller-supplied extras
   the manifest loader walks). The wiring check rejects **any**
   YAML edge with an ISR-tier endpoint — regardless of
   `edge_class` — because PIC modules in v1 have no module-facing
   API to read their bridge slot indices from inside
   `module_step` (see "ISR-tier I/O contract" above).
2. **`prepare_graph`.** Stores per-module domain + `pre_tick_drain`
   into `SCHED`. The cooperative scheduler skips Tier 1b/2 modules
   from `domain_exec_order` walks via the runtime check in
   `step_one_module`.
3. **Platform instantiation.** After `instantiate_one_module` runs
   for every entry, the platform calls
   [`scheduler::register_isr_tier_modules_from_graph`](../../src/kernel/scheduler/mod.rs).
   The helper walks every module slot, picks the appropriate
   `(step_fn, state_ptr)` pair (direct for `DynamicModule`, via a
   trampoline for `BuiltInModule`), and calls
   `isr_tier::register_tier1b_module` per entry.
4. **Timer arming.** If at least one Tier 1b module registered,
   the helper computes the minimum tick interval across all
   Tier 1b domains and calls `isr_tier::start_tier1b(period_us)`.
   On BCM2712 this stores the period and arms the architected
   counter; `bcm_isr_tier_poll` (polled from the scheduler thread)
   fires `isr_tier1b_handler` whenever the elapsed counter passes
   the period.
5. **Run loop.** The BCM `run_domain_loop` Tier 1b arm
   (`exec_mode == 2`) iterates `multicore::park_if_requested` +
   `isr_tier::poll_tier1b()` + `pump_cross_domain` + `WFE`. The
   Tier 0 arm also calls `isr_tier::poll_tier1b()` on every loop
   iteration so configurations sharing a core between cooperative
   and Tier 1b work still fire the ISR handler.
6. **ISR dispatch.** `isr_tier1b_handler` walks `ISR_SLOTS`, sets
   `scheduler::current_module` to the slot's `module_index`,
   invokes the registered `step_fn(state_ptr)`, records cycle
   metrics, and restores the saved current-module pointer on exit.

Tier 1c pre-pass dispatch:

1. `compute_domain_exec_orders_static` reads
   `sched.pre_tick_drain[module_idx]` and routes the module into
   `domain_pre_tick_order[d]` instead of `domain_exec_order[d]`.
2. `step_domain_modules` and `step_modules` invoke
   [`step_domain_pre_tick`](../../src/kernel/scheduler/mod.rs)
   *before* the regular `exec_order` rotation. The helper
   snapshot-restores `domain_budget_us_consumed` so pre-tick cost
   doesn't leak into the regular per-domain budget accounting.
3. If the combined pre-tick budget (`MAX_PRE_TICK_BUDGET_US = 5`
   µs) is exceeded, the helper emits `MON_PRE_TICK_OVERRUN`,
   bumps `domain_pre_tick_overruns[d]`, and stops iterating —
   remaining pre-tick modules wait until the next pass. The
   regular exec_order rotation continues uninterrupted (overrun
   does NOT abort the pass).

## Behavioural invariants pinned by tests

Conformance tests in [`tests/harness/tests/`](../../tests/harness/tests):

- **`scheduler_conformance.rs`** — Tier 0 cooperative basics
  (period gating, fault state machine, Done finalisation).
- **`scheduler_domain_conformance.rs`** — multi-domain partitioning,
  per-domain stepping isolation.
- **`scheduler_starvation_rotation.rs`** — per-domain budget overrun
  rotates `exec_order_offset` to prevent persistent starvation.
- **`scheduler_pre_tick_slot.rs`** (Tier 1c, 7 tests) —
  pre-tick partitioning, pre-tick-runs-before-exec_order ordering,
  budget overrun stops iteration without aborting the rest of the
  pass, budget isolation from the regular per-domain accumulator,
  pre-tick recovery after a previous overrun pass.
- **`scheduler_isr_tier_admission.rs`** (Tier 1b, 26 tests) —
  every gated §D7 syscall returns EACCES (channels: open / read /
  write / peek / poll), providers: open / call / query / close,
  heap_alloc / heap_realloc return null + heap_free is a no-op;
  cooperative callers not blocked, `module_is_isr_tier` exec_mode
  mapping, end-to-end admission via
  `register_isr_tier_modules_from_graph`, ISR dispatcher invokes
  the registered module only (not the cooperative sibling),
  `current_module` is set inside the handler so the gate fires
  correctly.
- **`scheduler_isr_bridges.rs`** (Tier 1b ↔ cooperative data flow,
  7 tests) — `wire_isr_bridges` allocates a ring slot per
  ISR-tier edge, `pump_isr_bridges` shuttles bytes cooperative →
  ISR (PIPE drain → ring push) and ISR → cooperative (ring pop →
  PIPE write), `register_isr_tier_modules_from_graph` populates
  per-module `in_bridges`/`out_bridges`, per-module
  `isr_budget_cycles` overrides flow through to
  `IsrMetrics::budget_cycles`, non-lossy backpressure (pump
  doesn't drain PIPE when the ring is full; doesn't pop the ring
  when the PIPE is back-pressured).
- **`scheduler_tier_differentiation.rs`** (cross-tier behaviour,
  8 tests) — Tier 0 + Tier 1c share a domain but pre-tick runs
  first, Tier 0 + Tier 1b diverge on dispatch path, Tier 2 fires
  on IRQ match (not periodic), all tiers coexist with per-tier
  dispatch paths, pre-tick overflow beyond
  `MAX_PRE_TICK_PER_DOMAIN` is dropped without panic, Tier 1b
  error doesn't poison cooperative state, graph rebuild clears
  ISR slot table, ISR-tier module with no step fn is skipped
  cleanly.

## What's not yet wired

- **Tier 2 (per-IRQ ISR)** admission is **wired as of 2026-06-16**.
  The PIC loader extracts the `.fmod`'s `module_isr_entry` export
  into `ModuleExports::isr_entry_fn` / `DynamicModule::isr_entry_fn()`
  ([`loader::lookup_exports`](../../src/kernel/loader.rs)); the Tier 2
  admission branch in
  [`register_isr_tier_modules_from_graph`](../../src/kernel/scheduler/mod.rs)
  forwards that pointer to `register_tier2_module` and refuses a
  Dynamic module that exported no ISR entry (rather than dispatching
  its cooperative `module_step` from IRQ context). The build-time
  validator was lifted from a hard-reject to admit-with-checks
  (`isr_safe = true` + `irq:` + `module_isr_entry` export). The
  wire-format byte (`exec_mode == 4`), YAML `irq:` field (TLV tag
  0xFC), `register_tier2_module`, `isr_tier2_trampoline`, and the
  `hal::irq_bind` hook were already in place. Exercised by a real
  module-pack loader test (`tests/harness/tests/kernel_loader_isr_entry.rs`)
  plus Dynamic-module admission + IRQ-dispatch tests in
  `tests/harness/tests/scheduler_isr_tier_admission.rs` — **these are
  local-only harness tests; `/tests/` is gitignored by repo policy, so
  they are not committed regression coverage**. The committed
  build-time coverage lives in the `fluxor-tools` unit/bin tests
  (`tools/src/manifest.rs`, `tools/src/config.rs`).
  **Still platform TODO:** a dedicated-core `run_domain_loop` WFI arm
  for `exec_mode == 4` (Tier 2 dispatch fires from the hardware IRQ
  trampoline, so this matters only when a Tier 2 domain owns its own
  physical core).
  - **`module_isr_init` is a reserved, unwired ABI symbol.** The
    packer detects it and the loader defines `ModuleIsrInitFn`, but
    `Tier2Registration` carries no init pointer and nothing calls it.
    Tier 2 state is built through the normal cooperative `module_new`
    at instantiation (non-ISR context), the same trusted-construction
    path Tier 1b uses — so the v1 Tier 2 contract is **`module_isr_entry`
    only**. A dedicated ISR-context init hook is a later addition if a
    driver needs ISR-time state setup distinct from `module_new`.
- **Module-facing bridge ABI for ISR step bodies.** See the
  "ISR-tier I/O contract" section above — the kernel-side bridge
  wiring is sound, but PIC modules have no documented way to read
  their own bridge slot indices from inside `module_step`. v1
  Tier 1b step bodies do private-state work only.
- **A real Tier 1b PIC driver in-tree.** The infrastructure is
  verified end-to-end via `BuiltInModule` fixtures in
  `scheduler_isr_bridges.rs` and `scheduler_tier_differentiation.rs`
  — every Tier 1b admission, dispatch, and bridge path is
  exercised. But no shipping driver currently registers via the
  Tier 1b path; the first real consumer will need the
  module-facing bridge ABI above before useful I/O is possible.
