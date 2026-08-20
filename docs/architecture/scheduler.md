# Scheduler

Fluxor's scheduler partitions modules into execution tiers. Each tier
has a fixed execution discipline (cooperative, ISR-driven, polled) and
a fixed API surface (which syscalls are allowed from a module's step
body). The tier is declared on the domain that owns the module, except
for the per-module Tier 1c opt-in.

Source: `src/kernel/exec/scheduler/mod.rs`, `src/kernel/exec/isr_tier.rs`

## Tier surface

| Tier | Wire byte (`exec_mode`) | Execution context | Cycle budget | Allowed syscalls | Use cases |
|------|-------------------------|-------------------|--------------|------------------|-----------|
| **0** Cooperative | 0 | Main scheduler loop, 1 ms tick | per-module `step_deadline_us` | full (heap, `provider_call`, `channel_*`) | most modules |
| **1a** High-rate cooperative | 1 | Sub-ms timer-driven cooperative tick | per-module `step_deadline_us` | full | audio loops, control loops |
| **1b** Timer ISR | 2 | Polled-timer ISR (BCM2712: soft-polled from the scheduler thread; RP: real timer ISR) | `DEFAULT_ISR_BUDGET_CYCLES` (2000 cycles) | ISR-safe bridge ops only — see [ISR-tier I/O contract](#isr-tier-io-contract) | precise-cadence drivers |
| **1c** Pre-pass drain | (per-module flag on a Tier 0/1a domain) | Cooperative, called at the start of every pass before `domain_exec_order` | combined `MAX_PRE_TICK_BUDGET_US` (5 µs) | full (cooperative) | NIC RX/TX, ARP-table drains |
| **2** IRQ-owned | 4 | Per-IRQ ISR (dispatched via `isr_tier2_trampoline` bound through `hal::irq_bind`) | per-module budget | ISR-safe bridge ops only, from `module_isr_entry` | precise per-IRQ drivers |
| **3** Poll | 3 | Continuous spin with WFE on idle | per-pass `domain_budget_us_limit` | full | tight polling loops |

Wire-byte values are stable: changing the byte mapping would break
already-built `.cfg.bin` blobs, so a new tier always reserves a fresh
value rather than renumbering, which is why the tier ordering and the
byte ordering differ (`1b → 2`, `2 → 4`).

## Where tier is declared

YAML graphs declare tier on the domain:

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

Accepted tier spellings are `0`/`cooperative`, `1a`/`high_rate`,
`1b`/`isr_timer`, `2`/`isr_owned`, and `3`/`poll`; an unknown value is
a build error rather than a silent fall-through to Tier 0.

The build-time validators (`validate_isr_tier_admission` and
`validate_pre_tick_drain_admission` in `tools/src/config/builder.rs`)
reject misconfigurations: a module without `isr_safe = true` in its
manifest cannot land in a Tier 1b/2 domain; a module with
`pre_tick_drain = true` cannot land in a Tier 1b/2/3 domain. A Tier 2
(`isr_owned`) module additionally must declare an `irq:` field and
export `module_isr_entry` in its source — the IRQ dispatches into that
entry point, not the cooperative `module_step`, so a Tier 2 module
missing either is rejected at build time. The declared `irq:` is also
range-checked against the resolved silicon's interrupt controller
(GIC-400 lines 0..=1019 on BCM2712, NVIC lines 0..=31 on RP2040 and
0..=52 on RP2350); the platform `irq_bind` enforces the same bound as
a runtime backstop.

## Manifest attestations

Source: `tools/src/manifest.rs`

Two boolean fields, both author claims (no static enforcement beyond
a NEON-import lint for `isr_safe`):

```toml
# modules/drivers/<your_isr_module>/manifest.toml
isr_safe = true       # legal admission to a Tier 1b/2 domain
                      # author attests: no heap, no cooperative
                      # provider_call, no channel_read/write,
                      # bounded execution.

# modules/drivers/rp1_gem/manifest.toml
pre_tick_drain = true # opt into the Tier 1c pre-pass slot.
                      # cooperative-context constraints apply.
```

`isr_safe` is encoded in bit 2 of the manifest binary's flags byte;
`pre_tick_drain` rides bit 3. Both round-trip through the `.fmod`
file format.

`pre_tick_drain` is also mirrored into bit 4 of the config-blob
module-entry domain byte (alongside the domain id bits) so
`prepare_graph` can read it without re-parsing the `.fmod` manifest.

## ISR-tier I/O contract

Source: `modules/sdk/internal/bridge.rs`, `src/kernel/exec/isr_tier.rs`

ISR-tier modules (Tier 1b and Tier 2) communicate with cooperative
tiers exclusively via bridge rings:

- The kernel allocates bridge ring slots for every edge with an
  ISR-tier endpoint (`wire_isr_bridges`), and the cooperative side of
  those edges is drained between PIPE channel and bridge ring by
  `pump_isr_bridges` at the end of each scheduler pass. The pump is
  non-lossy in both directions: it does not drain the PIPE when the
  ring is full, and does not pop the ring when the PIPE is
  back-pressured.
- The bridge slot indices are populated into each ISR-tier module's
  `in_bridges` / `out_bridges` arrays at admission time.
- From inside the step body, a module discovers its own bridge
  endpoints with the `SELF_BRIDGES` op (`0x0C44`), which returns
  tagged bridge fds, and then moves data with the bridge ops
  `WRITE` (`0x0CE0`), `READ` (`0x0CE1`), `POLL` (`0x0CE2`), and
  `INFO` (`0x0CE3`). These five ops are exempt from the ISR-tier
  syscall deny because the underlying ring operations are lock-free
  and allocation-free; every other `provider_call` op is denied from
  ISR context. Up to `MAX_BRIDGES_PER_MODULE` (4) input and output
  endpoints per module.

Graph wiring restriction: the build-time validator rejects any YAML
wiring edge with an ISR-tier endpoint. ISR-tier modules exchange data
through kernel-wired bridges, not through declared graph edges; a
declared edge into an ISR-tier module would create a channel the ISR
side cannot legally service.

## Runtime gates

Source: `src/kernel/module/syscalls.rs`,
`src/kernel/exec/scheduler/multigraph.rs`

1. **Build-time admission.** `validate_isr_tier_admission` and
   `validate_pre_tick_drain_admission` reject ill-formed graphs before
   a `.cfg.bin` is emitted.
2. **Cooperative skip.** `step_one_module` returns early for any
   module whose domain `exec_mode` is Tier 1b/2 (the ISR dispatcher
   handles them instead). Tier 1c modules are partitioned into
   `domain_pre_tick_order` at graph-prepare time and run from the
   pre-tick loop, not from `domain_exec_order`.
3. **Runtime EACCES gate.** `deny_isr_tier_syscall` rejects every
   cooperative-only syscall from Tier 1b/2 modules with
   `errno::EACCES`, emitting `MON_PERM_DENIED domain=N mod=M
   op=<syscall>`. The deny surface:
   - **Channels:** `channel_open`, `channel_read`, `channel_write`,
     `channel_peek`, `channel_poll`.
   - **Providers:** `provider_open`, `provider_call`,
     `provider_call_sel`, `provider_query`, `provider_close`, with
     the ISR-safe bridge ops exempted as described above. The gate
     fires at the syscall wrapper (before permission/contract
     checks) so the EACCES path is reached before any other
     diagnostic.
   - **Heap:** `heap_alloc`, `heap_free`, `heap_realloc`. Gated at
     the wrapper so kernel-internal heap callers (which never set
     `current_module` to an ISR-tier slot) are unaffected.

   The build-time validator already rejects malformed graphs; the
   runtime gate is a second layer, and the ISR dispatcher sets
   `current_module` before each step so the gate fires correctly
   even for ISR-context syscalls.

## ISR-tier dispatch path

Source: `src/kernel/exec/isr_tier.rs`,
`src/kernel/exec/scheduler/setup.rs`,
`src/kernel/exec/scheduler/domain_budget.rs`

Tier 1b admission and dispatch:

1. **Build time.** `validate_isr_tier_admission` confirms every
   module in a Tier 1b domain has `isr_safe = true` and runs the
   NEON-import lint against the module's source tree. The wiring
   check rejects any YAML edge with an ISR-tier endpoint (see the
   I/O contract above).
2. **`prepare_graph`.** Stores per-module domain and
   `pre_tick_drain` into the scheduler state. The cooperative
   scheduler skips Tier 1b/2 modules from `domain_exec_order` walks
   via the runtime check in `step_one_module`.
3. **Platform instantiation.** After every module is instantiated,
   the platform calls `register_isr_tier_modules_from_graph`. The
   helper walks every module slot, picks the appropriate
   `(step_fn, state_ptr)` pair (direct for `DynamicModule`, via a
   trampoline for built-ins), and calls
   `isr_tier::register_tier1b_module` per entry.
4. **Timer arming.** If at least one Tier 1b module registered, the
   helper computes the minimum tick interval across all Tier 1b
   domains and calls `isr_tier::start_tier1b(period_us)`. On BCM2712
   this stores the period and arms the architected counter;
   `bcm_isr_tier_poll` (polled from the scheduler thread) fires
   `isr_tier1b_handler` whenever the elapsed counter passes the
   period.
5. **Run loop.** The BCM2712 `run_domain_loop` Tier 1b arm
   (`exec_mode == 2`) iterates core parking checks,
   `isr_tier::poll_tier1b()`, `pump_cross_domain`, and WFE. The
   Tier 0 arm also calls `isr_tier::poll_tier1b()` on every loop
   iteration so configurations sharing a core between cooperative
   and Tier 1b work still fire the ISR handler.
6. **ISR dispatch.** `isr_tier1b_handler` walks the ISR slot table,
   sets the current-module pointer to the slot's module index,
   invokes the registered `step_fn(state_ptr)`, records cycle
   metrics, and restores the saved current-module pointer on exit.
   Rebuilding the graph clears the ISR slot table.

Tier 2 (IRQ-owned) admission and dispatch:

- The PIC loader extracts the `.fmod`'s `module_isr_entry` export
  into the module's exports; the Tier 2 admission branch in
  `register_isr_tier_modules_from_graph` forwards that pointer to
  `register_tier2_module` and refuses a dynamic module that exported
  no ISR entry, rather than dispatching its cooperative
  `module_step` from IRQ context.
- The scheduler binds the module's declared IRQ through
  `hal::irq_bind`, including the owning domain's core as the IRQ
  target so a dedicated Tier 2 core receives its own interrupts.
  The hardware IRQ dispatches into `isr_tier2_trampoline`, which
  looks the module up by IRQ number and invokes `module_isr_entry`.
- A Tier 2 domain that owns its own core runs the dedicated
  `run_domain_loop` arm for `exec_mode == 4`: cross-domain pumping
  plus WFI, with dispatch driven entirely by the hardware IRQ.
- Tier 2 module state is built through the normal cooperative
  `module_new` at instantiation time (non-ISR context), the same
  construction path Tier 1b uses. `module_isr_init` is a reserved
  ABI symbol: the packer detects it and the loader defines its
  type, but nothing calls it. Status: design target, not wired.

Tier 1c pre-pass dispatch:

1. Exec-order computation reads each module's `pre_tick_drain` flag
   and routes the module into `domain_pre_tick_order[d]` instead of
   `domain_exec_order[d]`.
2. `step_domain_modules` and `step_modules` invoke
   `step_domain_pre_tick` before the regular `exec_order` rotation.
   The helper snapshot-restores the domain budget accumulator so
   pre-tick cost does not leak into the regular per-domain budget
   accounting.
3. If the combined pre-tick budget (`MAX_PRE_TICK_BUDGET_US`, 5 µs)
   is exceeded, the helper emits `MON_PRE_TICK_OVERRUN`, bumps
   `domain_pre_tick_overruns[d]`, and stops iterating; remaining
   pre-tick modules wait until the next pass. The regular
   `exec_order` rotation continues uninterrupted — an overrun does
   not abort the pass, and pre-tick stepping recovers on the next
   pass.

## Behavioural invariants

- Tier 0 cooperative stepping honours per-module period gating, the
  fault state machine, and `Done` finalisation.
- Domains are stepped in isolation: a module only ever runs from its
  own domain's exec order (or pre-tick order).
- A per-domain budget overrun rotates `exec_order_offset` so the same
  head-of-order modules cannot persistently starve the tail.
- Pre-tick budget accounting is isolated from the regular per-domain
  accumulator, and a pre-tick overrun in one pass does not suppress
  pre-tick stepping in later passes.
- Per-module `isr_budget_cycles` overrides flow through to the ISR
  metrics; an ISR-tier module error does not poison cooperative
  scheduler state.
- Pre-tick modules beyond the per-domain capacity are dropped from
  the pre-tick order without a panic; an ISR-tier module with no
  step function is skipped cleanly.
