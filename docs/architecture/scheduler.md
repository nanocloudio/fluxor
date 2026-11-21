# Scheduler

Fluxor's scheduler runs every module in an execution domain, and every
domain has one execution mode. The mode fixes the domain's execution
discipline (cooperative pass, fixed-cadence interrupt contract, per-IRQ
dispatch) and its API surface (which syscalls a module's step body may
make). The mode is declared on the domain that owns the module; the one
per-module scheduling attribute is the pre-pass.

Source: `src/kernel/exec/scheduler/mod.rs`, `src/kernel/exec/interrupt.rs`,
`src/kernel/exec/timer.rs`, `src/kernel/exec/irq.rs`

## Execution modes

The modes form two families. The **cooperative** family (`tick`, `poll`)
gets the full syscall surface. The **interrupt** family (`timer`, `irq`)
is bridge-only, and admission requires the module's `interrupt_safe`
attestation.

| Mode (domain `exec:`, wire byte) | Family | Execution context | Cycle budget | Budget enforcement | Allowed syscalls | Use cases |
|------|--------|-------------------|--------------|--------------------|------------------|-----------|
| `tick` (0) | cooperative | The domain loop, one tick pass per tick: the graph's tick, or the domain's own `tick_us` (sub-ms for audio and control loops) | per-module `step_deadline_us` | Overrun is detected by the step guard, never pre-empted — see [Deadline enforcement](#deadline-enforcement) | full (heap, `provider_call`, `channel_*`) | most modules, audio loops, control loops |
| `poll` (1) | cooperative | The domain loop, passes back to back, WFE on idle | per-pass `domain_budget_us_limit` | The budget is checked between modules, rotating the domain's `exec_offset` rather than interrupting a step | full | tight polling loops |
| `timer` (2) | interrupt | Stepped at the domain's `rate_hz` under the interrupt contract (RP: a hardware alarm ISR; BCM2712: polled from the domain loop) | `DEFAULT_ISR_BUDGET_CYCLES`, the chip's (2000 counts of its cycle counter) | A step runs to completion; an overrun is counted in the interrupt metrics and, unless the module's policy is `Tolerate`, is a timeout fault — see [Interrupt-mode faults](#interrupt-mode-faults) | bridge ops only — see [Interrupt-mode I/O contract](#interrupt-mode-io-contract) | precise-cadence drivers |
| `irq` (3) | interrupt | Per-IRQ dispatch (`irq::irq_trampoline`, bound through `hal::irq_bind`) | per-module budget | As `timer` | bridge ops only, from `module_isr_entry` | precise per-IRQ drivers |

**Pre-pass** is a module attribute, not a mode: a module whose manifest
sets `pre_pass = true` runs at the start of every tick pass of its domain,
before the domain's exec order. It is legal only in a `tick` domain. At
most `MAX_PRE_PASS_PER_DOMAIN` modules per domain take it, and together
they share `tick_us / PRE_PASS_BUDGET_SHARE` (5 µs of a 100 µs tick); past
that budget the pre-pass stops after the overrunning module returns and the
rest wait for the next pass. The context is cooperative, with the full
syscall surface. Use cases: NIC RX/TX and ARP-table drains.

The wire byte is the boot-config domain record's `exec_mode`, the dense
`ExecMode` enum (`fluxor_contracts::boot_config::ExecMode`: `Tick` 0,
`Poll` 1, `Timer` 2, `Irq` 3); the decoder refuses any other value. Cadence
is a domain property: `tick_us` for a `tick` domain, `rate_hz` for a
`timer` domain. There is one tick loop: a `tick` domain on the graph's
tick and one with its own `tick_us` run the same domain loop, and every
`tick` domain keeps the worst-step and slow-pass metrics.

## Passes

Source: `src/kernel/exec/scheduler/pass.rs`,
`src/kernel/exec/scheduler/pacer.rs`,
`src/kernel/exec/scheduler/multigraph.rs`

One pass engine steps every cooperative domain on every target:
`pass::run(domain, kind)` runs either a tick pass (`PassKind::Tick`) or a
wake pass over latched wake bits (`PassKind::Wake(&mask)`), and returns
`PassResult { result, deadline_us, burst }`. A single-core loop (RP, Linux,
WASM) runs every domain in order through `pass::tick_all()` and
`pass::wake_all()`; a domain loop on its own core calls `pass::run` for
its one domain and takes only its own wakes (`pass::take_domain_wakes`).
A graph steps the same way whether it is the only resident graph or one
of many, admitted at boot or live: the node's graph takes the live add's
path (`prepare_graph` stages it through `splice::admit_boot`;
`instantiate_graph` runs `splice::instantiate_batch` and `splice::finish`),
`finish` splices each module into its domain's order and rebuilds the
resident-graph index on every target, and the pass walks that index.
There is no flat order: each domain holds the composer's order projected
onto it, appended to by an add and compacted by a free.

A tick pass, in order:

1. bumps the domain's pass count (`pass_count(domain)`, the domain's clock
   for fault records and monitor lines), drains the interrupt-mode fault
   latch (see [Interrupt-mode faults](#interrupt-mode-faults)) and enforces the drain
   ceiling;
2. walks the modules once for the active count and the not-ready and
   must-tick sets, and (domain 0) runs the readiness starvation sweep;
3. resets the domain budget, decays the worst-step figure, and resets the
   per-pass attribution;
4. runs the pre-pass once;
5. for each resident graph of the domain: its pause, its wakes, whether it
   is runnable, then the bounded multi-pass over the domain's exec order
   filtered to that graph;
6. runs the post-tick flush, the bridge pump, the lend pump and the slack
   donation;
7. merges the graphs' pacer deadlines into the domain's sleep, bounded by
   the domain's armed timers (`settle_deadline`).

A wake pass is step 5 for the woken modules alone, each once, with the
domain's budget deferring what does not fit.

A module with `step_period > 1` steps on a wall-clock due of
`step_period × the domain's nominal tick`; its `step_phase` staggers the first
due, and the due moves on only when the module actually steps. An event
wake bypasses the period gate.

Each resident `(graph, domain)` has one `Pacer`. It reads the signals of
the pass that just stepped its graph (work, a burst, a wake) and picks the
graph's next deadline under the domain's adaptive flags and
`PacerBounds`; `DeadlineMerge` folds a domain's pacers into the one sleep
the pass returns.

## Deadline enforcement

Source: `src/kernel/exec/step_guard.rs`,
`src/kernel/exec/scheduler/pass.rs`,
`src/kernel/exec/scheduler/fault.rs`

The per-module step deadline is a detection threshold, not a
pre-emption mechanism. Before each `module_step()` the scheduler arms
the step guard with the module's `effective_deadline_us()` (its
declared `step_deadline_us`, or `DEFAULT_STEP_DEADLINE_US`, 2 ms, when
it declares none) and disarms it on return. No target takes the
processor back from an ungated module that has already exceeded its
deadline; what differs between targets is only how promptly the
overrun is noticed. A gated (`contained` or `isolated`) module is the
exception: it is forced out at its deadline and faulted, by PendSV from the
same alarm on RP and by a lower-EL interrupt on BCM2712 (see
[module_isolation.md](module_isolation.md#liveness)).

| Target | Guard mechanism | Overrun observed |
|--------|-----------------|------------------|
| RP2350, RP2040 | One-shot hardware alarm (TIMER1 alarm 0, TIMER alarm 3) whose ISR sets a per-core timeout flag | At the deadline, while the step is still running |
| BCM2712 (AArch64) | Advisory elapsed-time comparison against `CNTPCT_EL0`, evaluated in the post-step check | After the step returns |
| Linux host | None; the guard entry points are no-ops | Never observed |
| WASM host | None; the guard entry points are no-ops | Never observed |

On the RP family the alarm ISR records the overrun and disables the
alarm, then returns to the interrupted module, which keeps running
until it returns of its own accord; nothing rewrites a stacked return
address to force it out. The one
place the early flag changes scheduling is a `Burst` re-step loop: the
loop tests the flag between iterations, so a module that overruns its
burst deadline (its declared `step_deadline_burst_us`, or
`step_deadline_us * BURST_MULTIPLIER`) stops re-stepping at the next
iteration boundary rather than at the end of the loop.

Once the scheduler observes the flag it calls the one fault handler,
`fault(FaultKind::Timeout)`, which records the fault against the module (fault counter, a `[guard]`
warning, and a `MON_FAULT` record in the fault ring) and then applies
the module's `FaultPolicy`:

- `Tolerate` records the overrun and nothing else; the module keeps
  running. This is the policy for modules whose synchronous device
  operations carry a legitimate heavy tail, such as a storage module
  stalled behind a device cache flush.
- `Restart`, while the module is below `max_restarts`, moves it to
  `Faulted` and holds it out of the pass until a wall-clock
  `restart_not_before_ms`: `restart_backoff_ms` doubled per restart
  already taken (capped at 2^8).
- Otherwise the module moves to `Terminated`, is finalised, and leaves
  the active set; a declared `quarantine_partner` that also faulted
  inside the quarantine window is terminated with it.

Every fault window is wall-clock, never a count of passes, so it holds
under the adaptive tick and while a domain idles: the restart backoff,
the quarantine window, the 4 ms cascade window that attributes a
downstream fault to an upstream one (`caused_by`), and the drain ceiling
(`MAX_DRAIN_MS`) on a reconfigure.

The practical consequence for timing claims: a deadline that produces
a prompt fault record on RP silicon is inert on the Linux and WASM
hosts, where the guard never fires. Deadline behaviour observed on a
host does not carry over to the embedded targets, and on no target
does the deadline bound the duration of a single step.

## Workload step budgets

Source: `src/kernel/exec/scheduler/live.rs` (`StepBudget`,
`admit_step_budget`), `tools/src/add_subgraph.rs`,
`tools/src/config/builder.rs` (`workload_step_budget`)

A module in a workload declares `step_deadline_us`,
`step_deadline_burst_us` and `fault_policy` with the same YAML keys and
the same value checks as a node-graph module:

```yaml
workloads:
  - name: kv
    modules:
      - name: kv_state_worker
        type: kv_state_worker
        step_deadline_us: 12000
        step_deadline_burst_us: 16000
        fault_policy: skip
```

`fluxor build --emit=workload` (and every module of a node graph's config,
its resident `workloads:` included) carries them in the module's record of the
composed graph (`fluxor_contracts::graph`), not in its params:

```text
module  entry_len u16 | flags u8 | domain u8 | name_hash u32
        | step_deadline_us u32 | burst_us u32 | fault_policy u8 | 0 u8 | 0 u8 | 0 u8
        | params [entry_len - 20]
```

All fields are little-endian. A deadline of `0` is the node's default
(`DEFAULT_STEP_DEADLINE_US`), a burst of `0` is `step_deadline_us ×
BURST_MULTIPLIER`, and the policy byte is `FaultPolicy`'s (0 skip,
1 restart, 2 tolerate). A policy byte outside that set fails the decode
with `EINVAL`. `fault_policy: restart_graph` names no policy, and the build
refuses it: a module's fault is its own.

The kernel admits a workload's budgets against its own node policy before
it allocates anything, and refuses the whole add with `ERANGE` rather than
clamping, as the build refuses an over-ceiling node graph:

- `fault_policy` must be `skip`, the one policy whose effect stays on the
  faulting module. `tolerate` records an overrun and lets the module run
  on, so the deadline it was admitted under would never bind it and the
  domain's other modules would pay for every late step; `restart` releases
  the module's provider layers and flushes its channels, which other
  owners may hold.
- When a deadline is declared, the step deadline and the effective burst
  deadline must each fit `16 ×` the domain's shortest tick (its
  `tick_min_us` on an adaptive-cadence domain, else its tick), and never
  more than 100 ms. The node's ticks are the ones that count, not those the
  image was built against. A module that declares neither deadline runs on
  the node's defaults and is not checked against this ceiling.

The admitted budget is put on the module's fault record before it
instantiates. The record starts empty, so a reused slot keeps nothing from
its last occupant. For a live-added module the module record is the only
source of its deadline and fault policy. The build rejects the same things
first (`workload_step_budget`), so an image that builds is one a node with
the same domain ticks will admit.

### Node tags in a workload's params

The node graph's builder adds tags to a module's params TLV that grant the
module something of the node's. A module in a workload belongs to its
workload's owner, not the node owner, so the add refuses its params with `EACCES`, before anything is allocated, if the
TLV carries any of these node tags (`scheduler::is_node_param_tag`):

| Tag | Setting | Why a workload cannot set it |
|-----|---------|------------------------------|
| `0xF2`, `0xF3` | restart count, restart backoff | A workload module's policy is `skip`, which restarts nothing |
| `0xF4` | trust class | The loader's signature check decides it |
| `0xF5` | protection level | Gating turns the platform's protection regime on for the whole node, and isolation draws a private region from the shared allocator |
| `0xF7` | quarantine partner | A global module index, which would tie the module's faults to another owner's module |
| `0xFB`, `0xFC` | ISR cycle budget, hardware IRQ | Interrupt resources of the node |
| `0xFD` | device window | Maps a register block into the module's isolation region |

The walk is the one `parse_protection_config` uses: entries after the
`0xFE` header, up to the `0xFF` end marker. A node tag with any length
counts. Extended entries after the end marker (`[tag][0][len BE]`, such as
`tls` credentials) are not read as tags.

The heap flags `0xF8` (zero on free), `0xF9` (fault on alloc failure) and
`0xFA` (canary) are allowed. They change how the module's own heap behaves
and size nothing. That heap is the module's arena, and the add charges the
module's state plus arena to its owner's `state_cap`.

The build refuses the same things first. A workload module may not declare
`trust_class`, `protection`, `device_window`, `isr_budget_cycles`, `irq`
(unless the module's schema has an `irq` param of its own),
`quarantine_partner`, `quarantine_partner_idx`, `max_restarts`,
`restart_backoff_ms` or `voices`.
`voices` presets are packed under tag `0xFD`. The build also checks the
packed params bytes with the same walk the kernel uses.

### What a workload's graph may reach

A workload's edges reach the node's modules only over ends made for it: a
`Net(key)` lane to the node's network provider, a `Caller(key)` lane to the
module that placed the workload, or a `Tap` of a running module's output.
An `Existing` end naming a module of the node's graph is refused `EACCES`
before anything is allocated: such an edge would rebuild that module's port
table from the edge list, so a workload could write into a node module's
input (ip's `addr_ctl` or `net_in`) or take one of its ports away. Every
edge of a workload has a module of the workload's own at one end at least.
A graph placed with the node's authority may name the node's modules.

Every ring a workload's add opens, lane rings included, is charged to its
owner's `buffer_cap` (the CREATE's memory limit clamps it, as it clamps
`state_cap`). An add whose rings do not fit is refused `ENOSPC` with
nothing left behind. A ring's charge goes back when the ring closes, with
whichever owner's teardown closes it.

An owner's lanes are its one graph's `Net` keys, declared and fixed at
CREATE. The network provider holds a stated number of lanes for every
workload together; a CREATE whose lanes it cannot all take is refused
`EBUSY` and rolled back whole. Sharing that capacity among workloads is the
node agent's capacity planning, not an admission rule.

### A workload's environment

Source: `crates/fluxor-abi/src/contracts/workload.rs` (`env`),
`src/kernel/workload/workload_graph.rs` (`bind_env`), `tools/src/schema.rs`
(`env_bind`, `with_env_binds`)

A workload is created with an environment: the `CREATE`'s options entries
`env`/`var`, each `NAME=VALUE` (the name up to the first `=`), a later
entry for a name replacing an earlier one. An orchestrator that runs a
workload on a node passes the workload's resolved environment this way,
literal values and values it resolved from its own configuration and secret
stores alike.

A host process takes the entries into its environment, over the source's
own. A graph workload takes them into its modules' params, where the graph
bound a param to a name:

```yaml
workloads:
  - name: web
    modules:
      - name: http
        type: http_server
        port: {env: PORT, default: 8080}   # PORT, else 8080
        site: {env: SITE_NAME}             # required: no SITE_NAME refuses the CREATE
        banner: {env: BANNER, required: false}  # BANNER, else the module's default
```

`fluxor build --emit=workload` packs a bound param as an env bind record
under the reserved params tag `0xED`, in the param's place:
`[target tag][kind][flags][name_len][name][default]` — the kind is the
param's (`u8`, `u16`, `u32`, `str`, `str_chunked`), the flags `REQUIRED` or
`DEFAULT`, and a default is an integer's little-endian bytes or a string's
bytes. `workload-image.json` lists every binding under `env` (`name`,
`module`, `param`, `required`), and `fluxor publish workload` carries the
list in the image's config blob (`{"env": [...]}`,
`application/vnd.nanocloud.fluxor.workload-image.config.v1+json`), so an
orchestrator that pulls the image refuses a workload missing a required name
before the `CREATE` would. No other build accepts a binding: nothing
else is created with an environment. `${NAME}` stays refused everywhere
(a graph is never read against the build host's environment); a binding
names the workload's own, explicitly.

The graph backend copies the subgraph into its own memory through
`bind_env` before anything is staged, writing each record out as the
param's entries: an integer (decimal, `0x` hex, `true`/`false`) in its
width, out of range `EINVAL`; a `str` as one entry (more than 255 bytes is
`EINVAL`); a `str_chunked` as 255-byte chunks; an empty string as no entry.
A name no entry gives takes the default, leaves an optional param out, and
refuses the `CREATE` with `EINVAL` when it is required. A subgraph the
values make too large (a module's params past 64 KiB, the subgraph past
the graph source's 64 KiB) is `E2BIG`. Every other add refuses params that
still carry a record (`EINVAL`), so a module never sees one. The spec
digest a staged `CREATE` is continued by covers the options, so every
continuation carries the same environment.

Only a schema param binds, so whatever a module should take per placement
is one. tls's and quic's peer names are: `verify_hostname`, `verify_uri`
(tls) and `alpn` are schema strings beside `cert_file`, `key_file` and
`trust`, so one image serves every cell with
`verify_uri: {env: PEER_URI}`. The builder holds a literal to the module's
rule (a well-formed URI, a hostname of at most 64 bytes, an ALPN list of
whole names); the module holds a bound value to the same rule and refuses
to construct on one that breaks it, rather than truncating or dropping it.

### Volumes lent to a workload

Source: `crates/fluxor-abi/src/contracts/workload.rs` (`volume`),
`src/platform/linux/owner_root.rs` (`lend`)

A `CREATE` lends a workload a host directory with the options entry
`mount`/`bind`, `<src>\0<dst>\0<ro>`: a host process has it bind-mounted at
`dst` in its root, and on Linux a graph workload's `fs` paths at or under
`dst` resolve beneath `src` (see
[the storage surface](storage_capability_surface.md#what-a-workload-reaches)).
A read-only volume takes no change; nothing in a volume is charged to the
owner; the owner's release closes it and leaves its directory as it was.
At most 16 per workload. A node that does not lend volumes does not list
the entry in `OPTIONS`, and a required entry it does not list fails the
`CREATE` with `ENOSYS`, so an orchestrator marks every volume required.

### A workload's own vault

Source: `crates/fluxor-abi/src/contracts/workload.rs` (`vault`),
`src/platform/linux/owner_root.rs` (`set_vault`),
`src/kernel/security/key_vault.rs` (`Scope`, `Keeper`)

A workload's labelled keys are its own whatever it brings: a label lives in
its module type's namespace within its owner's realm, the workload's
durable owner uid, so two workloads running one module type, and a workload
and the node, never reach each other's labels (a token's labels name a
module type and nothing narrower, so a workload's labels are the software
vault's alone). Kept in the node's store, under the node's sealing key and
bound to the realm, they stay with the node.

The options entry `vault`/`store`, `<dir>\0<seal_key>`, gives the workload
a vault of its own on Linux: `dir` lies in one of its writable volumes (made
when absent), `seal_key` is 64 hex digits its owner supplies. Every key a
module of the workload persists by label is sealed with ChaCha20-Poly1305
under `seal_key` and kept as one file per label in `dir`, and nothing of it
is in the node's store: the keys follow the volume and the seal key. The
same volume and seal key given to a workload on another node open the same
keys; a record that does not open under the key given is refused `EACCES`,
never written over by a fresh key. Such a key's custody is `SOFTWARE`
(`DESCRIBE`) whatever the node's sealing key is worth: whoever holds the
volume and the seal key holds the key, which is the point of keeping it
there, and the trade against a node-held key a device-unique seal or a
token would bind to the node. One vault per workload; `dir` outside a lent
volume, or in a read-only one, refuses the `CREATE`. The graph backend lists
the entry in `OPTIONS`; a host process (which reaches no kernel vault) and a
metal node do not, and answer a required entry `ENOSYS`.

## Where the execution mode is declared

YAML graphs declare the execution mode on the domain, with `exec:`:

```yaml
execution:
  domains:
    - name: main               # exec: tick is the default
      tick_us: 1000
    - name: net
      exec: poll
    - name: audio_isr
      exec: timer
      rate_hz: 40000           # 25 µs period
    - name: gpio
      exec: irq
modules:
  - name: sample_driver
    type: my_isr_driver        # author-supplied PIC module with
                               # `interrupt_safe = true` in its manifest
    domain: audio_isr
  - name: nic
    type: rp1_gem
    domain: main
    # `pre_pass = true` is on the module's manifest;
    # no YAML flag needed.
```

The modes are `tick` (the default when `exec:` is omitted), `poll`,
`timer` and `irq`; any other value is a build error. A module declares no mode or rate of
its own. A `tick` domain may declare its own `tick_us` (an audio domain at
`tick_us: 250` is one more `tick` domain). A `timer` domain's cadence is
its `rate_hz`, required and a whole number of microseconds per period
(`1_000_000 / rate_hz`, written into the domain record's `tick_us`);
`rate_hz` on any other mode, or `tick_us` on a `timer` domain, is refused.

A graph declares at most `MAX_DOMAINS` (4) domains, indexed 0..3 in
declaration order. A domain's core is its index: on the SMP targets
(bcm2712, uefi) domain d runs on core d, and on RP, Linux and wasm every
domain runs on the one thread, in index order. There is no `cores:` key;
the builder refuses it as an unknown key.

The build-time validators (`validate_interrupt_admission` and
`validate_pre_pass_admission` in `tools/src/config/builder.rs`)
reject misconfigurations: a module without `interrupt_safe = true` in
its manifest cannot land in a `timer` or `irq` domain; a module with
`pre_pass = true` can land only in a `tick` domain. An `irq`
module additionally must declare an `irq:` field and
export `module_isr_entry` in its source — the IRQ dispatches into that
entry point, not the cooperative `module_step`, so an `irq` module
missing either is rejected at build time. The declared `irq:` is also
range-checked against the resolved silicon's interrupt controller
(GIC-400 lines 0..=1019 on BCM2712, NVIC lines 0..=31 on RP2040 and
0..=52 on RP2350); the platform `irq_bind` enforces the same bound as
a runtime backstop.

## Manifest attestations

Source: `tools/src/manifest.rs`

Two boolean fields, both author claims with no static enforcement.
An interrupt-mode module may use FP/SIMD registers: on aarch64 the `irq`
entry runs inside a frame that keeps the interrupted code's FP/SIMD state
(see the dispatch path below):

```toml
# modules/drivers/<your_isr_module>/manifest.toml
interrupt_safe = true # legal admission to a timer/irq domain
                      # author attests: no heap, no cooperative
                      # provider_call, no channel_read/write,
                      # bounded execution.

# modules/drivers/rp1_gem/manifest.toml
pre_pass = true       # run in the domain's pre-pass (tick only).
                      # cooperative-context constraints apply.
```

`interrupt_safe` is encoded in bit 2 of the manifest binary's flags
byte; `pre_pass` rides bit 3. Both round-trip through the `.fmod`
file format.

`pre_pass` is also carried in the boot-config module record's flags
(`MODULE_FLAG_PRE_PASS`) so `prepare_graph` can read it without
re-parsing the `.fmod` manifest.

## Interrupt-mode I/O contract

Source: `crates/fluxor-abi/src/internal/bridge.rs`, `src/kernel/ipc/isr_ring.rs`, `src/kernel/exec/interrupt.rs`

Interrupt-mode modules (`timer` and `irq` domains) communicate with
cooperative domains exclusively via bridge rings:

- The kernel allocates bridge ring slots for every edge with an
  interrupt-mode endpoint (`wire_isr_bridges`), and the cooperative side
  of those edges is drained between PIPE channel and bridge ring by
  `pump_isr_bridges` at the end of each pass. The bridge pump is
  non-lossy in both directions: it does not drain the PIPE when the
  ring is full, and does not pop the ring when the PIPE is
  back-pressured.
- The bridge slot indices are populated into each interrupt-mode module's
  `in_bridges` / `out_bridges` arrays at admission time.
- In `module_new`, a module takes a handle to each of its bridge
  endpoints with the `SELF_BRIDGE` op (`0x2244`, `arg = [dir][index]`,
  one handle per call), and from the step body moves data with the
  bridge ops `WRITE` (`0x22E0`), `READ` (`0x22E1`), `POLL` (`0x22E2`),
  and `INFO` (`0x22E3`). These five ops are exempt from the interrupt-mode
  syscall deny because the underlying ring operations are lock-free
  and allocation-free; every other `provider_call` op is denied from
  interrupt context. Up to `MAX_BRIDGES_PER_MODULE` (4) input and output
  endpoints per module.

Graph wiring restriction: the build-time validator rejects any YAML
wiring edge with an interrupt-mode endpoint. Interrupt-mode modules
exchange data through kernel-wired bridges, not through declared graph
edges; a declared edge into an interrupt-mode module would create a
channel the interrupt side cannot legally service.

## Runtime gates

Source: `src/kernel/module/syscalls.rs`,
`src/kernel/exec/scheduler/multigraph.rs`

1. **Build-time admission.** `validate_interrupt_admission` and
   `validate_pre_pass_admission` reject ill-formed graphs before
   a `.cfg.bin` is emitted.
2. **Cooperative skip.** `step_one_module` returns early for any
   module whose domain's `ExecMode` is in the interrupt family (`timer`
   or `irq`; its dispatcher handles it instead). Pre-pass modules are
   partitioned into the domain's pre-pass order at graph-prepare time
   and run from the pre-pass, not from `domain_exec_order`.
3. **Runtime EACCES gate.** `deny_interrupt_mode_syscall` rejects every
   cooperative-only syscall from interrupt-mode modules
   (`module_is_interrupt_mode`) with `errno::EACCES`, emitting
   `MON_PERM_DENIED domain=N mod=M op=<syscall>`. The deny surface:
   - **Channels:** `channel_open`, `channel_read`, `channel_write`,
     `channel_peek`, `channel_discard`, `channel_poll`.
   - **Providers:** `provider_open`, `provider_call`,
     `provider_query`, `provider_close`, with
     the bridge ops exempted as described above. The gate
     fires at the syscall wrapper (before permission/contract
     checks) so the EACCES path is reached before any other
     diagnostic.
   - **Heap:** `heap_alloc`, `heap_free`, `heap_realloc`. Gated at
     the wrapper so kernel-internal heap callers (which never set
     `current_module` to an interrupt-mode slot) are unaffected.

   The build-time validator already rejects malformed graphs; the
   runtime gate is a second layer, and the interrupt dispatcher sets
   `current_module` before each step so the gate fires correctly
   even for syscalls made in interrupt context.

## Interrupt-mode dispatch path

Source: `src/kernel/exec/interrupt.rs`, `src/kernel/exec/timer.rs`,
`src/kernel/exec/irq.rs`, `src/kernel/exec/scheduler/setup.rs`,
`src/kernel/exec/scheduler/fault.rs`

`interrupt.rs` holds what the two interrupt modes share: the dispatch
gate, the fault latches, the bridge slots and the per-slot metrics
(`InterruptMetrics`, read through the `monitor` op `INTERRUPT_METRICS`,
whose argument byte 0 is the `ExecMode` byte, 2 for `timer` or 3 for
`irq`, and byte 1 the slot; any other mode is `EINVAL`). `timer.rs`
holds the `timer` slots (up to `MAX_TIMER_MODULES`), `irq.rs` the `irq`
slots (up to `MAX_IRQ_MODULES`).

`timer` admission and dispatch:

1. **Build time.** `validate_interrupt_admission` confirms every
   module in a `timer` domain has `interrupt_safe = true`. The wiring
   check rejects any YAML edge with an interrupt-mode endpoint (see the
   I/O contract above).
2. **Admission.** The node graph is staged through the splice like any
   add (`prepare_graph` → `splice::admit_boot`): each module's domain and
   pre-pass flag go into the scheduler state, and a module in an `irq`
   domain must carry its IRQ and an interrupt entry. The cooperative
   scheduler skips interrupt-mode modules in `domain_exec_order` walks via
   the runtime check in `step_one_module`.
3. **Publication.** Once every module is instantiated, `splice::finish`
   hands each interrupt-mode module to its dispatcher
   (`register_isr_module`): its `(step, state)` pair — a PIC module's
   `module_step`, a native module's vtable `step` — goes to
   `timer::register_module`.
4. **Timer arming.** If at least one `timer` module registered, the
   splice computes the minimum period across all `timer` domains and
   calls `timer::start(period_us)`. On RP this arms the hardware alarm
   whose ISR runs `timer::handler`. On BCM2712 it stores the period and
   arms the architected counter; `bcm_module_timer_poll` (the HAL's
   `module_timer_poll`, called from the domain loop) fires
   `timer::handler` whenever the elapsed counter passes the period.
5. **Domain loop.** The domain loop's (`kernel::exec::domains::run`)
   `timer` arm iterates core parking checks, `timer::poll()`, the
   cross-domain bridge pump, and WFE. The `tick` arm also calls
   `timer::poll()` on every iteration, so a configuration that shares a
   core between cooperative and `timer` work still fires the handler.
6. **Dispatch.** `timer::handler` walks the `timer` slot table,
   sets the current-module pointer to the slot's module index,
   invokes the registered `step_fn(state_ptr)`, records cycle
   metrics, and restores the saved current-module pointer on exit.
   Rebuilding the graph clears the slot table. `timer::ticks` counts the
   handler's runs.

`irq` admission and dispatch:

- The PIC loader extracts the `.fmod`'s `module_isr_entry` export
  into the module's exports (a native module states its `isr_entry`);
  admission refuses an `irq`-domain module without one, and
  `register_isr_module` forwards the entry to `irq::register_module`
  (an `IrqRegistration`), never dispatching a cooperative step from IRQ
  context.
- The scheduler binds the module's declared IRQ through
  `hal::irq_bind`, including the owning domain's core as the IRQ
  target so an `irq` domain on its own core receives its own interrupts.
  The hardware IRQ dispatches into `irq::irq_trampoline`, which
  looks the module up by IRQ number and invokes `module_isr_entry`;
  `irq::dispatch_count` counts the dispatches.
- On aarch64 the EL1 IRQ vector saves general registers only. The
  trampoline calls `module_isr_entry` through `fluxor_irq_fp_frame`
  (`src/arch/fp_frame.rs`), which keeps q0–q31, FPSR and FPCR across
  the call, so module code compiled `+neon` cannot disturb the code the
  IRQ interrupted. Everything else on the IRQ path is kept scalar:
  `fluxor ci` phase `irq-neon-free` links every `aarch64-unknown-none`
  kernel (each board and the UEFI host) and fails if any function reached
  from `irq_handler`, `irq_trampoline` or `event_signal_from_isr`
  names an FP/SIMD register. Cortex-M33 stacks its FPU in hardware and Cortex-M0+ has
  none, so the frame is aarch64 only.
- An `irq` domain that owns its own core runs the dedicated
  `domains::run` arm for `irq`: the cross-domain bridge pump
  plus WFI, with dispatch driven entirely by the hardware IRQ.
- An `irq` module's state is built through the normal cooperative
  `module_new` at instantiation time (thread context), the same
  construction path a `timer` module uses. There is no interrupt init
  entry point.

### Interrupt-mode faults

An interrupt-mode module is a module like any other: a step that answers
`Done` or an error is the end of its dispatch, and an overrun of its
cycle budget is a timeout. The handler does no fault work in interrupt
context. It classifies the answer (`Continue`, `Burst` and `Ready`
proceed), latches anything else in the module's slot, stops dispatching
the slot at once and raises a pending flag; under the `Tolerate` policy
an overrun is counted in the metrics and nothing more. An `irq` slot's
line is masked at the interrupt controller in the handler itself
(`hal::irq_mask`: one register write, no table, no log), so a
level-triggered line cannot refire before thread context sees the latch.
The binding stays until thread context.

The domain's next pass, on its own core, takes the latch: `Done`
finalizes the module; an error or overrun goes through the module's fault
policy as for a stepped module (fault record, `MON_FAULT`; `Skip`
terminates, `Restart` waits out its backoff). Since no pass steps an
interrupt-mode module, that pass also drives the restart: the module is
registered with its dispatcher again and its line unmasked, the binding
having stayed. An `irq` module that ends has its line queued; the primary
domain's next pass drops the binding (`hal::irq_unbind`) with every other
domain parked, the quiesce the binding table is changed under. A
terminated or finished module is never dispatched again.

## Pre-pass dispatch

1. Exec-order computation reads each module's pre-pass flag
   and routes the module into the domain's pre-pass order instead of
   `domain_exec_order[d]`.
2. The tick pass (`pass::run`) runs the pre-pass once, before the regular
   `exec_order` rotation. It snapshot-restores the domain budget
   accumulator so pre-pass cost does not leak into the regular
   per-domain budget accounting.
3. If the combined pre-pass budget (`PRE_PASS_BUDGET_SHARE`: 1/20 of
   the domain's tick, 5 µs at 100 µs) is exceeded, the pre-pass emits an
   overrun monitor record, counts the overrun against the domain, and
   stops iterating; the remaining pre-pass modules wait until the next
   pass. The regular `exec_order` rotation continues uninterrupted — an
   overrun does not abort the pass, and the pre-pass recovers on the
   next pass.

## Behavioural invariants

- Cooperative stepping honours per-module period gating, the
  fault state machine, and `Done` finalisation.
- A step deadline bounds nothing on its own: an overrun is detected,
  recorded, and acted on by fault policy, never pre-empted mid-step.
- Domains are stepped in isolation: a module only ever runs from its
  own domain's exec order (or pre-pass order).
- A per-domain budget overrun rotates the domain's `exec_offset` so the same
  head-of-order modules cannot persistently starve the tail.
- Pre-pass budget accounting is isolated from the regular per-domain
  accumulator, and a pre-pass overrun in one pass does not suppress
  the pre-pass in later passes.
- Per-module `isr_budget_cycles` overrides flow through to the interrupt
  metrics; an interrupt-mode module's error, `Done` or overrun stops its
  dispatch at once and reaches the fault machine on its domain's next
  pass, never in interrupt context.
- Pre-pass modules beyond `MAX_PRE_PASS_PER_DOMAIN` are dropped from
  the pre-pass order without a panic; an interrupt-mode module with no
  step function is skipped cleanly.
