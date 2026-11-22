# Vocabulary

One term per concept. Every Fluxor document, comment, log line and CLI
message uses these words with these meanings; a second word for the same
concept is a defect, and the table of [retired words](#retired-words) names
the replacement for each one in the way.

## The machine

| Term | Definition | Relations |
|---|---|---|
| **target** | A build descriptor: the silicon, board or host class (`targets/silicon/`, `targets/boards/`, `targets/host/`) a build is made for. Graph `target:` names one. | A target resolves to one runtime and one module ABI ([runtimes_and_abis.md](runtimes_and_abis.md)). A target is never the running machine: that is a node. |
| **node** | A running Fluxor instance: one kernel on one machine (a board, a cloud instance, a Linux host process, a browser tab), the unit an orchestrator manages. | A node is built for one target, runs one node graph and the workloads its owners place on it, and is reached through its node agent. |
| **node agent** | A node's control endpoint: the end of the [agent protocol](agent_protocol.md) a controller talks to. | One per node. It commits workloads into the node's store; the kernel runs them. |
| **core** | A processor core of the node's machine. | On the SMP targets (bcm2712, uefi) domain d runs on core d; on RP, Linux and wasm every domain runs on one thread ([concurrency.md](concurrency.md)). |
| **host** | Never bare. A **Linux host** is the machine a Linux node runs on; a **host class** is a target under `targets/host/` (uefi, wasm, Linux); the **host-process backend** runs a workload as a Linux process; the **build host** is the machine running `fluxor build`. | |

## Execution

| Term | Definition | Relations |
|---|---|---|
| **domain** | An execution domain: one core (on SMP) and one exec mode, fixed at boot. A graph declares up to `MAX_DOMAINS` (4), indexed 0..3. | A node runs its domains; every module instance runs in exactly one domain. A domain's index is its core. |
| **exec mode** | How a domain runs its modules: `tick` or `poll` (the cooperative family, full syscall surface), or `timer` or `irq` (the interrupt family, bridge-only, admitting only `interrupt_safe` modules). Encoded as `ExecMode` (`Tick` 0, `Poll` 1, `Timer` 2, `Irq` 3). | One per domain ([scheduler.md](scheduler.md#execution-modes)). Cadence belongs to the domain: `tick_us` for `tick`, `rate_hz` for `timer`. |
| **pre-pass** | A module attribute (`pre_pass = true`): the module runs at the start of every tick pass of its domain, before the exec order. | Legal only in a `tick` domain. Not an exec mode. |
| **domain loop** | The loop that drives a domain: on SMP one per core, elsewhere one loop that runs every domain in index order. | A domain loop runs passes. |
| **pass** | One iteration of a domain loop over its domain: a tick pass or a wake pass. | A pass steps module instances; budgets, wakes and fault windows are per pass. |

## Code

| Term | Definition | Relations |
|---|---|---|
| **module** | A module type: a `.fmod` (PIC) or a native module built into the kernel. | A module is instantiated as module instances. |
| **module instance** | One instantiation of a module in a module slot, with its own state, params and channels. | Belongs to one graph, one domain and one owner. |
| **stack** | A reusable composition of modules: a platform stack (`stacks/*.toml`, injected by target match) or a published stack (`packaging/stack/`, included by name) ([stacks.md](stacks.md)). | A graph includes stacks; their modules become the graph's module instances. "Protocol stack" stays plain English. |

## Graphs

| Term | Definition | Relations |
|---|---|---|
| **node graph** | The graph a node boots with and that runs for the node owner: its drivers, network, control plane and whatever else the node's own config declares. | One per node. Workload graphs are spliced in beside it. |
| **workload graph** | The graph of one workload: its modules and wiring, staged into a running node. | Runs for the workload's owner, beside the node graph. |
| **composed graph** | A graph in its wire form, the `FLXG` record the composer emits (`fluxor_contracts::graph`). | Both node graphs and workload graphs travel and are admitted as composed graphs. |
| **resident graph** | Any graph a node has admitted and is running: the node graph and every workload graph. | The pass engine steps each resident graph per domain ([scheduler.md](scheduler.md#passes)). |

## Owners and workloads

| Term | Definition | Relations |
|---|---|---|
| **owner** | The party a resource, module instance or workload is held for and charged to. | Every module instance has one owner. |
| **owner uid** | An owner's durable identity, stable across restarts and nodes. | Names the owner in stores, vault realms and the agent protocol. |
| **owner slot** | An owner's local index in a node's owner table (`MAX_OWNERS`). | Local to one node and one boot; an owner uid maps to an owner slot while the owner is resident. |
| **node owner** | The owner that holds the node's own authority (`OWNER_NODE`). | Owns the node graph. A workload never runs as the node owner. |
| **workload** | An owner's unit of work on a node, run by one backend: a workload graph (the graph backend) or a host process (the host-process backend). | A node runs many workloads, each for one owner. |

## Artefacts

An **image** is compiled and ready to admit; a **package** is the source
form a build or a run compiles.

| Term | Definition | Relations |
|---|---|---|
| **workload package** | The artefact `fluxor publish package` publishes from `packaging/`: `workload.json`, `resources.json`, the source graph and the `.fmod`s ([workload-packages.md](../guides/workload-packages.md)). | A node agent admits a workload by its package's digest; a run renders the package's graph with its params. |
| **workload image** | The artefact `fluxor build --emit=workload` writes and `fluxor publish workload` publishes: the composed graph and the `.fmod` of every module it loads. | The compiled form of one workload. Never the package. |
| **node image** | The `FXSL` image of a node graph: a header that pins it to the kernel it runs on, the module table and the compiled config ([network_boot.md](network_boot.md)). | What an RP flash slot holds, what OTA stages and activates, and what a Linux node loads (`node.img`). `fluxor build --emit=node` writes it and `fluxor publish node` publishes it. |
| **firmware image** | The kernel with a node image appended (`fluxor build --emit=firmware`). | What a board boots or netboots; the node image it carries is the fallback an OTA stage returns to. |
| **wasm bundle** | The `.wasm` file a wasm build writes: kernel, modules and config in one web asset ([wasm_platform.md](wasm_platform.md)). | The wasm target's firmware form; "bundle" in its web sense. |

A stack ([Code](#code)) is a composition a graph includes, not an artefact a
node admits.

## Retired words

The hygiene scanner refuses each of these in the source and the docs,
naming the term that replaced it; this table is the one place they stand.

<!-- vocabulary-exempt-begin: the table of retired words names them -->
| Retired | Use instead |
|---|---|
| tier, the numbered tiers (Tier 0, 1a, 1b, 1c, 2, 3), ISR tier | exec mode: `tick` (0 and 1a), `poll` (3), `timer` (1b), `irq` (2); 1c is the pre-pass attribute |
| the workload contract's Tier 1 and Tier 2 | header and options (an options entry) |
| runner, graph runner, domain runner, shared runner | domain loop |
| pre-tick (slot, budget, overrun) | pre-pass |
| `step_modules`, `step_domain_modules`, `step_resident_graphs_*` | a tick pass: `pass::tick_all` (every domain in index order), `pass::run(d, PassKind::Tick)` (one domain) |
| `step_woken_modules` | a wake pass: `pass::run(d, PassKind::Wake(..))` |
| `exec_order_offset` | `exec_offset`, the domain's rotation of its exec order |
| kernel fan | a tee or merge module the composer inserts |
| built-in module, built-ins, all-builtin (of modules) | native module, native modules, native-only; its manifest still says `builtin = true` |
| pump, main loop (for the domain loop) | domain loop. Data movers keep their own names: the cross-domain bridge pump, the interrupt bridge pump |
| base graph, boot graph, system graph, root graph, application graph | node graph |
| system owner, `OWNER_SYSTEM` | node owner, `OWNER_NODE` |
| tenant | owner |
| pod | workload |
| `workload_uid`, `--workload-uid` | owner uid: the agent field `owner_uid`, the flag `--owner-uid` |
| target (for the running machine), `target_id`, `--target-id` | node: the node id `node_id`, the flag `--node-id` |
| domain (for a value bound: module-index domain, edge domain) | range |
| isolation domain, protection domain | isolation region |
| bundle, service bundle, applet bundle (the `packaging/` artefact); `fluxor publish bundle`, `[uses] bundles`, `kind = "bundle"`, `target/fluxor/bundles`, the agent's `--bundle`, `--bundles` and `--bundle-digest`, `desired_bundle_digest`, `BUNDLE_MISSING` | workload package: `fluxor publish package`, `[uses] packages`, `kind = "package"`, `target/fluxor/packages`, `--package`, `--packages`, `--package-digest`, `desired_package_digest`, `PACKAGE_MISSING` |
| graph image, `graph.img`, `--emit=image`, `fluxor publish image` | node image, `node.img`, `--emit=node`, `fluxor publish node` |
| boot image, combined image, `--emit=combined`, the rig's `boot_bundle` | firmware image, `--emit=firmware`, the rig's `firmware_image` |
| Tier A, Tier B (memory) | the static reservation (Tier A), the elastic region (Tier B) |
| trust tier | trust class |
| module tier (`modules/foundation`, `modules/drivers`, …) | module layer |
| `BlobTier` | `BlobKind` |
| the key vault's tier, `TIER`, `vault_tier` | custody: the `CUSTODY` op, `R_CUSTODY`, `vault_custody` |
| the metric dimension key `domain`, `DimDomain` | `kind`, `DimKind` |
| crypt_block's attachment bundle, its `bundle` port | the attachment share set, the `shares` port |
| the fs contract's write, async, byte, object-model, handle-acquisition and degraded tiers | surface: the write surface, the async surface, … |
| the OPFS read and write tiers | the read layer and the write layer |
<!-- vocabulary-exempt-end -->

## Allowed qualified phrases

<!-- vocabulary-exempt-begin: the allowed qualified phrases name the words -->
These keep "domain" or "tier" in a meaning that is not an execution domain
or a retired tier, and the scanner allows them by name:

- **failure domain**: the set of things one fault takes down.
- **trust domain**: a SPIFFE trust domain, and the scope a set of nodes trusts one root in.
- **domain separation**, **domain-separated**: a cryptographic tag that keeps two uses of one key or hash apart.
- **domain name**: DNS.
- **clock domain**: hardware that runs from one clock.
- **USB hub tier**: a hub's depth in the USB topology.
<!-- vocabulary-exempt-end -->
