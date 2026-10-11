# Runtimes and module ABIs

Two names describe where a module goes, and they answer different
questions.

- A **runtime** is where a module runs: bare-metal silicon, or fluxor
  hosted as a process. It decides which contracts and providers exist,
  so it decides which modules may be placed there.
- A **module ABI** is the bytes a module compiles to: an instruction
  set and a CPU-feature floor. It names the artefact shelf, the store
  tag and the `fluxor.lock` pin.

Runtimes that share an ABI share module bytes. The hosted Linux runtime
on aarch64 loads the same `.fmod`s bare-metal Pi 5 runs, yet a module
built only for bare metal is not placed under Linux: sharing bytes is
not sharing contracts.

Source: `tools/src/runtime_abi.rs` (the table),
`modules/sdk/wire/wire.rs` (`runtime_bit`),
`tools/src/modules_build.rs` (build), `src/kernel/module/loader.rs`
(load-time check).

## Runtimes

| Runtime | Manifest bit | Module ABIs | Status |
|---------|--------------|-------------|--------|
| `rp2350` | `0x01` | `thumbv8m` | built |
| `rp2040` | `0x02` | `thumbv6m` | built |
| `bcm2712` | `0x04` | `aarch64` | built |
| `wasm` | `0x08` | `wasm32` | built |
| `linux` | `0x10` | `aarch64`, `x86_64` | built on aarch64 |
| `macos` | `0x20` | `aarch64`, `x86_64` | name reserved |
| `windows` | `0x40` | `aarch64`, `x86_64` | name reserved |
| `esp32` | `0x80` | `xtensa-lx6` | target validation only |

## Module ABIs

Each ABI has a floor: a CPU at or above it runs the modules, one below
it does not.

| ABI | Floor | Built |
|-----|-------|-------|
| `thumbv6m` | ARMv6-M (Cortex-M0+) | yes |
| `thumbv8m` | ARMv8-M Mainline with single-precision FPU (Cortex-M33) | yes |
| `aarch64` | ARMv8.0-A with AES, SHA2 and NEON | yes |
| `x86_64` | x86-64-v3 with AES-NI and PCLMULQDQ | no |
| `wasm32` | WebAssembly 1.0 (MVP) | yes |
| `xtensa-lx6` | Xtensa LX6 with single-precision FPU (ESP32) | no |

The hosted Linux runtime checks the `aarch64` floor at start and refuses
to run on a CPU without it. Its runtime binary, built on Debian 13,
needs glibc 2.39 or newer.

## Where each name is used

| Place | Uses |
|-------|------|
| Module `hardware_targets` | runtimes; any other token is refused |
| Graph `target:`, bundle `[[implementation]] target` | a target, which resolves to one runtime |
| Target files (`targets/*/*.toml`) | `runtime` and `module_abi` |
| Shelf `target/fluxor/<abi>/modules` | module ABI |
| Store tag `<abi>/<module>:<version>`, `fluxor.lock` `target` | module ABI |
| Per-target manifest values (`buffer_size = { default = 2048, aarch64 = 16384 }`, capacities, capability facts) | module ABI |
| Module `cfg(fluxor_abi = "...")` | module ABI |
| Target facts and capabilities (vault suites, trusted clock, FPU/NEON/MMU) | runtime |

## Rules

- A module belongs on every ABI shelf a runtime it names loads.
  `fluxor modules build` builds each ABI once, with every such module,
  whichever target asked for the shelf; `--all` builds each ABI that
  `[ci].targets` maps to. Publish requires exactly the same set, and
  retires any module tag outside it: after a publish, a project's tags
  are the shelves it declares and the modules built for them.
- A module naming no runtime is portable: it belongs on every shelf and
  runs under every runtime.
- Placement is checked twice: `fluxor build` refuses a graph that places
  a module under a runtime its manifest does not name, and the loader
  refuses a module whose signed runtime mask lacks its own runtime's
  bit.
- A runtime's name and bit are fixed once, in the table, before it is
  buildable, so adding one is additive: a new build recipe and target
  file, no renames.
