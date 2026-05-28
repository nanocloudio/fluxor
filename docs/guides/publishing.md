# Publishing fluxor artefacts

This guide is for fluxor maintainers — "I just edited fluxor, how
do I get my changes into downstream projects?" If you're on the
consumer side trying to figure out how to **use** fluxor in your
own project, see your project's own `docs/consuming_fluxor.md` (or
equivalent).

The prescriptive standard is at
[`../../../standards/dependencies.md`](../../../standards/dependencies.md).
This file is the how-to.

## TL;DR

```sh
make publish
```

In fluxor's checkout. That builds modules + the linux runtime
binary, then publishes four tiers (ABI source crate, SDK source crate,
fmod palette, runtime binary) into `~/.fluxor/registry/`. Consumers
then run `make update && make sync` in their own checkout and pick up
the new state.

**Version source-of-truth rule:** every workspace member crate's
`[package].version` MUST match fluxor.toml's `[project].version`.
Bump them together via `workspace.package` inheritance. Canonical
publish refuses mismatched crates because transitive-resolution
lookup (`projects/<dep>/<version>.toml`) keys on the project
version; a desynced crate version would make downstream lookups
miss.

## The four tiers

| Tier | What it is | Registry location |
|---|---|---|
| **ABI** (`fluxor-abi`) | Wire-stable contract IDs, opcodes, wire structs. Source crate. | `~/.fluxor/registry/cargo/fluxor-abi-<v>.crate` |
| **SDK** (`fluxor-sdk`) | `no_std` runtime helpers — crypto, codecs, params. Source crate. | `~/.fluxor/registry/cargo/fluxor-sdk-<v>.crate` |
| **fmod palette** | Compiled `.fmod` artefacts for foundation modules (`ip`, `tls`, `http`, `ws_stream`, …). Per `(target, name, version)`. | `~/.fluxor/registry/fmod/fluxor/<target>/<name>/<v>.fmod` |
| **Runtime binary** (`fluxor-linux`) | Host executable that runs PIC modules under Linux. Per `(host-target, name, version)`. | `~/.fluxor/registry/bin/fluxor/<host-target>/fluxor-linux/<v>` |

## First-time setup (per developer machine)

```sh
make setup                  # cargo install --locked --path tools
fluxor registry init        # bootstrap ~/.fluxor/registry/ + cargo git index
fluxor registry setup-cargo # add [registries.fluxor] to ~/.cargo/config.toml
```

Idempotent. Re-running any of these is safe.

## Daily — keeping downstream projects current

Two modes, depending on iteration intent.

### Mode A — canonical publish (versioned, reproducible)

Use when shipping a stable point — anything you want to be able to
roll back to or that needs to land in a downstream's
`fluxor.lock`.

```sh
# in fluxor/

# 1. Bump the version in TWO places:
#    - fluxor.toml's `[project].version`
#    - Cargo.toml's `[workspace.package].version`
#    Publishable crates (fluxor-abi, fluxor-sdk) inherit via
#    `version.workspace = true` so a single Cargo.toml edit
#    propagates to them. Downstream projects do the same.

# 2. Publish.
make publish
```

Canonical publish refuses to proceed when any workspace member
crate's resolved `[package].version` doesn't match `[project].
version` — the error names the offending crate, so you'll see
immediately if anything's out of sync.

`make publish` chains:

1. `make modules-all` — builds every silicon target's fmods
2. `make linux-bin` — builds `fluxor-linux`
3. `fluxor publish abi` — packages + indexes `fluxor-abi`
4. `fluxor publish sdk` — packages + indexes `fluxor-sdk`
5. `fluxor publish fmod` — copies all foundation fmods into the registry
6. `fluxor publish runtime --binary fluxor-linux` — copies the runtime binary

Per artefact, this also:

- Writes the cargo git-index entry (`~/.fluxor/registry/index/fl/ux/fluxor-abi`)
- Updates the project-meta file (`~/.fluxor/registry/projects/fluxor/<v>.toml`)
- Refuses to overwrite an existing `(name, version)` — bump if you forgot
- Refuses if `[project].version = "0.0.0-dev"` — set a real version

Consumers pick up the new version with `make update && make sync`
in their own checkout.

### Mode B — live workspace iteration (no version bumps)

Use when iterating fast between fluxor and a colocated consumer. No
version bumps, no canonical publish required for fmods and runtime
binaries — the consumer's `make sync` sources those tiers directly
from each workspace member's `target/` tree.

**What live mode covers today:**

| Tier | Live source? | How updates flow |
|---|---|---|
| fmods | Yes | Build with `make modules-all` upstream; consumer's `make sync` reads from your `target/<silicon>/modules/` |
| Runtime binary (`fluxor-linux`) | Yes | Build with `make linux-bin` upstream; consumer's `make sync` reads from your `target/<host-target>/release/` |
| Source crates (`fluxor-abi`, `fluxor-sdk`) | No — still registry | Consumer's `make sync` still extracts from `~/.fluxor/registry/cargo/`. To refresh: bump versions and run **canonical** `make publish` upstream, then `make update && make sync` in the consumer. |

**Source-crate refresh requires canonical publish, not local.** The
lockfile resolver only considers canonical artefacts — `-local.<sha>`
snapshots are invisible to `make update` and `make sync` in normal
(registry-resolved) consumption. They exist for the narrow case of a
downstream that declares `[dependencies] X = { path = "..." }` and
wants the path-overridden source to come from the registry directory
extract. For the workspace-mode flow you're in here, treat them as
out of scope.

The source-crate gap is the one hand-off that isn't fully live: when
you edit fluxor's SDK source (e.g. `modules/sdk/abi.rs`), the
consumer doesn't see the change automatically — you have to bump
versions, canonical-publish, and have the consumer `make sync`. Live
source-crate resolution across workspace members (so SDK edits flow
without a publish) is not yet supported.

**CI implication:** `fluxor ci`'s `lockfile-consistency` phase
detects workspace mode and skips with an advisory rather than
failing. CI runners shouldn't carry `~/.fluxor/workspace.toml` in the
first place; if a CI worker is misconfigured, this saves it from
spurious rejections.

```sh
# one-time, per developer machine
cat > ~/.fluxor/workspace.toml <<EOF
[workspace]
members = [
  "/srv/code/fluxor",
  "/srv/code/<consumer-project>",
]
EOF

# then in fluxor/, edit anything
# in the consumer's checkout, `make modules` / `make test` picks up live state
```

List every colocated checkout that should resolve to live source —
add more entries as you take on additional concurrent work. `fluxor
workspace status` (run from inside any member) confirms live mode is
active. See
[`../../../standards/dependencies.md`](../../../standards/dependencies.md)
§6 for the override semantics.

When you've stabilised the change and want it tagged for distribution,
switch to Mode A (canonical publish).

### Mode B and the lockfile-consistency CI phase

`fluxor ci`'s `lockfile-consistency` phase prints an advisory and
skips the actual consistency check when the project root is a
workspace member. CI shouldn't normally run inside a workspace
member; if you put a CI runner's working directory inside a
workspace-listed checkout, that's an env-hygiene bug.

## Local snapshots (`publish --local`)

`make publish-local` writes each artefact with a `-local.<sha>`
suffix. Useful only for path/git override workflows in a
downstream's `fluxor.toml`. `make update` / `make sync` in downstream
projects **never** consume `-local` artefacts — they're invisible to
canonical-mode resolution.

If you're reaching for `publish-local`, you probably want workspace
mode (Mode B) instead.

## Version stability strategy

The ABI version (`modules/sdk/wire.rs::ABI_VERSION`, currently `1`)
is the load-bearing pin downstream projects assert against. Bump it
only when the wire format genuinely breaks:

- module-header layout change
- channel-hint encoding change
- contract-id table reorganisation

Wire-stable improvements (faster crypto, NEON optimisations, new
modules, better algorithms) stay at the current ABI. They land as
patch / minor `[project].version` bumps without forcing downstream
rebuilds.

`[project].version` in fluxor.toml is independent of ABI. Bump it
freely per canonical publish — downstream `[dependencies] fluxor =
"0.1"` matches the whole 0.1.x family via cargo semver semantics.
Bumping ABI requires a major version bump (`0.2`) so the dep range
no longer matches and consumers explicitly opt in.

## Inspecting registry state

```sh
make registry-list           # everything in ~/.fluxor/registry/
make registry-gc-dry         # preview garbage-collection (locals/lives only)
make registry-gc             # actually collect — keeps newest 3 per group, min-age 24h
make workspace-status        # show workspace.toml state
fluxor inspect <config.yaml> # full discovery: project root, search paths, target stack
```

The registry is a real on-disk tree under `~/.fluxor/registry/`. Tar
through it with normal Unix tools if needed.

## When something is wrong

- **"canonical X already exists, bump version"** — `[project].version`
  unchanged since last publish, with **different content** in the
  packaged crate. Bump the version (in both fluxor.toml `[project]`
  AND the affected crate's `[package]`). Re-publishing the same
  content at the same version is an **idempotent skip** and doesn't
  error.
- **"version mismatch: crate `X` is at A but [project].version is B"** —
  a workspace member crate's `[package].version` desynced from
  `[project].version`. Bring them in line; this is the single
  source-of-truth rule.
- **"refuses to publish 0.0.0-dev"** — `[project].version` was never
  set. Add `version = "0.1.0"` (or whatever) to fluxor.toml's
  `[project]` block.
- **A consumer's `make sync` reports `hash mismatch`** — the local
  registry was tampered with or got out of sync with the consumer's
  `fluxor.lock`. Republish from fluxor (`make publish`) and have the
  consumer re-run `make update` to pick up the new hashes.
- **A consumer can't find the `fluxor` registry** — they haven't run
  `fluxor registry setup-cargo` on their machine. Each developer
  needs this once.

## Related reading

- [`../../../standards/dependencies.md`](../../../standards/dependencies.md) — prescriptive contract
- [`../../../standards/fluxor-modules.md`](../../../standards/fluxor-modules.md) — module-level standard
- [`../architecture/abi_layers.md`](../architecture/abi_layers.md) — what's actually in the ABI tier
