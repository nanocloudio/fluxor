# Publishing fluxor artefacts

This guide is for fluxor maintainers: "I just edited fluxor, how do
I get my changes into downstream projects?" If you are on the
consumer side trying to use fluxor in your own project, see that
project's own `docs/consuming_fluxor.md` (or equivalent).

Source: `tools/src/store_publish.rs`, `tools/src/oci_store.rs`,
`tools/src/store_sync.rs`, `tools/src/store_resolve.rs`.

## The short version

```sh
make publish
```

In fluxor's checkout. That builds fluxor's owned artefacts (fmods
for every silicon target, the linux runtime, the CLI) and runs
`fluxor publish`, which writes them all into the local OCI store in
one transaction: blobs staged first, then every `:ver` and
`:latest` tag plus the project index repointed in a single locked
`index.json` write. Partial publish is impossible by construction.
Consumers pick up the new state with `fluxor sync` (workspace
members) or `fluxor update && fluxor sync` (pinned checkouts).

## What fluxor owns and publishes

"Owned" artefacts are the ones this repo is the producer of — the
set `fluxor publish` builds, annotates, and tags, and the set the
project index (`fluxor/meta`) lists:

| Artefact | Content | Tag |
|---|---|---|
| SDK source tree | canonical tar of `modules/sdk/**` mapped under a `sdk/` path prefix — everything a `#[path]`/`include!` consumer reads; extraction preserves `target/fluxor/fluxor-abi/sdk/abi.rs` | `fluxor/src/fluxor-abi:<ver>` |
| Contracts source tree | canonical tar of `contracts/src/**` mapped under a `src/` path prefix | `fluxor/src/fluxor-contracts:<ver>` |
| fmod palette | compiled `.fmod` + manifest per foundation module (`ip`, `tls`, `quic`, …), per silicon target | `<target>/<name>:<ver>` |
| Runtimes | `fluxor-linux` and the `fluxor` CLI itself, one binary layer per host triple | `fluxor/run/<name>-<triple>:<ver>` |
| Project index | standard OCI index over the artefact manifests above; annotations carry fluxor's dependency declarations | `fluxor/meta:<ver>` |

`fluxor publish --only <kind>` scopes the publish to a subset of
artefact kinds (`source`, `fmod`, `runtime`); the transaction and
the index rewrite cover exactly what was published.

Only fluxor publishes runtimes; the `fluxor/run/` namespace is
reserved. A sibling "runtime" is a graph on `fluxor-linux`.

## Annotations every publish stamps

- `io.fluxor.abi-surface` — the epoch. Consumers hard-fail on an
  artefact without it, so nothing consumable can skip a publish.
- `io.fluxor.input-digest` — token-canonical digest of the
  artefact's actual inputs (module source dir + SDK epoch for
  fmods, the tree itself for source artefacts). This is what makes
  downstream staleness advisories exact: comment and formatting
  churn is digest-neutral.
- `io.fluxor.ci-digest` — records whether the artefact was built
  from a verified tree: publish annotates it when the artefact's
  current input digest matches the last verification stamp under
  `target/fluxor/`, and omits it otherwise. Information, never a
  gate — publish does not refuse on its absence.
- provenance (`local-build` vs `published`) and `source-rev` (plus
  a dirty bit). `local-build` is ordinary dev flow: every publish
  is a real, consumable store write, distinguished by annotation,
  not by filename or a separate shelf. Runtimes' staleness signal
  is rev-scoped (their inputs are effectively the whole kernel
  tree).

Every publish ends with a GC sweep: superseded blobs live until no
tag, snapshot, or workspace member's `fluxor.lock` pins them, then
go.

## First-time setup (per developer machine)

```sh
make install
```

Bootstrap only — the first build on an empty-store machine. It
builds the CLI, publishes it as a runtime artefact, and installs
the launcher at `~/.cargo/bin/fluxor` (resolve `:latest`, exec the
content-addressed blob). After that there is no installed copy to
go stale: every `fluxor publish` that covers the CLI repoints
`:latest`, and the next invocation is the new CLI. An empty store
reports the path back here:
``no fluxor CLI in store — run `make install` from a fluxor checkout``.

## Daily: keeping downstream projects current

One flow. Whether the consumer is a workspace member or a pinned
checkout changes only how it resolves, never how you publish.

```sh
# in fluxor/, after editing
fluxor publish              # or `make publish` for a full build-then-publish
```

- **Publish is always explicit.** Sync never builds or publishes on
  fluxor's behalf. `:latest` means "most recently published digest"
  and moves only when you run publish.
- **Workspace members** (`~/.fluxor/workspace.toml`) pick the
  change up on their next `fluxor sync`: sync resolves fluxor's
  artefacts to `:latest` and writes the resolved digests through
  the consumer's `fluxor.lock`, so the change is visible as an
  ordinary lockfile diff.
- **Pinned checkouts** stay on their digests until they run
  `fluxor update`.
- **SDK edits flow the same way.** Source trees are artefacts:
  editing `modules/sdk/abi.rs` and publishing repoints
  `fluxor/src/fluxor-abi:latest`; the consumer's next sync
  re-materialises `target/fluxor/fluxor-abi/` from the new digest.

### Forgotten-publish safety net

Sync in a consumer compares each live member artefact's current
input digest against the published annotation and warns per
artefact — e.g. `warning: module 'tls' inputs changed since publish
(fluxor)` — then proceeds. The same data shows in `fluxor workspace
status`.

### Batching: `fluxor workspace publish`

When several workspace members are stale (typically after an epoch
move, which changes every fmod's input digest at once), one verb
publishes them all:

```sh
fluxor workspace publish
```

For every member whose input digests differ from its published
artefacts, it runs that member's build + publish, topologically
ordered by the members' `fluxor.toml` dependency declarations. It
aborts at the first member whose build or publish fails; the
already-published prefix stands (each member's publish is
transactional, so the prefix is a coherent store state).

## Version discipline

`[project].version` in `fluxor.toml` is a label: it becomes the
`<ver>` component of every published tag, carried for human
readability. Resolution never orders versions — `:latest` is the
only tag with semantics, and consumers pin digests. Keep the label
meaningful (bump it when you'd want the tag to read differently in
`fluxor store ls` / `fluxor inspect`), and don't expect a bump to
do anything mechanical.

## The epoch (ABI surface)

Cross-artefact compatibility is the epoch — the ABI-surface digest
annotated on every artefact — not a version number.
`fluxor abi-regen` is the epoch's single writer; run it when the
ABI surface genuinely moves (wire structs, opcodes, contract IDs),
then rebuild and publish. Wire-stable improvements (faster crypto,
new modules, better algorithms) leave the epoch untouched and cost
consumers nothing.

An epoch move cascades by design: every fmod's input digest changes
at once, `workspace publish` republishes everything, and consumers'
sync enforces epoch homogeneity across their resolved set (a
mixed-epoch lockfile is a hard error naming `fluxor update`). Live
members must additionally match the *current* surface; that hard
error names `fluxor workspace publish`.

## Naming a released set

A release is a cross-project resolved state, which no single repo's
git history can name. Snapshot it:

```sh
fluxor store snapshot <name>       # one OCI index over the resolved set
```

Snapshots are also GC roots — everything a snapshot references is
retained. A consumer restores one with
`fluxor update --from snapshot/<name>` followed by `fluxor sync`.

## Inspecting store state

```sh
fluxor store ls                # everything in the store
fluxor inspect <ref>           # sha256:… or tag: kind, tags, epoch vs current
                               # surface, input digest, provenance,
                               # source rev, layers
fluxor workspace status        # members + per-artefact staleness
```

The store is a real on-disk OCI image layout
(`$XDG_DATA_HOME/fluxor/store`, typically
`~/.local/share/fluxor/store`, override `$FLUXOR_STORE`); every
construct in it is expressible against a stock OCI registry.

## When something is wrong

- ``no fluxor CLI in store — run `make install` from a fluxor
  checkout`` — empty store or missing CLI tag; run the bootstrap.
- **A live member's artefact has no `:latest` tag** — the member
  has never published; the error names `fluxor publish` in that
  member.
- **A consumer errors on an artefact lacking the epoch annotation**
  — its producer must publish; the error names `fluxor publish`
  there.
- **A consumer reports a mixed-epoch lockfile** — the resolved set
  straddles an ABI-surface move; `fluxor update` in the consumer
  advances the whole set.
- **A consumer's sync reports a pinned digest missing from the
  store** (the error names `fluxor update`) — the blob was
  garbage-collected (the checkout isn't a workspace member, so its
  pins aren't GC roots); `fluxor update && fluxor sync` there
  recovers in one step.
- **The module build reports an artefact name collision** — two
  module sources (a `<module>-<variant>` and a module directory of
  that literal name) would produce the same `<name>.fmod`; the
  error names both manifests. Rename one.

## Related reading

- [`../architecture/abi_layers.md`](../architecture/abi_layers.md) — what's actually in the ABI tier
