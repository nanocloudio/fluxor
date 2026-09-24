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

## Withholding a module

A module that builds and runs but must not ship — a licence question
still open, a provenance gate not yet cleared — declares so in its
own manifest:

```toml
[publish]
withheld = "AAC Huffman tables await provenance clearance"
```

`fluxor publish` then publishes every other module and leaves this
one out on every shelf, printing the module and its reason. Any tag
the module published earlier is **retired**: a withheld module must
not stay resolvable at a digest the project no longer vouches for.
Its input digest drops out of the staleness map too, so `fluxor ci`
and `workspace publish` do not report as stale an artefact no
publish will ever produce.

The reason is required; an empty one is a manifest error. Building,
testing, linting and local graphs are unaffected — withholding is a
distribution decision, not a build one. Delete the table to publish
the module again.

## What a manifest carries, and what it deliberately does not

A manifest records facts **derived from the artefact**:

- `io.fluxor.abi-surface` — the epoch. Consumers hard-fail on an
  artefact without it, so nothing consumable can skip a publish.
- `io.fluxor.input-digest` — token-canonical digest of the
  artefact's actual inputs (module source dir for fmods, the tree
  itself for source artefacts). This is what makes downstream
  staleness advisories exact: comment and formatting churn is
  digest-neutral. It is a *staleness* signal and not a content
  address — it does not cover the toolchain or the catalog, so two
  artefacts with different bytes can share one.
- `io.fluxor.kind`, `io.fluxor.project`, `io.fluxor.module.name`,
  `io.fluxor.module.target`.

Facts about the **publishing run** live beside the manifest, in the
store's `provenance/` table: `local-build` vs `published`, the git
revision, and the ci digest (recorded when the artefact's current
input digest matches the last green verification stamp under
`target/fluxor/` — information, never a gate). Read them with
`fluxor store ls` or `fluxor inspect`.

That split is what makes a publish cheap. Because the manifest is a
pure function of content and identity, **re-publishing unchanged
content produces a byte-identical manifest**: the digest does not
move, nothing is displaced, no sweep runs, and no downstream
`fluxor.lock` pin changes. `fluxor update` reports it as
`0 changed`. Were `source-rev` carried *inside* the manifest instead,
every publish would rewrite every manifest and strand every pin in
every consumer, whether or not a single module had changed — which is
why it is not.

Promotion `local-build` → `published` is likewise a re-tag of an
existing digest plus one more provenance row — never a rebuild.

`local-build` is ordinary dev flow: every publish is a real,
consumable store write, distinguished by its provenance record, not
by filename or a separate shelf.

## Who is holding what: the pin ledger

A `fluxor.lock` pins a manifest digest precisely so it stops moving
with the tag, which makes pins a garbage-collection root class the
store cannot see by looking at itself. It keeps a **ledger** of
them: `pins/<hash>.toml` in the store, one file per checkout,
written whenever a checkout writes a lockfile or resolves a pin.
Registration is automatic — there is no list to maintain.

Anything any checkout pins is a root. Membership of
`~/.fluxor/workspace.toml` decides who is epoch- and
currency-checked; it has nothing to do with who is allowed to hold a
digest, and using it as the root set meant a consumer nobody had
remembered to add was unprotected by construction.

Bootstrap a checkout that has not resolved anything since:

```sh
fluxor store adopt /path/to/checkout   # or, with no argument, this one
```

A publish that displaces a manifest another checkout still pins says
so, naming the checkouts, **before it writes anything**:

```sh
fluxor publish --dry-run       # print the displacement report, write nothing
fluxor publish --strict-pins   # refuse rather than leave anyone's pin stale
```

Symmetrically, `fluxor update` names the digests it stops holding
that somebody else still does — the moment a consumer's own
re-resolve stops being the thing keeping a manifest reachable.

## Collection: quarantine, then `gc`

A sweep can only prove it did not *find* a root, and the cost of
being wrong is an artefact nobody can rebuild to the same digest.
So a publish's sweep **moves** superseded blobs to `quarantine/`
rather than deleting them, and any read brings them straight back.

The publish sweep only ever looks at the manifest it just displaced,
so it is not a collector. That is a separate, deliberate verb:

```sh
fluxor store gc --dry-run              # what is unreachable, and how much
fluxor store gc                        # quarantine it; delete after 30 days
fluxor store gc --retain-days 7
fluxor store gc --forget-missing       # also drop ledger entries whose
                                       # checkout is gone (an unmounted repo
                                       # looks exactly like a deleted one, so
                                       # this is never automatic)
```

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
                               # surface, input digest, content address,
                               # every provenance record, layers
fluxor store fsck              # every pin every checkout holds: resolvable,
                               # quarantined or dead; sole-held pins;
                               # reclaimable bytes. Read-only, safe to run
                               # while others publish. --repair restores
                               # from quarantine and never deletes.
fluxor workspace status        # members + per-artefact staleness
```

`fsck` is the one to run when a build says an artefact is not in the
store. A **dead** pin is a loss, not a repair job: rebuilding mints a
different digest, so it is a re-pin rather than a recovery, and the
report says so.

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
