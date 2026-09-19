# ABI Surface Digest

Fluxor has no ABI version numbers. There is one surface, and the rule is that
the latest one is the only one: no compatibility windows, no negotiation. So
the only way to know that a module and a kernel agree is to hash everything
they must agree on and compare the hashes.

That hash is the **ABI surface digest**. Equality means compatible. That is the
whole idea; everything below is mechanism.

## What goes into it

Source: `modules/sdk/abi_surface.rs`, `tools/src/hash.rs`.

```
digest = sha256( every ABI constant, as name\0value pairs
               + "contracts_platform_src"\0
               + CONTRACTS_PLATFORM_SRC_HASH )
```

Two inputs, because the two halves of the surface are knowable in different
ways:

- **The constants** — contract ids, opcodes, permission bits, wire sizes, fd
  tags — are enumerated by `for_each_field` in `modules/sdk/abi_surface.rs`.
  Names are hashed alongside values, so two constants swapping values changes
  the digest. That list is **append-only**: a retired allocation keeps its
  entry rather than being deleted, or every later digest would shift.
- **`CONTRACTS_PLATFORM_SRC_HASH`** — a hash of the source files under
  `modules/sdk/` and `contracts/src/`. Wire-struct layouts and opcode
  name-hashes exist only as source; no walk over constants can see them, so
  that half is folded in as a source hash.

The source hash is token-based (`canonicalize_source` in
`tools/src/hash.rs`): each file is tokenised and the token stream is hashed,
so comments and formatting do not move it, but every identifier, literal, and
punctuation token does. This over-approximates: adding a private helper under
`modules/sdk/` moves the digest even though no wire byte changed. That trade
is deliberate: a narrower hash over public API shape would add
false-negative risk to the one mechanism that stops an incompatible module
loading, and the cost of an over-wide move is one re-sync per sibling, not
one per change.

## The two constants are not two copies

Source: `modules/sdk/abi_surface_srcpin.rs`.

`CONTRACTS_PLATFORM_SRC_HASH` and `ABI_SURFACE_DIGEST` live adjacent in
`abi_surface_srcpin.rs`, which makes them look like a pair. They are an input
and an output:

| Constant | Role | Why it must be a constant |
|---|---|---|
| `CONTRACTS_PLATFORM_SRC_HASH` | ingredient, read inside `write_surface` | The kernel computes its own digest at boot, on bare metal, with no filesystem to hash source files from |
| `ABI_SURFACE_DIGEST` | result, embedded by every PIC module as `FLUXOR_ABI_SURFACE` | It is the module's attestation stamp, in `no_std` code |

Neither can be derived away at build time. PIC modules compile through direct
`rustc` invocations with no `--extern` flags, so `abi_surface.rs` may use
`core` and nothing else; a const-evaluated SHA-256 would mean carrying a
second hash implementation in the SDK to delete one cached value.

Both are written by **`fluxor abi-regen`**, which is the single writer. Never
hand-edit either: a hand-pasted digest that happens to be wrong produces
artefacts that attest a surface nobody has.

## Where the digest ends up

```
                    modules/sdk/abi_surface.rs
                    (constants + src hash)
                              │
                      fluxor abi-regen
                              │
                ┌─────────────┴─────────────┐
                ▼                           ▼
  abi_surface_srcpin.rs              tools/src/hash.rs
  ABI_SURFACE_DIGEST                 the one spelled-out
  (embedded in every module)         digest, as a tripwire
                │
                ├──► every .fmod        (stamped at pack time)
                ├──► every graph slot   (stamped at build time)
                └──► every store artefact (io.fluxor.abi-surface annotation)
```

`abi-regen` writes two files. Everything else is stamped automatically from
`ABI_SURFACE_DIGEST` as artefacts are produced.

## The gates

Every check asks one question — *were these two things built against the same
surface?* — at four different moments:

| Gate | Where | Catches |
|---|---|---|
| **Pack / read** | `tools/src/modules.rs::verify_module_abi_surface` | an `.fmod` whose stamp differs from the CLI's digest |
| **Boot** | `src/kernel/boot/config.rs::decode_slot_header` | a graph slot that doesn't match the running kernel |
| **Sync** | `tools/src/store_resolve.rs::check_epoch` | a store artefact set that is mixed-epoch, unstamped, or behind the current surface |
| **Pin freshness** | `fluxor abi-regen --check` | the checked-in constants having gone stale against the source |

The first three compare two artefacts. The sync gate applies two rules over a
resolved artefact set: every artefact must carry the same
`io.fluxor.abi-surface` annotation (an unstamped or mixed set is a hard
error), and a live workspace member's artefacts must additionally match the
current epoch. The fourth gate checks the cache rather than compatibility:
`abi-regen --check` recomputes the digest from source and fails if either
checked-in site differs.

## The tripwire, and the two mounts

`abi_surface.rs` is `#[path]`-mounted into two different crates: the host
tools and the kernel. Both must compute the same digest, or an artefact
stamped by the CLI would be rejected by a kernel that disagrees about the
surface. The invariant: both mounts resolve to the single
`ABI_SURFACE_DIGEST` constant in `abi_surface_srcpin.rs`, so they cannot
disagree with each other without one of them disagreeing with the constant —
and a stale constant is exactly what `abi-regen --check` reports.

`tools/src/hash.rs` additionally carries the one spelled-out digest hex in
the tree. That literal is a deliberate tripwire: it goes stale on *any*
surface change, so a wire break has to be an explicit decision (updating the
literal via `abi-regen`) rather than a quiet consequence of an edit.

## Artefact digests beyond the epoch

Source: `tools/src/oci_store.rs`.

The store stamps every published artefact with annotations that answer
different questions. Confusing two of them is the usual source of surprise:

| Digest | Question it answers | Moves when |
|---|---|---|
| ABI surface digest (`io.fluxor.abi-surface`, "the epoch") | Can these bytes interoperate? | the module↔kernel interface changes |
| `CONTRACTS_PLATFORM_SRC_HASH` | — (an input to the epoch, never consulted alone) | any token under `modules/sdk/` or `contracts/src/` |
| input digest (`io.fluxor.input-digest`) | Are these bytes current? | any source the artefact is built from changes |
| content address (lock `content` field) | Do two manifests deliver the same artefact? | the layer bytes change |
| provenance record (store `provenance/` table) | Where did these bytes come from? | never — it is appended to, and lives BESIDE the manifest so re-stamping it cannot move the digest |
| blob digest (`sha256:…`) | Are these the bytes I asked for? | the bytes change (content addressing) |

The input digest uses the same token-canonical hashing as the src pin, but
over the artefact's own inputs; it is the per-artefact staleness signal and
the `workspace publish` work-list key. It is **not** a content address: it
covers the artefact's declared sources, not the toolchain or the catalog,
so two artefacts with different bytes can share one. When the question is
"is this the same artefact?", the layer digests answer it and the input
digest does not.

Provenance (`local-build` vs `published`, the git revision, the ci digest)
is a store-side table keyed by manifest digest, read by `fluxor store ls`
and `fluxor inspect` — see `docs/guides/publishing.md`. It is deliberately
not a manifest annotation: `source-rev` changes on every commit, so
stamping it into the manifest would rewrite the manifest and move the
digest every downstream `fluxor.lock` pins, whether or not a module had
changed.

## How a change propagates

```
edit modules/sdk/** or contracts/src/**
  → fluxor abi-regen            (rewrites the two pin sites)
  → cargo build                 (tools pick up the new constant)
  → fluxor publish              (artefacts stamped at the new epoch)
  → each sibling: fluxor update && fluxor sync
```

Until a sibling syncs, its `.fmod` files are rejected at load, and the sync
gate rejects its stale store artefacts: both are the same check from opposite
ends, the artefact's embedded epoch against the current surface. The cost of
an epoch move is paid per sibling catch-up, not per change — four surface
changes landed together cost each sibling the same single
`fluxor update && fluxor sync` as one would.

## When something fails

Every failure means the same thing (two things were built against different
surfaces), so the fix is nearly always the same:

```
fluxor abi-regen          # recompute the constants
fluxor modules build      # restamp artefacts against them
```

The messages you may see:

| Message | Gate |
|---|---|
| `built against a different ABI surface (module attests X, current is Y)` | pack/read |
| `mixed-epoch artifact set … run 'fluxor update' to advance the whole set` | sync |
| `carries no epoch annotation … run 'fluxor publish'` | sync |
| `ABI_SURFACE_DIGEST const … is stale — run 'fluxor abi-regen'` | pin freshness |

The one case that is *not* a stale pin is the spelled-out hex tripwire firing
on its own: that means the wire surface genuinely changed. Update the literal
only as part of that deliberate decision, and expect every already-built
`.fmod` and every pinned graph slot to stop matching — correctly.
