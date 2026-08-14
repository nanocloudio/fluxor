# Gates and digests

One model underlies the whole verification system:

> **Artefacts carry content digests; gates check that what is on disk
> matches what the digests claim.**

Everything below is an instance of that. This page exists because the
model was previously reconstructible only from source, and a design that
lives only in code is one where every drift incident earns a new phase
instead of a rule inside an existing one.

## The digests

Five, each answering a different question. Confusing two of them is the
usual source of surprise.

| digest | question it answers | moves when |
|---|---|---|
| **ABI surface** (`ABI_SURFACE_DIGEST`, "the epoch") | *Can these bytes interoperate?* | the module↔kernel interface changes |
| **contracts/platform src pin** (`CONTRACTS_PLATFORM_SRC_HASH`) | — (an input to the epoch, not consulted alone) | any token under `modules/sdk/**` or `contracts/src/**` |
| **input digest** (`io.fluxor.input-digest`) | *Are these bytes current?* | any source the artefact is built from changes |
| **ci digest** (`io.fluxor.ci-digest`) | *Were these bytes built from a green tree?* | stamped by a full `fluxor ci`, annotated by `publish` when it still matches |
| **blob digest** (`sha256:…`) | *Are these the bytes I asked for?* | the bytes change (content addressing) |

### The epoch over-approximates, and that is fine

`ABI_SURFACE_DIGEST = sha256(139 enumerated (name, value) pairs ‖
CONTRACTS_PLATFORM_SRC_HASH)`.

The first half is precise — a constant walk, immune to refactoring. The
second is a **token hash over every file** in `modules/sdk/**` and
`contracts/src/**`, which over-approximates: adding a private helper
moves the epoch even though no wire byte, opcode or layout changed.

Comments and formatting are free (the hash is token-based), but nothing
else is, so in principle a structural edit that changes no interface
still costs every sibling a re-sync.

**Measured, and it does not happen in practice.** Of the last 18 commits
that moved the epoch, 17 touched a genuinely shape-defining file —
`contracts/src/**`, `modules/sdk/{abi,contracts,wire,fence}`. Exactly one
(`8c35896`) was implementation-only, and it changed no `pub` signature,
no `const`, no `#[repr]`.

So the over-approximation is real but nearly free: narrowing the hash to
public API shape would have avoided **one re-sync in eighteen**, in
exchange for a false-negative risk in the one mechanism that stops an
incompatible module loading. Not worth it. The volume statistic that
suggests otherwise — most *lines* under those trees are implementation —
measures code size, not what moves the digest.

The epoch moves often because the ABI is genuinely still changing. That
is a project-phase fact, not a design flaw, and the cost is bounded the
right way already: it is paid **per sibling catch-up, not per move**.
Four surface changes in one session cost each sibling the same single
`fluxor update && fluxor sync` as one would. Landing surface changes
together is the only lever, and it is a habit rather than a mechanism.

## The gates

`fluxor ci` runs every phase even after a failure, so one run surfaces
everything. The phases fall into four groups.

| group | phases | what a failure means |
|---|---|---|
| **build correctness** | `fmt-check`, `clippy`, `cargo-test` ×2, `modules-build`, `module-tests` | the code is wrong |
| **artefact integrity** | `abi-surface-pin`, `lockfile-consistency`, `live-staleness`, `version-skew` | a digest and the tree disagree |
| **standards conformance** | `makefile`, `fluxor-toml-schema`, `hygiene`, `workspace-lint-opt-in` | a written standard is being violated silently |
| **domain rules** | `observability`, `presentation`, `examples`, `template-render` | a domain invariant is broken |

The conformance group exists because prose does not enforce itself: each
phase was added after a standard drifted unnoticed across repos. That is
also its risk — four phases with four config surfaces doing the same
shape of work (read a declarative rule set, emit `file:line`). Prefer a
rule inside an existing phase over a new phase.

## No exemptions

Hygiene rules carry **no exemption mechanism**. A rule either applies or
is wrong, and the fix is to the rule:

- 30 `inline-tests` exemptions across five repos said the same sentence —
  *"this file is `#[path]`/`include!`-mounted into a host test, so the
  block does run"*. That was one missing predicate, not thirty judgement
  calls. The rule now derives it (`host_compiled_closure`) and every row
  is gone.
- An exemption suppresses a finding while the condition survives; the
  `tests/` shadow-guard row hid 198 files that were versioned nowhere,
  including the test that guarded a duplicated table.

`[[ci.lints.exemption]]` is the one survivor, and deliberately: cargo
forbids `lints.workspace = true` alongside per-lint overrides in one
table, so a host tool crate relaxing `print_stdout` has no other way to
say so. That is a rule a project can be right to break — the only case
this pattern is for.

## How a change propagates

```
edit modules/sdk/** or contracts/src/**
  → fluxor abi-regen            (rewrites the two pin sites)
  → cargo build                 (tools pick up the new const)
  → fluxor publish              (artefacts re-annotated at the new epoch)
  → each sibling: fluxor update && fluxor sync
```

`live-staleness` fails until publish; a sibling's `.fmod` files are
rejected at load until it syncs. Both are the same check from opposite
ends: the artefact's embedded epoch against the current surface.
