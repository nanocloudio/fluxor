# ABI Surface Digest

Fluxor has no ABI version numbers. There is one surface, and the rule is that
the latest one is the only one — no compatibility windows, no negotiation. So
the only way to know that a module and a kernel agree is to hash everything
they must agree on and compare the hashes.

That hash is the **ABI surface digest**. Equality means compatible. That is the
whole idea; everything below is mechanism.

## What goes into it

```
digest = sha256( every ABI constant, as name\0value pairs
               + CONTRACTS_PLATFORM_SRC_HASH )
```

Two inputs, because the two halves of the surface are knowable in different
ways:

- **The constants** — contract ids, opcodes, permission bits, wire sizes, fd
  tags — are enumerated by `for_each_field` in `modules/sdk/abi_surface.rs`.
  Names are hashed alongside values, so two constants swapping values changes
  the digest. That list is **append-only**: a retired allocation keeps its
  entry rather than being deleted, or every later digest would shift.
- **`CONTRACTS_PLATFORM_SRC_HASH`** — a hash of the contract and platform
  *source files*. Wire-struct layouts and opcode name-hashes exist only as
  source; no walk over constants can see them, so that half is folded in as a
  source hash.

## The two constants are not two copies

They live adjacent in `modules/sdk/abi_surface_srcpin.rs`, which makes them
look like a pair. They are an input and an output:

| Constant | Role | Why it must be a constant |
|---|---|---|
| `CONTRACTS_PLATFORM_SRC_HASH` | **ingredient** — read *inside* `write_surface` | The kernel computes its own digest at boot, on bare metal, with no filesystem to hash source files from |
| `ABI_SURFACE_DIGEST` | **result** — embedded by every PIC module as `FLUXOR_ABI_SURFACE` | It is the module's attestation stamp, in `no_std` code |

Neither can be derived away at build time. PIC modules compile through direct
`rustc` invocations with no `--extern` flags at all, so `abi_surface.rs` may
use `core` and nothing else — a const-evaluated SHA-256 would mean carrying a
second hash implementation in the SDK to delete one cached value. Not a good
trade.

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
                └──► every graph slot   (stamped at build time)
```

`abi-regen` writes two files. Everything else is stamped automatically from
`ABI_SURFACE_DIGEST` as artefacts are produced.

## The four gates

Every check asks one question — *were these two things built against the same
surface?* — at four different moments:

| Gate | Where | Catches |
|---|---|---|
| **Pack / read** | `modules.rs::verify_module_abi_surface` | an `.fmod` whose stamp differs from the CLI's digest |
| **Boot** | `kernel/boot/config.rs::decode_slot_header` | a graph slot that doesn't match the running kernel |
| **Sync** | `sync.rs::unloadable` | staging an artefact that could never load |
| **CI** | `fluxor abi-regen --check`, plus the two locks | the *constants themselves* having gone stale |

The first three compare two artefacts. The fourth checks that the checked-in
constants still match what the source computes — the only gate about the cache
rather than about compatibility.

## The two locks, and why there are two

`abi_surface.rs` is `#[path]`-mounted into two different crates: the host tools
and the kernel. Both must compute the same digest, or an artefact stamped by
the CLI would be rejected by a kernel that disagrees about the surface.

- `tools/src/hash.rs::abi_surface_digest_is_locked` — tools mount vs the
  constant, **plus** the one spelled-out digest hex in the tree. That literal is
  the deliberate tripwire: it fails on *any* surface change, so a wire break has
  to be an explicit decision rather than a quiet consequence.
- `tests/harness/tests/abi_surface_digest.rs` — kernel mount vs the same
  constant.

Both compare against `ABI_SURFACE_DIGEST`, so transitively the two mounts agree
without either restating the digest. If **both** fail, the surface changed —
intended or not. If **one** fails, the two mounts have forked, and the fix is
the mount, never the constant.

## When something fails

Every one of these means the same thing — two things were built against
different surfaces — so the fix is nearly always the same:

```
fluxor abi-regen          # recompute the constants
fluxor modules build      # restamp artefacts against them
```

The messages you may see:

| Message | Gate |
|---|---|
| `built against a different ABI surface (module attests X, current is Y)` | pack/read |
| `ABI-surface pin STALE — run 'fluxor abi-regen'` | CI |
| `attests ABI surface X, current is Y` | sync |
| `ABI_SURFACE_DIGEST const … is stale` | tools lock |
| `the kernel's mount … computes a different digest` | harness lock |

The one case that is *not* a stale pin is the tools lock's hex tripwire firing
on its own: that means the wire surface genuinely changed. Update the literal
only as part of that deliberate decision, and expect every previously built
`.fmod` and every pinned graph slot to stop matching — correctly.
