# Platform-layer modules

Linux-host and wasm/browser built-ins. Their implementations are compiled
into the kernel (`builtin = true`); the `manifest.toml` here is the
declaration.

## Parameter tags

Every `[[params]]` entry declares an explicit `tag = N`, in
`10..=239`. The tag — not the entry's position in the file — is the
parameter's identity on the wire: a built-in receives its configuration as
a TLV blob keyed by tag, and the platform decodes it by tag.

Consequences:

- A tag is permanent once the built-in ships. Renaming a parameter,
  changing its type, or moving its tag re-points every deployed
  configuration that carries it.
- A retired parameter's tag is retired with it. Reusing the number makes
  an old config decode as the new field.
- `[[params]]` entries may be reordered or inserted freely; nothing about
  the encoding depends on the order.
- Duplicate, reserved, and out-of-range tags are rejected when the
  manifest is parsed, naming the manifest and the parameter.

The platform-side constants are generated from these manifests by
`fluxor abi-regen` into `crates/fluxor-abi/src/platform/native.rs`
(`abi::platform::native::<platform>::<name>`), so the tag number exists
once rather than in two places that must agree.

The released `(module, name, type, tag)` set is pinned in CI: a
released row changes only by updating the pin in the same commit.

## State

A built-in the kernel instantiates declares the state its instance takes
from the kernel's state arena, in 64-byte units: `state_bytes_64`. It is
generated as `STATE_BYTES` beside the name hash. The platform's vtable takes
exactly that (a compile-time assertion holds it to the instance's real state
type), and `fluxor build` charges the instance exactly that against the state
arena, by the arena's carve rule (`contracts/src/state_arena.rs`). A
manifest that describes a built-in the kernel does not instantiate as a graph
module (a boot-time provider backend) declares none, and a graph naming it is
refused at build.

A wasm native that seats a module heap for its instance states it in
`[capacities]`: `heap_seat`, the bytes before any scaling (at least what its
instance needs, which a compile-time assertion holds), `heap_seat_per_pixel`,
bytes per pixel of its `width` x `height` params, and `heap_seat_param`, the
tag of a param whose value is bytes the heap adds (its default when unset).
`fluxor abi-regen` emits them as `HEAP_SEAT`; the kernel seats exactly
`fluxor_contracts::state_arena::heap_seat_bytes` of it for the instance's
params, and the build charges the same.
