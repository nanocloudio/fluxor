# Platform-tier modules

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
`build.rs` into `fluxor::platform::builtin_param_tags`, so the tag number
exists once rather than in two places that must agree.

`tools/tests/builtin_param_layout.rs` pins the released
`(module, name, type, tag)` set; changing a released row means updating
that table in the same commit.
