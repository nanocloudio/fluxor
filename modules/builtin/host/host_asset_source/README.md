# host_asset_source

Linux-only built-in. Streams a host filesystem file as `OctetStream` on
its output port. Used by hosted media examples to feed encoded bytes
(JPEG, MP3, ROM dumps, …) into a codec without an SD/FAT32 chain.

## Configuration

| Param  | Type | Default          | Notes                        |
|--------|------|------------------|------------------------------|
| `path` | str  | (required)       | Filesystem path to the asset |

`path` carries `required = true` in the manifest, so omitting it from
the YAML fails the build with a clear message — there is no useful
default for "what file to stream."

```yaml
modules:
  - name: asset
    type: host_asset_source
    path: assets/test.jpg
```

The transparent `params: { ... }` wrapper is also accepted:

```yaml
- name: asset
  type: host_asset_source
  params:
    path: assets/test.jpg
```

The schema lives in `manifest.toml` `[[params]]`; the config tool packs
`path` into the kernel's TLV params stream alongside every other
built-in. See `docs/architecture/abi_layers.md` for the full
manifest-schema design.

## Behaviour

- Opens the file once at module-instantiation time. Subsequent steps
  emit chunks.
- Default chunk size: 1024 bytes (sized below the smallest channel
  ring buffer so writes never get rejected for being too large).
- On EOF: returns `Done` and stops emitting.
- On open failure: logs once, then no-ops every step.
