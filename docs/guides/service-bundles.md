# Service bundles

A service bundle is a published `role = "service"` workload: a graph
template, the `.fmod` of every module it loads, and a typed parameter
schema. A consumer pins it in `fluxor.lock` and runs it with values,
without wiring or reading its graph.

Source: `tools/src/service_params.rs`, `tools/src/workload_src.rs`,
`tools/src/store_sync.rs`.

## The source manifest

```toml
[workload]
name = "dns_service"
version = "0.1.0"
role = "service"

[[implementation]]
target = "linux"
graph = "linux.yaml"

[params.port]
type = "integer"          # string | integer | boolean
default = 15353
min = 1                   # integer only, inclusive
max = 65535
description = "UDP port the resolver answers on"

[params.answer]
type = "string"
required = true
example = "10.11.12.13"   # required when the param is required
description = "IPv4 address served for service.test"
```

A param is optional with a `default`, or `required = true` with an
`example` and no default. Param names are `[a-z][a-z0-9_]*`, at most 64
bytes. The workload name is ASCII letters, digits, `.`, `_` and `-`,
starting with a letter or digit, at most 64 bytes: it becomes a
directory name and a store tag. Unknown keys anywhere in the manifest,
a default or example of the wrong type or outside `min`/`max`, bounds
on a non-integer, `min > max`, more than 64 params, and strings over
4096 bytes or holding a NUL byte are all refused at emit. `role` is
`service` (the default) or `cli`; an applet (`role = "cli"`) takes
argv and may not declare `[params]`.

## The graph template

A graph names a param as `${param:<name>}`:

```yaml
modules:
  - name: dns
    port: ${param:port}            # whole value: becomes an integer node
    host:
      - "service.test=${param:answer}"   # inside text: interpolated
```

Substitution runs on the parsed graph, never on its text. A scalar
that is exactly one placeholder becomes a typed node; a placeholder
inside other text is interpolated, and only string and integer
params may appear there. A value therefore cannot add YAML structure,
and it cannot be read as an environment reference: `${VAR}`
substitution runs on the template first, as on every graph, and
leaves `${param:...}` alone. A value is substituted once and never
rescanned, so a value that itself reads `${param:other}` or `${HOME}`
stays literal text. Placeholders in mapping keys are refused. Every
placeholder must be declared and every declared param must be
referenced.

`workload.json` carries `role` and the schema (`params`); the graph
digest it pins is the template's.

## Publish, pin, sync, run

```sh
# producer
fluxor publish bundle packaging/service/dns_service/workload.toml

# consumer
fluxor store pin dns_service:latest
fluxor sync
fluxor run dns_service --param port=15353 --param answer=10.1.2.3
fluxor run dns_service --params dns.toml --param port=15400
```

`publish bundle` takes a source manifest or a bundle directory. The
bundle carries the `.fmod` bytes it pins (each must hash to the pinned
digest), is annotated with its project and ABI epoch, and joins the
project index. `fluxor sync` materialises a pinned bundle,
digest-verified, to:

```
target/fluxor/bundles/<name>/
  workload.json  graph.yaml  resources.json
  modules/<module>.fmod
  .fluxor-sync-stamp
```

`fluxor run <name>` resolves a bundle `fluxor.lock` pins (materialising
it if `sync` has not), or takes a bundle directory or source manifest
path. The template is rendered with the run's values and built against
the bundle's own `modules/` when it has them (a pinned, materialised
bundle), else the project's module directory; every module the bundle
pins is checked against its digest first, and a rendered graph that
loads a module the bundle does not pin is refused. The rendered graph
and blobs live in a private scratch directory under `target/fluxor/run/`
that is removed when the run ends. `fluxor-linux` is launched as for any
bundle; its exit code is the run's.

`--param name=value` is parsed by the declared type and may be
repeated; `--params <file.toml>` is one flat TOML table of
`name = value` with typed values. A `--param` overrides the file.
Before anything is built, the run refuses an unknown param (listing
the declared ones), a missing required param, a type or range error,
a repeated `--param`, and any value given to a bundle that declares
no params.

`fluxor update` carries bundle pins forward to `<name>:latest`.

## The ci gate

`fluxor ci`'s `service-bundles` phase checks every service source
manifest at `packaging/service/workload.toml`,
`packaging/service/<name>/workload.toml`, or a `workload.toml` in an
example's own directory: the schema, the placeholder
references, and each linux graph rendered with its defaults and
examples through `fluxor build --check`. A project shipping services
can list a service e2e script in `[ci.test] scripts` that publishes,
pins, syncs and runs the bundle against an isolated store and asserts
the refusals; `fluxor ci` hands every such script the CLI under test as
`$FLUXOR_BIN`. The `examples` phase skips a service's graph templates,
since only a run supplies their values.
