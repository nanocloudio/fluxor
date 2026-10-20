# Service bundles

A service bundle is a published `role = "service"` workload: a graph, the
`.fmod` of every module it loads, and the graph's typed params. A consumer
references it by name, and runs it with values, without wiring or reading
its graph. An applet bundle (`role = "cli"`) is the same artifact for a
program that takes argv instead of params.

Source: `tools/src/packaging.rs`, `tools/src/params.rs`,
`tools/src/workload_src.rs`, `tools/src/store_sync.rs`.

## Where a bundle lives

A project ships each bundle from its own directory under `packaging/`
([project-layout.md](project-layout.md)):

```text
packaging/service/<name>/workload.toml   role = "service"
packaging/applet/<name>/workload.toml    role = "cli"
```

The directory is named for the bundle, and its role matches the directory
it sits in. `fluxor publish` publishes exactly these and `fluxor ci`
checks exactly these.

## The source manifest

`workload.toml` carries identity only: the bundle's name, version and
role, and one `[[implementation]]` per target naming the graph beside it.

```toml
[workload]
name = "dns_service"
version = "0.1.0"
role = "service"

[[implementation]]
target = "linux"
graph = "linux.yaml"
```

The workload name is ASCII letters, digits, `.`, `_` and `-`, starting
with a letter or digit, at most 64 bytes: it becomes a directory name and a
store tag. `[workload] store_dir` names where the workload's control-plane
store lives, relative to the installed bundle unless absolute.
`[[export]]`, `[resources]` and `[health]` declare what the graph cannot:
an endpoint's binding, a capacity override, the health signals. Unknown
keys anywhere in the manifest are refused. A `[params]` table is refused
too: a bundle's params are its graph's.

## The graph and its params

The graph declares its params under `params:`, with the schema every graph
and stack uses, and names a value as `${param:<name>}`:

```yaml
target: linux

params:
  port:
    type: integer          # string | integer | boolean | file
    default: 15353
    min: 1                 # integer only, inclusive
    max: 65535
    description: UDP port the resolver answers on
  answer:
    type: string
    required: true
    example: 10.11.12.13   # required when the param is required
    description: IPv4 address served for service.test

modules:
  - name: dns
    port: ${param:port}                    # whole value: an integer node
    host:
      - "service.test=${param:answer}"     # inside text: interpolated
```

| Field | Meaning |
|---|---|
| `type` | `string`, `integer`, `boolean` or `file` |
| `required` | a caller must supply it; it then declares no `default` and declares an `example` |
| `default` | the value of an optional param; every optional param has one |
| `min`, `max` | inclusive bounds, integers only |
| `description` | shown when a required value is missing |
| `example` | the value a check renders with |

A `file` param is a path to a file the caller supplies — a CA bundle, a
certificate, a private key. It is always required and has no default: the
file is the caller's. Its `example` names a sample relative to the graph,
and the checks build with that sample. It renders as the file's absolute
path and goes where a module takes a path (`cert_file: ${param:cert}`,
`trust: "${file:${param:ca}}"`).

Param names are `[a-z][a-z0-9_]*`, at most 64 bytes. A default or example
of the wrong type or outside `min`/`max`, bounds on a non-integer,
`min > max`, more than 64 params, and strings over 4096 bytes or holding a
NUL byte are refused. Every placeholder is declared and every declared
param is referenced. Placeholders in mapping keys are refused.

Substitution runs on the parsed graph, never on its text. A scalar that is
exactly one placeholder becomes a typed node; a placeholder inside other
text is interpolated, and a boolean param may not appear there.
A value cannot add YAML structure, and a value is substituted once and
never rescanned. A graph is never read against the environment: a
`${VAR}` or `${VAR:-default}` in a graph is refused, naming `params:`.

An applet's graph declares no params: an applet takes argv.

`workload.json` carries `role` and the params. A graph that includes stacks
is carried with its includes expanded, its `params:` kept and every
placeholder it forwards into an include left for a run to render, so its
module references and state sum cover the stacks' modules
([stacks.md](../architecture/stacks.md#bundles)). A kernel built-in the
graph names (`cli_in`, `cli_out`, `linux_net`, …) is carried by every
runtime: the bundle pins no `.fmod` for it.

## Publish, reference, run

```sh
# producer
fluxor publish                    # every bundle under packaging/, with the rest
fluxor publish bundle packaging/service/dns_service/workload.toml

# consumer: fluxor.toml
#   [dependencies]
#   dns-producer = "0.1"
#   [uses]
#   bundles = ["dns_service"]
fluxor update
fluxor run dns_service --param port=15353 --param answer=10.1.2.3
fluxor run dns_service --params dns.toml --param port=15400
```

A bundle a project runs by name from a script — which no graph names — is
declared under `[uses] bundles` in `fluxor.toml`. That name is a reference:
`fluxor update` pins the bundle from the dependency in `[dependencies]` that
publishes it; a name the list does not hold has no pin after the next update. A name
two dependencies publish is refused as ambiguous. `fluxor sync` materialises
a pinned bundle, digest-verified, to:

```text
target/fluxor/bundles/<name>/
  workload.json  graph.yaml  resources.json
  modules/<module>.fmod
  .fluxor-sync-stamp
```

`fluxor run <name>` runs the project's own `packaging/` bundle of that name
when it ships one, else the bundle its `fluxor.lock` pins (materialising it
if `sync` has not). It also takes a bundle directory or a source manifest
path. The graph is rendered with the run's values and built against the
bundle's own `modules/` when it has them (a pinned, materialised bundle),
else the project's module directory; every module the bundle pins is
checked against its digest first, and a rendered graph that loads a module
the bundle does not pin is refused. The rendered graph and blobs live in a
private scratch directory under `target/fluxor/run/` that is removed when
the run ends. Its exit code is the run's.

`fluxor install <name>` registers an applet the same way: the project's
own, else the one it pins.

## Values

`--param name=value` is parsed by the declared type and may be repeated;
`--params <file.toml>` is one flat TOML table of `name = value` with typed
values. A `--param` overrides the file. A file param's path is relative to
the working directory when given by `--param`, and to the values file when
given in `--params`. Before anything is built, the run refuses an unknown
param (listing the declared ones), every missing required param (each
named), a type or range error, a file param naming no readable file, a
repeated `--param`, and any value given to a graph that declares no params.

The same flags run and build a plain graph: `fluxor run <graph.yaml>
--param k=v` and `fluxor build <graph.yaml> --param k=v` render the graph's
own `params:`, and a build given no values renders each default and refuses
a missing required param. A graph carrying an inline `scenario:` block is
still that graph and takes its values the same way; a `kind: scenario` file
composes graphs and takes none. `fluxor build --check` renders every param
with its default, else its example, and takes no values.

## The ci gate

`fluxor ci`'s `packaging` phase checks every bundle where the publish finds
it: its whole source manifest and its place, and each linux graph read as
the publish reads it — includes expanded, rendered with its params' defaults and examples —
through `fluxor build --check`. A project shipping services can list a
service e2e script in `[ci.test] scripts` that publishes, references, syncs
and runs the bundle against an isolated store and asserts the refusals;
`fluxor ci` hands every such script the CLI under test as `$FLUXOR_BIN`.
