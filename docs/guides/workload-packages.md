# Workload packages

A workload package is the source form of a workload, published from
`packaging/`. A service package is a published `role = "service"`
workload: a graph, the `.fmod` of every module it loads, and the graph's
typed params. A consumer references it by name, and runs it with values,
without wiring or reading its graph. An applet package (`role = "cli"`) is the same artifact for a
program that takes argv instead of params.

Source: `tools/src/packaging.rs`, `tools/src/params.rs`,
`tools/src/workload_src.rs`, `tools/src/store_sync.rs`.

## Where a package lives

A project ships each package from its own directory under `packaging/`
([project-layout.md](project-layout.md)):

```text
packaging/service/<name>/workload.toml   role = "service"
packaging/applet/<name>/workload.toml    role = "cli"
```

The directory is named for the package, and its role matches the directory
it sits in. `fluxor publish` publishes exactly these and `fluxor ci`
checks exactly these.

## The source manifest

`workload.toml` carries identity only: the package's name, version and
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
store tag. A workload that keeps state composes a `store` module in its
graph and names its directory with the `store` instance's `dir` param (a
`${param:<name>}` when a run chooses it); nothing in the environment moves it.
`[[export]]`, `[resources]` and `[health]` declare what the graph cannot:
an endpoint's binding, a capacity override, the health signals. Unknown
keys anywhere in the manifest are refused. A `[params]` table is refused
too: a package's params are its graph's.

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
`trust: ${param:ca}`; on a target that embeds credentials at build,
`trust: "${file:${param:ca}}"`). A `file` param is checked on the build host
that renders the graph; a credential a Linux module reads where it runs —
from a volume lent to a workload, say — is a `string` param holding its absolute path, or
an `{env: NAME}` binding in a workload image.

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
([stacks.md](../architecture/stacks.md#workload-packages)). A built-in the
graph names (`cli_in`, `cli_out`, `linux_net`, …) is part of every runtime
— a native module, or a host provider beside the runtime (`linux_net`'s
`fluxor-provider-net`): the package pins no `.fmod` for it.

## Publish, reference, run

```sh
# producer
fluxor publish                    # every package under packaging/, with the rest
fluxor publish package packaging/service/dns_service/workload.toml

# consumer: fluxor.toml
#   [dependencies]
#   dns-producer = "0.1"
#   [uses]
#   packages = ["dns_service"]
fluxor update
fluxor run dns_service --param port=15353 --param answer=10.1.2.3
fluxor run dns_service --params dns.toml --param port=15400
```

A package a project runs by name from a script — which no graph names — is
declared under `[uses] packages` in `fluxor.toml`. That name is a reference:
`fluxor update` pins the package from the dependency in `[dependencies]` that
publishes it; a name the list does not hold has no pin after the next update. A name
two dependencies publish is refused as ambiguous. `fluxor sync` materialises
a pinned package, digest-verified, to:

```text
target/fluxor/packages/<name>/
  workload.json  graph.yaml  resources.json
  modules/<module>.fmod  modules/<module>.toml
  .fluxor-sync-stamp
```

Each module comes with the `manifest.toml` it was published with
(`<module>.toml`), taken from the store's module artefact that carries those
bytes, so a run of the package resolves its modules from the package alone:
never from the `fluxor.lock` or tree of the project it is run in.

`fluxor run <name>` runs the project's own `packaging/` package of that name
when it ships one, else the package its `fluxor.lock` pins (materialising it
if `sync` has not). It also takes a package directory or a source manifest
path. The graph is rendered with the run's values and built against the
package's own `modules/`, which every emitted and materialised package
carries; every module the package pins is checked against its digest first,
and a rendered graph that loads a module the package does not pin is
refused. An installed applet is composed for the project it was installed
from (its signing key, target definition and Fluxor catalog), whichever
directory it is run in. Every run composes the image it runs
this way, against the runtime it runs: the image pins the host providers
beside that binary. The rendered graph and image live in a private per-user
directory (`$XDG_RUNTIME_DIR/fluxor-run/`, else `fluxor-run-<uid>` in the
system temporary directory), never in a project's tree, and are removed when
the run ends. Its exit code is the run's.

`fluxor install <name>` registers an applet the same way: the project's
own, else the one it pins.

## What `fluxor exec` gives an applet

An applet's graph is checked when its package is emitted, and every
`fluxor exec` composes its image as `fluxor run` does. Both of the applet's
streams are the program's: the composition prints nothing unless it fails,
or `-v` asks, and then on stderr. What belongs to the operator running it is
given to this run's copy of the image, never to the package:

- **A client identity.** Every client-mode `tls` that names no identity of
  its own (no `cert_file`, `key_file` or `identity_label`) is given the
  operator's: `--identity CERT,KEY` (DER files), else
  `$HOME/.config/<name>/client.der` and `client.key.der` when both exist.
  The key is taken by the key vault, so the applet's graph composes
  `key_vault` beside such a `tls`; one that does not is refused when the
  package is built, naming the instance.
- **A data directory.** A string param whose value is `${applet:data_dir}`,
  or begins with `${applet:data_dir}/`, is given the applet's own data
  directory: `$XDG_DATA_HOME/<name>` when that is an absolute path, else
  `$HOME/.local/share/<name>`, with no trailing separator. It is made, readable
  by its owner alone, the first time a run needs it; one that exists is kept
  as it is. `<name>` is the name the applet is executed under (its
  `fluxor install` name, else its package name). It is how an applet keeps
  state across runs, for example a `store` with
  `dir: "${applet:data_dir}/store"`. The resolved value must still fit what
  the module takes (`store` refuses a `dir` over 96 bytes when it is
  constructed).

`${applet:data_dir}` is the one applet placeholder, and only an applet's
graph may name it: built from a `role = "cli"` package's `workload.toml`
(`fluxor build`, `fluxor install`, `fluxor exec` or the publish that emits
it). A graph built any other way — a service, an example, the applet's graph
file built on its own — that names it is refused at build.

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

`fluxor ci`'s `packaging` phase checks every package where the publish finds
it: its whole source manifest and its place, and each linux graph read as
the publish reads it — includes expanded, rendered with its params' defaults and examples —
through `fluxor build --check`. A project shipping services can list a
service e2e script in `[ci.test] scripts` that publishes, references, syncs
and runs the package against an isolated store and asserts the refusals;
`fluxor ci` hands every such script the CLI under test as `$FLUXOR_BIN`.
