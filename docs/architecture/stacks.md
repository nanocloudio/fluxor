# Stacks

Source: `tools/src/stack_expand.rs`, `stacks/*.toml`, `tools/src/target.rs`
(platform stacks); `tools/src/stack.rs`, `tools/src/packaging.rs`,
`tools/src/store_cli.rs` (`publish stack`), `tools/src/store_resolve.rs`
(references), `tools/src/oci_store.rs` (`prepare_stack`) (published stacks)

## Overview

A stack is a set of modules and the wiring between them that a graph takes
in whole instead of writing out. There are two ways a stack enters a graph:

| | Platform stack | Published stack |
|---|---|---|
| Owned by | fluxor | any project |
| Lives in | `stacks/<name>.toml` in fluxor's catalog | `packaging/stack/<name>.yaml` in its owner's tree |
| Enters a graph by | `platform:` naming it | `include:` naming it, with an instance name |
| Selected by | matching the board and target | a file path, or its name |
| Parameterised by | board defaults and chained param sources | typed `params:` the includer binds |
| Reached through | the ports its variant injects | its named `exports:` |
| Distributed as | part of fluxor's catalog | an OCI artifact, `stack/<name>:<version>` |

A platform stack answers "what substrate does this board need": the `net`
stack is `virtio_net + ip` on qemu-virt and `rp1_gem + conn_guard + ip` on
a Pi 5, under one unchanged application graph. A published stack answers
"how is this subsystem composed": a storage node, a store replica, a
broker, shaped once by the project that owns it and instantiated by any
graph that wants one.

A graph may use both. Includes expand first, on the parsed graph, ahead of
platform stack expansion and placement, so platform stacks and every later
pass see an ordinary graph.

## Platform stacks

A graph YAML declares a `platform:` section naming the stacks it wants
(`net`, `audio`, `display`, `storage`, `pointer`, `keyboard`, `gamepad`,
`midi`, `debug`, `cli`); each stack is a profile file under `stacks/`
containing two kinds of injection block:

- `[[variant]]` — exclusive. Exactly one is selected by a
  specificity-scored match against board and target metadata (board name,
  phy, NIC). This answers "which driver / phy shape does this board use?".
- `[[overlay]]` — additive. Every overlay whose match predicate holds is
  applied on top of the variant (debug netconsole, pcap sink, and similar
  optional layers).

A selected variant injects concrete modules, wiring, params, and services
into the config before the ordinary generation pipeline runs. The `net`
stack, for example, injects `virtio_net + ip` on qemu-virt,
`cyw43 + wifi + ip` on pico2w, and `rp1_gem + conn_guard + ip` on pi5 —
three different substrate stacks under one unchanged application graph.
Board defaults (e.g. `net → {phy: wifi, nic: cyw43}`) come from the target
descriptor, so most configs need only name the stack.

Module params inside a stack resolve through chained sources: `env:VAR`
(environment), `user:KEY` (merged user platform fields), `host:PATH`
(`~/.config/fluxor/host.toml`), or a literal. The first source that
resolves wins; a trailing `|required` turns "nothing resolved" into a
build-time error so safety-critical params cannot fall back silently.

A project may override one platform stack by carrying its own
`stacks/<name>.toml`; every other name resolves to fluxor's catalog. The
catalog (`stacks/` and `targets/`) is fluxor's own; a project's
`fluxor publish` never sweeps it.

## Published stacks

A published stack is a parameterised piece of graph: modules, the wiring
between them, typed params and named exports. One project owns it; another
project's graph includes it by name, binds its params and wires to its
exports.

Applications compose sibling subsystems: a registry composes a storage
node, a control plane composes a store replica. A stack lets the owner of
the subsystem own its shape — which modules, of which types, wired how, with
which knobs, reachable through which ports — while the includer owns the
instance: the name it is known by, its param values, where it is placed and
what its exports connect to. The composer validates the result like any
other graph; neither side edits the other's text.

| | Owned by | Lives in |
|---|---|---|
| Modules, types, variants | stack | `modules:` |
| Internal wiring | stack | `wiring:` |
| Which knobs exist, their types and bounds | stack | `params:` |
| Which ports the outside may reach | stack | `exports:` |
| Instance name | includer | `include[].as` |
| Param values | includer | `include[].params` |
| Placement | includer | `include[].node` |
| What the exports connect to | includer | the graph's `wiring:` |
| Target, platform stacks, scheduler, domains | includer | the graph |

The rest of this document describes published stacks.

## The stack document

```yaml
stack: sealed_volume             # the name; marks the file as a stack
version: 0.1.0                   # the published version
description: A file-backed block device sealed by crypt_block.

params:
  image:
    type: string
    required: true
    example: volume.img
    description: The host file holding the sealed container.
  key:
    type: string
    required: true
    example: volume
    description: The vault label of the volume's master key.
  block_size:
    type: integer
    default: 512
    min: 512
    max: 4096

exports:
  blocks: seal.blocks            # an internal port the includer may wire
  status: seal.status

modules:
  - name: disk
    type: file_block
    path: ${param:image}
    block_size: ${param:block_size}
  - name: seal
    type: crypt_block
    key: ${param:key}
    block_size: ${param:block_size}

wiring:
  - from: disk.blocks
    to: seal.lower
```

A stack carries exactly these keys: `stack`, `version`,
`description`, `params`, `exports`, `modules`, `wiring`. A `target`,
`platform`, `scheduler`, `services`, `execution` or any other graph-wide
setting is refused, because it belongs to the graph that includes the
stack.

### Names

`stack:` is `[a-z][a-z0-9_-]*`, at most 64 bytes. It is a store tag
component, and it is ecosystem-unique: a name another project has
published into the store is refused. `version:` is a string (quote a numeric one) and is
required to publish. It is a store tag, `[A-Za-z0-9_][A-Za-z0-9._-]*` of at
most 128 bytes, and is never `latest`, which every publish moves.

### Params

Params are declared exactly as every graph's
([service-bundles.md](../guides/service-bundles.md#the-graph-and-its-params)),
with the same rules:

| Field | Meaning |
|---|---|
| `type` | `string`, `integer`, `boolean` or `file` |
| `required` | the includer must supply it; it then declares no `default` and declares an `example` |
| `default` | the value of an optional param; every optional param has one |
| `min`, `max` | inclusive bounds, integers only |
| `description` | shown when a required value is missing |
| `example` | the value a check without an includer renders with |

A param is referenced as `${param:<name>}` inside a module entry's values or
an edge's attributes. A scalar that is exactly one placeholder takes the
value's type (`block_size: ${param:block_size}` is an integer); a
placeholder inside other text interpolates, and a boolean may not appear
there. Substitution works on the parsed document, never its text, so a value
is data: it cannot open a mapping, add a module or add an edge.

The stack's shape takes no params. A module's `name`, `type` and
`variant`, every wiring endpoint and every export are literal. Every
placeholder must be declared, and every declared param must be used.

No graph is read against the environment, a stack included: a `${VAR}`
in one is refused. What a published stack means cannot depend on the
environment of whoever builds it; a value the includer's caller has is the
includer's own param, which it forwards.

### Exports

`exports:` maps an export name (`[a-z][a-z0-9_]*`) to one internal
`module.port`, or to a non-empty list of them. The includer can wire only
exports, so everything else stays private to the stack. An export
has no direction of its own. It stands for its endpoint, and the port's
manifest decides whether it can appear on the `from` or the `to` side of an
edge. A list fans an edge out: with `feed: [left.in, right.in]`, an edge
from `src.out` to `inst.feed` becomes one edge to each endpoint, each
carrying the edge's attributes. Each expanded edge is validated on its own,
so a list mixes no directions.

### Modules and wiring

Modules are the graph's module entries: a mapping with a `name`, an
optional `type` and `variant`, and the module's params. A bare name is
shorthand for `{ name: <name> }`. Names are unique and carry no `.`. A
module may not carry `node:`: where a stack runs is the includer's
decision.

Wiring is the graph's edge form, `{ from, to, … }`, and names only the
stack's own modules. A port outside the stack, such as the platform's
`linux_net.net_out`, is reached by exporting the internal port and letting
the includer wire it.

## Including a stack

```yaml
target: linux

include:
  - stack: sealed_volume.yaml      # a file path, relative to this graph
    as: data                       # the instance name
    params:
      image: data.img
      key: data
  - stack: sealed_volume           # by name
    as: scratch
    params: { image: scratch.img, key: scratch, block_size: 4096 }

modules:
  - name: fs
    type: fat32
  - name: log
    type: debug

wiring:
  - from: data.blocks              # <as>.<export>
    to: fs.blocks
  - from: data.status
    to: log.data
  - from: scratch.status
    to: log.data
```

An include entry carries `stack`, `as`, and optionally `params` and
`node`; any other key is refused.

- **`stack`** is a file path when it contains `/` or ends in `.yaml` or
  `.yml`, and is resolved against the including graph's directory. This is
  how tests and examples include fixtures. Otherwise it is a stack name:
  the project's own `packaging/stack/<name>.yaml`, else the stack its
  `fluxor.lock` pins under that name ([References](#references)).
- **`as`** is `[a-z][a-z0-9_]*`. It names the instance. It must differ from
  every other include's `as` and from every module name.
- **`params`** binds values. Every value is held to its declaration: an
  unknown name, a value of the wrong type, an out-of-bounds integer and a
  missing required value are all refused, together, naming the include. A
  `file` value is taken relative to the including graph and becomes the
  file's absolute path; the file must exist. A value that is exactly
  `${param:<x>}` forwards the including graph's own param `x`: it is
  accepted when the two are declared with the same type — integer to
  integer, string to string, boolean to boolean, file to file — and an
  integer's declared range lies inside the stack's, and it stays a
  placeholder the graph's values render. A value with a placeholder inside
  other text is a string. The forward is checked when the graph is read and
  when a bundle carrying it is emitted.
- **`node`** places the whole include (see [Placement](#placement)).

## Expansion

`include:` expands on the parsed graph before every other pass, ahead of
platform stack expansion and placement. Everything downstream sees an ordinary
graph:

1. Each include, in list order, loads its stack, resolves its values and
   substitutes them.
2. Each stack module is added as `<as>_<name>`, with `type:` set to its
   own type, or to its stack-local name when it had none. A name that
   collides with any module already in the graph, the graph's own or another
   include's, is refused. A `quarantine_partner` naming a stack
   module is renamed with it.
3. The stack's internal edges are added with their endpoints renamed,
   and their explicit buffer groups renumbered to the include's own
   ([Buffer groups](#buffer-groups)).
4. The graph's own edges are rewritten. An endpoint `<as>.<export>`
   becomes the export's internal endpoint or endpoints. An endpoint naming
   an export the stack does not declare is refused, listing the exports.
   An endpoint naming a stack-internal module directly
   (`data_disk.blocks`) is refused, naming the include whose export to use.
5. The `include:` key is removed.

The graph's own modules come first, then each include's modules in
declaration order. The graph's own edges, rewritten in place, come first,
then each include's internal edges. Expansion is a pure function of the
graph, the stack documents and the pins, so the same inputs give the
same module ids and edge order.

The expanded edges are ordinary edges. Content types, port directions,
required inputs, ring sizing and rate classes are checked by the same
validation as a hand-written edge. A content-type mismatch across the
include boundary is reported in the expanded names
(`content type mismatch: data_seal.status produces …`). `force: true` on
the includer's edge carries to every edge it expands to.

### Buffer groups

A stack may give its internal edges explicit `buffer_group:` numbers, a
mailbox edge's or an in-place chain's, as any graph may. Its numbers are its
own: in the including graph each distinct group a stack's wiring names is
renumbered to a group no one else in the graph holds, so it never joins the
includer's groups or another include's, a second include of the same stack
included. Edges that shared a group in the stack share one after it.

- A group whose number is free keeps it. A single include of a stack
  whose numbers the graph leaves free therefore keeps them.
- The rest, in ascending order, take the highest free groups, in ascending
  order. A group is free when the graph's own wiring does not name it and no
  earlier include holds it.
- Groups are numbered 1 to 31, the 5-bit field an edge carries. Renumbered
  groups stay at the top of the range, away from the in-place chains the
  build numbers up from 1; the framed edges it groups itself, numbered down
  from 31, skip every group the wiring names.
- An include whose groups outnumber the free ones is refused, naming the
  include and the groups held, never clamped. A stack edge whose group is
  not an integer from 0 to 31 is refused.

A placed include's edges belong to the graph that instantiates it on its
node, and are numbered there.

`fluxor build --check <graph>` runs the expansion and the full validation.
`fluxor build --check <stack>` checks a stack on its own: it parses,
and it renders with its defaults and examples; the `examples` phase of
`fluxor ci` checks an example stack that way. A stack's edges to
the outside are checked by the graphs that include it.

## Placement

`node: <name>` on an include places every module of the stack on that
node, as a placed member (`config::placement`). Each module is declared
with its `name`, `type`, `variant` and `node` only. Its params and the
stack's internal edges belong to the graph that instantiates it on that
node, and are not emitted here. The params are still resolved and checked,
because the instance is the includer's either way. An edge to a placed
include's export is refused: its members run on another node and are
reached over a remote channel, as any placed member is. Placement is
whole-include. A stack cannot split its own modules across nodes.

## Bundles

A workload bundle ([service-bundles.md](../guides/service-bundles.md)) carries
its graph with every include expanded. When the bundle is emitted, the graph
file is read as the build reads it — its includes resolved against the graph
file's own location and the project's pins — and the expanded graph, its
`params:` kept, is what `graph.yaml` holds and its digest pins. A bundle is
therefore whole without the stack files and pins its source tree held.

Everything read from the bundle reads the expanded graph: the module
references `workload.json` pins and the state sum `resources.json` carries
include the modules the includes contribute, and a run checks every module
the rendered graph loads against those references, so a stack's module
the bundle does not pin is refused rather than loaded unverified. A bundle
graph that still carries `include:` is refused. A placeholder the graph
forwards into an include survives the expansion for a run to render. A
graph without includes is carried as written.

## Publishing

A project's stacks are `packaging/stack/<name>.yaml`, each named for the
stack it holds, and publish with everything else it ships
([project-layout.md](../guides/project-layout.md)):

```sh
fluxor publish                    # sources, fmods, runtimes, stacks, bundles
fluxor publish --only stack       # just the stacks
fluxor publish --dry-run          # list what the sweep would publish
```

Stacks publish after the project's modules, whose digests they record, and
before its bundles, which may include them. `fluxor ci`'s `packaging` phase
checks each one as the publish does. A stack document anywhere else is not
published; a graph may still include it by path. Each stack is checked
before anything is written: a document that does not parse, declares no
`version`, is not at `packaging/stack/<name>.yaml`, or composes a module
that is neither the project's own, nor pinned, nor a kernel built-in
refuses the whole sweep.

One stack publishes on its own with:

```sh
fluxor publish stack packaging/stack/sealed_volume.yaml [--tag T] [--store DIR] [--published]
```

The publish:

1. Checks the document. It must be the project's
   `packaging/stack/<name>.yaml`, parse, declare a `version`, and render
   with its defaults and examples (a `file` example names a sample relative
   to the stack).
2. Resolves the stack's module references through the publishing
   project. For each distinct module type, it takes the project's own
   published modules (`<project>/meta:latest`), every target, or, failing
   that, the module pins of the project's `fluxor.lock`. A kernel built-in
   needs no reference. A type that resolves neither way is refused, because
   the stack would name a module no consumer could find.
3. Publishes one OCI artifact, kind `stack`, tagged
   `stack/<name>:<version>` and `stack/<name>:latest`, under the
   project its file belongs to, joining the project index in one
   transaction. `--tag` replaces the version tag and must name the same
   stack, `stack/<name>:<tag>`.

| Layer | Media type | Content |
|---|---|---|
| `stack.yaml` | `application/vnd.nanocloud.fluxor.stack.v1+yaml` | the document, byte for byte |
| `modules.json` | `application/vnd.nanocloud.fluxor.stack.modules.v1+json` | the module references, as `fluxor.lock` `[[artifact]]` entries |

A bundle carries the `.fmod` of every module it pins. A stack carries
references to the exact module artifacts, per target, it was composed
against. A stack is target-independent and is included by graphs for
any target, while a bundle is built for one. The modules are artifacts in
their own right, already in the store.

## References

A graph a project builds that includes a stack by name references it.
`fluxor update` pins every referenced stack from the dependency in
`[dependencies]` that publishes it — read from its project index,
`<dep>/meta:latest` — writing, in one locked lockfile update:

- the stack's own `[[artifact]]` entry (`kind = "stack"`), and
- each module reference it carries, as an ordinary module pin. The
  consumer's own modules are skipped because it builds those itself. A
  module the consumer already pins for the same target at another digest
  keeps the consumer's pin, with a note naming both digests, because one
  image carries one build of a module type.

A stack no graph references any more has no pin after the next update. A
name no dependency publishes, or two do, is refused, naming them; a pinned
document that names a stack other than the one its tag names is refused.
A project's own stacks are never pinned: a name the project ships resolves
to its `packaging/stack/<name>.yaml`.

The build reads a pinned stack from the store by its digest, verifying it,
and refuses one that composes a module the lockfile does not pin for that
target. The stack's modules resolve through the ordinary module pins, so
a build uses exactly the modules the stack was composed against unless
the consumer pinned its own. `fluxor sync` checks that each pinned stack's
layers are present and intact; there is nothing to materialise.

## Limits

- Params substitute values only. A variable set of keys, an optional
  module or a conditional edge is a different shape: publish it as a
  separate stack.
- A stack does not include other stacks, and carries no `services:`,
  `execution:` domains or other graph-wide sections. The includer sets
  those for the expanded modules by their prefixed names.
- Instance names prefix module names with `_` (`data_disk`), because `.`
  separates a module from its port in an endpoint. A collision that
  prefixing produces is refused, not renamed.
- Placement applies to a whole include.
