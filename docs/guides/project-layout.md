# Project layout

Every fluxor project has one shape. What it ships lives under `packaging/`,
and only there; what it references by name is pinned from what it depends
on; and every graph, stack and bundle declares its params the same way.

Source: `tools/src/packaging.rs`, `tools/src/store_resolve.rs`
(`references`), `tools/src/params.rs`, `tools/src/makefile_lint.rs`.

```text
<project>/
  fluxor.toml   Makefile
  modules/                        fmods
  packaging/
    stack/<name>.yaml             published stacks
    service/<name>/workload.toml  service bundles (graph beside it)
    applet/<name>/workload.toml   applet (CLI) bundles
  …                               anything else: never published
```

## What a project ships

`fluxor publish` publishes, in dependency order:

1. source trees (`modules/common/**`, and fluxor's SDK and contracts);
2. fmods and runtimes;
3. stacks: `packaging/stack/*.yaml`, each named for the stack it holds;
4. bundles: `packaging/service/*/workload.toml` and
   `packaging/applet/*/workload.toml`, each directory named for its bundle.

One discovery finds 3 and 4, and `fluxor ci` checks exactly what it finds,
the way the publish reads it: stacks render, and bundles' graphs, includes
expanded and rendered with their params' defaults and examples, pass
`fluxor build --check`. A directory with its own `fluxor.toml` or `.fluxor`
is another project and ships its own. A stack document anywhere else is not
published, though any graph can include it by path. Example and test
graphs anywhere else are checked by the `examples` phase and the project's
tests, and never published.

`fluxor publish --only source|fmod|runtime|stack|bundle` narrows the sweep;
`fluxor publish --dry-run` lists everything it would publish and writes
nothing.

## References are the pins

A graph the project builds that includes `stack: <name>` references that
stack. A bundle the project runs by name from a script is declared in
`fluxor.toml`:

```toml
[dependencies]
storage = "0.1"

[uses]
bundles = ["object-store"]
```

`fluxor update` resolves every reference through the projects in
`[dependencies]` — their published indexes, `<dep>/meta:latest` — and
writes the pin: the stack with the module references it carries, or the
bundle. An update pins exactly the references the project makes, so a
name it stops referencing has no pin after the next update. Stack and
bundle names are unique across the ecosystem; a name two dependencies
publish, or none does, is refused with the reason. A name the
project ships itself resolves to its own `packaging/` and is never pinned.
`fluxor sync` verifies and materialises the pins. Module pins come from each
dependency's index.

## Params

A runnable graph, a stack and a bundle's graph each declare `params:` with
one schema — `type` (`string`, `integer`, `boolean`, `file`), `default`,
`required`, `min`, `max`, `description`, `example` — and name a value as
`${param:<name>}`. A bundle's params are its graph's.
[service-bundles.md](service-bundles.md) has the full rules.

```sh
fluxor run graph.yaml --param port=9100
fluxor build graph.yaml --param port=9100
fluxor run object-store --params store.toml
```

A graph may forward its own param into an include
(`block_size: ${param:size}`) when the two are declared with the same type,
an integer's range inside the stack's. A graph is never substituted against
the environment: `${VAR}` in a graph is refused; a value a caller has is a
`--param`.

## The Makefile

Every project, nested ones included, carries the standard Makefile, whose
lifecycle targets each delegate to the `fluxor` verb of the same name:
`make build` is `fluxor build`, `make publish` is `fluxor publish`. The
`makefile` phase of `fluxor ci` holds each one to it.
