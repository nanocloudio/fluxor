# Running Fluxor

This guide brings up the smallest useful module graph on a Linux host
and smoke checks it. It is self-contained: the config is embedded
below and piped straight into `fluxor run` on stdin, so there is
nothing else to fetch.

Source: `tools/src/main.rs` (the `run` command), `src/platform/linux.rs`
(the hosted runtime), `modules/foundation/dns/mod.rs` (the module the
graph runs).

## Prerequisites

Follow the toolchain setup in the repository [README](../../README.md),
then build and install:

```sh
make build      # CLI, kernels, module palettes, and the Linux runtime
make install    # put the `fluxor` CLI on PATH
```

## Run

The graph is one `dns` module answering on UDP port 15353, wired to
the host network surface (`platform: net` provides the built-in
`linux_net` module). The single entry in its host table gives a query
something to resolve. Passing `-` as the config argument makes
`fluxor run` read the YAML from stdin, so the whole bring-up is one
shell command:

```sh
fluxor run - <<'EOF'
target: linux
tick_us: 1000

scheduler:
  accept_cycles: true

platform:
  net: {}

modules:
  - name: dns
    port: 15353
    ttl: 30
    host:
      - "fluxor.test=10.11.12.13"

wiring:
  - from: linux_net.net_out
    to: dns.net_in
  - from: dns.net_out
    to: linux_net.net_in
EOF
```

`fluxor run` compiles the YAML into a binary config, gathers the
module artefacts it names, and launches the `fluxor-linux` runtime on
the pair. Startup logs similar to these mean the graph is live:

```text
[... INFO fluxor_linux] [fluxor] linux platform boot
[... INFO fluxor::kernel::module::loader] [inst] loaded dns
[... INFO fluxor_linux] [inst] 2 of 2 modules loaded
[... INFO fluxor_linux] [sched] starting main loop, tick_us=1000
```

The scheduler also logs that it is accepting a two-module cycle:
`linux_net` and `dns` feed each other, which is why the config sets
`scheduler.accept_cycles`.

## Smoke check

From another terminal, resolve the name the graph carries:

```sh
dig +short @127.0.0.1 -p 15353 fluxor.test
# 10.11.12.13
```

or, without `dig`:

```sh
nslookup -port=15353 fluxor.test 127.0.0.1
# Name:    fluxor.test
# Address: 10.11.12.13
```

The answer comes from the running graph: the query enters through
`linux_net`, the `dns` module matches it against its host table, and
the response leaves the same way.

## Stopping

Ctrl+C in the terminal running `fluxor run` stops the runtime. Each
run is stateless; running the command again starts fresh.

## Richer graphs

The other guides in this directory cover composing larger graphs:
[foundation.md](foundation.md) describes the module palette this
graph drew on, and [publishing.md](publishing.md) covers packaging
modules for reuse. [docs/overview.md](../overview.md) indexes the
full doc set.
