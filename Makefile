# fluxor Makefile — the lifecycle only: help / build / test / lint /
# ci / publish / clean, plus `install` (this is the project that ships
# the CLI). See ../standards/make.md. Anything else is the `fluxor` CLI
# invoked directly (`fluxor modules build`, `fluxor run`, `fluxor
# update`, `fluxor sync`, …) — a make target that merely renames one CLI
# command is bloat, not convenience.
#
# Every lifecycle recipe is one delegation. The CLI verb reads the
# project's shape (root Cargo.toml, [ci.cargo] host_tools_crate,
# modules/ + [ci].targets, [ci.test] scripts, declared module
# harnesses, whether the cargo tree #[path]-mounts target/fluxor) and
# does what that shape implies — so there is no per-repo recipe body
# left to hand-write, and `make help` is generated (`fluxor help
# --make`). This is gate-enforced by `fluxor ci`'s `makefile` phase.

SHELL       := /bin/bash
.SHELLFLAGS := -euo pipefail -c
# `.cargo/config.toml` sets a bare-metal default target, so every host
# binary needs `--target` naming the build host explicitly. Asked, not
# assumed: a hard-coded triple silently cross-compiles on any other
# machine.
HOST_TRIPLE := $(shell rustc -vV | sed -n 's/^host: //p')
HOST_DIR    := target/$(HOST_TRIPLE)/release
LAUNCHER    ?= $(HOST_DIR)/fluxor-launcher
BINDIR      ?= $(if $(CARGO_HOME),$(CARGO_HOME),$(HOME)/.cargo)/bin
TARGET      ?= rp2350

.DEFAULT_GOAL := build

.PHONY: help build test lint ci publish clean install firmware

# ── Lifecycle ──────────────────────────────────────────────────────────

help:
	@fluxor help --make

build:
	fluxor build

test:
	fluxor test

lint:
	fluxor lint

ci:
	fluxor ci

publish:
	fluxor publish

clean:
	fluxor clean

# ── Project-specific compositions ─────────────────────────────────────
#
# Held to standards/make.md §4: each composes build/environment
# knowledge that lives nowhere else. Their bodies are plain invocations
# (§3): the per-target dispatch and the sign loop live in the scripts,
# where a conditional is allowed to live.

# What lives on PATH is the resolving LAUNCHER (Decision 8,
# registry_consolidation.md): every invocation resolves the CLI's
# `:latest` store artifact and execs its blob, so an installed copy can
# never lag a publish. The only failure mode left is the launcher being
# absent entirely — `make install` is the fix. CLI changes go live via
# `fluxor publish --only runtime` (or `fluxor workspace publish`), not
# reinstall.
#
# Bootstrap ONLY (Decision 8) — first build on an empty-store machine:
# build the tools CLI, the linux runtime, and the launcher; publish the
# CLI + fluxor-linux into the local OCI store with the freshly built
# tools binary (publish auto-includes the CLI for fluxor); install the
# resolving launcher as ~/.cargo/bin/fluxor. After this, every publish
# supersedes the CLI in place — there is nothing to reinstall.
# The launcher builds as `fluxor-launcher` and is copied onto PATH as
# `fluxor`, so it shares the workspace target dir with the CLI without
# either uplifting over the other.
#
# The `ln -snf` lines put the rig backends on the `fluxor rig` discovery
# path (dependencies.md §10a: one invariant artefact set — install
# always installs them). They point at the build outputs, so a later
# rebuild is picked up with no re-install.
install:
	cargo build --release -p fluxor-tools -p fluxor-launcher --target $(HOST_TRIPLE)
	cargo build --release --bin fluxor-linux --no-default-features --features host-linux,host-playback --target $(HOST_TRIPLE)
	$(HOST_DIR)/fluxor publish --only runtime
	install -D -m755 $(LAUNCHER) $(BINDIR)/fluxor
	@mkdir -p $(RIG_BACKEND_DIR)
	ln -snf $(CURDIR)/$(HOST_DIR)/telemetry-monitor_udp $(RIG_BACKEND_DIR)/telemetry-monitor_udp
	ln -snf $(CURDIR)/$(HOST_DIR)/observe-https_load   $(RIG_BACKEND_DIR)/observe-https_load
	ln -snf $(CURDIR)/$(HOST_DIR)/observe-udp_capture  $(RIG_BACKEND_DIR)/observe-udp_capture

RIG_BACKEND_DIR := $(if $(XDG_DATA_HOME),$(XDG_DATA_HOME),$(HOME)/.local/share)/fluxor/backends

# One kernel: build + objcopy to a raw boot image.
#   make firmware TARGET=rp2040   # rp2350 | rp2040 | qemu-virt | pi5 | wasm
firmware:
	@tools/firmware.sh $(TARGET)
