# fluxor Makefile — thin aliases over the `fluxor` CLI.
#
# Module discovery + per-target build is in `fluxor modules build`; the
# AST hygiene scan is in `fluxor lint hygiene`; the full CI gate is in
# `fluxor ci`. Project-specific targets (firmware, build-matrix, drift
# checks) sit alongside the standard set below.

SHELL       := /bin/bash
.SHELLFLAGS := -euo pipefail -c
CARGO       ?= cargo
FLUXOR      ?= target/aarch64-unknown-linux-gnu/release/fluxor
TARGET      ?= bcm2712

.DEFAULT_GOAL := build

# ── Standard targets ───────────────────────────────────────────────────

.PHONY: help build test fmt fmt-check clippy lint ci verify \
        modules modules-all modules-clean modules-list modules-resolve \
        up up-cluster clean setup \
        firmware firmware-all linux-bin tools install-rig-backends \
        targets init run flash all \
        check-no-inline-tests check-drift check-build-matrix check-stable

# `help` is zero-dependency: it must work before `fluxor` is installed.
help:
	@echo "fluxor make targets"
	@echo "  Standard surface:"
	@echo "    make build            host build"
	@echo "    make test             cargo test --workspace"
	@echo "    make fmt|fmt-check    rustfmt"
	@echo "    make clippy|lint      clippy + fmt-check"
	@echo "    make modules          PIC modules for TARGET=\$$(TARGET)"
	@echo "    make modules-all      modules for every target in fluxor.toml"
	@echo "    make up               render+run a single replica (CONFIG=, NODE_ID=)"
	@echo "    make up-cluster       spawn REPLICAS replicas"
	@echo "    make ci               full CI gate (fluxor ci)"
	@echo "    make clean            cargo clean + module artefacts"
	@echo "    make setup            install fluxor CLI onto PATH"
	@echo "  Registry:"
	@echo "    make publish               canonical publish of every publishable artefact"
	@echo "    make publish-local         same, content-hashed -local.<sha> suffix"
	@echo "    make publish-{abi,sdk,modules,common}[-local]   per-tier publish"
	@echo "    make update                regenerate fluxor.lock"
	@echo "    make sync[-dry]            install lockfile-resolved fmods locally"
	@echo "    make registry-init         bootstrap ~/.fluxor/registry/ + cargo git index"
	@echo "    make registry-list         inventory ~/.fluxor/registry/"
	@echo "    make registry-gc[-dry]     trim old -local/-live artefacts"
	@echo "    make registry-setup-cargo  add [registries.fluxor] to ~/.cargo/config.toml"
	@echo "    make workspace-status      show ~/.fluxor/workspace.toml state"
	@echo "  Project-specific:"
	@echo "    make firmware TARGET=…   bare-metal kernel build"
	@echo "    make linux-bin           Linux userspace binary"
	@echo "    make flash CONFIG=…      flash a graph to a USB-DFU target"
	@echo "    make targets             list available targets"

setup:
	$(CARGO) install --locked --path tools

# `build` / `test` / `clippy` run from `tools/` rather than the
# workspace root. The kernel's default features pull in embedded
# crates that don't compile on the host; cross-target kernel clippy
# lives in `fluxor ci`'s per-target matrix.
build:       ; cd tools && $(CARGO) build --all-targets
test:        ; cd tools && $(CARGO) test --all-targets --all-features
fmt:         ; $(CARGO) fmt --all
fmt-check:   ; $(CARGO) fmt --all -- --check
clippy:      ; cd tools && $(CARGO) clippy --all-targets --all-features -- -D warnings
lint:        fmt-check clippy

# ── Module CLI wrappers ────────────────────────────────────────────────
#
# Outputs land at `target/fluxor/$(SILICON_ID)/modules/<name>.fmod` — the
# canonical layout (standards/fluxor-modules.md §2) that the `combine` /
# `run` tooling, `fluxor sync`, and CI all read from.

modules: tools
	$(FLUXOR) modules build --target $(TARGET)

modules-all: tools
	$(FLUXOR) modules build --all

modules-clean: tools
	$(FLUXOR) modules clean

modules-list: tools
	@$(FLUXOR) modules list

modules-resolve: tools
	@$(FLUXOR) modules resolve --target $(TARGET)

# ── Registry publish wrappers ──────────────────────────────────────────
#
# Convention: explicit `-local` targets rather than a `LOCAL=1` flag.
# `publish` is canonical; `publish-local` produces `-local.<sha>`
# content-hashed artefacts for path/git override workflows.
# (Workspace mode bypasses publish entirely.)

# `make publish` is the one-stop "everything downstream needs" target.
# Builds module artefacts + the fluxor-linux runtime first, then
# publishes all four tiers (abi source, sdk source, fmod palette,
# runtime binary). Heavy but deterministic — incremental rebuilds
# make subsequent runs cheap.
publish: tools modules-all linux-bin publish-abi publish-sdk publish-modules publish-runtime
publish-local: tools modules-all linux-bin
	$(FLUXOR) publish --local
	$(FLUXOR) publish runtime --binary $(RUNTIME_BINARY) --local $(if $(HOST_TARGET),--host-target $(HOST_TARGET),)

publish-abi: tools
	$(FLUXOR) publish abi
publish-abi-local: tools
	$(FLUXOR) publish abi --local

publish-sdk: tools
	$(FLUXOR) publish sdk
publish-sdk-local: tools
	$(FLUXOR) publish sdk --local

publish-modules: tools
	$(FLUXOR) publish fmod
publish-modules-local: tools
	$(FLUXOR) publish fmod --local

# Runtime binary publish. The host-target defaults to rustc's host;
# override with HOST_TARGET=... for cross-compiled outputs.
HOST_TARGET ?=
RUNTIME_BINARY ?= fluxor-linux
publish-runtime: tools
	$(FLUXOR) publish runtime --binary $(RUNTIME_BINARY) $(if $(HOST_TARGET),--host-target $(HOST_TARGET),)
publish-runtime-local: tools
	$(FLUXOR) publish runtime --binary $(RUNTIME_BINARY) --local $(if $(HOST_TARGET),--host-target $(HOST_TARGET),)

# `publish-common` is a downstream-project target only — fluxor itself
# owns the SDK, not a project-local common crate. The recipe stays
# here so the standard `make publish-common` works in every fluxor-
# based project; in this repo it's an error path (fluxor has no
# `common/`).
publish-common: tools
	$(FLUXOR) publish common
publish-common-local: tools
	$(FLUXOR) publish common --local

# ── Registry maintenance ───────────────────────────────────────────────
#
# Inspect and trim `~/.fluxor/registry/`.

registry-init: tools
	$(FLUXOR) registry init

registry-list: tools
	@$(FLUXOR) registry list

registry-gc: tools
	$(FLUXOR) registry gc

registry-gc-dry: tools
	$(FLUXOR) registry gc --dry-run

registry-setup-cargo: tools
	$(FLUXOR) registry setup-cargo

# ── Lockfile ──────────────────────────────────────────────────────────
#
# `make update` re-resolves and rewrites `fluxor.lock` from
# `fluxor.toml` + registry state.

# `FEATURES` is a comma-separated list of features to activate when
# resolving the lockfile. Optional deps participate only when at
# least one active feature lists them under `[features]`.
FEATURES ?=
update: tools
	$(FLUXOR) update $(if $(FEATURES),--features $(FEATURES),)

# ── Sync ──────────────────────────────────────────────────────────────
#
# Install lockfile-resolved fmods into `target/fluxor/<target>/modules/`.
# Symmetric half of `make publish-modules`. Hash-verified, idempotent.

sync: tools
	$(FLUXOR) sync

sync-dry: tools
	$(FLUXOR) sync --dry-run

# ── Workspace mode ────────────────────────────────────────────────────
#
# `~/.fluxor/workspace.toml` lists colocated checkouts the CLI should
# treat as live source. Mode is positional (CWD-based);
# `workspace-status` is the inspection surface.

workspace-status: tools
	@$(FLUXOR) workspace status

# ── Run / cluster bring-up ─────────────────────────────────────────────

CONFIG  ?=
NODE_ID ?= 0

up: tools
	@if [ -z "$(CONFIG)" ]; then echo "Usage: make up CONFIG=examples/web_server/linux.yaml NODE_ID=0"; exit 1; fi
	$(FLUXOR) run $(CONFIG) --node-id $(NODE_ID)

REPLICAS ?= 3
up-cluster: tools
	@if [ -z "$(CONFIG)" ]; then echo "Usage: make up-cluster CONFIG=examples/cluster/linux.yaml REPLICAS=3"; exit 1; fi
	$(FLUXOR) up $(CONFIG) --replicas $(REPLICAS)

# ── Full CI gate ───────────────────────────────────────────────────────
#
# `make ci` delegates to `fluxor ci`. Every phase runs even when an
# earlier one fails; the summary at the end lists every failure and
# the exit code is non-zero on any failure.
ci: tools
	$(FLUXOR) ci

# Deprecated aliases for external CI entry-points; prefer `make ci`.
verify: ci
check-stable: ci

# ── clean ──────────────────────────────────────────────────────────────

clean:
	$(CARGO) clean
	rm -rf target/fluxor

# ─────────────────────────────────────────────────────────────────────────
# Project-specific targets — these sit alongside the standard set
# above and don't duplicate behaviour the CLI already owns.
# ─────────────────────────────────────────────────────────────────────────

# Per-target build configuration. The `firmware` recipe consults these;
# module per-target rustc flags live in `fluxor modules build`'s
# silicon-spec table now (replacing the old `MODULE_TARGET` / `MODULE_LD`
# / `MODULE_LINKER` / `MODULE_RUSTFLAGS` variables).
ifeq ($(TARGET),rp2040)
  RUST_TARGET    := thumbv6m-none-eabi
  CARGO_FEATURES := chip-rp2040
  SILICON_ID     := rp2040
else ifeq ($(TARGET),cm5)
  RUST_TARGET    := aarch64-unknown-none
  CARGO_FEATURES := board-cm5
  SILICON_ID     := bcm2712
else ifeq ($(TARGET),bcm2712)
  RUST_TARGET    := aarch64-unknown-none
  CARGO_FEATURES := chip-bcm2712
  SILICON_ID     := bcm2712
else ifeq ($(TARGET),wasm)
  RUST_TARGET    := wasm32-unknown-unknown
  CARGO_FEATURES := host-wasm
  SILICON_ID     := wasm
else
  RUST_TARGET    := thumbv8m.main-none-eabihf
  CARGO_FEATURES := chip-rp2350b
  SILICON_ID     := rp2350
endif

RELEASE_DIR  := target/$(RUST_TARGET)/release
FIRMWARE_ELF := $(RELEASE_DIR)/fluxor
FIRMWARE_BIN := target/$(TARGET)/firmware.bin

# ── Bare-metal firmware ────────────────────────────────────────────────

all: tools firmware-all modules-all linux-bin

firmware:
	@echo "Building firmware for $(TARGET) ($(RUST_TARGET))..."
ifeq ($(TARGET),wasm)
	$(CARGO) rustc --release --target $(RUST_TARGET) --no-default-features --features $(CARGO_FEATURES) --lib --crate-type=cdylib
else
	$(CARGO) build --release --target $(RUST_TARGET) --no-default-features --features $(CARGO_FEATURES)
endif
	@mkdir -p target/$(TARGET)
ifeq ($(TARGET),wasm)
	@cp $(RELEASE_DIR)/fluxor.wasm target/wasm/firmware.wasm
else ifeq ($(TARGET),bcm2712)
	@rust-objcopy -O binary $(FIRMWARE_ELF) $(FIRMWARE_BIN)
else ifeq ($(TARGET),cm5)
	@rust-objcopy -O binary $(FIRMWARE_ELF) $(FIRMWARE_BIN)
else
	@arm-none-eabi-objcopy -O binary $(FIRMWARE_ELF) $(FIRMWARE_BIN)
endif

firmware-all:
	$(MAKE) firmware TARGET=rp2350
	$(MAKE) firmware TARGET=rp2040
	$(MAKE) firmware TARGET=bcm2712
	$(MAKE) firmware TARGET=cm5

tools:
	@echo "Building tools..."
	$(CARGO) build --release -p fluxor-tools --target aarch64-unknown-linux-gnu

# Symlink rig backend executables into the discovery path used by
# `fluxor rig …`. Run after `make tools`.
RIG_BACKEND_DIR := $(if $(XDG_DATA_HOME),$(XDG_DATA_HOME),$(HOME)/.local/share)/fluxor/backends
RIG_BACKENDS    := telemetry-monitor_udp observe-https_load

# `observe-https_load` is feature-gated (pulls tokio + reqwest + rustls)
# so plain `make tools` doesn't carry async-HTTPS deps. Build it
# explicitly here so `install-rig-backends` finds it on the symlink path.
loadgen-backend:
	$(CARGO) build --release -p fluxor-tools --bin observe-https_load \
		--features observe-https-load --target aarch64-unknown-linux-gnu

install-rig-backends: tools loadgen-backend
	@mkdir -p $(RIG_BACKEND_DIR)
	@for b in $(RIG_BACKENDS); do \
		src=$(CURDIR)/target/aarch64-unknown-linux-gnu/release/$$b; \
		dst=$(RIG_BACKEND_DIR)/$$b; \
		if [ ! -x "$$src" ]; then \
			echo "install-rig-backends: $$src not built — run 'make tools' first" >&2; \
			exit 1; \
		fi; \
		ln -snf "$$src" "$$dst"; \
		echo "install-rig-backends: $$dst -> $$src"; \
	done

linux-bin: tools
	$(CARGO) build --release --bin fluxor-linux --no-default-features --features host-linux --target aarch64-unknown-linux-gnu

run: tools
	@if [ -z "$(CONFIG)" ]; then echo "Usage: make run CONFIG=examples/web_server/linux.yaml"; exit 1; fi
	$(FLUXOR) run $(CONFIG)

flash: tools
	@if [ -z "$(CONFIG)" ]; then echo "Usage: make flash CONFIG=examples/led_patterns/pico2w.yaml"; exit 1; fi
	$(FLUXOR) flash $(CONFIG)

targets: tools
	@$(FLUXOR) targets

init:
	git submodule update --init --recursive

# ── Migration aliases ──────────────────────────────────────────────────
#
# The historic standalone shell guards `check-no-inline-tests` and
# `check-drift` are now subsumed by `fluxor ci`. Aliases kept so any
# stray external scripts that still call them continue to work.
check-no-inline-tests: tools
	@$(FLUXOR) lint hygiene

check-drift:
	@if [ -x .context/drift/run.sh ]; then \
		.context/drift/run.sh; \
	else \
		echo "==> check-drift: no local drift checks installed (.context/drift/ absent)"; \
	fi

# Guard: every supported platform must build clean. Kernels only;
# module builds run through `fluxor modules build --all`. Kept as a
# project-specific target because `fluxor ci` doesn't cross-compile
# the kernel for every silicon target, only run host clippy.
check-build-matrix:
	@echo "==> build matrix ..."
	$(MAKE) linux-bin
	$(MAKE) firmware TARGET=wasm
	$(MAKE) firmware TARGET=rp2350
	$(MAKE) firmware TARGET=cm5
	@echo "==> build matrix: all 4 platforms green"
