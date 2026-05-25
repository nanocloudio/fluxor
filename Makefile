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
# Outputs land at `target/$(SILICON_ID)/modules/<name>.fmod` — the
# layout `combine` / `run` tooling expects. The newer
# `target/fluxor/<silicon>/modules/` layout is reachable by dropping
# the `--out target` flag.

modules: tools
	$(FLUXOR) modules build --target $(TARGET) --out target

modules-all: tools
	$(FLUXOR) modules build --all --out target

modules-clean: tools
	$(FLUXOR) modules clean --out target

modules-list: tools
	@$(FLUXOR) modules list

modules-resolve: tools
	@$(FLUXOR) modules resolve --target $(TARGET) --out target

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
