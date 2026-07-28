# fluxor Makefile — the lifecycle only: clean / build / test / lint /
# ci / publish / install (see ../standards/make.md). Anything else is the
# `fluxor` CLI invoked directly (`fluxor modules build`, `fluxor run`,
# `fluxor up`, `fluxor update`, `fluxor sync`, …) — a make target that
# merely renames one CLI command is bloat, not convenience.
#
# fluxor's workspace root is the bare-metal kernel and cannot build on
# the host with default features, so the lifecycle recipes substitute
# the equivalent per-target invocations for the standard's plain
# workspace ones — the target names and their meaning are unchanged.

SHELL       := /bin/bash
.SHELLFLAGS := -euo pipefail -c
CARGO       ?= cargo
FLUXOR      ?= target/aarch64-unknown-linux-gnu/release/fluxor
TARGET      ?= bcm2712

.DEFAULT_GOAL := build

.PHONY: help build test lint ci publish clean install \
        firmware secure-cm5 install-rig-backends

# `help` is zero-dependency: it must work before anything is built.
help:
	@echo "fluxor lifecycle:"
	@echo "  make build     everything: CLI, every kernel target, every module"
	@echo "                 palette, and the fluxor-linux runtime binary"
	@echo "  make test      tools tests + linux-runtime host tests"
	@echo "  make lint      rustfmt --check + clippy -D warnings"
	@echo "  make ci        fluxor ci — the full gate"
	@echo "  make publish   build, then publish every artefact tier"
	@echo "  make clean     cargo clean + module artefacts"
	@echo "  make install   CLI tools into ~/.cargo/bin (--locked --force,"
	@echo "                 reusing the workspace build cache)"
	@echo ""
	@echo "Project targets (genuine compositions):"
	@echo "  make firmware TARGET=…       one kernel: build + objcopy"
	@echo "                               (rp2040 | rp2350 | bcm2712 | cm5 | wasm)"
	@echo "  make secure-cm5              signature-enforced cm5 image"
	@echo "                               (keygen + build + sign + combine)"
	@echo "  make install-rig-backends    symlink rig backends into the"
	@echo "                               fluxor-rig discovery path"
	@echo ""
	@echo "Not make targets (use the CLI directly):"
	@echo "  fluxor modules build [--target …|--all]    PIC modules"
	@echo "  fluxor modules list|resolve|clean          module discovery"
	@echo "  fluxor run <cfg> [--node-id N]             single replica"
	@echo "  fluxor up <cfg> --replicas N               cluster bring-up"
	@echo "  fluxor flash <cfg>                         flash a USB-DFU target"
	@echo "  fluxor update [--features …]               regenerate fluxor.lock"
	@echo "  fluxor sync [--dry-run]                    install lockfile fmods"
	@echo "  fluxor publish <tier> [--local]            per-tier publish"
	@echo "  fluxor registry init|list|gc|setup-cargo   registry maintenance"
	@echo "  fluxor workspace status                    workspace-mode state"
	@echo "  fluxor targets                             list build targets"
	@echo "  .context/drift/run.sh                      local drift checks (if installed)"
	@echo ""
	@echo "One-time setup: make install"
	@echo "                git submodule update --init --recursive"

# ── Lifecycle ──────────────────────────────────────────────────────────

# The whole project: CLI first (module builds need it), then every
# module palette, every kernel, and the Linux runtime.
build:
	$(CARGO) build --release -p fluxor-tools --target aarch64-unknown-linux-gnu
	$(FLUXOR) modules build --all
	$(MAKE) firmware TARGET=rp2350
	$(MAKE) firmware TARGET=rp2040
	$(MAKE) firmware TARGET=bcm2712
	$(MAKE) firmware TARGET=cm5
	$(MAKE) firmware TARGET=wasm
	$(CARGO) build --release --bin fluxor-linux --no-default-features --features host-linux,host-playback --target aarch64-unknown-linux-gnu

# Install the CLI tools into ~/.cargo/bin. CARGO_TARGET_DIR reuses the
# workspace build cache (cargo install otherwise recompiles in a temp
# dir); --force overwrites same-version binaries so a rebuilt checkout
# always replaces the installed CLI — an installed `fluxor` that lags
# the checkout misbehaves silently.
install:
	CARGO_TARGET_DIR=target $(CARGO) install --locked --force --path tools --target aarch64-unknown-linux-gnu

# Tools tests, then the linux-runtime host tests. The runtime line
# canonicalizes flags that are easy to get wrong: the default cargo
# target is bare-metal (no `test` crate), so tests MUST name the host
# triple + linux features or they fail with E0463.
test:
	cd tools && $(CARGO) test --all-targets --all-features
	$(CARGO) test --release --bin fluxor-linux --no-default-features --features host-linux --target aarch64-unknown-linux-gnu

# The precise checks `fluxor ci`'s lint phase runs. Applying fixes is
# `cargo fmt --all`, typed directly. Kernel cross-target clippy lives
# in `fluxor ci`'s per-target matrix.
lint:
	$(CARGO) fmt --all -- --check
	cd tools && $(CARGO) clippy --all-targets --all-features -- -D warnings

ci:
	$(CARGO) build --release -p fluxor-tools --target aarch64-unknown-linux-gnu
	$(FLUXOR) ci

# Canonical publish of every publishable tier (abi source, sdk source,
# fmod palette, runtime binary — driven by fluxor.toml). Builds first
# so every artefact is current. `--local` / per-tier variants are CLI
# invocations (see help).
publish: build
	$(FLUXOR) publish

clean:
	$(CARGO) clean
	rm -rf target/fluxor

# ── Project-specific compositions ─────────────────────────────────────
#
# Held to standards/make.md §4: each composes build/environment
# knowledge that lives nowhere else.

# Per-target build configuration for the kernel. Module per-target
# rustc flags live in `fluxor modules build`'s silicon-spec table.
ifeq ($(TARGET),rp2040)
  RUST_TARGET    := thumbv6m-none-eabi
  CARGO_FEATURES := chip-rp2040
else ifeq ($(TARGET),cm5)
  RUST_TARGET    := aarch64-unknown-none
  CARGO_FEATURES := board-cm5
else ifeq ($(TARGET),bcm2712)
  RUST_TARGET    := aarch64-unknown-none
  CARGO_FEATURES := chip-bcm2712
else ifeq ($(TARGET),wasm)
  RUST_TARGET    := wasm32-unknown-unknown
  CARGO_FEATURES := host-wasm
else
  RUST_TARGET    := thumbv8m.main-none-eabihf
  CARGO_FEATURES := chip-rp2350b
endif

RELEASE_DIR  := target/$(RUST_TARGET)/release
FIRMWARE_ELF := $(RELEASE_DIR)/fluxor
FIRMWARE_BIN := target/$(TARGET)/firmware.bin

# Bare-metal kernel: cargo build + objcopy to a raw image, per-target
# toolchain knowledge that lives nowhere else.
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

# ── Secure (signature-enforced) cm5 image ──────────────────────────────
# Produces a bootable cm5 image that REJECTS unsigned/tampered modules at
# load: the kernel is built with `enforce_signatures` and the signing
# PUBLIC key embedded (`FLUXOR_SIGNING_PUBKEY_HEX`), every module is signed
# with the matching private seed, and the result is combined. Without this
# target the default cm5 build is permissive (unsigned modules load) — see
# docs/architecture/cm5_el0_isolation.md "Construction-phase trust boundary".
#
#   make secure-cm5                       # uses default key path + iso_transform demo
#   make secure-cm5 SECURE_CONFIG=examples/iso_probe/cm5.yaml
#   make secure-cm5 SIGN_KEY=/path/to.seed SECURE_IMG=/srv/tftp/fluxor/kernel_2712.img
#
# The private seed is generated (0600) on first run and reused thereafter;
# rotate with `fluxor keygen -k $(SIGN_KEY) --force`. Keep it OUT of git.
SIGN_KEY      ?= $(if $(XDG_CONFIG_HOME),$(XDG_CONFIG_HOME),$(HOME)/.config)/fluxor/signing/cm5.seed
SECURE_CONFIG ?= examples/iso_transform/cm5.yaml
SECURE_IMG    ?= target/cm5/secure.img

secure-cm5:
	$(CARGO) build --release -p fluxor-tools --target aarch64-unknown-linux-gnu
	@mkdir -p $(dir $(SIGN_KEY)) target/cm5
	@echo "[secure] resolving signing pubkey ($(SIGN_KEY))..."
	@PUBKEY=$$($(FLUXOR) keygen -k $(SIGN_KEY)) && \
	  echo "[secure] FLUXOR_SIGNING_PUBKEY_HEX=$$PUBKEY" && \
	  echo "[secure] building enforce_signatures firmware..." && \
	  FLUXOR_SIGNING_PUBKEY_HEX=$$PUBKEY $(CARGO) build --release \
	    --target aarch64-unknown-none --no-default-features \
	    --features board-cm5,enforce_signatures && \
	  rust-objcopy -O binary target/aarch64-unknown-none/release/fluxor target/cm5/firmware.bin && \
	  echo "[secure] building + signing modules..." && \
	  $(FLUXOR) modules build --target cm5 && \
	  for m in target/fluxor/bcm2712/modules/*.fmod; do \
	    $(FLUXOR) sign -k $(SIGN_KEY) "$$m" || exit 1; \
	  done && \
	  echo "[secure] combining $(SECURE_CONFIG) -> $(SECURE_IMG)..." && \
	  $(FLUXOR) combine -o $(SECURE_IMG) target/cm5/firmware.bin $(SECURE_CONFIG) && \
	  echo "[secure] done: $(SECURE_IMG) (unsigned/tampered modules will be rejected)"

# ── Rig backends ───────────────────────────────────────────────────────
# Symlink rig backend executables into the discovery path used by
# `fluxor rig …`. `observe-https_load` is feature-gated (tokio + reqwest
# + rustls) so the plain tools build doesn't carry async-HTTPS deps —
# it must be built explicitly with its feature before symlinking.
RIG_BACKEND_DIR := $(if $(XDG_DATA_HOME),$(XDG_DATA_HOME),$(HOME)/.local/share)/fluxor/backends
RIG_BACKENDS    := telemetry-monitor_udp observe-https_load observe-udp_capture

install-rig-backends:
	$(CARGO) build --release -p fluxor-tools --target aarch64-unknown-linux-gnu
	@mkdir -p $(RIG_BACKEND_DIR)
	@for b in $(RIG_BACKENDS); do \
		src=$(CURDIR)/target/aarch64-unknown-linux-gnu/release/$$b; \
		dst=$(RIG_BACKEND_DIR)/$$b; \
		ln -snf "$$src" "$$dst"; \
		echo "install-rig-backends: $$dst -> $$src"; \
	done
