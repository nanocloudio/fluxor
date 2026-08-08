# fluxor Makefile — the lifecycle only: clean / build / test / lint /
# ci / publish / install (see ../standards/make.md). Anything else is the
# `fluxor` CLI invoked directly (`fluxor modules build`, `fluxor run`,
# `fluxor run --replicas`, `fluxor update`, `fluxor sync`, …) — a make target that
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
LAUNCHER    ?= target/aarch64-unknown-linux-gnu/release/fluxor-launcher
BINDIR      ?= $(if $(CARGO_HOME),$(CARGO_HOME),$(HOME)/.cargo)/bin
TARGET      ?= qemu-virt

.DEFAULT_GOAL := build

.PHONY: help build test lint ci publish clean install firmware secure-pi5

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
	@echo "  make install   bootstrap only: build tools + runtime + launcher,"
	@echo "                 publish the CLI/runtime into the local OCI store,"
	@echo "                 install the resolving launcher as ~/.cargo/bin/fluxor,"
	@echo "                 and symlink the rig backends into the fluxor-rig"
	@echo "                 discovery path. If no 'fluxor' is on PATH, run it."
	@echo ""
	@echo "Project targets (genuine compositions):"
	@echo "  make firmware TARGET=…       one kernel: build + objcopy"
	@echo "                               (rp2350 | rp2040 | qemu-virt | pi5 | wasm)"
	@echo "  make secure-pi5              signature-enforced pi5 image"
	@echo "                               (keygen + build + sign + combine)"
	@echo ""
	@echo "Not make targets (use the CLI directly):"
	@echo "  fluxor modules build [--target …|--all]    PIC modules"
	@echo "  fluxor modules list|resolve|clean          module discovery"
	@echo "  fluxor run <cfg> [--node-id N]             single replica"
	@echo "  fluxor run <cfg> --replicas N               cluster bring-up"
	@echo "  fluxor flash <cfg>                         flash a USB-DFU target"
	@echo "  fluxor update [--from snapshot/<name>]     advance fluxor.lock pins"
	@echo "  fluxor sync [--dry-run]                    materialise fluxor.lock"
	@echo "  fluxor publish [--only source|fmod|runtime]  publish to the OCI store"
	@echo "  fluxor store ls|rm|pin|snapshot            store maintenance"
	@echo "  fluxor workspace status|publish|add|rm     live-workspace policy"
	@echo "  fluxor inspect [cfg|uf2|store-ref]         project / artifact info"
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
	$(MAKE) firmware TARGET=qemu-virt
	$(MAKE) firmware TARGET=pi5
	$(MAKE) firmware TARGET=wasm
	$(CARGO) build --release --bin fluxor-linux --no-default-features --features host-linux,host-playback --target aarch64-unknown-linux-gnu

# What lives on PATH is the resolving LAUNCHER (Decision 8,
# registry_consolidation.md): every invocation resolves the CLI's
# `:latest` store artifact and execs its blob, so an installed copy can
# never lag a publish. The only failure mode left is the launcher being
# absent entirely — `make install` (help text) is the fix. CLI changes
# go live via `$(FLUXOR) publish --only runtime` (or `fluxor workspace
# publish`), not reinstall.
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
install:
	$(CARGO) build --release -p fluxor-tools -p fluxor-launcher --target aarch64-unknown-linux-gnu
	$(CARGO) build --release --bin fluxor-linux --no-default-features --features host-linux,host-playback --target aarch64-unknown-linux-gnu
	$(FLUXOR) publish --only runtime
	install -D -m755 $(LAUNCHER) $(BINDIR)/fluxor
	@mkdir -p $(RIG_BACKEND_DIR)
	ln -snf $(CURDIR)/target/aarch64-unknown-linux-gnu/release/telemetry-monitor_udp $(RIG_BACKEND_DIR)/telemetry-monitor_udp
	ln -snf $(CURDIR)/target/aarch64-unknown-linux-gnu/release/observe-https_load   $(RIG_BACKEND_DIR)/observe-https_load
	ln -snf $(CURDIR)/target/aarch64-unknown-linux-gnu/release/observe-udp_capture  $(RIG_BACKEND_DIR)/observe-udp_capture

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

# Publish every artifact kind into the local OCI store (source trees,
# fmod palette, runtime binaries + the CLI — driven by fluxor.toml).
# Builds first so every artifact is current. `--only <kind>` variants
# are CLI invocations (see help).
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
else ifeq ($(TARGET),pi5)
  RUST_TARGET    := aarch64-unknown-none
  CARGO_FEATURES := board-pi5
else ifeq ($(TARGET),qemu-virt)
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
else ifeq ($(TARGET),qemu-virt)
	@rust-objcopy -O binary $(FIRMWARE_ELF) $(FIRMWARE_BIN)
else ifeq ($(TARGET),pi5)
	@rust-objcopy -O binary $(FIRMWARE_ELF) $(FIRMWARE_BIN)
else
	@arm-none-eabi-objcopy -O binary $(FIRMWARE_ELF) $(FIRMWARE_BIN)
endif

# ── Secure (signature-enforced) pi5 image ──────────────────────────────
# Produces a bootable pi5 image that REJECTS unsigned/tampered modules at
# load: the kernel is built with `enforce_signatures` and the signing
# PUBLIC key embedded (`FLUXOR_SIGNING_PUBKEY_HEX`), every module is signed
# with the matching private seed, and the result is combined. Without this
# target the default pi5 build is permissive (unsigned modules load) — see
# .context/pi5_el0_isolation.md "Construction-phase trust boundary".
#
#   make secure-pi5                       # uses default key path + iso_transform demo
#   make secure-pi5 SECURE_CONFIG=examples/iso_probe/pi5.yaml
#   make secure-pi5 SIGN_KEY=/path/to.seed SECURE_IMG=/srv/tftp/fluxor/kernel_2712.img
#
# The private seed is generated (0600) on first run and reused thereafter;
# rotate with `fluxor modules keygen -k $(SIGN_KEY) --force`. Keep it OUT of git.
SIGN_KEY      ?= $(if $(XDG_CONFIG_HOME),$(XDG_CONFIG_HOME),$(HOME)/.config)/fluxor/signing/pi5.seed
SECURE_CONFIG ?= examples/iso_transform/pi5.yaml
SECURE_IMG    ?= target/pi5/secure.img

secure-pi5:
	$(CARGO) build --release -p fluxor-tools --target aarch64-unknown-linux-gnu
	@mkdir -p $(dir $(SIGN_KEY)) target/pi5
	@echo "[secure] resolving signing pubkey ($(SIGN_KEY))..."
	@PUBKEY=$$($(FLUXOR) keygen -k $(SIGN_KEY)) && \
	  echo "[secure] FLUXOR_SIGNING_PUBKEY_HEX=$$PUBKEY" && \
	  echo "[secure] building enforce_signatures firmware..." && \
	  FLUXOR_SIGNING_PUBKEY_HEX=$$PUBKEY $(CARGO) build --release \
	    --target aarch64-unknown-none --no-default-features \
	    --features board-pi5,enforce_signatures && \
	  rust-objcopy -O binary target/aarch64-unknown-none/release/fluxor target/pi5/firmware.bin && \
	  echo "[secure] building + signing modules..." && \
	  $(FLUXOR) modules build --target bcm2712 && \
	  for m in target/fluxor/bcm2712/modules/*.fmod; do \
	    $(FLUXOR) sign -k $(SIGN_KEY) "$$m" || exit 1; \
	  done && \
	  echo "[secure] combining $(SECURE_CONFIG) -> $(SECURE_IMG)..." && \
	  $(FLUXOR) combine -o $(SECURE_IMG) target/pi5/firmware.bin $(SECURE_CONFIG) && \
	  echo "[secure] done: $(SECURE_IMG) (unsigned/tampered modules will be rejected)"

# ── Rig backends ───────────────────────────────────────────────────────
# Discovery path `fluxor rig …` probes for backend executables; `install`
# symlinks the three backends there (dependencies.md §10a: one invariant
# artefact set — install always installs them). All three build
# unconditionally with the plain tools build (dependencies.md §9a), and
# the links point at the build outputs, so a later rebuild is picked up
# with no re-install.
RIG_BACKEND_DIR := $(if $(XDG_DATA_HOME),$(XDG_DATA_HOME),$(HOME)/.local/share)/fluxor/backends
