# Fluxor Makefile -- Multi-target firmware, PIC modules, host tools
#
# Usage:
#   make                           Build tools + firmware + modules (default: rp2350)
#   make firmware TARGET=rp2040    Build firmware for a specific target
#   make firmware-all              Build firmware for all targets
#   make modules TARGET=rp2040    Build PIC modules for a specific target
#   make modules-all               Build modules for all targets
#   make targets                   List available targets
#   make fmt                      Apply rustfmt across the workspace
#   make lint                      Run clippy across every kernel target + tools
#                                  with `-D warnings` (CI-equivalent)

# Default target silicon (override: make firmware TARGET=rp2040)
TARGET ?= rp2350

# Target-to-toolchain lookup (avoids circular dep with tools binary)
# SILICON_ID: the chip the TARGET runs on. Board targets (e.g. cm5) map to
# their silicon (bcm2712). Modules are byte-identical across boards that
# share silicon + module_target, so they live under the silicon id.
ifeq ($(TARGET),rp2040)
  RUST_TARGET := thumbv6m-none-eabi
  CARGO_FEATURES := chip-rp2040
  MODULE_TARGET := thumbv6m-none-eabi
  MODULE_LD := modules/module.ld
  MODULE_LINKER := arm-none-eabi-ld
  SILICON_ID := rp2040
else ifeq ($(TARGET),cm5)
  RUST_TARGET := aarch64-unknown-none
  CARGO_FEATURES := board-cm5
  MODULE_TARGET := aarch64-unknown-none
  MODULE_LD := modules/module.ld
  MODULE_LINKER := rust-lld -flavor gnu
  SILICON_ID := bcm2712
else ifeq ($(TARGET),bcm2712)
  RUST_TARGET := aarch64-unknown-none
  CARGO_FEATURES := chip-bcm2712
  MODULE_TARGET := aarch64-unknown-none
  MODULE_LD := modules/module.ld
  MODULE_LINKER := rust-lld -flavor gnu
  SILICON_ID := bcm2712
else ifeq ($(TARGET),wasm)
  RUST_TARGET := wasm32-unknown-unknown
  CARGO_FEATURES := host-wasm
  MODULE_TARGET := wasm32-unknown-unknown
  # wasm has no linker script — the wasm module format prescribes
  # section layout. MODULE_LD is set to /dev/null so the module-build
  # rule has a placeholder to skip; module compilation for wasm is
  # done via cargo + cdylib, not rustc+ld (see modules-wasm rule).
  MODULE_LD := /dev/null
  MODULE_LINKER := wasm-ld
  SILICON_ID := wasm
else
  # rp2350, rp2350a, rp2350b: all use the same binary (runtime detection handles A/B)
  RUST_TARGET := thumbv8m.main-none-eabihf
  CARGO_FEATURES := chip-rp2350b
  MODULE_TARGET := thumbv8m.main-none-eabihf
  MODULE_LD := modules/module.ld
  MODULE_LINKER := arm-none-eabi-ld
  SILICON_ID := rp2350
endif

RELEASE_DIR := target/$(RUST_TARGET)/release
FIRMWARE_ELF := $(RELEASE_DIR)/fluxor
FIRMWARE_BIN := target/$(TARGET)/firmware.bin
MODULES_OUT := target/$(SILICON_ID)/modules
FLUXOR_TOOL := target/aarch64-unknown-linux-gnu/release/fluxor

# Module source directories under modules/
MODULE_DIRS := modules/drivers modules/foundation modules/app
# Shared PIC SDK files (abi.rs, runtime.rs, params.rs) live in modules/sdk/
SDK_DIR := modules/sdk
ABI_HEADER := $(SDK_DIR)/abi.rs

# Module type mapping: Source=1, Transformer=2, Sink=3, EventHandler=4, Protocol=5
mod_type = $(strip $(if $(filter cyw43,$(1)),5,$(if $(filter enc28j60,$(1)),5,$(if $(filter ch9120,$(1)),5,$(if $(filter sd,$(1)),5,$(if $(filter st7701s,$(1)),5,$(if $(filter gt911,$(1)),5,$(if $(filter pwm_rp,$(1)),5,$(if $(filter i2s_pio,$(1)),3,$(if $(filter button,$(1)),4,$(if $(filter flash_rp,$(1)),4,$(if $(filter temp_sensor,$(1)),1,$(if $(filter mic_pio,$(1)),1,2)))))))))))))

.PHONY: all firmware firmware-all tools modules modules-all linux-bin clean targets init run flash fmt lint

all: tools firmware-all modules-all linux-bin

firmware:
	@echo "Building firmware for $(TARGET) ($(RUST_TARGET))..."
ifeq ($(TARGET),wasm)
	@# wasm needs cdylib output for the host shim to instantiate.
	@# `cargo rustc --crate-type=cdylib` requests it on the side so
	@# Cargo.toml's default `crate-type = ["rlib"]` stays clean for
	@# every other target (avoids the "dropping unsupported crate
	@# type cdylib" warning on embedded builds).
	cargo rustc --release --target $(RUST_TARGET) --no-default-features --features $(CARGO_FEATURES) --lib --crate-type=cdylib
else
	cargo build --release --target $(RUST_TARGET) --no-default-features --features $(CARGO_FEATURES)
endif
	@mkdir -p target/$(TARGET)
ifeq ($(TARGET),wasm)
	@# The wasm build emits `fluxor.wasm` directly — no objcopy step.
	@# The bundle tool reads from `target/wasm/firmware.wasm`; copy
	@# (rather than rename) so subsequent `cargo build` doesn't have
	@# to rebuild from scratch.
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
	cargo build --release -p fluxor-tools --target aarch64-unknown-linux-gnu

modules: tools
ifeq ($(TARGET),wasm)
	@# Each module compiles to a self-contained wasm32 cdylib, which
	@# the pack tool wraps in the same `.fmod` envelope used by every
	@# other target. The kernel detects wasm payloads via the
	@# wasm-payload flag in the module header (bit 5 of byte 60) and
	@# dispatches through `host_instantiate_module` instead of the
	@# PIC loader.
	@#
	@# Every module is attempted. Modules that fail to compile or
	@# don't export the canonical wasm entry points are listed and
	@# skipped. The final summary prints the explicit built / skipped
	@# names so configs that reference a missing module surface the
	@# gap at build time.
	@mkdir -p $(MODULES_OUT)
	@built_list=""; skipped_list=""; total=0; \
	for dir in $(MODULE_DIRS); do \
		[ -d "$$dir" ] || continue; \
		for src in $$(find "$$dir" -mindepth 2 -maxdepth 3 -name 'mod.rs' | sort); do \
			mod_dir=$$(dirname "$$src"); \
			mod=$$(basename "$$mod_dir"); \
			total=$$((total + 1)); \
			wasm="$(MODULES_OUT)/$$mod.wasm"; \
			out="$(MODULES_OUT)/$$mod.fmod"; \
			# Drop any existing .fmod that does not contain the \
			# canonical wasm exports, so a non-canonical module \
			# never stays loadable to configs purely because the \
			# timestamp check would otherwise pass it through. \
			if [ -f "$$out" ]; then \
				if ! grep -q 'module_init_wasm' "$$out" || ! grep -q 'module_step_wasm' "$$out"; then \
					rm -f "$$out"; \
				fi; \
			fi; \
			newest=$$(find "$$mod_dir" -name '*.rs' -newer "$$out" 2>/dev/null | head -1); \
			if [ -n "$$newest" ] || [ "$(SDK_DIR)/runtime.rs" -nt "$$out" ] 2>/dev/null || [ "$(SDK_DIR)/wasm_entry.rs" -nt "$$out" ] 2>/dev/null || [ ! -f "$$out" ]; then \
				if rustc --crate-type=cdylib --target=wasm32-unknown-unknown -C opt-level=z -C strip=symbols -A warnings -o "$$wasm" "$$src" 2>/tmp/wasm_build.$$$$.err; then \
					if ! grep -q 'module_init_wasm' "$$wasm" || ! grep -q 'module_step_wasm' "$$wasm"; then \
						echo "Skip: $$mod (compiles for wasm32 but does not export module_init_wasm + module_step_wasm — non-canonical lifecycle, can't be wasm-payload)"; \
						skipped_list="$$skipped_list $$mod"; \
						rm -f "$$wasm" "$$out" /tmp/wasm_build.$$$$.err; \
						continue; \
					fi; \
					mtype=$$(echo "$(call mod_type,$$mod)"); [ -z "$$mtype" ] && mtype=2; \
					manifest_arg=""; \
					if [ -f "$$mod_dir/manifest.toml" ]; then manifest_arg="--manifest $$mod_dir/manifest.toml"; fi; \
					if ! $(FLUXOR_TOOL) pack "$$wasm" -o "$$out" -n "$$mod" -t "$$mtype" $$manifest_arg; then \
						echo "ERROR: pack failed for $$mod"; \
						rm -f "$$out" /tmp/wasm_build.$$$$.err; \
						exit 1; \
					fi; \
					built_list="$$built_list $$mod"; \
				else \
					echo "Skip: $$mod (wasm32 compile failed):"; \
					sed 's/^/  | /' /tmp/wasm_build.$$$$.err | head -5; \
					skipped_list="$$skipped_list $$mod"; \
					rm -f "$$out"; \
				fi; \
				rm -f /tmp/wasm_build.$$$$.err; \
			else \
				built_list="$$built_list $$mod"; \
			fi; \
		done; \
	done; \
	built_count=$$(echo "$$built_list" | wc -w); \
	skipped_count=$$(echo "$$skipped_list" | wc -w); \
	echo "Modules (wasm): built $$built_count of $$total"; \
	if [ -n "$$skipped_list" ]; then \
		echo "  skipped:$$skipped_list"; \
	fi
else
	@mkdir -p $(MODULES_OUT)
	@# rp2350a and rp2350b produce identical PIC modules (same thumbv8m target).
	@# Symlink both silicon variant names → rp2350 so combine tool finds modules at target/{silicon_id}/modules.
	@if [ "$(TARGET)" = "rp2350" ]; then \
		mkdir -p target/rp2350 && \
		{ [ -e target/rp2350a ] || ln -s rp2350 target/rp2350a; } && \
		{ [ -e target/rp2350b ] || ln -s rp2350 target/rp2350b; }; \
	fi
	@built=0; total=0; \
	for dir in $(MODULE_DIRS); do \
		[ -d "$$dir" ] || continue; \
		for src in $$(find "$$dir" -mindepth 2 -maxdepth 3 -name 'mod.rs' | sort); do \
			mod_dir=$$(dirname "$$src"); \
			mod=$$(basename "$$mod_dir"); \
			total=$$((total + 1)); \
			obj="$(MODULES_OUT)/$$mod.o"; \
			elf="$(MODULES_OUT)/$$mod.elf"; \
			out="$(MODULES_OUT)/$$mod.fmod"; \
			newest=$$(find "$$mod_dir" -name '*.rs' -newer "$$out" 2>/dev/null | head -1); \
			if [ -f "$$mod_dir/module.ld" ]; then ld_script="$$mod_dir/module.ld"; else ld_script="$(MODULE_LD)"; fi; \
			if [ -n "$$newest" ] || [ "$(ABI_HEADER)" -nt "$$out" ] 2>/dev/null || [ "$(SDK_DIR)/runtime.rs" -nt "$$out" ] 2>/dev/null || [ "$(MODULE_LD)" -nt "$$out" ] 2>/dev/null || [ ! -f "$$out" ]; then \
				rustc --crate-type=lib --target $(MODULE_TARGET) -O -C relocation-model=pic -A warnings --emit=obj -o "$$obj" "$$src" || exit 1; \
				$(MODULE_LINKER) -T "$$ld_script" --gc-sections --no-undefined --undefined=module_arena_size -o "$$elf" "$$obj" || exit 1; \
				mtype=$$(echo "$(call mod_type,$$mod)"); [ -z "$$mtype" ] && mtype=2; \
				manifest_arg=""; \
				if [ -f "$$mod_dir/manifest.toml" ]; then manifest_arg="--manifest $$mod_dir/manifest.toml"; fi; \
				$(FLUXOR_TOOL) pack "$$elf" -o "$$out" -n "$$mod" -t "$$mtype" $$manifest_arg || exit 1; \
				built=$$((built + 1)); \
			fi; \
		done; \
	done; \
	if [ "$$built" -gt 0 ]; then \
		echo "Modules ($(TARGET)): built $$built of $$total"; \
	else \
		echo "Modules ($(TARGET)): up to date ($$total)"; \
	fi
endif

modules-all:
	$(MAKE) modules TARGET=rp2350
	$(MAKE) modules TARGET=rp2040
	$(MAKE) modules TARGET=bcm2712

# Thin wrappers around fluxor CLI
run:
	@if [ -z "$(CONFIG)" ]; then echo "Usage: make run CONFIG=examples/qemu-virt/hello_server.yaml"; exit 1; fi
	$(FLUXOR_TOOL) run $(CONFIG)

flash:
	@if [ -z "$(CONFIG)" ]; then echo "Usage: make flash CONFIG=examples/pico2w/blinky.yaml"; exit 1; fi
	$(FLUXOR_TOOL) flash $(CONFIG)

targets:
	@$(FLUXOR_TOOL) targets

linux-bin: tools
	@cargo build --release --bin fluxor-linux --no-default-features --features host-linux --target aarch64-unknown-linux-gnu

init:
	git submodule update --init --recursive

fmt:
	@cargo fmt --all

# Run clippy on every kernel target the firmware ships for, plus the host
# tools and the Linux harness. Each invocation uses `-D warnings` so any
# new lint becomes a CI failure rather than a passive warning. Targets
# share most of the kernel source, but each enables a different set of
# `chip-*` / `board-*` features that gate platform code, so all of them
# must be checked. The leading `touch src/lib.rs` invalidates clippy's
# incremental cache so warnings re-emit even when the prior compile was
# silent on a sibling target.
lint:
	@echo "==> linting fluxor-tools (host + integration tests) ..."
	@cd tools && cargo clippy --all-targets --all-features -- -D warnings
	@echo "==> linting fluxor-linux (host-image, host-window, host-playback) ..."
	@touch src/lib.rs
	@cargo clippy --release --bin fluxor-linux \
		--no-default-features \
		--features "host-linux host-image host-window host-playback" \
		--target aarch64-unknown-linux-gnu -- -D warnings
	@echo "==> linting firmware (rp2350b) ..."
	@touch src/lib.rs
	@cargo clippy --release --target thumbv8m.main-none-eabihf \
		--no-default-features --features chip-rp2350b -- -D warnings
	@echo "==> linting firmware (rp2040) ..."
	@touch src/lib.rs
	@cargo clippy --release --target thumbv6m-none-eabi \
		--no-default-features --features chip-rp2040 -- -D warnings
	@echo "==> linting firmware (bcm2712) ..."
	@touch src/lib.rs
	@cargo clippy --release --target aarch64-unknown-none \
		--no-default-features --features chip-bcm2712 -- -D warnings
	@echo "==> linting firmware (board-cm5) ..."
	@touch src/lib.rs
	@cargo clippy --release --target aarch64-unknown-none \
		--no-default-features --features board-cm5 -- -D warnings
	@echo "==> linting firmware (wasm) ..."
	@touch src/lib.rs
	@# Lint the lib as rlib — type/borrow checks don't differ between
	@# rlib and cdylib, and `cargo clippy` doesn't accept `--crate-type`.
	@# The cdylib artifact itself is produced by `make firmware TARGET=wasm`.
	@cargo clippy --release --target wasm32-unknown-unknown \
		--no-default-features --features host-wasm -- -D warnings
	@echo "lint: clean"

clean:
	cargo clean
	rm -rf target
