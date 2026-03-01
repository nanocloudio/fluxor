# Fluxor Makefile -- Multi-target firmware, PIC modules, host tools
#
# Usage:
#   make                          Build firmware + tools + modules (default: rp2350a)
#   make firmware TARGET_ID=rp2040   Build for a specific target
#   make firmware-all             Build firmware for all RP targets
#   make modules                  Build all PIC modules
#   make package NAME=blinky      Combine firmware + config into UF2
#   make targets                  List available targets

# Default target (override: make firmware TARGET_ID=rp2040)
TARGET_ID ?= rp2350

# Target-to-toolchain lookup (avoids circular dep with tools binary)
ifeq ($(TARGET_ID),rp2040)
  RUST_TARGET := thumbv6m-none-eabi
  CARGO_FEATURES := chip-rp2040
  MODULE_TARGET := thumbv6m-none-eabi
else
  # rp2350, rp2350a, rp2350b: all use the same binary (runtime detection handles A/B)
  RUST_TARGET := thumbv8m.main-none-eabihf
  CARGO_FEATURES := chip-rp2350b
  MODULE_TARGET := thumbv8m.main-none-eabihf
endif

RELEASE_DIR := target/$(RUST_TARGET)/release
FIRMWARE_ELF := $(RELEASE_DIR)/fluxor
FIRMWARE_BIN := target/$(TARGET_ID)/firmware.bin
UF2_OUT := target/$(TARGET_ID)/uf2
MODULES_DIR := modules
MODULES_OUT := target/$(TARGET_ID)/modules
FLUXOR_TOOL := target/aarch64-unknown-linux-gnu/release/fluxor

PIC_SOURCES := $(filter-out $(MODULES_DIR)/mod.rs $(MODULES_DIR)/pic_runtime.rs $(MODULES_DIR)/param_macro.rs,$(wildcard $(MODULES_DIR)/*.rs))
PIC_NAMES := $(patsubst $(MODULES_DIR)/%.rs,%,$(PIC_SOURCES))
PIC_DIR_SOURCES := $(wildcard $(MODULES_DIR)/*/mod.rs)
PIC_DIR_NAMES := $(patsubst $(MODULES_DIR)/%/mod.rs,%,$(PIC_DIR_SOURCES))
ABI_HEADER := src/abi.rs

# Module type mapping: Source=1, Transformer=2, Sink=3, EventHandler=4, Protocol=5
# Determines capability-filtered syscall table per module.
# Protocol: full peripheral access (GPIO, SPI, I2C, PIO)
# Sink: channels + PIO stream
# EventHandler: channels + GPIO read-only
# Source/Transformer: channels + buffers + timers only
mod_type = $(strip $(if $(filter cyw43,$(1)),5,$(if $(filter enc28j60,$(1)),5,$(if $(filter ch9120,$(1)),5,$(if $(filter sd,$(1)),5,$(if $(filter st7701s,$(1)),5,$(if $(filter gt911,$(1)),5,$(if $(filter pwm,$(1)),5,$(if $(filter i2s,$(1)),3,$(if $(filter button,$(1)),4,$(if $(filter flash,$(1)),4,$(if $(filter temp_sensor,$(1)),1,$(if $(filter mic_source,$(1)),1,2)))))))))))))

.PHONY: all build firmware firmware-all tools modules package examples clean targets

all: build

build: firmware tools modules

firmware:
	@echo "Building firmware for $(TARGET_ID) ($(RUST_TARGET))..."
	cargo build --release --target $(RUST_TARGET) --no-default-features --features $(CARGO_FEATURES)
	@mkdir -p target/$(TARGET_ID)
	@arm-none-eabi-objcopy -O binary $(FIRMWARE_ELF) $(FIRMWARE_BIN)

firmware-all:
	$(MAKE) firmware TARGET_ID=rp2350
	$(MAKE) firmware TARGET_ID=rp2040

tools:
	@echo "Building tools..."
	cargo build --release -p fluxor-tools --target aarch64-unknown-linux-gnu

modules: tools
	@mkdir -p $(MODULES_OUT)
	@# rp2350a and rp2350b produce identical PIC modules (same thumbv8m target).
	@# Symlink both silicon variant names → rp2350 so combine tool finds modules at target/{silicon_id}/modules.
	@if [ "$(TARGET_ID)" = "rp2350" ]; then \
		mkdir -p target/rp2350 && \
		{ [ -e target/rp2350a ] || ln -s rp2350 target/rp2350a; } && \
		{ [ -e target/rp2350b ] || ln -s rp2350 target/rp2350b; }; \
	fi
	@built=0; total=0; \
	for mod in $(PIC_NAMES); do \
		total=$$((total + 1)); \
		src="$(MODULES_DIR)/$$mod.rs"; \
		obj="$(MODULES_OUT)/$$mod.o"; \
		elf="$(MODULES_OUT)/$$mod.elf"; \
		out="$(MODULES_OUT)/$$mod.fmod"; \
		if [ "$$src" -nt "$$out" ] 2>/dev/null || [ "$(ABI_HEADER)" -nt "$$out" ] 2>/dev/null || [ "$(MODULES_DIR)/pic_runtime.rs" -nt "$$out" ] 2>/dev/null || [ "$(MODULES_DIR)/param_macro.rs" -nt "$$out" ] 2>/dev/null || [ "$(MODULES_DIR)/module.ld" -nt "$$out" ] 2>/dev/null || [ ! -f "$$out" ]; then \
			rustc --crate-type=lib --target $(MODULE_TARGET) -O -C relocation-model=pic -A warnings --emit=obj -o "$$obj" "$$src" || exit 1; \
			arm-none-eabi-ld -T $(MODULES_DIR)/module.ld --gc-sections --no-undefined -o "$$elf" "$$obj" || exit 1; \
			mtype=$$(echo "$(foreach m,$(PIC_NAMES),$(m)=$(call mod_type,$(m)))" | tr ' ' '\n' | grep "^$$mod=" | cut -d= -f2); \
			[ -z "$$mtype" ] && mtype=2; \
			$(FLUXOR_TOOL) pack "$$elf" -o "$$out" -n "$$mod" -t "$$mtype" || exit 1; \
			built=$$((built + 1)); \
		fi \
	done; \
	for mod in $(PIC_DIR_NAMES); do \
		total=$$((total + 1)); \
		src="$(MODULES_DIR)/$$mod/mod.rs"; \
		obj="$(MODULES_OUT)/$$mod.o"; \
		elf="$(MODULES_OUT)/$$mod.elf"; \
		out="$(MODULES_OUT)/$$mod.fmod"; \
		newest=$$(find "$(MODULES_DIR)/$$mod" -name '*.rs' -newer "$$out" 2>/dev/null | head -1); \
		if [ -f "$(MODULES_DIR)/$$mod/module.ld" ]; then ld_script="$(MODULES_DIR)/$$mod/module.ld"; else ld_script="$(MODULES_DIR)/module.ld"; fi; \
		if [ -n "$$newest" ] || [ "$(ABI_HEADER)" -nt "$$out" ] 2>/dev/null || [ "$(MODULES_DIR)/pic_runtime.rs" -nt "$$out" ] 2>/dev/null || [ "$(MODULES_DIR)/param_macro.rs" -nt "$$out" ] 2>/dev/null || [ "$$ld_script" -nt "$$out" ] 2>/dev/null || [ ! -f "$$out" ]; then \
			rustc --crate-type=lib --target $(MODULE_TARGET) -O -C relocation-model=pic -A warnings --emit=obj -o "$$obj" "$$src" || exit 1; \
			arm-none-eabi-ld -T "$$ld_script" --gc-sections --no-undefined -o "$$elf" "$$obj" || exit 1; \
			mtype=$$(echo "$(foreach m,$(PIC_DIR_NAMES),$(m)=$(call mod_type,$(m)))" | tr ' ' '\n' | grep "^$$mod=" | cut -d= -f2); \
			[ -z "$$mtype" ] && mtype=2; \
			manifest_arg=""; \
			if [ -f "$(MODULES_DIR)/$$mod/manifest.toml" ]; then manifest_arg="--manifest $(MODULES_DIR)/$$mod/manifest.toml"; fi; \
			$(FLUXOR_TOOL) pack "$$elf" -o "$$out" -n "$$mod" -t "$$mtype" $$manifest_arg || exit 1; \
			built=$$((built + 1)); \
		fi \
	done; \
	if [ "$$built" -gt 0 ]; then \
		echo "Modules ($(TARGET_ID)): built $$built of $$total"; \
	else \
		echo "Modules ($(TARGET_ID)): up to date ($$total)"; \
	fi

# Resolve firmware binary path for a given board name.
# Uses `fluxor target-info <board> --field silicon` to get silicon id, then maps to firmware bin.
# Outputs the path, or empty string if the firmware isn't built.
define firmware_for_yaml
$(shell \
	board=$$(grep '^target:' $(1) 2>/dev/null | head -1 | awk '{print $$2}'); \
	if [ -z "$$board" ]; then echo "$(FIRMWARE_BIN)"; exit 0; fi; \
	silicon=$$($(FLUXOR_TOOL) target-info $$board --field silicon 2>/dev/null); \
	case "$$silicon" in \
		rp2040) fw="target/rp2040/firmware.bin" ;; \
		*)      fw="target/rp2350/firmware.bin" ;; \
	esac; \
	if [ -f "$$fw" ]; then echo "$$fw"; fi)
endef

package: build
	@if [ -z "$(NAME)" ]; then \
		echo "Usage: make package NAME=sd_logger"; \
		echo ""; \
		echo "Available examples:"; \
		find examples -name '*.yaml' | sort | while read f; do \
			dir=$$(basename $$(dirname $$f)); name=$$(basename $$f .yaml); \
			echo "  $$dir/$$name"; \
		done; \
		exit 1; \
	fi
	@yaml=$$(find examples -name '$(NAME).yaml' | head -1); \
	if [ -z "$$yaml" ]; then echo "Error: $(NAME).yaml not found in examples/"; exit 1; fi; \
	board=$$(grep '^target:' $$yaml | head -1 | awk '{print $$2}'); \
	silicon=$$($(FLUXOR_TOOL) target-info $$board --field id 2>/dev/null); \
	case "$$silicon" in \
		rp2040) fw="target/rp2040/firmware.bin"; outdir="target/rp2040/uf2" ;; \
		*)      fw="target/rp2350/firmware.bin"; outdir="target/rp2350/uf2" ;; \
	esac; \
	if [ ! -f "$$fw" ]; then echo "Error: $$fw not built (run: make firmware TARGET_ID=rp2040)"; exit 1; fi; \
	mkdir -p $$outdir && $(FLUXOR_TOOL) combine $$fw $$yaml -o $$outdir/$(NAME).uf2

examples: build
	@$(MAKE) firmware TARGET_ID=rp2040 --no-print-directory
	@$(MAKE) modules TARGET_ID=rp2040 --no-print-directory
	@count=0; skip=0; \
	for yaml in $$(find examples -name '*.yaml' | sort); do \
		name=$$(basename $$yaml .yaml); \
		subdir=$$(basename $$(dirname $$yaml)); \
		board=$$(grep '^target:' $$yaml | head -1 | awk '{print $$2}'); \
		silicon=$$($(FLUXOR_TOOL) target-info $$board --field id 2>/dev/null); \
		case "$$silicon" in \
			rp2040) fw="target/rp2040/firmware.bin"; outdir="target/rp2040/uf2" ;; \
			*)      fw="target/rp2350/firmware.bin"; outdir="target/rp2350/uf2" ;; \
		esac; \
		if [ ! -f "$$fw" ]; then \
			echo "Skip $$subdir/$$name ($$fw not built)"; skip=$$((skip + 1)); continue; \
		fi; \
		mkdir -p $$outdir/$$subdir; \
		$(FLUXOR_TOOL) combine $$fw $$yaml -o $$outdir/$$subdir/$${name}.uf2 && count=$$((count + 1)); \
	done; \
	echo "Built $$count example UF2s"; \
	if [ "$$skip" -gt 0 ]; then echo "Skipped $$skip examples"; fi

targets:
	@$(FLUXOR_TOOL) targets

clean:
	cargo clean
	rm -rf target
