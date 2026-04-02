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
  MODULE_LD := modules/module.ld
  MODULE_LINKER := arm-none-eabi-ld
else ifeq ($(TARGET_ID),cm5)
  RUST_TARGET := aarch64-unknown-none
  CARGO_FEATURES := board-cm5
  MODULE_TARGET := aarch64-unknown-none
  MODULE_LD := modules/module.ld
  MODULE_LINKER := rust-lld -flavor gnu
else ifeq ($(TARGET_ID),bcm2712)
  RUST_TARGET := aarch64-unknown-none
  CARGO_FEATURES := chip-bcm2712
  MODULE_TARGET := aarch64-unknown-none
  MODULE_LD := modules/module.ld
  MODULE_LINKER := rust-lld -flavor gnu
else
  # rp2350, rp2350a, rp2350b: all use the same binary (runtime detection handles A/B)
  RUST_TARGET := thumbv8m.main-none-eabihf
  CARGO_FEATURES := chip-rp2350b
  MODULE_TARGET := thumbv8m.main-none-eabihf
  MODULE_LD := modules/module.ld
  MODULE_LINKER := arm-none-eabi-ld
endif

RELEASE_DIR := target/$(RUST_TARGET)/release
FIRMWARE_ELF := $(RELEASE_DIR)/fluxor
FIRMWARE_BIN := target/$(TARGET_ID)/firmware.bin
UF2_OUT := target/$(TARGET_ID)/uf2
MODULES_OUT := target/$(TARGET_ID)/modules
FLUXOR_TOOL := target/aarch64-unknown-linux-gnu/release/fluxor

# Module source directories under modules/
MODULE_DIRS := modules/drivers modules/foundation modules/app
# Shared PIC build files (pic_runtime.rs, param_macro.rs, module.ld) live in modules/
SHARED_DIR := modules
ABI_HEADER := src/abi.rs

# Module type mapping: Source=1, Transformer=2, Sink=3, EventHandler=4, Protocol=5
# Determines capability-filtered syscall table per module.
# Protocol: full peripheral access (GPIO, SPI, I2C, PIO)
# Sink: channels + PIO stream
# EventHandler: channels + GPIO read-only
# Source/Transformer: channels + buffers + timers only
mod_type = $(strip $(if $(filter cyw43,$(1)),5,$(if $(filter enc28j60,$(1)),5,$(if $(filter ch9120,$(1)),5,$(if $(filter sd,$(1)),5,$(if $(filter st7701s,$(1)),5,$(if $(filter gt911,$(1)),5,$(if $(filter pwm_rp,$(1)),5,$(if $(filter i2s_pio,$(1)),3,$(if $(filter button,$(1)),4,$(if $(filter flash_rp,$(1)),4,$(if $(filter temp_sensor,$(1)),1,$(if $(filter mic_pio,$(1)),1,2)))))))))))))

.PHONY: all build firmware firmware-all tools modules package examples examples-rp examples-vm examples-cm5 examples-aarch64 clean targets vm vm-run cm5 aarch64-image linux linux-run

all: build

build: firmware tools modules

firmware:
	@echo "Building firmware for $(TARGET_ID) ($(RUST_TARGET))..."
	cargo build --release --target $(RUST_TARGET) --no-default-features --features $(CARGO_FEATURES)
	@mkdir -p target/$(TARGET_ID)
ifeq ($(TARGET_ID),bcm2712)
	@rust-objcopy -O binary $(FIRMWARE_ELF) $(FIRMWARE_BIN)
else ifeq ($(TARGET_ID),cm5)
	@rust-objcopy -O binary $(FIRMWARE_ELF) $(FIRMWARE_BIN)
else
	@arm-none-eabi-objcopy -O binary $(FIRMWARE_ELF) $(FIRMWARE_BIN)
endif

firmware-all:
	$(MAKE) firmware TARGET_ID=rp2350
	$(MAKE) firmware TARGET_ID=rp2040
	$(MAKE) firmware TARGET_ID=bcm2712
	$(MAKE) firmware TARGET_ID=cm5

# --- QEMU VM targets (BCM2712/aarch64) ---

VM_CONFIG ?= examples/qemu-virt/hello_server.yaml

vm: AARCH64_FIRMWARE_TARGET=bcm2712
vm: AARCH64_CONFIG=$(VM_CONFIG)
vm: AARCH64_OUTPUT=vm/kernel8.img
vm: aarch64-image ## Build BCM2712 kernel image for QEMU

vm-run: vm ## Build and run in QEMU with virtio-net
	qemu-system-aarch64 \
		-machine virt -cpu cortex-a76 -m 2G -nographic \
		-device virtio-net-device,netdev=net0,mac=52:54:00:12:34:56 \
		-netdev user,id=net0,hostfwd=tcp::18080-:80 \
		-kernel vm/kernel8.img

# --- CM5 bare-metal targets (Pi 5 / CM5 real hardware) ---

CM5_CONFIG ?= examples/cm5/hello_uart.yaml

cm5: AARCH64_FIRMWARE_TARGET=cm5
cm5: AARCH64_CONFIG=$(CM5_CONFIG)
cm5: AARCH64_OUTPUT=target/cm5/boot/kernel8.img
cm5: aarch64-image ## Build kernel8.img for real Pi 5 / CM5 hardware
	@echo "Copy to SD card with: cp target/cm5/boot/kernel8.img /boot/firmware/"

aarch64-image: tools
	@if [ -z "$(AARCH64_FIRMWARE_TARGET)" ] || [ -z "$(AARCH64_CONFIG)" ] || [ -z "$(AARCH64_OUTPUT)" ]; then \
		echo "Usage: make aarch64-image AARCH64_FIRMWARE_TARGET=<bcm2712|cm5> AARCH64_CONFIG=<yaml> AARCH64_OUTPUT=<img>"; \
		exit 1; \
	fi
	@$(MAKE) modules TARGET_ID=$(AARCH64_FIRMWARE_TARGET) --no-print-directory
	@$(MAKE) firmware TARGET_ID=$(AARCH64_FIRMWARE_TARGET) --no-print-directory
	@mkdir -p $$(dirname $(AARCH64_OUTPUT))
	@$(FLUXOR_TOOL) pack-image target/$(AARCH64_FIRMWARE_TARGET)/firmware.bin $(AARCH64_CONFIG) --modules-dir target/$(AARCH64_FIRMWARE_TARGET)/modules -o $(AARCH64_OUTPUT)

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
			if [ -n "$$newest" ] || [ "$(ABI_HEADER)" -nt "$$out" ] 2>/dev/null || [ "$(SHARED_DIR)/pic_runtime.rs" -nt "$$out" ] 2>/dev/null || [ "$(MODULE_LD)" -nt "$$out" ] 2>/dev/null || [ ! -f "$$out" ]; then \
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
		bcm2712) echo "Error: use 'make vm' for bcm2712 targets"; exit 1 ;; \
		*)      fw="target/rp2350/firmware.bin"; outdir="target/rp2350/uf2" ;; \
	esac; \
	if [ ! -f "$$fw" ]; then echo "Error: $$fw not built (run: make firmware TARGET_ID=rp2040)"; exit 1; fi; \
	mkdir -p $$outdir && $(FLUXOR_TOOL) combine $$fw $$yaml -o $$outdir/$(NAME).uf2

examples: examples-rp examples-aarch64

examples-rp: build
	@$(MAKE) firmware TARGET_ID=rp2040 --no-print-directory
	@$(MAKE) modules TARGET_ID=rp2040 --no-print-directory
	@count=0; \
	for yaml in $$(find examples -name '*.yaml' ! -path 'examples/qemu-virt/*' ! -path 'examples/cm5/*' ! -path 'examples/linux/*' | sort); do \
		name=$$(basename $$yaml .yaml); \
		subdir=$$(basename $$(dirname $$yaml)); \
		board=$$(grep '^target:' $$yaml | head -1 | awk '{print $$2}'); \
		silicon=$$($(FLUXOR_TOOL) target-info $$board --field id 2>/dev/null); \
		case "$$silicon" in \
			rp2040) fw="target/rp2040/firmware.bin"; outdir="target/rp2040/uf2" ;; \
			rp2350*) fw="target/rp2350/firmware.bin"; outdir="target/rp2350/uf2" ;; \
			*)      fw="target/rp2350/firmware.bin"; outdir="target/rp2350/uf2" ;; \
		esac; \
		if [ ! -f "$$fw" ]; then \
			echo "Skip $$subdir/$$name ($$fw not built)"; continue; \
		fi; \
		mkdir -p $$outdir/$$subdir; \
		$(FLUXOR_TOOL) combine $$fw $$yaml -o $$outdir/$$subdir/$${name}.uf2 && count=$$((count + 1)); \
	done; \
	echo "Built $$count RP example UF2s"

examples-aarch64: examples-vm examples-cm5

examples-vm: tools
	@count=0; \
	for yaml in $$(find examples/qemu-virt -name '*.yaml' | sort); do \
		name=$$(basename $$yaml .yaml); \
		out="target/bcm2712/images/qemu-virt/$${name}.img"; \
		$(MAKE) aarch64-image \
			AARCH64_FIRMWARE_TARGET=bcm2712 \
			AARCH64_CONFIG=$$yaml \
			AARCH64_OUTPUT=$$out \
			--no-print-directory || exit 1; \
		count=$$((count + 1)); \
	done; \
	echo "Built $$count QEMU example images"

examples-cm5: tools
	@count=0; \
	for yaml in $$(find examples/cm5 -name '*.yaml' | sort); do \
		name=$$(basename $$yaml .yaml); \
		out="target/cm5/images/cm5/$${name}.img"; \
		$(MAKE) aarch64-image \
			AARCH64_FIRMWARE_TARGET=cm5 \
			AARCH64_CONFIG=$$yaml \
			AARCH64_OUTPUT=$$out \
			--no-print-directory || exit 1; \
		count=$$((count + 1)); \
	done; \
	echo "Built $$count CM5 example images"

# --- Linux hosted target ---

linux: tools
	@$(MAKE) modules TARGET_ID=bcm2712 --no-print-directory
	@echo "Building fluxor-linux..."
	cargo build --release --bin fluxor-linux --no-default-features --features host-linux --target aarch64-unknown-linux-gnu
	@echo "Binary: target/aarch64-unknown-linux-gnu/release/fluxor-linux"

LINUX_CONFIG ?= examples/linux/hello.yaml
LINUX_BIN := target/aarch64-unknown-linux-gnu/release/fluxor-linux

linux-run: linux ## Build and run Fluxor on Linux
	@mkdir -p target/linux
	@$(FLUXOR_TOOL) mktable-config $(LINUX_CONFIG) -m target/bcm2712/modules -o target/linux/modules.bin
	@$(FLUXOR_TOOL) generate $(LINUX_CONFIG) -m target/bcm2712/modules -o target/linux/config.bin --binary
	$(LINUX_BIN) --config target/linux/config.bin --modules target/linux/modules.bin

targets:
	@$(FLUXOR_TOOL) targets

clean:
	cargo clean
	rm -rf target
