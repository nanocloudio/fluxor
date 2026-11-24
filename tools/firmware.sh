#!/bin/bash
# Build one kernel image for a board (or host) and emit its raw boot image.
#
#   tools/firmware.sh [pico|picow|pico2w|waveshare-lcd4|qemu-virt|pi5|wasm]
#
# The Makefile's `firmware` target calls this. It lives here rather than
# in a recipe because per-target dispatch is a conditional, and
# standards/make.md §3 puts conditionals in a `fluxor` subcommand or a
# script — never in a Makefile.
#
# TARGET is a **board** id, not a silicon id. standards/target_consolidation.md
# §3 puts firmware builds at the board level and module builds at the silicon
# level: a board is what you hold and flash, and it is what fixes the link
# origin, the pin map and the rig contract — several boards share one die.
# `fluxor modules build --target <silicon>` is the other half of the same
# split, and the two levels are deliberately not interchangeable here: passing
# a silicon id is an error rather than an alias, because an alias is how the
# two levels fuse back together.
#
# Everything per-target is read from the target TOMLs, so adding a board is a
# TOML file and nothing here. Resolution:
#
#   board → targets/boards/<id>.toml   [board] silicon → targets/silicon/<s>.toml
#   host  → targets/host/<id>.toml     (no silicon; it is not a chip)
#
# Cargo features come from the board's own [build] cargo_features when it
# declares them (pi5 does: `board-pi5` selects board-specific platform code
# over the plain chip feature) and from its silicon's otherwise.
set -euo pipefail

TARGET="${1:-${TARGET:-pico2w}}"

BOARD_TOML="targets/boards/$TARGET.toml"
HOST_TOML="targets/host/$TARGET.toml"

# Read `key = value` from within `[section]` of a target TOML. Values are
# either a bare string ("rp2350") or a single-line array (["board-pi5"]);
# both reduce to a comma-separated scalar, which is what cargo wants for
# --features anyway.
toml_get() {
    awk -v section="$1" -v key="$2" '
        /^\[/  { in_section = ($0 ~ "^\\[" section "\\]") ; next }
        in_section && $0 ~ "^[ \t]*" key "[ \t]*=" {
            sub(/^[^=]*=[ \t]*/, "")
            gsub(/[]["]/, "")
            gsub(/[ \t]*,[ \t]*/, ",")
            sub(/[ \t]*$/, "")
            print
            exit
        }
    ' "$3"
}

# A board that stands on a host (`[board] host = "linux"`: a machine with
# an operating system, running the hosted runtime) builds as that host.
if [[ -f "$BOARD_TOML" && -n "$(toml_get board host "$BOARD_TOML")" ]]; then
    HOST_TOML="targets/host/$(toml_get board host "$BOARD_TOML").toml"
    [[ -f "$HOST_TOML" ]] || {
        echo "firmware: board '$TARGET' names a host with no $HOST_TOML" >&2
        exit 2
    }
    SILICON=""
    RUST_TARGET="$(toml_get build rust_target "$HOST_TOML")"
    FEATURES="$(toml_get build cargo_features "$BOARD_TOML")"
    [[ -n "$FEATURES" ]] || FEATURES="$(toml_get build cargo_features "$HOST_TOML")"
elif [[ -f "$BOARD_TOML" ]]; then
    SILICON="$(toml_get board silicon "$BOARD_TOML")"
    SILICON_TOML="targets/silicon/$SILICON.toml"
    [[ -n "$SILICON" && -f "$SILICON_TOML" ]] || {
        echo "firmware: board '$TARGET' names silicon '$SILICON', which has no $SILICON_TOML" >&2
        exit 2
    }
    RUST_TARGET="$(toml_get build rust_target "$SILICON_TOML")"
    # Board features win over silicon features when declared; see above.
    FEATURES="$(toml_get build cargo_features "$BOARD_TOML")"
    [[ -n "$FEATURES" ]] || FEATURES="$(toml_get build cargo_features "$SILICON_TOML")"
elif [[ -f "$HOST_TOML" ]]; then
    SILICON=""
    RUST_TARGET="$(toml_get build rust_target "$HOST_TOML")"
    FEATURES="$(toml_get build cargo_features "$HOST_TOML")"
else
    BOARDS="$(ls targets/boards/*.toml 2>/dev/null | xargs -n1 basename | sed 's/\.toml$//' | tr '\n' ' ')"
    HOSTS="$(ls targets/host/*.toml 2>/dev/null | xargs -n1 basename | sed 's/\.toml$//' | tr '\n' ' ')"
    if [[ -f "targets/silicon/$TARGET.toml" ]]; then
        # The specific mistake this script exists to refuse, named precisely:
        # a silicon id is what `fluxor modules build --target` takes.
        echo "firmware: '$TARGET' is a silicon id, and firmware is built per board." >&2
        echo "          Boards on this silicon: $(grep -l "silicon = \"$TARGET\"" targets/boards/*.toml 2>/dev/null | xargs -n1 basename 2>/dev/null | sed 's/\.toml$//' | tr '\n' ' ')" >&2
    else
        echo "firmware: unknown TARGET '$TARGET'" >&2
    fi
    echo "          boards: $BOARDS" >&2
    echo "          hosts:  $HOSTS" >&2
    exit 2
fi

[[ -n "$RUST_TARGET" ]] || { echo "firmware: no [build] rust_target for '$TARGET'" >&2; exit 2; }
[[ -n "$FEATURES" ]]    || { echo "firmware: no [build] cargo_features for '$TARGET'" >&2; exit 2; }

# A target the firmware boots through a loader (UEFI) names the loader's
# triple in its host TOML; the loader is built with the kernel, below.
LOADER_TARGET=""
if [[ -f "$HOST_TOML" ]]; then
    LOADER_TARGET="$(toml_get build loader_target "$HOST_TOML")"
fi

# Resolution without the build, for anything that needs to know what this
# script *would* do: `FIRMWARE_PLAN_ONLY=1 tools/firmware.sh <board>`.
# This script reads the same TOMLs the CLI's target descriptors come from,
# but the awk reader above is a second parser of that data, so
# `tools/tests/firmware_target_table.rs` compares this line against
# `target::load_target` for every board. A second copy of *parsing* is only
# safe while something compares the results.
if [[ -n "${FIRMWARE_PLAN_ONLY:-}" ]]; then
    echo "target=$TARGET silicon=${SILICON:-} triple=$RUST_TARGET features=$FEATURES loader=$LOADER_TARGET"
    exit 0
fi

# Board facts the kernel compiles in (the crystal frequency, for one) come
# from the board TOML, so build.rs has to know which board this is. The
# silicon alone cannot answer it: two boards over one die fit different
# crystals, and one of them would silently get the other's clock.
export FLUXOR_BOARD="$TARGET"

RELEASE_DIR="target/$RUST_TARGET/release"
echo "Building firmware for $TARGET (${SILICON:-host}, $RUST_TARGET)..."
mkdir -p "target/$TARGET"

if [[ "$RUST_TARGET" == wasm32-* ]]; then
    cargo rustc --release --target "$RUST_TARGET" --no-default-features \
        --features "$FEATURES" --lib --crate-type=cdylib
    cp "$RELEASE_DIR/fluxor.wasm" "target/$TARGET/firmware.wasm"
    exit 0
fi

# The aarch64 kernel is compiled with the same ARMv8 crypto extensions
# as the bcm2712 modules it loads (`tools/src/modules_build.rs`): the
# silicon is a Cortex-A76, and the SDK primitives select their SHA-256
# and AES instruction paths on `target_feature`, not on the architecture.
# RUSTFLAGS is set only for aarch64: even an empty RUSTFLAGS replaces
# the per-target flags in `.cargo/config.toml`, which the rp kernels
# link with.
case "$RUST_TARGET" in
  aarch64-*) export RUSTFLAGS="-C target-feature=+aes,+sha2,+neon" ;;
esac
cargo build --release --target "$RUST_TARGET" --no-default-features --features "$FEATURES"

case "$RUST_TARGET" in
  aarch64-*) OBJCOPY=rust-objcopy ;;
  *)         OBJCOPY=arm-none-eabi-objcopy ;;
esac
"$OBJCOPY" -O binary "$RELEASE_DIR/fluxor" "target/$TARGET/firmware.bin"

# Keep a board-scoped copy of the ELF beside the raw image.
#
# cargo writes the ELF per *triple*, so two boards over one triple overwrite
# each other there: pi5 (board-pi5) and qemu-virt (chip-bcm2712) are the same
# aarch64-unknown-none, and whichever built last wins. The failure is silent
# rather than an error — a pi5 kernel run under QEMU drives the RP1 UART over
# PCIe, which QEMU does not have, so it boots and says nothing — indistinguishable
# from an image that never started.
#
# Anything wanting "the ELF for this board" should read this copy. The
# per-triple path remains whatever was built last and cannot be trusted to
# belong to any particular board.
cp "$RELEASE_DIR/fluxor" "target/$TARGET/firmware.elf"

# The loader the firmware runs to reach this kernel: its own crate
# (crates/fluxor-uefi-loader), a firmware application on the triple the
# target names. Built with the kernel so the two cannot come from different
# trees; `fluxor build` puts it on the boot disk at the target's
# `loader_path`.
if [[ -n "$LOADER_TARGET" ]]; then
    rustup target list --installed 2>/dev/null | grep -qx "$LOADER_TARGET" || {
        echo "firmware: the loader needs the $LOADER_TARGET target: rustup target add $LOADER_TARGET" >&2
        exit 2
    }
    env -u RUSTFLAGS cargo build --release -p fluxor-uefi-loader --target "$LOADER_TARGET"
    cp "target/$LOADER_TARGET/release/fluxor-uefi-loader.efi" "target/$TARGET/loader.efi"
fi

# An RP dependency tree must contain no third-party runtime crate. Asking
# Cargo what resolved is the check that matters: a crate can be in the tree
# with no `use` anywhere and still be linked, and a transitively enabled
# feature is easy to acquire without noticing.
case "$SILICON" in
  rp2040|rp2350) bash tools/img/verify_rp_closure.sh >/dev/null || exit 5 ;;
esac

# Verify the boot artifacts the bootrom checks before running the image.
# RP2040's boot2 carries a checksum; RP2350 carries an IMAGE_DEF
# block. Both are validated at every power-on and both fail the same way when
# wrong: the board does not boot and says nothing, because the thing that
# would have said something is what failed to load.
#
# They come from a dependency, so without this check they would be correct by
# inheritance rather than by verification.
case "$SILICON" in
  rp2040|rp2350)
    python3 tools/img/verify_firmware_image.py "$SILICON" "target/$TARGET/firmware.bin" || exit 4
    ;;
esac

# Prove the flash routines really are in RAM.
#
# Erasing flash makes flash unreadable, so the code doing it must not be
# executing from flash. `#[link_section = ".data.ram_func"]` states the
# intent; nothing checked it held. A linker script change, a section-garbage
# pass, or a rename would move these back into XIP silently, and the failure
# mode is a board that erases its own flash and then fetches the next
# instruction from the flash it just erased.
#
# The veneers the linker emits to *reach* these functions do live in flash,
# which is correct: a veneer runs before flash is disconnected.
case "$SILICON" in
  rp2040|rp2350)
    RAM_FUNCS="flash_erase_sector flash_program_page read_bootsel_io_qspi"
    # Where a second core runs a domain it waits out an XIP detach in a loop
    # that must be in RAM for the same reason, and must call nothing: a call
    # would be a fetch from the flash that is away.
    if [[ "$SILICON" == "rp2350" ]]; then
        RAM_FUNCS="$RAM_FUNCS fluxor_rp_ram_park"
        PARK_ASM="$(arm-none-eabi-objdump -d --disassemble=fluxor_rp_ram_park "target/$TARGET/firmware.elf")"
        if grep -Eq '[[:space:]](bl|blx)[[:space:]]' <<<"$PARK_ASM"; then
            echo "firmware: fluxor_rp_ram_park makes a call; the park loop must keep to RAM" >&2
            exit 3
        fi
        if ! grep -Eq '[[:space:]]wfe' <<<"$PARK_ASM"; then
            echo "firmware: fluxor_rp_ram_park did not disassemble; its check did not run" >&2
            exit 3
        fi
    fi
    NM_OUT="$(arm-none-eabi-nm "target/$TARGET/firmware.elf")"
    for sym in $RAM_FUNCS; do
        # Skip the long-call thunks; they are meant to be in flash.
        # `|| true`: the script runs under `set -e -o pipefail`, so a grep
        # that matches nothing would abort here and the diagnostic below
        # would never print. The empty case is handled, not fatal.
        addrs="$(echo "$NM_OUT" | grep -- "$sym" | grep -v Thunk | awk '{print $1}' || true)"
        [[ -n "$addrs" ]] || { echo "firmware: $sym not found in ELF" >&2; exit 3; }
        for a in $addrs; do
            if [[ "0x$a" -lt $((0x20000000)) ]]; then
                echo "firmware: $sym is at 0x$a, outside RAM — it must not run from flash" >&2
                exit 3
            fi
        done
    done
    ;;
esac

# Bound the kernel's own depth on each core's stack.
#
# A frame that outgrows the stack a core steps its modules on is a fault of
# the whole node, so the build bounds the kernel's share of each from the
# image's own call tree (`tools/img/kernel_stack_bound.py` reads it; its
# header states the method) and refuses an image over it:
#
#   - under a module stepped on core 0, every RP silicon: within the target's
#     `[kernel] kernel_stack_reserve_kb`, the share of the stack the composer
#     keeps from a module: what is in use where the pass engine calls the
#     module, the deepest call the module can make back (every entry of the
#     syscall table, through the provider table into every handler the
#     kernel registers, the primary-core ops included), one interrupt on top,
#     and HOOK_ALLOWANCE for the platform hooks the walk counts but cannot
#     follow;
#   - on a second core that runs a domain (rp2350): from the core's entry
#     within its `[smp] secondary_stack` less KERNEL_HEADROOM, and under a
#     module within the stack's `reserve_kb`, the same sum. The primary-core
#     ops are not in it: a second core hands them to core 0 as their first
#     act, so the kernel's `primary_` functions count for their own frame
#     there and no deeper.
#
# Where calls through registers lead:
#   - the log facade reaches the kernel's logger, and the formatter its
#     writer;
#   - the provider table's dispatch code (the provider module, the syscall
#     wrappers that inline it, the kernel bucket's call to the platform
#     extension) reaches the handlers registered by the two functions that
#     fill the tables, one dispatch deep; the script reads the handlers from
#     the image.
#
# Functions counted for their own frame and not walked below: the panic
# handler, which ends the core and is bounded as a root of its own (a panic
# inside it is counted for the entry's frame); and a table's first-use
# sizing, which runs once, at boot on core 0 for every table a pass reads.
#
# The interrupts are the lines each core enables: its step guard, its wake
# alarm, its module timer, its DMA line and a module's bound line.
case "$SILICON" in
  rp2040|rp2350)
    silicon_kb() {
        sed -n "s/^$1[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p" "$SILICON_TOML" | head -1
    }
    CORE0_RESERVE_KB="$(silicon_kb kernel_stack_reserve_kb)"
    STATIC_MAX_KB="$(silicon_kb ram_static_max_kb)"
    RAM_BYTES="$(sed -n 's/^ram_size[[:space:]]*=[[:space:]]*"\(0x[0-9A-Fa-f]*\)".*/\1/p' "$SILICON_TOML" | head -1)"
    [[ -n "$CORE0_RESERVE_KB" && -n "$STATIC_MAX_KB" && -n "$RAM_BYTES" ]] || {
        echo "firmware: $SILICON_TOML declares no kernel_stack_reserve_kb, ram_static_max_kb or ram_size" >&2
        exit 6
    }
    KERNEL_HEADROOM=2048
    HOOK_ALLOWANCE=256
    WHERE_CALLS_LEAD=(
        --leaf rust_begin_unwind --leaf "Raw::size_on_first_use"
        --reaches "GlobalLogger as log::Log>::log=RingLogger as log::Log>::log"
        --reaches "core::fmt::write=BufWriter as core::fmt::Write"
        --dispatch-from "kernel::module::provider::"
        --dispatch-from "kernel::module::syscalls::system_provider_dispatch"
        --dispatch-from "kernel::module::syscalls::syscall_provider_"
        --dispatch-from "kernel::module::syscalls::release_module_handles"
        --dispatch-table "kernel::module::syscalls::init_providers"
        --dispatch-table "platform::rp_providers::init"
        --dispatch-depth 1
    )
    SYSCALL_ENTRIES=(
        --entry syscall_channel_read --entry syscall_channel_write
        --entry syscall_channel_poll --entry syscall_channel_peek
        --entry syscall_channel_discard
        --entry syscall_heap_alloc --entry syscall_heap_free --entry syscall_heap_realloc
        --entry syscall_provider_open --entry syscall_provider_call
        --entry syscall_provider_query --entry syscall_provider_close
    )
    if [[ "$SILICON" == "rp2350" ]]; then
        CORE0_LINES=(--interrupt TIMER1_IRQ_0 --interrupt TIMER1_IRQ_1 --interrupt TIMER1_IRQ_2)
    else
        CORE0_LINES=(--interrupt TIMER_IRQ_1 --interrupt TIMER_IRQ_2 --interrupt TIMER_IRQ_3)
    fi
    python3 tools/img/kernel_stack_bound.py "target/$TARGET/firmware.elf" \
        --root fluxor_rp_main \
        --limit $(( RAM_BYTES - STATIC_MAX_KB * 1024 - KERNEL_HEADROOM )) \
        "${WHERE_CALLS_LEAD[@]}" \
        --depth-at "scheduler::pass::step_burst" \
        --depth-at-limit $((CORE0_RESERVE_KB * 1024)) \
        "${SYSCALL_ENTRIES[@]}" \
        "${CORE0_LINES[@]}" --interrupt DMA_IRQ_0 \
        --interrupt kernel::exec::irq::irq_trampoline \
        --allowance "$HOOK_ALLOWANCE" || exit 6
    if [[ "$SILICON" == "rp2350" ]]; then
        secondary_field() {
            sed -n "s/^secondary_stack[[:space:]]*=.*[{,][[:space:]]*$1[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p" "$SILICON_TOML"
        }
        STACK_KB="$(secondary_field size_kb)"
        RESERVE_KB="$(secondary_field reserve_kb)"
        [[ -n "$STACK_KB" && -n "$RESERVE_KB" ]] || {
            echo "firmware: $SILICON_TOML declares no [smp] secondary_stack size_kb and reserve_kb" >&2
            exit 6
        }
        python3 tools/img/kernel_stack_bound.py "target/$TARGET/firmware.elf" \
            --root fluxor::platform::rp_core1::core1_entry \
            --limit $((STACK_KB * 1024 - KERNEL_HEADROOM)) \
            "${WHERE_CALLS_LEAD[@]}" \
            --leaf "kernel::module::syscalls::primary_" \
            --depth-at "scheduler::pass::step_burst" \
            --depth-at-limit $((RESERVE_KB * 1024)) \
            "${SYSCALL_ENTRIES[@]}" \
            --interrupt TIMER0_IRQ_1 --interrupt TIMER0_IRQ_2 --interrupt TIMER0_IRQ_3 \
            --interrupt DMA_IRQ_1 --interrupt kernel::exec::irq::irq_trampoline \
            --allowance "$HOOK_ALLOWANCE" || exit 6
    fi
    python3 tools/img/kernel_stack_bound.py "target/$TARGET/firmware.elf" \
        --root rust_begin_unwind --limit "$KERNEL_HEADROOM" \
        --leaf "Raw::size_on_first_use" --leaf "core::panicking::panic" || exit 6
    ;;
esac
