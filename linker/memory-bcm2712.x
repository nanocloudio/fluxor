/* BCM2712 / aarch64 bare-metal linker script
 *
 * RAM origin is board-dependent:
 *   QEMU virt: 0x4008_0000 (default -kernel load address)
 *   Pi 5: 0x8_0000 (GPU firmware loads kernel8.img here)
 *
 * Origin is set by build.rs via: -DRAM_ORIGIN=0x... (cargo:rustc-link-arg)
 * Default: QEMU virt address if not overridden.
 */

ENTRY(_start)
EXTERN(_start)

/* LENGTH must hold .bss, which is dominated by the profile_host arenas
 * (abi::config::kernel: STATE_ARENA_SIZE 256M + BUFFER_ARENA_SIZE 8M — the
 * state arena is sized around the ip module's 65,536-slot connection
 * table) plus the fixed tables/pools and the 16M-aligned .bss window. 512M
 * leaves headroom and both backings cover it: QEMU virt runs with -m 1G
 * (origin 0x4008_0000 → region ends 0x6008_0000, ~511M left for the
 * relocated package payload above __end_block_addr) and Pi 5 has 8 GiB. */
MEMORY {
    RAM : ORIGIN = RAM_ORIGIN, LENGTH = 512M
}

SECTIONS {
    .text : {
        KEEP(*(.text._start))
        *(.text .text.*)
    } > RAM

    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
    } > RAM

    .data : ALIGN(8) {
        *(.data .data.*)
    } > RAM

    .layout_header : ALIGN(8) {
        KEEP(*(.layout_header))
    } > RAM

    /* End of loadable (file-backed) sections. Pack-image and combine
     * pad from this address up to the trailer's 256-byte boundary, so
     * __end_data_addr must mark the true end of the emitted binary
     * (no ALIGN here) for the trailer to land at the right offset. */
    __end_data_addr = .;

    /* PAYLOAD WINDOW. A RAM-loaded image (Pi 5: the VPU drops the whole
     * kernel_2712.img at RAM_ORIGIN) carries its module blob + config
     * appended after __end_data_addr, and `_start` zeroes
     * __bss_start..__bss_end before `main` runs. Anything appended at or
     * past __bss_start is therefore ERASED before the loader reads it —
     * the module table decodes as empty and the board boots a graph with
     * no modules: no network, no telemetry, no console, indistinguishable
     * from a board that never booted.
     *
     * With plain ALIGN(4096) the usable window is only the gap that
     * happens to fall between the firmware's end and the next alignment
     * boundary — an accidental budget that shrinks with every byte of
     * firmware growth and truncates payloads silently at a ceiling no
     * config file records. 16 MiB alignment makes the window a
     * deliberate ~13 MiB, so the real bound is the loader's designed
     * MAX_MODULES_BLOB_SIZE (8 MiB) rather than a layout artifact.
     * Costs nothing: .bss is NOLOAD, so the gap is unused address space,
     * not image bytes, and the region below (512M) still holds everything.
     */
    .bss (NOLOAD) : ALIGN(0x1000000) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    .uninit (NOLOAD) : ALIGN(8) {
        *(.uninit .uninit.*)
    } > RAM

    /* Stack in RAM, not part of the loadable image. 1 MB covers the deep
       call chains in the P-256 primitives (each curve constant materialised
       on the stack per call). */
    . = ALIGN(16);
    __stack_start = .;
    . = . + 1M;
    __stack_end = .;

    /* End of runtime-reserved RAM. Relocated package payload lives above this. */
    __end_block_addr = .;

    /DISCARD/ : {
        *(.ARM.exidx .ARM.exidx.*)
        *(.eh_frame)
    }
}

__start_block_addr = 0;
