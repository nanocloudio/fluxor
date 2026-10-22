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

/* RAM holds the image, the payload window after it (the module table and
 * config the packer appends, read in place), .bss (the buffer arena, elastic
 * region, OTA staging buffers and DMA arenas) and the stack.
 *
 * Nothing else of the kernel's is linked. The kernel's boot-sized tables and
 * the module state arena live in the DRAM zone the device tree describes
 * above RAM_CEILING (platform/bcm2712/memmap.rs): the tables carved from the
 * zone's top, zeroed as each is carved, the arena taking the rest and zeroing
 * what it hands out — never a region wholesale, and never at boot. On the
 * Pi 5 the firmware's memory map (the DTB's /memory node) is 0..0x3FC0_0000
 * and 0x4000_0000 up: the top 4 MiB of the first GB is the firmware's (its
 * nvram copy sits at 0x3FD2_xxxx), and the firmware places the DTB and
 * initramfs near 0x2E00_0000. A boot that writes over either never comes up,
 * so RAM stays below them and the zone starts at 1 GB. QEMU virt's zone
 * starts at 2 GB, above this region. */
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
       on the stack per call). The page below it is the guard: left unmapped
       in the kernel's table (and every isolated module's), so an overflow
       takes a translation fault at an address instead of writing through
       whatever lies beneath. */
    . = ALIGN(4096);
    __stack_guard = .;
    . = . + 4096;
    __stack_start = .;
    . = . + 1M;
    __stack_end = .;

    /* End of runtime-reserved RAM. */
    __end_block_addr = .;

    /DISCARD/ : {
        *(.ARM.exidx .ARM.exidx.*)
        *(.eh_frame)
    }
}

__start_block_addr = 0;

/* Everything the kernel reserves in RAM — image, .bss, the stack — must end
 * below RAM_CEILING (build.rs: 0x2E00_0000 on the Pi 5, where the firmware
 * places the DTB and initramfs; 0x8000_0000 on QEMU virt, where the zone
 * starts). On the Pi 5 a
 * .bss grown past it does not fail: the boot writes over the firmware's
 * region and the board stays dark with nothing on any console. A kernel
 * capacity raise that would do that fails the link here instead. */
ASSERT(__end_block_addr <= RAM_CEILING,
       "kernel RAM (image + .bss + stack) runs past RAM_CEILING: on a Pi 5 it would overwrite the firmware's DTB/initramfs at 0x2E000000 and boot dark. Shrink a .bss table in kernel::config.")

