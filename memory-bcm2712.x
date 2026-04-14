/* BCM2712 / aarch64 bare-metal linker script
 *
 * RAM origin is board-dependent:
 *   QEMU virt: 0x4008_0000 (default -kernel load address)
 *   Pi 5 / CM5: 0x8_0000 (GPU firmware loads kernel8.img here)
 *
 * Origin is set by build.rs via: -DRAM_ORIGIN=0x... (cargo:rustc-link-arg)
 * Default: QEMU virt address if not overridden.
 */

ENTRY(_start)
EXTERN(_start)

MEMORY {
    RAM : ORIGIN = RAM_ORIGIN, LENGTH = 128M
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

    /* End of loadable (file-backed) sections.
     * On aarch64 (RAM-loaded), the combine trailer is placed right after this
     * rather than after __end_block_addr (which includes BSS + stack). */
    . = ALIGN(256);
    __end_data_addr = .;

    .bss (NOLOAD) : ALIGN(4096) {
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
