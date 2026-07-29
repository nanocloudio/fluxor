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
 * (abi::config::kernel: STATE_ARENA_SIZE 96M + BUFFER_ARENA_SIZE 8M) plus
 * the fixed tables/pools. 192M leaves headroom and both backings cover it:
 * QEMU virt runs with -m 256M (origin 0x4008_0000 → region ends 0x4C08_0000,
 * ~63M left for the relocated package payload above __end_block_addr) and
 * Pi 5 has 8 GiB. */
MEMORY {
    RAM : ORIGIN = RAM_ORIGIN, LENGTH = 192M
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
