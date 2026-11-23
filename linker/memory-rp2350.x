MEMORY {
    /*
     * Pico 2 / RP2350 has 4MB of Flash (Pico 2 W same)
     */
    FLASH : ORIGIN = 0x10000000, LENGTH = 4096K
    /*
     * RAM consists of 8 banks, SRAM0-SRAM7, with a striped mapping.
     * This is usually good for performance, as it distributes load on
     * those banks evenly.
     */
    RAM : ORIGIN = 0x20000000, LENGTH = 512K
    /*
     * SRAM8 and SRAM9 are direct-mapped, 4 KiB each, directly above the
     * striped region. Together they are core 1's stack: nothing is linked
     * into them.
     */
    SRAM8 : ORIGIN = 0x20080000, LENGTH = 4K
    SRAM9 : ORIGIN = 0x20081000, LENGTH = 4K
}

SECTIONS {
    /* ### Boot ROM info
     *
     * Goes after .vector_table, to keep it in the first 4K of flash
     * where the Boot ROM (and picotool) can find it
     */
    .start_block : ALIGN(4)
    {
        __start_block_addr = .;
        KEEP(*(.start_block));
        KEEP(*(.boot_info));
    } > FLASH

} INSERT AFTER .vector_table;

/* move .text to start /after/ the boot info */
_stext = ADDR(.start_block) + SIZEOF(.start_block);

SECTIONS {
    /* ### Picotool 'Binary Info' Entries
     *
     * Picotool looks through this block (as we have pointers to it in our
     * header) to find interesting information.
     */
    .bi_entries : ALIGN(4)
    {
        /* We put this in the header */
        __bi_entries_start = .;
        /* Here are the entries */
        KEEP(*(.bi_entries));
        /* Keep this block a nice round size */
        . = ALIGN(4);
        /* We put this in the header */
        __bi_entries_end = .;
    } > FLASH
} INSERT AFTER .text;

SECTIONS {
    /* ### Boot ROM extra info
     *
     * Goes after everything in our program, so it can contain a signature.
     */
    .end_block : ALIGN(4)
    {
        __end_block_addr = .;
        KEEP(*(.end_block));
    } > FLASH

} INSERT AFTER .uninit;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);

/* Expose flash bounds to platform code so `validate_fn_addr` reads
 * the authoritative size from the linker rather than a hardcoded
 * constant. */
PROVIDE(__flash_start__ = ORIGIN(FLASH));
PROVIDE(__flash_end__ = ORIGIN(FLASH) + LENGTH(FLASH));

/* Core 1's stack: SRAM8 and SRAM9, contiguous. */
PROVIDE(__core1_stack_limit = ORIGIN(SRAM8));
PROVIDE(__core1_stack_top = ORIGIN(SRAM9) + LENGTH(SRAM9));
ASSERT(ORIGIN(SRAM9) == ORIGIN(SRAM8) + LENGTH(SRAM8), "SRAM8 and SRAM9 are not contiguous");

/* Exclusive accesses are arbitrated between the cores only in main SRAM
 * (0x20000000 to 0x20082000). Every lock word and atomic the two cores share
 * is a static, so all static RAM must lie inside it. */
ASSERT(__sdata >= 0x20000000 && __stack_limit <= 0x20082000,
       "static RAM lies outside the SRAM the exclusive monitor covers");
