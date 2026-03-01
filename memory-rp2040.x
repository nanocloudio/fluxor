MEMORY {
    /*
     * RP2040: 256-byte boot2 second-stage bootloader lives at the very start.
     */
    BOOT2 : ORIGIN = 0x10000000, LENGTH = 0x100
    /*
     * RP2040: 2MB Flash, after boot2.
     */
    FLASH : ORIGIN = 0x10000100, LENGTH = 2048K - 0x100
    /*
     * RP2040: 264KB SRAM (6 banks: 4x 64KB striped + 2x 4KB).
     * Striped banks 0-3: 256KB total.
     */
    RAM : ORIGIN = 0x20000000, LENGTH = 256K
    /*
     * SRAM4 and SRAM5: non-striped, 4KB each.
     */
    SRAM4 : ORIGIN = 0x20040000, LENGTH = 4K
    SRAM5 : ORIGIN = 0x20041000, LENGTH = 4K
}

SECTIONS {
    /* ### Boot2 second-stage bootloader (must be at 0x10000000) */
    .boot2 ORIGIN(BOOT2) :
    {
        KEEP(*(.boot2));
    } > BOOT2
}

SECTIONS {
    /* ### Picotool 'Binary Info' Entries */
    .bi_entries : ALIGN(4)
    {
        __bi_entries_start = .;
        KEEP(*(.bi_entries));
        . = ALIGN(4);
        __bi_entries_end = .;
    } > FLASH
} INSERT AFTER .text;

SECTIONS {
    /*
     * Firmware end marker — equivalent to RP2350's end_block.
     * Placed after .uninit so the combine tool can find the trailer.
     */
    .fluxor_end : ALIGN(4)
    {
        __end_block_addr = .;
    } > FLASH
} INSERT AFTER .uninit;
