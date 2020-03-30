OUTPUT_FORMAT(elf64-x86-64)

ENTRY(_start)
EXTERN(_elf_note)
EXTERN(ram32_start)

PHDRS
{
    pvh_notes   PT_NOTE FLAGS(0);
    pvh_text    PT_LOAD;
    pvh_bss     PT_LOAD;
    pml_data    PT_LOAD;

    rodata      PT_LOAD;
    data        PT_LOAD;
    text        PT_LOAD;
}

KERNEL_OFFSET = 0x80000000000;

/* Loaders like to put stuff in low memory (< 1M), so we don't use it. */
ram_min = 1M;
ram_max = 4M;

SECTIONS
{
    . = 1M;
    .pvh_notes  : { KEEP(*(.notes .notes.* .notes)) } :pvh_notes :pvh_text
    .pvh_text   : { KEEP(*(.ram64 .ram32))
                    KEEP(*(.entry64))             } :pvh_text
    .pvh_bss    : { KEEP(*(.bss.stack))           } :pvh_bss
    .pml_data   : { KEEP(*(.pmldata))           } :pml_data

    . = 2M + KERNEL_OFFSET;
    .rodata : AT(ADDR(.rodata) - KERNEL_OFFSET) { *(.rodata .rodata.*)            } :rodata
    .text   : AT(ADDR(.text)   - KERNEL_OFFSET) { *(.text .text.*)                } :text
    .data   : AT(ADDR(.data)   - KERNEL_OFFSET) { *(.data .data.*) *(.got .got.*) *(.bss .bss.*) } :data

    _kernel_start = ADDR(.rodata) - KERNEL_OFFSET;
    _kernel_end = . - KERNEL_OFFSET;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note.GNU-stack)
        *(.gnu_debuglink)
        *(.interp)
        *(.dynsym)
        *(.dynstr)
        *(.dynamic)
        *(.hash .gnu.hash)
        *(.comment)
        *(COMMON)
        *(.gcc_except_table)
        *(.rela.dyn)
        *(.note.gnu.build-id)
    }
}
