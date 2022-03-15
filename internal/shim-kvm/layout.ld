/* SPDX-License-Identifier: Apache-2.0 */

ENTRY(_start)
EXTERN(__SALLYPORT_ABI_)

PHDRS {
    pagetables   PT_LOAD;

    cpuid        PT_LOAD FLAGS(1 << 23); /* sallyport::elf::pf::kvm::CPUID */
    ghcb         PT_LOAD;
    secrets      PT_LOAD FLAGS(1 << 24); /* sallyport::elf::pf::kvm::SECRETS */

    sallyport    PT_LOAD FLAGS(1 << 22); /* sallyport::elf::pf::kvm::SALLYPORT */

    boot_text    PT_LOAD;
    boot_data    PT_LOAD;

    text         PT_LOAD;
    rodata       PT_LOAD;
    data         PT_LOAD;

    dynamic      PT_DYNAMIC;
    note         PT_NOTE;

    exec         0x63400000 FLAGS(0);
}

_ENARX_SHIM_START = 0xFFFFF000;
_ENARX_START = ABSOLUTE(0xFFE00000);
_ENARX_EXEC_LEN = 128M;

/*
 * These 3 sections need to be fixed for the startup asm block to work
 */
_ENARX_PML3  = ABSOLUTE(_ENARX_START + 0 * CONSTANT(COMMONPAGESIZE));
_ENARX_PML4  = ABSOLUTE(_ENARX_START + 1 * CONSTANT(COMMONPAGESIZE));
_ENARX_CPUID = ABSOLUTE(_ENARX_START + 2 * CONSTANT(COMMONPAGESIZE));

ASSERT((_ENARX_SHIM_START >= (3 * 0x40000000)), "SHIM_START is too low for current initial identity page table")
ASSERT((_ENARX_EXEC_START < (6 * 0x40000000)), "SHIM is too large for current initial identity page table")

SECTIONS {
    . = _ENARX_PML3;
    _ENARX_MEM_START = .;

    .pml3 : ALIGN(CONSTANT(COMMONPAGESIZE)) {
        QUAD(0);
        QUAD(0);
        QUAD(0);
        QUAD(3 * 0x40000000 + 0x83); /* Flags::HUGE_PAGE | Flags::WRITABLE | Flags::PRESENT */
        QUAD(4 * 0x40000000 + 0x83); /* Flags::HUGE_PAGE | Flags::WRITABLE | Flags::PRESENT */
        QUAD(5 * 0x40000000 + 0x83); /* Flags::HUGE_PAGE | Flags::WRITABLE | Flags::PRESENT */
        FILL(0);
        . = ALIGN(CONSTANT(COMMONPAGESIZE));
    } :pagetables

    . = _ENARX_PML4;
    .pml4 : ALIGN(CONSTANT(COMMONPAGESIZE)) {
        QUAD(_ENARX_PML3 + 0x3); /* Flags::WRITABLE | Flags::PRESENT */
        FILL(0);
        . = ALIGN(CONSTANT(COMMONPAGESIZE));
    } :pagetables

    . = _ENARX_CPUID;
    .cpuid (NOLOAD) : ALIGN(CONSTANT(COMMONPAGESIZE)) {
        . += CONSTANT(COMMONPAGESIZE);
    } :cpuid

    .ghcb (NOLOAD) : ALIGN(CONSTANT(COMMONPAGESIZE)) {
        _ENARX_GHCB = .;
        *(.ghcb .ghcb.*)
    } :ghcb

    .secrets (NOLOAD) : ALIGN(CONSTANT(COMMONPAGESIZE)) {
        _ENARX_SECRETS = .;
        . += CONSTANT(COMMONPAGESIZE);
    } :secrets

    .sallyport (NOLOAD) : ALIGN(CONSTANT(COMMONPAGESIZE)) { *(.sallyport .sallyport.*) } :sallyport

    . = _ENARX_SHIM_START;

    .reset_text   : { KEEP(*(.reset)) } :boot_text
    .rcrt1_text   : { rcrt1*.text rcrt1*.text.* } :boot_text

    . = ALIGN(CONSTANT(COMMONPAGESIZE));
    .dynamic            : { *(.dynamic) } :boot_data :dynamic
    .boot_data          : { KEEP(*(.entry64_data)) rcrt1*.data rcrt1*.data.* } :boot_data
    .data.rel.ro        : { *(.data.rel.ro .data.rel.ro.*) } :boot_data
    .got                : { *(.got) } :boot_data

    . = ALIGN(CONSTANT(COMMONPAGESIZE));
    .text               : { *(.text .text.*) } :text
    .rela.dyn           : { *(.rela.*) } :text

    . = ALIGN(CONSTANT(COMMONPAGESIZE));
    .rodata             : { *(.rodata .rodata.*) } :rodata
    .note               : { *(.note) } :rodata :note
    .dynsym             : { *(.dynsym) } :rodata
    .dynstr             : { *(.dynstr) } :rodata
    .gnu.hash           : { *(.gnu.hash) } :rodata
    .hash               : { *(.hash) } :rodata

    . = ALIGN(CONSTANT(COMMONPAGESIZE));
    .data               : { *(.data .data.*) } :data
    .bss                : { *(.bss .bss.*) } :data

    .code : ALIGN(CONSTANT(COMMONPAGESIZE)) {
        _ENARX_EXEC_START = .;
        FILL(0);
        . += _ENARX_EXEC_LEN;
    } :exec
    _ENARX_EXEC_END = .;

    /DISCARD/ : {
      *(.eh_frame*)
      *(.note.GNU-stack)
      *(.gnu_debuglink)
      *(.interp)
      *(.comment)
      *(COMMON)
      *(.note.gnu.build-id)
    }
}
