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
_ENARX_PML3  = ABSOLUTE(_ENARX_START + 0 * 4K);
_ENARX_PML4  = ABSOLUTE(_ENARX_START + 1 * 4K);
_ENARX_CPUID = ABSOLUTE(_ENARX_START + 2 * 4K);

ASSERT((_ENARX_SHIM_START >= (3 * 0x40000000)), "SHIM_START is too low for current initial identity page table")
ASSERT((_ENARX_EXEC_START < (6 * 0x40000000)), "SHIM is too large for current initial identity page table")

SECTIONS {
    . = _ENARX_PML3;
    _ENARX_MEM_START = .;

    .pml3 : ALIGN(4K) {
        QUAD(0);
        QUAD(0);
        QUAD(0);
        QUAD(3 * 0x40000000 + 0x83); /* Flags::HUGE_PAGE | Flags::WRITABLE | Flags::PRESENT */
        QUAD(4 * 0x40000000 + 0x83); /* Flags::HUGE_PAGE | Flags::WRITABLE | Flags::PRESENT */
        QUAD(5 * 0x40000000 + 0x83); /* Flags::HUGE_PAGE | Flags::WRITABLE | Flags::PRESENT */
        FILL(0);
        . = ALIGN(4K);
    } :pagetables

    . = _ENARX_PML4;
    .pml4 : ALIGN(4K) {
        QUAD(_ENARX_PML3 + 0x3); /* Flags::WRITABLE | Flags::PRESENT */
        FILL(0);
        . = ALIGN(4K);
    } :pagetables

    . = _ENARX_CPUID;
    .cpuid (NOLOAD) : ALIGN(4K) {
        . += 4K;
    } :cpuid

    .ghcb (NOLOAD) : ALIGN(4K) {
        _ENARX_GHCB = .;
        *(.ghcb .ghcb.*)
    } :ghcb

    .secrets (NOLOAD) : ALIGN(4K) {
        _ENARX_SECRETS = .;
        . += 4K;
    } :secrets

    .sallyport (NOLOAD) : ALIGN(4K) { *(.sallyport .sallyport.*) } :sallyport

    . = _ENARX_SHIM_START;

    .reset_text   : { KEEP(*(.reset)) } :boot_text
    .rcrt1_text   : { rcrt1*.text rcrt1*.text.* } :boot_text

    . = ALIGN(4K);
    .dynamic            : { *(.dynamic) } :boot_data :dynamic
    .boot_data          : { KEEP(*(.entry64_data)) rcrt1*.data rcrt1*.data.* } :boot_data
    .data.rel.ro        : { *(.data.rel.ro .data.rel.ro.*) } :boot_data
    .got                : { *(.got) } :boot_data

    . = ALIGN(4K);
    .text               : { *(.text .text.*) } :text
    .rela.dyn           : { *(.rela.*) } :text

    . = ALIGN(4K);
    .rodata             : { *(.rodata .rodata.*) } :rodata
    .note               : { *(.note) } :rodata :note
    .dynsym             : { *(.dynsym) } :rodata
    .dynstr             : { *(.dynstr) } :rodata
    .gnu.hash           : { *(.gnu.hash) } :rodata
    .hash               : { *(.hash) } :rodata

    . = ALIGN(4K);
    .data               : { *(.data .data.*) } :data
    .bss                : { *(.bss .bss.*) } :data

    .code : ALIGN(2M) {
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
