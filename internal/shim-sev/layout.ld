/* SPDX-License-Identifier: Apache-2.0 */

ENTRY(_start)
EXTERN(__SALLYPORT_ABI_)

PHDRS {
    sallyport    PT_LOAD FLAGS(1 << 22); /* sallyport::elf::pf::kvm::SALLYPORT */

    ghcb         PT_LOAD;
    secrets      PT_LOAD FLAGS(1 << 24); /* sallyport::elf::pf::kvm::SECRETS */
    cpuid        PT_LOAD FLAGS(1 << 23); /* sallyport::elf::pf::kvm::CPUID */

    pagetables   PT_LOAD;

    boot_text    PT_LOAD;
    boot_data    PT_LOAD;

    text         PT_LOAD;
    rodata       PT_LOAD;
    data         PT_LOAD;

    dynamic      PT_DYNAMIC;
    note         PT_NOTE;

    exec         0x63400000 FLAGS(0);
}

/* Configure this to a reasonable size
   Current block size is 69632, which gives a maximum count of 15420
   for the 3GB - 4GB range.
*/
_ENARX_SALLYPORT_BLOCK_COUNT = 2;
_ENARX_SALLYPORT_BLOCK_SIZE = 69632;

_ENARX_SALLYPORT_SIZE = ALIGN(_ENARX_SALLYPORT_BLOCK_COUNT * _ENARX_SALLYPORT_BLOCK_SIZE, CONSTANT(COMMONPAGESIZE));

ASSERT((_ENARX_SALLYPORT_SIZE <  (0x40000000 - 2 * CONSTANT(COMMONPAGESIZE))), "_ENARX_SALLYPORT_SIZE too big")

reset_vector = 0xFFFFF000;
_ENARX_SHIM_START = reset_vector;
_ENARX_SALLYPORT_START = _ENARX_SHIM_START - _ENARX_SALLYPORT_SIZE - 5 * CONSTANT(COMMONPAGESIZE);
_ENARX_SALLYPORT_END = _ENARX_SALLYPORT_START + _ENARX_SALLYPORT_SIZE;
_ENARX_EXEC_LEN = 128M;

ASSERT((_ENARX_SHIM_START >= (3 * 0x40000000)), "SHIM_START is too low for current initial identity page table")
ASSERT((_ENARX_EXEC_START < (6 * 0x40000000)), "SHIM is too large for current initial identity page table")

ASSERT((pml4t_ident == (reset_vector - CONSTANT(COMMONPAGESIZE))), "pml4t_ident not at 0xFFFFE000")
ASSERT((pml3t_ident == (reset_vector - 2*CONSTANT(COMMONPAGESIZE))), "pml3t_ident not at 0xFFFFD000")
ASSERT((_ENARX_CPUID == (reset_vector - 3*CONSTANT(COMMONPAGESIZE))), "_ENARX_CPUID not at 0xFFFFC000")
ASSERT((_ENARX_SECRETS == (reset_vector - 4*CONSTANT(COMMONPAGESIZE))), "_ENARX_SECRETS not at 0xFFFFB000")
ASSERT((_ENARX_GHCB == (reset_vector - 5*CONSTANT(COMMONPAGESIZE))), "_ENARX_GHCB not at 0xFFFFA000")

SECTIONS {
    . = _ENARX_SALLYPORT_START;
    _ENARX_MEM_START = ABSOLUTE(.);

    .sallyport (NOLOAD) : ALIGN(CONSTANT(COMMONPAGESIZE))  {
        . = _ENARX_SALLYPORT_SIZE;
    } :sallyport

    .ghcb (NOLOAD) : ALIGN(CONSTANT(COMMONPAGESIZE)) {
        _ENARX_GHCB = .;
        . += CONSTANT(COMMONPAGESIZE);
    } :ghcb

    .secrets (NOLOAD) : ALIGN(CONSTANT(COMMONPAGESIZE)) {
        _ENARX_SECRETS = .;
        . += CONSTANT(COMMONPAGESIZE);
    } :secrets

    .cpuid (NOLOAD) : ALIGN(CONSTANT(COMMONPAGESIZE)) {
        _ENARX_CPUID = .;
        . += CONSTANT(COMMONPAGESIZE);
    } :cpuid

    .pml3 : ALIGN(CONSTANT(COMMONPAGESIZE)) {
        PROVIDE_HIDDEN(pml3t_ident = ABSOLUTE(.));
        QUAD(0);
        QUAD(0);
        QUAD(0);
        QUAD(3 * 0x40000000 + 0x83); /* Flags::HUGE_PAGE | Flags::WRITABLE | Flags::PRESENT */
        QUAD(4 * 0x40000000 + 0x83); /* Flags::HUGE_PAGE | Flags::WRITABLE | Flags::PRESENT */
        QUAD(5 * 0x40000000 + 0x83); /* Flags::HUGE_PAGE | Flags::WRITABLE | Flags::PRESENT */
        FILL(0);
        . = CONSTANT(COMMONPAGESIZE);
    } :pagetables

    .pml4 : ALIGN(CONSTANT(COMMONPAGESIZE)) {
        PROVIDE_HIDDEN(pml4t_ident = ABSOLUTE(.));
        QUAD(pml3t_ident + 0x3); /* Flags::WRITABLE | Flags::PRESENT */
        FILL(0);
        . = CONSTANT(COMMONPAGESIZE);
    } :pagetables

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
        _ENARX_EXEC_START = ABSOLUTE(.);
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
