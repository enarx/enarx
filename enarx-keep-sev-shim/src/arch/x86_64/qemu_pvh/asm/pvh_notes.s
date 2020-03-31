# SPDX-License-Identifier: Apache-2.0

XEN_ELFNOTE_ENTRY          = 1
XEN_ELFNOTE_HYPERCALL_PAGE = 2
XEN_ELFNOTE_VIRT_BASE      = 3
XEN_ELFNOTE_PADDR_OFFSET   = 4
XEN_ELFNOTE_PHYS32_ENTRY   = 18

.macro ELFNOTE type desc
    .align 4
    .long 4     /* namesz */
    .long 4     /* descsz */
    .long \type
    .asciz "Xen"
    .align 4
    .long  \desc
    .align 4
.endm

.section .notes, "a"
.global _elf_note

_elf_note:
#ELFNOTE XEN_ELFNOTE_VIRT_BASE 0
#ELFNOTE XEN_ELFNOTE_ENTRY ram32_start
ELFNOTE XEN_ELFNOTE_PHYS32_ENTRY ram32_start
#ELFNOTE XEN_ELFNOTE_HYPERCALL_PAGE 0x1000
#ELFNOTE XEN_ELFNOTE_PADDR_OFFSET 0
