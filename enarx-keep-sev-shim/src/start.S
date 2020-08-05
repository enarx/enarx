// SPDX-License-Identifier: Apache-2.0

//! This is the elf entry point called by enarx-keep-sev
//!
//! It sets up essential registers, page tables and jumps in shim virtual address space
//! to the `_start_main` rust function.
//!
//! Arguments expected from the hypervisor:
//! %rdi  = address of SYSCALL_PAGE (boot_info)
//! %rsi  = shim load offset

// maximum offset for the offset page table
// gives the shim immediate 512GB addressable physical memory
#define SHIM_OFFSET 0xFFFFFF8000000000

#define SIZE_OF_INITIAL_STACK 0x10000

.section .text
.global _start
.hidden _DYNAMIC
.code64
.p2align 4

# Arguments expected from the hypervisor:
# arg1 %rdi  = address of SYSCALL_PAGE (boot_info)
# arg2 %rsi  = shim load offset
_start:
    # setup CR4
    mov    %cr4, %rax
    # FIXME: what about already set bits?
    or     $0x50620, %rax    # set FSGSBASE | PAE | OSFXSR | OSXMMEXCPT | OSXSAVE
    mov    %rax, %cr4

    # setup CR0
    mov    %cr0, %rax
    and    $0x60050009, %eax # mask EMULATE_COPROCESSOR | MONITOR_COPROCESSOR
    or     $0x80000021, %eax # set  PROTECTED_MODE_ENABLE | NUMERIC_ERROR | PAGING
    mov    %rax, %cr0

    # setup EFER
    # EFER |= LONG_MODE_ACTIVE | LONG_MODE_ENABLE | NO_EXECUTE_ENABLE | SYSTEM_CALL_EXTENSIONS
    # FIXME: what about already set bits?
    mov    $0xc0000080, %ecx
    rdmsr
    or     $0xd01, %eax
    mov    $0xc0000080, %ecx
    wrmsr

    # Setup the pagetables
    # done dynamically, otherwise we would have to correct the dynamic symbols twice
    lea  PML4T(%rip), %rax

    lea  PDPT_OFFSET(%rip), %rbx
    or   $0b11, %rbx    # (WRITABLE | PRESENT)
    # store PDPT_OFFSET table in PML4T in the correct slot
    # for SHIM_OFFSET
    mov  %rbx, (((SHIM_OFFSET & 0xFFFFFFFFFFFF) >> 39)*8)(%rax)

    lea  PDPT_IDENT(%rip), %rbx

    lea  PDT_IDENT(%rip), %rcx
    or   $0b111, %rcx   # (USER_ACCESSIBLE | WRITABLE | PRESENT)
    # store PDT_IDENT table in PDPT_IDENT in the correct slot
    # 0x0 - 0x4000_0000
    mov  %rcx, (%rbx)

    or   $0b111, %rbx   # (USER_ACCESSIBLE | WRITABLE | PRESENT)
    # store PDPT_IDENT table in PML4T in the correct slot
    # 0x0 - ...
    mov  %rbx, (%rax)

    mov %rax, %cr3

    # jump to RIP + SHIM_OFFSET
    lea _trampoline(%rip),%rax
    mov $SHIM_OFFSET, %rbx
    adox %rbx, %rax
    jmp *%rax
_trampoline:

    mov $SHIM_OFFSET, %r15
    #  add SHIM_OFFSET to shim load offset
    adox %r15, %rsi
    # add SHIM_OFFSET to SYSCALL_PAGE
    adox %r15, %rdi

    # load stack in shim virtual address space
    lea _initial_shim_stack(%rip), %rsp
    # sub 8 because we push 8 bytes later and want 16 bytes align
    add $(SIZE_OF_INITIAL_STACK-8), %rsp

    # save arg1
    push %rdi

    lea _DYNAMIC(%rip),%rdi
    # %rdi - _DYNAMIC + SHIM_OFFSET
    # %rsi - shim load offset + SHIM_OFFSET
    # correct dynamic symbols with shim load offset + SHIM_OFFSET
    .hidden _dyn_reloc
    call _dyn_reloc

    # restore arg1
    pop %rdi

    # jump to _start_main
    xor %rbp,%rbp
    jmp _start_main

.L100:  # some paranoid code preventing speculative execution
    hlt
    jmp .L100

.section .bss
.align 4096
_initial_shim_stack:
.space SIZE_OF_INITIAL_STACK

#
# # Page Tables:
#
# * PDPT_IDENT: an identity mapped one for 0x0 - 0x40_0000
# * PDPT_OFFSET: an offset page table with offset $SHIM_OFFSET

# The root table of the 4-Level Paging
# Intel Vol 3A - 4.5
# will contain:
#       [0] PDPT_IDENT:  0x0                   - 0x80_0000_0000
# [1..=510] empty for now
#     [511] PDPT_OFFSET: 0xFFFF_FF80_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF
.section .bss
.align  4096
PML4T:
.space 4096

# Offset Page-Directory-Pointer Table
# with pointers to Huge Pages, mapping 38bit of addresses to
# SHIM_OFFSET + x, making the translation of shim virtual address space
# to physical address space easy, by substracting SHIM_OFFSET.
# This also enables mapping user space below SHIM_OFFSET and use the same
# CR3 for shim and user space.
.section .data
.align  4096
PDPT_OFFSET:
# helper macro to calculate PDPT_OFFSET entries
.macro  QUAD from,count,step
.set    offset,0
.rept   \count
.quad   (\from + offset)
.set    offset,offset+\step
.endr
.endm
# fill in PDPT_OFFSET entries with 0x83 flags (HUGE_PAGE | WRITABLE | PRESENT)
# and calculated offsets
QUAD    0x83,512,0x40000000

# Identity Page-Directory-Pointer Table
# will contain a pointer to a Identity Page-Directory Table
#      [0] PDT_IDENT:  0x0                   - 0x4000_0000
# [1..512] empty for now
.section .bss
.align  4096
PDPT_IDENT:
.space  4096

# Identity Page-Directory Table
# with 2 pointers to 2MB Huge Pages
#  [0..=1] 0x0 - 0x40_0000
# [1..512] empty for now
.section .data
.align  4096
PDT_IDENT:
.quad   0x000083  # 0x00_0000 - 0x20_0000 (HUGE_PAGE | WRITABLE | PRESENT)
.quad   0x200083  # 0x20_0000 - 0x40_0000 (HUGE_PAGE | WRITABLE | PRESENT)
.space  4080
