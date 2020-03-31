# SPDX-License-Identifier: Apache-2.0

.section .ram32, "ax"
.global ram32_start
.code32
/*
* Entry point for PVH guests.
*
* Xen ABI specifies the following register state when we come here:
*
* - `ebx`: contains the physical memory address where the loader has placed
*          the boot start info structure.
* - `cr0`: bit 0 (PE) must be set. All the other writeable bits are cleared.
* - `cr4`: all bits are cleared.
* - `cs `: must be a 32-bit read/execute code segment with a base of ‘0’
*          and a limit of ‘0xFFFFFFFF’. The selector value is unspecified.
* - `ds`, `es`: must be a 32-bit read/write data segment with a base of
*               ‘0’ and a limit of ‘0xFFFFFFFF’. The selector values are all
*               unspecified.
* - `tr`: must be a 32-bit TSS (active) with a base of '0' and a limit
*         of '0x67'.
* - `eflags`: bit 17 (VM) must be cleared. Bit 9 (IF) must be cleared.
*             Bit 8 (TF) must be cleared. Other bits are all unspecified.
*
* All other processor registers and flag bits are unspecified. The OS is in
* charge of setting up it's own stack, GDT and IDT.
*/

ram32_start:
    # Indicate (via serial) that we are executing out of RAM
    #movw $0x2f8, %dx
    #movb $'R', %al
    #outb %al, %dx

#setup_page_tables:
    # First PML2 entry identity maps [0, 2 MiB)
    movl $0b10000011, (PML2IDENT) # huge (bit 7), writable (bit 1), present (bit 0)
    # First PML3 entry points to PML2 table
    movl $PML2IDENT, %eax
    orb  $0b00000011, %al # writable (bit 1), present (bit 0)
    movl %eax, (PML3IDENT)
    # First PML4 entry points to PML3 table
    movl $PML3IDENT, %eax
    orb  $0b00000011, %al # writable (bit 1), present (bit 0)
    movl %eax, (PML4T)

#enable_paging:
    # Load page table root into CR3
    movl $PML4T, %eax
    movl %eax, %cr3

    # Set CR4.PAE (Physical Address Extension)
    movl %cr4, %eax
    orb  $0b00100000, %al # Set bit 5
    movl %eax, %cr4
    # Set EFER.LME (Long Mode Enable)
    movl $0xC0000080, %ecx
    rdmsr
    orb  $0b00000001, %ah # Set bit 8
    wrmsr
    # Set CRO.PG (Paging)
    movl %cr0, %eax
    orl  $(1 << 31), %eax
    movl %eax, %cr0

    # Indicate (via serial) that we have enabled paging
    #movw $0x2f8, %dx
    #movb $'P', %al
    #outb %al, %dx

#jump_to_64bit:
    # We are now in 32-bit compatibility mode. To enter 64-bit mode, we need to
    # load a 64-bit code segment into our GDT.
    lgdtl .gdt64_ptr
    # Set CS to a 64-bit segment and jump to 64-bit code.

    #ljmpl $(.code64_desc - .gdt64_start), $ram64_start

    push  $0x8
    lea    ram64_start,%eax
    push   %eax
    lret

.gdt64_ptr:
    .short .gdt64_end - .gdt64_start - 1 # GDT length is actually (length - 1)
    .long .gdt64_start
.gdt64_start:
    # First descriptor is null
    .quad 0
.code64_desc:
    # For 64-bit code descriptors, all bits except the following are ignored:
    # - CS.A=1 (bit 40) segment is accessed, prevents a write on first use.
    # - CS.R=1 (bit 41) segment is readable. (this might not be necessary)
    # - CS.C=1 (bit 42) segment is conforming. (this might not be necessary)
    # - CS.E=1 (bit 43) required, we are a executable code segment.
    # - CS.S=1 (bit 44) required, we are not a system segment.
    # - CS.DPL=0 (bits 45/46) we are using this segment in Ring 0.
    # - CS.P=1 (bit 47) required, the segment is present.
    # - CS.L=1 (bit 53) required, we are a 64-bit (long mode) segment.
    # - CS.D=0 (bit 54) required, CS.L=1 && CS.D=1 is resevered for future use.
    .quad (1<<40) | (1<<41) | (1<<42) | (1<<43) | (1<<44) | (1<<47) | (1<<53)
.gdt64_end:
