# SPDX-License-Identifier: Apache-2.0

.section .entry64, "ax"
.global _start
.global _setup_pto
.code64

.p2align 4
_start:
    movabs $_start_main,%rax


# %rax  = jmp to start function
# %rdi  = first parameter for start function
.p2align 4
_setup_pto:
    mov    %rdi, %r11
    mov    %rax, %r12

/*
        Cr4::update(|f| {
            f.insert(
                Cr4Flags::FSGSBASE
                    | Cr4Flags::PHYSICAL_ADDRESS_EXTENSION
                    | Cr4Flags::OSFXSR
                    | Cr4Flags::OSXMMEXCPT_ENABLE
                    | Cr4Flags::OSXSAVE,
            )
        });
        Cr0::update(|cr0| {
            cr0.insert(
                Cr0Flags::PROTECTED_MODE_ENABLE | Cr0Flags::NUMERIC_ERROR | Cr0Flags::PAGING,
            );
            cr0.remove(Cr0Flags::EMULATE_COPROCESSOR | Cr0Flags::MONITOR_COPROCESSOR)
        });

        Efer::update(|efer| {
            efer.insert(
                EferFlags::LONG_MODE_ACTIVE
                    | EferFlags::LONG_MODE_ENABLE
                    | EferFlags::NO_EXECUTE_ENABLE
                    | EferFlags::SYSTEM_CALL_EXTENSIONS,
            )
        });
*/
    mov    %cr4,%rax
    or     $0x50620,%rax
    mov    %rax,%cr4

    mov    %cr0,%rax
    and    $0x60050008,%eax
    mov    $0x80000021,%ecx
    or     %rax,%rcx
    mov    %rcx,%cr0

    mov    $0xc0000080,%ecx
    rdmsr
    or     $0xd01,%eax
    mov    $0xc0000080,%ecx
    wrmsr

    mov  $PML2IDENT, %eax
    orb  $0b00000111, %al # writable (bit 1), present (bit 0)
    mov  $PML3IDENT, %edx
    movl %eax, (%edx)

    mov  $PML3IDENT, %edx
    orb  $0b00000111, %dl # writable (bit 1), present (bit 0)
    mov  $PML4T, %eax
    mov  %edx, (%eax)
    mov  %rax, %cr3

    invlpg (%eax)

    # setup physical offset page table
    movabs $PML3TO, %rax
    orb  $0b00000011, %al # writable (bit 1), present (bit 0)
    movabs  $PML4T, %rdx
    addl $128, %edx
    movl %eax, (%edx)
    invlpg (%rax)

_before_jump:
    mov    %r11, %rdi
    mov    %r12, %rax

    # Setup some stack
    movq $(first_kernel_stack_end - 8), %rsp
    movq %rsp, %rbp

    # jump into kernel address space
    jmpq *%rax

.pto_halt_loop:
    hlt
    jmp .pto_halt_loop

stack_size = 0x10000

.section .bss.stack, "aw"
.align 4096
first_kernel_stack:
.space stack_size
first_kernel_stack_end:
