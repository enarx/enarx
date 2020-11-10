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

#ifdef NDEBUG
#define SIZE_OF_INITIAL_STACK (48 * 1024)
#else
#define SIZE_OF_INITIAL_STACK (150 * 1024)
#endif

.section .text
.global _start
.hidden _DYNAMIC
.code64
.p2align 4
.intel_syntax noprefix

// Arguments expected from the hypervisor:
// arg1 %rdi  = address of SYSCALL_PAGE (boot_info)
// arg2 %rsi  = shim load offset
_start:
    // Check if we have a valid (0x8000_001F) CPUID leaf
    mov     eax,    0x80000000
    cpuid

    // This check should fail on Intel or Non SEV AMD CPUs. In future if
    // Intel CPUs supports this CPUID leaf then we are guranteed to have exact
    // same bit definition.
    cmp     eax,    0x8000001f
    jl      NoSev

    // Check for memory encryption feature:
    //  CPUID  Fn8000_001F[EAX] - Bit 1
    mov     eax,    0x8000001f
    cpuid
    bt      eax,    1
    jnc     NoSev

    // Check if memory encryption is enabled
    //  MSR_0xC0010131 - Bit 0 (SEV enabled)
    mov     ecx,    0xc0010131
    rdmsr
    bt      eax,    0
    jnc     NoSev

    // Get pte bit position to enable memory encryption
    // CPUID Fn8000_001F[EBX] - Bits 5:0
    mov     eax,    ebx
    and     eax,    0x3f

    // If SEV is enabled, C-bit is always above 31
    bts     rdx,    rax
    jmp     SevExit

NoSev:
    xor     rdx,    rdx

SevExit:
    // backup edx to r11 and r12
    // r11: C-bit >> 32
    // r12: C-bit full 64bit mask
    mov     r12,    rdx
    mov     r11,    rdx
    shr     r11,    0x20

    // setup CR4
    mov     rax,    cr4
    // set FSGSBASE | PAE | OSFXSR | OSXMMEXCPT | OSXSAVE
    or      rax,    0x50620
    mov     cr4,    rax

    // setup CR0
    mov     rax,    cr0
    // mask EMULATE_COPROCESSOR | MONITOR_COPROCESSOR
    and     eax,    0x60050009
    // set  PROTECTED_MODE_ENABLE | NUMERIC_ERROR | PAGING
    or      eax,    0x80000021
    mov     cr0,    rax


    // setup EFER
    // EFER |= LONG_MODE_ACTIVE | LONG_MODE_ENABLE | NO_EXECUTE_ENABLE | SYSTEM_CALL_EXTENSIONS
    // FIXME: what about already set bits?
    mov     ecx,    0xc0000080
    rdmsr
    or      eax,    0xd01
    mov     ecx,    0xc0000080
    wrmsr

    // Setup the pagetables
    // done dynamically, otherwise we would have to correct the dynamic symbols twice

    // setup PDPT_OFFSET in PML4T table
    lea     rax,    [rip + PML4T]
    lea     rbx,    [rip + PDPT_OFFSET]
    or      rbx,    r12         // set C-bit
    or      rbx,    0x3         // (WRITABLE | PRESENT)
    mov     QWORD PTR [rax + (((SHIM_OFFSET & 0xFFFFFFFFFFFF) >> 39)*8)],   rbx

    // set C-bit in all entries of the PDT_OFFSET table
    lea     rbx,    [rip + PDT_OFFSET]
    mov     rdx,    r11
    mov     ecx,    512         // Counter to 512 page table entries
    add     rbx,    4           // Pre-advance pointer by 4 bytes for the higher 32bit
setCBit_PDT_OFFSET:
    mov     DWORD PTR [rbx],    edx
    add     rbx,    8           // advance pointer by 8
    loop    setCBit_PDT_OFFSET

    // set C-bit in all entries of the PDPT_OFFSET table
    lea     rbx,    [rip + PDPT_OFFSET]
    mov     rdx,    r11
    mov     ecx,    512         // Counter to 512 page table entries
    add     rbx,    4           // Pre-advance pointer by 4 bytes for the higher 32bit
setCBit_PDPT_OFFSET:
    mov     DWORD PTR [rbx],    edx
    add     rbx,    8           // advance pointer by 8
    loop    setCBit_PDPT_OFFSET

    // setup PDPT_OFFSET table entry 0 with PDT_OFFSET table
    lea     rbx,    [rip + PDPT_OFFSET]
    lea     rcx,    [rip + PDT_OFFSET]
    or      rcx,    r12         // set C-bit
    or      rcx,    0x3         // ( WRITABLE | PRESENT)
    // store PDT_OFFSET table in PDPT_OFFSET in the correct slot
    // 0x0 - 0x4000_0000
    mov     QWORD PTR [rbx],    rcx

    // set C-bit for the first 3 entries in the PDT_IDENT table
    lea     rcx,    [rip + PDT_IDENT]
    mov     rdx,    r11
    mov     DWORD PTR [rcx + (0*8 + 4)],    edx
    mov     DWORD PTR [rcx + (1*8 + 4)],    edx
    mov     DWORD PTR [rcx + (2*8 + 4)],    edx

    // setup PDPT_IDENT table entry 0 with PDT_IDENT table
    lea     rbx,    [rip + PDPT_IDENT]
    or      rcx,    r12         // set C-bit
    or      rcx,    0x3         // ( WRITABLE | PRESENT)
    // store PDT_IDENT table in PDPT_IDENT in the correct slot
    // 0x0 - 0x4000_0000
    mov     QWORD PTR [rbx],    rcx

    // setup PDPT_IDENT in PML4T table
    or      rbx,    r12         // set C-bit
    or      rbx,    0x3         // ( WRITABLE | PRESENT)
    lea     rax,    [rip + PML4T]
    mov     QWORD PTR [rax],    rbx

    or      rax,    r12         // set C-bit for new CR3
    mov     cr3,    rax

    // advance rip to kernel address space with SHIM_OFFSET
    lea     rax,    [rip + _trampoline]
    mov     rbx,    SHIM_OFFSET
    adox    rax,    rbx
    jmp     rax

_trampoline:
    mov     r15,    SHIM_OFFSET
    //  add SHIM_OFFSET to shim load offset
    adox    rsi,    r15
    //  add SHIM_OFFSET to address of SYSCALL_PAGE (boot_info)
    adox    rdi,    r15

    // load stack in shim virtual address space
    lea     rsp,    [rip + _initial_shim_stack]
    // sub 8 because we push 8 bytes later and want 16 bytes align
    add     rsp,    SIZE_OF_INITIAL_STACK

    // save arg1
    push    rdi

    lea     rdi,    [rip + _DYNAMIC]
    // %rdi - _DYNAMIC + SHIM_OFFSET
    // %rsi - shim load offset + SHIM_OFFSET
    // correct dynamic symbols with shim load offset + SHIM_OFFSET
    .hidden _dyn_reloc
    call    _dyn_reloc

    // restore arg1
    pop     rdi

    // set arg2 to SEV C-Bit mask
    mov     rsi,    r12
    xor     rbp,    rbp

    // call _start_main
    // arg1 %rdi  = address of SYSCALL_PAGE (boot_info)
    // arg2 %rsi  = SEV C-bit mask
    call    _start_main

.section .bss
.align 4096
_initial_shim_stack:
.space SIZE_OF_INITIAL_STACK
