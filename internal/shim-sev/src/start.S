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
    lea     rax,    [rip + PML4T]
    lea     rbx,    [rip + PDPT_OFFSET]
    // set C-bit
    or      rbx,    r12
    // (WRITABLE | PRESENT)
    or      rbx,    0x3
    mov     QWORD PTR [rax + (((SHIM_OFFSET & 0xFFFFFFFFFFFF) >> 39)*8)],   rbx

    // set C-bit in PDPT_OFFSET table
    lea     rbx,    [rip + PDPT_OFFSET]
    mov     rdx,    r11
    // Counter to 512 page table entries
    mov     ecx,    512
    // Pre-advance pointer by 4 bytes for the higher 32bit
    add     rbx,    4

setCBit:
    mov     DWORD PTR [rbx],    edx
    // advance pointer by 8
    add     rbx,    8
    loop    setCBit

    // set C-bit in PDT_IDENT table
    lea     rcx,    [rip + PDT_IDENT]
    mov     rdx,    r11
    mov     DWORD PTR [rcx + (1*8 + 4)],    edx
    mov     DWORD PTR [rcx + (2*8 + 4)],    edx

    // setup PDPT_IDENT table
    lea     rbx,    [rip + PDPT_IDENT]
    // set C-bit
    or      rcx,    r12
    // ( WRITABLE | PRESENT)
    or      rcx,    0x3
    // store PDT_IDENT table in PDPT_IDENT in the correct slot
    // 0x0 - 0x4000_0000
    mov     QWORD PTR [rbx],    rcx

    // set C-bit
    or      rbx,    r12
    // ( WRITABLE | PRESENT)
    or      rbx,    0x3

    lea     rax,    [rip + PML4T]
    mov     QWORD PTR [rax],    rbx

    or      rax,    r12
    mov     cr3,    rax

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
    add     rsp,    (SIZE_OF_INITIAL_STACK-8)

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
    mov     rsi,r12
    xor     rbp,rbp

    // jump to _start_main
    // arg1 %rdi  = address of SYSCALL_PAGE (boot_info)
    // arg2 %rsi  = SEV C-bit mask
    jmp     _start_main

.section .bss
.align 4096
_initial_shim_stack:
.space SIZE_OF_INITIAL_STACK

//
// // Page Tables:
//
// * PDPT_IDENT: an identity mapped one for 0x0 - 0x40_0000
// * PDPT_OFFSET: an offset page table with offset $SHIM_OFFSET

// The root table of the 4-Level Paging
// Intel Vol 3A - 4.5
// will contain:
//       [0] PDPT_IDENT:  0x0                   - 0x80_0000_0000
// [1..=510] empty for now
//     [511] PDPT_OFFSET: 0xFFFF_FF80_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF
.section .bss
.align  4096
PML4T:
.space 4096

// Offset Page-Directory-Pointer Table
// with pointers to Huge Pages, mapping 38bit of addresses to
// SHIM_OFFSET + x, making the translation of shim virtual address space
// to physical address space easy, by substracting SHIM_OFFSET.
// This also enables mapping user space below SHIM_OFFSET and use the same
// CR3 for shim and user space.
.section .data
.align  4096
.att_syntax
PDPT_OFFSET:
// helper macro to calculate PDPT_OFFSET entries
.macro  QUAD from,count,step
.set    offset,0
.rept   \count
.quad   (\from + offset)
.set    offset,offset+\step
.endr
.endm
// fill in PDPT_OFFSET entries with 0x83 flags (HUGE_PAGE | WRITABLE | PRESENT)
// and calculated offsets
QUAD    0x83,512,0x40000000

// Identity Page-Directory-Pointer Table
// will contain a pointer to a Identity Page-Directory Table
//      [0] PDT_IDENT:  0x0                   - 0x4000_0000
// [1..512] empty for now
.section .bss
.align  4096
PDPT_IDENT:
.space  4096

// Identity Page-Directory Table
// with 2 pointers to 2MB Huge Pages
//  [0..=1] 0x0 - 0x40_0000
// [1..512] empty for now
.section .data
.align  4096
PDT_IDENT:
.quad   0x000083  // 0x00_0000 - 0x20_0000 (HUGE_PAGE | WRITABLE | PRESENT)
.quad   0x200083  // 0x20_0000 - 0x40_0000 (HUGE_PAGE | WRITABLE | PRESENT)
.quad   0x400083  // 0x40_0000 - 0x60_0000 (HUGE_PAGE | WRITABLE | PRESENT)
.space  4072
