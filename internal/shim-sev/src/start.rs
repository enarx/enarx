// SPDX-License-Identifier: Apache-2.0

//! This is the elf entry point called by the hypervisor
//!
//! see [`_start`](_start)

use crate::addr::SHIM_VIRT_OFFSET;
use crate::pagetables::{PDPT_IDENT, PDPT_OFFSET, PDT_IDENT, PDT_OFFSET, PML4T};
use primordial::Page;
use rcrt1::_dyn_reloc;

#[cfg(not(debug_assertions))]
const INITIAL_STACK_PAGES: usize = 12;
#[cfg(debug_assertions)]
const INITIAL_STACK_PAGES: usize = 50;

#[no_mangle]
static INITIAL_SHIM_STACK: [Page; INITIAL_STACK_PAGES] = [Page::zeroed(); INITIAL_STACK_PAGES];

/// The initial function called at startup
///
/// It sets up essential registers, page tables and jumps in shim virtual address space
/// to the `_start_main` rust function.
///
/// Arguments expected from the hypervisor:
/// * %rdi  = address of SYSCALL_PAGE (boot_info)
/// * %rsi  = shim load offset
#[allow(clippy::integer_arithmetic)]
#[no_mangle]
#[naked]
pub unsafe extern "sysv64" fn _start() -> ! {
    asm!(
        "
    // Check if we have a valid (0x8000_001F) CPUID leaf
    mov     eax,    0x80000000
    cpuid

    // This check should fail on Intel or Non SEV AMD CPUs. In future if
    // Intel CPUs supports this CPUID leaf then we are guranteed to have exact
    // same bit definition.
    cmp     eax,    0x8000001f
    jl      2f

    // Check for memory encryption feature:
    //  CPUID  Fn8000_001F[EAX] - Bit 1
    mov     eax,    0x8000001f
    cpuid
    bt      eax,    1
    jnc     2f

    // Check if memory encryption is enabled
    //  MSR_0xC0010131 - Bit 0 (SEV enabled)
    mov     ecx,    0xc0010131
    rdmsr
    bt      eax,    0
    jnc     2f

    // Get pte bit position to enable memory encryption
    // CPUID Fn8000_001F[EBX] - Bits 5:0
    mov     eax,    ebx
    and     eax,    0x3f

    // If SEV is enabled, C-bit is always above 31
    bts     rdx,    rax
    jmp     3f

2:
    xor     rdx,    rdx

3:
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
    lea     rax,    [rip + {PML4T}]
    lea     rbx,    [rip + {PDPT_OFFSET}]
    or      rbx,    r12         // set C-bit
    or      rbx,    0x3         // (WRITABLE | PRESENT)
    mov     QWORD PTR [rax + ((({SHIM_VIRT_OFFSET} & 0xFFFFFFFFFFFF) >> 39)*8)],   rbx

    // set C-bit in all entries of the PDT_OFFSET table
    lea     rbx,    [rip + {PDT_OFFSET}]
    mov     rdx,    r11
    mov     ecx,    512         // Counter to 512 page table entries
    add     rbx,    4           // Pre-advance pointer by 4 bytes for the higher 32bit
4:
    or      DWORD PTR [rbx],edx // set C-bit
    add     rbx,    8           // advance pointer by 8
    loop    4b

    // set C-bit in all entries of the PDPT_OFFSET table
    lea     rbx,    [rip + {PDPT_OFFSET}]
    mov     rdx,    r11
    mov     ecx,    512         // Counter to 512 page table entries
    add     rbx,    4           // Pre-advance pointer by 4 bytes for the higher 32bit
5:
    or      DWORD PTR [rbx],edx // set C-bit
    add     rbx,    8           // advance pointer by 8
    loop    5b

    // setup PDPT_OFFSET table entry 0 with PDT_OFFSET table
    lea     rbx,    [rip + {PDPT_OFFSET}]
    lea     rcx,    [rip + {PDT_OFFSET}]
    or      rcx,    r12         // set C-bit
    or      rcx,    0x3         // ( WRITABLE | PRESENT)
    // store PDT_OFFSET table in PDPT_OFFSET in the correct slot
    // 0x0 - 0x4000_0000
    mov     QWORD PTR [rbx],    rcx

    // set C-bit for the first 3 entries in the PDT_IDENT table
    lea     rcx,    [rip + {PDT_IDENT}]
    mov     rdx,    r11
    or      DWORD PTR [rcx + (0*8 + 4)],    edx
    or      DWORD PTR [rcx + (1*8 + 4)],    edx
    or      DWORD PTR [rcx + (2*8 + 4)],    edx

    // setup PDPT_IDENT table entry 0 with PDT_IDENT table
    lea     rbx,    [rip + {PDPT_IDENT}]
    or      rcx,    r12         // set C-bit
    or      rcx,    0x3         // ( WRITABLE | PRESENT)
    // store PDT_IDENT table in PDPT_IDENT in the correct slot
    // 0x0 - 0x4000_0000
    mov     QWORD PTR [rbx],    rcx

    // setup PDPT_IDENT in PML4T table
    or      rbx,    r12         // set C-bit
    or      rbx,    0x3         // ( WRITABLE | PRESENT)
    lea     rax,    [rip + {PML4T}]
    mov     QWORD PTR [rax],    rbx

    or      rax,    r12         // set C-bit for new CR3
    mov     cr3,    rax

    // advance rip to kernel address space with {SHIM_VIRT_OFFSET}
    lea     rax,    [rip + 6f]
    mov     rbx,    {SHIM_VIRT_OFFSET}
    adox    rax,    rbx
    jmp     rax

6:
    mov     r15,    {SHIM_VIRT_OFFSET}
    //  add {SHIM_VIRT_OFFSET} to shim load offset
    adox    rsi,    r15
    //  add {SHIM_VIRT_OFFSET} to address of SYSCALL_PAGE (boot_info)
    adox    rdi,    r15

    // load stack in shim virtual address space
    lea     rsp,    [rip + {INITIAL_SHIM_STACK}]
    // sub 8 because we push 8 bytes later and want 16 bytes align
    add     rsp,    {SIZE_OF_INITIAL_STACK}

    // save arg1
    push    rdi

    .hidden _DYNAMIC
    lea     rdi,    [rip + _DYNAMIC]
    // %rdi - _DYNAMIC + {SHIM_VIRT_OFFSET}
    // %rsi - shim load offset + {SHIM_VIRT_OFFSET}
    // correct dynamic symbols with shim load offset + {SHIM_VIRT_OFFSET}
    .hidden {DYN_RELOC}
    call    {DYN_RELOC}

    // restore arg1
    pop     rdi

    // set arg2 to SEV C-Bit mask
    mov     rsi,    r12
    xor     rbp,    rbp

    // call _start_main
    // arg1 %rdi  = address of SYSCALL_PAGE (boot_info)
    // arg2 %rsi  = SEV C-bit mask
    call    _start_main
    ",
    SHIM_VIRT_OFFSET = const SHIM_VIRT_OFFSET,
    SIZE_OF_INITIAL_STACK = const INITIAL_STACK_PAGES * 4096,
    DYN_RELOC = sym _dyn_reloc,
    PML4T = sym PML4T,
    PDPT_OFFSET = sym PDPT_OFFSET,
    PDT_OFFSET = sym PDT_OFFSET,
    PDT_IDENT = sym PDT_IDENT,
    PDPT_IDENT = sym PDPT_IDENT,
    INITIAL_SHIM_STACK = sym INITIAL_SHIM_STACK,
    options(noreturn)
    )
}
