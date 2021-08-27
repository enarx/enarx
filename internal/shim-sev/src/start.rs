// SPDX-License-Identifier: Apache-2.0

//! This is the elf entry point called by the hypervisor
//!
//! see [`_start`](_start)

use crate::_start_main;
use crate::addr::SHIM_VIRT_OFFSET;
use crate::pagetables::{PDPT_IDENT, PDPT_OFFSET, PDT_IDENT, PDT_OFFSET, PML4T, PT_IDENT};
use core::mem::size_of;
use primordial::Page;
use rcrt1::dyn_reloc;

#[cfg(not(debug_assertions))]
const INITIAL_STACK_PAGES: usize = 12;
#[cfg(debug_assertions)]
const INITIAL_STACK_PAGES: usize = 50;

#[no_mangle]
#[link_section = ".entry64_data"]
static INITIAL_SHIM_STACK: [Page; INITIAL_STACK_PAGES] = [Page::zeroed(); INITIAL_STACK_PAGES];

/// The initial function called at startup
///
/// It sets up essential registers, page tables and jumps in shim virtual address space
/// to the `_start_main` rust function.
#[allow(clippy::integer_arithmetic)]
#[no_mangle]
#[naked]
#[link_section = ".reset"]
pub unsafe extern "sysv64" fn _start() -> ! {
    asm!("
.set reset_vector, 0xFFFFF000
.macro define_addr name,label
.set \\name, (reset_vector + (\\label - 99b))
.endm
99:
// A small jump table with well known addresses
// to be used because of a rust bug for long jumps
.code32
// 0xFFFF_F000
    jmp     30f      // jump to code32_start
.align 8
.code64
// 0xFFFF_F008
    jmp     40f      // jump to code64_start

.align 8
66:
define_addr gdt32_ptr 66b
.align 8
// gdt32_ptr == 0xFFFF_F010
    .short gdt32_end - gdt32_start - 1 // GDT length is actually (length - 1)
    .long gdt32_start // address of gdt32_start
define_addr gdt32_start 67f
67: // gdt32_start
    .quad 0          // First descriptor is always unused
//code32_desc // base = 0x00000000, limit = 0xfffff x 4K
    .short 0xffff    // limit[0..16] = 0xffff
    .short 0x0000    // base [0..16] = 0x0000
    .byte 0x00       // base[16..24] = 0x00
    .byte 0x9B       // present, DPL = 0, system, code seg, grows up, readable, accessed
    .byte 0xCF       // 4K gran, 32-bit, limit[16..20] = 0x1111 = 0xf
    .byte 0x00       // base[24..32] = 0x00
//data32_desc // base = 0x00000000, limit = 0xfffff x 4K
    .short 0xffff    // limit 15:0
    .short 0x0000    // base 15:0
    .byte 0x00       // base[16..24] = 0x00
    .byte 0x93       // present, DPL = 0, system, data seg, ring0 only, writable, accessed
    .byte 0xCF       // 4K gran, 32-bit, limit[16..20] = 0x1111 = 0xf
    .byte 0x00       // base[24..32] = 0x00
//code64_desc
    // For 64-bit code descriptors, all bits except the following are ignored:
    // - CS.A=1 (bit 40) segment is accessed, prevents a write on first use.
    // - CS.R=1 (bit 41) segment is readable. (this might not be necessary)
    // - CS.C=1 (bit 42) segment is conforming. (this might not be necessary)
    // - CS.E=1 (bit 43) required, we are a executable code segment.
    // - CS.S=1 (bit 44) required, we are not a system segment.
    // - CS.DPL=0 (bits 45/46) we are using this segment in Ring 0.
    // - CS.P=1 (bit 47) required, the segment is present.
    // - CS.L=1 (bit 53) required, we are a 64-bit (long mode) segment.
    // - CS.D=0 (bit 54) required, CS.L=1 && CS.D=1 is resevered for future use.
    .quad (1<<40) | (1<<41) | (1<<42) | (1<<43) | (1<<44) | (1<<47) | (1<<53)
68:
define_addr gdt32_end 68b

20:
define_addr code16_start 20b
.code16
    cli

    lgdtd   cs:gdt32_ptr

    // setup CR0
    mov     eax,    cr0
    // set  PROTECTED_MODE_ENABLE
    or      al,     0x1
    mov     cr0,    eax

    // Due to a rust/LLVM bug, we have to use an absolute address here
    // expressions like (reset_vector + (label_2 - label_3)) don't seem to work
    // jmpl    0x8,    code32_start
    jmpl    0x8,    reset_vector

define_addr code32_start 30f
30:  // code32_start:
.code32
    mov     ax,     0x10 // 0x10 points at the new data selector
    mov     ds,     ax
    mov     ss,     ax

    // Check if we have a valid (0x8000_001F) CPUID leaf
    mov     eax,    0x80000000
    cpuid

    // This check should fail on Intel or Non SEV AMD CPUs. In future if
    // Intel CPUs supports this CPUID leaf then we are guaranteed to have exact
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
    and     ebx,    0x3f
    mov     eax,    ebx

    // The encryption bit position is always above 31
    sub     ebx,    32
    xor     edx,    edx
    bts     edx,    ebx
    jmp     3f

2:
    xor     edx,    edx

3:
    // Correct initial PML3
    mov     eax, 0xFFFFF000 - 0x2000
    or      [eax + 4 + 3*8], edx
    or      [eax + 4 + 4*8], edx
    or      [eax + 4 + 5*8], edx

    // Correct initial PML4
    mov     eax, 0xFFFFF000 - 0x1000
    // Set C-Bit in PML4 - pre 64bit
    or      [eax + 4], edx

    // activate initial simple identity page table
    mov     cr3,    eax

    // backup C-bit
    mov     ebx,    edx

    // setup CR4
    mov     eax,    cr4
    // set FSGSBASE | PAE | OSFXSR | OSXMMEXCPT | OSXSAVE
    or      eax,    0x50620
    mov     cr4,    eax

    // setup EFER
    // EFER |= LONG_MODE_ACTIVE | LONG_MODE_ENABLE | NO_EXECUTE_ENABLE | SYSTEM_CALL_EXTENSIONS
    // FIXME: what about already set bits?
    mov     ecx,    0xc0000080
    rdmsr
    or      eax,    0xd01
    mov     ecx,    0xc0000080
    wrmsr

    // setup CR0
    mov     eax,    cr0
    // mask EMULATE_COPROCESSOR | MONITOR_COPROCESSOR
    and     eax,    0x60050009
    // set  PROTECTED_MODE_ENABLE | NUMERIC_ERROR | PAGING
    or      eax,    0x80000021
    mov     cr0,    eax

    // Due to a rust/LLVM bug, we have to use an absolute address here
    // jmpl    0x18,    code64_start
    jmpl    0x18,   (reset_vector + 0x8)

define_addr code64_start 40f
40: // code64_start:
.code64
    // backup edx to r11 and r12
    // r11: C-bit >> 32
    // r12: C-bit full 64bit mask
    mov     r12,    rbx
    mov     r11,    rbx
    shl     r12,    0x20

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
    // 3: 0xc000_0000 - 0x1_0000_0000
    mov     QWORD PTR [rbx + 3*8],    rcx

    // set C-bit in all entries of the PT_IDENT table
    lea     rbx,    [rip + {PT_IDENT}]
    mov     rdx,    r11
    mov     ecx,    512         // Counter to 512 page table entries
    add     rbx,    4           // Pre-advance pointer by 4 bytes for the higher 32bit
6:
    or      DWORD PTR [rbx],edx // set C-bit
    add     rbx,    8           // advance pointer by 8
    loop    6b

    lea     rcx,    [rip + {PDT_IDENT}]
    lea     rbx,    [rip + {PT_IDENT}]
    or      rbx,    r12         // set C-bit
    or      rbx,    0x3         // ( WRITABLE | PRESENT)
    // store PT_IDENT table in PDT_IDENT in the correct slot
    mov     QWORD PTR [rcx + 511*8],    rbx

    // setup PDPT_IDENT table entry 3 with PDT_IDENT table
    lea     rbx,    [rip + {PDPT_IDENT}]
    or      rcx,    r12         // set C-bit
    or      rcx,    0x3         // ( WRITABLE | PRESENT)
    // store PDT_IDENT table in PDPT_IDENT in the correct slot
    mov     QWORD PTR [rbx + 8*3],    rcx

    // setup PDPT_IDENT in PML4T table
    or      rbx,    r12         // set C-bit
    or      rbx,    0x3         // ( WRITABLE | PRESENT)
    lea     rax,    [rip + {PML4T}]
    mov     QWORD PTR [rax],    rbx

    or      rax,    r12         // set C-bit for new CR3
    mov     cr3,    rax

    // advance rip to kernel address space with {SHIM_VIRT_OFFSET}
    xor     eax,    eax         // clear OF for adox
    lea     rax,    [rip + 50f] // trampoline
    mov     rsi,    {SHIM_VIRT_OFFSET}
    adox    rax,    rsi
    jmp     rax                 // trampoline

50: // trampoline:

    // load stack in shim virtual address space
    lea     rsp,    [rip + {INITIAL_SHIM_STACK}]
    // sub 8 because we push 8 bytes later and want 16 bytes align
    add     rsp,    {SIZE_OF_INITIAL_STACK}

    .hidden _DYNAMIC
    lea     rdi,    [rip + _DYNAMIC]
    // %rdi - _DYNAMIC + {SHIM_VIRT_OFFSET}
    // %rsi - {SHIM_VIRT_OFFSET}
    // correct dynamic symbols with shim load offset + {SHIM_VIRT_OFFSET}
    .hidden {DYN_RELOC}
    call    {DYN_RELOC}

    // set arg1 to SEV C-Bit mask
    mov     rdi,    r12
    xor     rbp,    rbp

    // arg1 %rdi  = SEV C-bit mask
    call    {START_MAIN}
97: // end of code
.fill((0xFF0 - (97b - 99b)))

// reset vector @ 0xFFFF_FFF0
.code16
    jmp 20b
    hlt

98: // end of reset vector jump table

// fill until the end of page minus 2 for the `ud2` rust/llvm add
.fill(({PAGE_SIZE} - (98b - 99b) - 2))

// END OF PAGE
    ",
    SHIM_VIRT_OFFSET = const SHIM_VIRT_OFFSET,
    SIZE_OF_INITIAL_STACK = const INITIAL_STACK_PAGES * size_of::<Page>(),
    PAGE_SIZE = const size_of::<Page>(),
    DYN_RELOC = sym dyn_reloc,
    START_MAIN = sym _start_main,
    PML4T = sym PML4T,
    PDPT_OFFSET = sym PDPT_OFFSET,
    PDT_OFFSET = sym PDT_OFFSET,
    PT_IDENT = sym PT_IDENT,
    PDT_IDENT = sym PDT_IDENT,
    PDPT_IDENT = sym PDPT_IDENT,
    INITIAL_SHIM_STACK = sym INITIAL_SHIM_STACK,
    options(noreturn)
    )
}
