// SPDX-License-Identifier: Apache-2.0

//! The SEV shim
//!
//! Contains the startup code and the main function.

#![no_std]
#![deny(clippy::all)]
#![deny(clippy::integer_arithmetic)]
#![deny(missing_docs)]
#![no_main]
#![feature(asm, naked_functions)]

extern crate compiler_builtins;
extern crate rcrt1;

use shim_sev::addr::SHIM_VIRT_OFFSET;
use shim_sev::debug::print_stack_trace;
use shim_sev::gdt;
use shim_sev::interrupts;
use shim_sev::pagetables::{unmap_identity, PDPT, PDT_C000_0000, PML4T, PT_FFE0_0000};
use shim_sev::payload;
use shim_sev::print::{self, enable_printing, is_printing_enabled};
use shim_sev::snp::C_BIT_MASK;
use shim_sev::sse;

use core::mem::size_of;
use core::sync::atomic::{AtomicBool, Ordering};

use noted::noted;
use primordial::Page;
use rcrt1::dyn_reloc;
use sallyport::{elf::note, REQUIRES};
use x86_64::registers::control::{Cr0Flags, Cr4Flags, EferFlags};

noted! {
    static NOTE_ENARX_SALLYPORT<note::NAME, note::REQUIRES, [u8; REQUIRES.len()]> = REQUIRES;
}

#[cfg(not(target_feature = "crt-static"))]
#[allow(missing_docs)]
fn __check_for_static_linking() {
    compile_error!("shim is not statically linked");
}

#[cfg(not(debug_assertions))]
const INITIAL_STACK_PAGES: usize = 12;
#[cfg(debug_assertions)]
const INITIAL_STACK_PAGES: usize = 50;

#[no_mangle]
#[link_section = ".entry64_data"]
static INITIAL_SHIM_STACK: [Page; INITIAL_STACK_PAGES] = [Page::zeroed(); INITIAL_STACK_PAGES];

/// Switch the stack and jump to a function
///
/// # Safety
///
/// This function is unsafe, because the caller has to ensure a 16 byte
/// aligned usable stack.
#[allow(clippy::integer_arithmetic)]
unsafe fn switch_shim_stack(ip: extern "sysv64" fn() -> !, sp: u64) -> ! {
    debug_assert_eq!(sp % 16, 0);

    // load a new stack pointer and jmp to function
    asm!(
        "mov rsp, {SP}",
        "sub rsp, 8",
        "push rbp",
        "call {IP}",

        SP = in(reg) sp,
        IP = in(reg) ip,

        options(noreturn, nomem)
    )
}

/// Defines the entry point function.
///
/// # Safety
/// Do not call from Rust.
unsafe extern "sysv64" fn _start_main(c_bit_mask: u64) -> ! {
    C_BIT_MASK.store(c_bit_mask, Ordering::Relaxed);

    unmap_identity();

    // Everything setup, so print works
    enable_printing();

    // Switch the stack to a guarded stack
    switch_shim_stack(shim_main, gdt::INITIAL_STACK.pointer.as_u64())
}

/// The main function for the shim with stack setup
extern "sysv64" fn shim_main() -> ! {
    unsafe { gdt::init() };
    sse::init_sse();
    interrupts::init();

    payload::execute_payload()
}

/// The panic function
///
/// Called, whenever somethings panics.
///
/// Reverts to a triple fault, which causes a `#VMEXIT` and a KVM shutdown,
/// if it can't print the panic and exit normally with an error code.
#[panic_handler]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    use shim_sev::debug::_enarx_asm_triple_fault;

    static mut ALREADY_IN_PANIC: AtomicBool = AtomicBool::new(false);

    // Don't print anything, if the FRAME_ALLOCATOR is not yet initialized
    unsafe {
        if is_printing_enabled()
            && ALREADY_IN_PANIC
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            print::_eprint(format_args!("{}\n", info));
            print_stack_trace();
            // FIXME: might want to have a custom panic hostcall
            shim_sev::hostcall::shim_exit(255);
        }
    }

    // provoke triple fault, causing a VM shutdown
    unsafe { _enarx_asm_triple_fault() }
}

/// The initial function called at startup
///
/// It sets up essential registers, page tables and jumps in shim virtual address space
/// to the `_start_main` rust function.
///
/// # Safety
///
/// This function MUST not be called.
#[allow(clippy::integer_arithmetic)]
#[no_mangle]
#[naked]
#[link_section = ".reset"]
pub unsafe extern "sysv64" fn _start() -> ! {
    asm!("
.set reset_vector_page, 0xFFFFF000

.macro define_addr name,label
.set \\name, (reset_vector_page + (\\label - 99b))
.endm

99: // 0xFFFF_F000

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
    or      al,     {PROTECTED_MODE_ENABLE}
    mov     cr0,    eax

    // Due to a rust/LLVM bug, we have to use an absolute address here
    // expressions like (reset_vector + (label_2 - label_3)) don't seem to work
    // jmpl    0x8,    code32_start
    jmpl    0x8,    reset_vector_page

define_addr code32_start 30f
30:  // code32_start:
.code32
    mov     ax,     0x10 // 0x10 points at the new data selector
    mov     ds,     ax
    mov     ss,     ax

    mov     eax,    DWORD PTR {CPUID_PAGE}
    mov     ecx,    DWORD PTR [eax]

    test    ecx,    ecx
    je      2f

    add    ecx,     0x1
13:
    add    ecx,     0xffffffff

    // CPUID not found
    je     88f

    mov    edi,     eax
    add    eax,     0x30
    // Get pte bit position to enable memory encryption
    // CPUID Fn8000_001F[EBX] - Bits 5:0
    cmp    DWORD PTR [edi+0x10],0x8000001f
    jne    13b
    cmp    DWORD PTR [edi+0x14],0
    jne    13b

    // found the entry
    mov    ebx,     DWORD PTR [edi+0x2C]
    and     ebx,    0x3f

    // The encryption bit position is always above 31
    sub     ebx,    32
    xor     edx,    edx
    bts     edx,    ebx
    jmp     3f

2:
    xor     edx,    edx

3:
    // Correct initial PML3
    mov     eax,    {INITIAL_PML3}
    or      [eax + 4 + 3*8], edx
    or      [eax + 4 + 4*8], edx
    or      [eax + 4 + 5*8], edx

    // Correct initial PML4
    mov     eax, {INITIAL_PML4}
    // Set C-Bit in PML4 - pre 64bit
    or      [eax + 4], edx

    // activate initial simple identity page table
    mov     cr3,    eax

    // backup C-bit
    mov     ebx,    edx

    // setup CR4
    mov     eax,    cr4
    // set FSGSBASE | PAE | OSFXSR | OSXMMEXCPT | OSXSAVE
    or      eax,    {CR4_FLAGS}
    mov     cr4,    eax

    // setup EFER
    // EFER |= LONG_MODE_ACTIVE | LONG_MODE_ENABLE | NO_EXECUTE_ENABLE | SYSTEM_CALL_EXTENSIONS
    // FIXME: what about already set bits?
    mov     ecx,    0xc0000080
    rdmsr
    or      eax,    {EFER_FLAGS}
    wrmsr

    // setup CR0
    mov     eax,    cr0
    // set PG
    or     eax,     {CR0_PAGING}
    // enable paging
    mov     cr0,    eax

    // Due to a rust/LLVM bug, we have to use an absolute address here
    // jmpl    0x18,    code64_start
    jmpl    0x18,   (reset_vector_page + 0x8)

88: // Terminate with a GHCB exit
    // set exit reason and exit code
    mov     eax,    (0x2 << 16) + 0x1100
    xor     edx,    edx
    mov     ecx,    {SEV_GHCB_MSR}
    wrmsr
    rep     vmmcall
    #
    # We shouldn't come back from the VMGEXIT, but if we do, just loop.
    #
2:
    hlt
    jmp 2b

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

    // setup PDPT in PML4T table
    lea     rax,    [rip + {PML4T}]
    lea     rbx,    [rip + {PDPT}]
    or      rbx,    r12         // set C-bit
    or      rbx,    0x3         // (WRITABLE | PRESENT)
    // SHIM_VIRT_OFFSET
    mov     QWORD PTR [rax + ((({SHIM_VIRT_OFFSET} & 0xFFFFFFFFFFFF) >> 39)*8)],   rbx
    // IDENTITY
    mov     QWORD PTR [rax],    rbx

    // setup PDPT table entry 0 with PDT_C000_0000 table
    lea     rbx,    [rip + {PDPT}]
    lea     rcx,    [rip + {PDT_C000_0000}]
    or      rcx,    r12         // set C-bit
    or      rcx,    0x3         // ( WRITABLE | PRESENT)
    // store PDT_C000_0000 table in PDPT in the correct slot
    // 3: 0xc000_0000 - 0x1_0000_0000
    mov     QWORD PTR [rbx + 3*8],    rcx

    lea     rcx,    [rip + {PDT_C000_0000}]
    lea     rbx,    [rip + {PT_FFE0_0000}]
    or      rbx,    r12         // set C-bit
    or      rbx,    0x3         // ( WRITABLE | PRESENT)
    // store PT_FFE0_0000 table in PDT_C000_0000 in the correct slot
    mov     QWORD PTR [rcx + 511*8],    rbx

    // set C-bit in all entries of the PDPT table
    lea     rbx,    [rip + {PDPT}]
    mov     rdx,    r11
    mov     ecx,    512         // Counter to 512 page table entries
    add     rbx,    4           // Pre-advance pointer by 4 bytes for the higher 32bit
4:
    or      DWORD PTR [rbx],edx // set C-bit
    add     rbx,    8           // advance pointer by 8
    loop    4b

    // set C-bit in all entries of the PDT_C000_0000 table
    lea     rbx,    [rip + {PDT_C000_0000}]
    mov     rdx,    r11
    mov     ecx,    512         // Counter to 512 page table entries
    add     rbx,    4           // Pre-advance pointer by 4 bytes for the higher 32bit
5:
    or      DWORD PTR [rbx],edx // set C-bit
    add     rbx,    8           // advance pointer by 8
    loop    5b

    // set C-bit in all entries of the PT_FFE0_0000 table
    lea     rbx,    [rip + {PT_FFE0_0000}]
    mov     rdx,    r11
    mov     ecx,    512         // Counter to 512 page table entries
    add     rbx,    4           // Pre-advance pointer by 4 bytes for the higher 32bit
6:
    or      DWORD PTR [rbx],edx // set C-bit
    add     rbx,    8           // advance pointer by 8
    loop    6b

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

    sub     rsp,    8
    push    rbp

    // arg1 %rdi  = SEV C-bit mask
    call    {START_MAIN}

97: // end of code
.fill (0xFF0 - (97b - 99b))

// reset vector @ 0xFFFF_FFF0
.code16
    jmp     20b
    hlt

98: // end of reset vector jump table

// fill until the end of page minus 2 for the `ud2` rust/llvm add
.fill(({PAGE_SIZE} - (98b - 99b) - 2))

// END OF PAGE
    ",
    EFER_FLAGS = const (EferFlags::LONG_MODE_ENABLE.bits() | EferFlags::SYSTEM_CALL_EXTENSIONS.bits() | EferFlags::NO_EXECUTE_ENABLE.bits()),
    SHIM_VIRT_OFFSET = const SHIM_VIRT_OFFSET,
    SIZE_OF_INITIAL_STACK = const INITIAL_STACK_PAGES * size_of::<Page>(),
    PAGE_SIZE = const size_of::<Page>(),
    DYN_RELOC = sym dyn_reloc,
    START_MAIN = sym _start_main,
    PML4T = sym PML4T,
    PDPT = sym PDPT,
    PDT_C000_0000 = sym PDT_C000_0000,
    PT_FFE0_0000 = sym PT_FFE0_0000,
    INITIAL_SHIM_STACK = sym INITIAL_SHIM_STACK,
    CPUID_PAGE = const 0xFFFF_C000u32,
    INITIAL_PML3 = const 0xFFFF_D000u32,
    INITIAL_PML4 = const 0xFFFF_E000u32,
    SEV_GHCB_MSR = const 0xC001_0130u32,
    CR4_FLAGS = const (Cr4Flags::FSGSBASE.bits() | Cr4Flags::PHYSICAL_ADDRESS_EXTENSION.bits() | Cr4Flags::OSFXSR.bits() | Cr4Flags::OSXMMEXCPT_ENABLE.bits() | Cr4Flags::OSXSAVE.bits()),
    PROTECTED_MODE_ENABLE = const Cr0Flags::PROTECTED_MODE_ENABLE.bits(),
    CR0_PAGING = const Cr0Flags::PAGING.bits(),
    options(noreturn)
    )
}
