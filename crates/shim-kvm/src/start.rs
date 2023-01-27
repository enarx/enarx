// SPDX-License-Identifier: Apache-2.0

//! The SEV shim
//!
//! Contains the startup code and the main function.

#[allow(unused_extern_crates)]
extern crate rcrt1;

use enarx_shim_kvm::addr::SHIM_VIRT_OFFSET;
use enarx_shim_kvm::allocator::ZERO_PAGE_FRAME;
use enarx_shim_kvm::gdt;
use enarx_shim_kvm::hostcall::BLOCK_SIZE;
use enarx_shim_kvm::interrupts;
use enarx_shim_kvm::pagetables::{unmap_identity, PDPT, PDT_C000_0000, PML4T, PT_FFE0_0000};
use enarx_shim_kvm::shim_stack::{init_stack_with_guard, GuardedStack};
use enarx_shim_kvm::snp::launch::{Policy, PolicyFlags, Version};
use enarx_shim_kvm::snp::C_BIT_MASK;
use enarx_shim_kvm::sse;
use enarx_shim_kvm::stdio::enable_printing;
use enarx_shim_kvm::SHIM_STACK_START;
use enarx_shim_kvm::{exec, SHIM_EX_STACK_START, SHIM_STACK_SIZE};

use core::arch::{asm, global_asm};
use core::mem::size_of;
use core::sync::atomic::Ordering;

use noted::noted;
use primordial::Page;
use rcrt1::dyn_reloc;
use sallyport::{elf::note, REQUIRES};
use spin::Lazy;
use x86_64::registers::control::{Cr0Flags, Cr4Flags, EferFlags};
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

const POLICY_FLAGS: PolicyFlags = PolicyFlags::SMT;

#[cfg(not(any(features = "dbg", features = "gdb", features = "bench")))]
const KEEP_POLICY_FLAGS: PolicyFlags = POLICY_FLAGS;

#[cfg(any(features = "dbg", features = "gdb", features = "bench"))]
const KEEP_POLICY_FLAGS: PolicyFlags =
    PolicyFlags::from_bits_truncate(POLICY_FLAGS.bits() | POLICY_FLAGS::DEBUG.bits());

const POLICY: u64 = Policy {
    flags: KEEP_POLICY_FLAGS,
    minfw: Version {
        major: 1,
        minor: 51,
    },
}
.as_u64();

noted! {
    static NOTE_ENARX_SALLYPORT<note::NAME, note::REQUIRES, [u8; REQUIRES.len()]> = REQUIRES;

    static NOTE_BLOCK_SIZE<note::NAME, note::BLOCK_SIZE, u64> = BLOCK_SIZE as u64;

    static NOTE_SVN<note::NAME, note::snp::SVN, u32> = 1;
    static NOTE_POLICY<note::NAME, note::snp::POLICY, u64> = POLICY;
    static NOTE_FAMILY_ID<note::NAME, note::snp::FAMILY_ID, [u8; 16]> = [0; 16];
    static NOTE_IMAGE_ID<note::NAME, note::snp::IMAGE_ID, [u8; 16]> = [0; 16];
}

#[cfg(not(debug_assertions))]
const INITIAL_STACK_PAGES: usize = 12;
#[cfg(debug_assertions)]
const INITIAL_STACK_PAGES: usize = 50;

#[no_mangle]
#[link_section = ".entry64_data"]
static INITIAL_SHIM_STACK: [Page; INITIAL_STACK_PAGES] = [Page::zeroed(); INITIAL_STACK_PAGES];

/// Create a shim stack
pub fn shim_stack() -> GuardedStack {
    let start = VirtAddr::new(SHIM_STACK_START);
    assert!((start + SHIM_STACK_SIZE).as_u64() < SHIM_EX_STACK_START);
    init_stack_with_guard(start, SHIM_STACK_SIZE, PageTableFlags::empty())
}

/// Switch the stack and jump to a function
///
/// # Safety
///
/// This function is unsafe, because the caller has to ensure a 16 byte
/// aligned usable stack.
#[allow(clippy::integer_arithmetic)]
#[cfg_attr(coverage, no_coverage)]
unsafe fn switch_shim_stack(ip: extern "sysv64" fn(VirtAddr) -> !, sp: VirtAddr) -> ! {
    debug_assert_eq!(sp.as_u64() % 16, 0);

    // load a new stack pointer and jmp to function
    asm!(
    "mov    rsp,    rdi",
    "sub    rsp,    8  ",
    "push   rbp        ",
    "call   {IP}       ",

    IP = in(reg) ip,
    in("rdi") sp.as_u64(),

    options(noreturn, nomem)
    )
}

/// Defines the entry point function.
///
/// # Safety
/// Do not call from Rust.
#[cfg_attr(coverage, no_coverage)]
unsafe extern "sysv64" fn _pre_main(c_bit_mask: u64) -> ! {
    C_BIT_MASK.store(c_bit_mask, Ordering::Relaxed);

    unmap_identity();

    let stack_pointer = shim_stack().pointer;

    // Everything setup, so print works
    enable_printing();

    // Switch the stack to a guarded stack
    switch_shim_stack(main, stack_pointer)
}

/// The main function for the shim with stack setup
#[cfg_attr(coverage, no_coverage)]
extern "sysv64" fn main(stack_pointer: VirtAddr) -> ! {
    // Safety: The stack pointer is 16 byte aligned.
    unsafe {
        gdt::init(stack_pointer);
    }
    sse::init_sse();
    interrupts::init();
    Lazy::force(&ZERO_PAGE_FRAME);
    exec::execute_exec()
}

/// The panic function
///
/// Called, whenever somethings panics.
///
/// Reverts to a triple fault, which causes a `#VMEXIT` and a KVM shutdown,
/// if it can't print the panic and exit normally with an error code.
#[panic_handler]
#[cfg_attr(coverage, no_coverage)]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    use core::sync::atomic::AtomicBool;
    use enarx_shim_kvm::debug::_enarx_asm_triple_fault;
    #[cfg(feature = "dbg")]
    use enarx_shim_kvm::stdio::{self, is_printing_enabled};

    static mut ALREADY_IN_PANIC: AtomicBool = AtomicBool::new(false);

    // Don't print anything, if the FRAME_ALLOCATOR is not yet initialized
    unsafe {
        if ALREADY_IN_PANIC
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            #[cfg(feature = "dbg")]
            if is_printing_enabled() {
                stdio::_eprint(format_args!("{_info}\n"));
                enarx_shim_kvm::debug::print_stack_trace();
            }
            // FIXME: might want to have a custom panic hostcall
            enarx_shim_kvm::hostcall::shim_exit(255);
        }
    }

    // provoke triple fault, causing a VM shutdown
    unsafe { _enarx_asm_triple_fault() }
}

#[rustfmt::skip]
macro_rules! set_table_c_bit {
    (cbit = $cbit_reg:literal, $dst_reg:literal = $dst:literal, $src_reg:literal = $src:literal, offset = $offset:literal) => {
        concat!(
            // setup $dst table entry $offset with $src table
            "lea ", $dst_reg ,", [rip + ", $dst, "]\n",
            "lea ", $src_reg ,", [rip + ", $src, "]\n",
            "or  ", $src_reg ,",", $cbit_reg, "\n", // set C-Bit
            "or  ", $src_reg ,", 0x3\n", // set ( WRITABLE | PRESENT)
            "mov QWORD PTR [", $dst_reg, "+ ", $offset, "*8],", $src_reg, "\n",
        )
    };
}

#[rustfmt::skip]
macro_rules! correct_table_c_bit {
    (cbit_low = $cbit_reg:literal, ctr = $cnt_reg:literal, $dst_reg:literal = $dst:literal) => {
        concat!(
            "lea ", $dst_reg, ", [rip + ", $dst, "]\n",
            // Counter to 512 page table entries
            "mov ", $cnt_reg, ", 512\n",
            // Pre-advance pointer by 4 bytes for the higher 32bit
            "add ", $dst_reg, ", 4\n",
            "2:\n",
            // set C-bit
            "or DWORD PTR [", $dst_reg, "],", $cbit_reg, "\n",
            // advance pointer by 8
            "add ", $dst_reg, ", 8\n",
            "loop   2b\n"
        )
    };
}

// The initial function called at startup
//
// It sets up essential registers, page tables and jumps in shim virtual address space
// to the `_pre_main` rust function.
global_asm!(
        ".pushsection .reset,\"ax\",@progbits",
        ".global _start",
        "_start:",
        ".set reset_vector_page, 0xFFFFF000",

        ".macro define_addr name,label",
        ".set \\name, (reset_vector_page + (\\label - 99b))",
        ".endm",

        // 0xFFFF_F000 - the reset vector page
        "99:",
        // A small jump table with well known addresses
        // to be used because of a rust bug for long jumps

        // *****************************
        // 0xFFFF_F000
        // jump to code32_start
        // *****************************
        ".code32",
        "jmp     30f",

        // *****************************
        // 0xFFFF_F008
        // jump to code64_start
        // *****************************
        ".align 8",
        ".code64",
        "jmp     40f",

        // *****************************
        // The GDT table used for the 16->64 bit transition
        // *****************************
        "define_addr gdt_ptr 66f",
        ".align 8",
        "66:",
        ".short gdt_end - gdt_start - 1", // GDT length is actually (length - 1)
        ".long gdt_start", // address of gdt_start

        // The GDT entries
        "define_addr gdt_start 67f",
        "67:",              // gdt_start
        ".quad  0",         // First descriptor is always unused
        // code32_desc      // base = 0x00000000, limit = 0xfffff x 4K
        ".short 0xffff",    // limit[0..16] = 0xffff
        ".short 0x0000",    // base [0..16] = 0x0000
        ".byte  0x00",      // base[16..24] = 0x00
        ".byte  0x9B",      // present, DPL = 0, system, code seg, grows up, readable, accessed
        ".byte  0xCF",      // 4K gran, 32-bit, limit[16..20] = 0x1111 = 0xf
        ".byte  0x00",      // base[24..32] = 0x00
        // data32_desc      // base = 0x00000000, limit = 0xfffff x 4K
        ".short 0xffff",    // limit 15:0
        ".short 0x0000",    // base 15:0
        ".byte  0x00",      // base[16..24] = 0x00
        ".byte  0x93",      // present, DPL = 0, system, data seg, ring0 only, writable, accessed
        ".byte  0xCF",      // 4K gran, 32-bit, limit[16..20] = 0x1111 = 0xf
        ".byte  0x00",      // base[24..32] = 0x00
        // code64_desc
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
        ".quad  (1<<40) | (1<<41) | (1<<42) | (1<<43) | (1<<44) | (1<<47) | (1<<53)",
        "68:",
        "define_addr gdt_end 68b",

        // *****************************
        // 16-bit setup code
        // *****************************
        "define_addr code16_start 20f",
        "20:",
        ".code16",

        // Disable interrupts
        "cli",

        // Load 32-bit global descriptor table
        "lgdtd  cs:gdt_ptr",

        // setup CR0
        "mov    eax,    cr0",
        // set  PROTECTED_MODE_ENABLE
        "or     al,     {PROTECTED_MODE_ENABLE}",
        "mov    cr0,    eax",

        // Due to a rust/LLVM bug, we have to use an absolute address here
        // expressions like (reset_vector + (label_2 - label_3)) don't seem to work
        // jmpl    0x8,    code32_start
        "jmpl   0x8,    reset_vector_page",

        // *****************************
        // 32-bit setup code
        // *****************************
        "define_addr code32_start 30f",
        "30:",
        ".code32",
        // 0x10 points at the new data selector
        "mov    ax,     0x10",
        "mov    ds,     ax",
        "mov    ss,     ax",

        // Load CPUID_PAGE
        "mov    eax,    DWORD PTR {_ENARX_CPUID}",
        "mov    ecx,    DWORD PTR [eax]",

        // If no entries in CPUID_PAGE, assume no C-Bit
        "test   ecx,    ecx",
        "je     33f",

        "add    ecx,    0x1",
        "32:",
        "add    ecx,    0xffffffff",

        // CPUID not found, terminate
        "je     88f",

        "mov    edi,    eax",
        "add    eax,    0x30",
        // Get pte bit position to enable memory encryption
        // CPUID Fn8000_001F[EBX] - Bits 5:0
        "cmp    DWORD PTR [edi+0x10], 0x8000001f",
        "jne    32b",
        "cmp    DWORD PTR [edi+0x14], 0",
        "jne    32b",

        // found the entry
        "mov    edx,    DWORD PTR [edi+0x2C]",
        // mask the other bits
        "and    edx,    0x3f",

        // The encryption bit position is always above 31
        "sub    edx,    32",
        "xor    ebx,    ebx",
        // set the C-Bit >> 32
        "bts    ebx,    edx",
        "jmp    34f",

        // No C-Bit
        "33:",
        "xor    ebx,    ebx",

        "34:",
        // Correct initial PML3
        // ebx contains C-Bit >> 32
        "mov    eax,    {_ENARX_PML3}",
        "or     [eax + 4 + 3*8], ebx",
        "or     [eax + 4 + 4*8], ebx",
        "or     [eax + 4 + 5*8], ebx",

        // Correct initial PML4
        "mov    eax,    {_ENARX_PML4}",
        // Set C-Bit in PML4 - pre 64bit
        "or     [eax + 4], ebx",

        // activate initial simple identity page table
        "mov    cr3,    eax",

        // setup CR4
        "mov    eax,    cr4",
        // set FSGSBASE | PAE | OSFXSR | OSXMMEXCPT | OSXSAVE
        "or     eax,    {CR4_FLAGS}",
        "mov    cr4,    eax",

        // setup EFER
        // EFER = LONG_MODE_ACTIVE | LONG_MODE_ENABLE | NO_EXECUTE_ENABLE | SYSTEM_CALL_EXTENSIONS
        "mov    ecx,    0xc0000080",
        "rdmsr",
        "or     eax,    {EFER_FLAGS}",
        "wrmsr",

        // setup CR0 to enable paging
        "mov    eax,    cr0",
        "or     eax,    {CR0_PAGING}",
        "mov    cr0,    eax",

        // Due to a rust/LLVM bug, we have to use an absolute address here
        // jmpl    0x18,    code64_start
        "jmpl   0x18,   (reset_vector_page + 0x8)",


        // *****************************
        // Terminate with a GHCB exit
        // *****************************
        "88:",
        // set exit reason and exit code
        "mov    eax,    (0x2 << 16) + 0x1100",
        "xor    edx,    edx",
        "mov    ecx,    {SEV_GHCB_MSR}",
        "wrmsr",
        "rep    vmmcall",

        // We shouldn't come back from the VMGEXIT, but if we do, just loop.
        "2:",
        "hlt",
        "jmp    2b",

        // *****************************
        // 64-bit setup code
        // *****************************
        "define_addr code64_start 40f",
        "40:",
        ".code64",

        // ebx contains C-bit >> 32
        // r12: C-bit full 64bit mask
        "mov    r12,    rbx",
        "shl    r12,    32",

        // Setup the pagetables
        // done dynamically, otherwise we would have to correct the dynamic symbols twice

        set_table_c_bit!(
            cbit = "r12",
            "rax" = "{PML4T}",
            "rdx" = "{PDPT}",
            offset = "((({SHIM_VIRT_OFFSET} & 0xFFFFFFFFFFFF) >> 39))"
        ),
        // Also set {PDPT} in slot 0 (identity) of {PML4T}
        "mov    QWORD PTR [rax],    rdx",

        set_table_c_bit!(cbit = "r12", "rcx" = "{PDPT}", "rdx" = "{PDT_C000_0000}", offset = 3),
        set_table_c_bit!(cbit = "r12", "rcx" = "{PDT_C000_0000}", "rdx" = "{PT_FFE0_0000}", offset = 511),

        correct_table_c_bit!(cbit_low = "ebx", ctr = "ecx", "rdx" = "{PDPT}"),
        correct_table_c_bit!(cbit_low = "ebx", ctr = "ecx", "rdx" = "{PDT_C000_0000}"),
        correct_table_c_bit!(cbit_low = "ebx", ctr = "ecx", "rdx" = "{PT_FFE0_0000}"),

        // set C-bit for new CR3 and load it
        "or     rax,    r12",
        "mov    cr3,    rax",

        // load trampoline address and correct with {SHIM_VIRT_OFFSET}
        "lea    rax,    [rip + 50f]",
        "mov    rsi,    {SHIM_VIRT_OFFSET}",
        "add    rax,    rsi",
         // jump to trampoline
        "jmp    rax",

        // trampoline:
        "50:",

        // load stack in shim virtual address space
        "lea    rsp,    [rip + {INITIAL_SHIM_STACK}]",
        // sub 8 because we push 8 bytes later and want 16 bytes align
        "add    rsp,    {SIZE_OF_INITIAL_STACK}",

        // rdi - _DYNAMIC
        // rsi - {SHIM_VIRT_OFFSET}
        // correct dynamic symbols with shim load offset + {SHIM_VIRT_OFFSET}
        "lea    rdi,    [rip + _DYNAMIC]",
        "call   {DYN_RELOC}",

        // set arg1 to SEV C-Bit mask
        "mov    rdi,    r12",

        // setup stack frame
        "xor    rbp,    rbp",
        "sub    rsp,    8",
        "push   rbp",

        // call the `_pre_main` function and never return
        // arg1 rdi  = SEV C-bit mask
        "call   {PRE_MAIN}",

        // end of code
        "97:",
        ".fill (0xFF0 - (97b - 99b))",

        // reset vector @ 0xFFFF_FFF0
        ".code16",
        "jmp     20b",
        "hlt",

        // end of reset vector jump table
        "98:",

        // fill until the end of page minus 2 for the `ud2` rust/llvm add
        ".fill(({PAGE_SIZE} - (98b - 99b) - 2))",
        // END OF PAGE
        ".popsection",
        ".code64",

        EFER_FLAGS = const (EferFlags::LONG_MODE_ENABLE.bits() | EferFlags::SYSTEM_CALL_EXTENSIONS.bits() | EferFlags::NO_EXECUTE_ENABLE.bits()),
        SHIM_VIRT_OFFSET = const SHIM_VIRT_OFFSET,
        SIZE_OF_INITIAL_STACK = const INITIAL_STACK_PAGES * size_of::<Page>(),
        PAGE_SIZE = const size_of::<Page>(),
        DYN_RELOC = sym dyn_reloc,
        PRE_MAIN = sym _pre_main,
        PML4T = sym PML4T,
        PDPT = sym PDPT,
        PDT_C000_0000 = sym PDT_C000_0000,
        PT_FFE0_0000 = sym PT_FFE0_0000,
        INITIAL_SHIM_STACK = sym INITIAL_SHIM_STACK,
        _ENARX_PML3 = const 0xFFE0_0000u32, // Can't use `sym` because linker does not recognize absolute addresses
        _ENARX_PML4 = const 0xFFE0_1000u32, // Can't use `sym` because linker does not recognize absolute addresses
        _ENARX_CPUID = const 0xFFE0_2000u32, // Can't use `sym` because linker does not recognize absolute addresses
        SEV_GHCB_MSR = const 0xC001_0130u32,
        CR4_FLAGS = const (Cr4Flags::FSGSBASE.bits() | Cr4Flags::PHYSICAL_ADDRESS_EXTENSION.bits() | Cr4Flags::OSFXSR.bits() | Cr4Flags::OSXMMEXCPT_ENABLE.bits() | Cr4Flags::OSXSAVE.bits()),
        PROTECTED_MODE_ENABLE = const Cr0Flags::PROTECTED_MODE_ENABLE.bits(),
        CR0_PAGING = const Cr0Flags::PAGING.bits()  | Cr0Flags::WRITE_PROTECT.bits() | Cr0Flags::MONITOR_COPROCESSOR.bits(),
);
