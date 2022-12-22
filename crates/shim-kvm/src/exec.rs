// SPDX-License-Identifier: Apache-2.0

//! Functions dealing with the exec

use crate::addr::ShimPhysAddr;
use crate::allocator::ALLOCATOR;
use crate::random::random;
use crate::shim_stack::init_stack_with_guard;
use crate::snp::cpuid;
use crate::usermode::usermode;
use crate::{
    EXEC_BRK_VIRT_ADDR_BASE, EXEC_ELF_VIRT_ADDR_BASE, EXEC_STACK_SIZE, EXEC_STACK_VIRT_ADDR_BASE,
};

use core::convert::TryFrom;
use core::sync::atomic::{AtomicBool, Ordering};

use crt0stack::{self, Builder, Entry};
use goblin::elf::header::header64::Header;
use goblin::elf::header::ELFMAG;
use goblin::elf::program_header::program_header64::*;
use lset::Line;
use spin::{Lazy, RwLock};
use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

/// Indicator, if the executable is ready to be executed or already executed
pub static EXEC_READY: AtomicBool = AtomicBool::new(false);

/// The randomized virtual address of the exec
#[cfg(not(feature = "gdb"))]
pub static EXEC_VIRT_ADDR: Lazy<RwLock<VirtAddr>> =
    Lazy::new(|| RwLock::new(EXEC_ELF_VIRT_ADDR_BASE + (random() & 0x7F_FFFF_F000)));

/// The non-randomized virtual address of the exec in case the gdb feature is active
#[cfg(feature = "gdb")]
pub static EXEC_VIRT_ADDR: Lazy<RwLock<VirtAddr>> =
    Lazy::new(|| RwLock::new(EXEC_ELF_VIRT_ADDR_BASE));

/// Actual brk virtual address the exec gets, when calling brk
pub static BRK_LINE: Lazy<RwLock<Line<VirtAddr>>> = Lazy::new(|| {
    let start = EXEC_BRK_VIRT_ADDR_BASE + (random() & 0xFFFF_F000);
    RwLock::new(Line::new(start, start))
});

/// The global NextMMap RwLock
pub static NEXT_MMAP_RWLOCK: Lazy<RwLock<VirtAddr>> =
    Lazy::new(|| RwLock::new(*EXEC_VIRT_ADDR.read()));

/// load the elf binary
fn map_elf(app_virt_start: VirtAddr) -> &'static Header {
    let header: &Header = unsafe { &crate::_ENARX_EXEC_START };
    let header_ptr = header as *const _;

    if !header.e_ident[..ELFMAG.len()].eq(ELFMAG) {
        panic!("Not valid ELF");
    }

    let headers: &[ProgramHeader] = unsafe {
        #[allow(clippy::cast_ptr_alignment)]
        core::slice::from_raw_parts(
            (header_ptr as usize as *const u8).offset(header.e_phoff as _) as *const ProgramHeader,
            header.e_phnum as _,
        )
    };

    // Convert to shim physical addresses with potential SEV C-Bit set
    let code_start_phys = ShimPhysAddr::try_from(header as *const _)
        .unwrap()
        .raw()
        .raw();

    for ph in headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD && ph.p_memsz > 0)
    {
        let voff = ph.p_paddr % ph.p_align;
        let map_from = PhysAddr::new(code_start_phys.checked_add(ph.p_paddr - voff).unwrap());
        let voff = ph.p_vaddr % ph.p_align;
        let map_to = app_virt_start + ph.p_vaddr - voff;

        let mut page_table_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if (ph.p_flags & PF_X) == 0 {
            page_table_flags |= PageTableFlags::NO_EXECUTE
        };
        if (ph.p_flags & PF_W) != 0 {
            page_table_flags |= PageTableFlags::WRITABLE
        };

        debug_assert_eq!(ph.p_align % Page::<Size4KiB>::SIZE, 0);

        ALLOCATOR
            .lock()
            .map_memory(
                map_from,
                map_to,
                (ph.p_memsz + voff) as _,
                page_table_flags,
                PageTableFlags::PRESENT
                    | PageTableFlags::USER_ACCESSIBLE
                    | PageTableFlags::WRITABLE,
            )
            .expect("Map exec elf failed!");
    }

    header
}

fn crt0setup(
    app_virt_start: VirtAddr,
    stack_slice: &'static mut [u8],
    header: &Header,
) -> (VirtAddr, u64) {
    let mut builder = Builder::new(stack_slice);
    builder.push("/init").unwrap();
    let mut builder = builder.done().unwrap();
    builder.push("LANG=C").unwrap();
    let mut builder = builder.done().unwrap();

    let ph_header = app_virt_start + header.e_phoff;
    let ph_entry = app_virt_start + header.e_entry;

    let hwcap = cpuid(1).edx;

    let rand = unsafe { core::mem::transmute([random(), random()]) };

    for aux in &[
        //Entry::SysInfoEHdr(0x7FD735C0E000),
        Entry::ExecFilename("/init"),
        Entry::Platform("x86_64"),
        Entry::Uid(1000),
        Entry::EUid(1000),
        Entry::Gid(1000),
        Entry::EGid(1000),
        Entry::PageSize(4096),
        Entry::Secure(false),
        Entry::ClockTick(100),
        Entry::Flags(0),
        //Entry::Base(0),
        Entry::PHdr(ph_header.as_u64() as _),
        Entry::PHent(header.e_phentsize as _),
        Entry::PHnum(header.e_phnum as _),
        Entry::HwCap(hwcap as _),
        // FSGSBASE flag is 1 << 1
        Entry::HwCap2(2),
        Entry::Random(rand),
        Entry::Entry(ph_entry.as_u64() as _),
    ] {
        builder.push(aux).unwrap();
    }
    let handle = builder.done().unwrap();
    let sp = &*handle as *const _ as u64;

    (ph_entry, sp)
}

/// execute the exec
pub fn execute_exec() -> ! {
    let header = map_elf(*EXEC_VIRT_ADDR.read());

    let stack = init_stack_with_guard(
        EXEC_STACK_VIRT_ADDR_BASE + (random() & 0xFFFF_F000),
        EXEC_STACK_SIZE,
        PageTableFlags::USER_ACCESSIBLE,
    );

    let (entry, sp_handle) = crt0setup(*EXEC_VIRT_ADDR.read(), stack.slice, header);

    #[cfg(feature = "gdb")]
    unsafe {
        use core::arch::asm;

        // Breakpoint at the exec entry address
        asm!(
            "mov dr0, {}",
            "mov dr7, {}",

            in(reg) entry.as_u64(),
            in(reg) 1u64,
        )
    };

    unsafe {
        EXEC_READY.store(true, Ordering::Relaxed);
        usermode(entry.as_u64(), sp_handle)
    }
}
