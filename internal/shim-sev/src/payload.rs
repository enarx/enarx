// SPDX-License-Identifier: Apache-2.0

//! Functions dealing with the payload
use crate::addr::{ShimPhysAddr, ShimVirtAddr};
use crate::allocator::ALLOCATOR;
use crate::paging::SHIM_PAGETABLE;
use crate::random::random;
use crate::shim_stack::init_stack_with_guard;
use crate::usermode::usermode;
use crate::{get_cbit_mask, PAYLOAD_READY};

use core::convert::TryFrom;
use core::ops::DerefMut;
use core::sync::atomic::Ordering;
use crt0stack::{self, Builder, Entry};
use goblin::elf::header::header64::Header;
use goblin::elf::header::ELFMAG;
use goblin::elf::program_header::program_header64::*;
use nbytes::bytes;
use primordial::Address;
use spinning::{Lazy, RwLock};
use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

/// Payload virtual address, where the elf binary is mapped to, plus a random offset
const PAYLOAD_ELF_VIRT_ADDR_BASE: VirtAddr = VirtAddr::new_truncate(0x7f00_0000_0000);

/// The first brk virtual address the payload gets, plus a random offset
const PAYLOAD_BRK_VIRT_ADDR_BASE: VirtAddr = VirtAddr::new_truncate(0x5555_0000_0000);

/// Payload stack virtual address
const PAYLOAD_STACK_VIRT_ADDR_BASE: VirtAddr = VirtAddr::new_truncate(0x7ff0_0000_0000);

/// Initial payload stack size
#[allow(clippy::integer_arithmetic)]
const PAYLOAD_STACK_SIZE: u64 = bytes![8; MiB];

/// The randomized virtual address of the payload
pub static PAYLOAD_VIRT_ADDR: Lazy<RwLock<VirtAddr>> = Lazy::new(|| {
    RwLock::<VirtAddr>::const_new(
        spinning::RawRwLock::const_new(),
        PAYLOAD_ELF_VIRT_ADDR_BASE + (random() & 0x7F_FFFF_F000),
    )
});

/// Actual brk virtual address the payload gets, when calling brk
pub static NEXT_BRK_RWLOCK: Lazy<RwLock<VirtAddr>> = Lazy::new(|| {
    RwLock::<VirtAddr>::const_new(
        spinning::RawRwLock::const_new(),
        PAYLOAD_BRK_VIRT_ADDR_BASE + (random() & 0xFFFF_F000),
    )
});

/// The global NextMMap RwLock
pub static NEXT_MMAP_RWLOCK: Lazy<RwLock<VirtAddr>> =
    Lazy::new(|| RwLock::<VirtAddr>::const_new(spinning::RawRwLock::const_new(), VirtAddr::new(0)));

/// load the elf binary
fn map_elf(app_virt_start: VirtAddr) -> &'static Header {
    let code_start = unsafe { &crate::_ENARX_CODE_START };

    let app_load_addr = Address::<u64, Header>::from(code_start);
    let app_load_addr_virt = ShimVirtAddr::try_from(app_load_addr).unwrap();

    let header_ptr: *const Header = app_load_addr_virt.into();
    let header: &Header = unsafe { &*header_ptr };

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
    let code_start_addr_virt = ShimVirtAddr::try_from(app_load_addr).unwrap();

    let code_start_phys = ShimPhysAddr::try_from(code_start_addr_virt)
        .unwrap()
        .raw()
        .raw()
        | get_cbit_mask();

    for ph in headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD && ph.p_memsz > 0)
    {
        let map_from = PhysAddr::new(code_start_phys.checked_add(ph.p_paddr).unwrap());

        let map_to = app_virt_start + ph.p_vaddr;

        let mut page_table_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if (ph.p_flags & PF_X) == 0 {
            page_table_flags |= PageTableFlags::NO_EXECUTE
        };
        if (ph.p_flags & PF_W) != 0 {
            page_table_flags |= PageTableFlags::WRITABLE
        };

        debug_assert_eq!(ph.p_align, Page::<Size4KiB>::SIZE);

        ALLOCATOR
            .write()
            .map_memory(
                SHIM_PAGETABLE.write().deref_mut(),
                map_from,
                map_to,
                ph.p_memsz as _,
                page_table_flags,
                PageTableFlags::PRESENT
                    | PageTableFlags::USER_ACCESSIBLE
                    | PageTableFlags::WRITABLE,
            )
            .expect("Map payload elf failed!");
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

    let hwcap = unsafe { core::arch::x86_64::__cpuid(1) }.edx;
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
        Entry::HwCap2(0),
        Entry::Random(rand),
        Entry::Entry(ph_entry.as_u64() as _),
    ] {
        builder.push(aux).unwrap();
    }
    let handle = builder.done().unwrap();
    let sp = &*handle as *const _ as u64;

    (ph_entry, sp)
}

/// execute the payload
pub fn execute_payload() -> ! {
    let header = map_elf(*PAYLOAD_VIRT_ADDR.read());

    let stack = init_stack_with_guard(
        PAYLOAD_STACK_VIRT_ADDR_BASE + (random() & 0xFFFF_F000),
        PAYLOAD_STACK_SIZE,
        PageTableFlags::USER_ACCESSIBLE,
    );

    let (entry, sp_handle) = crt0setup(*PAYLOAD_VIRT_ADDR.read(), stack.slice, header);

    unsafe {
        PAYLOAD_READY.store(true, Ordering::Relaxed);
        usermode(entry.as_u64(), sp_handle)
    }
}
