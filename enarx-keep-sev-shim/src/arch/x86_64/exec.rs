// SPDX-License-Identifier: Apache-2.0

use super::syscall;
use crate::arch::x86_64::structures::paging::{
    mapper::MapToError, FrameAllocator, Mapper, OffsetPageTable, Page, PageTableFlags, Size4KiB,
};
use crate::memory::BootInfoFrameAllocator;
use crate::{exit_hypervisor, HyperVisorExitCode};
use crt0stack::{self, Builder, Entry};
use x86_64::instructions::random::RdRand;
use x86_64::VirtAddr;

const PML4_SIZE: usize = 0x0000_0080_0000_0000;
const USER_STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB
const USER_STACK_OFFSET: usize = PML4_SIZE * 4;
//const USER_HEAP_OFFSET: usize = PML4_SIZE;

pub fn exec_elf(
    mapper: &mut OffsetPageTable,
    frame_allocator: &mut BootInfoFrameAllocator,
    app_entry_point: *const u8,
    app_load_addr: *const u8,
    app_phnum: usize,
) -> ! {
    let virt_start_addr = VirtAddr::new(USER_STACK_OFFSET as u64);
    let start_page: Page = Page::containing_address(virt_start_addr);
    let end_page: Page = Page::containing_address(virt_start_addr + USER_STACK_SIZE - 256u64);
    let page_range = Page::range_inclusive(start_page, end_page);

    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::<Size4KiB>::FrameAllocationFailed)
            .unwrap();
        mapper
            .map_to(
                page,
                frame,
                PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE,
                PageTableFlags::USER_ACCESSIBLE,
                frame_allocator,
            )
            .unwrap()
            .flush();
    }

    const ELF64_HDR_SIZE: u64 = 0x40;
    const ELF64_PHDR_SIZE: u64 = 56;

    let hwcap = unsafe { core::arch::x86_64::__cpuid(1) }.edx;
    let rdrand = RdRand::new();
    let (r1, r2) = match rdrand {
        None => {
            if cfg!(debug_assertions) {
                eprintln!("!!! No RDRAND. Using pseudo random numbers!!!");
                (0xAFFE_AFFE_AFFE_AFFE_u64, 0xC0FF_EEC0_FFEE_C0FF_u64)
            } else {
                panic!("No rdrand supported by CPU")
            }
        }
        Some(rdrand) => (rdrand.get_u64().unwrap(), rdrand.get_u64().unwrap()),
    };

    let mut ra = [0u8; 16];
    let r1u8 = unsafe { core::slice::from_raw_parts(&r1 as *const u64 as *const u8, 8) };
    let r2u8 = unsafe { core::slice::from_raw_parts(&r2 as *const u64 as *const u8, 8) };
    ra[0..8].copy_from_slice(r1u8);
    ra[8..16].copy_from_slice(r2u8);

    let mut sp_slice =
        unsafe { core::slice::from_raw_parts_mut((USER_STACK_OFFSET) as *mut u8, USER_STACK_SIZE) };

    let mut builder = Builder::new(&mut sp_slice);
    builder.push("/init").unwrap();
    let mut builder = builder.done().unwrap();
    builder.push("LANG=C").unwrap();
    let mut builder = builder.done().unwrap();
    for aux in &[
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
        Entry::PHdr((app_load_addr as u64 + ELF64_HDR_SIZE) as _),
        Entry::PHent(ELF64_PHDR_SIZE as _),
        Entry::PHnum(app_phnum),
        Entry::HwCap(hwcap as _),
        Entry::HwCap2(0),
        Entry::Random(ra),
    ] {
        builder.push(aux).unwrap();
    }
    let handle = builder.done().unwrap();
    let sp = handle.start_ptr() as *const () as usize;

    #[cfg(debug_assertions)]
    {
        eprintln!("app_entry_point={:#X}", app_entry_point as u64);
        eprintln!("app_load_addr={:#X}", app_load_addr as u64);
        eprintln!("app_phnum={}", app_phnum);
        eprintln!("stackpointer={:#X}", sp);
        eprintln!("USER_STACK_OFFSET={:#X}", USER_STACK_OFFSET);
        eprintln!("\n========= APP START =============\n");
    }

    if app_entry_point.is_null() {
        eprintln!("app_entry_point.is_null()");
        exit_hypervisor(HyperVisorExitCode::Success);
        crate::hlt_loop()
    } else {
        unsafe {
            syscall::usermode(app_entry_point as usize, sp, 0);
        }
    }
}
