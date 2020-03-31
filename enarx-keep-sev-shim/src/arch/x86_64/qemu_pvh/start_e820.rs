// SPDX-License-Identifier: Apache-2.0

use crate::arch::x86_64::qemu_pvh::hvm_start_info::{
    self, hvm_memmap_table_entry as HvmMemmapTableEntry, hvm_modlist_entry as HvmModlistEntry,
    hvm_start_info as HvmStartInfo, XEN_HVM_START_MAGIC_VALUE,
};
use crate::arch::x86_64::{PAGESIZE, PHYSICAL_MEMORY_OFFSET};
use crate::{exit_hypervisor, hlt_loop, HyperVisorExitCode};
use vmsyscall::bootinfo::BootInfo;
use vmsyscall::memory_map::{FrameRange, Map, Region, RegionType};
use x86_64::PhysAddr;

extern "C" {
    // FIXME: remove after using enumerate crate
    #[allow(improper_ctypes)]
    fn _start_main(bootinfo: *mut BootInfo) -> !;
}

pub static mut APP_START_PTR: u64 = 0;
pub static mut APP_SIZE: u64 = 0;

/// # Safety
///
/// Relies on qemu to correctly fill out the structure
impl core::fmt::Debug for HvmStartInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        let memmap_slice = unsafe {
            core::slice::from_raw_parts(
                self.memmap_paddr as *const HvmMemmapTableEntry,
                self.memmap_entries as _,
            )
        };

        let modlist_slice = unsafe {
            core::slice::from_raw_parts(
                self.modlist_paddr as *const HvmModlistEntry,
                self.nr_modules as _,
            )
        };

        f.debug_struct("HvmStartInfo")
            .field("magic", &format_args!("{:#x}", self.magic))
            .field("version", &format_args!("{}", self.version))
            .field("modlist", &format_args!("{:#?}", modlist_slice))
            .field("cmdline_paddr", &format_args!("{:#x}", self.cmdline_paddr))
            .field("rsdp_paddr", &format_args!("{:#x}", self.rsdp_paddr))
            .field("memmap", &format_args!("{:#?}", memmap_slice))
            .finish()
    }
}

impl HvmMemmapTableEntry {
    pub fn get_type(&self) -> HvmMemmapTableEntryType {
        match self.type_ {
            hvm_start_info::XEN_HVM_MEMMAP_TYPE_RAM => HvmMemmapTableEntryType::RAM,
            hvm_start_info::XEN_HVM_MEMMAP_TYPE_RESERVED => HvmMemmapTableEntryType::Reserved,
            hvm_start_info::XEN_HVM_MEMMAP_TYPE_ACPI => HvmMemmapTableEntryType::ACPI,
            hvm_start_info::XEN_HVM_MEMMAP_TYPE_NVS => HvmMemmapTableEntryType::NVS,
            hvm_start_info::XEN_HVM_MEMMAP_TYPE_UNUSABLE => HvmMemmapTableEntryType::Unusable,
            hvm_start_info::XEN_HVM_MEMMAP_TYPE_DISABLED => HvmMemmapTableEntryType::Disabled,
            hvm_start_info::XEN_HVM_MEMMAP_TYPE_PMEM => HvmMemmapTableEntryType::PMEM,
            _ => HvmMemmapTableEntryType::Unknown,
        }
    }
}

impl core::fmt::Debug for HvmMemmapTableEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("HvmMemmapTableEntry")
            .field("type", &format_args!("{:#?}", self.get_type()))
            .field(
                "address",
                &format_args!("{:#x}..{:#x}", self.addr, self.addr + self.size),
            )
            .finish()
    }
}

impl core::fmt::Debug for HvmModlistEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("HvmModlistEntry")
            .field(
                "address",
                &format_args!("{:#x}..{:#x}", self.paddr, self.paddr + self.size),
            )
            .field("cmdline_paddr", &format_args!("{:#x}", self.cmdline_paddr))
            .finish()
    }
}

#[derive(Debug)]
pub enum HvmMemmapTableEntryType {
    RAM,
    Reserved,
    ACPI,
    NVS,
    Unusable,
    Disabled,
    PMEM,
    Unknown,
}

extern "C" {
    static _kernel_start: usize;
    static _kernel_end: usize;
}

#[export_name = "_start_e820"]
pub unsafe extern "C" fn rust_start_820(hvm_start_info: *const HvmStartInfo) -> ! {
    assert_eq!((*hvm_start_info).magic, XEN_HVM_START_MAGIC_VALUE);

    eprintln!("hvm_start_info={:#?}", &(*hvm_start_info));

    if (*hvm_start_info).nr_modules != 1 {
        eprintln!("ERROR: You must specify exactly on `-initrd <elf binary>` parameter");
        exit_hypervisor(HyperVisorExitCode::Failed);
        hlt_loop();
    }

    let kernel_start_ptr = &_kernel_start as *const _ as u64;
    let kernel_end_ptr = &_kernel_end as *const _ as u64;

    let memmap_slice = core::slice::from_raw_parts(
        (*hvm_start_info).memmap_paddr as *const HvmMemmapTableEntry,
        (*hvm_start_info).memmap_entries as _,
    );

    let modlist_slice = core::slice::from_raw_parts(
        (*hvm_start_info).modlist_paddr as *const HvmModlistEntry,
        (*hvm_start_info).nr_modules as _,
    );

    pub const SYSCALL_PHYS_ADDR: u64 = 0x8000; // qemu does not like 0x1000

    core::ptr::write(
        SYSCALL_PHYS_ADDR as *mut BootInfo,
        BootInfo {
            memory_map: Map::new(),
            entry_point: core::ptr::null(),
            load_addr: core::ptr::null(),
            elf_phnum: 0,
            syscall_trigger_port: 0,
        },
    );

    let boot_info: *mut BootInfo = SYSCALL_PHYS_ADDR as _;

    for entry in memmap_slice {
        let end = entry.addr + entry.size;
        let start = entry.addr;

        //eprintln!("Handling {:#?}", entry);
        #[allow(clippy::single_match)]
        match entry.get_type() {
            HvmMemmapTableEntryType::RAM => {
                (*boot_info).memory_map.add_region(Region {
                    range: FrameRange::new(
                        PhysAddr::new(start).align_up(PAGESIZE as u64).as_u64(),
                        PhysAddr::new(end).align_down(PAGESIZE as u64).as_u64(),
                    ),
                    region_type: RegionType::Usable,
                });
            }

            HvmMemmapTableEntryType::Reserved => {
                (*boot_info).memory_map.add_region(Region {
                    range: FrameRange::new(
                        PhysAddr::new(start).align_down(PAGESIZE as u64).as_u64(),
                        PhysAddr::new(end).align_up(PAGESIZE as u64).as_u64(),
                    ),
                    region_type: RegionType::Reserved,
                });
            }

            _ => {}
        }
    }
    //eprintln!("{:#?}", (*boot_info).memory_map);
    (*boot_info).memory_map.mark_allocated_region(Region {
        range: FrameRange::new(0, 0x1000),
        region_type: RegionType::Reserved,
    });

    (*boot_info).memory_map.mark_allocated_region(Region {
        range: FrameRange::new(SYSCALL_PHYS_ADDR, SYSCALL_PHYS_ADDR + 0x1000),
        region_type: RegionType::InUse,
    });

    (*boot_info).memory_map.mark_allocated_region(Region {
        range: FrameRange::new(kernel_start_ptr, kernel_end_ptr - 1),
        region_type: RegionType::Kernel,
    });

    let app_start_ptr = modlist_slice[0].paddr;
    APP_START_PTR = app_start_ptr + PHYSICAL_MEMORY_OFFSET;
    APP_SIZE = modlist_slice[0].size;

    (*boot_info).memory_map.mark_allocated_region(Region {
        range: FrameRange::new(app_start_ptr, app_start_ptr + APP_SIZE - 1),
        region_type: RegionType::App,
    });

    _start_main(boot_info)
}
