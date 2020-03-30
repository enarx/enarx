// SPDX-License-Identifier: Apache-2.0

use crate::arch::x86_64::PAGESIZE;
use vmsyscall::bootinfo::BootInfo;
use vmsyscall::memory_map::{FrameRange, Map, Region, RegionType};
use x86_64::PhysAddr;

extern "C" {
    // FIXME: remove after using enumerate crate
    #[allow(improper_ctypes)]
    fn _start_main(bootinfo: *mut BootInfo) -> !;
}

#[repr(C)]
pub struct HvmStartInfo {
    magic: u32, /* Contains the magic value 0x336ec578       */
    /* ("xEn3" with the 0x80 bit of the "E" set).*/
    version: u32,       /* Version of this structure.                */
    flags: u32,         /* SIF_xxx flags.                            */
    nr_modules: u32,    /* Number of modules passed to the kernel.   */
    modlist_paddr: u64, /* Physical address of an array of           */
    /* hvm_modlist_entry.                        */
    cmdline_paddr: u64, /* Physical address of the command line.     */
    rsdp_paddr: u64,    /* Physical address of the RSDP ACPI data    */
    /* structure.                                */
    /* All following fields only present in version 1 and newer */
    memmap_paddr: u64, /* Physical address of an array of           */
    /* hvm_memmap_table_entry.                   */
    memmap_entries: u32, /* Number of entries in the memmap table.    */
    /* Value will be zero if there is no memory  */
    /* map being provided.                       */
    reserved: u32, /* Must be zero.                             */
}

/// https://github.com/Xilinx/xen/blob/master/xen/include/public/arch-x86/hvm/start_info.h#L105
#[repr(C)]
pub struct HvmMemmapTableEntry {
    addr: u64,       /* Base address of the memory region         */
    size: u64,       /* Size of the memory region in bytes        */
    entry_type: u32, /* Mapping type                              */
    reserved: u32,   /* Must be zero for Version 1.               */
}

impl HvmMemmapTableEntry {
    pub fn get_type(&self) -> HvmMemmapTableEntryType {
        const XEN_HVM_MEMMAP_TYPE_RAM: u32 = 1;
        const XEN_HVM_MEMMAP_TYPE_RESERVED: u32 = 2;
        const XEN_HVM_MEMMAP_TYPE_ACPI: u32 = 3;
        const XEN_HVM_MEMMAP_TYPE_NVS: u32 = 4;
        const XEN_HVM_MEMMAP_TYPE_UNUSABLE: u32 = 5;
        const XEN_HVM_MEMMAP_TYPE_DISABLED: u32 = 6;
        const XEN_HVM_MEMMAP_TYPE_PMEM: u32 = 7;

        match self.entry_type {
            XEN_HVM_MEMMAP_TYPE_RAM => HvmMemmapTableEntryType::RAM,
            XEN_HVM_MEMMAP_TYPE_RESERVED => HvmMemmapTableEntryType::Reserved,
            XEN_HVM_MEMMAP_TYPE_ACPI => HvmMemmapTableEntryType::ACPI,
            XEN_HVM_MEMMAP_TYPE_NVS => HvmMemmapTableEntryType::NVS,
            XEN_HVM_MEMMAP_TYPE_UNUSABLE => HvmMemmapTableEntryType::Unusable,
            XEN_HVM_MEMMAP_TYPE_DISABLED => HvmMemmapTableEntryType::Disabled,
            XEN_HVM_MEMMAP_TYPE_PMEM => HvmMemmapTableEntryType::PMEM,
            _ => HvmMemmapTableEntryType::Unknown,
        }
    }
}

//#[cfg(feature = "allocator")]
impl core::fmt::Debug for HvmMemmapTableEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(
            f,
            "HvmMemmapTableEntry({:#?} {:#x}..{:#x})",
            self.get_type(),
            self.addr,
            self.addr + self.size
        )
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
    eprintln!("rust_start_820, magic={:#X}", (*hvm_start_info).magic);
    let kernel_start_ptr = &_kernel_start as *const _ as u64;
    let kernel_end_ptr = &_kernel_end as *const _ as u64;

    let e820_count = (*hvm_start_info).memmap_entries;
    let entry = (*hvm_start_info).memmap_paddr as *const HvmMemmapTableEntry;
    eprintln!("addr={}", (*entry).addr);
    let e820_table = core::slice::from_raw_parts(
        (*hvm_start_info).memmap_paddr as *const HvmMemmapTableEntry,
        e820_count as _,
    );
    eprintln!("e820_table={:#X}", (*hvm_start_info).memmap_paddr);
    eprintln!("e820_count={}", e820_count);
    eprintln!("{:#?}", e820_table);

    pub const BOOTINFO_PHYS_ADDR: u64 = 0x8000;

    core::ptr::write(
        BOOTINFO_PHYS_ADDR as *mut BootInfo,
        BootInfo {
            memory_map: Map::new(),
            entry_point: core::ptr::null(),
            load_addr: core::ptr::null(),
            elf_phnum: 0,
            syscall_trigger_port: 0,
        },
    );

    let boot_info: *mut BootInfo = BOOTINFO_PHYS_ADDR as _;

    for entry in e820_table {
        let end = entry.addr + entry.size;
        let start = entry.addr;
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
    /* FIXME
    (*boot_info).memory_map.mark_allocated_region(Region {
        range: FrameRange::new(SYSCALL_PHYS_ADDR, SYSCALL_PHYS_ADDR + 0x1000),
        region_type: RegionType::InUse,
    });
    */
    (*boot_info).memory_map.mark_allocated_region(Region {
        range: FrameRange::new(kernel_start_ptr, kernel_end_ptr),
        region_type: RegionType::Kernel,
    });

    _start_main(boot_info)
}
