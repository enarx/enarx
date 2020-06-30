// SPDX-License-Identifier: Apache-2.0

use crate::x86_64::*;

use kvm_ioctls::VcpuFd;
use x86_64::registers::control::{Cr0Flags, Cr4Flags};
use x86_64::registers::model_specific::EferFlags;
use x86_64::PhysAddr;

use std::io;

pub fn set_gen_regs(vcpu: &VcpuFd, entry: PhysAddr) -> Result<(), io::Error> {
    let mut regs = vcpu.get_regs()?;

    regs.rip = entry.as_u64();
    regs.rflags |= 0x2;

    vcpu.set_regs(&regs)?;
    Ok(())
}

pub fn set_special_regs(vcpu: &VcpuFd) -> Result<(), io::Error> {
    let mut sregs = vcpu.get_sregs()?;

    let cs = KvmSegment {
        base: 0,
        limit: 0xFFFFF,
        selector: 8,
        type_: 11,
        present: 1,
        dpl: 0,
        db: 0,
        s: 1,
        l: 1,
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    };

    sregs.cs = cs;

    sregs.efer = (EferFlags::LONG_MODE_ENABLE | EferFlags::LONG_MODE_ACTIVE).bits();
    sregs.cr0 = (Cr0Flags::PROTECTED_MODE_ENABLE
        | Cr0Flags::NUMERIC_ERROR
        | Cr0Flags::PAGING
        | Cr0Flags::MONITOR_COPROCESSOR)
        .bits();
    sregs.cr3 = PML4_START.as_u64();
    sregs.cr4 = (Cr4Flags::PHYSICAL_ADDRESS_EXTENSION).bits();

    vcpu.set_sregs(&sregs)?;
    Ok(())
}
