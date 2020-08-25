// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Kvm, VcpuExit};

const CODE: &[u8] = &[
    0xf4, // hlt
];

#[test]
fn sev() {
    let kvm = Kvm::new().unwrap();
    let vm = kvm.create_vm().unwrap();

    const MEM_SIZE: usize = 0x1000;
    let address_space = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            MEM_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        ) as *mut u8
    };

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: MEM_SIZE as _,
        userspace_addr: address_space as _,
        flags: 0,
    };

    unsafe {
        vm.set_user_memory_region(mem_region).unwrap();
    }

    unsafe {
        let zeros = [0u8; MEM_SIZE];
        std::slice::from_raw_parts_mut(address_space, MEM_SIZE)
            .write(&zeros[..])
            .unwrap();
    }

    let vcpu = vm.create_vcpu(0).unwrap();
    let mut sregs = vcpu.get_sregs().unwrap();
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    vcpu.set_sregs(&sregs).unwrap();

    let mut regs = vcpu.get_regs().unwrap();
    regs.rip = std::ptr::null() as *const u64 as u64;
    regs.rflags = 2;
    vcpu.set_regs(&regs).unwrap();

    loop {
        match vcpu.run().unwrap() {
            VcpuExit::Hlt => break,
            exit_reason => panic!("unexpected exit reason: {:?}", exit_reason),
        }
    }
}
