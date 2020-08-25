// SPDX-License-Identifier: Apache-2.0

use sev::certs::Chain;
use sev::firmware::Firmware;
use sev::launch::{HeaderFlags, Launcher, Policy};
use sev::session::Session;
use sev::Generation;

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Kvm, VcpuExit};

use std::convert::TryFrom;
use std::fs::File;
use std::io::Write;

const CODE: &[u8] = &[
    0xf4, // hlt
];

fn get_cert_chain(sev: &mut Firmware) -> Chain {
    use codicon::Decoder;

    // If you are running this test suite often without manipulating the platform
    // state (i.e., platform reset) it is recommended that you export the entire
    // chain to a file and use this environment variable to avoid getting rate-limited
    // by the AMD web service (which will cause a panic).
    if let Ok(cached_chain) = std::env::var("CHAIN") {
        let mut chain = File::open(cached_chain).unwrap();

        Chain::decode(&mut chain, ()).unwrap()
    } else {
        let mut platform = sev.pdh_cert_export().unwrap();

        let id = sev.get_identifer().unwrap();
        let url = format!("https://kdsintf.amd.com/cek/id/{}", id);

        let mut resp = reqwest::blocking::get(&url)
            .unwrap()
            .error_for_status()
            .unwrap();

        let mut cek = vec![];
        let _ = resp.copy_to(&mut cek).unwrap();
        platform.cek = sev::certs::sev::Certificate::decode(&mut &cek[..], ()).unwrap();

        let ca = Generation::try_from(&platform).unwrap().into();

        Chain { sev: platform, ca }
    }
}

#[cfg_attr(any(not(has_sev), feature = "dangerous_tests"), ignore)]
#[test]
fn sev() {
    let mut sev = Firmware::open().unwrap();
    let build = sev.platform_status().unwrap().build;
    let chain = get_cert_chain(&mut sev);

    let policy = Policy::default();
    let session = Session::try_from(policy).unwrap();
    let start = session.start(chain).unwrap();

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

    let guest_addr = unsafe { std::slice::from_raw_parts(address_space, MEM_SIZE) };

    let (mut launcher, measurement) = {
        let launcher = Launcher::new(&vm, &sev).unwrap();
        let launcher = launcher.start(start).unwrap();
        let launcher = launcher.measure().unwrap();
        let measurement = launcher.measurement();
        (launcher, measurement)
    };

    let session = session.measure().unwrap();
    let session = session.verify(build, measurement).unwrap();
    let secret = session.secret(HeaderFlags::default(), CODE).unwrap();

    launcher.pin_pages(guest_addr).unwrap();
    launcher.inject(secret, &guest_addr[0]).unwrap();

    let _handle = launcher.finish().unwrap();

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
