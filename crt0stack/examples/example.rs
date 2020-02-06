// SPDX-License-Identifier: Apache-2.0

use crt0stack::{self, Builder, Entry, OutOfSpace};

fn exec(initial_stack_ptr: &()) -> ! {
    println!("initial_stack_ptr={:#?}", initial_stack_ptr as *const ());
    // load sp for the elf binary

    // execute elf

    std::process::exit(0);
}

fn main() -> core::result::Result<(), OutOfSpace> {
    const ELF64_HDR_SIZE: u64 = 0x40;
    const ELF64_PHDR_SIZE: u64 = 56;
    let load_addr: u64 = 0x40_0000; // First elf PT_LOAD
    let num_elf_program_sections: usize = 4;

    let prog = "/init";

    let hwcap = unsafe { core::arch::x86_64::__cpuid(1) }.edx;
    let r1: u64 = 0xAFFEAFFEAFFEAFFE; /* for truly random bytes use
                                      x86_64::instructions::random::RdRand::new()
                                      .unwrap()
                                      .get_u64()
                                      .unwrap();
                                      */
    let r2: u64 = 0xC0FFEEC0FFEEC0FF; /* for truly random bytes use
                                      x86_64::instructions::random::RdRand::new()
                                      .unwrap()
                                      .get_u64()
                                      .unwrap();
                                      */
    let mut random_bytes = [0u8; 16];
    let r1u8 = unsafe { core::slice::from_raw_parts(&r1 as *const u64 as *const u8, 8) };
    let r2u8 = unsafe { core::slice::from_raw_parts(&r2 as *const u64 as *const u8, 8) };
    random_bytes[0..8].copy_from_slice(r1u8);
    random_bytes[8..16].copy_from_slice(r2u8);

    // some memory allocated for the stack
    let mut stack_mem = [0u8; 4096];

    let mut builder = Builder::new(&mut stack_mem);
    builder.push(prog)?;
    let mut builder = builder.next()?;
    builder.push("LANG=C")?;
    let mut builder = builder.next()?;
    for i in &[
        Entry::ExecFilename(prog),
        Entry::Platform("x86_64"),
        Entry::Uid(1000),
        Entry::EUid(1000),
        Entry::Gid(1000),
        Entry::EGid(1000),
        Entry::Pagesize(4096),
        Entry::Secure(false),
        Entry::ClockTick(100),
        Entry::Flags(0),
        Entry::PHdr((load_addr + ELF64_HDR_SIZE) as _),
        Entry::PHent(ELF64_PHDR_SIZE as _),
        Entry::PHnum(num_elf_program_sections),
        Entry::HWCap(hwcap as _),
        Entry::HWCap2(0),
        Entry::Random(random_bytes),
    ] {
        builder.push(i)?;
    }

    let handle = builder.done()?;
    exec(handle.start_ptr());
}
