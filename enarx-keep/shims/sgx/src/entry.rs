// SPDX-License-Identifier: Apache-2.0

use crt0stack::{Builder, Entry, Handle, OutOfSpace};
use goblin::elf::header::{header64::Header, ELFMAG};

use crate::Layout;

extern "C" {
    fn jump(rsp: u64, fnc: u64) -> !;
    fn exit(code: u8) -> !;
}

fn random() -> u64 {
    let mut r: u64 = 0;

    for _ in 0..1024 {
        if unsafe { core::arch::x86_64::_rdrand64_step(&mut r) } == 1 {
            return r;
        }
    }

    unsafe { exit(1) }
}

fn crt0setup<'a>(
    layout: &Layout,
    hdr: &Header,
    crt0: &'a mut [u8],
) -> Result<Handle<'a>, OutOfSpace> {
    let rand = unsafe { core::mem::transmute([random(), random()]) };
    let phdr = layout.code.start as u64 + hdr.e_phoff;

    // Set the arguments
    let mut builder = Builder::new(crt0);
    builder.push("/init")?;

    // Set the environment
    let mut builder = builder.done()?;
    builder.push("LANG=C")?;

    // Set the aux vector
    let mut builder = builder.done()?;
    builder.push(&Entry::ExecFilename("/init"))?;
    builder.push(&Entry::Platform("x86_64"))?;
    builder.push(&Entry::Uid(1000))?;
    builder.push(&Entry::EUid(1000))?;
    builder.push(&Entry::Gid(1000))?;
    builder.push(&Entry::EGid(1000))?;
    builder.push(&Entry::PageSize(4096))?;
    builder.push(&Entry::Secure(false))?;
    builder.push(&Entry::ClockTick(100))?;
    builder.push(&Entry::Flags(0))?; // TODO: https://github.com/enarx/enarx/issues/386
    builder.push(&Entry::HwCap(0))?; // TODO: https://github.com/enarx/enarx/issues/386
    builder.push(&Entry::HwCap2(0))?; // TODO: https://github.com/enarx/enarx/issues/386
    builder.push(&Entry::PHdr(phdr as _))?;
    builder.push(&Entry::PHent(hdr.e_phentsize as _))?;
    builder.push(&Entry::PHnum(hdr.e_phnum as _))?;
    builder.push(&Entry::Random(rand))?;

    builder.done()
}

#[no_mangle]
pub extern "C" fn entry(_rdi: u64, _rsi: u64, _rdx: u64, layout: &Layout, _r8: u64, _r9: u64) -> ! {
    // Validate the ELF header.
    let hdr = unsafe { &*(layout.code.start as *const Header) };

    if !hdr.e_ident[..ELFMAG.len()].eq(ELFMAG) {
        unsafe { exit(1) };
    }

    // Prepare the crt0 stack.
    let mut crt0 = [0u8; 1024];
    let space = random() as usize & 0xf0;
    let handle = match crt0setup(layout, hdr, &mut crt0[space..]) {
        Err(OutOfSpace) => unsafe { exit(1) },
        Ok(handle) => handle,
    };

    unsafe {
        jump(
            handle.start_ptr() as *const _ as _,
            layout.code.start as u64 + hdr.e_entry,
        )
    }
}
