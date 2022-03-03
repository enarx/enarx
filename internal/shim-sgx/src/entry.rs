// SPDX-License-Identifier: Apache-2.0

//! FIXME: add docs

use core::arch::asm;

use crt0stack::{Builder, Entry, Handle, OutOfSpace};
use goblin::elf::header::{header64::Header, ELFMAG};

fn exit(code: usize) -> ! {
    loop {
        unsafe {
            asm!(
                "syscall",
                in("rax") libc::SYS_exit,
                in("rdi") code
            );
        }
    }
}

fn random() -> u64 {
    let mut r: u64 = 0;

    for _ in 0..1024 {
        if unsafe { core::arch::x86_64::_rdrand64_step(&mut r) } == 1 {
            return r;
        }
    }

    exit(1)
}

fn crt0setup<'a>(
    hdr: &Header,
    crt0: &'a mut [u8],
    off: *const (),
) -> Result<Handle<'a>, OutOfSpace> {
    let rand = unsafe { core::mem::transmute([random(), random()]) };
    let phdr = off as u64 + hdr.e_phoff;

    // Set the arguments
    let mut builder = Builder::new(crt0);
    builder.push("/init")?;

    // Set the environment
    let mut builder = builder.done()?;
    builder.push("LANG=C")?;
    // FIXME - v0.1.0 KEEP-CONFIG HACK
    // We don't yet have a well-defined way to pass runtime configuration from
    // the frontend/CLI into the keep. This is a hack to simulate that process.
    // For v0.1.0 the keep configuration is hardcoded as follows:
    //   * the .wasm module is open on fd3 and gets no arguments or env vars
    //   * stdin, stdout, and stderr are enabled and should go to fd 0,1,2
    //   * logging should be turned on at "debug" level
    // This is one possible way we could provide that information to the code
    // inside the keep. The actual implementation may be completely different.
    builder.push("ENARX_STDIO_FDS=0,1,2")?;
    builder.push("ENARX_MODULE_FD=3")?;
    builder.push("RUST_LOG=enarx=debug,wasmldr=debug")?;

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

/// The initial entry function to startup the exec code
///
/// # Safety
///
/// The caller has to ensure `offset` points to a valid, aligned Elf header and is non-null.
pub unsafe fn entry(offset: *const ()) -> ! {
    // Validate the ELF header.
    let hdr = &*(offset as *const Header);
    if !hdr.e_ident[..ELFMAG.len()].eq(ELFMAG) {
        exit(1);
    }

    // Prepare the crt0 stack.
    let mut crt0 = [0u8; 1024];
    let space = random() as usize & 0xf0;
    let handle = match crt0setup(hdr, &mut crt0[space..], offset) {
        Err(OutOfSpace) => exit(1),
        Ok(handle) => handle,
    };

    let entry = offset as u64 + hdr.e_entry;

    #[cfg(feature = "gdb")]
    crate::handler::gdb::set_bp(entry);

    asm!(
        "mov rsp, {SP}",
        "jmp {START}",
        SP = in(reg) &*handle,
        START = in(reg) entry,
        options(noreturn)
    )
}
