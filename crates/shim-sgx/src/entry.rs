// SPDX-License-Identifier: Apache-2.0

//! FIXME: add docs

use core::arch::asm;

use crate::thread::Tcb;
use crt0stack::{Builder, Entry, Handle, OutOfSpace};
use goblin::elf::header::{header64::Header, ELFMAG};
use sallyport::libc::SYS_exit_group;

fn exit_group(code: usize) -> ! {
    loop {
        unsafe {
            asm!(
                "syscall",
                in("rax") SYS_exit_group,
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

    exit_group(1)
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
    builder.push("RUST_LOG=enarx=debug,enarx-exec-wasmtime=debug")?;

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
    builder.push(&Entry::HwCap2(2))?; // FSGSBASE flag is 1 << 1
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
#[inline(never)] // prevent inlining to avoid stack frame getting merged with `main()`'s
pub unsafe fn entry(offset: *const (), tcb: &mut Tcb) -> i32 {
    // Validate the ELF header.
    let hdr = &*(offset as *const Header);
    if !hdr.e_ident[..ELFMAG.len()].eq(ELFMAG) {
        exit_group(1);
    }

    // Prepare the crt0 stack.
    // FIXME: https://github.com/enarx/enarx/issues/2234
    // This is a bit of a hack. We need to pass the crt0 stack to the shim, but
    // it might not be the last thing the compiler has on the stack.
    // If it does, there is UB, if something will be restored from it on return.
    let mut crt0 = [0u8; 1024];
    let space = random() as usize & 0xf0;
    let handle = match crt0setup(hdr, &mut crt0[space..], offset) {
        Err(OutOfSpace) => exit_group(1),
        Ok(handle) => handle,
    };

    let entry = offset as u64 + hdr.e_entry;

    #[cfg(feature = "gdb")]
    crate::handler::gdb::set_bp(entry);

    let ret: i32;

    asm!(
        "rdfsbase rcx                        ",
        "mov [rdx + 0*8], rcx                ", // tcb.fsbase
        "rdgsbase rcx                        ",
        "mov [rdx + 1*8], rcx                ", // tcb.gsbase
        "mov [rdx + 2*8], rbp                ", // tcb.rbp
        "mov [rdx + 3*8], rbx                ", // tcb.rbx
        "lea rcx,         [rip + 2f]         ",
        "mov [rdx + 4*8], rcx                ", // tcb.rip = label 2
        "mov [rdx + 5*8], rsp                ", // tcb.rsp
        "mov rsp,         rax                ", // load crt0 stack
        "mov rax,         0                  ",
        "wrfsbase rax                        ", // clear fsbase
        "jmp r15                             ", // jump to entry point
        "2:                                  ", // return point for exit

        inout("rax") &*handle as *const _ as u64 => _,
        lateout("ecx") ret,
        inout("r15") entry => _,
        lateout("r14") _,
        lateout("r13") _,
        lateout("r12") _,
        lateout("r11") _,
        lateout("r10") _,
        lateout("r9") _,
        lateout("r8") _ ,
        lateout("rdi") _,
        lateout("rsi") _,
        inout("rdx") &mut tcb.return_to_main as *mut _ as u64 => _,
    );

    ret
}
