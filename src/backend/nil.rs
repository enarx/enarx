// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use crt0stack::{Builder, Entry, Handle, OutOfSpace};
use goblin::elf64::program_header::PT_LOAD;
use mmarinus::{perms, Kind, Map};
use primordial::Page;

use std::ops::Range;
use std::sync::{Arc, RwLock};
use std::{arch::asm, mem::forget};

use super::binary::Binary;

pub struct Backend;

impl crate::backend::Backend for Backend {
    #[inline]
    fn name(&self) -> &'static str {
        "nil"
    }

    #[inline]
    fn shim(&self) -> &'static [u8] {
        &[]
    }

    #[inline]
    fn have(&self) -> bool {
        true
    }

    fn data(&self) -> Vec<super::Datum> {
        vec![]
    }

    #[inline]
    fn keep(&self, shim: &[u8], exec: &[u8]) -> Result<Arc<dyn super::Keep>> {
        assert_eq!(shim.len(), 0);

        // Parse the ELF files.
        let ebin = Binary::new(exec.as_ref())?;

        // Check the bounds of the executable.
        let range = ebin.range();
        eprintln!("range: {:?}", range);
        if range.start != 0 {
            return Err(anyhow!("The executable doesn't fit in the slot!"));
        }

        // Create the mapping and copy the bytes.
        let mut size = range.end - range.start;
        eprintln!("size: {:?}", size);
        if !size.is_power_of_two() {
            size = size.next_power_of_two();
        }
        eprintln!("size: {:?}", size);

        // Pick a place to load the binary to.
        let map = Map::map(size)
            .anywhere()
            .anonymously()
            .known::<perms::None>(Kind::Private)?;
        let base = map.addr();
        drop(map);
        eprintln!("base: {:016x}", base);

        // Get an array of all final segment locations (relocated).
        for phdr in ebin.headers(PT_LOAD) {
            let bytes = &ebin.bytes()[phdr.file_range()];
            let slim = phdr.vm_range();
            let wide = Range {
                start: slim.start / Page::SIZE * Page::SIZE,
                end: (slim.end + Page::SIZE - 1) / Page::SIZE * Page::SIZE,
            };

            eprintln!("slim: {:016x}..{:016x}", slim.start, slim.end);
            eprintln!("wide: {:016x}..{:016x}", wide.start, wide.end);
            eprintln!("skip: {:016x}", slim.start - wide.start);

            // Create the mapping and copy the bytes.
            let mut map = Map::map(wide.end - wide.start)
                .at(base + wide.start)
                .anonymously()
                .known::<perms::ReadWrite>(Kind::Private)?;
            eprintln!("map: {:016x}..{:016x}", map.addr(), map.addr() + map.size());
            map[slim.start - wide.start..][..bytes.len()].copy_from_slice(bytes);
            forget(
                map.remap()
                    .anonymously()
                    .unknown(Kind::Private, phdr.p_flags as i32)?,
            );
        }

        let thread = Thread {
            phdr: ebin.elf().header.e_phoff as usize + base,
            phent: ebin.elf().header.e_phentsize as _,
            phnum: ebin.elf().header.e_phnum as _,
            entry: ebin.elf().entry as usize + base,
        };

        eprintln!("entry: {:016x}", ebin.elf().entry);
        eprintln!("entry: {:016x}", thread.entry);
        Ok(Arc::new(RwLock::new(Keep(vec![Box::new(thread)]))))
    }

    #[inline]
    fn hash(&self, _shim: &[u8], _exec: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

struct Keep(Vec<Box<dyn super::Thread>>);

impl super::Keep for RwLock<Keep> {
    fn spawn(self: Arc<Self>) -> Result<Option<Box<dyn super::Thread>>> {
        Ok(self.write().unwrap().0.pop())
    }
}

struct Thread {
    phdr: usize,
    phent: usize,
    phnum: usize,
    entry: usize,
}

impl Thread {
    fn crt0setup<'a>(&self, crt0: &'a mut [u8]) -> Result<Handle<'a>, OutOfSpace> {
        let rand: [u8; 16] = rand::random();

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
        builder.push(&Entry::HwCap2(0))?; // TODO: https://github.com/enarx/enarx/issues/386
        builder.push(&Entry::PHdr(self.phdr))?;
        builder.push(&Entry::PHent(self.phent))?;
        builder.push(&Entry::PHnum(self.phnum))?;
        builder.push(&Entry::Random(rand))?;

        builder.done()
    }
}

impl super::Thread for Thread {
    fn enter(&mut self, _gdblisten: &Option<String>) -> Result<super::Command> {
        eprintln!("enter");

        // Prepare the crt0 stack.
        let mut crt0 = [0u8; 1024];
        let handle = match self.crt0setup(&mut crt0[..]) {
            Err(OutOfSpace) => std::process::exit(1),
            Ok(handle) => handle,
        };

        eprintln!(
            "enter1: {:016x} {:016x}",
            &*handle as *const _ as usize, self.entry
        );

        unsafe {
            asm!(
                "mov rsp, {SP}",
                "jmp {START}",
                SP = in(reg) &*handle,
                START = in(reg) self.entry,
                options(noreturn)
            )
        }
    }
}
