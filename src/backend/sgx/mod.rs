// SPDX-License-Identifier: Apache-2.0

mod enclave;

use crate::backend::sgx::attestation::get_attestation;
use crate::backend::{Command, Datum, Keep};
use crate::binary::*;
use enclave::{Builder, Enclave, Entry, Registers, Vector};

use anyhow::Result;
use goblin::elf::program_header::*;
use lset::{Line, Span};
use primordial::{Page, Pages};
use sallyport::syscall::{SYS_ENARX_CPUID, SYS_ENARX_GETATT};
use sallyport::{elf, Block};
use sgx::crypto::openssl::{RS256PrivateKey, S256Digest};
use sgx::crypto::PrivateKey;
use sgx::page::{Class, Flags, SecInfo};
use sgx::parameters::{Masked, Parameters};
use sgx::signature::{Author, Hasher, Signature};

use std::arch::x86_64::__cpuid_count;
use std::convert::TryInto;
use std::fmt::Debug;
use std::num::NonZeroU32;
use std::sync::Arc;

mod attestation;
mod data;

struct Segment {
    fline: Line<usize>,
    mline: Line<usize>,
    pages: Pages<Vec<Page>>,
    vaddr: usize,
    sinfo: SecInfo,
    phash: bool,
}

impl Debug for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let letter = |b, c| if b { c } else { ' ' };

        f.write_fmt(format_args!(
            "Segment({:08x}:{:08x} => {:08x}:{:08x} => {:08x}:{:08x} {}{}{}{}{})",
            self.fline.start,
            self.fline.end,
            self.mline.start,
            self.mline.end,
            self.vaddr,
            self.vaddr + self.pages.len() * Page::SIZE,
            letter(self.sinfo.flags().contains(Flags::READ), 'r'),
            letter(self.sinfo.flags().contains(Flags::WRITE), 'w'),
            letter(self.sinfo.flags().contains(Flags::EXECUTE), 'x'),
            letter(self.sinfo.class() == Class::Tcs, 't'),
            letter(self.phash, 'm'),
        ))
    }
}

impl Segment {
    pub fn new(component: &Component, phdr: &ProgramHeader, relocate: usize) -> Self {
        assert_eq!(relocate % Page::SIZE, 0);

        let fline = Line::from(phdr.file_range());
        let mline = Line::from(phdr.vm_range()) >> relocate;
        let vaddr = mline.start / Page::SIZE * Page::SIZE;

        let mspan = Span::from(mline);
        let bytes = &component.bytes[phdr.file_range()];
        let pages = Pages::copy_into(bytes, mspan.count, mline.start % Page::SIZE);

        let mut rwx = Flags::empty();
        if phdr.p_flags & PF_R != 0 {
            rwx |= Flags::READ;
        }
        if phdr.p_flags & PF_W != 0 {
            rwx |= Flags::WRITE;
        }
        if phdr.p_flags & PF_X != 0 {
            rwx |= Flags::EXECUTE;
        }

        Self {
            fline,
            mline,
            pages,
            vaddr,
            sinfo: match phdr.p_flags & elf::pf::sgx::TCS {
                0 => SecInfo::reg(rwx),
                _ => SecInfo::tcs(),
            },
            phash: phdr.p_flags & elf::pf::sgx::UNMEASURED == 0,
        }
    }
}

pub struct Backend;

impl crate::backend::Backend for Backend {
    fn name(&self) -> &'static str {
        "sgx"
    }

    fn shim(&self) -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/bin/shim-sgx"))
    }

    fn have(&self) -> bool {
        data::dev_sgx_enclave().pass
    }

    fn data(&self) -> Vec<Datum> {
        let mut data = vec![data::dev_sgx_enclave()];

        data.extend(data::CPUIDS.iter().map(|c| c.into()));

        let max = unsafe { __cpuid_count(0x00000000, 0x00000000) }.eax;
        data.push(data::epc_size(max));

        data
    }

    /// Create a keep instance on this backend
    fn build(&self, shim: Component, code: Component) -> Result<Arc<dyn Keep>> {
        // Find the offset for loading the code.
        let slot = Span::from(shim.find_header(elf::pt::EXEC).unwrap().vm_range());
        assert!(Span::from(code.region()).count <= slot.count);

        // Find the size of the enclave (in powers of two).
        let size: u8 = unsafe {
            shim.read_note(elf::note::NAME, elf::note::sgx::BITS)?
                .unwrap()
        };
        let size = 1 << size;

        // Find the number of pages in an SSA frame.
        let ssap: u8 = unsafe {
            shim.read_note(elf::note::NAME, elf::note::sgx::SSAP)?
                .unwrap()
        };
        let ssap = NonZeroU32::new(ssap.into()).unwrap();

        // Find the enclave parameters.
        let params: Parameters = unsafe {
            Parameters {
                misc: Masked {
                    data: shim
                        .read_note(elf::note::NAME, elf::note::sgx::MISC)?
                        .unwrap(),
                    mask: shim
                        .read_note(elf::note::NAME, elf::note::sgx::MISCMASK)?
                        .unwrap(),
                },
                attr: Masked {
                    data: shim
                        .read_note(elf::note::NAME, elf::note::sgx::ATTR)?
                        .unwrap(),
                    mask: shim
                        .read_note(elf::note::NAME, elf::note::sgx::ATTRMASK)?
                        .unwrap(),
                },
                pid: shim
                    .read_note(elf::note::NAME, elf::note::sgx::PID)?
                    .unwrap(),
                svn: shim
                    .read_note(elf::note::NAME, elf::note::sgx::SVN)?
                    .unwrap(),
            }
        };

        // Get an array of all final segment (relative) locations.
        let ssegs = shim
            .filter_header(PT_LOAD)
            .map(|phdr| Segment::new(&shim, phdr, 0));
        let csegs = code
            .filter_header(PT_LOAD)
            .map(|phdr| Segment::new(&code, phdr, slot.start));
        let mut segs: Vec<_> = ssegs.chain(csegs).collect();

        // Ensure no segments overlap in memory.
        segs.sort_unstable_by_key(|x| x.vaddr);
        for pair in segs.windows(2) {
            let bytes: &[u8] = pair[0].pages.as_ref();
            assert!(pair[0].vaddr + bytes.len() <= pair[1].vaddr);
        }

        // Initialize the new enclave.
        let mut builder = Builder::new(size, ssap, params)?;
        let mut hasher = Hasher::<S256Digest>::new(size, ssap);

        // Map all the pages.
        for seg in segs {
            let bytes = seg.pages.as_ref();
            builder.load(bytes, seg.vaddr, seg.sinfo, seg.phash)?;
            hasher.load(bytes, seg.vaddr, seg.sinfo, seg.phash).unwrap();
        }

        // Create the enclave signature
        let hash = hasher.finish();
        let author = Author::new(0, 0);
        let body = params.body(hash);
        let key = RS256PrivateKey::generate(3)?;
        let signature = Signature::new(&key, author, body)?;

        // Build the enclave.
        Ok(builder.build(&signature)?)
    }
}

impl super::Keep for Enclave {
    fn spawn(self: Arc<Self>) -> Result<Option<Box<dyn crate::backend::Thread>>> {
        let thread = match self.spawn() {
            Some(thread) => thread,
            None => return Ok(None),
        };

        Ok(Some(Box::new(Thread {
            thread,
            registers: Registers::default(),
            block: Block::default(),
            cssa: usize::default(),
            how: Entry::Enter,
        })))
    }
}

struct Thread {
    thread: enclave::Thread,
    registers: Registers,
    block: Block,
    cssa: usize,
    how: Entry,
}

impl Thread {
    fn cpuid(&mut self) {
        unsafe {
            let cpuid = core::arch::x86_64::__cpuid_count(
                self.block.msg.req.arg[0].try_into().unwrap(),
                self.block.msg.req.arg[1].try_into().unwrap(),
            );

            self.block.msg.req.arg[0] = cpuid.eax.into();
            self.block.msg.req.arg[1] = cpuid.ebx.into();
            self.block.msg.req.arg[2] = cpuid.ecx.into();
            self.block.msg.req.arg[3] = cpuid.edx.into();
        }
    }

    fn attest(&mut self) -> Result<()> {
        let result = unsafe {
            get_attestation(
                self.block.msg.req.arg[0].into(),
                self.block.msg.req.arg[1].into(),
                self.block.msg.req.arg[2].into(),
                self.block.msg.req.arg[3].into(),
            )?
        };

        self.block.msg.rep = Ok([result.into(), 0.into()]).into();
        Ok(())
    }
}

impl super::Thread for Thread {
    fn enter(&mut self) -> Result<Command> {
        let prev = self.how;
        self.registers.rdi = (&mut self.block).into();

        self.how = match self.thread.enter(prev, &mut self.registers) {
            Err(ei) if ei.trap == Vector::InvalidOpcode => Entry::Enter,
            Ok(_) => Entry::Resume,
            e => panic!("Unexpected AEX: {:?}", e),
        };

        // Keep track of the CSSA
        match self.how {
            Entry::Enter => self.cssa += 1,
            Entry::Resume => match self.cssa {
                0 => unreachable!(),
                _ => self.cssa -= 1,
            },
        }

        // If we have handled an InvalidOpcode error, evaluate the sallyport.
        if let (Entry::Enter, Entry::Resume) = (prev, self.how) {
            match unsafe { self.block.msg.req }.num.into() {
                SYS_ENARX_CPUID => self.cpuid(),
                SYS_ENARX_GETATT => self.attest()?,
                _ => return Ok(Command::SysCall(&mut self.block)),
            }
        }

        Ok(Command::Continue)
    }
}
