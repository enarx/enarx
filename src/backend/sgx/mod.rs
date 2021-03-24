// SPDX-License-Identifier: Apache-2.0

use crate::backend::sgx::attestation::get_attestation;
use crate::backend::{Command, Datum, Keep};
use crate::binary::{Component, ComponentType};
use sallyport::syscall::{SYS_ENARX_CPUID, SYS_ENARX_ERESUME, SYS_ENARX_GETATT};

use anyhow::{anyhow, Result};
use lset::Span;
use primordial::Page;
use sgx::enclave::{Builder, Enclave, Entry, Registers, Segment};
use sgx::types::{
    page::{Flags, SecInfo},
    ssa::Exception,
    tcs::Tcs,
};

use std::arch::x86_64::__cpuid_count;
use std::convert::TryInto;
use std::path::Path;
use std::sync::{Arc, RwLock};

mod attestation;
mod data;
mod shim;

const SHIM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bin/shim-sgx"));

impl From<crate::binary::Segment> for Segment {
    #[inline]
    fn from(value: crate::binary::Segment) -> Self {
        let mut rwx = Flags::empty();

        if value.perms.read {
            rwx |= Flags::R;
        }
        if value.perms.write {
            rwx |= Flags::W;
        }
        if value.perms.execute {
            rwx |= Flags::X;
        }

        Self {
            si: SecInfo::reg(rwx),
            dst: value.dst,
            src: value.src,
        }
    }
}

pub struct Backend;

impl crate::backend::Backend for Backend {
    fn name(&self) -> &'static str {
        "sgx"
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
    fn build(&self, mut code: Component, _sock: Option<&Path>) -> Result<Arc<dyn Keep>> {
        let mut shim = ComponentType::Shim.into_component_from_bytes(SHIM)?;

        // Calculate the memory layout for the enclave.
        let layout = crate::backend::sgx::shim::Layout::calculate(shim.region(), code.region());

        // Relocate the shim binary.
        shim.entry += layout.shim.start;
        for seg in shim.segments.iter_mut() {
            seg.dst += layout.shim.start;
        }

        // Relocate the code binary.
        code.entry += layout.code.start;
        for seg in code.segments.iter_mut() {
            seg.dst += layout.code.start;
        }

        // Create SSAs and TCS.
        let ssas = vec![Page::default(); 2];
        let tcs = Tcs::new(
            shim.entry - layout.enclave.start,
            Page::size() * 2, // SSAs after Layout (see below)
            ssas.len() as _,
        );

        let internal = vec![
            // TCS
            Segment {
                si: SecInfo::tcs(),
                dst: layout.prefix.start,
                src: vec![Page::copy(tcs)],
            },
            // Layout
            Segment {
                si: SecInfo::reg(Flags::R),
                dst: layout.prefix.start + Page::size(),
                src: vec![Page::copy(layout)],
            },
            // SSAs
            Segment {
                si: SecInfo::reg(Flags::R | Flags::W),
                dst: layout.prefix.start + Page::size() * 2,
                src: ssas,
            },
            // Heap
            Segment {
                si: SecInfo::reg(Flags::R | Flags::W | Flags::X),
                dst: layout.heap.start,
                src: vec![Page::default(); Span::from(layout.heap).count / Page::size()],
            },
            // Stack
            Segment {
                si: SecInfo::reg(Flags::R | Flags::W),
                dst: layout.stack.start,
                src: vec![Page::default(); Span::from(layout.stack).count / Page::size()],
            },
        ];

        let shim_segs: Vec<_> = shim.segments.into_iter().map(Segment::from).collect();
        let code_segs: Vec<_> = code.segments.into_iter().map(Segment::from).collect();

        // Initiate the enclave building process.
        let mut builder = Builder::new(layout.enclave).expect("Unable to create builder");
        builder.load(&internal)?;
        builder.load(&shim_segs)?;
        builder.load(&code_segs)?;
        Ok(builder.build()?)
    }

    fn measure(&self, mut _code: Component) -> Result<String> {
        unimplemented!()
    }
}

impl super::Keep for RwLock<Enclave> {
    fn add_thread(self: Arc<Self>) -> Result<Box<dyn crate::backend::Thread>> {
        Ok(Box::new(Thread {
            thread: sgx::enclave::Thread::new(self).ok_or_else(|| anyhow!("out of threads"))?,
            block: Default::default(),
        }))
    }
}

struct Thread {
    thread: sgx::enclave::Thread,
    block: sallyport::Block,
}

impl super::Thread for Thread {
    fn enter(&mut self) -> Result<Command> {
        let mut registers = Registers::default();
        let mut how = Entry::Enter;

        // The main loop event handles different types of enclave exits and
        // re-enters the enclave with specific parameters.
        //
        //   1. Asynchronous exits (AEX) with an invalid opcode indicate
        //      that a syscall should be performed. Execution continues in
        //      the enclave with EENTER[CSSA = 1]. The syscall
        //      is proxied and potentially passed back out to the host.
        //
        //   2. OK with a syscall number other than SYS_ERESUME indicates the syscall
        //      to be performed. The syscall is performed here and enclave
        //      execution resumes with EENTER[CSSA = 1].
        //
        //   3. OK with a syscall number of SYS_ERESUME indicates that a syscall has
        //      been performed as well as handled internally in the enclave
        //      and normal enclave execution should resume
        //      with ERESUME[CSSA = 0].
        //
        //   4. Asynchronous exits other than invalid opcode will panic.
        loop {
            registers.rdx = (&mut self.block).into();
            how = match self.thread.enter(how, &mut registers) {
                Err(ei) if ei.trap == Exception::InvalidOpcode => Entry::Enter,
                Ok(_) => match unsafe { self.block.msg.req }.num.into() {
                    SYS_ENARX_CPUID => unsafe {
                        let cpuid = core::arch::x86_64::__cpuid_count(
                            self.block.msg.req.arg[0].try_into().unwrap(),
                            self.block.msg.req.arg[1].try_into().unwrap(),
                        );

                        self.block.msg.req.arg[0] = cpuid.eax.into();
                        self.block.msg.req.arg[1] = cpuid.ebx.into();
                        self.block.msg.req.arg[2] = cpuid.ecx.into();
                        self.block.msg.req.arg[3] = cpuid.edx.into();

                        Entry::Enter
                    },
                    SYS_ENARX_GETATT => {
                        let result = unsafe {
                            get_attestation(
                                self.block.msg.req.arg[0].into(),
                                self.block.msg.req.arg[1].into(),
                                self.block.msg.req.arg[2].into(),
                                self.block.msg.req.arg[3].into(),
                            )?
                        };

                        self.block.msg.rep = Ok([result.into(), 0.into()]).into();

                        Entry::Enter
                    }
                    SYS_ENARX_ERESUME => Entry::Resume,
                    _ => return Ok(Command::SysCall(&mut self.block)),
                },
                e => panic!("Unexpected AEX: {:?}", e),
            }
        }
    }
}
