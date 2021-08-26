// SPDX-License-Identifier: Apache-2.0

use super::Vm;

use crate::backend::{Command, Thread};
use sallyport::syscall::enarx::MemInfo;
use sallyport::syscall::{SYS_ENARX_BALLOON_MEMORY, SYS_ENARX_MEM_INFO};
use sallyport::KVM_SYSCALL_TRIGGER_PORT;

use super::personality::Personality;

use anyhow::{anyhow, Result};
use kvm_ioctls::{VcpuExit, VcpuFd};
use primordial::{Address, Register};
use sallyport::{Block, Reply};

use std::sync::{Arc, RwLock};

pub struct Cpu<P: Personality> {
    fd: VcpuFd,
    keep: Arc<RwLock<Vm<P>>>,
}

impl<P: Personality> Cpu<P> {
    pub fn new(fd: VcpuFd, keep: Arc<RwLock<Vm<P>>>) -> Result<Self> {
        Ok(Self { fd, keep })
    }
}

impl<P: Personality> Thread for Cpu<P> {
    fn enter(&mut self) -> Result<Command> {
        match self.fd.run()? {
            VcpuExit::IoOut(port, data) => match port {
                KVM_SYSCALL_TRIGGER_PORT => {
                    let mut keep = self.keep.write().unwrap();

                    debug_assert_eq!(data.len(), 2);
                    let block_nr = data[0] as usize + ((data[1] as usize) << 8);

                    let sallyport: &mut Block = unsafe {
                        std::slice::from_raw_parts_mut(
                            keep.syscall_blocks.start.as_mut_ptr(),
                            keep.syscall_blocks.count.get(),
                        )
                        .get_mut(block_nr)
                        .unwrap()
                    };

                    let syscall_nr: i64 = unsafe { sallyport.msg.req.num.into() };

                    match syscall_nr {
                        0..=512 => Ok(Command::SysCall(sallyport)),

                        SYS_ENARX_BALLOON_MEMORY => {
                            let pages = unsafe { sallyport.msg.req.arg[0].into() };

                            let result = keep.add_memory(pages).map(|addr| {
                                let ok_result: [Register<usize>; 2] = [addr.into(), 0.into()];
                                ok_result
                            })?;

                            sallyport.msg.rep = Reply::from(Ok(result));
                            Ok(Command::Continue)
                        }

                        SYS_ENARX_MEM_INFO => {
                            let mem_slots = keep.kvm.get_nr_memslots();
                            let virt_start = Address::from(
                                keep.regions.first().unwrap().as_virt().start.as_ptr(),
                            );
                            let mem_info: MemInfo = MemInfo {
                                virt_start,
                                mem_slots,
                            };

                            let c = sallyport.cursor();
                            c.write(&mem_info)
                                .map_err(|_| anyhow!("Failed to allocate MemInfo in Block"))?;

                            let ok_result: [Register<usize>; 2] = [0.into(), 0.into()];

                            sallyport.msg.rep = Reply::from(Ok(ok_result));

                            Ok(Command::Continue)
                        }

                        x => Err(anyhow!("syscall {} not implemented", x)),
                    }
                }
                _ => Err(anyhow!("data from unexpected port: {}", port)),
            },
            exit_reason => {
                if cfg!(debug_assertions) {
                    Err(anyhow!(
                        "{:?} {:#x?} {:#x?}",
                        exit_reason,
                        self.fd.get_regs(),
                        self.fd.get_sregs()
                    ))
                } else {
                    Err(anyhow!("{:?}", exit_reason))
                }
            }
        }
    }
}
