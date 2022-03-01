// SPDX-License-Identifier: Apache-2.0

use super::super::Command;
use super::KeepPersonality;

use std::sync::{Arc, RwLock};

use anyhow::{bail, Result};
use kvm_ioctls::{VcpuExit, VcpuFd};
use mmarinus::{perms, Kind, Map};
use primordial::{Address, Register};
use sallyport::syscall::enarx::MemInfo;
use sallyport::syscall::{SYS_ENARX_BALLOON_MEMORY, SYS_ENARX_MEM_INFO};
use sallyport::Block;
use sallyport::{Request, KVM_SYSCALL_TRIGGER_PORT};

pub struct Thread<P: KeepPersonality> {
    keep: Arc<RwLock<super::Keep<P>>>,
    vcpu_fd: Option<VcpuFd>,

    #[cfg(feature = "gdb")]
    gdb_fd: Option<std::net::TcpStream>,
}

impl<P: KeepPersonality> Drop for Thread<P> {
    fn drop(&mut self) {
        let vcpu_fd = self.vcpu_fd.take().unwrap();
        self.keep.write().unwrap().cpu_fds.push(vcpu_fd);
    }
}

impl<P: KeepPersonality + 'static> super::super::Keep for RwLock<super::Keep<P>> {
    fn spawn(self: Arc<Self>) -> Result<Option<Box<dyn super::super::Thread>>> {
        let cpu_opt = self.write().unwrap().cpu_fds.pop();
        match cpu_opt {
            None => Ok(None),
            Some(vcpu_fd) => Ok(Some(Box::new(Thread {
                keep: self,
                vcpu_fd: Some(vcpu_fd),

                #[cfg(feature = "gdb")]
                gdb_fd: None,
            }))),
        }
    }
}

impl<P: KeepPersonality> Thread<P> {
    pub fn balloon(&mut self, req: &Request) -> Result<[Register<usize>; 2], i32> {
        let log2: usize = req.arg[0].into();
        let npgs: usize = req.arg[1].into(); // Number of Pages
        let addr: usize = req.arg[2].into(); // Guest Physical Address
        let size: usize = 1 << log2; // Page Size

        // Get the current page size
        let pgsz = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) } as usize;
        assert!(pgsz.is_power_of_two());

        // Check that the page size is supported and addr is aligned
        if size != pgsz || addr % size != 0 {
            return Err(libc::EINVAL);
        }

        // Allocate the new memory
        let pages = Map::map(size * npgs)
            .anywhere()
            .anonymously()
            .known::<perms::ReadWrite>(Kind::Private)
            .map_err(|e| e.err.raw_os_error().unwrap_or(libc::ENOTSUP))?;

        let mut keep = self.keep.write().unwrap();

        // Map the memory into the VM
        let vaddr = keep
            .map(pages, addr)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::ENOTSUP))?
            .as_virt()
            .start;

        Ok([vaddr.as_u64().into(), 0.into()])
    }

    pub fn meminfo(&self, block: &mut Block) -> Result<[Register<usize>; 2], i32> {
        let keep = self.keep.read().unwrap();

        // The maximum number of memory slots possible for a virtual machine
        // minus the ones which were already used.
        let mem_slots = keep.kvm_fd.get_nr_memslots() - keep.regions.len();

        // FIXME:
        // Obsolete, if [host side syscall verification and address translation](https://github.com/enarx/enarx/issues/957)
        // is implemented.
        let virt_start = Address::from(keep.sallyport_start.as_mut_ptr());

        let mem_info: MemInfo = MemInfo {
            virt_start,
            mem_slots,
        };

        let c = block.cursor();
        c.write(&mem_info).map_err(|_| libc::ENOBUFS)?;

        Ok([0.into(), 0.into()])
    }
}

impl<P: KeepPersonality> super::super::Thread for Thread<P> {
    fn enter(&mut self) -> Result<Command<'_>> {
        let vcpu_fd = self.vcpu_fd.as_mut().unwrap();
        match vcpu_fd.run()? {
            VcpuExit::IoOut(KVM_SYSCALL_TRIGGER_PORT, data) => {
                debug_assert_eq!(data.len(), 2);
                let block_nr = data[0] as usize + ((data[1] as usize) << 8);

                let block_virt = self.keep.write().unwrap().sallyports[block_nr]
                    .take()
                    .unwrap();

                // If some other thread tried to use the same block, the above unwrap would have panicked.
                let block = unsafe { &mut *block_virt.as_mut_ptr::<Block>() };

                // To avoid clashing of rep and req in the union, clone the request
                let req = unsafe { block.msg.req };

                let ret = match i64::from(req.num) {
                    SYS_ENARX_BALLOON_MEMORY => {
                        let rep = self.balloon(&req).into();
                        block.msg.rep = rep;
                        Ok(Command::Continue)
                    }

                    SYS_ENARX_MEM_INFO => {
                        block.msg.rep = self.meminfo(block).into();
                        Ok(Command::Continue)
                    }

                    #[cfg(feature = "gdb")]
                    sallyport::syscall::SYS_ENARX_GDB_START
                    | sallyport::syscall::SYS_ENARX_GDB_PEEK
                    | sallyport::syscall::SYS_ENARX_GDB_READ
                    | sallyport::syscall::SYS_ENARX_GDB_WRITE => {
                        Ok(Command::Gdb(block, &mut self.gdb_fd))
                    }

                    _ => Ok(Command::SysCall(block)),
                };

                // In case of gdb, this is unsafe, but we know the block is not misused in the main loop
                self.keep.write().unwrap().sallyports[block_nr].replace(block_virt);
                ret
            }
            #[cfg(debug_assertions)]
            reason => bail!(
                "KVM error: {:?} {:#x?} {:#x?}",
                reason,
                vcpu_fd.get_regs(),
                vcpu_fd.get_sregs()
            ),

            #[cfg(not(debug_assertions))]
            reason => bail!("KVM error: {:?}", reason),
        }
    }
}
