// SPDX-License-Identifier: Apache-2.0

use super::super::Command;
use super::KeepPersonality;
#[cfg(feature = "gdb")]
use crate::backend::execute_gdb;
use crate::backend::kvm::builder::kvm_new_vcpu;
use crate::backend::parking::THREAD_PARK;
use crate::backend::Keep as _;

use std::io;
use std::iter;
use std::mem::size_of;
use std::ops::DerefMut;
use std::sync::{Arc, RwLock};

use anyhow::{bail, Context, Result};
use kvm_ioctls::{VcpuExit, VcpuFd};
use libc::{c_int, timespec};
use mmarinus::{perms, Map};
use sallyport::host::deref_aligned;
use sallyport::item::enarxcall::Payload;
use sallyport::item::{Block, Item};
use sallyport::libc::EAGAIN;
use sallyport::{item, KVM_SYSCALL_TRIGGER_EXIT_THREAD, KVM_SYSCALL_TRIGGER_PORT};
use tracing::{error, trace, trace_span};
use x86_64::PhysAddr;

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

impl<P: KeepPersonality> super::super::Keep for RwLock<super::Keep<P>> {
    fn spawn(self: Arc<Self>) -> Result<Option<Box<dyn super::super::Thread>>> {
        let mut this = self.write().unwrap();
        let cpu_opt = this.cpu_fds.pop();
        let thread = match cpu_opt {
            None => {
                let super::Keep {
                    kvm_fd,
                    vm_fd,
                    num_cpus: num_cpu,
                    ..
                } = this.deref_mut();
                let vcpu_fd = Some(kvm_new_vcpu(kvm_fd, vm_fd, *num_cpu)?);
                *num_cpu += 1;
                vcpu_fd.map(|vcpu_fd| {
                    Box::new(Thread {
                        keep: self.clone(),
                        vcpu_fd: Some(vcpu_fd),
                        #[cfg(feature = "gdb")]
                        gdb_fd: None,
                    }) as Box<dyn super::super::Thread>
                })
            }
            Some(vcpu_fd) => Some(Box::new(Thread {
                keep: self.clone(),
                vcpu_fd: Some(vcpu_fd),

                #[cfg(feature = "gdb")]
                gdb_fd: None,
            }) as Box<dyn super::super::Thread>),
        };
        Ok(thread)
    }
}

impl<P: KeepPersonality> Thread<P> {
    pub fn balloon(&mut self, log2: usize, npgs: usize, addr: usize) -> sallyport::Result<usize> {
        let size: usize = 1 << log2; // Page Size

        // Get the current page size
        let pgsz = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) } as usize;
        assert!(pgsz.is_power_of_two());

        // Check that the page size is supported and addr is aligned
        if size != pgsz || addr % size != 0 {
            return Err(libc::EINVAL);
        }

        // Allocate the new memory
        let pages = Map::bytes(size * npgs)
            .anywhere()
            .anonymously()
            .with(perms::ReadWrite)
            .map_err(|e| e.err.raw_os_error().unwrap_or(libc::ENOTSUP))?;

        let mut keep = self.keep.write().unwrap();

        // Map the memory into the VM
        let vaddr = keep
            .map(pages, addr)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::ENOTSUP))?
            .as_virt()
            .start;

        Ok(vaddr.as_u64() as _)
    }

    pub fn meminfo(&self) -> sallyport::Result<usize> {
        let keep = self.keep.read().unwrap();

        // The maximum number of memory slots possible for a virtual machine
        // minus the ones which were already used.
        Ok(keep.kvm_fd.get_nr_memslots() - keep.regions.len())
    }

    fn kvm_enarxcall<'a>(
        &mut self,
        enarxcall: &'a mut Payload,
        data: &'a mut [u8],
    ) -> Result<Option<Item<'a>>> {
        match enarxcall {
            item::Enarxcall {
                num: item::enarxcall::Number::MemInfo,
                ret,
                ..
            } => {
                *ret = match self.meminfo() {
                    Ok(n) => n,
                    Err(e) => -e as usize,
                };
                Ok(None)
            }

            item::Enarxcall {
                num: item::enarxcall::Number::BalloonMemory,
                argv: [log2, npgs, addr, ..],
                ret,
            } => {
                *ret = match self.balloon(*log2, *npgs, *addr) {
                    Ok(n) => n,
                    Err(e) => -e as usize,
                };
                Ok(None)
            }
            item::Enarxcall {
                num: item::enarxcall::Number::NewSallyport,
                argv: [addr, index, ..],
                ret,
                ..
            } => {
                // Register a new sallyport block
                let mut keep = self.keep.write().unwrap();
                let block_virt = keep
                    .virt_from_guest_phys(PhysAddr::new(*addr as _))
                    .unwrap();
                if keep.sallyports.len() < *index + 1 {
                    keep.sallyports.resize(*index + 1, None);
                }
                assert!(keep.sallyports[*index].is_none());
                keep.sallyports[*index].replace(block_virt);
                *ret = 0;
                Ok(None)
            }
            item::Enarxcall {
                num: item::enarxcall::Number::Spawn,
                ret,
                ..
            } => {
                // retry for a little time, there should be exiting threads in flight,
                // which can be reused.
                let thread: Option<_> = {
                    let mut i = 0;
                    loop {
                        if let Some(thread) = self.keep.clone().spawn()? {
                            break Some(thread);
                        } else {
                            i += 1;
                            if i < 10 {
                                std::thread::sleep(std::time::Duration::from_millis(50));
                                continue;
                            }
                            break None;
                        }
                    }
                };

                *ret = Self::spawn_thread(thread);

                Ok(None)
            }
            item::Enarxcall {
                num: item::enarxcall::Number::Park,
                argv: [val, timeout, ..],
                ret,
                ..
            } => {
                let timeout = if *timeout != sallyport::NULL {
                    Some(unsafe {
                        // Safety: `deref_aligned` gives us a pointer to an aligned `timespec` struct.
                        // We also know, that the resulting pointer is inside the allocated sallyport block, where `data`
                        // is a subslice of.
                        *deref_aligned::<timespec>(data, *timeout, 1)
                            .map_err(io::Error::from_raw_os_error)
                            .context("failed to dereference timespec in Park enarxcall")?
                    })
                } else {
                    None
                };

                *ret = THREAD_PARK
                    .park(*val as _, timeout.as_ref())
                    .map(|v| v as usize)
                    .unwrap_or_else(|e| -e as usize);

                Ok(None)
            }
            item::Enarxcall {
                num: item::enarxcall::Number::UnPark,
                ret,
                ..
            } => {
                THREAD_PARK.unpark();
                *ret = 0;
                Ok(None)
            }
            _ => return Ok(Some(Item::Enarxcall(enarxcall, data))),
        }
    }

    fn spawn_thread(thread: Option<Box<dyn super::super::Thread>>) -> usize {
        if let Some(mut thread) = thread {
            std::thread::spawn(move || {
                std::panic::catch_unwind(move || {
                    let ret = trace_span!(
                        "Thread",
                        id = ?std::thread::current().id()
                    )
                    .in_scope(|| loop {
                        match thread.enter(&None)? {
                            Command::Continue => (),
                            Command::Exit(exit_code) => {
                                return Ok::<i32, anyhow::Error>(exit_code);
                            }
                        }
                    });

                    if let Err(e) = ret {
                        error!("Thread failed: {e:#?}");
                        std::process::exit(1);
                    }
                    ret
                })
                .unwrap_or_else(|e| {
                    error!("Thread panicked: {e:#?}");
                    std::process::exit(1);
                })
            });
            0
        } else {
            error!("no more Keep threads available");
            -EAGAIN as usize
        }
    }
}

impl<P: KeepPersonality> super::super::Thread for Thread<P> {
    fn enter(&mut self, _gdblisten: &Option<String>) -> Result<Command> {
        let vcpu_fd = self.vcpu_fd.as_mut().unwrap();
        match vcpu_fd.run()? {
            VcpuExit::IoOut(port, data) if port == KVM_SYSCALL_TRIGGER_EXIT_THREAD => {
                let status = data[0] as c_int + ((data[1] as c_int) << 8);
                Ok(Command::Exit(status))
            }
            VcpuExit::IoOut(port, data) if port == KVM_SYSCALL_TRIGGER_PORT => {
                debug_assert_eq!(data.len(), 2);
                let block_nr = data[0] as usize + ((data[1] as usize) << 8);
                let block_virt = self.keep.write().unwrap().sallyports[block_nr]
                    .take()
                    .unwrap();

                // If some other thread tried to use the same block, the above unwrap would have panicked.
                let block: Block = unsafe {
                    std::slice::from_raw_parts_mut(
                        block_virt.as_mut_ptr::<usize>(),
                        self.keep.read().unwrap().sallyport_block_size / size_of::<usize>(),
                    )
                }
                .into();

                for item in block {
                    match item {
                        Item::Gdbcall(_gdbcall, _data) => {
                            #[cfg(feature = "gdb")]
                            unsafe {
                                execute_gdb(
                                    _gdbcall,
                                    _data,
                                    &mut self.gdb_fd,
                                    _gdblisten.as_ref().unwrap(),
                                )
                                .map_err(io::Error::from_raw_os_error)
                                .context("execute_gdb")?;
                            }
                        }

                        Item::Enarxcall(enarxcall, data) => {
                            if let Some(Item::Enarxcall(enarxcall, data)) =
                                self.kvm_enarxcall(enarxcall, data)?
                            {
                                let mut keep = self.keep.write().unwrap();
                                sallyport::host::execute(
                                    keep.personality.enarxcall(enarxcall, data)?.into_iter(),
                                )
                                .map_err(io::Error::from_raw_os_error)
                                .context("sallyport::host::execute")?;
                            }
                        }

                        // Catch exit_group for a clean shutdown
                        Item::Syscall(
                            item::Syscall {
                                num,
                                argv: [code, ..],
                                ..
                            },
                            ..,
                        ) if (*num == libc::SYS_exit_group as usize) => {
                            trace!("exit_group({code})");
                            std::process::exit(*code as _);
                        }

                        // Catch exit and exit_group for a clean shutdown
                        Item::Syscall(syscall, ..) if (syscall.num == libc::SYS_exit as usize) => {
                            trace!(?syscall);
                            panic!("unexpected exit syscall!");
                        }

                        Item::Syscall(ref _syscall, ..) => {
                            #[cfg(feature = "dbg")]
                            match (
                                _syscall.num as libc::c_long,
                                _syscall.argv[1] as libc::c_int,
                            ) {
                                (
                                    libc::SYS_write | libc::SYS_read,
                                    libc::STDIN_FILENO | libc::STDOUT_FILENO | libc::STDERR_FILENO,
                                ) => {}
                                _ => {
                                    trace!(?_syscall);
                                }
                            }

                            sallyport::host::execute(iter::once(item))
                                .map_err(io::Error::from_raw_os_error)
                                .context("sallyport::host::execute")?;
                        }
                    }
                }

                self.keep.write().unwrap().sallyports[block_nr].replace(block_virt);
                Ok(Command::Continue)
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
