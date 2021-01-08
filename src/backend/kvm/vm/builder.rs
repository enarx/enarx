// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::backend::kvm::shim::BootInfo;
use crate::binary::Component;
use crate::sallyport::Block;

use personality::Personality;

use anyhow::Result;
use kvm_ioctls::{Kvm, VmFd};
use lset::{Line, Span};
use mmarinus::{perms, Kind, Map};
use openssl::hash::Hasher;
use x86_64::{align_up, PhysAddr, VirtAddr};

use std::mem::size_of;

fn num_syscall_blocks<A: image::Arch>() -> usize {
    (MAX_SETUP_SIZE - size_of::<A>()) / size_of::<Block>()
}

/// A functor type that receives a target address as its first input,
/// a base/memory region starting address as its second input, and it
/// returns the guest physical address that corresponds to the target
/// address.
///
/// Implementors may choose to override this so that they can enable
/// certain bits in the resulting physical address (i.e., SEV memory
/// encryption).
pub type Hv2GpFn = dyn Fn(VirtAddr, VirtAddr) -> PhysAddr;

pub trait Hook {
    fn preferred_digest() -> measure::Kind {
        measure::Kind::Null
    }

    fn shim_loaded(&mut self, _vm: &mut VmFd, _addr_space: &[u8]) -> Result<()> {
        Ok(())
    }

    fn code_loaded(
        &mut self,
        _vm: &mut VmFd,
        _saddr_space: &[u8],
        _syscall_blocks: VirtAddr,
    ) -> Result<()> {
        Ok(())
    }

    fn hv2gp(&self) -> Box<Hv2GpFn> {
        Box::new(|target, start| PhysAddr::new(target.as_u64() - start.as_u64()))
    }
}

pub struct Builder<T: Hook> {
    hook: T,
    shim: Component,
    code: Component,
}

pub struct Built<A: image::Arch, P: Personality> {
    vm: Vm<A, P>,
    msr: measure::Measurement,
}

impl<T: Hook> Builder<T> {
    pub fn new(shim: Component, code: Component, hook: T) -> Self {
        Self { shim, code, hook }
    }

    pub fn build<A: image::Arch, P: Personality>(mut self) -> Result<Built<A, P>> {
        let kvm = Kvm::new()?;
        let mut fd = kvm.create_vm()?;

        let mut boot_info = Self::calculate_setup_region::<A>(
            self.shim.region().into(),
            self.code.region().into(),
        )?;

        let mem_size = align_up(boot_info.mem_size as _, size_of::<Page>() as _);
        // fill out remaining fields of `BootInfo`
        boot_info.nr_syscall_blocks = num_syscall_blocks::<A>();
        boot_info.mem_size = mem_size as _;

        let (map, region) = Self::allocate_address_space(mem_size as _)?;
        unsafe { fd.set_user_memory_region(region)? };

        let initial_state = unsafe { &mut *(map.addr() as *mut () as *mut image::Image<A>) };

        let components = &mut [
            (&mut self.shim, boot_info.shim.start),
            (&mut self.code, boot_info.code.start),
        ];
        initial_state.commit(&map, &boot_info, &self.hook, components);

        let shim_start = boot_info.shim.start;
        let shim_entry = PhysAddr::new(self.shim.entry as _);
        self.hook.shim_loaded(&mut fd, &map)?;

        let msr = {
            let mut hasher = Hasher::new(T::preferred_digest().into())?;
            let address_space =
                unsafe { std::slice::from_raw_parts(map.addr() as *const u8, map.size()) };
            hasher.update(address_space)?;
            let digest_bytes = hasher.finish()?;

            measure::Measurement {
                kind: T::preferred_digest(),
                digest: digest_bytes,
            }
        };

        // Be sure to perform any measurements before this hook is called! At
        // least in the case of SEV, the address space will be encrypted during
        // that hook, which means you'll be taking a different measurement!
        self.hook
            .code_loaded(&mut fd, &map, initial_state.syscall_region_start())?;

        let arch = VirtAddr::from_ptr(&initial_state.arch as *const A);
        let syscall_blocks = Span {
            start: initial_state.syscall_region_start(),
            count: NonZeroUsize::new(boot_info.nr_syscall_blocks).unwrap(),
        };

        let vm = Vm {
            kvm,
            fd,
            regions: vec![Region::new(region, map)],
            syscall_blocks,
            hv2gp: self.hook.hv2gp(),
            shim_entry,
            shim_start: PhysAddr::new(shim_start as _),
            arch,
            _phantom: PhantomData,
            _personality: PhantomData,
        };

        Ok(Built { vm, msr })
    }

    fn calculate_setup_region<A: image::Arch>(
        shim_size: Span<usize>,
        code_size: Span<usize>,
    ) -> Result<BootInfo> {
        let setup_size = Line {
            start: 0,
            end: size_of::<image::Image<A>>() + num_syscall_blocks::<A>(),
        };

        let boot_info = BootInfo::calculate(setup_size, shim_size, code_size)
            .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;

        Ok(boot_info)
    }

    fn allocate_address_space(
        mem_size: usize,
    ) -> Result<(Map<perms::ReadWrite>, KvmUserspaceMemoryRegion)> {
        let map = Map::map(mem_size)
            .anywhere()
            .anonymously()
            .known::<perms::ReadWrite>(Kind::Private)?;

        let region = KvmUserspaceMemoryRegion {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: mem_size as _,
            userspace_addr: map.addr() as _,
        };

        let res = (map, region);

        Ok(res)
    }
}

impl<A: image::Arch, P: Personality> Built<A, P> {
    pub fn measurement(&self) -> measure::Measurement {
        self.msr
    }

    pub fn vm(self) -> Vm<A, P> {
        self.vm
    }
}
