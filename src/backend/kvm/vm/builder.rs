// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::binary::{Component, PT_ENARX_CODE, PT_ENARX_SALLYPORT};

use personality::Personality;

use anyhow::Result;
use kvm_ioctls::{Kvm, VmFd};
use lset::Span;
use mmarinus::{perms, Kind, Map};
use openssl::hash::Hasher;
use x86_64::{align_up, VirtAddr};

use goblin::elf::program_header::PT_LOAD;
use sallyport::Block;
use std::mem::size_of;

pub trait Hook {
    fn preferred_digest() -> measure::Kind {
        measure::Kind::Null
    }

    fn shim_loaded(
        &mut self,
        _vm: &mut VmFd,
        _addr_space: &mut [u8],
        _shim: &Component,
    ) -> Result<()> {
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
}

pub struct Builder<'a, T: Hook> {
    hook: T,
    shim: Component<'a>,
    code: Component<'a>,
}

pub struct Built<P: Personality, T: Hook> {
    hook: T,
    vm: Vm<P>,
}

impl<'a, T: Hook> Builder<'a, T> {
    pub fn new(shim: Component<'a>, code: Component<'a>, hook: T) -> Self {
        Self { hook, shim, code }
    }

    fn load_component(&self, start: VirtAddr, component: &Component) {
        use std::slice::from_raw_parts_mut;

        for seg in component.filter_header(PT_LOAD) {
            let dst = start + seg.p_paddr as u64;
            let dst = unsafe { from_raw_parts_mut(dst.as_mut_ptr::<u8>(), seg.p_memsz as _) };
            dst[0..(seg.p_filesz as usize)].copy_from_slice(
                &component.bytes[(seg.p_offset as usize)..((seg.p_offset + seg.p_filesz) as usize)],
            );
        }
    }

    pub fn build<P: Personality>(mut self) -> Result<Built<P, T>> {
        let kvm = Kvm::new()?;
        let mut fd = kvm.create_vm()?;

        let mem_size = align_up(
            (Span::from(self.shim.region()).count) as _,
            size_of::<Page>() as _,
        ) as usize
            + align_up(
                (Span::from(self.code.region()).count) as _,
                size_of::<Page>() as _,
            ) as usize;

        let shim_start = self.shim.region().start;

        let (mut map, region) = Self::allocate_address_space(shim_start as _, mem_size as _)?;

        unsafe { fd.set_user_memory_region(region)? };

        let sallyport_range = Span::from(
            self.shim
                .find_header(PT_ENARX_SALLYPORT)
                .ok_or_else(|| {
                    anyhow::anyhow!("Couldn't find SALLYPORT program header in shim executable.")
                })?
                .vm_range(),
        );

        let code_range = Span::from(
            self.shim
                .find_header(PT_ENARX_CODE)
                .ok_or_else(|| {
                    anyhow::anyhow!("Couldn't find CODE program header in shim executable.")
                })?
                .vm_range(),
        );

        self.load_component(VirtAddr::new(map.addr() as _) - shim_start, &self.shim);
        self.hook.shim_loaded(&mut fd, map.as_mut(), &self.shim)?;

        self.load_component(
            VirtAddr::new(map.addr() as _) - shim_start + code_range.start,
            &self.code,
        );

        let syscall_blocks = Span {
            start: VirtAddr::new(sallyport_range.start as _) - shim_start + map.addr(),
            count: NonZeroUsize::new(sallyport_range.count / size_of::<Block>()).unwrap(),
        };

        let mut cpus = VecDeque::new();
        cpus.push_back(0);

        let vm = Vm {
            kvm,
            fd,
            regions: vec![Region::new(region, map)],
            syscall_blocks,
            _personality: PhantomData,
            cpus,

            #[cfg(target_arch = "x86_64")]
            rip: PhysAddr::new(self.shim.elf.entry as _),

            #[cfg(target_arch = "x86_64")]
            cr3: PhysAddr::new(
                self.shim
                    .find_header(crate::binary::PT_ENARX_PML4)
                    .unwrap()
                    .vm_range()
                    .start as _,
            ),
        };

        Ok(Built {
            vm,
            hook: self.hook,
        })
    }

    fn allocate_address_space(
        guest_phys_addr: u64,
        mem_size: usize,
    ) -> Result<(Map<perms::ReadWrite>, KvmUserspaceMemoryRegion)> {
        let map = Map::map(mem_size)
            .anywhere()
            .anonymously()
            .known::<perms::ReadWrite>(Kind::Private)?;

        let region = KvmUserspaceMemoryRegion {
            slot: 0,
            flags: 0,
            guest_phys_addr,
            memory_size: mem_size as _,
            userspace_addr: map.addr() as _,
        };

        let res = (map, region);

        Ok(res)
    }
}

impl<P: Personality, T: Hook> Built<P, T> {
    pub fn measurement(&mut self) -> Result<measure::Measurement> {
        let mut hasher = Hasher::new(T::preferred_digest().into())?;
        let address_space = self.vm.regions[0].backing();

        hasher.update(address_space)?;
        let digest_bytes = hasher.finish()?;

        Ok(measure::Measurement {
            kind: T::preferred_digest(),
            digest: digest_bytes,
        })
    }

    pub fn vm(mut self) -> Result<Vm<P>> {
        self.hook.code_loaded(
            &mut self.vm.fd,
            self.vm.regions[0].backing(),
            self.vm.syscall_blocks.start,
        )?;

        Ok(self.vm)
    }
}
