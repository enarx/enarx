// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use goblin::elf::{header::*, program_header::*, Elf};

use lset::Line;
use sallyport::SALLYPORT_ABI_VERSION_BASE;

use std::cmp::{max, min};

#[allow(dead_code)]
pub enum ComponentType {
    Shim,
    Payload,
}

/// The sallyport program header type
#[cfg(any(feature = "backend-sev", feature = "backend-kvm"))]
pub const PT_ENARX_SALLYPORT: u32 = PT_LOOS + 0x34a0001;
/// The enarx code program header type
#[cfg(any(feature = "backend-sev", feature = "backend-kvm"))]
pub const PT_ENARX_CODE: u32 = PT_LOOS + 0x34a0003;

pub struct Component<'a> {
    pub bytes: &'a [u8],
    pub elf: Elf<'a>,
    pub pie: bool,
    pub component_type: ComponentType,
}

impl<'a> Component<'a> {
    /// Loads a binary from bytes
    pub fn from_bytes(
        bytes: &'a (impl AsRef<[u8]> + ?Sized),
        component_type: ComponentType,
    ) -> Result<Self> {
        let bytes = bytes.as_ref();

        // Parse the file.
        let elf = Elf::parse(bytes).unwrap();

        // Validate identity assumptions.
        assert_eq!(elf.header.e_ident[EI_CLASS], ELFCLASS64);
        assert_eq!(elf.header.e_ident[EI_DATA], ELFDATA2LSB);
        assert_eq!(elf.header.e_ident[EI_VERSION], EV_CURRENT);

        // Validate header assumptions.
        assert_eq!(elf.header.e_machine, EM_X86_64);
        assert_eq!(elf.header.e_version, EV_CURRENT as _);
        let pie = match elf.header.e_type {
            ET_DYN => true,
            ET_EXEC => false,
            _ => panic!("Unsupported ELF type!"),
        };

        // Validate that there is no interpreter.
        assert!(!elf
            .program_headers
            .iter()
            .fold(false, |a, ph| a | (ph.p_type == PT_INTERP)));

        // Validate that the entry point is in one of the loaded sections.
        assert_eq!(
            1,
            elf.program_headers
                .iter()
                .filter(|ph| {
                    ph.p_type == PT_LOAD
                        && elf.header.e_entry >= ph.p_vaddr
                        && elf.header.e_entry < ph.p_vaddr + ph.p_memsz
                })
                .count()
        );

        if matches!(component_type, ComponentType::Shim) {
            // There shouldn't be any symbols in the shim, except this one.
            let strtab = elf.strtab.to_vec()?;
            let ver = strtab
                .iter()
                .find(|x| x.starts_with(SALLYPORT_ABI_VERSION_BASE))
                .ok_or_else(|| anyhow!("Couldn't find sallyport version in shim executable."))?;

            sallyport::check_abi_version(ver)
                .map_err(|_| anyhow!("Sallyport version mismatch in shim executable."))?;
        }

        let component = Self {
            bytes,
            elf,
            component_type,
            pie,
        };

        // Validate that for pie binaries the first segment starts at 0.
        assert_eq!(pie, component.find_header(PT_LOAD).unwrap().p_vaddr == 0);

        Ok(component)
    }

    pub fn filter_header(&self, type_: u32) -> impl Iterator<Item = &ProgramHeader> {
        self.elf
            .program_headers
            .iter()
            .filter(move |ph| ph.p_type == type_)
    }

    pub fn find_header(&self, type_: u32) -> Option<&ProgramHeader> {
        self.elf
            .program_headers
            .iter()
            .find(|ph| ph.p_type == type_)
    }

    /// Find the total memory region for the binary.
    #[allow(dead_code)]
    pub fn region(&self) -> Line<usize> {
        self.filter_header(PT_LOAD)
            .map(|x| Line::from(x.vm_range()))
            .fold(usize::max_value()..usize::min_value(), |l, r| {
                min(l.start, r.start)..max(l.end, r.end)
            })
            .into()
    }
}
