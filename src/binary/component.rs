// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use goblin::elf::{header::*, program_header::*, Elf};

use lset::Line;
use mmarinus::{perms, Kind};
use primordial::Page;
use sallyport::SALLYPORT_ABI_VERSION_BASE;

use std::cmp::{max, min};
use std::path::Path;

use super::Segment;

#[allow(dead_code)]
pub enum ComponentType {
    Shim,
    Payload,
}

impl ComponentType {
    /// Loads a binary from a file
    #[allow(dead_code)]
    pub fn into_component_from_path(self, path: impl AsRef<Path>) -> Result<Component> {
        Component::from_path(path, self)
    }

    /// Loads a binary from bytes
    #[allow(dead_code)]
    pub fn into_component_from_bytes(self, bytes: impl AsRef<[u8]>) -> Result<Component> {
        Component::from_bytes(bytes, self)
    }
}

pub struct Component {
    pub segments: Vec<Segment>,
    pub entry: usize,
    pub pie: bool,
}

impl Component {
    /// Loads a binary from a file
    fn from_path(path: impl AsRef<Path>, component_type: ComponentType) -> Result<Self> {
        let map = Kind::Private.load::<perms::Read, _>(path)?;
        Self::from_bytes(map, component_type)
    }

    /// Loads a binary from bytes
    fn from_bytes(bytes: impl AsRef<[u8]>, component_type: ComponentType) -> Result<Self> {
        // Parse the file.
        let elf = Elf::parse(bytes.as_ref()).unwrap();

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

        let mut segments = Vec::new();
        for ph in elf.program_headers.iter() {
            if let Some(seg) = Segment::from_ph(&bytes, ph)? {
                segments.push(seg);
            }
        }

        // Validate that for pie binaries the first segment starts at 0.
        assert_eq!(pie, segments[0].dst == 0);

        Ok(Self {
            entry: elf.entry as _,
            segments,
            pie,
        })
    }

    /// Find the total memory region for the binary.
    #[allow(dead_code)]
    pub fn region(&self) -> Line<usize> {
        self.segments
            .iter()
            .map(|x| Line {
                start: x.dst,
                end: x.dst + x.src.len() * Page::size(),
            })
            .fold(usize::max_value()..usize::min_value(), |l, r| {
                min(l.start, r.start)..max(l.end, r.end)
            })
            .into()
    }
}
