use std::io::Result;

use goblin::{elf, elf::program_header::PT_LOAD};

use crate::access::Access;
use crate::drivers::Loader;
use crate::span::Span;

pub struct Binary<'a>(&'a [u8], elf::Elf<'a>);

impl<'a> Binary<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        use elf::header::*;

        let elf = match goblin::Object::parse(&bytes).unwrap() {
            goblin::Object::Elf(elf) => elf,
            o => panic!("Unsupported object type: {:?}", o),
        };

        // Validate identity assumptions.
        assert_eq!(elf.header.e_ident[EI_CLASS], ELFCLASS64);
        assert_eq!(elf.header.e_ident[EI_DATA], ELFDATA2LSB);
        assert_eq!(elf.header.e_ident[EI_VERSION], EV_CURRENT);
        //assert_eq!(elf.header.e_ident[EI_OSABI], ELFOSABI_NONE);
        //assert_eq!(elf.header.e_ident[EI_ABIVERSION], 0);

        // Validate header assumptions.
        assert_eq!(elf.header.e_type, ET_EXEC);
        assert_eq!(elf.header.e_machine, EM_X86_64);
        assert_eq!(elf.header.e_version, EV_CURRENT as _);

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

        Ok(Self(bytes, elf))
    }

    pub fn load<T>(&self, mut loader: Box<dyn Loader<T>>) -> Result<T> {
        for ph in &self.1.program_headers {
            if ph.p_type != PT_LOAD {
                continue;
            }

            loader.load(
                &self.0[ph.p_offset as usize..][..ph.p_filesz as usize],
                Span {
                    start: ph.p_vaddr,
                    count: ph.p_memsz,
                },
                Access::from_bits_truncate(ph.p_flags as u8),
            )?;
        }

        loader.done(self.1.header.e_entry)
    }
}
