// SPDX-License-Identifier: Apache-2.0

use sgx_types::page::Flags;

use goblin::elf::{header::*, program_header::*, Elf};
use memory::Page;
use span::Span;

use std::cmp::{max, min};
use std::io::Result;
use std::ops::Range;
use std::path::Path;

/// A loadable segment of code
pub struct Segment {
    pub src: Vec<Page>,
    pub dst: Span<usize, usize>,
    pub rwx: Flags,
}

impl<'a> Segment {
    /// Creates a segment from a `ProgramHeader`.
    fn from_ph(file: &[u8], ph: &ProgramHeader) -> Result<Option<Self>> {
        if ph.p_type != PT_LOAD {
            return Ok(None);
        }

        let mut rwx = Flags::empty();

        if ph.p_flags & PF_R != 0 {
            rwx |= Flags::R;
        }

        if ph.p_flags & PF_W != 0 {
            rwx |= Flags::W;
        }

        if ph.p_flags & PF_X != 0 {
            rwx |= Flags::X;
        }

        let src = Span {
            start: ph.p_offset as usize,
            count: ph.p_filesz as usize,
        };

        let unaligned = Range::from(Span {
            start: ph.p_vaddr as usize,
            count: ph.p_memsz as usize,
        });

        let frame = Range {
            start: unaligned.start / Page::size(),
            end: (unaligned.end + Page::size() - 1) / Page::size(),
        };

        let aligned = Range {
            start: frame.start * Page::size(),
            end: frame.end * Page::size(),
        };

        let subslice = Span::from(Range {
            start: unaligned.start - aligned.start,
            end: unaligned.end - aligned.start,
        });

        let subslice = Range::from(Span {
            start: subslice.start,
            count: min(subslice.count, src.count),
        });

        let src = &file[Range::from(src)];
        let mut buf = vec![Page::default(); Span::from(frame).count];
        unsafe { buf.align_to_mut() }.1[subslice].copy_from_slice(src);

        Ok(Some(Self {
            rwx,
            dst: aligned.into(),
            src: buf,
        }))
    }
}

/// A collection of code segments and the entry point
pub struct Component {
    pub segments: Vec<Segment>,
    pub entry: usize,
    pub pie: bool,
}

impl<'a> Component {
    /// Loads a binary from a file
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read(path)?;

        // Parse the file.
        let elf = Elf::parse(data.as_ref()).unwrap();

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

        let mut segments = Vec::new();
        for ph in elf.program_headers.iter() {
            if let Some(seg) = Segment::from_ph(&data, ph)? {
                segments.push(seg);
            }
        }

        // Validate that for pie binaries the first segment starts at 0.
        assert_eq!(pie, segments[0].dst.start == 0);

        Ok(Self {
            entry: elf.entry as _,
            segments,
            pie,
        })
    }

    /// Find the bottom and top of the binary segments.
    pub fn range(&self) -> Range<usize> {
        self.segments.iter().map(|x| Range::from(x.dst)).fold(
            Range {
                start: usize::max_value(),
                end: usize::min_value(),
            },
            |l, r| Range {
                start: min(l.start, r.start),
                end: max(l.end, r.end),
            },
        )
    }
}
