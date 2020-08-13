// SPDX-License-Identifier: Apache-2.0

//! Types for describing segment data loaded from a program header.

use anyhow::Result;
use bounds::{Line, Span};
use goblin::elf::program_header::*;
use memory::Page;

use std::cmp::min;
use std::ops::Range;

use super::Permissions;

/// A loadable segment of code
pub struct Segment {
    pub src: Vec<Page>,
    pub dst: usize,
    pub perms: Permissions,
}

impl Segment {
    /// Creates a segment from a `ProgramHeader`.
    pub fn from_ph(file: &[u8], ph: &ProgramHeader) -> Result<Option<Self>> {
        if ph.p_type != PT_LOAD {
            return Ok(None);
        }

        let perms = Permissions {
            read: ph.is_read(),
            write: ph.is_write(),
            execute: ph.is_executable(),
        };

        let src = Span {
            start: ph.p_offset as usize,
            count: ph.p_filesz as usize,
        };

        let unaligned = Line::from(Span {
            start: ph.p_vaddr as usize,
            count: ph.p_memsz as usize,
        });

        let frame = Line {
            start: unaligned.start / Page::size(),
            end: (unaligned.end + Page::size() - 1) / Page::size(),
        };

        let aligned = Line {
            start: frame.start * Page::size(),
            end: frame.end * Page::size(),
        };

        let subslice = Span::from(Line {
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
            perms,
            dst: aligned.start,
            src: buf,
        }))
    }
}
