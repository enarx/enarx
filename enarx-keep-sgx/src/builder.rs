// SPDX-License-Identifier: Apache-2.0

use super::{
    component::Component,
    convert::{f2p, p2f},
    Bounds,
};

use addr::Offset;
use enarx_keep::{Keep, Start};
use iocuddle_sgx as sgx;
use openssl::{bn, rsa};
use sgx_crypto::{Hasher, Signature as _};
use sgx_types::{
    page::{Class, Flags, SecInfo},
    secs::*,
    sig::*,
    ssa::StateSaveArea,
    tcs::Tcs,
};

use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::Result;
use std::mem::{size_of, size_of_val};
use std::num::NonZeroU32;

pub struct Builder {
    span: Bounds,
    file: File,
    mmap: mmap::Mapping,
    hash: Hasher,
    perm: Vec<(addr::Offset<usize>, usize, SecInfo)>,
}

impl Builder {
    const TCS_OFFSET: Offset<usize> = Offset::new(0);

    pub fn build(span: Bounds, shim: Component, code: Component) -> Result<Box<dyn Keep<Start>>> {
        let ssas = [StateSaveArea::default(), StateSaveArea::default()];
        let ssas_offs = span.count - Offset::from(size_of_val(&ssas));

        let tcs = Tcs::new(shim.entry - span.start, ssas_offs, ssas.len() as u32 - 1);

        // Validate assumptions.
        assert!(code.range().start > span.start + size_of::<Tcs>().into());
        assert!(shim.range().start > code.range().end);
        assert!(span.start + ssas_offs > shim.range().end);

        let mut builder = Self::new(span)?;

        // Load the TCS.
        builder.load(&tcs, Self::TCS_OFFSET, SecInfo::tcs())?;

        // Load the SSAs.
        for (i, ssa) in ssas.iter().enumerate() {
            let off = span.count - size_of_val(&ssas).into();
            let idx = i * size_of_val(ssa);
            builder.load(ssa, off + idx.into(), SecInfo::reg(Flags::R | Flags::W))?;
        }

        // Load the shim segments.
        for seg in shim.segments.iter() {
            let si = SecInfo::reg(p2f(seg.prt));
            builder.load(&seg.src, seg.dst.start - span.start, si)?;
        }

        // Load the code segments.
        for seg in code.segments.iter() {
            let si = SecInfo::reg(p2f(seg.prt));
            builder.load(&seg.src, seg.dst.start - span.start, si)?;
        }

        // Complete the process.
        builder.done()
    }

    fn new(span: Bounds) -> Result<Self> {
        // Open the device.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sgx/enclave")?;

        // Map the memory for the enclave.
        let mmap = unsafe {
            mmap::Builder::new(span.count)
                .flags(mmap::Flags::SHARED | mmap::Flags::FIXED_NOREPLACE)
                .address(span.start)
                .file(&mut file, 0)
                .map()?
        };

        let ssa_pages = NonZeroU32::new(StateSaveArea::frame_size().into()).unwrap();

        // Create the hasher.
        let hash = Hasher::new(span.count, ssa_pages);

        // Create the enclave.
        let secs = Secs::new(span.start, span.count, ssa_pages);
        let create = sgx::Create::new(&secs);
        sgx::ENCLAVE_CREATE.ioctl(&mut file, &create).unwrap();

        Ok(Self {
            span,
            file,
            mmap,
            hash,
            perm: Vec::new(),
        })
    }

    fn load<T: AsRef<[u8]> + ?Sized>(
        &mut self,
        src: &T,
        dst: addr::Offset<usize>,
        si: SecInfo,
    ) -> Result<()> {
        const FLAGS: sgx::Flags = sgx::Flags::MEASURE;

        let size = src.as_ref().len();

        // The dst must be inside the enclave.
        if dst + size.into() > self.span.count {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }

        // Update the enclave.
        let mut ap = sgx::AddPages::new(src, dst, &si, FLAGS);
        sgx::ENCLAVE_ADD_PAGES.ioctl(&mut self.file, &mut ap)?;

        // Update the hash.
        self.hash.add(src, dst, si, true);

        // Save permissions fixups for later.
        self.perm.push((dst, size, si));

        Ok(())
    }

    fn done(mut self) -> Result<Box<dyn Keep<Start>>> {
        // Generate a signing key.
        let exp = bn::BigNum::try_from(3u32)?;
        let key = rsa::Rsa::generate_with_e(3072, &exp)?;

        // Create the enclave signature.
        let vendor = Vendor::UNKNOWN.author(0, 0);
        let sig = Signature::sign(vendor, self.hash.finish().into(), key)?;

        // Initialize the enclave.
        let init = sgx::Init::new(&sig);
        sgx::ENCLAVE_INIT.ioctl(&mut self.file, &init)?;

        // Fix up mapped permissions.
        for (dst, size, si) in self.perm {
            let protection = match si.class {
                Class::Tcs => mmap::Protections::READ | mmap::Protections::WRITE,
                Class::Reg => f2p(si.flags),
                _ => panic!("Unsupported class!"),
            };

            // Change the permissions on an existing region of memory.
            unsafe {
                self.mmap
                    .remap(dst, size.into())?
                    .protections(protection)
                    .file(&mut self.file, 0)
                    .update()?;
            }
        }

        Ok(Box::new(super::Enclave {
            tcs: self.span.start,
            mem: self.mmap,
        }))
    }
}
