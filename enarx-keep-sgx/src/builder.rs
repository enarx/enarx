// SPDX-License-Identifier: Apache-2.0

use super::enclave::Enclave;
use super::map;

use iocuddle_sgx as sgx;
use openssl::{bn, rsa};
use sgx_crypto::{Hasher, Signer};
use sgx_types::{
    page::{Class, Flags, SecInfo},
    secs::*,
    sig::*,
    ssa::StateSaveArea,
};
use span::Span;

use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{Error, Result};
use std::ops::Range;

fn f2p(flags: Flags) -> libc::c_int {
    let mut prot = libc::PROT_NONE;
    if flags.contains(Flags::R) {
        prot |= libc::PROT_READ;
    }

    if flags.contains(Flags::W) {
        prot |= libc::PROT_WRITE;
    }

    if flags.contains(Flags::X) {
        prot |= libc::PROT_EXEC;
    }

    prot
}

pub struct Builder {
    sign: Parameters,
    file: File,
    mmap: map::Unmap,
    hash: Hasher,
    perm: Vec<(Span<usize>, SecInfo)>,
}

impl Builder {
    pub fn new(span: impl Into<Span<usize>>) -> Result<Self> {
        let span = span.into();

        // Open the device.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sgx/enclave")?;

        // Map the memory for the enclave
        let mmap = unsafe {
            map::map(
                span.start,
                span.count,
                libc::PROT_NONE,
                libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
                Some(&file),
                0,
            )?;
            map::Unmap::new(span)
        };

        // Create the hasher.
        let hash = Hasher::new(span.count, StateSaveArea::frame_size());

        // Create the enclave.
        let sign = Parameters::default();
        let secs = Secs::new(span, StateSaveArea::frame_size(), sign);
        let create = sgx::Create::new(&secs);
        sgx::ENCLAVE_CREATE.ioctl(&mut file, &create)?;

        Ok(Self {
            sign,
            file,
            mmap,
            hash,
            perm: Vec::new(),
        })
    }

    pub fn load<T: AsRef<[u8]> + ?Sized>(
        &mut self,
        src: &T,
        dst: usize,
        si: SecInfo,
    ) -> Result<()> {
        const FLAGS: sgx::Flags = sgx::Flags::MEASURE;
        let off = dst - self.mmap.span().start;

        // Update the enclave.
        let mut ap = sgx::AddPages::new(src, off, &si, FLAGS);
        sgx::ENCLAVE_ADD_PAGES.ioctl(&mut self.file, &mut ap)?;

        // Update the hash.
        self.hash.add(src, off, si, true);

        // Save permissions fixups for later.
        self.perm.push((
            Span {
                start: dst,
                count: src.as_ref().len(),
            },
            si,
        ));

        Ok(())
    }

    pub fn done(mut self) -> Result<Enclave> {
        // Generate a signing key.
        let exp = bn::BigNum::try_from(3u32)?;
        let key = rsa::Rsa::generate_with_e(3072, &exp)?;

        // Create the enclave signature.
        let vendor = Vendor::UNKNOWN.author(0, 0);
        let sig = key.sign(vendor, self.hash.finish(self.sign))?;

        // Initialize the enclave.
        let init = sgx::Init::new(&sig);
        sgx::ENCLAVE_INIT.ioctl(&mut self.file, &init)?;

        // Fix up mapped permissions.
        self.perm.sort_by(|l, r| l.0.start.cmp(&r.0.start));
        for (span, si) in self.perm {
            #[rustfmt::skip]
            let rwx = match si.class {
                Class::Tcs => libc::PROT_READ | libc::PROT_WRITE,
                Class::Reg => f2p(si.flags),
                _ => panic!("Unsupported class!"),
            };
            // Change the permissions on an existing region of memory.
            unsafe {
                if libc::mprotect(span.start as _, span.count, rwx) != 0 {
                    return Err(Error::last_os_error());
                }
            }

            let range = Range::from(span);
            eprintln!("{:016x}-{:016x} {:?}", range.start, range.end, si);
        }

        let tcs = self.mmap.span().start;
        Ok(Enclave::new(self.mmap, tcs))
    }
}
