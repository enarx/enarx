// SPDX-License-Identifier: Apache-2.0

use super::config::Config;
use super::ioctls::*;

use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::sync::{Arc, RwLock};

use anyhow::{Error, Result};
use mmarinus::{perms, Kind, Map};
use primordial::Page;
use sgx::crypto::{openssl::*, *};
use sgx::page::{Class, Flags, SecInfo};
use sgx::signature::{Author, Hasher, Signature};

use log::trace;

pub struct Builder {
    file: File,
    cnfg: Config,
    hash: Hasher<S256Digest>,
    mmap: Map<perms::Unknown>,
    perm: Vec<(*const (), usize, SecInfo)>,
    tcsp: Vec<*const super::Tcs>,
}

impl TryFrom<super::config::Config> for Builder {
    type Error = Error;

    fn try_from(config: super::config::Config) -> Result<Self> {
        trace!("parsed config: {:?}", config);
        assert!(config.size.is_power_of_two()); // This is verified by `Config`...

        // Map the memory for the enclave
        // We map twice as much as we need so that we can naturally align it.
        let map = Map::map(config.size * 2)
            .anywhere()
            .anonymously()
            .known::<perms::None>(Kind::Private)?;

        // Naturally align the mapping.
        let addr = (map.addr() + config.size - 1) / config.size * config.size;
        let (_, map) = map.split_at(addr)?;
        let (map, _) = map.split(config.size)?;
        trace!(
            "enclave location: {:016x}-{:016x}",
            map.addr(),
            map.addr() + map.size()
        );

        // Open the device.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sgx_enclave")?;

        // Create the enclave.
        let secs = config
            .parameters
            .secs(map.addr() as *const (), map.size(), config.ssap);
        trace!("creating enclave: {:?}", secs);
        let create = Create::new(&secs);
        ENCLAVE_CREATE.ioctl(&mut file, &create)?;

        Ok(Builder {
            hash: Hasher::new(config.size, config.ssap),
            mmap: map.into(), // Discard typed permissions
            perm: Vec::new(),
            tcsp: Vec::new(),
            cnfg: config,
            file,
        })
    }
}

impl super::super::Mapper for Builder {
    type Config = super::config::Config;
    type Output = Arc<dyn super::super::Keep>;

    fn map(
        &mut self,
        pages: Map<perms::ReadWrite>,
        to: usize,
        with: (SecInfo, bool),
    ) -> anyhow::Result<()> {
        // Ignore regions with no pages.
        if pages.is_empty() {
            return Ok(());
        }

        trace!(
            "adding pages: {:016x}-{:016x} {}",
            self.mmap.addr() + to,
            self.mmap.addr() + to + pages.size(),
            with.0
        );

        // Update the enclave.
        let mut ap = AddPages::new(&*pages, to, &with.0, with.1);
        ENCLAVE_ADD_PAGES.ioctl(&mut self.file, &mut ap)?;

        // Update the hasher.
        self.hash.load(&*pages, to, with.0, with.1).unwrap();

        // Save permissions fixups for later.
        let mut addr = self.mmap.addr() + to;
        self.perm.push((addr as *const (), pages.size(), with.0));

        // Keep track of TCS pages.
        if with.0.class() == Class::Tcs {
            for chunk in pages.chunks(Page::SIZE) {
                self.tcsp.push(addr as *const super::Tcs);
                addr += chunk.len();
            }
        }

        Ok(())
    }
}

impl TryFrom<Builder> for Arc<dyn super::super::Keep> {
    type Error = Error;

    fn try_from(mut builder: Builder) -> Result<Self> {
        // Create the enclave signature
        let hash = builder.hash.finish();
        let author = Author::new(0, 0);
        let body = builder.cnfg.parameters.body(hash);
        let key = RS256PrivateKey::generate(3)?;
        let signature = Signature::new(&key, author, body)?;

        // Initialize the enclave.
        let init = Init::new(&signature);
        ENCLAVE_INIT.ioctl(&mut builder.file, &init)?;
        trace!("enclave initialized");

        // Fix up mapped permissions.
        builder.perm.sort_by_key(|x| x.0);
        for (addr, size, si) in builder.perm {
            trace!(
                "remapping: {:016x}-{:016x} {}",
                addr as usize,
                addr as usize + size,
                si
            );

            let rwx = match si.class() {
                Class::Tcs => libc::PROT_READ | libc::PROT_WRITE,
                Class::Reg => {
                    let mut prot = libc::PROT_NONE;
                    if si.flags().contains(Flags::READ) {
                        prot |= libc::PROT_READ;
                    }
                    if si.flags().contains(Flags::WRITE) {
                        prot |= libc::PROT_WRITE;
                    }
                    if si.flags().contains(Flags::EXECUTE) {
                        prot |= libc::PROT_EXEC;
                    }

                    prot
                }
                _ => panic!("Unsupported class!"),
            };

            // Change the permissions on an existing region of memory.
            std::mem::forget(unsafe {
                Map::map(size)
                    .onto(addr as usize)
                    .from(&mut builder.file, 0)
                    .unknown(Kind::Shared, rwx)?
            });
        }

        Ok(Arc::new(super::Keep {
            _mem: builder.mmap,
            tcs: RwLock::new(builder.tcsp),
        }))
    }
}
