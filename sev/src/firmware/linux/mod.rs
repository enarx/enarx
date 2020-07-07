// SPDX-License-Identifier: Apache-2.0

mod ioctl;

use std::fs::{File, OpenOptions};
use std::mem::{size_of_val, MaybeUninit};
use std::os::raw::{c_int, c_ulong};
use std::os::unix::io::AsRawFd;

use super::*;
use crate::certs::sev::Certificate;
use linux::ioctl::*;
use types::*;

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum Code {
    PdhGenerate = 4,
    PdhCertificateExport,
    PekCertificateImport,
    GetIdentifier,
}

pub struct Firmware(File);

impl Firmware {
    fn cmd<T>(&self, code: Code, mut value: T) -> Result<T, Indeterminate<Error>> {
        extern "C" {
            fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        }
        const SEV_ISSUE_CMD: c_ulong = 0xc0105300;

        #[repr(C, packed)]
        struct Command {
            code: Code,
            data: u64,
            error: u32,
        }

        let mut cmd = Command {
            data: &mut value as *mut T as u64,
            error: 0,
            code,
        };

        match unsafe { ioctl(self.0.as_raw_fd(), SEV_ISSUE_CMD, &mut cmd) } {
            0 => Ok(value),
            _ => Err(cmd.error.into()),
        }
    }

    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new().read(true).write(true).open("/dev/sev")?,
        ))
    }

    pub fn platform_reset(&mut self) -> Result<(), Indeterminate<Error>> {
        PLATFORM_RESET.ioctl(&mut self.0, &mut Command::new(&mut PlatformReset))?;
        Ok(())
    }

    pub fn platform_status(&mut self) -> Result<Status, Indeterminate<Error>> {
        let mut info: PlatformStatus = Default::default();
        PLATFORM_STATUS.ioctl(&mut self.0, &mut Command::new(&mut info))?;
        let config = info.config;

        Ok(Status {
            build: Build {
                version: Version {
                    major: info.version.major,
                    minor: info.version.minor,
                },
                build: config.build() as _,
            },
            guests: info.guest_count,
            flags: Flags::from_bits_truncate(info.flags.bits().into()),
            state: match info.state {
                0 => State::Uninitialized,
                1 => State::Initialized,
                2 => State::Working,
                _ => return Err(Indeterminate::Unknown),
            },
        })
    }

    pub fn pek_generate(&mut self) -> Result<(), Indeterminate<Error>> {
        PEK_GEN.ioctl(&mut self.0, &mut Command::new(&mut PekGen))?;
        Ok(())
    }

    pub fn pek_csr(&mut self) -> Result<Certificate, Indeterminate<Error>> {
        #[allow(clippy::uninit_assumed_init)]
        let mut pek: Certificate = unsafe { MaybeUninit::uninit().assume_init() };
        let mut csr = PekCsr::new(&mut pek);
        PEK_CSR.ioctl(&mut self.0, &mut Command::new(&mut csr))?;

        Ok(pek)
    }

    pub fn pdh_generate(&self) -> Result<(), Indeterminate<Error>> {
        self.cmd(Code::PdhGenerate, ())?;
        Ok(())
    }

    pub fn pdh_cert_export(&self) -> Result<certs::sev::Chain, Indeterminate<Error>> {
        #[repr(C, packed)]
        struct Certs {
            pdh_addr: u64,
            pdh_size: u32,
            chain_addr: u64,
            chain_size: u32,
        }

        #[allow(clippy::uninit_assumed_init)]
        let mut chain: [Certificate; 3] = unsafe { MaybeUninit::uninit().assume_init() };
        #[allow(clippy::uninit_assumed_init)]
        let mut pdh: Certificate = unsafe { MaybeUninit::uninit().assume_init() };

        self.cmd(
            Code::PdhCertificateExport,
            Certs {
                pdh_addr: &mut pdh as *mut _ as u64,
                pdh_size: size_of_val(&pdh) as u32,
                chain_addr: &mut chain as *mut _ as u64,
                chain_size: size_of_val(&chain) as u32,
            },
        )?;

        Ok(certs::sev::Chain {
            pdh,
            pek: chain[0],
            oca: chain[1],
            cek: chain[2],
        })
    }

    pub fn pek_cert_import(
        &self,
        pek: &Certificate,
        oca: &Certificate,
    ) -> Result<(), Indeterminate<Error>> {
        #[repr(C, packed)]
        struct Certs {
            pek_addr: u64,
            pek_size: u32,
            oca_addr: u64,
            oca_size: u32,
        }

        self.cmd(
            Code::PekCertificateImport,
            Certs {
                pek_addr: pek as *const _ as u64,
                pek_size: size_of_val(pek) as u32,
                oca_addr: oca as *const _ as u64,
                oca_size: size_of_val(oca) as u32,
            },
        )?;

        Ok(())
    }

    pub fn get_identifer(&self) -> Result<Identifier, Indeterminate<Error>> {
        // Per AMD, this interface will change in a future revision.
        // Future iterations will only ever return one id and its
        // length will be variable. We handle the current verison of
        // the API here. We'll adjust to future versions later. We
        // don't anticipate any future change in *our* public API.

        #[repr(C, packed)]
        struct Ids([u8; 64], [u8; 64]);

        #[allow(clippy::uninit_assumed_init)]
        let ids: Ids = self.cmd(Code::GetIdentifier, unsafe {
            MaybeUninit::uninit().assume_init()
        })?;
        Ok(Identifier(ids.0.to_vec()))
    }
}
