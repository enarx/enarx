// SPDX-License-Identifier: Apache-2.0

mod ioctl;

use std::fs::{File, OpenOptions};
use std::mem::MaybeUninit;

use super::*;
use crate::certs::sev::Certificate;
use linux::ioctl::*;
use types::*;

pub struct Firmware(File);

impl Firmware {
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

    pub fn pdh_generate(&mut self) -> Result<(), Indeterminate<Error>> {
        PDH_GEN.ioctl(&mut self.0, &mut Command::new(&mut PdhGen))?;
        Ok(())
    }

    pub fn pdh_cert_export(&mut self) -> Result<certs::sev::Chain, Indeterminate<Error>> {
        #[allow(clippy::uninit_assumed_init)]
        let mut chain: [Certificate; 3] = unsafe { MaybeUninit::uninit().assume_init() };
        #[allow(clippy::uninit_assumed_init)]
        let mut pdh: Certificate = unsafe { MaybeUninit::uninit().assume_init() };

        let mut pdh_cert_export = PdhCertExport::new(&mut pdh, &mut chain);
        PDH_CERT_EXPORT.ioctl(&mut self.0, &mut Command::new(&mut pdh_cert_export))?;

        Ok(certs::sev::Chain {
            pdh,
            pek: chain[0],
            oca: chain[1],
            cek: chain[2],
        })
    }

    pub fn pek_cert_import(
        &mut self,
        pek: &Certificate,
        oca: &Certificate,
    ) -> Result<(), Indeterminate<Error>> {
        let mut pek_cert_import = PekCertImport::new(pek, oca);
        PEK_CERT_IMPORT.ioctl(&mut self.0, &mut Command::new(&mut pek_cert_import))?;
        Ok(())
    }

    pub fn get_identifer(&mut self) -> Result<Identifier, Indeterminate<Error>> {
        let mut bytes = [0u8; 64];
        let mut id = GetId::new(&mut bytes);

        GET_ID.ioctl(&mut self.0, &mut Command::new(&mut id))?;

        Ok(Identifier(id.as_slice().to_vec()))
    }
}
