// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::mem::{size_of_val, MaybeUninit};

use iocuddle_sev::*;
use sev_types::command::{
    GetIdentifier, PdhCertificateExport, PdhGenerate, PekCertificateImport,
    PekCertificateSigningRequest, PekGenerate, PlatformReset, PlatformStatus,
};

use super::*;
use crate::certs::sev::Certificate;

pub struct Firmware(File);

impl Firmware {
    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(File::open("/dev/sev")?))
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
                build: config.build() as u8,
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
        PEK_GENERATE.ioctl(&mut self.0, &mut Command::new(&mut PekGenerate))?;
        Ok(())
    }

    pub fn pek_csr(&mut self) -> Result<Certificate, Indeterminate<Error>> {
        #[allow(clippy::uninit_assumed_init)]
        let mut pek: Certificate = unsafe { MaybeUninit::uninit().assume_init() };

        let mut req =
            PekCertificateSigningRequest::new(&mut pek as *mut _ as u64, size_of_val(&pek) as u32);

        PEK_CERTIFICATE_SIGNING_REQUEST.ioctl(&mut self.0, &mut Command::new(&mut req))?;

        Ok(pek)
    }

    pub fn pdh_generate(&mut self) -> Result<(), Indeterminate<Error>> {
        PDH_GENERATE.ioctl(&mut self.0, &mut Command::new(&mut PdhGenerate))?;
        Ok(())
    }

    pub fn pdh_cert_export(&mut self) -> Result<certs::sev::Chain, Indeterminate<Error>> {
        #[allow(clippy::uninit_assumed_init)]
        let mut chain: [Certificate; 3] = unsafe { MaybeUninit::uninit().assume_init() };
        #[allow(clippy::uninit_assumed_init)]
        let mut pdh: Certificate = unsafe { MaybeUninit::uninit().assume_init() };

        let mut certs = PdhCertificateExport::new(
            &mut pdh as *mut _ as u64,
            size_of_val(&pdh) as u32,
            &mut chain as *mut _ as u64,
            size_of_val(&chain) as u32,
        );

        PDH_CERTIFICATE_EXPORT.ioctl(&mut self.0, &mut Command::new(&mut certs))?;

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
        let mut certs = PekCertificateImport::new(
            pek as *const _ as u64,
            size_of_val(pek) as u32,
            oca as *const _ as u64,
            size_of_val(oca) as u32,
        );

        PEK_CERTIFICATE_IMPORT.ioctl(&mut self.0, &mut Command::new(&mut certs))?;

        Ok(())
    }

    pub fn get_identifer(&mut self) -> Result<Identifier, Indeterminate<Error>> {
        // Per AMD, this interface will change in a future revision.
        // Future iterations will only ever return one id and its
        // length will be variable. We handle the current verison of
        // the API here. We'll adjust to future versions later. We
        // don't anticipate any future change in *our* public API.

        let mut ids = GetIdentifier([0u8; 64], [0u8; 64]);

        GET_IDENTIFIER.ioctl(&mut self.0, &mut Command::new(&mut ids))?;

        Ok(Identifier(ids.0.to_vec()))
    }
}
