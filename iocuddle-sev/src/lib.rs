// SPDX-License-Identifier: Apache-2.0

use core::marker::PhantomData;

use enumerate::enumerate;
use iocuddle::*;
use sev_types::command::{
    GetIdentifier, PdhCertificateExport, PdhGenerate, PekCertificateImport,
    PekCertificateSigningRequest, PekGenerate, PlatformReset, PlatformStatus,
};

// FIXME: https://github.com/rust-lang/rustfmt/issues/4085
#[rustfmt::skip]
enumerate! {
    pub enum IoctlCode: u32 {
	PlatformReset = 0,
	PlatformStatus = 1,
	PekGenerate = 2,
	PekCertificateSigningRequest = 3,
	PdhGenerate = 4,
	PdhCertificateExport = 5,
	PekCertificateImport = 6,
	GetIdentifier = 7,
    }
}

const SEV: Group = Group::new(b'S');
pub const PLATFORM_RESET: Ioctl<WriteRead, &Command<PlatformReset>> = unsafe { SEV.write_read(0) };
pub const PLATFORM_STATUS: Ioctl<WriteRead, &Command<PlatformStatus>> =
    unsafe { SEV.write_read(0) };
pub const PEK_GENERATE: Ioctl<WriteRead, &Command<PekGenerate>> = unsafe { SEV.write_read(0) };
pub const PEK_CERTIFICATE_SIGNING_REQUEST: Ioctl<
    WriteRead,
    &Command<PekCertificateSigningRequest>,
> = unsafe { SEV.write_read(0) };
pub const PDH_GENERATE: Ioctl<WriteRead, &Command<PdhGenerate>> = unsafe { SEV.write_read(0) };
pub const PDH_CERTIFICATE_EXPORT: Ioctl<WriteRead, &Command<PdhCertificateExport>> =
    unsafe { SEV.write_read(0) };
pub const PEK_CERTIFICATE_IMPORT: Ioctl<WriteRead, &Command<PekCertificateImport>> =
    unsafe { SEV.write_read(0) };
pub const GET_IDENTIFIER: Ioctl<WriteRead, &Command<GetIdentifier>> = unsafe { SEV.write_read(0) };

pub trait SevIoctl {
    const CODE: IoctlCode;
}

impl SevIoctl for PlatformReset {
    const CODE: IoctlCode = IoctlCode::PlatformReset;
}

impl SevIoctl for PlatformStatus {
    const CODE: IoctlCode = IoctlCode::PlatformStatus;
}

impl SevIoctl for PekGenerate {
    const CODE: IoctlCode = IoctlCode::PekGenerate;
}

impl<'a> SevIoctl for PekCertificateSigningRequest<'a> {
    const CODE: IoctlCode = IoctlCode::PekCertificateSigningRequest;
}

impl SevIoctl for PdhGenerate {
    const CODE: IoctlCode = IoctlCode::PdhGenerate;
}

impl<'a> SevIoctl for PdhCertificateExport<'a> {
    const CODE: IoctlCode = IoctlCode::PdhCertificateExport;
}

impl<'a> SevIoctl for PekCertificateImport<'a> {
    const CODE: IoctlCode = IoctlCode::PekCertificateImport;
}

impl SevIoctl for GetIdentifier {
    const CODE: IoctlCode = IoctlCode::GetIdentifier;
}

#[repr(C, packed)]
pub struct Command<'a, T: SevIoctl> {
    code: IoctlCode,
    data: u64,
    error: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: SevIoctl> Command<'a, T> {
    pub fn new(subcmd: &'a mut T) -> Self {
        Command {
            code: T::CODE,
            data: subcmd as *mut T as u64,
            error: 0,
            _phantom: PhantomData,
        }
    }
}
