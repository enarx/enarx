// SPDX-License-Identifier: Apache-2.0

pub mod wrapper;

use std::fs::{File, OpenOptions};
use std::mem::{size_of_val, MaybeUninit};
use std::os::raw::{c_int, c_ulong};
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;

use crate::certs::sev::Certificate;
use crate::firmware::linux::ioctl::wrapper::Command;
use crate::firmware::*;
use wrapper::*;

type KvmIoctlResult<T> = std::result::Result<T, Indeterminate<Error>>;

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum Code {
    PlatformReset = 0,
    PlatformStatus,
    PekGenerate,
    PekCertificateSigningRequest,
    PdhGenerate,
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

    pub fn platform_reset(&self) -> Result<(), Indeterminate<Error>> {
        self.cmd(Code::PlatformReset, ())?;
        Ok(())
    }

    pub fn platform_status(&self) -> Result<Status, Indeterminate<Error>> {
        #[repr(C, packed)]
        struct Info {
            api_major: u8,
            api_minor: u8,
            state: u8,
            flags: u32,
            build: u8,
            guest_count: u32,
        }

        #[allow(clippy::uninit_assumed_init)]
        let i: Info = self.cmd(Code::PlatformStatus, unsafe {
            MaybeUninit::uninit().assume_init()
        })?;

        Ok(Status {
            build: Build {
                version: Version {
                    major: i.api_major,
                    minor: i.api_minor,
                },
                build: i.build,
            },
            guests: i.guest_count,
            flags: Flags::from_bits_truncate(i.flags),
            state: match i.state {
                0 => State::Uninitialized,
                1 => State::Initialized,
                2 => State::Working,
                _ => return Err(Indeterminate::Unknown),
            },
        })
    }

    pub fn pek_generate(&self) -> Result<(), Indeterminate<Error>> {
        self.cmd(Code::PekGenerate, ())?;
        Ok(())
    }

    pub fn pek_csr(&self) -> Result<Certificate, Indeterminate<Error>> {
        #[repr(C, packed)]
        struct Cert {
            addr: u64,
            len: u32,
        }

        #[allow(clippy::uninit_assumed_init)]
        let mut pek: Certificate = unsafe { MaybeUninit::uninit().assume_init() };

        self.cmd(
            Code::PekCertificateSigningRequest,
            Cert {
                addr: &mut pek as *mut _ as u64,
                len: size_of_val(&pek) as u32,
            },
        )?;

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

pub struct Handle(u32);

pub struct Initialized;
pub struct Started(Handle);
pub struct Measured(Handle, launch::Measurement);

pub struct Launch<'a, T, V: AsRawFd, F: AsRawFd> {
    state: T,
    fw: &'a mut V,
    vm: &'a mut F,
}

impl<'a, T, F: AsRawFd, V: AsRawFd> Launch<'a, T, F, V> {
    fn cmd<U>(&self, code: wrapper::Code, mut data: U) -> KvmIoctlResult<U> {
        let cmd = Command {
            error: 0,
            data: &mut data as *mut _ as u64,
            fd: self.fw.as_raw_fd() as u32,
            code,
        };

        let encryptop = EncryptOp::new(&cmd);
        encryptop.ioctl(self.vm)?;
        Ok(data)
    }
}

impl<'a, F: AsRawFd, V: AsRawFd> Launch<'a, Initialized, F, V> {
    pub fn new(fw: &'a mut F, vm: &'a mut V) -> KvmIoctlResult<Self> {
        let l = Launch {
            state: Initialized,
            fw,
            vm,
        };
        l.cmd(wrapper::Code::Init, ())?;
        Ok(l)
    }

    pub fn start(self, start: launch::Start) -> KvmIoctlResult<Launch<'a, Started, F, V>> {
        #[repr(C)]
        struct Data {
            handle: u32,
            policy: launch::Policy,
            dh_addr: u64,
            dh_size: u32,
            session_addr: u64,
            session_size: u32,
        }

        let data = Data {
            handle: 0,
            policy: start.policy,
            dh_addr: &start.cert as *const _ as u64,
            dh_size: size_of_val(&start.cert) as u32,
            session_addr: &start.session as *const _ as u64,
            session_size: size_of_val(&start.session) as u32,
        };

        let state = Started(Handle(self.cmd(wrapper::Code::LaunchStart, data)?.handle));
        Ok(Launch {
            state,
            fw: self.fw,
            vm: self.vm,
        })
    }
}

impl<'a, F: AsRawFd, V: AsRawFd> Launch<'a, Started, F, V> {
    pub fn update_data(&mut self, data: &[u8]) -> KvmIoctlResult<()> {
        #[repr(C)]
        struct Data {
            addr: u64,
            size: u32,
        }

        let data = Data {
            addr: data.as_ptr() as u64,
            size: data.len() as u32,
        };

        self.cmd(wrapper::Code::LaunchUpdateData, data)?;
        Ok(())
    }

    pub fn measure(self) -> KvmIoctlResult<Launch<'a, Measured, F, V>> {
        #[repr(C)]
        struct Data {
            addr: u64,
            size: u32,
        }

        #[allow(clippy::uninit_assumed_init)]
        let mut measurement: launch::Measurement = unsafe { MaybeUninit::uninit().assume_init() };
        let data = Data {
            addr: &mut measurement as *mut _ as u64,
            size: size_of_val(&measurement) as u32,
        };

        self.cmd(wrapper::Code::LaunchMeasure, data)?;

        Ok(Launch {
            state: Measured(self.state.0, measurement),
            fw: self.fw,
            vm: self.vm,
        })
    }
}

impl<'a, F: AsRawFd, V: AsRawFd> Launch<'a, Measured, F, V> {
    pub fn measurement(&self) -> launch::Measurement {
        self.state.1
    }

    pub fn inject(&self, mut secret: launch::Secret, gaddr: u64, size: u32) -> KvmIoctlResult<()> {
        #[repr(C)]
        struct Data {
            headr_addr: u64,
            headr_size: u32,
            guest_addr: u64,
            guest_size: u32,
            trans_addr: u64,
            trans_size: u32,
        }

        let data = Data {
            headr_addr: &mut secret.header as *mut _ as u64,
            headr_size: size_of_val(&secret.header) as u32,
            guest_addr: gaddr,
            guest_size: size,
            trans_addr: secret.ciphertext.as_mut_ptr() as u64,
            trans_size: secret.ciphertext.len() as u32,
        };

        self.cmd(wrapper::Code::LaunchUpdateData, data)?;
        Ok(())
    }

    pub fn finish(self) -> KvmIoctlResult<(Handle, RawFd)> {
        self.cmd(wrapper::Code::LaunchFinish, ())?;
        Ok((self.state.0, self.vm.as_raw_fd()))
    }
}
