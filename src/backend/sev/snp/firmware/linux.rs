// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.

use super::super::{Error, Indeterminate, Version};
use super::{Build, Identifier, State, Status, TcbStatus, TcbVersion};

use iocuddle::{Group, Ioctl, WriteRead};

use std::fs::{File, OpenOptions};
use std::marker::PhantomData;
use std::os::unix::io::{AsRawFd, RawFd};

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/psp-sev.h
impl_const_id! {
    pub Id => u32;
    // […]
    GetId<'_> = 8, /* GET_ID2 is 8, the deprecated GET_ID ioctl is 7 */
    SnpPlatformStatus = 9,
}

const SEV: Group = Group::new(b'S');

/// Get the CPU's unique ID that can be used for getting a certificate for the CEK public key.
const GET_ID: Ioctl<WriteRead, &Command<'_, GetId<'_>>> = unsafe { SEV.write_read(0) };

/// Return information about the current status and capabilities of the SEV-SNP platform.
const SNP_PLATFORM_STATUS: Ioctl<WriteRead, &Command<'_, SnpPlatformStatus>> =
    unsafe { SEV.write_read(0) };

/// Get the CPU's unique ID that can be used for getting
/// a certificate for the CEK public key.
#[repr(C, packed)]
struct GetId<'a> {
    id_addr: u64,
    id_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> GetId<'a> {
    pub fn new(id: &'a mut [u8; 64]) -> Self {
        Self {
            id_addr: id.as_mut_ptr() as _,
            id_len: id.len() as _,
            _phantom: PhantomData,
        }
    }

    /// This method is only meaningful if called *after* the GET_ID2 ioctl is called because the
    /// kernel will write the length of the unique CPU ID to `GetId.id_len`.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.id_addr as *const u8, self.id_len as _) }
    }
}

/// Query the SEV-SNP platform status.
///
/// (Chapter 8.3; Table 38)
#[derive(Default)]
#[repr(C)]
struct SnpPlatformStatus {
    /// The firmware API version (major.minor)
    pub version: Version,

    /// The platform state.
    pub state: u8,

    /// IsRmpInitiailzied
    pub is_rmp_init: u8,

    /// The platform build ID.
    pub build_id: u32,

    /// MaskChipId
    pub mask_chip_id: u32,

    /// The number of valid guests maintained by the SEV-SNP firmware.
    pub guest_count: u32,

    /// Installed TCB version.
    pub platform_tcb_version: TcbVersion,

    /// Reported TCB version.
    pub reported_tcb_version: TcbVersion,
}

/// The Rust-flavored, FFI-friendly version of `struct sev_issue_cmd` which is
/// used to pass arguments to the SEV ioctl implementation.
///
/// This struct is defined in the Linux kernel: include/uapi/linux/psp-sev.h
#[repr(C, packed)]
pub struct Command<'a, T: Id> {
    code: u32,
    data: u64,
    error: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Id> Command<'a, T> {
    /// Create an SEV command with the expectation that the host platform/kernel will write to
    /// the caller's address space either to the data held in the `Command.subcmd` field or some
    /// other region specified by the `Command.subcmd` field.
    pub fn from_mut(subcmd: &'a mut T) -> Self {
        Command {
            code: T::ID,
            data: subcmd as *mut T as u64,
            error: 0,
            _phantom: PhantomData,
        }
    }
}

/// A handle to the SEV platform.
pub struct Firmware(File);

impl Firmware {
    /// Create a handle to the SEV platform.
    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new().read(true).write(true).open("/dev/sev")?,
        ))
    }

    /// Query the SNP platform status.
    pub fn platform_status(&mut self) -> Result<Status, Indeterminate<Error>> {
        let mut info: SnpPlatformStatus = Default::default();
        SNP_PLATFORM_STATUS.ioctl(&mut self.0, &mut Command::from_mut(&mut info))?;

        Ok(Status {
            build: Build {
                version: Version {
                    major: info.version.major,
                    minor: info.version.minor,
                },
                build: info.build_id,
            },
            guests: info.guest_count,
            tcb: TcbStatus {
                platform_version: info.platform_tcb_version,
                reported_version: info.reported_tcb_version,
            },
            is_rmp_init: info.is_rmp_init == 1,
            mask_chip_id: info.mask_chip_id == 1,
            state: match info.state {
                0 => State::Uninitialized,
                1 => State::Initialized,
                // SNP platforms cannot be in any other State.
                _ => return Err(Indeterminate::Unknown),
            },
        })
    }

    /// Query the unique CPU identifier.
    ///
    /// This is especially helpful for sending AMD an HTTP request to fetch
    /// the signed CEK certificate.
    pub fn identifier(&mut self) -> Result<Identifier, Indeterminate<Error>> {
        let mut bytes = [0u8; 64];
        let mut id = GetId::new(&mut bytes);

        GET_ID.ioctl(&mut self.0, &mut Command::from_mut(&mut id))?;

        Ok(Identifier(id.as_slice().to_vec()))
    }
}

impl AsRawFd for Firmware {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
