// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.

use super::super::{Error, Indeterminate, Version};
use super::{Build, State, Status, TcbStatus, TcbVersion};

use iocuddle::{Group, Ioctl, WriteRead};

use std::fs::{File, OpenOptions};
use std::marker::PhantomData;
use std::os::unix::io::{AsRawFd, RawFd};

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/psp-sev.h
impl_const_id! {
    pub Id => u32;
    // […]
    SnpPlatformStatus = 9,
}

const SEV: Group = Group::new(b'S');

/// Return information about the current status and capabilities of the SEV-SNP platform.
const SNP_PLATFORM_STATUS: Ioctl<WriteRead, &Command<SnpPlatformStatus>> =
    unsafe { SEV.write_read(0) };

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

    // FIXME: remove `allow(unused)`
    // because we want to use  `platform_status()` later in a sub command.
    // See: https://github.com/enarx/enarx/issues/1020
    #[allow(unused)]
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
}

impl AsRawFd for Firmware {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
