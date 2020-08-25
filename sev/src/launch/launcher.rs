// SPDX-License-Identifier: Apache-2.0

use super::{Measurement, Secret, Start};

use crate::launch::linux::ioctl::*;
use crate::launch::types::*;

use std::io::Result;
use std::mem::MaybeUninit;
use std::os::unix::io::{AsRawFd, RawFd};

pub struct Handle(u32);

pub struct New;
pub struct Started(Handle);
pub struct Measured(Handle, Measurement);

struct Fd<'a>(&'a dyn AsRawFd);

impl AsRawFd for Fd<'_> {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

pub struct Launcher<'a, T> {
    state: T,
    kvm: Fd<'a>,
    sev: Fd<'a>,
}

impl<'a> Launcher<'a, New> {
    pub fn new(kvm: &'a dyn AsRawFd, sev: &'a dyn AsRawFd) -> Result<Self> {
        let mut launcher = Launcher {
            kvm: Fd(kvm),
            sev: Fd(sev),
            state: New,
        };

        INIT.ioctl(&mut launcher.kvm, &mut Command::from(&launcher.sev, &Init))?;

        Ok(launcher)
    }

    pub fn start(mut self, start: Start) -> Result<Launcher<'a, Started>> {
        let mut launch_start = LaunchStart::new(&start.policy, &start.cert, &start.session);
        LAUNCH_START.ioctl(
            &mut self.kvm,
            &mut Command::from_mut(&self.sev, &mut launch_start),
        )?;

        let next = Launcher {
            state: Started(Handle(launch_start.handle)),
            kvm: self.kvm,
            sev: self.sev,
        };

        Ok(next)
    }
}

impl<'a> Launcher<'a, Started> {
    pub fn update_data(&mut self, data: &[u8]) -> Result<()> {
        let launch_update_data = LaunchUpdateData::new(data);
        LAUNCH_UPDATE_DATA.ioctl(
            &mut self.kvm,
            &mut Command::from(&self.sev, &launch_update_data),
        )?;
        Ok(())
    }

    pub fn measure(mut self) -> Result<Launcher<'a, Measured>> {
        let mut measurement = unsafe { MaybeUninit::zeroed().assume_init() };
        LAUNCH_MEASUREMENT.ioctl(
            &mut self.kvm,
            &mut Command::from_mut(&self.sev, &mut LaunchMeasure::new(&mut measurement)),
        )?;

        let next = Launcher {
            state: Measured(self.state.0, measurement),
            kvm: self.kvm,
            sev: self.sev,
        };

        Ok(next)
    }
}

impl<'a> Launcher<'a, Measured> {
    pub fn measurement(&self) -> Measurement {
        self.state.1
    }

    pub fn inject(&mut self, secret: Secret, guest: &u8) -> Result<()> {
        let launch_secret = LaunchSecret::new(&secret.header, guest, &secret.ciphertext[..]);
        LAUNCH_SECRET.ioctl(&mut self.kvm, &mut Command::from(&self.sev, &launch_secret))?;
        Ok(())
    }
}
