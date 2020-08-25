// SPDX-License-Identifier: Apache-2.0

use super::Start;

use crate::launch::linux::ioctl::*;
use crate::launch::types::*;

use std::io::Result;
use std::os::unix::io::{AsRawFd, RawFd};

pub struct Handle(u32);

pub struct New;
pub struct Started(Handle);

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

