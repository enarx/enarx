// SPDX-License-Identifier: Apache-2.0

use crate::launch::linux::ioctl::*;
use crate::launch::types::*;

use std::io::Result;
use std::os::unix::io::{AsRawFd, RawFd};

pub struct New;

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
}

