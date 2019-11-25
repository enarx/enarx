// Copyright 2019 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::convert::TryInto;
use std::io::{Error, Result};
use std::os::raw::{c_int, c_uint, c_ulong, c_void};
use std::os::unix::io::AsRawFd;
use std::ptr::null;

pub mod sgx;

extern "C" {
    pub fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
}

pub trait Ioctl {
    const REQUEST: c_ulong;

    fn ioctl(&self, fd: &impl AsRawFd) -> Result<c_uint> {
        let r = unsafe {
            ioctl(
                fd.as_raw_fd(),
                Self::REQUEST,
                self as *const _,
                null::<c_void>(),
            )
        };

        r.try_into().or_else(|_| Err(Error::last_os_error()))
    }
}
