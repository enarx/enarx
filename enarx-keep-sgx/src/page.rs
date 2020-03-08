// SPDX-License-Identifier: Apache-2.0

use std::io::{Error, Result};

pub fn size() -> Result<usize> {
    let ret = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
    if ret < 0 {
        return Err(Error::last_os_error());
    }

    Ok(ret as _)
}
