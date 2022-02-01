// SPDX-License-Identifier: Apache-2.0

use crate::backend::Datum;

use libc::{uname, utsname};
use std::{ffi::CStr, io, mem::MaybeUninit, os::raw::c_char, str::Utf8Error};

pub fn system_info() -> Datum {
    fn system_info_string(utsname: utsname) -> Result<String, Utf8Error> {
        fn array_to_str(array: &'_ [c_char; 65]) -> Result<&'_ str, Utf8Error> {
            unsafe { CStr::from_ptr(array.as_ptr()) }.to_str()
        }

        Ok(format!(
            "{} {} {} {} {} {}",
            array_to_str(&utsname.sysname)?,
            array_to_str(&utsname.nodename)?,
            array_to_str(&utsname.release)?,
            array_to_str(&utsname.version)?,
            array_to_str(&utsname.machine)?,
            array_to_str(&utsname.domainname)?,
        ))
    }

    let mut utsname = MaybeUninit::uninit();

    Datum {
        name: "System Info".to_string(),
        pass: true,
        info: if unsafe { uname(utsname.as_mut_ptr()) } != 0 {
            Some(format!("[{}]", io::Error::last_os_error()))
        } else {
            Some(
                system_info_string(unsafe { utsname.assume_init() })
                    .unwrap_or_else(|e| format!("[utf8 error: {}]", e)),
            )
        },
        mesg: None,
    }
}
