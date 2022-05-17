// SPDX-License-Identifier: Apache-2.0

use crate::backend::BACKENDS;
use crate::cli::Result;
use crate::Backend;

use std::fmt::{self, Formatter};
use std::ops::Deref;

use clap::Args;
#[cfg(unix)]
use libc::{uname, utsname};
use serde::Serialize;

/// Show details about backend support on this system
#[derive(Args, Debug)]
pub struct Options {
    #[clap(short, long)]
    /// Emit JSON rather than human-readable output
    json: bool,
}

#[derive(Serialize)]
struct Info<'a> {
    version: &'static str,
    system_info: String,
    backends: &'a Vec<Box<dyn Backend>>,
}

impl fmt::Display for Info<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use colorful::*;

        fn get_icon(is_atty: bool, pass: bool) -> String {
            match is_atty {
                true => match pass {
                    true => "✔".green().to_string(),
                    false => "✗".red().to_string(),
                },
                false => match pass {
                    true => "✔".into(),
                    false => "✗".into(),
                },
            }
        }

        let is_atty = atty::is(atty::Stream::Stdout);
        let backends = self.backends;

        writeln!(f, "Enarx version {}", self.version)?;
        writeln!(f, "System Info: {}", self.system_info)?;

        for backend in backends {
            let data = backend.data();
            let pass = data.iter().all(|x| x.pass);
            let icon = get_icon(is_atty, pass);

            writeln!(f, "{} Backend: {}", icon, backend.name())?;

            for datum in &data {
                let icon = get_icon(is_atty, datum.pass);
                write!(f, "  {} {}", icon, datum.name)?;

                if let Some(ref info) = datum.info {
                    write!(f, ": {}", info)?;
                }
                writeln!(f)?;
            }

            for datum in &data {
                if let Some(mesg) = datum.mesg.as_ref() {
                    writeln!(f, "\n  {}\n", mesg)?;
                }
            }
        }
        Ok(())
    }
}

impl Options {
    /// Display nicely-formatted info about each backend
    pub fn display(self) -> Result<()> {
        let backends = BACKENDS.deref();

        #[cfg(windows)]
        fn get_system_info() -> String {
            // FIXME
            "Windows".into()
        }

        #[cfg(unix)]
        fn get_system_info() -> String {
            use std::{ffi::CStr, io, mem::MaybeUninit, os::raw::c_char, str::Utf8Error};

            fn utsname_to_string(mut utsname: utsname) -> Result<String, Utf8Error> {
                fn array_to_str<const N: usize>(
                    array: &'_ mut [c_char; N],
                ) -> Result<&'_ str, Utf8Error> {
                    array[N - 1] = 0;
                    unsafe { CStr::from_ptr(array.as_ptr()) }.to_str()
                }

                Ok(format!(
                    "{} {} {} {}",
                    array_to_str(&mut utsname.sysname)?,
                    array_to_str(&mut utsname.release)?,
                    array_to_str(&mut utsname.version)?,
                    array_to_str(&mut utsname.machine)?,
                ))
            }

            let mut utsname = MaybeUninit::uninit();

            let uname_str = if unsafe { uname(utsname.as_mut_ptr()) } != 0 {
                format!("[{}]", io::Error::last_os_error())
            } else {
                utsname_to_string(unsafe { utsname.assume_init() })
                    .unwrap_or_else(|e| format!("[utf8 error: {}]", e))
            };

            uname_str
        }

        let info = Info {
            version: env!("CARGO_PKG_VERSION"),
            system_info: get_system_info(),
            backends,
        };
        if self.json {
            println!("{}", serde_json::to_string_pretty(&info)?);
        } else {
            println!("{}", info);
        }

        Ok(())
    }
}

#[test]
fn test_info() {
    Options { json: true }.display().unwrap();
    Options { json: false }.display().unwrap();
}
