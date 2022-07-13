// SPDX-License-Identifier: Apache-2.0

use crate::backend::{Backend, BACKENDS};

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

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let backends = BACKENDS.deref();

        #[cfg(windows)]
        fn get_system_info() -> String {
            // FIXME
            "Windows".into()
        }

        #[cfg(unix)]
        fn get_system_info() -> String {
            use std::{ffi::CStr, io, mem::MaybeUninit, os::raw::c_char, str::Utf8Error};

            fn utsname_to_string(mut utsname: utsname) -> anyhow::Result<String, Utf8Error> {
                fn array_to_str<const N: usize>(
                    array: &'_ mut [c_char; N],
                ) -> anyhow::Result<&'_ str, Utf8Error> {
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

            if unsafe { uname(utsname.as_mut_ptr()) } != 0 {
                format!("[{}]", io::Error::last_os_error())
            } else {
                utsname_to_string(unsafe { utsname.assume_init() })
                    .unwrap_or_else(|e| format!("[utf8 error: {}]", e))
            }
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
            let mut data = backend.data();
            data.extend(backend.config());
            let pass = backend.have() && backend.configured();
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

#[test]
fn test_info() {
    Options { json: true }.execute().unwrap();
    Options { json: false }.execute().unwrap();
}
