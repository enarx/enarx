// SPDX-License-Identifier: Apache-2.0
use crate::backend::{Backend, BACKENDS};
use clap::Args;
#[cfg(unix)]
use libc::{uname, utsname};
use serde::Serialize;
use std::fmt::{self, Formatter};
use std::ops::Deref;
use std::process::ExitCode;
/// Show details about backend support on this system

#[derive(Args, Debug)]
pub struct Options {
    #[clap(short, long)]
    /// Emit JSON rather than human-readable output
    json: bool,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
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
                    .unwrap_or_else(|e| format!("[utf8 error: {e}]"))
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
            println!("{info}");
        }

        Ok(ExitCode::SUCCESS)
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
                    write!(f, ": {info}")?;
                }
                writeln!(f)?;
            }

            for datum in &data {
                if let Some(mesg) = datum.mesg.as_ref() {
                    writeln!(f, "\n  {mesg}\n")?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::Options;
    use crate::backend::{Backend, Datum, Keep, Signatures};
    use anyhow::bail;
    use once_cell::sync::Lazy;
    use serde_json::json;
    use std::{ops::Deref, sync::Arc};

    #[test]
    fn test_info() {
        Options { json: true }.execute().unwrap();
        Options { json: false }.execute().unwrap();
    }

    #[test]
    fn test_info_json() {
        pub struct Dummy;

        impl crate::backend::Backend for Dummy {
            #[inline]
            fn name(&self) -> &'static str {
                "dummy"
            }

            #[inline]
            fn shim(&self) -> &'static [u8] {
                &[]
            }

            fn data(&self) -> Vec<Datum> {
                //Here I will do all the main work.
                vec![
                    Datum {
                        name: "Driver".into(),
                        pass: true,
                        info: Some("/dev/dummy".into()),
                        mesg: None,
                    },
                    Datum {
                        name: " Dummy Driver".into(),
                        pass: false,
                        info: Some("driver".into()),
                        mesg: None,
                    },
                    Datum {
                        name: " Dummy Backend".into(),
                        pass: false,
                        info: None,
                        mesg: None,
                    },
                    Datum {
                        name: "  Dummy Backend".into(),
                        pass: false,
                        info: None,
                        mesg: None,
                    },
                    Datum {
                        name: "   Dummy Backend".into(),
                        pass: false,
                        info: None,
                        mesg: None,
                    },
                    Datum {
                        name: "Dummy Backend".into(),
                        pass: false,
                        info: None,
                        mesg: None,
                    },
                    Datum {
                        name: "Dummy Backend".into(),
                        pass: false,
                        info: None,
                        mesg: None,
                    },
                ]
            }

            fn config(&self) -> Vec<Datum> {
                vec![]
            }

            fn keep(
                &self,
                _: &[u8],
                _: &[u8],
                _: Option<Signatures>,
            ) -> anyhow::Result<Arc<dyn Keep>> {
                bail!("This is a dummy backend")
            }

            fn hash(&self, _: &[u8], _: &[u8]) -> anyhow::Result<Vec<u8>> {
                Ok(Vec::<u8>::new())
            }
        }

        let expected_json_output = json! ({
          "backend": "dummy",
          "data": [
            {
              "name": "Driver",
              "pass": true,
              "info": "/dev/dummy",
              "mesg": "null",
              "data": [
                {
                  "name": "Dummy Driver",
                  "pass": false,
                  "info": "driver",
                  "mesg": "null",
                  "data": []
                },
                {
                  "name": "Dummy Backend",
                  "pass": false,
                  "info": "null",
                  "mesg": "null",
                  "data": [
                    {
                      "name": "Dummy Backend",
                      "pass": false,
                      "info": "null",
                      "mesg": "null",
                      "data": [
                        {
                          "name": "Dummy Backend",
                          "pass": false,
                          "info": "null",
                          "mesg": "null",
                          "data": []
                        }
                      ]
                    }
                  ]
                }
              ]
            },
            {
              "name": "Dummy Backend",
              "pass": false,
              "info": "null",
              "mesg": "null",
              "data": []
            },
            {
              "name": "Dummy Backend",
              "pass": false,
              "info": "null",
              "mesg": "null",
              "data": []
            }
          ]
        });

        let dummy_instance: Lazy<Box<dyn Backend>> = Lazy::new(|| Box::new(Dummy {}));

        assert_eq!(
            serde_json::to_string_pretty(&dummy_instance.deref()).unwrap(),
            serde_json::to_string_pretty(&expected_json_output).unwrap(),
            "Platform info json output test failed"
        );
    }
}
