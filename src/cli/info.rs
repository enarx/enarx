// SPDX-License-Identifier: Apache-2.0

use crate::backend::BACKENDS;
use crate::cli::{Result, StructOpt};
use crate::Backend;
use core::fmt::Formatter;
use serde::Serialize;
use std::fmt;
use std::ops::Deref;
/// Show details about backend support on this system
#[derive(StructOpt, Debug)]
pub struct Options {
    #[structopt(short, long)]
    /// Emit JSON rather than human-readable output
    json: bool,
}

#[derive(Serialize)]
struct Info<'a> {
    version: &'static str,
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

        let info = Info {
            version: env!("CARGO_PKG_VERSION"),
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
