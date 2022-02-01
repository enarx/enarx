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
        let backends = self.backends;
        writeln!(f, "Version {} starting up", self.version)?;
        for backend in backends {
            writeln!(f, "Backend: {}", backend.name())?;

            let data = backend.data();

            for datum in &data {
                let icon = match datum.pass {
                    true => "✔".green(),
                    false => "✗".red(),
                };

                if let Some(info) = datum.info.as_ref() {
                    writeln!(f, " {} {}: {}", icon, datum.name, info)?;
                } else {
                    writeln!(f, " {} {}", icon, datum.name)?;
                }
            }

            for datum in &data {
                if let Some(mesg) = datum.mesg.as_ref() {
                    writeln!(f, "\n{}\n", mesg)?;
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
