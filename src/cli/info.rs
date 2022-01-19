// SPDX-License-Identifier: Apache-2.0

use crate::backend::BACKENDS;
use crate::cli::{Result, StructOpt};
use std::ops::Deref;

/// Show details about backend support on this system
#[derive(StructOpt, Debug)]
pub struct Options {
    #[structopt(short, long)]
    /// Emit JSON rather than human-readable output
    json: bool,
}

impl Options {
    /// Display nicely-formatted info about each backend
    pub fn display(self) -> Result<()> {
        use colorful::*;

        let backends = BACKENDS.deref();

        if self.json {
            println!("{}", serde_json::to_string_pretty(&backends)?);
        } else {
            for backend in backends {
                println!("Backend: {}", backend.name());

                let data = backend.data();

                for datum in &data {
                    let icon = match datum.pass {
                        true => "✔".green(),
                        false => "✗".red(),
                    };

                    if let Some(info) = datum.info.as_ref() {
                        println!(" {} {}: {}", icon, datum.name, info);
                    } else {
                        println!(" {} {}", icon, datum.name);
                    }
                }

                for datum in &data {
                    if let Some(mesg) = datum.mesg.as_ref() {
                        println!("\n{}\n", mesg);
                    }
                }
            }
        }

        Ok(())
    }
}
