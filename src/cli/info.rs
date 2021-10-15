// SPDX-License-Identifier: Apache-2.0

use crate::backend::BACKENDS;
use crate::cli::{Result, StructOpt};
use std::ops::Deref;

/// Show details about backend support on this system
#[derive(StructOpt, Debug)]
pub struct Options {}

impl Options {
    /// Display nicely-formatted info about each backend
    #[allow(clippy::unnecessary_wraps)]
    pub fn display(self) -> Result<()> {
        use colorful::*;

        for backend in BACKENDS.deref() {
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

        Ok(())
    }
}
