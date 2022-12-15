// SPDX-License-Identifier: Apache-2.0

use crate::backend::sev::snp::vcek::{get_vcek_reader, get_vcek_reader_with_path, sev_cache_dir};

use std::io::{self, ErrorKind};
use std::process::ExitCode;

use clap::Args;

/// Print the VCEK certificate for this platform to stdout in PEM format
#[derive(Args, Debug)]
pub struct Options {
    /// Print the location of the VCEK certificate file
    #[clap(long)]
    file: bool,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        if self.file {
            match get_vcek_reader_with_path(sev_cache_dir()?) {
                Ok((path, _)) => {
                    println!("{path:?}");
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    if matches!(
                        e.downcast_ref::<io::Error>().map(io::Error::kind),
                        Some(ErrorKind::NotFound)
                    ) {
                        eprintln!("No cache file found.");
                        Ok(ExitCode::SUCCESS)
                    } else {
                        Err(e)
                    }
                }
            }
        } else {
            let mut reader = get_vcek_reader()?;
            io::copy(&mut reader, &mut io::stdout())?;
            Ok(ExitCode::SUCCESS)
        }
    }
}
