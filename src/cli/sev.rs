// SPDX-License-Identifier: Apache-2.0

use crate::backend::sev::Firmware;

use anyhow::{anyhow, Context, Result};
use structopt::StructOpt;

/// SEV-specific functionality
#[derive(StructOpt, Debug)]
pub enum Command {
    /// Download VCEK certificates for SEV platform and print to stdout in PEM format
    Vcek,
}

pub fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Vcek => {
            // Get the platform information.
            let mut sev = Firmware::open().context("failed to open /dev/sev")?;
            let id = sev.identifier().context("failed to query identifier")?;
            let status = sev
                .platform_status()
                .context("failed to query platform status")?;

            // Ensure the versions match.
            if status.tcb.platform_version != status.tcb.reported_version {
                // It is not clear from the documentation what the difference between the two is,
                // therefore only proceed if they are identical to ensure correctness.
                // TODO: Figure out which one should be used and drop this check.
                return Err(anyhow!("reported TCB version mismatch"));
            }

            let url = id.vcek_url(&status.tcb.reported_version);
            let rsp = ureq::get(&url).call()?;

            std::io::copy(&mut rsp.into_reader(), &mut std::io::stdout())?;
            Ok(())
        }
    }
}
