// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use structopt::StructOpt;

const EFI_UUID: &str = "304e0796-d515-4698-ac6e-e76cb1a71c28";
const EFI_NAME: &str = "SgxRegistrationServerRequest";
const PATH: &str = "/sys/firmware/efi/efivars";
const URL: &str = "https://api.trustedservices.intel.com/sgx/registration/v1/platform";

/// SGX-specific functionality
#[derive(StructOpt, Debug)]
pub enum Command {
    /// Register the platform with Intel
    Register,
}

pub fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Register => {
            let path = format!("{}/{}-{}", PATH, EFI_NAME, EFI_UUID);
            let bytes = std::fs::read(path).context("unable to read platform data")?;

            ureq::post(URL)
                .set("Content-Type", "application/octet-stream")
                .send_bytes(&bytes[8..])?;

            Ok(())
        }
    }
}
