// SPDX-License-Identifier: Apache-2.0

use std::process::ExitCode;

use anyhow::Context;
use clap::Args;

const EFI_UUID: &str = "304e0796-d515-4698-ac6e-e76cb1a71c28";
const EFI_NAME: &str = "SgxRegistrationServerRequest";
const PATH: &str = "/sys/firmware/efi/efivars";
const URL: &str = "https://api.trustedservices.intel.com/sgx/registration/v1/platform";

/// Register this machine with Intel.
#[derive(Args, Debug, Default)]
pub struct Options {}

impl Options {
    pub fn execute(self) -> anyhow::Result<ExitCode> {
        let path = format!("{PATH}/{EFI_NAME}-{EFI_UUID}");
        let bytes = std::fs::read(path).context("unable to read platform data")?;

        ureq::post(URL)
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&bytes[8..])?;

        Ok(ExitCode::SUCCESS)
    }
}
