// SPDX-License-Identifier: Apache-2.0

//! Enclave object

use std::fs::{metadata, File, OpenOptions};
use std::io::{Error, ErrorKind, Result};
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

/// Path to the enclave device.
pub const ENCLAVE_DEVICE_PATH: &str = "/dev/sgx_enclave";

/// Wraps an enclave file descriptor.
pub struct Enclave(File);

impl From<Enclave> for File {
    fn from(enclave: Enclave) -> File {
        enclave.0
    }
}

impl From<File> for Enclave {
    fn from(file: File) -> Enclave {
        Self(file)
    }
}

impl Enclave {
    pub fn new() -> Result<Enclave> {
        if !Path::new(ENCLAVE_DEVICE_PATH).exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("{} was not found", ENCLAVE_DEVICE_PATH),
            ));
        }

        if !metadata(ENCLAVE_DEVICE_PATH)
            .unwrap()
            .file_type()
            .is_char_device()
        {
            return Err(Error::new(
                ErrorKind::NotFound,
                "{} is not a chracter device",
            ));
        }

        #[allow(clippy::redundant_closure)]
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(ENCLAVE_DEVICE_PATH)
            .map(Enclave::from)
    }
}
