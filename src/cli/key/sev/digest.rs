// SPDX-License-Identifier: Apache-2.0

use crate::backend::sev::snp::launch::IdAuth;
use crate::backend::sev::snp::sign::PublicKey;
use crate::backend::ByteSized;

use std::fmt::Debug;
use std::fs::File;
use std::io::ErrorKind;
use std::io::Read;

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Args;
use p384::ecdsa::signature::Signer as _;
use p384::ecdsa::SigningKey;
use p384::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha384};

/// Generate SEV Digest for provided SEV key and write to file.
#[derive(Args, Debug)]
pub struct Options {
    /// SEV P-384 private key in PEM form
    #[clap(long, required = true)]
    key: Utf8PathBuf,

    /// File path to write digest
    #[clap(long, required = true)]
    out: Utf8PathBuf,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let mut sev_key_file = File::open(&self.key).context("Failed to open SEV key file")?;
        let mut buffer = String::new();
        sev_key_file.read_to_string(&mut buffer)?;
        let sev_key = SigningKey::from_pkcs8_pem(&buffer).context("Failed to parse SEV key")?;

        let id_auth = IdAuth {
            id_key_algo: 1,   // ECDSA P-384 with SHA-384.
            auth_key_algo: 1, // ECDSA P-384 with SHA-384.
            ..Default::default()
        };

        let sig = sev_key.sign(id_auth.id_key.as_bytes());
        let r = sig.r().as_ref().to_le_bytes();
        let s = sig.s().as_ref().to_le_bytes();

        let mut res_key = PublicKey::default();

        res_key.component.r[..r.as_slice().len()].copy_from_slice(r.as_slice());
        res_key.component.s[..s.as_slice().len()].copy_from_slice(s.as_slice());

        let mut hasher = Sha384::new();
        hasher.update(res_key.as_bytes());
        let result: String = format!("{:X}", hasher.finalize());

        //println!("{}", result);

        //let json_digest = serde_json::to_string(&result)?;

        //println!("{}", json_digest);

        let path = self.out.into_string();

        let f = File::open(path.clone());

        let _ = match f {
            Ok(_) => println!("File found"),
            Err(error) => match error.kind() {
                ErrorKind::NotFound => match File::create(path.clone()) {
                    Ok(_) => println!("Created file"),
                    Err(e) => panic!("Problem creating the file: {:?}", e),
                },
                _ => (),
            },
        };

        std::fs::write(path, result.as_bytes()).expect("Invalid json file path");

        Ok(())
    }
}
