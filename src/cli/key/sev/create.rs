// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fs::File;
use std::io::ErrorKind;

use camino::Utf8PathBuf;
use clap::Args;
use p384::ecdsa::SigningKey;
use p384::pkcs8;
use p384::pkcs8::{EncodePublicKey, LineEnding};

use crate::backend::ByteSized;

/// Generate SEV Digest for provided SEV key and write to file.
#[derive(Args, Debug)]
pub struct Options {
    /// File path to write SEV key in PEM form
    #[clap(long, required = true)]
    out: Utf8PathBuf,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let rng = rand::thread_rng();
        let key = SigningKey::random(rng);
        //let key_info = key.to_bytes();

        //let key_info = SigningKey::to_pkcs8_pem(&key, LineEnding::default());
        let result: String = format!("{:X}", key.to_bytes());

        //let result = pkcs8::ToPrivateKey::to_pkcs8_pem(&key);

        println!("{}", result);

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

        std::fs::write(path, result).expect("Invalid .key file path");

        Ok(())
    }
}
