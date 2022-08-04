// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fs::File;
use std::io::ErrorKind;

use camino::Utf8PathBuf;
use clap::Args;
use rand::thread_rng;
use rsa::{pkcs8::EncodePrivateKey, pkcs8::LineEnding, RsaPrivateKey};

/// Generate SEV Digest for provided SEV key and write to file.
#[derive(Args, Debug)]
pub struct Options {
    /// File path to write SGX key in PEM form
    #[clap(long, required = true)]
    out: Utf8PathBuf,
}

impl Options {
    pub fn execute(self) -> anyhow::Result<()> {
        let mut rng = thread_rng();
        //let exp = BigUint::from(exponent);
        //let key = RsaPrivateKey::new_with_exp(&mut rng, 384 * 8, &exp)?;
        let key = RsaPrivateKey::new(&mut rng, 384 * 8)?;
        let res_key = RsaPrivateKey::to_pkcs8_pem(&key, LineEnding::default()).unwrap();

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

        std::fs::write(path, res_key.as_bytes()).expect("Invalid json file path");

        Ok(())
    }
}
