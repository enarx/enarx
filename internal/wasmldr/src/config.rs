// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub files: Option<Vec<File>>,
}

#[derive(Deserialize, Debug)]
pub struct File {
    #[serde(rename = "type")]
    pub type_: String,
    pub name: String,
    pub addr: Option<String>,
    pub port: Option<u16>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            files: Some(vec![
                File {
                    type_: "stdio".to_string(),
                    name: "stdin".to_string(),
                    addr: None,
                    port: None,
                },
                File {
                    type_: "stdio".to_string(),
                    name: "stdout".to_string(),
                    addr: None,
                    port: None,
                },
                File {
                    type_: "stdio".to_string(),
                    name: "stderr".to_string(),
                    addr: None,
                    port: None,
                },
            ]),
        }
    }
}
