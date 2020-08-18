// SPDX-License-Identifier: Apache-2.0

extern crate reqwest;
#[macro_use]
extern crate serde_derive;

//Commented out as unused in TEST 1
//use ::host_components::*;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct Payload {
    encoding: String,
    contents: Vec<u8>,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let connect_port: u16 = args[0].parse().unwrap();

    //TODO - add loading of files from command-line
    let in_path = Path::new("external/return_1.wasm");

    let in_contents = match std::fs::read(in_path) {
        Ok(in_contents) => {
            println!("Contents = of {} bytes", &in_contents.len());
            in_contents
        }
        Err(_) => {
            println!("Failed to read from file");
            panic!("We have no data to use");
        }
    };

    let payload = Payload {
        encoding: String::from("wasm"),
        contents: in_contents,
    };

    //add client certificate presentation
    let client_cert_path: &str = "key-material/client.p12";
    let mut cert_buf = Vec::new();

    File::open(&client_cert_path)
        .expect("certificate opening problems")
        .read_to_end(&mut cert_buf)
        .expect("certificate file reading problems");
    //DANGER, DANGER - password hard-coded
    //DANGER, DANGER - password in clear-text
    //FIXME, FIXME
    let pkcs12_client_id = reqwest::Identity::from_pkcs12_der(&cert_buf, "enarx-test")
        .expect("certificate reading problems");

    //TEST 1 - localhost:port
    let connect_uri = format!("https://localhost:{}/payload", connect_port);
    //TEST 2 - other_add:port
    //let connect_uri = format!("https://{}:{}/payload", LOCAL_LISTEN_ADDRESS, connect_port);

    //we accept invalid certs here because in the longer term, we will have mechanism
    // for finding out what the cert should be dynamically, and adding it, but currently,
    // we don't know what to expect as cert is dynamically generated and self-signed
    //TODO: add certs dynamically as part of protocol
    let res = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .identity(pkcs12_client_id)
        .build()
        .unwrap()
        .post(&connect_uri)
        .json(&payload)
        .send();
    println!("{:#?}", res);
}
