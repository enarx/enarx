extern crate reqwest;
//extern crate rocket_contrib;
#[macro_use]
extern crate serde_derive;

//use rocket_contrib::json::{Json, JsonValue};
use reqwest::Identity;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct Payload {
    encoding: String,
    contents: Vec<u8>,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let connect_port: u16 = args[0].parse().unwrap();

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

    let connect_uri = format!("https://localhost:{}/payload", connect_port);
    let res = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .identity(pkcs12_client_id)
        .build()
        .unwrap()
        .post(&connect_uri)
        .json(&payload)
        .send();
    println!("{:#?}", res);

    /*
    match TcpStream::connect("localhost:3333") {
            Ok(mut stream) => {
                println!("Successfully connected to server in port 3333");
                println!("Sending our data");
                stream.write_all(&in_contents).unwrap();
            }
            Err(e) => {
                println!("Failed to connect: {}", e);
            }
        }
        println!("Terminated.");
    */
}
