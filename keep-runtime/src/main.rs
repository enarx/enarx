// SPDX-License-Identifier: Apache-2.0

//! The Enarx Keep runtime binary.
//!
//! It can be used to run a Wasm file with given command-line
//! arguments and environment variables.
//!
//! ## Example invocation
//!
//! ```console
//! $ RUST_LOG=keep_runtime=info RUST_BACKTRACE=1 cargo run target/debug/fixtures/return_1.wasm
//!    Compiling keep-runtime v0.1.0 (/home/steveej/src/job-redhat/enarx/github_enarx_enarx/keep-runtime)
//!     Finished dev [unoptimized + debuginfo] target(s) in 4.36s
//!      Running `target/debug/keep-runtime`
//! [2020-01-23T21:58:16Z INFO  keep_runtime] got result: [
//!         I32(
//!             1,
//!         ),
//!     ]
//! ```
//!

#![deny(missing_docs)]
#![deny(clippy::all)]
//#![feature(proc_macro_hygiene, decl_macro)]

mod workload;

#[macro_use]
extern crate serde_derive;

use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509Name, X509NameBuilder, X509};

//use std::collections::HashMap;
use std::path::Path;
//use warp::http::StatusCode;
use warp::Filter;
#[derive(Serialize, Deserialize)]
struct Payload {
    encoding: String,
    contents: Vec<u8>,
}

use log::info;
/// Source of the key to use for TLS
//pub const KEY_SOURCE: &str = "file-system";
pub const KEY_SOURCE: &str = "generate";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let listen_port: u16 = args[0].parse().unwrap();
    let (server_key, server_cert) = get_credentials_bytes();

    // POST /payload
    let workload = warp::post()
        .and(warp::path("payload"))
        .and(warp::body::json())
        .and_then(payload_launch);

    let routes = workload;
    warp::serve(routes)
        .tls()
        .cert(&server_cert)
        .key(&server_key)
        //TODO - fix this so that we can bind to other IP addresses
        .run(([127, 0, 0, 1], listen_port))
        .await;
}

fn create_new_runtime(recvd_data: &[u8]) {
    format!("About to attempt new runtime creation");
    let _ = env_logger::try_init_from_env(env_logger::Env::default());
    //TODO - get args these from main() if required
    //    let args = std::env::args().skip(1);
    let dummy_arr: [&str; 1] = [""];
    let vars = std::env::vars();

    let result = workload::run(recvd_data, &dummy_arr, vars).expect("Failed to run workload");
    println!("Got result (println) {:#?}", result);
    info!("got result: {:#?}", result);
}

async fn payload_launch(payload: Payload) -> Result<impl warp::Reply, warp::Rejection> {
    format!("Received a {} file", payload.encoding);
    println!("Received a {} file", payload.encoding);
    create_new_runtime(&payload.contents);
    Ok(warp::reply::with_status(
        "Payload received",
        warp::http::StatusCode::OK,
    ))
}

fn get_credentials_bytes() -> (Vec<u8>, Vec<u8>) {
    let mut key: Vec<u8> = Vec::new();
    let mut cert: Vec<u8> = Vec::new();
    let (key, cert) = match KEY_SOURCE {
        "file-system" => (get_key_bytes_fs(), get_cert_bytes_fs()),
        "generate" => (generate_credentials()),
        //no match!
        _ => panic!("No match for credentials source"),
    };
    (key, cert)
}

//implementation for file system
fn get_cert_bytes_fs() -> Vec<u8> {
    let in_path = Path::new("key-material/server.crt");

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
    in_contents
}

//implementation for file system
fn get_key_bytes_fs() -> Vec<u8> {
    println!("Generating server key (PEM)");
    let in_path = Path::new("key-material/server.key");

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
    in_contents
}

//TODO - this is vital code, and needs to be carefully audited!
fn generate_credentials() -> (Vec<u8>, Vec<u8>) {
    let key = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(key.clone()).unwrap();

    let mut x509_name = openssl::x509::X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_text("C", "GB").unwrap();
    x509_name.append_entry_by_text("O", "enarx-test").unwrap();
    x509_name.append_entry_by_text("CN", "127.0.0.1").unwrap();
    let x509_name = x509_name.build();

    let mut x509_builder = openssl::x509::X509::builder().unwrap();
    x509_builder.set_not_before(&Asn1Time::days_from_now(0).unwrap());
    x509_builder.set_not_after(&Asn1Time::days_from_now(7).unwrap());
    x509_builder.set_subject_name(&x509_name).unwrap();
    x509_builder.set_pubkey(&pkey).unwrap();
    x509_builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let certificate = x509_builder.build();

    (
        key.private_key_to_pem().unwrap(),
        certificate.to_pem().unwrap(),
    )
}
