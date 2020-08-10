#[macro_use]
extern crate serde_derive;

use serde_json::{Deserializer, Value};
use std::io::prelude::*;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;

fn main() {
    //get and parse args
    let args: Vec<String> = std::env::args().collect();
    //store auth-token
    //bind to unix socket
    //await commands
    //TODO - remove hard-coding!
    let kuuid = args[1].clone();
    let bind_socket = format!("/tmp/enarx-keep-{}.sock", kuuid);

    let data = r#"
        {
            "auth-token": "a1b2c3"
        }"#;
    println!("Sending JSON data\n{}", data);

    let mut stream = UnixStream::connect(bind_socket).expect("failed to connect");
    stream.write_all(&data.as_bytes()).expect("failed to write");
}

fn keep_loader_connection(stream: UnixStream) {
    let deserializer = serde_json::Deserializer::from_reader(stream);
    let iterator = deserializer.into_iter::<serde_json::Value>();
    for json_pair in iterator {
        println!("Received {:?}", json_pair);
    }

    //Ok(())
}
