// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate serde_derive;

use ::host_components::*;
use std::io::prelude::*;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

//IMPORTANT - after every change to this file, the following steps need to be run:
// remove link file in /etc/systemd/user/
// recreate link file in /etc/systemd/user/
// `systemctl daemon-reload`
/*
pub const KEEP_INFO_COMMAND: &str = "keep-info";
pub const KEEP_APP_LOADER_START_COMMAND: &str = "apploader-start"; // requires app_loader_bind_port to be provided
pub const KEEP_LOADER_STATE_UNDEF: u8 = 0;
pub const KEEP_LOADER_STATE_LISTENING: u8 = 1;
pub const KEEP_LOADER_STATE_STARTED: u8 = 2;
pub const KEEP_LOADER_STATE_COMPLETE: u8 = 3;
pub const KEEP_LOADER_STATE_ERROR: u8 = 15;
*/
//TODO - put in a shared space
#[derive(Serialize, Deserialize)]
struct JsonCommand {
    commandtype: String,
    commandcontents: String,
}

fn main() {
    println!("Welcome to a new keep-loader");

    //get and parse args
    let args: Vec<String> = std::env::args().collect();
    //bind to unix socket
    //await commands
    //TODO - remove hard-coding!
    println!("Keep-loader has received {} args", args.len());
    let kuuid = args[1].clone();
    println!("kuuid = {}", kuuid);
    let bind_socket = format!("/tmp/enarx-keep-{}.sock", kuuid);
    println!("binding to {}", bind_socket);
    let keepapploader = Arc::new(Mutex::new(build_keepapploader(
        KEEP_LOADER_STATE_UNDEF,
        kuuid.parse().expect("problems parsing kuuid"),
        0,
        "".to_string(),
    )));

    let listener = UnixListener::bind(bind_socket).unwrap();
    //initialise state as listening
    //TODO - error checking
    let set_state_result = set_state(KEEP_LOADER_STATE_LISTENING, keepapploader.clone());
    match set_state_result {
        Ok(_v) => {}
        Err(e) => println!("Error setting state, {}", e),
    }

    //only one bind at a time expected here (check for auth-token?)
    //but our connectee may drop, so keep listening
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let childstate = keepapploader.clone();
                thread::spawn(move || keep_loader_connection(stream, childstate));
            }
            Err(err) => {
                println!("Keep-loader error in stream: {}", err);
                //TODO - something better here, including clean-up for /tmp file
                panic!("Stream error {}", err);
            }
        }
    }
}

fn build_keepapploader(
    state: u8,
    kuuid: usize,
    app_loader_bind_port: u16,
    bindaddress: String,
) -> KeepLoader {
    KeepLoader {
        state: state,
        kuuid: kuuid,
        app_loader_bind_port: app_loader_bind_port,
        bindaddress: bindaddress,
    }
}

fn keep_loader_connection(stream: UnixStream, keepapploader: Arc<Mutex<KeepLoader>>) {
    //the below values are very much fall-backs
    let mut app_addr: String = String::from("127.0.0.1");
    let mut app_port: u16 = APP_LOADER_BIND_PORT_START;

    //let mut json_pair: serde_json::value::Value;
    let mut stream = &stream;
    let deserializer = serde_json::Deserializer::from_reader(stream);
    let iterator = deserializer.into_iter::<serde_json::Value>();

    let kal = keepapploader.clone();

    for json_pair in iterator {
        match json_pair {
            Ok(value) => {
                let json_command: JsonCommand = serde_json::from_value(value).unwrap();
                match json_command.commandtype.as_str() {
                    KEEP_APP_LOADER_ADDR => {
                        app_addr = json_command.commandcontents;
                        kal.lock().unwrap().bindaddress = app_addr.clone();
                    }
                    KEEP_APP_LOADER_PORT => {
                        app_port = json_command
                            .commandcontents
                            .parse()
                            .expect("problems parsing port information");
                        kal.lock().unwrap().app_loader_bind_port = app_port.clone();
                    }
                    KEEP_APP_LOADER_START_COMMAND => {
                        println!("About to spawn, listening on port {}", app_port.to_string());
                        let child_spawn_result = Command::new(WASM_RUNTIME_BINARY_PATH)
                            .arg(&app_addr)
                            .arg(app_port.to_string())
                            .spawn();
                        match &child_spawn_result {
                            Ok(_v) => {
                                let state_result =
                                    set_state(KEEP_LOADER_STATE_STARTED, kal.clone());
                                match state_result {
                                    Ok(_v) => println!("Spawned new runtime, set state"),
                                    Err(e) => {
                                        println!("Spawned new runtime, no state set due to {}!", e)
                                    }
                                }
                                println!("Set state attempted");
                                println!("State = {}", kal.lock().unwrap().state);
                            }
                            Err(e) => {
                                println!("Error spawning runtime {:?}", e);
                            }
                        }
                    }
                    KEEP_INFO_COMMAND => {
                        //provide information back
                        let keepresponse: KeepLoader = kal.lock().unwrap().clone();
                        println!(
                            "Sending data about KeepLoader, status {}",
                            &keepresponse.state
                        );
                        let serializedjson =
                            serde_json::to_string(&keepresponse).expect("problem serializing data");
                        println!("Sending JSON data from keep-loader\n{}", serializedjson);
                        &stream
                            .write_all(&serializedjson.as_bytes())
                            .expect("failed to write");
                    }
                    _ => println!("Unknown command received"),
                }
            }
            Err(e) => println!("Problem parsing command to keep-loader: {}", e),
        }
    }
}

fn set_state(desired_state: u8, keeploaderapp: Arc<Mutex<KeepLoader>>) -> Result<String, String> {
    let mut keep_app = keeploaderapp.lock().unwrap();
    let mut transition_ok = false;
    println!(
        "Attempting to move from state {} to state {}",
        &keep_app.state, &desired_state
    );
    //DEBT: this code works, but is ugly.  Re-write needed.
    //logic for state machine here - there are lots of ways to do this, and this version
    // can probably be optimised
    // options:
    // KEEP_LOADER_STATE_UNDEF
    // KEEP_LOADER_STATE_LISTENING
    // KEEP_LOADER_STATE_STARTED
    // KEEP_LOADER_STATE_COMPLETE
    // KEEP_LOADER_STATE_ERROR
    //
    //TODO - consider taking this back to a set of match statements?
    // (previously had some problems with fallthrough?)
    //note - if you mistype these variable names, Rust sometimes fails to match
    // silently - unclear why
    if keep_app.state == KEEP_LOADER_STATE_UNDEF {
        match desired_state {
            KEEP_LOADER_STATE_LISTENING => {
                transition_ok = true;
            }
            KEEP_LOADER_STATE_ERROR => transition_ok = true,
            _ => transition_ok = false,
        }
    } else if keep_app.state == KEEP_LOADER_STATE_LISTENING {
        match desired_state {
            KEEP_LOADER_STATE_STARTED => transition_ok = true,
            KEEP_LOADER_STATE_ERROR => transition_ok = true,
            _ => transition_ok = false,
        }
    } else if keep_app.state == KEEP_LOADER_STATE_STARTED {
        match desired_state {
            KEEP_LOADER_STATE_COMPLETE => transition_ok = true,
            KEEP_LOADER_STATE_ERROR => transition_ok = true,
            _ => transition_ok = false,
        }
    } else if keep_app.state == KEEP_LOADER_STATE_COMPLETE {
        match desired_state {
            KEEP_LOADER_STATE_ERROR => transition_ok = true,
            _ => transition_ok = false,
        }
    } else if keep_app.state == KEEP_LOADER_STATE_ERROR {
        match desired_state {
            KEEP_LOADER_STATE_ERROR => transition_ok = true,
            _ => transition_ok = false,
        }
    } else {
        println!("State not recognised");
    }

    if transition_ok {
        keep_app.state = desired_state;
        println!("Transitioning to {} state", &keep_app.state);
        Ok(format!("State transitioned to {}", &keep_app.state))
    } else {
        println!("Staying in {} state", &keep_app.state);
        Err(format!("No state transition, still in {}", &keep_app.state))
    }
}
