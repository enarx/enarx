// SPDX-License-Identifier: Apache-2.0

extern crate reqwest;
extern crate serde_derive;

use ::host_components::*;
use std::collections::HashMap;
//TODO - better user input
use std::io;

fn main() {
    let mut user_input = String::new();

    let mut command_list_all: HashMap<String, String> = HashMap::new();
    command_list_all.insert("command".to_string(), "list-all".to_string());
    let mut command_new_keep: HashMap<String, String> = HashMap::new();
    command_new_keep.insert("command".to_string(), "new-keep".to_string());
    command_new_keep.insert("keep-arch".to_string(), "wasi".to_string());
    command_new_keep.insert("auth-token".to_string(), "a3f9cb07".to_string());
    let mut command_list_keeps: HashMap<String, String> = HashMap::new();
    command_list_keeps.insert("command".to_string(), "list-keeps".to_string());

    println!("Welcome to the Enarx keep-manager tester.");
    println!("We will step through a number of tests.  First ensure that you are running a");
    println!("keep-manager on localhost port 3030 (the default).");
    println!("");
    println!("First test is against unimplemented backend code, and should fail!");
    println!("Press <Enter>");
    io::stdin()
        .read_line(&mut user_input)
        .expect("Failed to read line");

    //NOTE - this should fail: not currently implemented
    let builder = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post("https://localhost:3032/contracts_post/")
        .json(&command_list_all);
    let res = builder.send();
    println!("{:#?}", res);

    println!("");
    println!("Press <Enter> to create a Keep");

    io::stdin()
        .read_line(&mut user_input)
        .expect("Failed to read line");

    //construct a couple of keeps with command1
    let res1: reqwest::blocking::Response = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post("https://localhost:3030/keeps_post/")
        .json(&command_new_keep)
        .send()
        .expect("Possible issues");

    let keeploader1: KeepLoader = res1.json().expect("Possible issues");
    println!("Keep created with kuuid = {}", keeploader1.kuuid);

    println!("");
    println!("Press <Enter> to create another Keep");

    io::stdin()
        .read_line(&mut user_input)
        .expect("Failed to read line");

    let res2: reqwest::blocking::Response = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post("https://localhost:3030/keeps_post/")
        .json(&command_new_keep)
        .send()
        .expect("Possible issues");
    //let content2 = res2.text();
    let keeploader2: KeepLoader = res2.json().expect("Possible issues");
    println!("Keep created with kuuid = {}", keeploader2.kuuid);

    println!("");
    println!("Press <Enter> to list keeps.  This may include more than the Keeps you just");
    println!("created if the keep-manager is long-lived");
    println!("");

    io::stdin()
        .read_line(&mut user_input)
        .expect("Failed to read line");

    //list keeps
    let res3 = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post("https://localhost:3030/keeps_post/")
        .json(&command_list_keeps)
        .send()
        .expect("Possible issues");
    let keeploadervec: KeepLoaderVec = res3.json().expect("Possible issues");
    //TODO - output
    println!("State 0  = undefined (awaiting start)");
    println!("State 1  = listening for commands");
    println!("State 2  = started (awaiting workload)");
    println!("State 3  = completed");
    println!("State 15 = error state\n");
    for keeploader in &keeploadervec.klvec {
        println!(
            "Keep kuuid {}, state {}, listening on {}:{}",
            keeploader.kuuid,
            keeploader.state,
            keeploader.bindaddress,
            keeploader.app_loader_bind_port
        );
    }

    let number_of_kls = &keeploadervec.klvec.len();
    println!("We have {} Keep-loaders", number_of_kls);
    println!("");
    if *number_of_kls < 1 {
        panic!("We don't have any keep-loaders to start, sorry!  This is an error.");
    }
    println!("Press <Enter> to start the most recently created Keep");

    io::stdin()
        .read_line(&mut user_input)
        .expect("Failed to read line");

    println!(
        "About to send start-keep command for kuuid {}, to listen on port {}",
        &keeploadervec.klvec.last().unwrap().kuuid.to_string(),
        &keeploadervec.klvec[number_of_kls - 1]
            .app_loader_bind_port
            .to_string()
    );
    let mut command_start_keep: HashMap<String, String> = HashMap::new();
    command_start_keep.insert("command".to_string(), "start-keep".to_string());
    command_start_keep.insert(
        "kuuid".to_string(),
        keeploadervec.klvec.last().unwrap().kuuid.to_string(),
    );
    command_start_keep.insert(
        "app-loader-bind-port".to_string(),
        keeploadervec.klvec[number_of_kls - 1]
            .app_loader_bind_port
            .to_string(),
    );

    //start the first keep in our list
    let _res4 = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post("https://localhost:3030/keeps_post/")
        .json(&command_start_keep)
        .send()
        .expect("Possible issues");

    println!("");
    println!("If you got here with no unexpected errors, then we have succeeded!");
    println!("");
    println!(
        "Next, you probably want to load an application into your recently-started Keep using the"
    );
    println!("command eg.app-loader-tester, with a single argument: the port on which it should");
    println!("be listening:");
    println!(
        "   e.g. ./target/debug/app-loader-tester {}",
        keeploadervec.klvec[number_of_kls - 1]
            .app_loader_bind_port
            .to_string()
    );
    println!("");
    println!("Good luck!");
    println!("");
    println!("Join us at https://chat.enarx.dev");
    println!("           https://github.io/enarx");
}
