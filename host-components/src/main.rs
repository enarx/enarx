// SPDX-License-Identifier: Apache-2.0

extern crate serde_derive;

use ::host_components::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use warp::Filter;

#[tokio::main]
async fn main() {
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), BIND_PORT);

    let keeploaderlist = models::find_existing_keep_loaders();

    // TODO: in case there are existing keeploaders out there, try finding them at
    //  /tmp/enarx-keep-*.sock, try connecting to them, if OK, add to
    //  keeploaderlist
    // TODO: what if we can't connect?  should we delete them?  Mark them dead?
    // Match any non-explicitly managed requests "/" request and return
    let declare = warp::any().map(|| {
        format!(
            "Protocol_name = {}\nProtocol_version = {}",
            PROTO_NAME, PROTO_VERSION
        )
    });

    let keep_posts = warp::post()
        .and(warp::path("keeps_post"))
        .and(warp::body::json())
        .and(filters::with_keeploaderlist(keeploaderlist.await))
        .and_then(filters::keeps_parse);

    let routes = keep_posts.or(declare);
    println!(
        "Starting server on {}, {} v{}",
        BIND_PORT, PROTO_NAME, PROTO_VERSION
    );
    warp::serve(routes)
        .tls()
        .cert_path("key-material/server.crt")
        .key_path("key-material/server.key")
        .run(socket)
        .await;
}

mod models {
    use ::host_components::*;
    use glob::glob;
    use std::io::prelude::*;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    pub fn new_empty_keeploaderlist() -> KeepLoaderList {
        Arc::new(Mutex::new(Vec::new()))
    }

    pub async fn find_existing_keep_loaders() -> KeepLoaderList {
        println!("Looking for existing keep-loaders in /tmp");
        let kllvec = new_empty_keeploaderlist();
        for existing_keeps in glob("/tmp/enarx-keep-*.sock").expect("Failed to read glob pattern") {
            //println!("keep-loader = {:?}", &existing_keeps);
            //TODO - rework this code - it's fairly brittle.  As an iterator.next(), maybe?
            match existing_keeps {
                Ok(path) => {
                    let stream_result = UnixStream::connect(path.clone());
                    match stream_result {
                        Ok(mut stream) => {
                            println!("Able to connect to {:?}", path.display());
                            //this is what we'll add, but first we need to contact the
                            //keep-loader and find out information about the Keep
                            let jsoncommand = JsonCommand {
                                commandtype: String::from(KEEP_INFO_COMMAND),
                                commandcontents: "".to_string(),
                            };
                            let serializedjson = serde_json::to_string(&jsoncommand)
                                .expect("problem serializing data");

                            //println!("Sending JSON data\n{}", serializedjson);
                            &stream
                                .write_all(&serializedjson.as_bytes())
                                .expect("failed to write");
                            //now get a reply
                            let deserializer = serde_json::Deserializer::from_reader(stream);
                            let iterator = deserializer.into_iter::<serde_json::Value>();
                            for json_pair in iterator {
                                println!(
                                    "Got a reply from {}, which is {:?}",
                                    path.display(),
                                    &json_pair
                                );
                                match json_pair {
                                    Ok(value) => {
                                        let keeploader: KeepLoader =
                                            serde_json::from_value(value).unwrap();
                                        let mut keeploaderlist = kllvec.lock().await;
                                        println!(
                                            "keeploader on {} has kuuid {}",
                                            path.display(),
                                            keeploader.kuuid,
                                        );
                                        keeploaderlist.push(keeploader);
                                        println!("Pushed keeploader to list");
                                    }
                                    Err(e) => println!("not a useful reply {}", e),
                                }

                                break;
                            }
                        }
                        Err(_) => println!("Unable to connect to {:?}", path.display()),
                    }
                }
                Err(e) => println!("{:?}", e),
            }
        }
        println!("Completed iterating through keep-loaders");
        kllvec
    }
}

mod filters {
    use ::host_components::*;
    use std::collections::{HashMap, HashSet};
    use std::convert::Infallible;
    use std::io::prelude::*;
    use std::os::unix::net::UnixStream;
    use std::process::Command;
    use warp::Filter;

    pub fn with_keeploaderlist(
        keeploaderlist: KeepLoaderList,
    ) -> impl Filter<Extract = (KeepLoaderList,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || keeploaderlist.clone())
    }

    pub fn new_keep(
        authtoken: &str,
        apploaderbindport: u16,
        apploaderbindaddr: &str,
    ) -> KeepLoader {
        let new_kuuid = rand::random::<usize>();

        println!("Received auth_token {}", authtoken);
        println!("About to spawn new keep-loader");
        //TODO - the chances should be _pretty_ low, but should
        // we check for an existing keep?
        //TODO - remove hard-coded systemd-escape sequence ("\x20")
        let service_cmd = format!(
            "enarx-keep@{}\\x20{}\\x20{}.service",
            new_kuuid, apploaderbindaddr, apploaderbindport
        );
        println!("service_cmd = {}", service_cmd);
        let _child = Command::new("systemctl")
            .arg("--user")
            .arg("start")
            .arg(service_cmd)
            .output()
            .expect("failed to execute child");

        println!("Spawned new keep-loader");
        println!(
            "Got this far with authtoken = {}, new_kuuid = {}, apploaderbindport = {}",
            authtoken, new_kuuid, apploaderbindport
        );

        let new_keeploader = KeepLoader {
            state: KEEP_LOADER_STATE_UNDEF,
            kuuid: new_kuuid,
            app_loader_bind_port: apploaderbindport,
            bindaddress: "".to_string(),
        };
        new_keeploader
    }

    pub fn assign_port(kllvec: Vec<KeepLoader>, requestedport: u16) -> u16 {
        let mut assigned_ports: HashSet<u16> = HashSet::new();
        for existing in kllvec.iter() {
            assigned_ports.insert(existing.app_loader_bind_port);
        }
        let chosen_port: u16;
        if !assigned_ports.contains(&requestedport) {
            chosen_port = requestedport;
        } else {
            let mut check_port: u16 = APP_LOADER_BIND_PORT_START;
            for check_add in 0..kllvec.len() {
                check_port = APP_LOADER_BIND_PORT_START + check_add as u16;
                println!("check_port = {}", &check_port);
                if !assigned_ports.contains(&check_port) {
                    break;
                }
                check_port = check_port + 1;
            }
            chosen_port = check_port;
        }
        chosen_port
    }

    pub async fn keeps_parse(
        command_group: HashMap<String, String>,
        keeploaderlist: KeepLoaderList,
    ) -> Result<impl warp::Reply, Infallible> {
        //NOTE - is this actually Infallible?
        //   ) -> Result<impl warp::Reply, warp::Rejection> {

        let undefined = UndefinedReply {
            text: String::from("undefined"),
        };
        let mut json_reply = warp::reply::json(&undefined);

        match command_group.get(KEEP_COMMAND).unwrap().as_str() {
            "new-keep" => {
                let supported: bool;
                println!("new-keep ...");
                let authtoken = command_group.get(KEEP_AUTH).unwrap();
                let keeparch = command_group.get(KEEP_ARCH).unwrap().as_str();
                match keeparch {
                    KEEP_ARCH_WASI => {
                        //currently only supported option
                        supported = true;
                        println!("wasi keep to be started");
                    }
                    KEEP_ARCH_SEV => {
                        //currently unsupported
                        //TODO - better error-handling
                        supported = false;
                    }
                    KEEP_ARCH_SGX => {
                        //currently unsupported
                        //TODO - better error-handling
                        supported = false;
                    }
                    _ => {
                        //default to nothing, for safety
                        supported = false;
                    }
                }

                if supported {
                    let mut kll = keeploaderlist.lock().await;
                    let new_keeploader = new_keep(authtoken, 0, "");
                    println!(
                        "Keeploaderlist currently has {} entries, about to add {}",
                        kll.len(),
                        new_keeploader.kuuid,
                    );
                    //add this new new keeploader to the list
                    kll.push(new_keeploader.clone());
                    json_reply = warp::reply::json(&new_keeploader);
                } else {
                    let new_keeploader = KeepLoader {
                        state: KEEP_LOADER_STATE_ERROR,
                        kuuid: 0,
                        app_loader_bind_port: 0,
                        bindaddress: "".to_string(),
                    };
                    //this is an empty, unsupported Keep
                    json_reply = warp::reply::json(&new_keeploader);
                }
            }
            "list-keeps" => {
                //update list
                let kll = keeploaderlist.lock().await;

                let kllvec: Vec<KeepLoader> = kll.clone().into_iter().collect();
                for keeploader in &kllvec {
                    println!(
                        "Keep kuuid {}, state {}, listening on {}:{}",
                        keeploader.kuuid,
                        keeploader.state,
                        keeploader.bindaddress,
                        keeploader.app_loader_bind_port
                    );
                }
                let json_keeploadervec = KeepLoaderVec { klvec: kllvec };

                json_reply = warp::reply::json(&json_keeploadervec);
            }
            "start-keep" => {
                let mut kll = keeploaderlist.lock().await;
                let kllvec: Vec<KeepLoader> = kll.clone().into_iter().collect();
                let kuuid: usize = command_group.get(KEEP_KUUID).unwrap().parse().unwrap();

                let keepaddr_opt = command_group.get(KEEP_ADDR);
                let keepport_opt = command_group.get(KEEP_PORT);
                let ap_bind_addr: &str;
                let ap_bind_port: u16;
                //TODO - need unit tests for this
                match keepaddr_opt {
                    Some(addr) => {
                        println!("start-keep received {}", &addr);
                        ap_bind_addr = addr;
                        //if we have been provided with a port, we use that,
                        // if not, default to default (APP_LOADER_BIND_PORT_START).
                        // ASSERT: we cannot be expected to manage all possible
                        //  IP addresses and associated ports
                        match keepport_opt {
                            Some(port) => {
                                println!("... and port {}", port);
                                match ap_bind_addr {
                                    //deal with the case where we're on localhost, in which case
                                    // we'll auto-assign
                                    "127.0.0.1" => {
                                        ap_bind_port =
                                            assign_port(kllvec.clone(), APP_LOADER_BIND_PORT_START)
                                    }
                                    &_ => {
                                        ap_bind_port = port.parse().expect("Problems parsing port")
                                    }
                                }
                            }
                            None => match ap_bind_addr {
                                "127.0.0.1" => {
                                    ap_bind_port =
                                        assign_port(kllvec.clone(), APP_LOADER_BIND_PORT_START)
                                }
                                &_ => ap_bind_port = APP_LOADER_BIND_PORT_START,
                            },
                        }
                    }
                    //if we have no address, then we use localhost and try suggested
                    // but auto-assign if it's already taken
                    None => {
                        println!("start-keep received no address, so starting on localhost");
                        ap_bind_addr = "127.0.0.1";
                        //request the very first available port
                        // assign_port will grant the next available if
                        // APP_LOADER_BIND_PORT_START is not available
                        ap_bind_port = assign_port(kllvec.clone(), APP_LOADER_BIND_PORT_START);
                    }
                }
                let bind_socket = format!("/tmp/enarx-keep-{}.sock", &kuuid);

                //construct commands with the relevant details
                let json_set_app_addr = JsonCommand {
                    commandtype: String::from(KEEP_APP_LOADER_ADDR),
                    commandcontents: ap_bind_addr.to_string(),
                };
                let json_set_app_port = JsonCommand {
                    commandtype: String::from(KEEP_APP_LOADER_PORT),
                    commandcontents: ap_bind_port.to_string(),
                };
                let json_start_command = JsonCommand {
                    commandtype: String::from(KEEP_APP_LOADER_START_COMMAND),
                    commandcontents: "".to_string(),
                };
                let serializedjson_addr =
                    serde_json::to_string(&json_set_app_addr).expect("problem serialising data");
                let serializedjson_port =
                    serde_json::to_string(&json_set_app_port).expect("problem serialising data");
                let serializedjson_start =
                    serde_json::to_string(&json_start_command).expect("problem serialising data");
                println!("About to send address, port and start command to keep-loader");
                let mut stream = UnixStream::connect(bind_socket).expect("failed to connect");
                &stream
                    .write_all(&serializedjson_addr.as_bytes())
                    .expect("failed to write");
                &stream
                    .write_all(&serializedjson_port.as_bytes())
                    .expect("failed to write");
                &stream
                    .write_all(&serializedjson_start.as_bytes())
                    .expect("failed to write");
                //update the information about this keep-loader
                //TODO - update with a query on the keep-loader itself?
                //first find the correct entry in the list
                for k in 0..kll.len() {
                    let keeploader = &kll[k];
                    //for mut keeploader in kll {
                    if keeploader.kuuid == kuuid {
                        println!("About to update state for keep-loader with kuuid {}, address {}, port {}", kuuid, &ap_bind_addr, ap_bind_port);
                        &kll.remove(k);
                        let new_keeploader = KeepLoader {
                            state: KEEP_LOADER_STATE_STARTED,
                            kuuid: kuuid,
                            app_loader_bind_port: ap_bind_port,
                            bindaddress: ap_bind_addr.to_string(),
                        };
                        &kll.push(new_keeploader.clone());
                        break;
                    }
                }
            }

            &_ => {}
        }
        println!(
            "Received a {:?} command",
            command_group.get(KEEP_COMMAND).unwrap()
        );
        Ok(json_reply)
    }
}
