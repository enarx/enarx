#[macro_use]
extern crate serde_derive;

use rand::Rng;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use warp::http::StatusCode;
use warp::Filter;

pub const PROTO_VERSION: f32 = 0.1;
pub const PROTO_NAME: &str = "Enarx-Keep-Manager";
pub const BIND_PORT: u16 = 3030;

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

//TODO: move this to lib.rs or similar
mod models {
    use glob::glob;
    use serde_derive::{Deserialize, Serialize};
    use std::fs;
    use std::io::prelude::*;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    //TODO - put this in the right place
    pub const KEEP_INFO_COMMAND: &str = "keep-info";

    pub type KeepLoaderList = Arc<Mutex<Vec<KeepLoader>>>;

    #[derive(Serialize, Deserialize, Clone)]
    pub struct KeepLoader {
        pub state: u8,
        pub kuuid: usize,
        pub app_loader_bind_port: u16,
        pub bindaddress: String,
        //we may wish to add information here about whether we're happy to share
        // all of this information with external parties, but since the keeploader
        // is operating outside the TEE boundary, there's only so much we can do
        // to keep this information confidential
    }

    #[derive(Serialize, Deserialize)]
    pub struct JsonCommand {
        pub commandtype: String,
        pub commandcontents: String,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct KeepLoaderVec {
        pub klvec: Vec<KeepLoader>,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct UndefinedReply {
        pub text: String,
    }

    pub fn new_empty_KeepLoaderList() -> KeepLoaderList {
        Arc::new(Mutex::new(Vec::new()))
    }

    pub async fn find_existing_keep_loaders() -> KeepLoaderList {
        println!("Looking for existing keep-loaders in /tmp");
        let mut kllvec = new_empty_KeepLoaderList();
        for existing_keeps in glob("/tmp/enarx-keep-*.sock").expect("Failed to read glob pattern") {
            //println!("keep-loader = {:?}", &existing_keeps);
            match existing_keeps {
                Ok(path) => {
                    let stream_result = UnixStream::connect(path.clone());
                    match stream_result {
                        Ok(mut stream) => {
                            println!("Able to connect to {:?}", path.display());
                            //TODO - add to list
                            //this is what we'll add, but first we need to contact the
                            //keep-loader and find out what the kuuid and app_loader_bind_port are
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
                                    Err(e) => println!("not a useful reply"),
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
    use super::models::{JsonCommand, KeepLoader, KeepLoaderList, KeepLoaderVec, UndefinedReply};
    use fork::{daemon, setsid, Fork};
    use rand::Rng;
    use serde_json::json;
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::io::prelude::*;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    //    use subprocess::Exec;
    use warp::Filter;

    //there's got to be a better way of doing this (enums?) in a lib.rs file?
    pub const CONTRACT_COMMAND: &str = "command";
    pub const KEEP_COMMAND: &str = "command";
    pub const KEEP_AUTH: &str = "auth-token";
    pub const KEEP_KUUID: &str = "kuuid";
    pub const KEEP_ARCH: &str = "keep-arch";
    pub const KEEP_ARCH_WASI: &str = "wasi";
    pub const KEEP_ARCH_SEV: &str = "AMD-SEV";
    pub const KEEP_ARCH_SGX: &str = "Intel-SGX";
    pub const KEEP_APP_LOADER_BIND_PORT: &str = "app-loader-bind-port";
    pub const APP_LOADER_BIND_PORT_START: u16 = 3031;
    pub const KEEP_APP_LOADER_STATE_UNDEF: u8 = 0;
    pub const KEEP_INFO_COMMAND: &str = "keep-info";

    pub const KEEP_APP_LOADER_START_COMMAND: &str = "apploader-start"; // requires app_loader_bind_port to be provided

    pub fn with_keeploaderlist(
        keeploaderlist: KeepLoaderList,
    ) -> impl Filter<Extract = (KeepLoaderList,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || keeploaderlist.clone())
    }

    pub fn new_keep(authtoken: &str, apploaderbindport: u16) -> KeepLoader {
        let new_kuuid = rand::random::<usize>();

        println!("Received auth_token {}", authtoken);
        println!("About to spawn new keep-loader");
        //TODO - the chances should be _pretty_ low, but should
        // we check for an existing keep?
        //TODO - remove hard-coded systemd-escape sequence ("\x20")
        let service_cmd = format!("enarx-keep@{}\\x20{}.service", new_kuuid, apploaderbindport);
        println!("service_cmd = {}", service_cmd);
        let mut child = Command::new("systemctl")
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
            state: KEEP_APP_LOADER_STATE_UNDEF,
            kuuid: new_kuuid,
            app_loader_bind_port: apploaderbindport,
            bindaddress: "".to_string(),
        };
        new_keeploader
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
                let mut supported: bool = false;
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
                    let mut kllvec = keeploaderlist.lock().await;

                    //we reserve a port for the app-loader to bind on here,
                    // as there's no other point at which we can be sure what's available,
                    // and we have a mutex here, so we should use it.  There's obviously
                    // a possible issue that other apps on the host might take this, but
                    // there's little we can do about this.  This all assumes, of course,
                    // that we're listening on the host's IP address, which is not
                    // assured.  This needs thinking about.
                    //
                    //use the Mutex here
                    let ap_bind_port: u16 = kllvec.len() as u16 + APP_LOADER_BIND_PORT_START;
                    let new_keeploader = new_keep(authtoken, ap_bind_port);
                    println!(
                        "Keeploaderlist currently has {} entries, about to add {}",
                        kllvec.len(),
                        new_keeploader.kuuid,
                    );
                    let new_kuuid = (new_keeploader.kuuid).clone();
                    kllvec.push(new_keeploader.clone());
                    json_reply = warp::reply::json(&new_keeploader);
                } else {
                    let new_keeploader = KeepLoader {
                        state: KEEP_APP_LOADER_STATE_UNDEF,
                        kuuid: 0,
                        app_loader_bind_port: 0,
                        bindaddress: "".to_string(),
                    };
                    json_reply = warp::reply::json(&new_keeploader);
                }
            }
            "list-keeps" => {
                let kllvec = keeploaderlist.lock().await;
                let kllvec: Vec<KeepLoader> = kllvec.clone().into_iter().collect();
                let json_keeploadervec = KeepLoaderVec { klvec: kllvec };

                json_reply = warp::reply::json(&json_keeploadervec);
            }
            "start-keep" => {
                // println!("command_group = {:?}", command_group);
                let kuuid: usize = command_group.get(KEEP_KUUID).unwrap().parse().unwrap();
                //need port binding information, at least
                //this needs to come from an external source, in case we've recreated the
                //list of Keeploaders, and don't have port binding info for each
                let app_loader_bind_port: u16 = command_group
                    .get(KEEP_APP_LOADER_BIND_PORT)
                    .unwrap()
                    .parse()
                    .unwrap();
                println!("apploaderbindport = {}", app_loader_bind_port);
                let bind_socket = format!("/tmp/enarx-keep-{}.sock", kuuid);
                println!("About to connect to {}", &bind_socket);

                let jsoncommand = JsonCommand {
                    commandtype: String::from(KEEP_APP_LOADER_START_COMMAND),
                    commandcontents: app_loader_bind_port.to_string(),
                };
                let serializedjson =
                    serde_json::to_string(&jsoncommand).expect("problem serializing data");
                /*                let data_part_1 = r#"
                {
                    "keep-start": ""#;
                        let data_part_2 = r#""
                }"#;
                        let data = format!("{}{}{}", data_part_1, app_loader_bind_port, data_part_2);*/
                println!("Sending JSON data\n{}", serializedjson);

                let mut stream = UnixStream::connect(bind_socket).expect("failed to connect");
                &stream
                    .write_all(&serializedjson.as_bytes())
                    .expect("failed to write");
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
