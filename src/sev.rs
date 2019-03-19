extern crate tiny_http;
extern crate colored;
extern crate reqwest;
extern crate clap;
extern crate sev;

use clap::ArgMatches;

use sev::fwapi::{Sev, Status, Identifier};
use sev::certs::{Certificate, Usage};

use std::process::exit;
use std::io::Write;
use std::fs::File;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const ARK: &[u8] = include_bytes!("certs/naples/ark.cert");
const ASK: &[u8] = include_bytes!("certs/naples/ask.cert");

fn download(rsp: reqwest::Result<reqwest::Response>, usage: Usage) -> Certificate {
    let mut rsp = rsp.expect(&format!("unable to contact {} server", usage));

    if !rsp.status().is_success() {
        panic!("received failure from {} server: {}", usage, rsp.status());
    }

    let mut buf = Vec::new();
    rsp.copy_to(&mut buf)
        .expect(&format!("unable to complete {} download", usage));

    usage.load(&mut &buf[..])
        .expect(&format!("unable to parse downloaded {}", usage))
}

fn write(matches: &ArgMatches, name: &str, output: &[u8]) -> ! {
    let mut file = File::create(matches.value_of(name).unwrap())
        .expect("unable to create output file");

    file.write_all(output).expect("unable to write output file");
    exit(0)
}

fn sev() -> Sev {
    sev::fwapi::Sev::new().expect("unable to open /dev/sev")
}

fn platform_status() -> Status {
    sev().platform_status().expect("unable to fetch platform status")
}

fn pdh_cert_export() -> [Certificate; 4] {
    sev().pdh_cert_export().expect("unable to export SEV certificates")
}

fn get_identifer() -> Identifier {
    sev().get_identifer().expect("error fetching identifier")
}

fn download_cek() -> Certificate {
    const CEK_SVC: &str = "https://kdsintf.amd.com/cek/id";

    let id = get_identifer();
    let url = format!("{}/{}", CEK_SVC, id);
    download(reqwest::get(&url), Usage::ChipEndorsementKey)
}

fn main() {
    use clap::{Arg, App, SubCommand};

    let matches = App::new("SEV Platform Control")
        .version(VERSION)
        .author("Nathaniel McCallum <npmccallum@redhat.com>")
        .about("Utilities for managing the SEV environement")

        .subcommand(SubCommand::with_name("platform")
            .about("Platform commands")

            .subcommand(SubCommand::with_name("reset")
                .about("Resets the SEV platform")
            )

            .subcommand(SubCommand::with_name("show")
                .about("Shows information about the SEV platform")
                .subcommand(SubCommand::with_name("guests")
                    .about("Show the current number of guests"))
                .subcommand(SubCommand::with_name("build")
                    .about("Show the current firmware build"))
                .subcommand(SubCommand::with_name("state")
                    .about("Show the current platform state"))
                .subcommand(SubCommand::with_name("flags")
                    .about("Show the current platform flags"))
                .subcommand(SubCommand::with_name("id")
                    .about("Show the CPU identifier"))
            )
        )

        .subcommand(SubCommand::with_name("chain")
            .about("Certificate chain commands")

            .subcommand(SubCommand::with_name("export")
                .about("Export the full SEV certificate chain")
                .arg(Arg::with_name("file").required(true))
            )

            .subcommand(SubCommand::with_name("verify")
                .about("Verify the full SEV certificate chain")
                .arg(Arg::with_name("sev")
                    .help("Read SEV chain from the specified file")
                    .takes_value(true)
                    .long("sev"))
                .arg(Arg::with_name("ca")
                    .help("Read CA chain from the specified file")
                    .takes_value(true)
                    .long("ca"))
            )

            .subcommand(SubCommand::with_name("show")
                .about("Show information about the certificate chain")
                .arg(Arg::with_name("sev")
                    .help("Read SEV chain from the specified file")
                    .takes_value(true)
                    .long("sev"))
                .arg(Arg::with_name("ca")
                    .help("Read CA chain from the specified file")
                    .takes_value(true)
                    .long("ca"))
            )
        )

        .subcommand(SubCommand::with_name("oca")
            .about("Owner Certification Authority commands")

            .subcommand(SubCommand::with_name("create")
                .about("Generate a new, self-signed OCA certificate and key")
                .arg(Arg::with_name("cert").required(true))
                .arg(Arg::with_name("key").required(true)))

            .subcommand(SubCommand::with_name("serve")
                .about("Run a server to handle OCA certificate signing requests")
                .arg(Arg::with_name("cert").required(true))
                .arg(Arg::with_name("key").required(true))
            )
        )

        .subcommand(SubCommand::with_name("pek")
            .about("Platform Endorsement Key commands")

            .subcommand(SubCommand::with_name("rotate")
                .about("Rotate the PEK")
                .arg(Arg::with_name("adopt")
                    .takes_value(true)
                    .long("adopt"))
            )
        )

        .subcommand(SubCommand::with_name("pdh")
            .about("Platform Diffie Hellman commands")

            .subcommand(SubCommand::with_name("rotate")
                .about("Rotate the PDH")
            )
        )

        .get_matches();

    match matches.subcommand() {
        ("platform", Some(m)) => platform::cmd(m),
        ("chain", Some(m)) => chain::cmd(m),
        ("oca", Some(m)) => oca::cmd(m),
        ("pek", Some(m)) => pek::cmd(m),
        ("pdh", Some(m)) => pdh::cmd(m),
        _ => {
            eprintln!("{}", matches.usage());
            exit(1);
        }
    }
}

mod platform {
    use super::*;
    use sev::fwapi::{Flags, State};

    pub fn cmd(matches: &ArgMatches) -> ! {
        match matches.subcommand() {
            ("reset", Some(m)) => reset(m),
            ("show", Some(m)) => show::cmd(m),
            _ => {
                eprintln!("{}", matches.usage());
                exit(1);
            }
        }
    }

    fn reset(_: &ArgMatches) -> ! {
        sev().platform_reset().expect("error resetting platform");
        exit(0)
    }

    mod show {
        use super::*;

        pub fn cmd(matches: &ArgMatches) -> ! {
            match matches.subcommand() {
                ("id", Some(_)) => {
                    println!("{}", get_identifer());
                    exit(0)
                },

                (n, Some(m)) => status(m, n),

                _ => {
                    eprintln!("{}", matches.usage());
                    exit(1)
                }
            }
        }

        fn status(_: &ArgMatches, name: &str) -> ! {
            let status = platform_status();

            match name {
                "guests" => println!("{}", status.guests),
                "build" => println!("{}", status.build),
                "flags" => for f in status.flags {
                    println!("{}", match f {
                        Flags::Owned => "owned",
                        Flags::EncryptedState => "es",
                    });
                },
                "state" => println!("{}", match status.state {
                    State::Uninitialized => "uninitialized",
                    State::Initialized => "initialized",
                    State::Working => "working",
                }),
                _ => exit(1),
            }

            exit(0)
        }
    }
}

mod chain {
    use super::*;

    pub fn cmd(matches: &ArgMatches) -> ! {
        match matches.subcommand() {
            ("export", Some(m)) => export(m),
            ("verify", Some(m)) => verify(m),
            ("show", Some(m)) => show(m),
            _ => {
                eprintln!("{}", matches.usage());
                exit(1);
            }
        }
    }

    fn sev_chain(filename: &str) -> [Certificate; 4] {
        let mut file = File::open(filename)
            .expect("unable to open SEV certificate chain file");

        let pdh = Usage::PlatformDiffieHellman.load(&mut file)
            .expect("unable to decode PDH");

        let pek = Usage::PlatformEndorsementKey.load(&mut file)
            .expect("unable to decode PEK");

        let oca = Usage::OwnerCertificateAuthority.load(&mut file)
            .expect("unable to decode OCA");

        let cek = Usage::ChipEndorsementKey.load(&mut file)
            .expect("unable to decode CEK");

        [pdh, pek, oca, cek]
    }

    fn ca_chain(filename: &str) -> [Certificate; 2] {
        let mut file = File::open(&filename)
            .expect("unable to open CA certificate chain file");

        let ask = Usage::AmdSevKey.load(&mut file)
            .expect("unable to decode ASK");

        let ark = Usage::AmdRootKey.load(&mut file)
            .expect("unable to decode ARK");

        [ask, ark]
    }

    fn sev_chain_builtin() -> [Certificate; 4] {
        let [pdh, pek, oca, _] = pdh_cert_export();
        let cek = download_cek();
        [pdh, pek, oca, cek]
    }

    fn ca_chain_builtin() -> [Certificate; 2] {
        [Usage::AmdSevKey.load(&mut &ASK[..]).unwrap(),
            Usage::AmdRootKey.load(&mut &ARK[..]).unwrap()]
    }

    fn export(matches: &ArgMatches) -> ! {
        let chain = pdh_cert_export();
        let cek = download_cek();

        let mut out = std::io::Cursor::new(Vec::new());
        chain[0].save(&mut out).unwrap();
        chain[1].save(&mut out).unwrap();
        chain[2].save(&mut out).unwrap();
        cek.save(&mut out).unwrap();

        write(matches, "file", &out.into_inner())
    }

    fn verify(matches: &ArgMatches) -> ! {
        let [pdh, pek, oca, cek] = match matches.value_of("sev") {
            Some(filename) => sev_chain(&filename),
            None => sev_chain_builtin(),
        };

        let [ask, ark] = match matches.value_of("ca") {
            Some(filename) => ca_chain(filename),
            None => ca_chain_builtin(),
        };

        oca.verify(&oca).expect("OCA not self-signed");
        oca.verify(&pek).expect("PEK not signed by OCA");

        ark.verify(&ark).expect("ARK not self-signed");
        ark.verify(&ask).expect("ASK not signed by ARK");
        ask.verify(&cek).expect("CEK not signed by ASK");
        cek.verify(&pek).expect("PEK not signed by CEK");
        pek.verify(&pdh).expect("PDH not signed by PEK");

        exit(0)
    }

    fn show(matches: &ArgMatches) -> ! {
        use colored::Colorize;

        let [pdh, pek, oca, cek] = match matches.value_of("sev") {
            Some(filename) => sev_chain(&filename),
            None => sev_chain_builtin(),
        };

        let [ask, ark] = match matches.value_of("ca") {
            Some(filename) => ca_chain(&filename),
            None => ca_chain_builtin(),
        };

        fn v(p: &Certificate, c: &Certificate, s: bool) -> String {
            let a = match (s, p.verify(&p).is_ok()) {
                (false, _)    => " ".into(),
                (true, true)  => "•".green(),
                (true, false) => "•".red(),
            };

            let b = if p.verify(&c).is_ok() { "⮤".green() } else { "⮤".red() };

            format!("{}{}", a, b)
        }

        println!("{}", pdh);
        println!("{} {}", v(&pek, &pdh, false), pek);
        println!("   {} {}", v(&oca, &pek, true), oca);
        println!("   {} {}", v(&cek, &pek, false), cek);
        println!("      {} {}", v(&ask, &cek, false), ask);
        println!("         {} {}", v(&ark, &ask, true), ark);

        exit(0)
    }
}

mod oca {
    use tiny_http::{Server, Request, Response, StatusCode, Method};
    use sev::certs::PrivateKey;
    use super::*;

    pub fn cmd(matches: &ArgMatches) -> ! {
        match matches.subcommand() {
            ("create", Some(m)) => create(m),
            ("serve", Some(m)) => serve(m),
            _ => {
                eprintln!("{}", matches.usage());
                exit(1);
            }
        }
    }

    fn create(matches: &ArgMatches) -> ! {
        let (oca, prv) = Certificate::oca()
            .expect("unable to generate OCA key pair");

        // Write the certificate
        let crt = matches.value_of("cert").unwrap();
        let mut crt = File::create(crt).expect("unable to create certificate file");
        oca.save(&mut crt).expect("unable to write certificate file");

        // Write the private key
        let key = matches.value_of("key").unwrap();
        let mut key = File::create(key).expect("unable to create key file");
        prv.save(&mut key).expect("unable to write key file");

        exit(0)
    }

    fn serve(matches: &ArgMatches) -> ! {
        let (enc, key) = load(matches);
        let mut buf = vec![0u8; enc.len()];

        let srv = Server::http("0.0.0.0:8000").unwrap();
        for (i, mut req) in srv.incoming_requests().enumerate() {
            eprintln!("{:08}: {} > {} {}", i, req.remote_addr(),
                        req.method(), req.url());

            if req.url() != "/" {
                let rsp = Response::empty(StatusCode(404));
                eprintln!("{:08}: {} < {:03}", i, req.remote_addr(), 404);
                req.respond(rsp).unwrap();
                continue;
            }

            let (code, data) = match req.method() {
                Method::Get => (200, Some(&enc[..])),
                Method::Post => match sign(&mut req, &key, &mut buf) {
                    Ok(_) => (200, Some(&buf[..])),
                    Err(c) => (c, None),
                },

                _ => (405, None),
            };

            if let Some(d) = data {
                let rdr = &mut &d[..];
                let rsp = Response::new(StatusCode(200), Vec::new(), rdr, Some(enc.len()), None);
                eprintln!("{:08}: {} < {:03}", i, req.remote_addr(), 200);
                req.respond(rsp).unwrap();
            } else {
                let rsp = Response::empty(StatusCode(code));
                eprintln!("{:08}: {} < {:03}", i, req.remote_addr(), code);
                req.respond(rsp).unwrap();
            }
        }

        exit(1)
    }

    fn load(matches: &ArgMatches) -> (Vec<u8>, PrivateKey) {
        let oca = matches.value_of("cert").unwrap();
        let key = matches.value_of("key").unwrap();

        // Load certificate
        let mut oca = File::open(oca).expect("unable to open certificate file");
        let oca = Usage::OwnerCertificateAuthority.load(&mut oca)
            .expect("unable to decode OCA certificate");

        // Load private key
        let mut key = File::open(key).expect("unable to open key file");
        let key = oca.load(&mut key).expect("unable to read key file");

        // Re-encode the certificate
        let mut enc = Vec::new();
        oca.save(&mut enc).unwrap();

        (enc, key)
    }

    fn sign(req: &mut Request, key: &PrivateKey, buf: &mut [u8]) -> Result<(), u16> {
        // Read in the provided PEK CSR
        if req.body_length() != Some(buf.len()) { Err(413u16)? }
        req.as_reader().read_exact(&mut &mut buf[..]).or(Err(500u16))?;

        let mut pek = Usage::PlatformEndorsementKey.load(&mut &buf[..]).or(Err(400u16))?;
        key.sign(&mut pek).or(Err(400u16))?;
        pek.save(&mut &mut buf[..]).or(Err(500u16))?;
        Ok(())
    }
}

mod pek {
    use sev::fwapi::Flags;
    use super::*;

    pub fn cmd(matches: &ArgMatches) -> ! {
        match matches.subcommand() {
            ("rotate", Some(m)) => rotate(m),
            _ => {
                eprintln!("{}", matches.usage());
                exit(1);
            }
        }
    }

    fn rotate(matches: &ArgMatches) -> ! {
        if let Some(url) = matches.value_of("adopt") {
            let oca = download(reqwest::get(url), Usage::OwnerCertificateAuthority);
            oca.verify(&oca).expect("unable to self-verify OCA certificate");

            sev().pek_generate().expect("unable to reset PEK");

            let csr = sev().pek_csr().expect("unable to fetch PEK CSR");

            let mut buf = Vec::new();
            csr.save(&mut buf).expect("unable to re-encode PEK CSR");

            let clt = reqwest::Client::new();
            let pek = download(clt.post(url).body(buf).send(), Usage::PlatformEndorsementKey);

            sev().pek_cert_import(&pek, &oca).expect("unable to import PEK and OCA");
        } else {
            if platform_status().flags.contains(&Flags::Owned) {
                eprintln!("not rotating owned system; see --adopt option");
                exit(1);
            } else {
                sev().pek_generate().expect("unable to rotate PEK");
            }
        }

        exit(0)
    }
}

mod pdh {
    use super::*;

    pub fn cmd(matches: &ArgMatches) -> ! {
        match matches.subcommand() {
            ("rotate", Some(m)) => rotate(m),
            _ => {
                eprintln!("{}", matches.usage());
                exit(1);
            }
        }
    }

    fn rotate(_: &ArgMatches) -> ! {
        sev().pdh_generate().expect("unable to rotate PDH");
        exit(0)
    }
}
