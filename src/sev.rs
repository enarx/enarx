extern crate tiny_http;
extern crate reqwest;
extern crate codicon;
extern crate clap;
extern crate sev;

use clap::ArgMatches;

use codicon::Decoder;

use sev::certs::{Certificate, Kind, Usage};
use sev::fwapi::{Sev, Status, Identifier};

use std::collections::HashMap;
use std::process::exit;
use std::io::Write;
use std::fs::File;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn download(rsp: reqwest::Result<reqwest::Response>, name: &str) -> Certificate {
    let mut rsp = rsp.expect(&format!("unable to contact {} server", name));

    if !rsp.status().is_success() {
        panic!("received failure from {} server: {}", name, rsp.status());
    }

    let mut buf = Vec::new();
    rsp.copy_to(&mut buf)
        .expect(&format!("unable to complete {} download", name));

    Certificate::decode(&mut &buf[..], Kind::Sev)
        .expect(&format!("unable to parse downloaded {}", name))
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

fn pdh_cert_export() -> HashMap<Usage, Certificate> {
    sev().pdh_cert_export().expect("unable to export SEV certificates")
}

fn get_identifer() -> Identifier {
    sev().get_identifer().expect("error fetching identifier")
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
                .about("Resets the SEV platform"))

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
                    .about("Show the CPU identifier"))))

        .subcommand(SubCommand::with_name("chain")
            .about("Certificate chain commands")

            .subcommand(SubCommand::with_name("export")
                .about("Export the full SEV certificate chain")
                .arg(Arg::with_name("file").required(true)))

            .subcommand(SubCommand::with_name("verify")
                .about("Verify the full SEV certificate chain")
                .arg(Arg::with_name("sev").required(true))
                .arg(Arg::with_name("ca").required(true)))

            .subcommand(SubCommand::with_name("show")
                .about("Show information about the certificate chain")
                .arg(Arg::with_name("sev").required(true))
                .arg(Arg::with_name("ca").required(true))))

        .subcommand(SubCommand::with_name("oca")
            .about("Owner Certification Authority commands")

            .subcommand(SubCommand::with_name("create")
                .about("Generate a new, self-signed OCA certificate and key")
                .arg(Arg::with_name("cert").required(true))
                .arg(Arg::with_name("key").required(true)))

            .subcommand(SubCommand::with_name("serve")
                .about("Run a server to handle OCA certificate signing requests")
                .arg(Arg::with_name("cert").required(true))
                .arg(Arg::with_name("key").required(true))))

        .subcommand(SubCommand::with_name("pek")
            .about("Platform Endorsement Key commands")

            .subcommand(SubCommand::with_name("rotate")
                .about("Rotate the PEK")
                .arg(Arg::with_name("adopt")
                    .takes_value(true)
                    .long("adopt"))))

        .subcommand(SubCommand::with_name("pdh")
            .about("Platform Diffie Hellman commands")

            .subcommand(SubCommand::with_name("rotate")
                .about("Rotate the PDH")))

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
    use sev::certs::{Full, Verifier};
    use codicon::Encoder;
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

    fn export(matches: &ArgMatches) -> ! {
        const CEK_SVC: &str = "https://kdsintf.amd.com/cek/id";

        let id = get_identifer();
        let url = format!("{}/{}", CEK_SVC, id);
        let cek = download(reqwest::get(&url), "CEK");

        let mut chain = pdh_cert_export();
        chain.insert(cek.key.usage, cek);

        let mut out = std::io::Cursor::new(Vec::new());
        chain[&Usage::PlatformDiffieHellman].encode(&mut out, Full).unwrap();
        chain[&Usage::PlatformEndorsementKey].encode(&mut out, Full).unwrap();
        chain[&Usage::OwnerCertificateAuthority].encode(&mut out, Full).unwrap();
        chain[&Usage::ChipEndorsementKey].encode(&mut out, Full).unwrap();

        write(matches, "file", &out.into_inner())
    }

    fn verify(matches: &ArgMatches) -> ! {
        let sev = matches.value_of("sev").unwrap();
        let ca = matches.value_of("ca").unwrap();

        let mut sev = File::open(&sev).expect("unable to open SEV certificate chain file");
        let mut ca = File::open(&ca).expect("unable to open CA certificate chain file");

        let pdh = Certificate::decode(&mut sev, Kind::Sev).expect("unable to decode PDH");
        let pek = Certificate::decode(&mut sev, Kind::Sev).expect("unable to decode PEK");
        let oca = Certificate::decode(&mut sev, Kind::Sev).expect("unable to decode OCA");
        let cek = Certificate::decode(&mut sev, Kind::Sev).expect("unable to decode CEK");
        let ask = Certificate::decode(&mut ca, Kind::Ca).expect("unable to decode ASK");
        let ark = Certificate::decode(&mut ca, Kind::Ca).expect("unable to decode ARK");

        let pek = match [&oca, &pek].verify() {
            Err(_) => exit(1),
            Ok(c) => c,
        };

        match [&ark, &ask, &cek, pek, &pdh].verify() {
            Err(_) => exit(1),
            Ok(_) => exit(0),
        }
    }

    fn show(matches: &ArgMatches) -> ! {
        let sev = matches.value_of("sev").unwrap();
        let ca = matches.value_of("ca").unwrap();

        let mut sev = File::open(&sev).expect("unable to open SEV certificate chain file");
        let mut ca = File::open(&ca).expect("unable to open CA certificate chain file");

        loop {
            let crt = match Certificate::decode(&mut sev, Kind::Sev) {
                Err(_) => break,
                Ok(c) => c,
            };

            println!("{}", crt);
        }

        loop {
            let crt = match Certificate::decode(&mut ca, Kind::Ca) {
                Err(_) => break,
                Ok(c) => c,
            };

            println!("{}", crt);
        }

        exit(0)
    }
}

mod oca {
    use tiny_http::{Server, Request, Response, StatusCode, Method};
    use sev::certs::{Body, Full, Firmware, PrivateKey};
    use codicon::Encoder;
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
        // Generate the OCA key pair and certificate
        let (key, prv) = Usage::OwnerCertificateAuthority.generate()
            .expect("unable to generate OCA key pair");

        // Create the certificate
        let mut oca = Certificate {
            firmware: Some(Firmware(0, 0)),
            sigs: [None, None],
            version: 1,
            key
        };

        // Self-sign the OCA
        let mut buf = Vec::new();
        oca.encode(&mut buf, Body).expect("unable to encode OCA body");
        oca.sigs[0] = Some(oca.key.sign(&buf, &prv).expect("unable to self-sign OCA"));

        // Write the certificate
        let crt = matches.value_of("cert").unwrap();
        let mut crt = File::create(crt).expect("unable to create certificate file");
        oca.encode(&mut crt, Full).expect("unable to write certificate file");

        // Write the private key
        let key = matches.value_of("key").unwrap();
        let mut key = File::create(key).expect("unable to create key file");
        prv.encode(&mut key, ()).expect("unable to write key file");

        std::process::exit(0)
    }

    fn serve(matches: &ArgMatches) -> ! {
        let ((enc, crt), prv) = load(matches);
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
                Method::Post => match sign(&mut req, &crt, &prv, &mut buf) {
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

        std::process::exit(1)
    }

    fn load(matches: &ArgMatches) -> ((Vec<u8>, Certificate), PrivateKey) {
        let crt = matches.value_of("cert").unwrap();
        let key = matches.value_of("key").unwrap();

        // Load certificate
        let mut crt = File::open(crt).expect("unable to open certificate file");
        let crt = Certificate::decode(&mut crt, Kind::Sev)
            .expect("unable to decode certificate");

        // Re-encode certificate
        let mut enc = Vec::new();
        crt.encode(&mut enc, Full).expect("unable to re-encode certificate");

        // Load private key
        let mut key = File::open(key).expect("unable to open key file");
        let prv = PrivateKey::decode(&mut key, ()).expect("unable to read key file");

        // Test that signing works
        let sig = crt.key.sign(&[0u8; 0], &prv).expect("unable to sign");
        crt.key.verify(&[0u8; 0], &sig).expect("unable to verify");

        ((enc, crt), prv)
    }

    fn sign(req: &mut Request, oca: &Certificate, key: &PrivateKey, buf: &mut [u8]) -> Result<(), u16> {
        // Read in the provided PEK CSR
        if req.body_length() != Some(buf.len()) { Err(413u16)? }
        req.as_reader().read_exact(&mut &mut buf[..]).or(Err(500u16))?;

        // Validate the PEK CSR data
        let mut pek = Certificate::decode(&mut &buf[..], Kind::Sev).or(Err(400u16))?;
        if pek.key.usage != Usage::PlatformEndorsementKey { Err(400u16)? }
        if pek.sigs != [None, None] { Err(400u16)? }

        // Sign the PEK
        let mut bdy = Vec::new();
        pek.encode(&mut bdy, Body).or(Err(500u16))?;
        pek.sigs[0] = Some(oca.key.sign(&bdy, &key).or(Err(500u16))?);

        // Encode the signed PEK
        pek.encode(&mut &mut buf[..], Full).or(Err(500u16))?;
        Ok(())
    }
}

mod pek {
    use sev::certs::{Full, Verifier};
    use sev::fwapi::Flags;
    use codicon::Encoder;
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
            let oca = download(reqwest::get(url), "OCA");
            [&oca].verify().expect("unable to self-verify OCA certificate");

            sev().pek_generate().expect("unable to reset PEK");

            let csr = sev().pek_csr().expect("unable to fetch PEK CSR");

            let mut buf = Vec::new();
            csr.encode(&mut buf, Full).expect("unable to re-encode PEK CSR");

            let clt = reqwest::Client::new();
            let pek = download(clt.post(url).body(buf).send(), "PEK");

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
