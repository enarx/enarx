// SPDX-License-Identifier: Apache-2.0

//! `sevctl` is a tool for managing the AMD Secure Encrypted Virtualization (SEV) Platform
//! Secure Processor (PSP).

#![deny(clippy::all)]
#![deny(missing_docs)]

use clap::ArgMatches;

use codicon::*;

use ::sev::certs::builtin::naples::*;
use ::sev::certs::*;
use ::sev::firmware::{Firmware, Status};

use std::fs::File;
use std::process::exit;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

fn download(rsp: reqwest::Result<reqwest::blocking::Response>, usage: Usage) -> sev::Certificate {
    let mut rsp = rsp.expect(&format!("unable to contact {} server", usage));

    if !rsp.status().is_success() {
        panic!("received failure from {} server: {}", usage, rsp.status());
    }

    let mut buf = Vec::new();
    rsp.copy_to(&mut buf)
        .expect(&format!("unable to complete {} download", usage));

    sev::Certificate::decode(&mut &buf[..], ())
        .expect(&format!("unable to parse downloaded {}", usage))
}

fn firmware() -> Firmware {
    Firmware::open().expect("unable to open /dev/sev")
}

fn platform_status() -> Status {
    firmware()
        .platform_status()
        .expect("unable to fetch platform status")
}

fn chain() -> sev::Chain {
    const CEK_SVC: &str = "https://kdsintf.amd.com/cek/id";

    let mut chain = firmware()
        .pdh_cert_export()
        .expect("unable to export SEV certificates");

    let id = firmware()
        .get_identifer()
        .expect("error fetching identifier");
    let url = format!("{}/{}", CEK_SVC, id);
    chain.cek = download(reqwest::blocking::get(&url), Usage::CEK);

    chain
}

fn main() {
    use clap::{App, Arg, SubCommand};

    let matches = App::new("SEV Platform Control")
        .version(VERSION)
        .author(AUTHORS.split(";").nth(0).unwrap())
        .about("Utilities for managing the SEV environement")
        .subcommand(SubCommand::with_name("reset").about("Resets the SEV platform"))
        .subcommand(
            SubCommand::with_name("show")
                .about("Shows information about the SEV platform")
                .subcommand(
                    SubCommand::with_name("version").about("Show the current firmware version"),
                )
                .subcommand(
                    SubCommand::with_name("guests").about("Show the current number of guests"),
                )
                .subcommand(
                    SubCommand::with_name("flags").about("Show the current platform flags"),
                ),
        )
        .subcommand(
            SubCommand::with_name("export")
                .about("Export the SEV certificate chain")
                .arg(
                    Arg::with_name("file")
                        .help("SEV certificate chain output file")
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("verify")
                .about("Verify the full SEV/CA certificate chain")
                .arg(
                    Arg::with_name("quiet")
                        .help("Do not print anything to the console")
                        .long("quiet")
                        .short("q"),
                )
                .arg(
                    Arg::with_name("sev")
                        .help("Read SEV chain from the specified file")
                        .takes_value(true)
                        .long("sev"),
                )
                .arg(
                    Arg::with_name("oca")
                        .help("Read OCA from the specified file")
                        .takes_value(true)
                        .long("oca"),
                )
                .arg(
                    Arg::with_name("ca")
                        .help("Read CA chain from the specified file")
                        .takes_value(true)
                        .long("ca"),
                ),
        )
        .subcommand(
            SubCommand::with_name("generate")
                .about("Generate a new, self-signed OCA certificate and key")
                .arg(
                    Arg::with_name("cert")
                        .help("OCA certificate output file")
                        .required(true),
                )
                .arg(
                    Arg::with_name("key")
                        .help("OCA private key output file")
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("serve")
                .about("Run a server to handle OCA certificate signing requests")
                .arg(
                    Arg::with_name("cert")
                        .help("OCA certificate input file")
                        .required(true),
                )
                .arg(
                    Arg::with_name("key")
                        .help("OCA private key input file")
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("rotate")
                .about("Rotate certificates and their keys")
                .subcommand(
                    SubCommand::with_name("all")
                        .about("Rotate the OCA, PEK and PDH certificates")
                        .arg(
                            Arg::with_name("adopt")
                                .help("URL of OCA signing service")
                                .takes_value(true)
                                .long("adopt"),
                        ),
                )
                .subcommand(SubCommand::with_name("pdh").about("Rotate the PDH certificate")),
        )
        .get_matches();

    match matches.subcommand() {
        ("reset", Some(m)) => reset::cmd(m),
        ("show", Some(m)) => show::cmd(m),
        ("export", Some(m)) => export::cmd(m),
        ("verify", Some(m)) => verify::cmd(m),
        ("generate", Some(m)) => generate::cmd(m),
        ("serve", Some(m)) => serve::cmd(m),
        ("rotate", Some(m)) => rotate::cmd(m),
        _ => {
            eprintln!("{}", matches.usage());
            exit(1);
        }
    }
}

mod reset {
    use super::*;

    pub fn cmd(_: &ArgMatches) -> ! {
        firmware()
            .platform_reset()
            .expect("error resetting platform");
        exit(0)
    }
}

mod show {
    use super::*;
    use ::sev::firmware::Flags;

    pub fn cmd(matches: &ArgMatches) -> ! {
        let status = platform_status();

        match matches.subcommand_name() {
            Some("version") => println!("{}", status.build),

            Some("guests") => println!("{}", status.guests),

            Some("flags") => {
                for f in [Flags::OWNED, Flags::ENCRYPTED_STATE].iter() {
                    println!(
                        "{}",
                        match status.flags & *f {
                            Flags::ENCRYPTED_STATE => "es",
                            Flags::OWNED => "owned",
                            _ => continue,
                        }
                    );
                }
            }

            _ => {
                eprintln!("{}", matches.usage());
                exit(1);
            }
        }

        exit(0)
    }
}

mod export {
    use super::*;
    use std::io::Write;

    pub fn cmd(matches: &ArgMatches) -> ! {
        let chain = chain();

        let mut out = std::io::Cursor::new(Vec::new());
        chain.encode(&mut out, ()).unwrap();

        let mut file =
            File::create(matches.value_of("file").unwrap()).expect("unable to create output file");

        file.write_all(&out.into_inner())
            .expect("unable to write output file");

        exit(0)
    }
}

mod verify {
    use super::*;
    use colorful::*;
    use std::convert::TryInto;
    use std::fmt::Display;

    pub fn cmd(matches: &ArgMatches) -> ! {
        let mut schain = sev_chain(matches.value_of("sev"));
        let cchain = ca_chain(matches.value_of("ca"));
        let quiet = matches.is_present("quiet");
        let mut err = false;

        if let Some(filename) = matches.value_of("oca") {
            let mut file = File::open(filename).expect("unable to open OCA certificate file");

            schain.oca = sev::Certificate::decode(&mut file, ()).expect("unable to decode OCA");
        }

        if !quiet {
            println!("{}", schain.pdh);
        }
        err |= status("", &schain.pek, &schain.pdh, quiet);
        err |= status("   ", &schain.oca, &schain.pek, quiet);
        err |= status("   ", &schain.cek, &schain.pek, quiet);
        err |= status("      ", &cchain.ask, &schain.cek, quiet);
        err |= status("         ", &cchain.ark, &cchain.ask, quiet);

        exit(err as i32)
    }

    fn status<'a, P, C>(pfx: &str, p: &'a P, c: &'a C, quiet: bool) -> bool
    where
        P: Display,
        C: Display,
        &'a P: TryInto<Usage, Error = std::io::Error>,
        (&'a P, &'a P): Verifiable,
        (&'a P, &'a C): Verifiable,
    {
        let sig = (p, c).verify().is_ok();
        let lnk = if sig { "⮤".green() } else { "⮤".red() };

        !match p.try_into().unwrap() {
            Usage::OCA | Usage::ARK => {
                let selfsig = (p, p).verify().is_ok();
                let slf = if selfsig { "•".green() } else { "•".red() };
                if !quiet {
                    println!("{}{}{} {}", pfx, slf, lnk, p);
                }
                sig && selfsig
            }

            _ => {
                if !quiet {
                    println!("{}{}{} {}", pfx, " ", lnk, p);
                }
                sig
            }
        }
    }

    fn sev_chain(filename: Option<&str>) -> sev::Chain {
        match filename {
            None => chain(),
            Some(f) => {
                let mut file = File::open(f).expect("unable to open SEV certificate chain file");

                sev::Chain::decode(&mut file, ()).expect("unable to decode chain")
            }
        }
    }

    fn ca_chain(filename: Option<&str>) -> ca::Chain {
        match filename {
            Some(f) => {
                let mut file = File::open(&f).expect("unable to open CA certificate chain file");

                ca::Chain::decode(&mut file, ()).expect("unable to decode chain")
            }

            None => ca::Chain {
                ask: ca::Certificate::decode(&mut &ASK[..], ()).unwrap(),
                ark: ca::Certificate::decode(&mut &ARK[..], ()).unwrap(),
            },
        }
    }
}

mod generate {
    use super::*;

    pub fn cmd(matches: &ArgMatches) -> ! {
        let (mut oca, prv) =
            sev::Certificate::generate(sev::Usage::OCA).expect("unable to generate OCA key pair");
        prv.sign(&mut oca).unwrap();

        // Write the certificate
        let crt = matches.value_of("cert").unwrap();
        let mut crt = File::create(crt).expect("unable to create certificate file");
        oca.encode(&mut crt, ())
            .expect("unable to write certificate file");

        // Write the private key
        let key = matches.value_of("key").unwrap();
        let mut key = File::create(key).expect("unable to create key file");
        prv.encode(&mut key, ()).expect("unable to write key file");

        exit(0)
    }
}

mod serve {
    use super::*;
    use tiny_http::{Method, Request, Response, Server, StatusCode};

    pub fn cmd(matches: &ArgMatches) -> ! {
        let (enc, key) = load(matches);
        let mut buf = vec![0u8; enc.len()];

        let srv = Server::http("0.0.0.0:8000").unwrap();
        for (i, mut req) in srv.incoming_requests().enumerate() {
            eprintln!(
                "{:08}: {} > {} {}",
                i,
                req.remote_addr(),
                req.method(),
                req.url()
            );

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

    fn load(matches: &ArgMatches) -> (Vec<u8>, PrivateKey<sev::Usage>) {
        let oca = matches.value_of("cert").unwrap();
        let key = matches.value_of("key").unwrap();

        // Load certificate
        let mut oca = File::open(oca).expect("unable to open certificate file");
        let oca = sev::Certificate::decode(&mut oca, ()).expect("unable to decode OCA certificate");

        // Load private key
        let mut key = File::open(key).expect("unable to open key file");
        let key = PrivateKey::decode(&mut key, &oca).expect("unable to read key file");

        // Re-encode the certificate
        let mut enc = Vec::new();
        oca.encode(&mut enc, ()).unwrap();

        (enc, key)
    }

    fn sign(req: &mut Request, key: &PrivateKey<sev::Usage>, buf: &mut [u8]) -> Result<(), u16> {
        // Read in the provided PEK CSR
        if req.body_length() != Some(buf.len()) {
            Err(413u16)?
        }
        req.as_reader()
            .read_exact(&mut &mut buf[..])
            .or(Err(500u16))?;

        let mut pek = sev::Certificate::decode(&mut &buf[..], ()).or(Err(400u16))?;
        key.sign(&mut pek).or(Err(400u16))?;
        pek.encode(&mut &mut buf[..], ()).or(Err(500u16))?;
        Ok(())
    }
}

mod rotate {
    use super::*;
    use ::sev::firmware::Flags;

    pub fn cmd(matches: &ArgMatches) -> ! {
        match matches.subcommand() {
            ("all", Some(m)) => all(m),
            ("pdh", Some(m)) => pdh(m),
            _ => {
                eprintln!("{}", matches.usage());
                exit(1);
            }
        }
    }

    fn all(matches: &ArgMatches) -> ! {
        if let Some(url) = matches.value_of("adopt") {
            let oca = download(reqwest::blocking::get(url), Usage::OCA);
            (&oca, &oca)
                .verify()
                .expect("unable to self-verify OCA certificate");

            firmware().pek_generate().expect("unable to reset PEK");

            let csr = firmware().pek_csr().expect("unable to fetch PEK CSR");

            let mut buf = Vec::new();
            csr.encode(&mut buf, ())
                .expect("unable to re-encode PEK CSR");

            let clt = reqwest::blocking::Client::new();
            let pek = download(clt.post(url).body(buf).send(), Usage::PEK);

            firmware()
                .pek_cert_import(&pek, &oca)
                .expect("unable to import PEK and OCA");
        } else {
            if platform_status().flags.contains(Flags::OWNED) {
                eprintln!("not rotating owned system; see --adopt option");
                exit(1);
            } else {
                firmware()
                    .pek_generate()
                    .expect("unable to rotate OCA, PEK and PDH");
            }
        }

        exit(0)
    }

    fn pdh(_: &ArgMatches) -> ! {
        firmware().pdh_generate().expect("unable to rotate PDH");
        exit(0)
    }
}
