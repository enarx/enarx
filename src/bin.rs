extern crate tiny_http;
extern crate colored;
extern crate reqwest;
extern crate clap;
extern crate sev;

use clap::ArgMatches;

use sev::certs::{Certificate, Usage};
use sev::fwapi::{Sev, Status};

use std::process::exit;
use std::fs::File;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
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

fn sev() -> Sev {
    sev::fwapi::Sev::new().expect("unable to open /dev/sev")
}

fn platform_status() -> Status {
    sev().platform_status().expect("unable to fetch platform status")
}

fn chain() -> [Certificate; 4] {
    const CEK_SVC: &str = "https://kdsintf.amd.com/cek/id";

    let [pdh, pek, oca, _] = sev().pdh_cert_export()
        .expect("unable to export SEV certificates");

    let id = sev().get_identifer().expect("error fetching identifier");
    let url = format!("{}/{}", CEK_SVC, id);
    let cek = download(reqwest::get(&url), Usage::ChipEndorsementKey);

    [pdh, pek, oca, cek]
}

fn main() {
    use clap::{Arg, App, SubCommand};

    let matches = App::new("SEV Platform Control")
        .version(VERSION)
        .author(AUTHORS.split(";").nth(0).unwrap())
        .about("Utilities for managing the SEV environement")

        .subcommand(SubCommand::with_name("reset")
            .about("Resets the SEV platform")
        )

        .subcommand(SubCommand::with_name("show")
            .about("Shows information about the SEV platform")
            .subcommand(SubCommand::with_name("version")
                .about("Show the current firmware version"))
            .subcommand(SubCommand::with_name("guests")
                .about("Show the current number of guests"))
            .subcommand(SubCommand::with_name("flags")
                .about("Show the current platform flags"))
        )

        .subcommand(SubCommand::with_name("export")
            .about("Export the SEV certificate chain")
            .arg(Arg::with_name("file")
                .help("SEV certificate chain output file")
                .required(true)
            )
        )

        .subcommand(SubCommand::with_name("verify")
            .about("Verify the full SEV/CA certificate chain")
            .arg(Arg::with_name("quiet")
                .help("Do not print anything to the console")
                .long("quiet")
                .short("q")
            )
            .arg(Arg::with_name("sev")
                .help("Read SEV chain from the specified file")
                .takes_value(true)
                .long("sev")
            )
            .arg(Arg::with_name("oca")
                .help("Read OCA from the specified file")
                .takes_value(true)
                .long("oca")
            )
            .arg(Arg::with_name("ca")
                .help("Read CA chain from the specified file")
                .takes_value(true)
                .long("ca")
            )
        )

        .subcommand(SubCommand::with_name("generate")
            .about("Generate a new, self-signed OCA certificate and key")
            .arg(Arg::with_name("cert")
                .help("OCA certificate output file")
                .required(true)
            )
            .arg(Arg::with_name("key")
                .help("OCA private key output file")
                .required(true)
            )
        )

        .subcommand(SubCommand::with_name("serve")
            .about("Run a server to handle OCA certificate signing requests")
            .arg(Arg::with_name("cert")
                .help("OCA certificate input file")
                .required(true)
            )
            .arg(Arg::with_name("key")
                .help("OCA private key input file")
                .required(true)
            )
        )

        .subcommand(SubCommand::with_name("rotate")
            .about("Rotate certificates and their keys")

            .subcommand(SubCommand::with_name("all")
                .about("Rotate the OCA, PEK and PDH certificates")
                .arg(Arg::with_name("adopt")
                    .help("URL of OCA signing service")
                    .takes_value(true)
                    .long("adopt")
                )
            )

            .subcommand(SubCommand::with_name("pdh")
                .about("Rotate the PDH certificate")
            )
        )

        .get_matches();

    match matches.subcommand() {
        ("reset",    Some(m)) => reset::cmd(m),
        ("show",     Some(m)) => show::cmd(m),
        ("export",   Some(m)) => export::cmd(m),
        ("verify",   Some(m)) => verify::cmd(m),
        ("generate", Some(m)) => generate::cmd(m),
        ("serve",    Some(m)) => serve::cmd(m),
        ("rotate",   Some(m)) => rotate::cmd(m),
        _ => {
            eprintln!("{}", matches.usage());
            exit(1);
        }
    }
}

mod reset {
    use super::*;

    pub fn cmd(_: &ArgMatches) -> ! {
        sev().platform_reset().expect("error resetting platform");
        exit(0)
    }
}

mod show {
    use sev::fwapi::Flags;
    use super::*;

    pub fn cmd(matches: &ArgMatches) -> ! {
        let status = platform_status();

        match matches.subcommand_name() {
            Some("version") => println!("{}", status.build),

            Some("guests") => println!("{}", status.guests),

            Some("flags") => for f in status.flags {
                println!("{}", match f {
                    Flags::Owned => "owned",
                    Flags::EncryptedState => "es",
                });
            },

            _ => {
                eprintln!("{}", matches.usage());
                exit(1);
            }
        }

        exit(0)
    }
}

mod export {
    use std::io::Write;
    use super::*;

    pub fn cmd(matches: &ArgMatches) -> ! {
        let chain = chain();

        let mut out = std::io::Cursor::new(Vec::new());
        chain[0].save(&mut out).unwrap();
        chain[1].save(&mut out).unwrap();
        chain[2].save(&mut out).unwrap();
        chain[3].save(&mut out).unwrap();

        let mut file = File::create(matches.value_of("file").unwrap())
            .expect("unable to create output file");

        file.write_all(&out.into_inner())
            .expect("unable to write output file");

        exit(0)
    }
}

mod verify {
    use colored::Colorize;
    use super::*;

    pub fn cmd(matches: &ArgMatches) -> ! {
        let [pdh, pek, mut oca, cek] = sev_chain(matches.value_of("sev"));
        let [ask, ark] = ca_chain(matches.value_of("ca"));
        let quiet = matches.is_present("quiet");
        let mut err = false;

        if let Some(filename) = matches.value_of("oca") {
            let mut file = File::open(filename)
                .expect("unable to open OCA certificate file");

            oca = Usage::OwnerCertificateAuthority.load(&mut file)
                .expect("unable to decode OCA");
        }

        if !quiet { println!("{}", pdh); }
        err |= status("", &pek, &pdh, quiet);
        err |= status("   ", &oca, &pek, quiet);
        err |= status("   ", &cek, &pek, quiet);
        err |= status("      ", &ask, &cek, quiet);
        err |= status("         ", &ark, &ask, quiet);

        exit(err as i32)
    }

    fn status(pfx: &str, p: &Certificate, c: &Certificate, quiet: bool) -> bool {
        let sig = p.verify(c).is_ok();
        let lnk = if sig { "⮤".green() } else { "⮤".red() };

        !match p.usage() {
            Usage::OwnerCertificateAuthority | Usage::AmdRootKey => {
                let selfsig = p.verify(&p).is_ok();
                let slf = if selfsig { "•".green() } else { "•".red() };
                if !quiet { println!("{}{}{} {}", pfx, slf, lnk, p); }
                sig && selfsig
            },

            _ => {
                if !quiet { println!("{}{}{} {}", pfx, " ", lnk, p); }
                sig
            }
        }
    }

    fn sev_chain(filename: Option<&str>) -> [Certificate; 4] {
        match filename {
            None => chain(),
            Some(f) => {
                let mut file = File::open(f)
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
            },
        }
    }

    fn ca_chain(filename: Option<&str>) -> [Certificate; 2] {
        match filename {
            Some(f) => {
                let mut file = File::open(&f)
                    .expect("unable to open CA certificate chain file");

                let ask = Usage::AmdSevKey.load(&mut file)
                    .expect("unable to decode ASK");

                let ark = Usage::AmdRootKey.load(&mut file)
                    .expect("unable to decode ARK");

                [ask, ark]
            },

            None => {
                [Usage::AmdSevKey.load(&mut &ASK[..]).unwrap(),
                    Usage::AmdRootKey.load(&mut &ARK[..]).unwrap()]
            }
        }
    }
}

mod generate {
    use super::*;

    pub fn cmd(matches: &ArgMatches) -> ! {
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
}

mod serve {
    use tiny_http::{Server, Request, Response, StatusCode, Method};
    use sev::certs::PrivateKey;
    use super::*;

    pub fn cmd(matches: &ArgMatches) -> ! {
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

mod rotate {
    use sev::fwapi::Flags;
    use super::*;

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
                sev().pek_generate().expect("unable to rotate OCA, PEK and PDH");
            }
        }

        exit(0)
    }

    fn pdh(_: &ArgMatches) -> ! {
        sev().pdh_generate().expect("unable to rotate PDH");
        exit(0)
    }
}
