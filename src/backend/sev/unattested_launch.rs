// SPDX-License-Identifier: Apache-2.0

//! The `unattested_launch` is an implementation of a so-called "synthetic"
//! or "fake" client that speaks the remote AMD SEV launch protocol. This
//! exists for several reasons:
//!
//!   1.) There is no special-casing in the SEV backend launch process. It
//!       will speak the same protocol for all launch use-cases. The
//!       synthetic client allows us to avoid special-casing any of the launch
//!       code.
//!   2.) The synthetic client allows for keeps to be launched in solitary
//!       environments such as CI or other testing where there are no actual
//!       clients who will participate in the launch protocol.
//!   3.) Sometimes you just want a keep and you don't care to attest.
//!   4.) The synthetic client, as a side-effect, also acts as some degree
//!       of test coverage for the client-side of the remote attestation
//!       protocol.

use std::convert::TryFrom;
use std::os::unix::net::UnixStream;

use ::sev::certs::{ca, sev};
use ::sev::launch::Policy;
use ::sev::session::Session;
use codicon::{Decoder, Encoder};
use koine::attestation::sev::*;
use serde::de::Deserialize;
use serde_cbor as serde_flavor;

pub fn launch(sock: UnixStream) {
    let mut de = serde_flavor::Deserializer::from_reader(&sock);
    let chain_packet =
        Message::deserialize(&mut de).expect("failed to deserialize expected certificate chain");
    let chain_packet = match chain_packet {
        Message::CertificateChainNaples(chain) => chain,
        Message::CertificateChainRome(chain) => chain,
        _ => panic!("expected certificate chain"),
    };

    let chain = ::sev::certs::Chain {
        ca: ca::Chain {
            ark: ca::Certificate::decode(chain_packet.ark.as_slice(), ()).expect("ark"),
            ask: ca::Certificate::decode(chain_packet.ask.as_slice(), ()).expect("ask"),
        },
        sev: sev::Chain {
            pdh: sev::Certificate::decode(chain_packet.pdh.as_slice(), ()).expect("pdh"),
            pek: sev::Certificate::decode(chain_packet.pek.as_slice(), ()).expect("pek"),
            cek: sev::Certificate::decode(chain_packet.cek.as_slice(), ()).expect("cek"),
            oca: sev::Certificate::decode(chain_packet.oca.as_slice(), ()).expect("oca"),
        },
    };

    let policy = Policy::default();
    let session = Session::try_from(policy).expect("failed to craft policy");

    let start = session.start(chain).expect("failed to start session");
    let mut ls = LaunchStart {
        policy: vec![],
        cert: vec![],
        session: vec![],
    };
    serde_flavor::to_writer(&mut ls.policy, &start.policy).expect("failed to serialize policy");
    start
        .cert
        .encode(&mut ls.cert, ())
        .expect("start cert encode");
    serde_flavor::to_writer(&mut ls.session, &start.session).expect("failed to serialize session");

    let start_packet = Message::LaunchStart(ls);
    serde_flavor::to_writer(&sock, &start_packet).expect("failed to serialize launch start");

    // Discard the measurement, the synthetic client doesn't care
    // for an unattested launch.
    let msr =
        Message::deserialize(&mut de).expect("failed to deserialize expected measurement packet");
    assert!(matches!(msr, Message::Measurement(_)));

    let secret_packet = Message::Secret(vec![]);
    serde_flavor::to_writer(&sock, &secret_packet).expect("failed to serialize secret packet");

    let fin = Message::deserialize(&mut de).expect("failed to deserialize expected finish packet");
    assert!(matches!(fin, Message::Finish(_)));
}
