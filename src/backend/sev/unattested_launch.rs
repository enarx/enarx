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

use ::sev::launch::{HeaderFlags, Policy};
use ::sev::session::Session;
use anyhow::{bail, Context, Result};
use ciborium::value::Bytes;
use ciborium::{de::from_reader, ser::into_writer};
use koine::attestation::sev::*;

pub fn launch(sock: UnixStream) -> Result<()> {
    let chain_packet =
        from_reader(&sock).context("failed to deserialize expected certificate chain")?;
    let chain = match chain_packet {
        Message::CertificateChainNaples(chain) => chain,
        Message::CertificateChainRome(chain) => chain,
        _ => panic!("expected certificate chain"),
    };

    let policy = Policy::default();
    let session = Session::try_from(policy).context("failed to craft policy")?;

    let start = session.start(chain).context("failed to start session")?;
    let start_packet = Message::LaunchStart(start);
    into_writer(&start_packet, &sock).context("failed to serialize launch start")?;

    // Discard the measurement, the synthetic client doesn't care
    // for an unattested launch.
    let msr = from_reader(&sock).context("failed to deserialize expected measurement packet")?;

    let msr = match msr {
        Message::Measurement(m) => m,
        _ => bail!("expected measurement packet"),
    };

    let session = unsafe { session.mock_verify(msr.measurement) }.context("verify failed")?;

    let ct_vec = vec![
        0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8, 10, 11, 12, 13, 14,
    ];
    let mut ct_enc = Vec::new();
    into_writer(&Bytes::from(ct_vec), &mut ct_enc).context("failed to encode secret")?;

    let secret = session
        .secret(HeaderFlags::default(), &ct_enc)
        .context("gen_secret failed")?;

    let secret_packet = Message::Secret(Some(secret));

    into_writer(&secret_packet, &sock).context("failed to serialize secret packet")?;

    let fin = from_reader(&sock).context("failed to deserialize expected finish packet")?;

    if !matches!(fin, Message::Finish(_)) {
        bail!("expected finish packet");
    }

    Ok(())
}
