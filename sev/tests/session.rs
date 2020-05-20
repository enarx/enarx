// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "openssl")]

mod initialized {
    use ::sev::{certs::builtin::naples::*, certs::*, launch, session::Session};
    use codicon::Decoder;
    use std::convert::*;

    #[test]
    fn create() {
        Session::try_from(launch::Policy::default()).unwrap();
    }

    #[test]
    fn start() {
        const CEK: &[u8] = include_bytes!("naples/cek.cert");
        const OCA: &[u8] = include_bytes!("naples/oca.cert");
        const PEK: &[u8] = include_bytes!("naples/pek.cert");
        const PDH: &[u8] = include_bytes!("naples/pdh.cert");

        let session = Session::try_from(launch::Policy::default()).unwrap();
        session
            .start(Chain {
                ca: ca::Chain {
                    ark: ca::Certificate::decode(&mut &ARK[..], ()).unwrap(),
                    ask: ca::Certificate::decode(&mut &ASK[..], ()).unwrap(),
                },
                sev: sev::Chain {
                    cek: sev::Certificate::decode(&mut &CEK[..], ()).unwrap(),
                    oca: sev::Certificate::decode(&mut &OCA[..], ()).unwrap(),
                    pek: sev::Certificate::decode(&mut &PEK[..], ()).unwrap(),
                    pdh: sev::Certificate::decode(&mut &PDH[..], ()).unwrap(),
                },
            })
            .unwrap();
    }
}
