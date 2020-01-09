// Copyright 2019 Red Hat
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg(feature = "openssl")]

mod initialized {
    use ::sev::{certs::*, launch, session::Session};
    use codicon::Decoder;
    use std::convert::*;

    #[test]
    fn create() {
        Session::try_from(launch::Policy::default()).unwrap();
    }

    #[test]
    fn start() {
        const ARK: &[u8] = include_bytes!("naples/ark.cert");
        const ASK: &[u8] = include_bytes!("naples/ask.cert");
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
