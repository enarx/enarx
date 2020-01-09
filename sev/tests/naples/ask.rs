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

use super::*;

#[test]
fn decode() {
    ca::Certificate::decode(&mut &ASK[..], ()).unwrap();
}

#[test]
fn encode() {
    let ask = ca::Certificate::decode(&mut &ASK[..], ()).unwrap();

    let mut output = Vec::new();
    ask.encode(&mut output, ()).unwrap();
    assert_eq!(ASK.len(), output.len());
    assert_eq!(ASK.to_vec(), output);
}

#[cfg(feature = "openssl")]
#[test]
fn verify() {
    let ark = ca::Certificate::decode(&mut ARK, ()).unwrap();
    let ask = ca::Certificate::decode(&mut ASK, ()).unwrap();

    (&ark, &ask).verify().unwrap();
    assert!((&ask, &ark).verify().is_err());
}
