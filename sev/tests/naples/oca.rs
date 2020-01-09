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
    sev::Certificate::decode(&mut &OCA[..], ()).unwrap();
}

#[test]
fn encode() {
    let oca = sev::Certificate::decode(&mut &OCA[..], ()).unwrap();

    let mut output = Vec::new();
    oca.encode(&mut output, ()).unwrap();
    assert_eq!(OCA.len(), output.len());
    assert_eq!(OCA.to_vec(), output);
}

#[cfg(feature = "openssl")]
#[test]
fn verify() {
    let oca = sev::Certificate::decode(&mut OCA, ()).unwrap();
    (&oca, &oca).verify().unwrap();
}

#[cfg(feature = "openssl")]
#[test]
fn create() {
    let mut pdh = sev::Certificate::decode(&mut &PDH[..], ()).unwrap();
    let (mut oca, key) = sev::Certificate::generate(sev::Usage::OCA).unwrap();

    assert!((&pdh, &pdh).verify().is_err());
    assert!((&oca, &pdh).verify().is_err());
    assert!((&oca, &oca).verify().is_err());

    key.sign(&mut oca).unwrap();

    assert!((&pdh, &pdh).verify().is_err());
    assert!((&oca, &pdh).verify().is_err());
    (&oca, &oca).verify().unwrap();

    key.sign(&mut pdh).unwrap();
    (&oca, &pdh).verify().unwrap();
}
