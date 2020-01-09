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
    sev::Certificate::decode(&mut &PEK[..], ()).unwrap();
}

#[test]
fn encode() {
    let pek = sev::Certificate::decode(&mut &PEK[..], ()).unwrap();

    let mut output = Vec::new();
    pek.encode(&mut output, ()).unwrap();
    assert_eq!(PEK.len(), output.len());
    assert_eq!(PEK.to_vec(), output);
}

#[cfg(feature = "openssl")]
#[test]
fn verify() {
    let cek = sev::Certificate::decode(&mut CEK, ()).unwrap();
    let oca = sev::Certificate::decode(&mut OCA, ()).unwrap();
    let pek = sev::Certificate::decode(&mut PEK, ()).unwrap();

    (&cek, &pek).verify().unwrap();
    assert!((&pek, &cek).verify().is_err());

    (&oca, &pek).verify().unwrap();
    assert!((&pek, &oca).verify().is_err());
}
