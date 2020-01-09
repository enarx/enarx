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
    sev::Certificate::decode(&mut &PDH[..], ()).unwrap();
}

#[test]
fn encode() {
    let pdh = sev::Certificate::decode(&mut &PDH[..], ()).unwrap();

    let mut output = Vec::new();
    pdh.encode(&mut output, ()).unwrap();
    assert_eq!(PDH.len(), output.len());
    assert_eq!(PDH.to_vec(), output);
}

#[cfg(feature = "openssl")]
#[test]
fn verify() {
    let pek = sev::Certificate::decode(&mut PEK, ()).unwrap();
    let pdh = sev::Certificate::decode(&mut PDH, ()).unwrap();

    (&pek, &pdh).verify().unwrap();
    assert!((&pdh, &pek).verify().is_err());
}
