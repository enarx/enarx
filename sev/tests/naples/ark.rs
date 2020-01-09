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
    let bad = ca::Certificate::decode(&mut &ARK_BAD[..], ()).unwrap();
    let ark = ca::Certificate::decode(&mut &ARK[..], ()).unwrap();
    assert_eq!(ark, bad);
}

#[test]
fn encode() {
    let ark = ca::Certificate::decode(&mut &ARK_BAD[..], ()).unwrap();

    let mut output = Vec::new();
    ark.encode(&mut output, ()).unwrap();
    assert_eq!(ARK.len(), output.len());
    assert_eq!(ARK.to_vec(), output);

    let ark = ca::Certificate::decode(&mut &ARK[..], ()).unwrap();

    let mut output = Vec::new();
    ark.encode(&mut output, ()).unwrap();
    assert_eq!(ARK.len(), output.len());
    assert_eq!(ARK.to_vec(), output);
}

#[cfg(feature = "openssl")]
#[test]
fn verify() {
    let ark = ca::Certificate::decode(&mut &ARK_BAD[..], ()).unwrap();
    (&ark, &ark).verify().unwrap();

    let ark = ca::Certificate::decode(&mut &ARK[..], ()).unwrap();
    (&ark, &ark).verify().unwrap();
}
