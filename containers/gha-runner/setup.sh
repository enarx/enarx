#!/bin/bash

set -e -o pipefail

function gettag() {
    python3 -c 'import sys; import json; print(json.loads(sys.stdin.read())[0]["tag_name"])'
}

rel="https://api.github.com/repos/actions/runner/releases"
tag=$(curl -s -X GET "${rel}" | gettag)
tar="actions-runner-linux-x64-${tag:1}.tar.gz"
url="https://github.com/actions/runner/releases/download/${tag}/${tar}"

mkdir runner
curl -L "${url}" | tar xzC runner
