#!/bin/bash

set -e -o pipefail

function gettag() {
    python3 -c 'import sys; import json; print(json.loads(sys.stdin.read())[0]["tag_name"])'
}

rel="https://api.github.com/repos/actions/runner/releases"
tag=$(curl -s -X GET "${rel}" | gettag)
tar="actions-runner-linux-x64-${tag:1}.tar.gz"
url="https://github.com/actions/runner/releases/download/${tag}/${tar}"

mkdir /runner
curl -L "${url}" | tar xzC /runner

if [ -z "${URL}" ] || [ -z "${NAME}" ] || [ -z "${TOKEN}" ]; then
    [ -w /srv ] && echo 'Refusing to run with writable /srv!' && exit 1

    for f in credentials_rsaparams credentials runner; do
        ln -sf /srv/$f /runner/.$f
    done

    exec /runner/bin/Runner.Listener run
fi

RUNNER_ALLOW_RUNASROOT=1 /runner/bin/Runner.Listener configure \
    --unattended \
    --url "${URL}" \
    --name "${NAME}" \
    --token "${TOKEN}"

for f in credentials_rsaparams credentials runner; do
    cp /runner/.$f /srv/$f
done
