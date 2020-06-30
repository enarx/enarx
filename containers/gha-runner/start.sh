#!/bin/bash

set -e -o pipefail

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
