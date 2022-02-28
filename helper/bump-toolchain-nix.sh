#!/usr/bin/env bash

TOOLCHAIN_VERSION="${1:-nightly-$(date +%Y-%m-%d)}"

echo "Usage: $0 [-h [<TOOLCHAIN_VERSION>]"

echo "Update to Nix rust toolchain version ${TOOLCHAIN_VERSION}"
set +e
NIX_TOOLCHAIN_HASH="$(nix-shell 2>&1 | grep 'got:' | cut -d: -f2 | tr -d '[:blank:]')"
set -e
if [[ $NIX_TOOLCHAIN_HASH ]]; then
  sed -i  "s#sha256 = .*#sha256 = \"${NIX_TOOLCHAIN_HASH}\";#" flake.nix
else
  echo "Problem obtaining new NIX_TOOLCHAIN_HASH or toolchain already up to date."
  echo "No changes made."
fi
