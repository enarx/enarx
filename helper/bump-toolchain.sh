#!/usr/bin/env bash

TOOLCHAIN_VERSION="${1:-nightly-$(date +%Y-%m-%d)}"

echo "Usage: $0 [-h [<TOOLCHAIN_VERSION>]"

echo "Update to rust toolchain version ${TOOLCHAIN_VERSION}"
sed -i "s/channel = .*/channel = \"${TOOLCHAIN_VERSION}\"/" rust-toolchain.toml
sed -i "s/toolchain: .*/toolchain: ${TOOLCHAIN_VERSION}/" .github/workflows/{lint,test}.yml
