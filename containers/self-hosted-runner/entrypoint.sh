#!/bin/bash

# Clone the repo.
git clone https://github.com/"${GITHUB_REPOSITORY}" current-checkout
cd current-checkout

# Checkout the SHA we want to test.
git fetch origin "${GITHUB_REF}"
git checkout -b testbranch FETCH_HEAD

# Run hardware-specific tests. `integration` will conditionally execute based
# on available hardware.
cargo make build && cargo make integration
