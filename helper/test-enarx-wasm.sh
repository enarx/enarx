#!/usr/bin/env bash

if ! command -v "${ENARX_BIN[0]}" &> /dev/null; then
  if [ -x $(dirname $0)/../target/release/enarx ]; then
    ENARX_BIN=$(dirname $0)/../target/release/enarx
  elif [ -x $(dirname $0)/../target/debug/enarx ]; then
    ENARX_BIN=$(dirname $0)/../target/debug/enarx
  else
    (cd $(dirname $0); cd ..; cargo build --release)
    ENARX_BIN=$(dirname $0)/../target/release/enarx
  fi
fi

if [ -f "$CARGO_MANIFEST_DIR"/Enarx.toml ]; then
  CONFIG="$CARGO_MANIFEST_DIR"/Enarx.toml
fi

"${ENARX_BIN[@]}" run ${CONFIG+--wasmcfgfile $CONFIG} "$@"
