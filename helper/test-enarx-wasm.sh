#!/bin/sh

if ! [ -f "$ENARX_BIN" ]; then
  (cd ..; cargo build -q)
  ENARX_BIN=$(dirname $0)/../target/debug/enarx
fi

"$ENARX_BIN" run "$@"
