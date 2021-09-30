[![Workflow Status](https://github.com/enarx/enarx-wasmldr/workflows/test/badge.svg)](https://github.com/enarx/enarx-wasmldr/actions?query=workflow%3A%22test%22)
[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/enarx/enarx-wasmldr.svg)](https://isitmaintained.com/project/enarx/enarx-wasmldr "Average time to resolve an issue")
[![Percentage of issues still open](https://isitmaintained.com/badge/open/enarx/enarx-wasmldr.svg)](https://isitmaintained.com/project/enarx/enarx-wasmldr "Percentage of issues still open")
![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)

# enarx-wasmldr

The Enarx Keep runtime binary.

It can be used to run a Wasm file with given command-line
arguments and environment variables.

### Example invocation

```console
$ wat2wasm fixtures/return_1.wat
$ RUST_LOG=enarx_wasmldr=info RUST_BACKTRACE=1 cargo run return_1.wasm
    Finished dev [unoptimized + debuginfo] target(s) in 0.07s
     Running `target/x86_64-unknown-linux-musl/debug/enarx-wasmldr target/x86_64-unknown-linux-musl/debug/build/enarx-wasmldr-c374d181f6abdda0/out/fixtures/return_1.wasm`
[2020-09-10T17:56:18Z INFO  enarx_wasmldr] got result: [
        I32(
            1,
        ),
    ]
```

On Unix platforms, the command can also read the workload from the
file descriptor (3):
```console
$ RUST_LOG=enarx_wasmldr=info RUST_BACKTRACE=1 cargo run 3< return_1.wasm
```


License: Apache-2.0
