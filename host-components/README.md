# How to run the host-components

MikeCamel@github.com

2020-08-11

This file explains the steps you need to run the Enarx host-components
as a Proof of Concept demo.  The exact capabilities of this demo will
change over time, and so this document should be updated to reflect that.

## What the demo shows

The demo is made up of several components:
- a keep-manager
- multiple keep-loaders, created by the by the keep-manager using
systemctl
- an app-loader, which waits for, and then runs, a WebAssembly file
- a keep-manager-tester, which talks to the keep-manager, requesting
information, setting up the keep-loaders and preparing them to accept
the WebAssembly file
- an app-loader-tester, which sends the app-loader a WebAssembly file

## Preparing the demo

 - The demo currently only runs on a single machine, as it listens on
localhost.
 - The demo currently has no support for Keeps running in TEEs: it supports
wasmtime.
 - The demo currently has little support for outputs from a workload.
 - The demo currently doesn't support filesystem access from a workload.
 - The demo currently doesn't support socket access from a workload.
 - The demo currently has a hard-coded .wasm (WebAssembly) file to run.
 Others can be used, but do not expect much output!

JSON is used for communications.
Communications to the keep-manager from the keep-manager-tester are over HTTPS.
Communications to the app-loader from the app-loader-tester are over HTTPS
with both client and server certificates (the latter being created and self-
signed by the app-loader).

In order to run the demo, you shouldn't need any tools beyond those normally
required to compile Enarx.

Steps:
1. download the latest source code from github (the easiest way is to do a
`git clone` of the repository.
2. enter the enarx/keep-runtime directory
3. run `cargo build`
4. enter the enarx/host-components directory
5. edit the file `lib.rs` to reflect the location on your system of the
`keep-runtime` binary created in previous
6. run `cargo build`
7. enter the enarx/host-components directory
8. edit the file `enarx-keep@.service` to update the `ExecStart` entry
to reflect the location of the `keep-loader` binary created in the previous
step
9. edit the file `enarx-keep@.service` to update the `StandardOutput` and
`StandardError` entries to reflect your preferred locations for the files to
record stdio and stderr
10. run `sudo ln -s enarx-keep@.service /etc/systemd/user/enarx-keep@.service`
11. run `sudo systemd reload-daemon` (running this with the parameter `--user`
**may** work)

If you have run the demo before, you should kill old instances
of the keep-loader.  This is best down by running the command
`pkill -9 keep-loader`.  You may also wish to delete any keeploader output
files (the locations of which you set in step 9).  Although it's unlikely to
have any impact on the demo, you may wish to clean up old files with
`rm /tmp/enarx-keep*.sock`.

**NOTE** if you make any changes to the keep-loader.rs file, after recompiling
it, you will need to remove the old link in /etc/systemd/user/, recreate it
(step 10 above), and perform reload the systemctl daemon (step 11 above).

## Running the demo

You will need two different command line terminals, both running on the same
machine.

Terminal 1 - server:
 - enter the `enarx/host-components` directory
 - run the command `.target/debug/keep-manager`
 - you should see the keep-manager starting up
 - move to Terminal 2 - client.

Terminal 2 - client:
 - enter the `enarx/host-components` directory
 - run the command `.target/debug/keep-manager-tester`
 - follow the instructions
 - once the binary has finished executing, you will be prompted
 to run another command (the app-loader-tester).  Follow these instructions.
 - if everything has executed correctly, you can visit the file locations that
 you specified for `StandardOutput` and `StandardErr` and see the results of
 running the WebAssembly.
 - move to Terminal 1 - server.

Terminal 1 - server:
 - halt the running process with CTRL-C.  Start it again with the command
 `.target/debug/keep-manager`.  You should see that it has found the keep-loaders
 that it created last time, and provided you with some information about them.
 - move to Terminal 2 - client.

Terminal 2 - client:
 - you can run the same series of commands again
 - note the differences in numbers of keep-loaders available, and the command
 to run with app-loader-tester, which should be different

## Improving the demo

There are numerous "TODO" comments in the source files for the demo,
and if you are interested in taking on any of the work to improve it,
please identify a relevant issue (or create a new one) at
[https://github.com/enarx/enarx/issues](https://github.com/enarx/enarx/issues).

