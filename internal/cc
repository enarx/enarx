#!/usr/bin/python3

# This file MUST NOT be named `ld`, otherwise Rust will try to outsmart us.

# The purpose of this file is to wrap invocations of the system linker so that
# we can modify the command line on a per-crate basis. Modifying the command
# line of the linker invocation is as simple as dropping a `link.json` file
# in the root of your crate and specifying this script as your linker in
# your `.cargo/config` file:
#
#  [build]
#  rustflags = [ "-C", "linker=./cc" ]
#
# The `link.json` file looks like this (all fields are optional):
#
#  {
#     "script": {
#       "replace": { "-lba[rz]": [ "-Wl,--whole-archive", "-lbar", "-lbaz" ] },
#       "prepend": [ "-lbar" ],
#       "append": [ "-lbaz" ],
#       "append-target-rlib": ["libc"],
#       "debug": false
#     },
#     "build": {
#       "replace": { "-lba[rz]": [ "-Wl,--whole-archive", "-lbar", "-lbaz" ] },
#       "prepend": [ "-lbar" ],
#       "append": [ "-lbaz" ]
#       "append-target-rlib": ["libc"],
#       "debug": false
#     },
#     "test": {
#       "replace": { "-lba[rz]": [ "-Wl,--whole-archive", "-lbar", "-lbaz" ] },
#       "prepend": [ "-lbar" ],
#       "append": [ "-lbaz" ]
#       "append-target-rlib": ["libc"],
#       "debug": false
#     }
#  }
#
# The "script", "build" and "test" fields indicate the modifications to
# perform during the compilation of the build script (`build.rs`), all crate
# artifacts and tests, respectively.
#
# The "replace" field replaces all arguments that match the regex field with
# zero or more arguments. The positioning in the arguments is maintained
# so that position-relative meanings between arguments is preserved.
#
# The "prepend" and "append" fields add a new argument to the linker
# invocation at the start or end of the arguments, respectively.
#
# The "append-target-rlib" field adds a rust rlib of the target directory.
# E.g. if "libc" is specified,
# $HOME/.rustup/[…]/x86_64-unknown-linux-musl/lib/liblibc-6c4492b949101b15.rlib
# is added to the linker invocation at the end of the arguments as a static library.
#
# The "debug" field, when `true`, causes this script to dump all linker
# arguments and environment variables to the console and exit with a failure.
# This is useful for debugging the modifications to the linker arguments.
#
# Crates that do not specify `link.json` will execute the linker without
# modifying the linker arguments.

import shutil
import pprint
import json
import sys
import os
import re
import glob

def replace(argv, regex, values):
    assert(isinstance(values, list))

    for a in argv:
        if re.match(regex, a):
            for v in values:
                yield v
        else:
            yield a

# Find the real compiler.
cc = os.getenv('CC')
if cc is None:
    cc = shutil.which('cc')
assert(cc is not None)
argv = sys.argv[1:]


target_rlib_dir = \
    os.path.dirname([x for x in argv if x.find("libcompiler_builtins") != -1 and x.endswith(".rlib")][0])

try:
    path = os.getenv('CARGO_MANIFEST_DIR')
    file = os.path.join(path, 'link.json')
    with open(file) as f:
        link = json.load(f)
        assert(isinstance(link, dict))

    # Determine what we are trying to link.
    if len([a for a in argv if "build_script_build" in a]) > 0:
        link = link.get("script", {})
    elif len([a for a in argv if "/libtest-" in a]) > 0:
        link = link.get("test", {})
    else:
        link = link.get("build", {})

    # Replace any items that match the regex.
    for (regex, values) in link.get("replace", {}).items():
        argv = list(replace(argv, regex, values))

    # Prepend and append new items.
    argv = link.get("prepend", []) + argv + link.get("append", [])

    for name in link.get("append-target-rlib", []):
        rlibs = glob.glob(target_rlib_dir + "/lib" + name + "-*.rlib")
        argv.append("-Wl,--push-state")
        argv.append("-Wl,-Bstatic")
        for rlib in rlibs:
            argv.append(rlib)
        argv.append("-Wl,--pop-state")

    if link.get("debug", False):
        pprint.pprint(dict(os.environ))
        pprint.pprint(argv)
        sys.exit(1)
except FileNotFoundError:
    pass

# Execute the real linker.
os.execvp(cc, [cc] + argv)
