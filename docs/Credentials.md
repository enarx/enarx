# Credential handling

By default, login credentials are stored securely using the secure store provided by your platform, e.g. on Linux it would use the [D-Bus secrets service](https://specifications.freedesktop.org/secret-service/latest/).

## Credential helpers

It is also possible to override the keychain storage and use a custom credential helper instead.

A credential helper is a program, which is called by `enarx` with two positional arguments a `mode` as the first and an `oidc_domain` as the second like so: `<credential helper> <insert|show> <oidc_domain>`.

### `insert` mode

When called with `"insert"` in the first argument, credential helper should read and securely store the secret associated with `oidc_domain` passed in the second argument from stdin.

Example invocation:

```sh
enarx-credential-helper-mybackend insert auth.profian.com
```

### `show` mode

When called with `"show"` in the first argument, credential helper should write the secret associated with `oidc_domain` passed in the second argument to stdout.

Example invocation:

```sh
enarx-credential-helper-mybackend show auth.profian.com
```

### Configuration

In order to use a credential helper, either set `ENARX_CREDENTIAL_HELPER` environment variable equal to absolute path to an executable credential helper or pass it via `credential-helper` command-line flag.

Example invocation:
```sh 
enarx user login --credential-helper /usr/bin/enarx-credential-helper-gopass
```

Alternatively:
```sh 
ENARX_CREDENTIAL_HELPER=/usr/bin/enarx-credential-helper-gopass enarx user login
```

Eventually, it will be possible to configure credential helpers via a CLI configuration file. Please follow https://github.com/enarx/enarx/issues/2021 for more details.

### Example credential helpers

#### Pass

The following credential helper can be used to store credentials in [`pass`](https://www.passwordstore.org/):

```sh
#!/bin/sh
set -e
if [ "${1}" = "insert" ]; then
    exec pass insert -f -m "misc/enarx/${2}" 1> /dev/null
elif [ "${1}" = "show" ]; then
    exec pass show "misc/enarx/${2}"
else
    echo "Unknown command '${1}'"
    exit 1
fi
```

#### Gopass

The following credential helper can be used to store credentials in [`gopass`](https://www.gopass.pw/):

```sh
#!/bin/sh
set -e
if [ "${1}" = "insert" ]; then
    exec gopass insert -f "misc/enarx/${2}"
elif [ "${1}" = "show" ]; then
    gopass find misc/enarx 1>/dev/null 2>/dev/null
    exec gopass show -n -o "misc/enarx/${2}"
else
    echo "Unknown command '${1}'"
    exit 1
fi
```
