# sevctl

`sevctl` is a command line utility for managing the AMD Secure Encrypted Virtualization (SEV) platform.
It currently supports the entire management API for the Naples generation of processors.

## Usage

### help

Every `sevctl` (sub)command comes with a quick `--help` option for a reference on its use. For example:

```
$ sevctl --help
```

or

```
$ sevctl show --help
```

### export

Exports the SEV certificate chain to the provided file path.

```
$ sevctl export /path/to/where/you/want/the-certificate
```

### generate

Generates a new (self-signed) OCA certificate and key.

```
$ sevctl generate ~/my-cert ~/my-key
```

### reset

Resets the SEV platform. This will clear all persistent data managed by the platform.

```
$ sevctl reset
```

### rotate

Rotates all the certificates. If the system is _not_ self-owned, the new certificate will
need to be signed by the old with the `--adopt` option to safely rotate.

```
$ sevctl rotate all
```

Rotates the Platform Diffie-Hellman (PDH).

```
$ sevctl rotate pdh
```

### serve

Runs a server to handle OCA certificate signing requests.

```
$ sevctl serve ~/my-cert ~/my-key
```

### show

Describes the state of the SEV platform.

```
$ sevctl show flags
```

```
$ sevctl show guests
```

### verify

Verifies the full SEV/CA certificate chain. File paths to these certificates can be supplied as
command line arguments if they are stored on the local filesystem. If they are not supplied, the
well-known public components will be downloaded from their remote locations.

```
$ sevctl verify
```
