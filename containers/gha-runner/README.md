This container encapsulates the GitHub Actions Runner.

# The Problem

When you deploy the GitHub Actions Runner, if it is attached to a public
repo than anyone can submit code to run on your system via a simple pull
request. This isn't great security.

# The Answer

Using this container, we cleanly separate the GitHub Actions Runner
**identity** from the rest of its state. This means that as long as you
follow the instructions below properly, you can blow away any instance
of this container and start a new one and the identity of the GitHub
Actions Runner will persist.

# Deployment

## Setup

First, you must register a new GitHub Actions Runner instance. This
establishes an identity which will persist across container instances.
In order to accomplish this, you must provide three environment
variables (`URL`, `NAME` and `TOKEN`) and a writable volume mounted into
the container at /srv. For example:

```
$ mkdir my_runner
$ podman run --rm -t -v ./my_runner:/srv:rw,Z \
    -e URL=https://github.com/me/my_repo \
    -e NAME=belvedere \
    -e TOKEN=$TOKEN \
    quay.io/enarx/gha-runner
--------------------------------------------------------------------------------
|        ____ _ _   _   _       _          _        _   _                      |
|       / ___(_) |_| | | |_   _| |__      / \   ___| |_(_) ___  _ __  ___      |
|      | |  _| | __| |_| | | | | '_ \    / _ \ / __| __| |/ _ \| '_ \/ __|     |
|      | |_| | | |_|  _  | |_| | |_) |  / ___ \ (__| |_| | (_) | | | \__ \     |
|       \____|_|\__|_| |_|\__,_|_.__/  /_/   \_\___|\__|_|\___/|_| |_|___/     |
|                                                                              |
|                       Self-hosted runner registration                        |
|                                                                              |
--------------------------------------------------------------------------------

# Authentication


√ Connected to GitHub

# Runner Registration



√ Runner successfully added
√ Runner connection is good

# Runner settings


√ Settings Saved.
```

Once this command completes, your identity is provisioned.

## Runtime

In order to run the container, you should ensure two things:

1. All environment variables are removed.
2. The volume mount has been converted to read-only.

For example:

```
$ podman run --rm -t -v ./my_runner:/srv:ro,Z quay.io/enarx/gha-runner

√ Connected to GitHub

2020-06-30 20:39:11Z: Listening for Jobs
```

# Caveats

Until the GitHub Actions Runner supports `podman` and `podman` supports
running nested, unprivileged containers, you will not be able to launch
containers using GitHub Actions workflows. Such is the trade-off for
security.

# Security Considerations

This container enforces that `/srv` is mounted read-only during runtime.

It is presumed that the setup process is run in a trusted environment.
Since this process doesn't accept any jobs from the queue, there is no
opportunity to embed untrusted code from GitHub during the setup process.

Conversely, the runtime process presumes that all incoming jobs are
hostile. An incoming job might be able to do some malicious tasks
(bitcoin mining, spam, etc), but you can always just destroy the
container to remediate the situation. Since during runtime the volume
mount is read-only, the malicious job is unable to persist data across
container instances.

Deployers of this container would do well to consider proactively
destroying and recreating the container at regular intervals to limit
the scope of malicious behavior.
