# Publish & Deploy Apps

Enarx is more than just a tool for running WebAssembly. It also allows you to publish a WebAssembly package to a remote package host, as well as securely run a published package in a local Enarx keep. The following sections will demonstrate this process, along with other useful commands for interacting with a package host.

## Registering a user and authenticating with the package host

Before we begin, you will need a GitHub account in order to authenticate to the package host.

First, register a new user with the package host using the `enarx user register` command, as shown here:

```
enarx user register your_username
```

Upon entering this command, Enarx will print two things to your terminal: a web page URL, and a unique one-time code. Open the URL (on any device), then enter the one-time code into the form field on the web page. Once you have entered the code, it will ask to connect to your GitHub account. Follow the instructions shown on the page, and when you have finished connecting your GitHub account you may close the page and return to your terminal. Note that it may take a few moments before your terminal finishes authenticating with GitHub. Once it does, it will notify you that your credentials have been saved locally. The command will then exit, indicating that your user account has been successfully registered.

Note that in the future when you need to log in again (for example, if you are connecting from a different computer), you can do so with the `enarx user login` command, as shown here:

```
enarx user login
```

## Registering a new repository

Before you can publish a package, you will first have to register the repository with the package host. You can do so with the `enarx repo register` command, as shown here:

```
enarx repo register your_username/your_reponame
```

In the above example, `your_username` is the username that you registered previously, and `your_reponame` is the name that you want this repository to have.

## Publishing a WebAssembly package

Before you can publish, you will first need to [compile your application to WebAssembly](../WebAssembly/Introduction). At the end of this process you will have a file with the `.wasm` file extension. Rename this file to `main.wasm` and place it in the same directory as a properly configured [`Enarx.toml`](Enarx_toml).

<!--- TODO: Remove this requirement once https://github.com/profianinc/drawbridge/issues/244 is resolved -->
**NOTE**: Currently Enarx.toml and main.wasm need to be the only files in the directory.

Once you have a directory containing a `main.wasm` and an `Enarx.toml`, we can *publish* this directory to the package host with the `enarx package publish` command, as shown here:

```
enarx package publish your_username/your_reponame:0.1.0 your_directory
```

In the above example, `0.1.0` is a *tag*, which identifies a unique version of the package being uploaded to this repository.

## Running a published package

Once a package has been published, it can be run directly with the `enarx deploy` command, as shown here:

```
enarx deploy some_username/some_reponame:0.1.0
```

Unlike `enarx repo register` and `enarx package publish`, this command does not require authentication and can deploy any public package.

## Retrieving information about a user, repository, or package

You can view information about repositories and packages via the `info` family of commands.

The following command will show the tags of all packages published to a given repository:

```
enarx repo info some_username/some_reponame
```

The following command will show information about a specific package:

```
enarx package info some_username/some_reponame:0.1.0
```

## Manually specifying a package host

All the previous examples in this document have made use of the default package host. However, it is also possible to specify other package hosts. Generally this is done by explicitly specifying a domain name as a prefix to the username. Here's an example of `enarx package info` using a non-default package host:

```
enarx package info example.com/some_username/some_reponame:0.1.0
```

Any valid domain name is permitted, and a port may be explicitly specified:

```
enarx package info localhost:1234/some_username/some_reponame
```
