# Enarx

## Introduction
Enarx is an application deployment system enabling applications
to run within Trusted Execution Environments (TEEs) without rewriting for
particular platforms or SDKs. It handles attestation and delivery into a
run-time “Keep” based on WebAssembly, offering developers a wide range of
language choices for implementation. Enarx is CPU-architecture independent,
enabling the same application code to be deployed across multiple targets,
abstracting issues such as cross-compilation and differing attestation
mechanisms between hardware vendors. Work is currently underway on AMD SEV and
Intel SGX.

We've known for a long time that we need encryption for data at rest and in
transit: Enarx helps you do encryption for data as well as algorithms in use.

[Read more](https://github.com/enarx/enarx/wiki/Enarx-Introduction)

## Project aim
The aim of the Enarx project is to create a way to allow easy deployment of
applications using Trusted Execution Environments (TEEs) across multiple
platforms, with strong security properties.


Deployed workloads should be:
* Confidentiality protected from the host and from other workloads
* Integrity protected from the host and from other workloads
* Cryptographically attested at every instance deployment
* Platform-agnostic at deployment time
  * able to run on multiple silicon architectures without recompilation
  * able to run on any cloud, Edge or other environment which provides
     appropriate hardware 
* Language-agnostic at development time
  * able to be written in multiple languages and compiled to a single package

The mechanism itself should be capable of being FIPS-certified.

## Getting Started

Please check our [wiki](https://github.com/enarx/enarx/wiki), which includes
further details on how to get more information.  It's also where we plan to
keep up-to-date project information.

Ready to dive in? Learn [how to
contribute](https://github.com/enarx/enarx/wiki/How-to-contribute) on the wiki.

Building the various components of Enarx is currently complex: we are working on
this.  Please [contact us](https://chat.enarx.dev) for help.

## Authors

See the list of [people](https://github.com/orgs/enarx/people) who participate in this project.

## License

This project is licensed under the Apache 2.0 license - see the
[LICENSE](LICENSE) file for details

## Sponsors

Enarx would not be possible without the support of its sponsors. Many thanks to
all who contribute to the long term succes of this project!

### Confidential Computing Consortium

Enarx is a software project in the [Confidential Computing
Consortium](https://confidentialcomputing.io), a project community at the Linux
Foundation dedicated to defining and accelerating the adoption of confidential
computing.

### Red Hat

[Red Hat](https://www.redhat.com) employs many of the engineers who work on this
project.

### Packet

[Packet](https://www.packet.com) currently provides development and testing
infrastructure to the Enarx project from their easy to use bare-metal cloud.
