# Attestation Documentation

This directory contains information on attestation for the various
technologies involved. Technologies are listed in alphabetical order.

Please note that attestation is a deeply technical process and readers
should be familiar with some [prerequisite concepts](./prerequisites.md)
before reading this document.

### Colors

In process diagrams, colors mean the following:

* Green: Implicitly Trusted
* Red: Untrusted
* Yellow: Trusted via a Cryptographic Root of Trust
* Orange: Trusted via Cryptographic Measurement

In certificate chain diagrams, colors mean the following:

* Blue: The private key is accessable only by hardware.

## IBM

### PEF

![ibm pef process](./ibm/pef/process.msc.png)
![ibm pef cert chain](./ibm/pef/certchain.dot.png)

## Intel

### SGX

TBD
