go-ima
======

[![GoDoc](https://godoc.org/pault.ag/go/ima?status.svg)](https://godoc.org/pault.ag/go/ima)

Integrity Measurement Architecture (or IMA) is a component of the Linux kernel
that allows for the signing of binaries, and ensure that software that gets run
is intact.

This repo contains a go native implementation of the IMA signing format,
as well as some basic tools to read and write those to the filesytem.

The interface looks a lot like a `crypto.Signer`, and the goal was to create
an API that was familiar to Go developers. Additionally, this code only requires
a `crypto.Signer` to create Signatures, and a `crypto.PublicKey` to verify them.

This is handy if you have a hardware device (such as an HSM) with blinded
private key material.
