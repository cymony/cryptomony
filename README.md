<p align="center">
    <img width="450" src="assets/images/ctyptomony.png">
</p>

<p align="center">
    <a href="LICENSE">
        <img src="https://img.shields.io/badge/License-BSD--3-yellow" alt="License">
    </a>
    <a href="https://pkg.go.dev/github.com/cymony/cryptomony">
        <img src="https://pkg.go.dev/badge/github.com/cymony/cryptomony.svg" alt="Go Reference">
    </a>
    <a href="https://goreportcard.com/report/github.com/cymony/cryptomony">
        <img src="https://goreportcard.com/badge/github.com/cymony/cryptomony">
    </a>
    <a href="https://github.com/cymony/cryptomony/actions/workflows/ci-cryptomony.yml">
        <img src="https://github.com/cymony/cryptomony/actions/workflows/ci-cryptomony.yml/badge.svg">
    </a>
    <a href='https://coveralls.io/github/cymony/cryptomony?branch=main'>
        <img src='https://coveralls.io/repos/github/cymony/cryptomony/badge.svg?branch=main' alt='Coverage Status' />
    </a>
</p>

## About

This library contains complete cryptographic protocols or partial implementations. We are publishing this library without guarantee. API, code, algorithm changes may occurs in the future according to Cymony's needs or changes in draft versions.

## Installation

```sh
go get -u github.com/cymony/cryptomony
```

## List of Utility Packages

In general, utility packages are packages prepared for easy usage. They are simple wrappers for the standard library packages.

- [hash](./hash): A wrapper for hash functions.
- [ksf](./ksf): A wrapper for key stretching functions.
- [xof](./xof): A wrapper for extendable-output functions.

## List of Algorithms

### High-Level Protocols

- [OPRFs using Prime-Order Groups](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/)
- [OPAQUE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/)

### Prime-Order Groups on Elliptic Curves

- [P-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
- [P-384](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
- [P-521](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
- [Ristretto](https://datatracker.ietf.org/doc/draft-irtf-cfrg-ristretto255-decaf448/)
- [Hash To Curve](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/)

### Zero-knowledge Proofs

- [DLEQ](https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-16.html#name-discrete-logarithm-equivale)

## License

This project is licensed under the [BSD 3-Clause](./LICENSE)
