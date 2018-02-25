[![build status](https://gitlab.com/matthegap/tiny-asn1/badges/develop/build.svg)](https://gitlab.com/matthegap/tiny-asn1/commits/develop)

# Summary

A very small library which can encode and parse DER encoded ASN.1 data structures

The library is intended to be used on 32-bit microcontrollers

# Features

* Can encode and decode arbitrary DER encoded data
* Uses no memory on the heap

# License

This code can be used under the terms of the LGPLv3 license.
For the details see LICENSE.

# Usage

## Requirements

CMake is needed to create the Makefiles, gcc and pkg-config for the build, libcheck to run the unit tests.
If you are on Ubuntu Xenial, you need the following packages:

    cmake pkg-config check gcc g++

## Build

    cmake .
    make
    make test

## Use

After building with the commands above, you can find `libtiny-asn1.a` in the build/ directory, which you can copy to whatever place you need it. The neccesary header file is `src/tiny-asn1.h`.

## Documentation

The API documentation can be created with

    make doc

Afer that, open `doc/html/index.html` in a browser of your choice.

# Acknowledgments

This code was in part inspired by [libtomcrypt](https://github.com/libtom/libtomcrypt) and the book `Cryptography for Developers` by Tom St Denis and Simon Johnson.
