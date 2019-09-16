# xcrypto

Miscellaneous crypto-related utility packages written in Go.

# Components

See the individual directories for licensing information.

## pkcs12

This is a a fork of
[golang.org/x/crypto/pkcs12](https://godoc.org/golang.org/x/crypto/pkcs12)
which adds flexible encoding support. It constructs PKCS#12 `.pfx`
files capable of being read (at least) by:

* Its own decoder.
* `openssl pkcs12`.
* Java's PKCS12 keystore implementation.

We have not attempted to push this upstream because past attempts to
push analogous code have been declined.

To build and test:

    cd pkcs12
    go test -v ./...
    ./test-openssl
    ./test-java

## KDF

KDF includes from-scratch implementations of the [KDF1 and KDF2 key derivation algorithms](https://www.shoup.net/iso/std6.pdf) used in various cryptographic schemes.
The 2 flavors of KDF implement the standard `io.Reader` interface. The code includes known answer tests and example
usage.