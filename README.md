Okapi is a collection of interfaces providing universal API to third-party cryptographic libraries. The intent is to be able transparently mix and match implementations from various sources. Subpackages implement these interfaces by calling external libraries (e.g. OpenSSL's libcrypto, or Microsoft's CNG). These subpackages serve both as default implemenations as well as templates for plugging in other libraries (e.g. cryptographic tokens, hardware accellerators, etc.)

Usage
=====

An application will need to import both the general okapi package to get access to the API, but also any implementation packages that it wants to employ. However if the application doesn't use any implementation specific types directly, which should be the usual case, Go will complain about an unused import. In this case a [blank import](http://golang.org/doc/effective_go.html#blank_import) of the implementation has to be used, for example:

```go
import (
  "github.com/mkobetic/okapi"
  _ "github.com/mkobetic/okapi/libcrypto"
)
```

See tests subdirectory for usage examples, the test files are mostly go testing style examples.

Status
======

* libcrypto implementation is under active development hashes and symmetric ciphers should be mostly functional
* mscng implementation has only a sketch of hash implementation currently, may not even compile yet

TODO
====

 * libcrypto: implement pkey
 * libcrypto: add pkey generation support
 * libcrypto: add PKCS8 import/export for PrivateKey
 * libcrypto: add X.509 import/export for PublicKey
 * libcrypto: add PublicKey construction support
 * libcrypto: add HMAC support to hashes
 * libcrypto: add random support
 * mscng: catch up
 * gocrypto implementation
 * benchmarks