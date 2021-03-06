Okapi is a collection of interfaces providing universal API to third-party cryptographic libraries. The intent is to be able transparently mix and match implementations from various sources.

Subpackages implement these interfaces by calling external libraries (e.g. OpenSSL's libcrypto, or Microsoft's CNG). These subpackages serve both as default implemenations as well as templates for plugging in other libraries (e.g. cryptographic tokens, hardware accellerators, etc.)

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

DONE
====

* libcrypto: hashes, symmetric ciphers, RSA, DSA and DH
* gocrypto: hashes and symmetric ciphers
* mscng: only a sketch of hash implementation, may not even compile yet (having difficulties with cgo dev on Windows)

TODO
====

* libcrypto: ECDH, ECDSA
* libcrypto: add PKCS8 import/export for PrivateKey
* libcrypto: add X.509 import/export for PublicKey
* libcrypto: portable signature import/export
* figure out proper GCM interface
* gocrypto: AEAD
* gocrypto: RSA, DSA, DH
* gocrypto: ECDSA, ECDH
* benchmarks
* mscng: catch up
* more test coverage
