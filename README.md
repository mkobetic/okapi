Okapi is a collection of interfaces providing universal API to third-party cryptographic libraries. The intent is to be able transparently mix and match implementations from various sources. Subpackages implement these interfaces by calling external libraries (e.g. OpenSSL's libcrypto, or Microsoft's CNG). These subpackages serve both as default implemenations as well as templates for plugging in other libraries (e.g. cryptographic tokens, hardware accellerators, etc.)


Implementation Notes
====================

* Allocating C-structures in Go memory is fine as long as the garbage collector is either non-moving or at least stop-the-world type. Both of these conditions hold as of Go 1.2. As soon as Go objects start moving around while the C-call is in progress, the allocation strategy will have to be completely rethought. At this point it seems we'll be fine for foreseable future though.