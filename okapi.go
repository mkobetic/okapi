/*
Okapi is a collection of interfaces providing universal API to third-party cryptographic libraries. The intent is to be able transparently mix and match implementations from various sources. Subpackages implement these interfaces by calling external libraries (e.g. OpenSSL's libcrypto, or Microsoft's CNG)
*/
package okapi

var DefaultBufferSize = 16 * 1024

// helpers

func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}
