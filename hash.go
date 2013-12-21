package okapi

import (
	"fmt"
)

// Hash is a cryptographic hash algorithm that computes a fixed sized digest from arbitrary amount of byte input. Input is written into Hashes the same way as into Writers.
// Unlike hash.Hash, computing the digest finalizes the internal state of the Hash and no more input can be written into it (unless it is Reset first). If an intermediate Digest is required, or the hash computation needs to diverge and continue along separate input lines, clone the Hash after processing the common initial part of the input.
type Hash interface {
	// Write is used to submit input to the Hash compution. It conforms to standard Writer interface
	Write([]byte) (int, error)
	// Digest finalizes the hash computation and provides the digest value. No more input into the hash is possible after Digest is called (unless the Hash is Reset)
	Digest() []byte
	// Size returns the byte size of the digest value (this is constant and depends solely on the type of hash algorithm used)
	Size() int
	// BlockSize returns byte size of the hash algorithm block (this is constant and depends solely on the type of the hash algorithm used)
	BlockSize() int
	// Clone creates a complete copy of the Hash. The copy is in the same state as if it processed the same input as the original Hash. This can be used to obtain intermediate digest values or to diverge along different input paths.
	Clone() Hash
	// Reset reinitializes the Hash to initial state as if no input was processed yet. This can be used to recycle Hash instances.
	Reset()
	// Close MUST be called before a Hash is discarded, to properly discard and release its associated resources
	Close()
}

// HashAlgorithm identifies particular cryptographic hash algorithm. It provides implementation agnostic way of identifying hash algorithms.
type HashAlgorithm uint

// Known hash algorithms, matches the codes of crypto/Hash
var (
	SHA224, SHA256, SHA384, SHA512 func() Hash
)

const (
	MD4 HashAlgorithm = 1 + iota
	MD5
	SHA1
	//	SHA224
	//	SHA256
	//	SHA384
	//	SHA512
	_
	RIPEMD160
	MAX_HASH // always keep this last
)

// Internal registry of default hash algorithm implementations. Hash implementation packages will automatically register their implementations here. This registry can be further tuned with the Use() function.
var hashes = make([]func() Hash, MAX_HASH)

// Creates and instance of Hash from a HashAlgorithm value using the default implementation as is reflected in the hashes registry.
func (h HashAlgorithm) New() Hash {
	if h < MAX_HASH {
		if f := hashes[h]; f != nil {
			return f()
		}
	}
	panic(fmt.Sprintf("Unavailable hash algorithm %d", h))
}

// Registers a Hash creation function for given hash algorithm in the default implementation registry.
func (h HashAlgorithm) Use(f func() Hash) {
	if h < MAX_HASH {
		hashes[h] = f
	} else {
		panic(fmt.Sprintf("Unknown hash algorithm %d", h))
	}
}
