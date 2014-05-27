package okapi

/*
Hash is a cryptographic hash algorithm that computes a fixed sized digest from arbitrary amount of byte input.
Input is written into Hashes the same way as into Writers.
Unlike hash.Hash, computing the digest finalizes the internal state of the Hash
and no more input can be written into it (unless it is Reset first).
If an intermediate digest is required, or the hash computation needs to diverge and continue
along separate input lines, clone the Hash after processing the common initial part of the input.
*/
type Hash interface {
	// Write is used to submit input to the Hash compution.
	// It conforms to standard Writer interface
	Write([]byte) (int, error)
	// Digest finalizes the hash computation and provides the digest value.
	// No more input into the hash is possible after Digest is called (unless the Hash is Reset)
	Digest() []byte
	// Size returns the byte size of the digest value (this is constant
	// and depends solely on the type of hash algorithm used)
	Size() int
	// BlockSize returns byte size of the hash algorithm block (this is constant
	// and depends solely on the type of the hash algorithm used)
	BlockSize() int
	// Clone creates a complete copy of the Hash. The copy is in the same state
	// as if it processed the same input as the original Hash.
	// This can be used to obtain intermediate digest values or to diverge along different input paths.
	Clone() Hash
	// Reset reinitializes the Hash to initial state as if no input was processed yet.
	// This can be used to recycle Hash instances.
	Reset()
	// Close MUST be called before a Hash is discarded, to properly discard and release its associated resources
	Close()
}

// HashSpecs are used to create instances of Hashes.
type HashSpec interface {
	New() Hash
}

// Predefined HashSpecs for known hash algorithms.
// Implementations are provided by sub-packages.
var (
	MD4, MD5, SHA1,
	SHA224, SHA256, SHA384, SHA512,
	RIPEMD160 HashSpec
)

// MAC is a keyed Hash. MACs support the Hash interface, the only difference is
// That they require a HashSpec and a key being created.
// MACSpec is used to create instances of MACs.
type MACSpec interface {
	New(hash HashSpec, key []byte) Hash
}

// Predefined MACSpecs for know MAC algorithms.
// Implementations are provided by sub-packages.
var (
	HMAC MACSpec
)
