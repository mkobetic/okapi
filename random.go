package okapi

// Random is a cryptographicly secure pseudo-random byte generator.
// The interface complies with io.Reader interface (similarly to crypto/rand package).
// The interface also include a Close method to allow resource release in specific implementations.
type Random interface {
	// Read fills provided size with random bytes.
	Read([]byte) (int, error)
	// Close MUST be called before a Random is discarded, to properly discard and release its associated resources
	Close()
}

// RandomSpecs are used to create instances of Random.
type RandomSpec interface {
	New() Random
}

// Set of predefined (well known) RandomSpecs.
var (
	// Default represents the default (unspecified) PRNG of imported implementation.
	DefaultRandom RandomSpec
)
