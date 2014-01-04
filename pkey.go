package okapi

// KeyConstructor creates a PrivateKey for given algorithm and purpose.
// The parameters contain the required constituents of the key
// which are algorithm and key type specific.
// If parameters contain only public key constituents the constructor returns
// a partially initialized PrivateKey that can only be used to obtain a PublicKey from it.
// The parameters may also contain key generation parameters
// in which case a full PrivateKey will be generated
type KeyConstructor func(parameters interface{}) (PrivateKey, error)

// Predefined key constructors for known algorithms and purposes, implementations are provided by subpackages. Note that different implementations can support different set of algorithms/purposes. If given algorithm/purpose combination is not supported by the imported implementations, the value of the corresponding variable will be nil.
var (
	// encryption PKCS1 v1.5 & v2.0
	RSA_15, RSA_OAEP,
	// signing PKCS1 v1.5
	RSA_15_MD5, RSA_15_SHA1, RSA_15_SHA224, RSA_15_SHA256, RSA_15_SHA384, RSA_15_SHA512,
	// signing PKCS1 v2.0
	RSA_PSS_MD5, RSA_PSS_SHA1, RSA_PSS_SHA224, RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
	// signing DSS
	DSA_SHA1, DSA_SHA224, DSA_SHA256, DSA_SHA384, DSA_SHA512,
	ECDSA_SHA1, ECDSA_224, ECDSA_SHA256, ECDSA_384, ECDSA_SHA512,
	// key agreement
	DH, ECDH KeyConstructor
)

// PrivateKey provides private key operations for given public key algorithm and purpose.
// The purpose determines which operations are available:
// * encryption: Decrypt
// * signing: Sign
// * key agreement: Derive
type PrivateKey interface {
	// Decrypt decrypts provided input.
	Decrypt(encrypted []byte) (decrypted []byte, err error)
	// Sign generates a signature for the provided input digest.
	// The digest must match the configured key type.
	// The signature format is algorithm specific
	Sign(digest []byte) (signature []byte, err error)
	// Derive generates a shared secret from the public key
	// provided by the other participant of the key agreement
	Derive(peer PublicKey) (secret []byte, err error)
	// Extract a PublicKey from the PrivateKey
	PublicKey() PublicKey
	// Close MUST be called before discarding a key instance to securely discard and release any associated resources.
	Close()
}

// PublicKey provides public key operations for given public key algorithm and purpose.
// The purpose determines which operations are available:
// * encryption: Encrypt
// * signing: Verify
type PublicKey interface {
	// Encrypt encrypts provided input.
	// Note that the size of input is constrained by the size of the PrivateKey
	Encrypt(plain []byte) (encrypted []byte, err error)
	// Verify checks whether provided signature matches the provided digest.
	// The digest and signature type must match the configured key type.
	Verify(signature []byte, digest []byte) (valid bool, err error)
	// Close MUST be called before discarding a key instance to securely discard and release any associated resources.
	Close()
}
