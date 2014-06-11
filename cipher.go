package okapi

import (
	"io"
)

// Cipher is a symmetric/secret key encryption algorithm, meaning the same key is used
// to both encrypt and decrypt the data and therefore must be kept secret.
// The Cipher API is deliberately simple and consequently somewhat less convenient,
// CipherWriter and CipherReader should be used instead whenever possible.
type Cipher interface {
	// Update processes (encrypts or decrypts) input slice and writes the result into the output slice.
	// It returns the number of bytes read and written. The input and output may be the same slice.
	// Update will return with no progress (0,0), if there is not at least
	// a block size worth of room in out slice.
	Update(in, out []byte) (ins, outs int)
	// Finish completes the last block of data and writes out whatever is left
	// in the internal buffers and returns the number of bytes written.
	// If the configured cipher mode requires multiples of block size of input (e.g. ECB, CBC),
	// Finish will panic if that condition wasn't met.
	// Update calls are not allowed after Finish is called.
	Finish(out []byte) int
	// BlockSize returns the block size of the underlying encryption algorithm in bytes.
	// For stream ciphers the block size is 1.
	BlockSize() int
	// KeySize returns the size of the encryption key in bytes. For some algorithms
	// it is constant for others it can be variable.
	KeySize() int
	// Close MUST be called to securely discard and release any associated secrets and resources.
	Close()
	// Cipher must keep track of how much buffered/unprocessed input it's buffering,
	// this should always be less than block size
	BufferedSize() int
}

// CipherSpecs are used to create instances of Ciphers from a secret key and
// an optional initialization vector (iv).
type CipherSpec interface {
	// New creates a Cipher from the CipherSpec, key and iv. The encrypt boolean
	// indicates whether the Cipher will be used for encryption or decryption.
	New(key, iv []byte, encrypt bool) Cipher
	// NewReader creates CipherReader wrapped around provided Reader.
	// The associated Cipher is created from the CipherSpec, key and iv.
	// The optional buffer is used internally. If buffer is not provided,
	// it will be created with DefaultBufferSize.
	NewReader(in io.Reader, key, iv, buffer []byte) *CipherReader
	// NewWriter creates CipherWriter wrapped around provided Writer.
	// The associated cipher is created from the CipherSpec, key and iv.
	// The optional buffer is used internally. If buffer is not provided,
	// it will be created with DefaultBufferSize.
	NewWriter(out io.Writer, key, iv, buffer []byte) *CipherWriter
}

// Predefined CipherSpecs for known encryption algorithms and modes.
// Implementations are provided by subpackages.`
// Note that the set of supported algorithms/modes can differ among implementations.
// If given algorithm/mode combination is not supported by the imported implementations,
// the value of the corresponding variable will be nil.
var (
	AES_ECB, AES_CBC, AES_OFB, AES_CFB, AES_CTR, AES_GCM,
	BF_ECB, BF_CBC, BF_OFB, BF_CFB,
	DES3_ECB, DES3_CBC, DES3_OFB, DES3_CFB,
	RC4 CipherSpec
)
