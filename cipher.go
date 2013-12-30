package okapi

import (
	"io"
)

/*
Cipher is a symmetric/secret key encryption algorithm, meaning the same key is used to both encrypt and decrypt the data and therefore must be kept secret.
The Cipher API is deliberately simple and consequently somewhat less convenient, CipherWriter and CipherReader should be preferred whenever possible.
*/
type Cipher interface {
	// Update processes input slice and writes the result into the output slice and returns the number of input bytes processed.
	Update(in, out []byte) int
	// BlockSize returns the block size in bytes of the underlying encryption algorithm. For stream ciphers the block size is 1.
	BlockSize() int
	// KeySize returns the size of the encryption key in bytes. For some algorithms it is constant for others it can be variable.
	KeySize() int
	// Close MUST be called before discarding a cipher instance to securely discard and release any associated resources.
	Close()
}

// CipherConstructors are used to create instances of Ciphers from a secret key, optional initialization vector (iv) and a boolean indicating whether the cipher instance will be used for encryption or decryption.
type CipherConstructor func(key, iv []byte, encrypt bool) Cipher

// Predefined CipherConstructors for known encryption algorithms and modes, implementations are provided by subpackages. Note that different implementations can support different set of algorithms/modes. If given algorithm/mode combination is not supported, the value of the corresponding variable will be nil.
var (
	AES_ECB, AES_CBC, AES_OFB, AES_CFB, AES_CTR, AES_GCM,
	BF_ECB, BF_CBC, BF_OFB, BF_CFB,
	DES3_ECB, DES3_CBC, DES3_OFB, DES3_CFB,
	RC4 CipherConstructor
)

type CipherWriter struct {
	output io.Writer
	cipher Cipher
}

func NewCipherWriter(out io.Writer, cc CipherConstructor, key, iv []byte) *CipherWriter {
	return &CipherWriter{output: out, cipher: cc(key, iv, true)}
}

type CipherReader struct {
	input  io.Reader
	cipher Cipher
}

func NewCipherReader(in io.Reader, cc CipherConstructor, key, iv []byte) *CipherReader {
	return &CipherReader{input: in, cipher: cc(key, iv, false)}
}
