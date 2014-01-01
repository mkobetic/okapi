package okapi

import (
	"io"
)

/*
Cipher is a symmetric/secret key encryption algorithm, meaning the same key is used to both encrypt and decrypt the data and therefore must be kept secret.
The Cipher API is deliberately simple and consequently somewhat less convenient, CipherWriter and CipherReader should be preferred whenever possible.
*/
type Cipher interface {
	// Update processes input slice and writes the result into the output slice and returns the number of bytes written.
	Update(in, out []byte) int
	// Finish completes the last block of data and writes out whatever is left in the internal buffers and returns the number of bytes written. If the configured cipher mode requires multiples of block size of input (e.g. ECB, CBC), Finish will panic if that condition wasn't met.
	// Update calls are not allowed after Finish is called.
	Finish(out []byte) int
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

var DefaultBufferSize = 16 * 1024

type CipherWriter struct {
	output     io.Writer
	buffer     []byte
	unconsumed uint
	cipher     Cipher
}

func NewCipherWriter(out io.Writer, cc CipherConstructor, key, iv, buffer []byte) *CipherWriter {
	if buffer == nil {
		buffer = make([]byte, DefaultBufferSize)
	}
	return &CipherWriter{output: out, cipher: cc(key, iv, true), buffer: buffer}
}

func (w *CipherWriter) Write(in []byte) (int, error) {
	var (
		total     = 0
		encrypted = 0
	)
	for total < len(in) {
		encrypted = w.cipher.Update(in[total:], w.buffer)
		total += encrypted
		_, err := w.output.Write(w.buffer[:encrypted])
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (w *CipherWriter) Close() error {
	encrypted := w.cipher.Finish(w.buffer)
	if encrypted == 0 {
		return nil
	}
	_, err := w.output.Write(w.buffer[:encrypted])
	return err
}

type CipherReader struct {
	input      io.Reader
	buffer     []byte
	unconsumed uint
	cipher     Cipher
}

func NewCipherReader(in io.Reader, cc CipherConstructor, key, iv, buffer []byte) *CipherReader {
	if buffer == nil {
		buffer = make([]byte, DefaultBufferSize)
	}
	return &CipherReader{input: in, cipher: cc(key, iv, false), buffer: buffer}
}

// func (w *CipherReader) Read(out []byte) (int, error) {
// 	for total := 0; total < len(out); {
// 		read, err := input.Read(buffer)
// 		if err != nil {
// 			return total, err
// 		}
// 		decrypted := cipher.Update(buffer[:read], out[total:])
// 		total += decrypted
// 	}
// 	return total, nil
// }

// func (w *CipherReader) Close() error {
// 	encrypted := cipher.Finish(buffer)
// 	if encrypted == 0 {
// 		return nil
// 	}
// 	_, err := output.Write(buffer[:encrypted])
// 	return err
// }
