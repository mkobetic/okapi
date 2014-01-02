package okapi

import (
	"errors"
	"io"
)

/*
Cipher is a symmetric/secret key encryption algorithm, meaning the same key is used to both encrypt and decrypt the data and therefore must be kept secret.
The Cipher API is deliberately simple and consequently somewhat less convenient, CipherWriter and CipherReader should be used instead whenever possible.
*/
type Cipher interface {
	// Update processes input slice and writes the result into the output slice and returns the number of bytes read and written.
	// Update will return with no progress (0,0), if there is not at least a block size worth of room in out slice.
	Update(in, out []byte) (ins, outs int)
	// Finish completes the last block of data and writes out whatever is left in the internal buffers and returns the number of bytes written. If the configured cipher mode requires multiples of block size of input (e.g. ECB, CBC), Finish will panic if that condition wasn't met.
	// Update calls are not allowed after Finish is called.
	Finish(out []byte) int
	// BlockSize returns the block size of the underlying encryption algorithm in bytes. For stream ciphers the block size is 1.
	BlockSize() int
	// KeySize returns the size of the encryption key in bytes. For some algorithms it is constant for others it can be variable.
	KeySize() int
	// Close MUST be called before discarding a cipher instance to securely discard and release any associated resources.
	Close()
	// Cipher must keep track of how much buffered/unprocessed input it's buffering, this should always be less than block size
	BufferedSize() int
}

// CipherConstructors are used to create instances of Ciphers from a secret key, optional initialization vector (iv) and a boolean indicating whether the cipher instance will be used for encryption or decryption.
type CipherConstructor func(key, iv []byte, encrypt bool) Cipher

// Predefined CipherConstructors for known encryption algorithms and modes, implementations are provided by subpackages. Note that different implementations can support different set of algorithms/modes. If given algorithm/mode combination is not supported by the imported implementations, the value of the corresponding variable will be nil.
var (
	AES_ECB, AES_CBC, AES_OFB, AES_CFB, AES_CTR, AES_GCM,
	BF_ECB, BF_CBC, BF_OFB, BF_CFB,
	DES3_ECB, DES3_CBC, DES3_OFB, DES3_CFB,
	RC4 CipherConstructor
)

var DefaultBufferSize = 16 * 1024

// CipherWriter encrypts bytes being written before passing them down to the underlying writer.
type CipherWriter struct {
	output io.Writer
	buffer []byte
	cipher Cipher
}

func NewCipherWriter(out io.Writer, cc CipherConstructor, key, iv, buffer []byte) *CipherWriter {
	if buffer == nil {
		buffer = make([]byte, DefaultBufferSize)
	}
	return &CipherWriter{output: out, cipher: cc(key, iv, true), buffer: buffer}
}

func (w *CipherWriter) Write(in []byte) (int, error) {
	var (
		total = 0
		ins   = 0
		outs  = 0
	)
	for total < len(in) {
		ins, outs = w.cipher.Update(in[total:], w.buffer)
		total += ins
		_, err := w.output.Write(w.buffer[:outs])
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
	unconsumed int
	cipher     Cipher
}

func NewCipherReader(in io.Reader, cc CipherConstructor, key, iv, buffer []byte) *CipherReader {
	if buffer == nil {
		buffer = make([]byte, DefaultBufferSize)
	}
	return &CipherReader{input: in, cipher: cc(key, iv, false), buffer: buffer}
}

func (r *CipherReader) Read(out []byte) (int, error) {
	buffered := r.cipher.BufferedSize()
	written := 0
	toWrite := len(out)
	for toWrite >= len(r.buffer)+buffered {
		read, err := r.bufferRead(r.buffer, out[written:])
		if err != nil {
			return written + read, err
		}
		written += read
		toWrite -= read
	}
	if toWrite == 0 {
		return written, nil
	}
	// last buffer fill
	blockSize := r.cipher.BlockSize()
	read := min(len(r.buffer), ((toWrite-1)/blockSize+1)*blockSize-buffered)
	read, err := r.bufferRead(r.buffer[:read], out[written:])
	if err != nil {
		return written + read, err
	}
	written += read
	toWrite -= read
	if toWrite == 0 {
		return written, nil
	}
	// we may still be few bytes short, read just enough to decrypt one more block
	read = blockSize - r.cipher.BufferedSize()
	read, err = r.bufferRead(r.buffer[:read], out[written:])
	return written + read, err
}

func (r *CipherReader) bufferRead(buffer, out []byte) (int, error) {
	read, err := r.input.Read(buffer)
	if read == 0 {
		return 0, err
	}
	_, outs := r.cipher.Update(buffer[:read], out)
	return outs, err
}

func (r *CipherReader) Close() error {
	outs := r.cipher.Finish(r.buffer)
	if outs == 0 {
		return nil
	}
	return errors.New("Unfinished cipher block")
}

func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}
