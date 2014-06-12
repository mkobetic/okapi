package okapi

import (
	"errors"
	"io"
)

// CipherReader decrypts bytes read from the underlying Reader.
// CipherReader MUST be closed before it's discarded.
type CipherReader struct {
	input  io.Reader
	buffer []byte
	cipher Cipher
}

// NewCipherReader creates CipherReader wrapped around provided Reader.
// The associated cipher is created from the provided CipherSpec, key and iv.
// The optional buffer is used internally. If buffer is not provided,
// it will be created with DefaultBufferSize.
func NewCipherReader(in io.Reader, cs CipherSpec, key, iv, buffer []byte) *CipherReader {
	if buffer == nil {
		buffer = make([]byte, DefaultBufferSize)
	}
	return &CipherReader{input: in, cipher: cs.New(key, iv, false), buffer: buffer}
}

// Read reads necessary amount of input from the underlying Reader and decrypts it
// into the provided slice. It conforms to the io.Reader interface.
// Note that due to the nature of block ciphers, certain amount of read-ahead is necessary
// to provide the requested amount of bytes, although best effort is made to minimize the amount
// of read-ahead (generally only the input necessary to decrypt the last partially read block).
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
	// TODO: ignoring ins is fishy, what if the cipher does not consume all input?
	_, outs := r.cipher.Update(buffer[:read], out)
	return outs, err
}

// Close checks that there isn't any pending input left, then releases any associated resources, e.g. the cipher.
// If the underlying Reader is a Closer, then it Closes it as well.
func (r *CipherReader) Close() error {
	defer r.cipher.Close()
	outs := r.cipher.Finish(r.buffer)
	if outs != 0 {
		return errors.New("Unfinished cipher block")
	}
	if closer, ok := r.input.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
