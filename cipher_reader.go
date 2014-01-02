package okapi

import (
	"errors"
	"io"
)

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
