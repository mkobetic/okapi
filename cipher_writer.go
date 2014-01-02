package okapi

import (
	"io"
)

// CipherWriter encrypts bytes being written before passing them down to the underlying writer. CipherWriter MUST be closed before it's discarded.
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
