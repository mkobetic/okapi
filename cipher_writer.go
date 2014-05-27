package okapi

import (
	"io"
)

// CipherWriter encrypts written bytes then writes the encrypted bytes into the underlying Writer.
// CipherWriter MUST be closed before it's discarded.
type CipherWriter struct {
	output io.Writer
	buffer []byte
	cipher Cipher
}

// NewCipherWriter creates CipherWriter wrapped around the provided Writer.
// The associated cipher is created from the provided CipherSpec, key and iv.
// The optional buffer is used internally. If buffer is not provided,
// it will be created with DefaultBufferSize.
func NewCipherWriter(out io.Writer, cs CipherSpec, key, iv, buffer []byte) *CipherWriter {
	if buffer == nil {
		buffer = make([]byte, DefaultBufferSize)
	}
	return &CipherWriter{output: out, cipher: cs.New(key, iv, true), buffer: buffer}
}

// Write encrypts bytes from the provided slice and writes the encrypted bytes into the underlying writer.
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

// Close finishes encryption of any pending input and writes it into the underlying Writer.
// Then it releases associated resources, e.g. the cipher.
// If the underlying Writer is a Closer, it will close it as well.
func (w *CipherWriter) Close() error {
	defer w.cipher.Close()
	encrypted := w.cipher.Finish(w.buffer)
	if encrypted != 0 {
		if _, err := w.output.Write(w.buffer[:encrypted]); err != nil {
			return err
		}
	}
	if closer, ok := w.output.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
