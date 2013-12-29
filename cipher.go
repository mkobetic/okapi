package okapi

import (
	"io"
)

type Cipher interface {
	Update(in, out []byte) int
	BlockSize() int
	Close()
}

type CipherConstructor func(key, iv []byte, encrypt bool) Cipher

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
