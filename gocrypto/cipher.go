package gocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
	"github.com/mkobetic/okapi"
	"io"
)

func init() {
	okapi.RC4 = RC4
	//okapi.DES3_ECB = DES3_ECB
	okapi.DES3_CBC = DES3_CBC
	//okapi.DES3_CFB = DES3_CFB
	okapi.DES3_OFB = DES3_OFB
	//okapi.AES_ECB = AES_ECB
	okapi.AES_CBC = AES_CBC
	okapi.AES_OFB = AES_OFB
	//okapi.AES_CFB = AES_CFB
	okapi.AES_CTR = AES_CTR
	//okapi.AES_GCM = AES_GCM
}

var (
	RC4      = CipherSpec{stream: func(k []byte) (cipher.Stream, error) { return rc4.NewCipher(k) }}
	AES_CBC  = CipherSpec{block: aes.NewCipher, modeEncrypt: cipher.NewCBCEncrypter, modeDecrypt: cipher.NewCBCDecrypter}
	AES_OFB  = CipherSpec{block: aes.NewCipher, mode: cipher.NewOFB}
	AES_CTR  = CipherSpec{block: aes.NewCipher, mode: cipher.NewCTR}
	DES3_CBC = CipherSpec{block: des.NewTripleDESCipher, modeEncrypt: cipher.NewCBCEncrypter, modeDecrypt: cipher.NewCBCDecrypter}
	DES3_OFB = CipherSpec{block: des.NewTripleDESCipher, mode: cipher.NewOFB}
)

// CipherSpec represents a cipher algorithm.
type CipherSpec struct {
	stream      func(key []byte) (cipher.Stream, error)
	block       func(key []byte) (cipher.Block, error)
	modeEncrypt func(c cipher.Block, iv []byte) cipher.BlockMode
	modeDecrypt func(c cipher.Block, iv []byte) cipher.BlockMode
	mode        func(c cipher.Block, iv []byte) cipher.Stream
}

func (cs CipherSpec) New(key, iv []byte, encrypt bool) okapi.Cipher {
	if cs.stream != nil {
		c, err := cs.stream(key)
		if err != nil {
			panic(err)
		}
		return &StreamCipher{cipher: c, keySize: len(key)}
	}
	c, err := cs.block(key)
	if err != nil {
		panic(err)
	}
	if cs.mode != nil {
		return &StreamCipher{cipher: cs.mode(c, iv), keySize: len(key)}
	}
	var bc *BlockCipher
	if encrypt {
		bc = &BlockCipher{cipher: cs.modeEncrypt(c, iv), keySize: len(key)}
	} else {
		bc = &BlockCipher{cipher: cs.modeDecrypt(c, iv), keySize: len(key)}
	}
	bc.buffer = make([]byte, 0, bc.BlockSize())
	return bc
}

func (cs CipherSpec) NewReader(in io.Reader, key, iv, buffer []byte) *okapi.CipherReader {
	return okapi.NewCipherReader(in, cs, key, iv, buffer)
}

func (cs CipherSpec) NewWriter(out io.Writer, key, iv, buffer []byte) *okapi.CipherWriter {
	return okapi.NewCipherWriter(out, cs, key, iv, buffer)
}

type BlockCipher struct {
	cipher  cipher.BlockMode
	keySize int
	buffer  []byte
}

func (c *BlockCipher) KeySize() int {
	return c.keySize
}

func (c *BlockCipher) BlockSize() int {
	return c.cipher.BlockSize()
}

func (c *BlockCipher) BufferedSize() int {
	return len(c.buffer)
}

func (c *BlockCipher) Update(in, out []byte) (int, int) {
	var outl = len(out) / c.BlockSize() * c.BlockSize()
	if outl == 0 {
		return 0, 0
	}
	var inl = (len(in) + len(c.buffer)) / c.BlockSize() * c.BlockSize()
	if inl > outl {
		inl = outl
	} else {
		outl = inl
	}
	inl -= len(c.buffer)
	copy(out, c.buffer)
	copy(out[len(c.buffer):], in[:inl])
	out = out[:outl]
	c.cipher.CryptBlocks(out, out)
	// save the leftover from in
	in = in[inl:]
	c.buffer = c.buffer[:0]
	if !(len(in) < c.BlockSize()) {
		panic("input exceeded output size by more than a block")
	}
	if len(in) > 0 {
		c.buffer = append(c.buffer, in...)
	}
	return inl + len(c.buffer), outl
}

func (c *BlockCipher) Finish(out []byte) int {
	if len(c.buffer) == 0 {
		return 0
	}
	if len(c.buffer)%c.BlockSize() != 0 {
		panic("input is not multiple of cipher block size")
	}
	if len(c.buffer) > len(out) {
		panic("input is larger than provided output space")
	}
	c.cipher.CryptBlocks(out, c.buffer)
	return len(c.buffer)
}

func (c *BlockCipher) Close() {
}

type StreamCipher struct {
	cipher  cipher.Stream
	keySize int
}

func (c *StreamCipher) KeySize() int {
	return c.keySize
}

func (c *StreamCipher) BlockSize() int {
	return 1
}

func (c *StreamCipher) BufferedSize() int {
	return 0
}

func (c *StreamCipher) Update(in, out []byte) (int, int) {
	c.cipher.XORKeyStream(out, in)
	return len(in), len(in)
}

func (c *StreamCipher) Finish(out []byte) int {
	return 0
}

func (c *StreamCipher) Close() {
	if rc4c, ok := c.cipher.(*rc4.Cipher); ok {
		rc4c.Reset()
	}
}
