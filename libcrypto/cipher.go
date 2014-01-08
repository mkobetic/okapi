// +build !windows

package libcrypto

// #include <openssl/evp.h>
import "C"
import (
	"fmt"
	"github.com/mkobetic/okapi"
	"unsafe"
)

func init() {
	okapi.RC4 = RC4.constructor()
	okapi.BF_ECB = BF_ECB.constructor()
	okapi.BF_CBC = BF_CBC.constructor()
	okapi.BF_CFB = BF_CFB.constructor()
	okapi.BF_OFB = BF_OFB.constructor()
	okapi.DES3_ECB = DES3_ECB.constructor()
	okapi.DES3_CBC = DES3_CBC.constructor()
	okapi.DES3_CFB = DES3_CFB.constructor()
	okapi.DES3_OFB = DES3_OFB.constructor()
	okapi.AES_ECB = AES_ECB.constructor()
	okapi.AES_CBC = AES_CBC.constructor()
	okapi.AES_OFB = AES_OFB.constructor()
	okapi.AES_CFB = AES_CFB.constructor()
	okapi.AES_CTR = AES_CTR.constructor()
	okapi.AES_GCM = AES_GCM.constructor()
}

type cipherParams interface {
	constructor() okapi.CipherConstructor
	algorithm(keySize int) *C.EVP_CIPHER
}

type fixedKeyParams map[int]*C.EVP_CIPHER

func (p fixedKeyParams) constructor() okapi.CipherConstructor {
	return func(key, iv []byte, encrypt bool) okapi.Cipher {
		return NewCipher(p, key, iv, encrypt)
	}
}

func (p fixedKeyParams) algorithm(keySize int) *C.EVP_CIPHER {
	v := p[keySize]
	if v == nil {
		panic(fmt.Sprintf("Invalid key size: %d", keySize))
	}
	return v
}

type variableKeyParams struct {
	cipher *C.EVP_CIPHER
}

func (p variableKeyParams) constructor() okapi.CipherConstructor {
	return func(key, iv []byte, encrypt bool) okapi.Cipher {
		return NewCipher(p, key, iv, encrypt)
	}
}

func (p variableKeyParams) algorithm(keySize int) *C.EVP_CIPHER {
	return p.cipher
}

var (
	RC4      = variableKeyParams{C.EVP_rc4()}
	AES_ECB  = fixedKeyParams{16: C.EVP_aes_128_ecb(), 24: C.EVP_aes_192_ecb(), 32: C.EVP_aes_256_ecb()}
	AES_CBC  = fixedKeyParams{16: C.EVP_aes_128_cbc(), 24: C.EVP_aes_192_cbc(), 32: C.EVP_aes_256_cbc()}
	AES_CFB  = fixedKeyParams{16: C.EVP_aes_128_cfb(), 24: C.EVP_aes_192_cfb(), 32: C.EVP_aes_256_cfb()}
	AES_OFB  = fixedKeyParams{16: C.EVP_aes_128_ofb(), 24: C.EVP_aes_192_ofb(), 32: C.EVP_aes_256_ofb()}
	AES_CTR  = fixedKeyParams{16: C.EVP_aes_128_ctr(), 24: C.EVP_aes_192_ctr(), 32: C.EVP_aes_256_ctr()}
	AES_GCM  = fixedKeyParams{16: C.EVP_aes_128_gcm(), 24: C.EVP_aes_192_gcm(), 32: C.EVP_aes_256_gcm()}
	AES_CCM  = fixedKeyParams{16: C.EVP_aes_128_ccm(), 24: C.EVP_aes_192_ccm(), 32: C.EVP_aes_256_ccm()}
	AES_XTS  = fixedKeyParams{16: C.EVP_aes_128_xts(), 32: C.EVP_aes_256_xts()}
	BF_ECB   = variableKeyParams{C.EVP_bf_ecb()}
	BF_CBC   = variableKeyParams{C.EVP_bf_cbc()}
	BF_CFB   = variableKeyParams{C.EVP_bf_cfb()}
	BF_OFB   = variableKeyParams{C.EVP_bf_ofb()}
	DES3_ECB = variableKeyParams{C.EVP_des_ede3_ecb()}
	DES3_CBC = variableKeyParams{C.EVP_des_ede3_cbc()}
	DES3_CFB = variableKeyParams{C.EVP_des_ede3_cfb()}
	DES3_OFB = variableKeyParams{C.EVP_des_ede3_ofb()}
)

type Cipher struct {
	ctx       *C.EVP_CIPHER_CTX
	cipher    *C.EVP_CIPHER // libcrypto constant
	buffered  int           // how many input bytes are buffered/unprocessed <0,blockSize)
	blockSize int           // caches the cipher block size
}

func NewCipher(params cipherParams, key, iv []byte, encrypt bool) *Cipher {
	algorithm := params.algorithm(len(key))
	c := &Cipher{cipher: algorithm}
	c.blockSize = int(C.EVP_CIPHER_block_size(algorithm))
	c.ctx = new(C.EVP_CIPHER_CTX)
	C.EVP_CIPHER_CTX_init(c.ctx)

	var ivp *C.uchar
	if iv != nil {
		ivp = (*C.uchar)(&iv[0])
	}
	var enc C.int = 0
	if encrypt {
		enc = 1
	}
	check1(C.EVP_CipherInit_ex(c.ctx, algorithm, nil, nil, nil, enc))
	C.EVP_CIPHER_CTX_set_key_length(c.ctx, C.int(len(key)))
	C.EVP_CIPHER_CTX_set_padding(c.ctx, 0) // No padding
	check1(C.EVP_CipherInit_ex(c.ctx, nil, nil, (*C.uchar)(&key[0]), ivp, -1))
	return c
}

func (c *Cipher) KeySize() int {
	return int(C.EVP_CIPHER_CTX_key_length(c.ctx))
}

func (c *Cipher) BlockSize() int {
	return c.blockSize
}

func (c *Cipher) BufferedSize() int {
	return c.buffered
}

func (c *Cipher) GCMGetTag(out []byte) int {
	return int(C.EVP_CIPHER_CTX_ctrl(c.ctx, C.EVP_CTRL_GCM_GET_TAG, C.int(len(out)), unsafe.Pointer(&out[0])))
}

func (c *Cipher) GCMSetTag(in []byte) int {
	return int(C.EVP_CIPHER_CTX_ctrl(c.ctx, C.EVP_CTRL_GCM_SET_TAG, C.int(len(in)), unsafe.Pointer(&in[0])))
}

func (c *Cipher) Update(in, out []byte) (int, int) {
	if len(out) < c.blockSize {
		return 0, 0
	}
	var outl, inl C.int
	if len(in)+c.buffered > len(out) {
		inl = C.int(len(out) - c.buffered)
	} else {
		inl = C.int(len(in))
	}
	check1(C.EVP_CipherUpdate(c.ctx, (*C.uchar)(&out[0]), &outl, (*C.uchar)(&in[0]), inl))
	c.buffered = c.buffered + int(inl) - int(outl)
	if c.buffered >= c.blockSize {
		panic("Unprocessed input exeeded block size!")
	}
	return int(inl), int(outl)
}

func (c *Cipher) Finish(out []byte) int {
	var outl C.int
	var output *C.uchar
	if out != nil && len(out) != 0 {
		output = (*C.uchar)(&out[0])
	}
	check1(C.EVP_CipherFinal_ex(c.ctx, output, &outl))
	return int(outl)
}

func (c *Cipher) Close() {
	if c.ctx == nil {
		return
	}
	defer func() {
		c.ctx = nil
	}()
	C.EVP_CIPHER_CTX_cleanup(c.ctx)
}
