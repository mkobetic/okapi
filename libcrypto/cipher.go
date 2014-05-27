// +build !windows

package libcrypto

// #include <openssl/evp.h>
import "C"
import (
	"fmt"
	"github.com/mkobetic/okapi"
	"io"
	"unsafe"
)

func init() {
	okapi.RC4 = RC4
	okapi.BF_ECB = BF_ECB
	okapi.BF_CBC = BF_CBC
	okapi.BF_CFB = BF_CFB
	okapi.BF_OFB = BF_OFB
	okapi.DES3_ECB = DES3_ECB
	okapi.DES3_CBC = DES3_CBC
	okapi.DES3_CFB = DES3_CFB
	okapi.DES3_OFB = DES3_OFB
	okapi.AES_ECB = AES_ECB
	okapi.AES_CBC = AES_CBC
	okapi.AES_OFB = AES_OFB
	okapi.AES_CFB = AES_CFB
	okapi.AES_CTR = AES_CTR
	okapi.AES_GCM = AES_GCM
}

var (
	RC4      = CipherSpec{0: C.EVP_rc4()}
	AES_ECB  = CipherSpec{16: C.EVP_aes_128_ecb(), 24: C.EVP_aes_192_ecb(), 32: C.EVP_aes_256_ecb()}
	AES_CBC  = CipherSpec{16: C.EVP_aes_128_cbc(), 24: C.EVP_aes_192_cbc(), 32: C.EVP_aes_256_cbc()}
	AES_CFB  = CipherSpec{16: C.EVP_aes_128_cfb(), 24: C.EVP_aes_192_cfb(), 32: C.EVP_aes_256_cfb()}
	AES_OFB  = CipherSpec{16: C.EVP_aes_128_ofb(), 24: C.EVP_aes_192_ofb(), 32: C.EVP_aes_256_ofb()}
	AES_CTR  = CipherSpec{16: C.EVP_aes_128_ctr(), 24: C.EVP_aes_192_ctr(), 32: C.EVP_aes_256_ctr()}
	AES_GCM  = CipherSpec{16: C.EVP_aes_128_gcm(), 24: C.EVP_aes_192_gcm(), 32: C.EVP_aes_256_gcm()}
	AES_CCM  = CipherSpec{16: C.EVP_aes_128_ccm(), 24: C.EVP_aes_192_ccm(), 32: C.EVP_aes_256_ccm()}
	AES_XTS  = CipherSpec{16: C.EVP_aes_128_xts(), 32: C.EVP_aes_256_xts()}
	BF_ECB   = CipherSpec{0: C.EVP_bf_ecb()}
	BF_CBC   = CipherSpec{0: C.EVP_bf_cbc()}
	BF_CFB   = CipherSpec{0: C.EVP_bf_cfb()}
	BF_OFB   = CipherSpec{0: C.EVP_bf_ofb()}
	DES3_ECB = CipherSpec{0: C.EVP_des_ede3_ecb()}
	DES3_CBC = CipherSpec{0: C.EVP_des_ede3_cbc()}
	DES3_CFB = CipherSpec{0: C.EVP_des_ede3_cfb()}
	DES3_OFB = CipherSpec{0: C.EVP_des_ede3_ofb()}
)

// CipherSpec represents a cipher algorithm. Different map entries correspond
// to implementations for different key sizes. Variable key size algorithms have
// single map entry with key 0.
type CipherSpec map[int]*C.EVP_CIPHER

func (cs CipherSpec) New(key, iv []byte, encrypt bool) okapi.Cipher {
	var algorithm *C.EVP_CIPHER
	algorithm, ok := cs[0]
	if !ok {
		algorithm, ok = cs[len(key)]
		if !ok {
			panic(fmt.Sprintf("Invalid key size: %d", len(key)))
		}
	}
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

func (cs CipherSpec) NewReader(in io.Reader, key, iv, buffer []byte) *okapi.CipherReader {
	return okapi.NewCipherReader(in, cs, key, iv, buffer)
}

func (cs CipherSpec) NewWriter(out io.Writer, key, iv, buffer []byte) *okapi.CipherWriter {
	return okapi.NewCipherWriter(out, cs, key, iv, buffer)
}

type Cipher struct {
	ctx       *C.EVP_CIPHER_CTX
	cipher    *C.EVP_CIPHER // libcrypto constant
	buffered  int           // how many input bytes are buffered/unprocessed <0,blockSize)
	blockSize int           // caches the cipher block size
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
