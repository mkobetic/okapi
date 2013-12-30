// +build !windows

// Package libcrypto implements okapi interfaces using OpenSSL's libcrypto library.
package libcrypto

// #cgo LDFLAGS:  -L/usr/local/opt/openssl/lib -lcrypto
// #cgo CFLAGS: -I/usr/local/opt/openssl/include
// #include <openssl/evp.h>
import "C"
import (
	"github.com/mkobetic/okapi"
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
}

type Cipher struct {
	ctx    *C.EVP_CIPHER_CTX
	cipher *C.EVP_CIPHER // libcrypto constant
}

func RC4(key, iv []byte, encrypt bool) okapi.Cipher {
	return NewCipher(C.EVP_rc4(), key, iv, encrypt)
}

func BF_ECB(key, iv []byte, encrypt bool) okapi.Cipher {
	return NewCipher(C.EVP_bf_ecb(), key, iv, encrypt)
}

func BF_CBC(key, iv []byte, encrypt bool) okapi.Cipher {
	return NewCipher(C.EVP_bf_cbc(), key, iv, encrypt)
}

func BF_CFB(key, iv []byte, encrypt bool) okapi.Cipher {
	return NewCipher(C.EVP_bf_cfb(), key, iv, encrypt)
}

func BF_OFB(key, iv []byte, encrypt bool) okapi.Cipher {
	return NewCipher(C.EVP_bf_ofb(), key, iv, encrypt)
}

func DES3_ECB(key, iv []byte, encrypt bool) okapi.Cipher {
	return NewCipher(C.EVP_des_ede3_ecb(), key, iv, encrypt)
}

func DES3_CBC(key, iv []byte, encrypt bool) okapi.Cipher {
	return NewCipher(C.EVP_des_ede3_cbc(), key, iv, encrypt)
}

func DES3_CFB(key, iv []byte, encrypt bool) okapi.Cipher {
	return NewCipher(C.EVP_des_ede3_cfb(), key, iv, encrypt)
}

func DES3_OFB(key, iv []byte, encrypt bool) okapi.Cipher {
	return NewCipher(C.EVP_des_ede3_ofb(), key, iv, encrypt)
}

func NewCipher(algorithm *C.EVP_CIPHER, key, iv []byte, encrypt bool) okapi.Cipher {
	c := &Cipher{cipher: algorithm}
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
	check(C.EVP_CipherInit_ex(c.ctx, algorithm, nil, nil, nil, enc))
	C.EVP_CIPHER_CTX_set_key_length(c.ctx, C.int(len(key)))
	C.EVP_CIPHER_CTX_set_padding(c.ctx, 0)
	check(C.EVP_CipherInit_ex(c.ctx, nil, nil, (*C.uchar)(&key[0]), ivp, -1))
	return c
}

func (c *Cipher) KeySize() int {
	return int(C.EVP_CIPHER_CTX_key_length(c.ctx))
}

func (c *Cipher) BlockSize() int {
	return int(C.EVP_CIPHER_CTX_block_size(c.ctx))
}

func (c *Cipher) GCMGetTag(out []byte) int {
	return int(C.EVP_CIPHER_CTX_ctrl(c.ctx, C.EVP_CTRL_GCM_GET_TAG, C.int(len(out)), unsafe.Pointer(&out[0])))
}

func (c *Cipher) GCMSetTag(in []byte) int {
	return int(C.EVP_CIPHER_CTX_ctrl(c.ctx, C.EVP_CTRL_GCM_SET_TAG, C.int(len(in)), unsafe.Pointer(&in[0])))
}

func (c *Cipher) Update(in, out []byte) int {
	var outl C.int
	check(C.EVP_CipherUpdate(c.ctx, (*C.uchar)(&out[0]), &outl, (*C.uchar)(&in[0]), C.int(len(in))))
	return int(outl)
}

func (c *Cipher) Finish(out []byte) int {
	var outl C.int
	var output *C.uchar
	if out != nil && len(out) != 0 {
		output = (*C.uchar)(&out[0])
	}
	check(C.EVP_CipherFinal_ex(c.ctx, output, &outl))
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
