// +build !windows

package libcrypto

/*
#cgo LDFLAGS:  -L/usr/local/opt/openssl/lib -lcrypto
#cgo CFLAGS: -I/usr/local/opt/openssl/include
#include <openssl/evp.h>
#include <openssl/rsa.h>
*/
import "C"
import (
	"github.com/mkobetic/okapi"
	"unsafe"
)

func init() {
	okapi.RSA = RSA.constructor()
	okapi.RSA_OAEP = RSA_OAEP.constructor()
	okapi.RSA_MD5 = RSA_MD5.constructor()
	okapi.RSA_SHA1 = RSA_SHA1.constructor()
	okapi.RSA_SHA224 = RSA_SHA224.constructor()
	okapi.RSA_SHA256 = RSA_SHA256.constructor()
	okapi.RSA_SHA384 = RSA_SHA384.constructor()
	okapi.RSA_SHA512 = RSA_SHA512.constructor()
	okapi.RSA_PSS_MD5 = RSA_PSS_MD5.constructor()
	okapi.RSA_PSS_SHA1 = RSA_PSS_SHA1.constructor()
	okapi.RSA_PSS_SHA224 = RSA_PSS_SHA224.constructor()
	okapi.RSA_PSS_SHA256 = RSA_PSS_SHA256.constructor()
	okapi.RSA_PSS_SHA384 = RSA_PSS_SHA384.constructor()
	okapi.RSA_PSS_SHA512 = RSA_PSS_SHA512.constructor()
}

type RSAParameters struct {
	padding C.int
	md      *C.EVP_MD
}

var (
	RSA            = RSAParameters{C.RSA_PKCS1_PADDING, nil}
	RSA_OAEP       = RSAParameters{C.RSA_PKCS1_OAEP_PADDING, nil}
	RSA_MD5        = RSAParameters{C.RSA_PKCS1_PADDING, C.EVP_md5()}
	RSA_SHA1       = RSAParameters{C.RSA_PKCS1_PADDING, C.EVP_sha1()}
	RSA_SHA224     = RSAParameters{C.RSA_PKCS1_PADDING, C.EVP_sha224()}
	RSA_SHA256     = RSAParameters{C.RSA_PKCS1_PADDING, C.EVP_sha256()}
	RSA_SHA384     = RSAParameters{C.RSA_PKCS1_PADDING, C.EVP_sha384()}
	RSA_SHA512     = RSAParameters{C.RSA_PKCS1_PADDING, C.EVP_sha512()}
	RSA_PSS_MD5    = RSAParameters{C.RSA_PKCS1_PSS_PADDING, C.EVP_md5()}
	RSA_PSS_SHA1   = RSAParameters{C.RSA_PKCS1_PSS_PADDING, C.EVP_sha1()}
	RSA_PSS_SHA224 = RSAParameters{C.RSA_PKCS1_PSS_PADDING, C.EVP_sha224()}
	RSA_PSS_SHA256 = RSAParameters{C.RSA_PKCS1_PSS_PADDING, C.EVP_sha256()}
	RSA_PSS_SHA384 = RSAParameters{C.RSA_PKCS1_PSS_PADDING, C.EVP_sha384()}
	RSA_PSS_SHA512 = RSAParameters{C.RSA_PKCS1_PSS_PADDING, C.EVP_sha512()}
)

func (p RSAParameters) constructor() okapi.KeyConstructor {
	return func(keyParameters interface{}) (okapi.PrivateKey, error) {
		return newRSAKey(keyParameters, p)
	}
}

func (p RSAParameters) configure(key *PKey) {
	key.parameters = p
	checkP(C.EVP_PKEY_CTX_ctrl(key.ctx, C.EVP_PKEY_RSA, -1, C.EVP_PKEY_CTRL_RSA_PADDING, p.padding, nil))
	//checkP(C.EVP_PKEY_CTX_set_rsa_padding(key.ctx, p.padding))
	if p.md != nil {
		checkP(C.EVP_PKEY_CTX_ctrl(key.ctx, -1, C.EVP_PKEY_OP_TYPE_SIG, C.EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(p.md)))
		//checkP(C.EVP_PKEY_CTX_set_signature_md(key.ctx, p.md))
	}
}

func (p RSAParameters) isForEncryption() bool   { return p.md == nil }
func (p RSAParameters) isForSigning() bool      { return p.md != nil }
func (p RSAParameters) isForKeyAgreement() bool { return false }

func newRSAKey(keyParameters interface{}, rsaParameters RSAParameters) (*PKey, error) {
	key, err := newPKey(C.EVP_PKEY_RSA, keyParameters)
	if err != nil {
		return key, err
	}
	rsaParameters.configure(key)
	return key, nil
}
