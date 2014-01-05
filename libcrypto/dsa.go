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
	okapi.DSA_SHA1 = DSA_SHA1.constructor()
	okapi.DSA_SHA224 = DSA_SHA224.constructor()
	okapi.DSA_SHA256 = DSA_SHA256.constructor()
	okapi.DSA_SHA384 = DSA_SHA384.constructor()
	okapi.DSA_SHA512 = DSA_SHA512.constructor()
}

type DSAParameters struct {
	md *C.EVP_MD
}

var (
	DSA_SHA1   = DSAParameters{C.EVP_sha1()}
	DSA_SHA224 = DSAParameters{C.EVP_sha224()}
	DSA_SHA256 = DSAParameters{C.EVP_sha256()}
	DSA_SHA384 = DSAParameters{C.EVP_sha384()}
	DSA_SHA512 = DSAParameters{C.EVP_sha512()}
)

func (p DSAParameters) constructor() okapi.KeyConstructor {
	return func(keyParameters interface{}) (okapi.PrivateKey, error) {
		return newDSAKey(keyParameters, p)
	}
}

func (p DSAParameters) configure(key *PKey) {
	key.parameters = p
	if key.public {
		check1(C.EVP_PKEY_verify_init(key.ctx))
	} else {
		check1(C.EVP_PKEY_sign_init(key.ctx))
	}
	// following macro didn't work: undeclared?
	// checkP(C.EVP_PKEY_CTX_set_signature_md(key.ctx, p.md))
	checkP(C.EVP_PKEY_CTX_ctrl(key.ctx, -1, C.EVP_PKEY_OP_TYPE_SIG, C.EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(p.md)))
}

func (p DSAParameters) isForEncryption() bool   { return false }
func (p DSAParameters) isForSigning() bool      { return true }
func (p DSAParameters) isForKeyAgreement() bool { return false }

func newDSAKey(keyParameters interface{}, dsaParameters DSAParameters) (*PKey, error) {
	key, err := newPKey(C.EVP_PKEY_DSA, keyParameters)
	if err != nil {
		return key, err
	}
	dsaParameters.configure(key)
	return key, nil
}
