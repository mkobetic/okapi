// +build !windows

package libcrypto

/*
#cgo LDFLAGS:  -L/usr/local/opt/openssl/lib -lcrypto
#cgo CFLAGS: -I/usr/local/opt/openssl/include
#include <openssl/evp.h>
#include <openssl/dsa.h>
*/
import "C"
import (
	"errors"
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

type dsaParameters struct {
	md *C.EVP_MD
}

var (
	DSA_SHA1   = dsaParameters{C.EVP_sha1()}
	DSA_SHA224 = dsaParameters{C.EVP_sha224()}
	DSA_SHA256 = dsaParameters{C.EVP_sha256()}
	DSA_SHA384 = dsaParameters{C.EVP_sha384()}
	DSA_SHA512 = dsaParameters{C.EVP_sha512()}
)

func (p dsaParameters) constructor() okapi.KeyConstructor {
	return func(keyParameters interface{}) (okapi.PrivateKey, error) {
		return newPKey(keyParameters, p)
	}
}

func (p dsaParameters) configure(key *PKey) {
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

func (p dsaParameters) isForEncryption() bool   { return false }
func (p dsaParameters) isForSigning() bool      { return true }
func (p dsaParameters) isForKeyAgreement() bool { return false }

func (p dsaParameters) generate(size int) (*PKey, error) {
	pkey, err := newDSAParams(size)
	if err != nil {
		return nil, err
	}
	return newPKeyParams(pkey)
}

func newDSAParams(size int) (*C.EVP_PKEY, error) {
	ctx := C.EVP_PKEY_CTX_new_id(C.EVP_PKEY_DSA, nil)
	if ctx == nil {
		return nil, errors.New("Failed EVP_PKEY_CTX_new_id")
	}
	err := error1(C.EVP_PKEY_paramgen_init(ctx))
	if err != nil {
		return nil, err
	}
	// Following macro didn't work
	// err = error1(C.EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, size))
	// err = error1(C.EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_DSA, C.EVP_PKEY_OP_PARAMGEN, C.EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, C.int(size), nil))

	if err != nil {
		return nil, err
	}
	var pkey *C.EVP_PKEY
	err = error1(C.EVP_PKEY_paramgen(ctx, &pkey))
	if err != nil {
		return nil, err
	}
	return pkey, nil
}
