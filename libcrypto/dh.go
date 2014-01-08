// +build !windows

package libcrypto

// #include <openssl/evp.h>
// #include <openssl/dh.h>
import "C"
import (
	"errors"
	"github.com/mkobetic/okapi"
)

func init() {
	okapi.DH = DH.constructor()
}

type dhParameters struct {
}

var (
	DH = dhParameters{}
)

func (p dhParameters) constructor() okapi.KeyConstructor {
	return func(keyParameters interface{}) (okapi.PrivateKey, error) {
		return NewPKey(keyParameters, p)
	}
}

func (p dhParameters) configure(key *PKey) {
	key.parameters = p
	if !key.public {
		check1(C.EVP_PKEY_derive_init(key.ctx))
	}
}

func (p dhParameters) isForEncryption() bool   { return false }
func (p dhParameters) isForSigning() bool      { return false }
func (p dhParameters) isForKeyAgreement() bool { return true }

func (p dhParameters) toPublic(pri *PKey) (pub *PKey, err error) {
	return nil, errors.New("TODO")
}

func (p dhParameters) generate(size int) (*PKey, error) {
	pkey, err := newDHParams(size)
	if err != nil {
		return nil, err
	}
	return newPKeyParams(pkey)
}

func newDHParams(size int) (*C.EVP_PKEY, error) {
	ctx := C.EVP_PKEY_CTX_new_id(C.EVP_PKEY_DH, nil)
	if ctx == nil {
		return nil, errors.New("Failed EVP_PKEY_CTX_new_id")
	}
	err := error1(C.EVP_PKEY_paramgen_init(ctx))
	if err != nil {
		return nil, err
	}
	// Following macro didn't work:
	// err = error1(C.EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, size))
	err = error1(C.EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_DH, C.EVP_PKEY_OP_PARAMGEN, C.EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, C.int(size), nil))
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
