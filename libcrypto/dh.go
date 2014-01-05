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
		return newDHKey(keyParameters, p)
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

func newDHKey(kp interface{}, dhp dhParameters) (*PKey, error) {
	key, err := newPKey(C.EVP_PKEY_DH, kp)
	if err != nil {
		return key, err
	}
	dhp.configure(key)
	return key, nil
}
