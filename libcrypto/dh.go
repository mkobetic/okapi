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

type DHParameters struct {
}

var (
	DH = DHParameters{}
)

func (p DHParameters) constructor() okapi.KeyConstructor {
	return func(keyParameters interface{}) (okapi.PrivateKey, error) {
		return newDHKey(keyParameters, p)
	}
}

func (p DHParameters) configure(key *PKey) {
	key.parameters = p
	if !key.public {
		check1(C.EVP_PKEY_derive_init(key.ctx))
	}
}

func (p DHParameters) isForEncryption() bool   { return false }
func (p DHParameters) isForSigning() bool      { return false }
func (p DHParameters) isForKeyAgreement() bool { return true }

func newDHKey(keyParameters interface{}, dhParameters DHParameters) (*PKey, error) {
	key, err := newPKey(C.EVP_PKEY_DH, keyParameters)
	if err != nil {
		return key, err
	}
	dhParameters.configure(key)
	return key, nil
}
