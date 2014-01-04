// +build !windows

package libcrypto

/*
#cgo LDFLAGS:  -L/usr/local/opt/openssl/lib -lcrypto
#cgo CFLAGS: -I/usr/local/opt/openssl/include
#include <openssl/evp.h>
#include <openssl/pem.h>
*/
import "C"
import (
	"github.com/mkobetic/okapi"
)

func init() {
	okapi.RSA_15 = RSA_15
}

func RSA_15(parameters interface{}) (okapi.PrivateKey, error) {
	return NewPrivateKey(C.EVP_PKEY_RSA, parameters)
}
