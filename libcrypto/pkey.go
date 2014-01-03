// +build !windows

package libcrypto

// #cgo LDFLAGS:  -L/usr/local/opt/openssl/lib -lcrypto
// #cgo CFLAGS: -I/usr/local/opt/openssl/include
// #include <openssl/evp.h>
import "C"
import (
	"github.com/mkobetic/okapi"
	"unsafe"
)

type PrivateKey struct {
	pkey *C.EVP_PKEY
}

func NewPrivateKeyPEM(pem []byte) *okapi.PrivateKey {
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem[0]), C.int(len(pem)))
	defer C.BIO_free(bio)
	pkey := C.PEM_read_bio_PrivateKey(bio, nil, nil, nil)
	&PrivateKey{pkey: pkey}
}

type PublicKey struct {
	pkey *C.EVP_PKEY
}

func NewPublicKeyPEM(pem []byte) *okapi.PrivateKey {
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem[0]), C.int(len(pem)))
	defer C.BIO_free(bio)
	pkey := C.PEM_read_bio_PUBKEY(bio, nil, nil, nil)
	&PrivateKey{pkey: pkey}
}
