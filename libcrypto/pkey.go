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
	"errors"
	"github.com/mkobetic/okapi"
	"unsafe"
)

type PrivateKey struct {
	pkey *C.EVP_PKEY
}

func (key *PrivateKey) Decrypt(encrypted []byte) (decrypted []byte, err error) {
	return nil, nil
}

func (key *PrivateKey) Sign(digest []byte) (signature []byte, err error) {
	return nil, nil
}

func (key *PrivateKey) Derive(pub okapi.PublicKey) (secret []byte, err error) {
	return nil, nil
}

func (key *PrivateKey) PublicKey() okapi.PublicKey {
	var buffer *C.uchar
	blen := int(C.i2d_PublicKey(key.pkey, &buffer))
	if blen < 0 {
		panic("Key conversion failed (i2d)")
	}
	pkey := C.d2i_PublicKey(C.EVP_PKEY_id(key.pkey), nil, &buffer, C.long(blen))
	// pkey := C.pri2pub(key.pkey)
	if pkey == nil {
		panic("PrivateKey to PublicKey conversion failed!")
	}
	return &PublicKey{pkey: pkey}
}

func (key *PrivateKey) Close() {}

func (key *PrivateKey) KeySize() int {
	return int(C.EVP_PKEY_bits(key.pkey))
}

func RSA_15(parameters interface{}) (okapi.PrivateKey, error) {
	switch parameters := parameters.(type) {
	case string:
		return NewPrivateKeyPEM([]byte(parameters))
	default:
		return nil, errors.New("Invalid Parameters")
	}
}

func NewPrivateKeyPEM(pem []byte) (okapi.PrivateKey, error) {
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem[0]), C.int(len(pem)))
	defer C.BIO_free(bio)
	pkey := C.PEM_read_bio_PrivateKey(bio, nil, nil, nil)
	if pkey == nil {
		return nil, errors.New("Invalid PEM input")
	}
	return &PrivateKey{pkey: pkey}, nil
}

type PublicKey struct {
	pkey *C.EVP_PKEY
}

func NewPublicKeyPEM(pem []byte) okapi.PublicKey {
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem[0]), C.int(len(pem)))
	defer C.BIO_free(bio)
	pkey := C.PEM_read_bio_PUBKEY(bio, nil, nil, nil)
	return &PublicKey{pkey: pkey}
}

func (key *PublicKey) Encrypt(plain []byte) (encrypted []byte, err error) {
	return nil, nil
}

func (key *PublicKey) Verify(signature []byte, digest []byte) (valid bool, err error) {
	return false, nil
}

func (key *PublicKey) Close() {}
