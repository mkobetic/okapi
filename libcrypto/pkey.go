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
	"math/big"
	"unsafe"
)

type algorithmParameters interface {
	configure(*PKey)
	isForSigning() bool
	isForEncryption() bool
	isForKeyAgreement() bool
}

type PKey struct {
	pkey       *C.EVP_PKEY
	ctx        *C.EVP_PKEY_CTX
	parameters algorithmParameters
	public     bool
}

func (key *PKey) Decrypt(encrypted []byte) (decrypted []byte, err error) {
	if key.public {
		return nil, errors.New("Public key cannot decrypt!")
	}
	if !key.parameters.isForEncryption() {
		return nil, errors.New("Key is not configured for encryption!")
	}
	var outlen C.size_t
	inlen := C.size_t(len(encrypted))
	in := (*C.uchar)(&encrypted[0])
	err = error1(C.EVP_PKEY_decrypt(key.ctx, nil, &outlen, in, inlen))
	if err != nil {
		return nil, err
	}
	decrypted = make([]byte, int(outlen))
	err = error1(C.EVP_PKEY_decrypt(key.ctx, (*C.uchar)(&decrypted[0]), &outlen, in, inlen))
	if err != nil {
		return nil, err
	}
	return decrypted[:int(outlen)], nil
}

func (key *PKey) Sign(digest []byte) (signature []byte, err error) {
	if key.public {
		return nil, errors.New("Public key cannot sign!")
	}
	if !key.parameters.isForSigning() {
		return nil, errors.New("Key is not for configured signing!")
	}
	var outlen C.size_t
	inlen := C.size_t(len(digest))
	in := (*C.uchar)(&digest[0])
	err = error1(C.EVP_PKEY_sign(key.ctx, nil, &outlen, in, inlen))
	if err != nil {
		return nil, err
	}
	signature = make([]byte, int(outlen))
	err = error1(C.EVP_PKEY_sign(key.ctx, (*C.uchar)(&signature[0]), &outlen, in, inlen))
	if err != nil {
		return nil, err
	}
	return signature[:int(outlen)], nil
}

func (key *PKey) Derive(pub okapi.PublicKey) (secret []byte, err error) {
	if key.public {
		return nil, errors.New("Public key cannot derive!")
	}
	if !key.parameters.isForKeyAgreement() {
		return nil, errors.New("Key is not configured for key agreement!")
	}
	return nil, errors.New("TODO")
}

func (key *PKey) PublicKey() okapi.PublicKey {
	if key.public {
		return key
	}
	var buffer *C.uchar
	blen := int(C.i2d_PublicKey(key.pkey, &buffer))
	if blen < 0 {
		panic("Key conversion failed (i2d)")
	}
	pkey := C.d2i_PublicKey(C.EVP_PKEY_id(key.pkey), nil, &buffer, C.long(blen))
	if pkey == nil {
		panic("PrivateKey to PublicKey conversion failed!")
	}
	pub, err := newPKey(key.keyType(), pkey)
	if err != nil {
		panic(err.Error())
	}
	pub.public = true
	pub.parameters = key.parameters
	pub.parameters.configure(pub)
	return pub
}

func (key *PKey) Encrypt(plain []byte) (encrypted []byte, err error) {
	if !key.parameters.isForEncryption() {
		return nil, errors.New("Key is not configured for encryption!")
	}
	var outlen C.size_t
	inlen := C.size_t(len(plain))
	in := (*C.uchar)(&plain[0])
	err = error1(C.EVP_PKEY_encrypt(key.ctx, nil, &outlen, in, inlen))
	if err != nil {
		return nil, err
	}
	encrypted = make([]byte, int(outlen))
	err = error1(C.EVP_PKEY_encrypt(key.ctx, (*C.uchar)(&encrypted[0]), &outlen, in, inlen))
	if err != nil {
		return nil, err
	}
	return encrypted[:int(outlen)], nil
}

func (key *PKey) Verify(signature []byte, digest []byte) (valid bool, err error) {
	if !key.parameters.isForSigning() {
		return false, errors.New("Key is not configured for signing!")
	}
	result := C.EVP_PKEY_verify(key.ctx, (*C.uchar)(&signature[0]), C.size_t(len(signature)), (*C.uchar)(&digest[0]), C.size_t(len(digest)))
	if int(result) < 0 {
		return false, error1(result)
	}
	return result == 1, nil
}

func (key *PKey) Close() {
	C.EVP_PKEY_CTX_free(key.ctx)
	C.EVP_PKEY_free(key.pkey)
}

func (key *PKey) KeySize() int {
	return int(C.EVP_PKEY_bits(key.pkey))
}

func (key *PKey) keyType() C.int {
	return C.EVP_PKEY_id(key.pkey)
}

func newPKey(keyType C.int, parameters interface{}) (key *PKey, err error) {
	switch parameters := parameters.(type) {
	case *C.EVP_PKEY:
		key = &PKey{pkey: parameters}
	case int:
		key, err = newPKeySize(keyType, parameters)
	case []*big.Int:
		key, err = newPKeyElements(keyType, parameters)
	case string:
		key, err = newPKeyPEM([]byte(parameters))
	default:
		err = errors.New("Invalid Parameters")
	}
	if err != nil {
		return
	}
	ctx := C.EVP_PKEY_CTX_new(key.pkey, nil)
	if ctx == nil {
		C.EVP_PKEY_free(key.pkey)
		return nil, errors.New("Failed to create EVP_PKEY_CTX")
	}
	key.ctx = ctx
	return key, nil
}

func newPKeySize(keyType C.int, size int) (*PKey, error) {
	return nil, errors.New("TODO")
}

func newPKeyElements(keyType C.int, elements []*big.Int) (*PKey, error) {
	return nil, errors.New("TODO")
}

func newPKeyPEM(pem []byte) (*PKey, error) {
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem[0]), C.int(len(pem)))
	defer C.BIO_free(bio)
	pkey := C.PEM_read_bio_PrivateKey(bio, nil, nil, nil)
	if pkey == nil {
		return nil, errors.New("Invalid PEM input")
	}
	return &PKey{pkey: pkey}, nil
}
