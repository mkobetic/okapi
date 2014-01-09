// +build !windows

package libcrypto

// #include <openssl/evp.h>
// #include <openssl/pem.h>
import "C"
import (
	"errors"
	"github.com/mkobetic/okapi"
	"unsafe"
)

type algorithmParameters interface {
	configure(key *PKey)
	generate(size int) (key *PKey, err error)
	toPublic(pri *PKey) (pub *PKey, err error)
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

func (key *PKey) Derive(peer okapi.PublicKey) (secret []byte, err error) {
	if key.public {
		return nil, errors.New("Public key cannot derive!")
	}
	if !key.parameters.isForKeyAgreement() {
		return nil, errors.New("Key is not configured for key agreement!")
	}
	err = error1(C.EVP_PKEY_derive_set_peer(key.ctx, peer.(*PKey).pkey))
	if err != nil {
		return nil, err
	}
	var outlen C.size_t
	err = error1(C.EVP_PKEY_derive(key.ctx, nil, &outlen))
	if err != nil {
		return nil, err
	}
	secret = make([]byte, int(outlen))
	err = error1(C.EVP_PKEY_derive(key.ctx, (*C.uchar)(&secret[0]), &outlen))
	if err != nil {
		return nil, err
	}
	return secret[:int(outlen)], nil
}

func (key *PKey) PublicKey() okapi.PublicKey {
	if key.public {
		return key
	}
	pub, err := key.parameters.toPublic(key)
	if err != nil {
		panic(err.Error())
	}
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
	if key.pkey == nil {
		return
	}
	if key.ctx != nil {
		C.EVP_PKEY_CTX_free(key.ctx)
		key.ctx = nil
	}
	C.EVP_PKEY_free(key.pkey)
	key.pkey = nil
}

func (key *PKey) KeySize() int {
	return int(C.EVP_PKEY_bits(key.pkey))
}

func NewPKey(kps interface{}, aps algorithmParameters) (key *PKey, err error) {
	switch kps := kps.(type) {
	case int:
		key, err = aps.generate(kps)
	// case []*big.Int:
	// 	key, err = newRSAKeyElements(keyType, parameters)
	case string:
		key, err = newPKeyFromPEM([]byte(kps))
	case *PKey:
		key, err = newPKeyFromParams(kps.pkey)
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
	aps.configure(key)
	return
}

func newPKeyFromPEM(pem []byte) (*PKey, error) {
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem[0]), C.int(len(pem)))
	defer C.BIO_free(bio)
	pkey := C.PEM_read_bio_PrivateKey(bio, nil, nil, nil)
	if pkey == nil {
		return nil, errors.New("Invalid PEM input")
	}
	return &PKey{pkey: pkey}, nil
}

func newPKeyFromParams(params *C.EVP_PKEY) (*PKey, error) {
	ctx := C.EVP_PKEY_CTX_new(params, nil)
	if ctx == nil {
		return nil, errors.New("Failed EVP_PKEY_CTX_new_id")
	}
	err := error1(C.EVP_PKEY_keygen_init(ctx))
	if err != nil {
		return nil, err
	}
	var pkey *C.EVP_PKEY
	err = error1(C.EVP_PKEY_keygen(ctx, &pkey))
	if err != nil {
		return nil, err
	}
	return &PKey{pkey: pkey}, nil
}

func newPKeyFromPrivate(pri *PKey) (*PKey, error) {
	var buffer *C.uchar
	blen := int(C.i2d_PublicKey(pri.pkey, &buffer))
	if blen < 0 {
		return nil, errors.New("Key conversion failed (i2d)")
	}
	pkey := C.d2i_PublicKey(C.EVP_PKEY_id(pri.pkey), nil, &buffer, C.long(blen))
	if pkey == nil {
		return nil, errors.New("PrivateKey to PublicKey conversion failed!")
	}
	pub := &PKey{pkey: pkey, public: true, parameters: pri.parameters}
	ctx := C.EVP_PKEY_CTX_new(pkey, nil)
	if ctx == nil {
		C.EVP_PKEY_free(pkey)
		return nil, errors.New("Failed to create EVP_PKEY_CTX")
	}
	pub.ctx = ctx
	pri.parameters.configure(pub)
	return pub, nil
}
