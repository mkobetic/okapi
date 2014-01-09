// +build !windows

package libcrypto

// #include <openssl/evp.h>
// #include <openssl/dh.h>
import "C"
import (
	"errors"
	"github.com/mkobetic/okapi"
	"unsafe"
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
	// This is butt ugly, but it seems that the only way to create
	// a public EVP_PKEY for DH is to create a key from the parameters
	// and then manually copy the pub_key member of the internal DH key over.
	dh1 := (*C.DH)(C.EVP_PKEY_get1_DH(pri.pkey))
	if dh1 == nil {
		return nil, errors.New(libcryptoError())
	}
	size := C.i2d_DHparams(dh1, nil)
	bytes := make([]byte, int(size))
	bytesp := (*C.uchar)(&bytes[0])
	size = C.i2d_DHparams(dh1, &bytesp)
	bytesp = (*C.uchar)(&bytes[0])
	dh2 := C.d2i_DHparams(nil, &bytesp, (C.long)(size))
	if dh2 == nil {
		return nil, errors.New(libcryptoError())
	}
	dh2.pub_key = C.BN_dup(dh1.pub_key)
	pkey := C.EVP_PKEY_new()
	// err := error1(C.EVP_PKEY_assign_DH(pkey, dh2))
	err = error1(C.EVP_PKEY_assign(pkey, C.EVP_PKEY_DH, unsafe.Pointer(dh2)))
	if err != nil {
		return nil, err
	}
	pub = &PKey{pkey: pkey, public: true, parameters: pri.parameters}
	ctx := C.EVP_PKEY_CTX_new(pkey, nil)
	if ctx == nil {
		C.EVP_PKEY_free(pkey)
		return nil, errors.New("Failed to create EVP_PKEY_CTX")
	}
	pub.ctx = ctx
	pri.parameters.configure(pub)
	return pub, nil
}

func (p dhParameters) generate(size int) (*PKey, error) {
	pkey, err := newDHParams(size)
	if err != nil {
		return nil, err
	}
	return newPKeyFromParams(pkey)
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
