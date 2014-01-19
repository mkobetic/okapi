// +build !windows

package libcrypto

// #include <openssl/evp.h>
// #include <openssl/ec.h>
import "C"
import (
	"errors"
)

var (
	size2curve = map[int]C.int{224: C.NID_secp224r1, 384: C.NID_secp384r1, 521: C.NID_secp521r1}
)

func newECParams(size int) (*C.EVP_PKEY, error) {
	ctx := C.EVP_PKEY_CTX_new_id(C.EVP_PKEY_EC, nil)
	if ctx == nil {
		return nil, errors.New("Failed EVP_PKEY_CTX_new_id")
	}
	defer C.EVP_PKEY_CTX_free(ctx)
	err := error1(C.EVP_PKEY_paramgen_init(ctx))
	if err != nil {
		return nil, err
	}
	// Following macro didn't work:
	// err = error1(C.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, size2curve[size]))
	err = error1(C.EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_EC, C.EVP_PKEY_OP_PARAMGEN, C.EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, size2curve[size], nil))
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
