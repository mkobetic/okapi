// +build !windows

package libcrypto

// #include <openssl/evp.h>
// #include <openssl/rsa.h>
import "C"
import (
	"errors"
	"github.com/mkobetic/okapi"
	"unsafe"
)

func init() {
	okapi.RSA = RSA.constructor()
	okapi.RSA_OAEP = RSA_OAEP.constructor()
	okapi.RSA_MD5 = RSA_MD5.constructor()
	okapi.RSA_SHA1 = RSA_SHA1.constructor()
	okapi.RSA_SHA224 = RSA_SHA224.constructor()
	okapi.RSA_SHA256 = RSA_SHA256.constructor()
	okapi.RSA_SHA384 = RSA_SHA384.constructor()
	okapi.RSA_SHA512 = RSA_SHA512.constructor()
	okapi.RSA_PSS_MD5 = RSA_PSS_MD5.constructor()
	okapi.RSA_PSS_SHA1 = RSA_PSS_SHA1.constructor()
	okapi.RSA_PSS_SHA224 = RSA_PSS_SHA224.constructor()
	okapi.RSA_PSS_SHA256 = RSA_PSS_SHA256.constructor()
	okapi.RSA_PSS_SHA384 = RSA_PSS_SHA384.constructor()
	okapi.RSA_PSS_SHA512 = RSA_PSS_SHA512.constructor()
}

type rsaParameters struct {
	padding C.int
	md      *C.EVP_MD
}

var (
	RSA            = rsaParameters{C.RSA_PKCS1_PADDING, nil}
	RSA_OAEP       = rsaParameters{C.RSA_PKCS1_OAEP_PADDING, nil}
	RSA_MD5        = rsaParameters{C.RSA_PKCS1_PADDING, C.EVP_md5()}
	RSA_SHA1       = rsaParameters{C.RSA_PKCS1_PADDING, C.EVP_sha1()}
	RSA_SHA224     = rsaParameters{C.RSA_PKCS1_PADDING, C.EVP_sha224()}
	RSA_SHA256     = rsaParameters{C.RSA_PKCS1_PADDING, C.EVP_sha256()}
	RSA_SHA384     = rsaParameters{C.RSA_PKCS1_PADDING, C.EVP_sha384()}
	RSA_SHA512     = rsaParameters{C.RSA_PKCS1_PADDING, C.EVP_sha512()}
	RSA_PSS_MD5    = rsaParameters{C.RSA_PKCS1_PSS_PADDING, C.EVP_md5()}
	RSA_PSS_SHA1   = rsaParameters{C.RSA_PKCS1_PSS_PADDING, C.EVP_sha1()}
	RSA_PSS_SHA224 = rsaParameters{C.RSA_PKCS1_PSS_PADDING, C.EVP_sha224()}
	RSA_PSS_SHA256 = rsaParameters{C.RSA_PKCS1_PSS_PADDING, C.EVP_sha256()}
	RSA_PSS_SHA384 = rsaParameters{C.RSA_PKCS1_PSS_PADDING, C.EVP_sha384()}
	RSA_PSS_SHA512 = rsaParameters{C.RSA_PKCS1_PSS_PADDING, C.EVP_sha512()}
)

func (p rsaParameters) constructor() okapi.KeyConstructor {
	return func(keyParameters interface{}) (okapi.PrivateKey, error) {
		return NewPKey(keyParameters, p)
	}
}

func (p rsaParameters) configure(key *PKey) {
	key.parameters = p
	if p.isForEncryption() {
		if key.public {
			check1(C.EVP_PKEY_encrypt_init(key.ctx))
		} else {
			check1(C.EVP_PKEY_decrypt_init(key.ctx))
		}
	} else {
		if key.public {
			check1(C.EVP_PKEY_verify_init(key.ctx))
		} else {
			check1(C.EVP_PKEY_sign_init(key.ctx))
		}
	}
	// following macro didn't work: undeclared?
	// checkP(C.EVP_PKEY_CTX_set_rsa_padding(key.ctx, p.padding))
	checkP(C.EVP_PKEY_CTX_ctrl(key.ctx, C.EVP_PKEY_RSA, -1, C.EVP_PKEY_CTRL_RSA_PADDING, p.padding, nil))
	if p.md != nil {
		// following macro didn't work: undeclared?
		// checkP(C.EVP_PKEY_CTX_set_signature_md(key.ctx, p.md))
		checkP(C.EVP_PKEY_CTX_ctrl(key.ctx, -1, C.EVP_PKEY_OP_TYPE_SIG, C.EVP_PKEY_CTRL_MD, 0, unsafe.Pointer(p.md)))
	}
}

func (p rsaParameters) isForEncryption() bool   { return p.md == nil }
func (p rsaParameters) isForSigning() bool      { return p.md != nil }
func (p rsaParameters) isForKeyAgreement() bool { return false }

func (p rsaParameters) toPublic(pri *PKey) (pub *PKey, err error) {
	return newPKeyFromPrivate(pri)
}

func (p rsaParameters) generate(size int) (*PKey, error) {
	ctx := C.EVP_PKEY_CTX_new_id(C.EVP_PKEY_RSA, nil)
	if ctx == nil {
		return nil, errors.New("Failed EVP_PKEY_CTX_new_id")
	}
	err := error1(C.EVP_PKEY_keygen_init(ctx))
	if err != nil {
		return nil, err
	}
	// Following macro didn't work
	// err = error1(C.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, size))
	err = error1(C.EVP_PKEY_CTX_ctrl(ctx, C.EVP_PKEY_RSA, C.EVP_PKEY_OP_KEYGEN, C.EVP_PKEY_CTRL_RSA_KEYGEN_BITS, C.int(size), nil))
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
