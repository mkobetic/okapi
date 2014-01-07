// +build !windows

package libcrypto

// #include <openssl/evp.h>
import "C"
import (
	"fmt"
	"github.com/mkobetic/okapi"
)

func init() {
	okapi.AES_ECB = AES_ECB
	okapi.AES_CBC = AES_CBC
	okapi.AES_OFB = AES_OFB
	okapi.AES_CFB = AES_CFB
	okapi.AES_CTR = AES_CTR
	okapi.AES_GCM = AES_GCM
}

func AES_ECB(key, iv []byte, encrypt bool) okapi.Cipher {
	switch len(key) {
	case 16:
		return NewCipher(C.EVP_aes_128_ecb(), key, iv, encrypt)
	case 24:
		return NewCipher(C.EVP_aes_192_ecb(), key, iv, encrypt)
	case 32:
		return NewCipher(C.EVP_aes_256_ecb(), key, iv, encrypt)
	default:
		panic(fmt.Sprintf("Invalided AES key length: %d", len(key)))
	}
}

func AES_CBC(key, iv []byte, encrypt bool) okapi.Cipher {
	switch len(key) {
	case 16:
		return NewCipher(C.EVP_aes_128_cbc(), key, iv, encrypt)
	case 24:
		return NewCipher(C.EVP_aes_192_cbc(), key, iv, encrypt)
	case 32:
		return NewCipher(C.EVP_aes_256_cbc(), key, iv, encrypt)
	}
	panic(fmt.Sprintf("Invalided AES key length: %d", len(key)))
}

func AES_CFB(key, iv []byte, encrypt bool) okapi.Cipher {
	switch len(key) {
	case 16:
		return NewCipher(C.EVP_aes_128_cfb(), key, iv, encrypt)
	case 24:
		return NewCipher(C.EVP_aes_192_cfb(), key, iv, encrypt)
	case 32:
		return NewCipher(C.EVP_aes_256_cfb(), key, iv, encrypt)
	default:
		panic(fmt.Sprintf("Invalided AES key length: %d", len(key)))
	}
}

func AES_OFB(key, iv []byte, encrypt bool) okapi.Cipher {
	switch len(key) {
	case 16:
		return NewCipher(C.EVP_aes_128_ofb(), key, iv, encrypt)
	case 24:
		return NewCipher(C.EVP_aes_192_ofb(), key, iv, encrypt)
	case 32:
		return NewCipher(C.EVP_aes_256_ofb(), key, iv, encrypt)
	default:
		panic(fmt.Sprintf("Invalided AES key length: %d", len(key)))
	}
}

func AES_CTR(key, iv []byte, encrypt bool) okapi.Cipher {
	switch len(key) {
	case 16:
		return NewCipher(C.EVP_aes_128_ctr(), key, iv, encrypt)
	case 24:
		return NewCipher(C.EVP_aes_192_ctr(), key, iv, encrypt)
	case 32:
		return NewCipher(C.EVP_aes_256_ctr(), key, iv, encrypt)
	default:
		panic(fmt.Sprintf("Invalided AES key length: %d", len(key)))
	}
}

func AES_GCM(key, iv []byte, encrypt bool) okapi.Cipher {
	switch len(key) {
	case 16:
		return NewCipher(C.EVP_aes_128_gcm(), key, iv, encrypt)
	case 24:
		return NewCipher(C.EVP_aes_192_gcm(), key, iv, encrypt)
	case 32:
		return NewCipher(C.EVP_aes_256_gcm(), key, iv, encrypt)
	default:
		panic(fmt.Sprintf("Invalided AES key length: %d", len(key)))
	}
}

func AES_CCM(key, iv []byte, encrypt bool) okapi.Cipher {
	switch len(key) {
	case 16:
		return NewCipher(C.EVP_aes_128_ccm(), key, iv, encrypt)
	case 24:
		return NewCipher(C.EVP_aes_192_ccm(), key, iv, encrypt)
	case 32:
		return NewCipher(C.EVP_aes_256_ccm(), key, iv, encrypt)
	default:
		panic(fmt.Sprintf("Invalided AES key length: %d", len(key)))
	}
}

func AES_XTS(key, iv []byte, encrypt bool) okapi.Cipher {
	switch len(key) {
	case 16:
		return NewCipher(C.EVP_aes_128_xts(), key, iv, encrypt)
	case 32:
		return NewCipher(C.EVP_aes_256_xts(), key, iv, encrypt)
	default:
		panic(fmt.Sprintf("Invalided AES key length: %d", len(key)))
	}
}
