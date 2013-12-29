// +build windows

// Package mscng implements okapi interfaces using Microsoft CNG library (available on Windows Vista and later).
package mscng

// #cgo LDFLAGS: -lbcrypt
// #include <bcrypt.h>
import "C"
import (
	"errors"
	"github.com/mkobetic/okapi"
	"unsafe"
)

func init() {
	okapi.MD4 = MD4
	okapi.MD5 = MD5
	okapi.SHA1 = SHA1
	okapi.SHA224 = SHA224
	okapi.SHA256 = SHA256
	okapi.SHA384 = SHA384
	okapi.SHA512 = SHA512
}

type Hash struct {
	digest    []byte
	provider  C.BCRYPT_ALG_HANDLE
	hash      C.BCRYPT_HASH_HANDLE
	algorithm C.LPCWSTR
	object    []byte
}

func MD4() okapi.Hash    { return NewHash(C.BCRYPT_MD4_ALGORITHM) }
func MD5() okapi.Hash    { return NewHash(C.BCRYPT_MD5_ALGORITHM) }
func SHA1() okapi.Hash   { return NewHash(C.BCRYPT_SHA1_ALGORITHM) }
func SHA224() okapi.Hash { return NewHash(C.BCRYPT_SHA224_ALGORITHM) }
func SHA256() okapi.Hash { return NewHash(C.BCRYPT_SHA256_ALGORITHM) }
func SHA384() okapi.Hash { return NewHash(C.BCRYPT_SHA384_ALGORITHM) }
func SHA512() okapi.Hash { return NewHash(C.BCRYPT_SHA512_ALGORITHM) }

func NewHash(algorithm C.LPCWSTR) okapi.Hash {
	h := &Hash{algorithm: algorithm}
	check(C.BCryptOpenAlgorithmProvider(&h.provider, algorithm, nil, 0))
	h.object = make([]byte, h.getDWORDProperty(C.BCRYPT_OBJECT_LENGTH))
	check(C.BCryptCreateHash(h.provider, &h.hash, &h.object[0], property, nil, 0, 0))
	return h
}

func (h *Hash) Size() int {
	return h.getDWORDProperty(C.BCRYPT_HASH_BLOCK_LENGTH)
}

func (h *Hash) BlockSize() int {
	return h.getDWORDProperty(C.BCRYPT_HASH_DIGEST_LENGTH)
}

func (h *Hash) Reset() {
	check(BCryptDestroyHash(h.hash))
	check(BCryptCreateHash(h.provider, &h.hash, &h.object[0], property, nil, 0, 0))
}

func (h *Hash) Clone() okapi.Hash {
	h2 := &Hash{algorithm: h.algorithm}
	check(C.BCryptOpenAlgorithmProvider(&h2.provider, h.algorithm, nil, 0))
	h2.object = make([]byte, len(h.object))
	check(C.BCryptDuplicateHash(h.hash, &h2.hash, &h2.object[0], len(h2.object), 0))
	return h2
}

func (h *Hash) Digest() []byte {
	if h.digest != nil {
		return h.digest
	}
	h.digest = make([]byte, h.Size())
	check(C.BCryptFinishHash(h.hash, unsafe.Pointer(&h.digest[0]), len(h.digest), 0))
	return h.digest
}

func (h *Hash) Write(data []byte) (int, error) {
	if h.digest != nil {
		return 0, errors.New("Cannot write into finalized hash")
	}
	check(C.BCryptHashData(h.hash, unsafe.Pointer(&data[0]), C.size_t(len(data))))
	return len(data), nil
}

func (h *Hash) Close() {
	if h.provider == nil {
		return
	}
	defer func() {
		h.provider = nil
		h.hash = nil
	}()
	check(C.BCryptDestroyHash(h.hash))
	check(C.BCryptCloseAlgorithmProvider(h.provider, 0))
}

func (h *Hash) getDWORDProperty(name C.LPCWSTR) uint {
	var property, propertyLength C.DWORD
	check(C.BCryptGetProperty(h.provider, name, &property, unsafe.Sizeof(property), &propertyLength, 0))
	return uint(property)
}
