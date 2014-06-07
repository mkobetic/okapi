package gocrypto

import (
	"crypto"
	"errors"
	"github.com/mkobetic/okapi"
	"hash"
)

func init() {
	okapi.MD5 = MD5
	okapi.SHA1 = SHA1
	okapi.SHA224 = SHA224
	okapi.SHA256 = SHA256
	okapi.SHA384 = SHA384
	okapi.SHA512 = SHA512
	okapi.RIPEMD160 = RIPEMD160
}

var (
	MD5       = HashSpec{crypto.MD5}
	SHA1      = HashSpec{crypto.SHA1}
	SHA224    = HashSpec{crypto.SHA224}
	SHA256    = HashSpec{crypto.SHA256}
	SHA384    = HashSpec{crypto.SHA384}
	SHA512    = HashSpec{crypto.SHA512}
	RIPEMD160 = HashSpec{crypto.RIPEMD160}
)

type HashSpec struct {
	hash crypto.Hash
}

func (hs HashSpec) New() okapi.Hash {
	return &Hash{Hash: hs.hash.New()}
}

type Hash struct {
	hash.Hash
	digest []byte
}

func (h *Hash) Clone() okapi.Hash {
	panic("gocrypto does not support Hash cloning")
	return nil
}

func (h *Hash) Write(data []byte) (int, error) {
	if h.digest != nil {
		return 0, errors.New("cannot write into finalized hash")
	}
	return h.Hash.Write(data)
}

func (h *Hash) Digest() []byte {
	if h.digest != nil {
		return h.digest
	}
	h.digest = make([]byte, 0, h.Size())
	h.digest = h.Sum(h.digest)
	return h.digest
}

func (h *Hash) Reset() {
	h.digest = nil
	h.Hash.Reset()
}

func (h *Hash) Close() {
}
