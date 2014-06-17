package gocrypto

import (
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
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
	h := hs.hash.New()
	return &Hash{Hash: h, digest: make([]byte, 0, h.Size())}
}

type Hash struct {
	hash.Hash
	digest []byte
}

func (h *Hash) Clone() okapi.Hash {
	panic("gocrypto does not support Hash cloning")
}

func (h *Hash) Write(data []byte) (int, error) {
	if len(h.digest) > 0 {
		return 0, errors.New("cannot write into finalized hash")
	}
	return h.Hash.Write(data)
}

func (h *Hash) Digest() []byte {
	if len(h.digest) > 0 {
		return h.digest
	}
	h.digest = h.Sum(h.digest)
	return h.digest
}

func (h *Hash) Reset() {
	h.digest = h.digest[:0]
	h.Hash.Reset()
}

func (h *Hash) Close() {
}
