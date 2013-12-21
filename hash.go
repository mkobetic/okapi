package okapi

import (
	"fmt"
)

type Hash interface {
	Write([]byte) (int, error)
	Digest() []byte
	Size() int
	BlockSize() int
	Clone() Hash
	Reset()
	Close()
}

type HashId uint

const (
	MD4 HashId = 1 + iota
	MD5
	SHA1
	SHA224
	SHA256
	SHA384
	SHA512
	_
	RIPEMD160
	MAX_HASH // keep this last
)

var hashes = make([]func() Hash, MAX_HASH)

func (h HashId) New() Hash {
	if h < MAX_HASH {
		if f := hashes[h]; f != nil {
			return f()
		}
	}
	panic(fmt.Sprintf("Unavailable hash algorithm %d", h))
}

func (h HashId) Use(f func() Hash) {
	if h < MAX_HASH {
		hashes[h] = f
	} else {
		panic(fmt.Sprintf("Unknown hash algorithm %d", h))
	}
}
