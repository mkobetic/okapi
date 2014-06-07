package gocrypto

import (
	"crypto/hmac"
	"github.com/mkobetic/okapi"
)

func init() {
	okapi.HMAC = HMAC
}

type MACSpec struct{}

var (
	HMAC = MACSpec{}
)

func (ms MACSpec) New(hs okapi.HashSpec, key []byte) okapi.Hash {
	return &Hash{Hash: hmac.New(hs.(HashSpec).hash.New, key)}
}
