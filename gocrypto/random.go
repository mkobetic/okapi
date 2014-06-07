package gocrypto

import (
	"crypto/rand"
	"github.com/mkobetic/okapi"
)

func init() {
	okapi.DefaultRandom = DefaultRandom
}

type RandomSpec struct{}

var (
	DefaultRandom = RandomSpec{}
)

func (rs RandomSpec) New() okapi.Random {
	return &Random{}
}

type Random struct {
}

func (r *Random) Read(b []byte) (int, error) {
	return rand.Read(b)
}

func (r *Random) Close() {
}
