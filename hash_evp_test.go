package okapi

import (
	"encoding/hex"
	"testing"
)

func TestEvpHash(t *testing.T) {
	hash := NewHash(MD5)
	defer hash.Close()
	if hash.Size() != 16 {
		t.Fail()
	}
	if hash.BlockSize() != 64 {
		t.Fail()
	}
	hash.Write([]byte("test"))
	digest := hash.Sum([]byte{})
	if hex.EncodeToString(digest) != "098f6bcd4621d373cade4e832627b4f6" {
		t.Fail()
	}
}
