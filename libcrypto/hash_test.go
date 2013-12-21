package libcrypto

import (
	"encoding/hex"
	"github.com/mkobetic/okapi"
	"testing"
)

func TestEvpHash(t *testing.T) {
	md5 := NewHash(MD5)
	defer md5.Close()
	if md5.Size() != 16 {
		t.Fail()
	}
	if md5.BlockSize() != 64 {
		t.Fail()
	}
	md5.Write([]byte("test"))
	digest := md5.Digest()
	if hex.EncodeToString(digest) != "098f6bcd4621d373cade4e832627b4f6" {
		t.Fail()
	}
}

func TestOkapiHash(t *testing.T) {
	md5 := okapi.MD5.New()
	defer md5.Close()
}
