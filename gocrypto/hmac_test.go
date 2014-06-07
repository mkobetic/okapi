package gocrypto

import (
	_ "crypto/md5"
	"encoding/hex"
	"testing"
)

func TestHMACHash(t *testing.T) {
	key := []byte("Open Sesame!")
	md5 := HMAC.New(MD5, key)
	defer md5.Close()
	if md5.Size() != 16 {
		t.Fail()
	}
	if md5.BlockSize() != 64 {
		t.Fail()
	}
	md5.Write([]byte("test"))
	digest := md5.Digest()
	if hex.EncodeToString(digest) != "1c4bb1f739e4a8e2f61c3f74e538630b" {
		t.Fatal(hex.EncodeToString(digest))
	}
	count, err := md5.Write([]byte("test"))
	if err == nil || count != 0 {
		t.Fail()
	}
}
