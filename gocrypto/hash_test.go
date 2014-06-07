package gocrypto

import (
	_ "crypto/md5"
	_ "crypto/sha1"
	"encoding/hex"
	"testing"
)

func TestHash(t *testing.T) {
	md5 := MD5.New()
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
		t.Fatalf("%x", digest)
	}
	count, err := md5.Write([]byte("test"))
	if err == nil || count != 0 {
		t.Fatalf("count=%d, err=%s", count, err)
	}
}

func TestHashReset(t *testing.T) {
	sha := SHA1.New()
	defer sha.Close()
	sha.Write([]byte("test"))
	digest := sha.Digest()
	if hex.EncodeToString(digest) != "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" {
		t.Fatalf("%x", digest)
	}
	sha.Reset()
	count, err := sha.Write([]byte("test"))
	if err != nil || count != 4 {
		t.Fail()
	}
	digest = sha.Digest()
	if hex.EncodeToString(digest) != "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" {
		t.Fatalf("%x", digest)
	}
}
