package libcrypto

import (
	"encoding/hex"
	"testing"
)

func TestEvpHash(t *testing.T) {
	md5 := MD5()
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
	count, err := md5.Write([]byte("test"))
	if err == nil || count != 0 {
		t.Fail()
	}
}

func TestHashCloning(t *testing.T) {
	sha := SHA256()
	defer sha.Close()
	sha.Write([]byte("test"))
	sha2 := sha.Clone()
	digest := sha2.Digest()
	if hex.EncodeToString(digest) != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fail()
	}
	count, err := sha.Write([]byte("test"))
	if err != nil || count != 4 {
		t.Fail()
	}
	digest = sha.Digest()
	if hex.EncodeToString(digest) != "37268335dd6931045bdcdf92623ff819a64244b53d0e746d438797349d4da578" {
		t.Fail()
	}
}
