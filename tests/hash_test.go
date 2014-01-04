package tests

import (
	"encoding/hex"
	"fmt"
	. "github.com/mkobetic/okapi"
	_ "github.com/mkobetic/okapi/libcrypto"
	_ "testing"
)

func ExampleMD5() {
	md5 := MD5()
	defer md5.Close()
	fmt.Printf("Block size %d, digest size %d\n", md5.BlockSize(), md5.Size())
	md5.Write([]byte("test"))
	digest := md5.Digest()
	fmt.Printf("Digest: %s\n", hex.EncodeToString(digest))
	// Output:
	// Block size 64, digest size 16
	// Digest: 098f6bcd4621d373cade4e832627b4f6
}

func ExampleHashCloning() {
	sha := SHA256()
	defer sha.Close()
	fmt.Printf("Block size %d, digest size %d\n", sha.BlockSize(), sha.Size())
	sha.Write([]byte("test"))
	sha2 := sha.Clone()
	defer sha2.Close()
	digest := sha2.Digest()
	fmt.Printf("Digest 1: %s\n", hex.EncodeToString(digest))
	sha.Write([]byte("test"))
	digest = sha.Digest()
	fmt.Printf("Digest 2: %s\n", hex.EncodeToString(digest))
	// Output:
	// Block size 64, digest size 32
	// Digest 1: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
	// Digest 2: 37268335dd6931045bdcdf92623ff819a64244b53d0e746d438797349d4da578
}
