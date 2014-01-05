// +build !windows

package libcrypto

import (
	"testing"
)

func TestReadPrivatePEM_DSA(t *testing.T) {
	pri, err := newDSAKey(pemDSA1024, DSA_SHA1)
	if err != nil {
		t.Fatal("Failed reading PEM")
	}
	defer pri.Close()
	if pri.KeySize() != 1024 {
		t.Fatal("Invalid key size!")
	}
	pub := pri.PublicKey()
	defer pub.Close()
}

func TestDSA_SHA1(t *testing.T) {
	pri, _ := newDSAKey(pemDSA1024, DSA_SHA1)
	defer pri.Close()
	pub := pri.PublicKey().(*PKey)
	defer pub.Close()
	digest := []byte("0123456789ABCDEF0123")
	signature, err := pri.Sign(digest)
	if err != nil {
		t.Fatalf("Signing failed: %s", err)
	}
	valid, err := pub.Verify(signature, digest)
	if err != nil {
		t.Fatalf("Verification failed: %s", err)
	}
	if !valid {
		t.Fatalf("\nSignature Invalid\nDigest   : %x\nSignature: %x", digest, signature)
	}
}
