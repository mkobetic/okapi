// +build !windows

package libcrypto

import (
	"bytes"
	"testing"
)

func TestGenerateKey_RSA(t *testing.T) {
	pri, err := newPKey(512, RSA)
	if err != nil {
		t.Fatalf("Failed generating key: %s", err)
	}
	defer pri.Close()
	if pri.KeySize() != 512 {
		t.Fatal("Invalid key size!")
	}
}

func TestReadPrivatePEM_RSA(t *testing.T) {
	pri, err := newPKey(pemRSA1024, RSA)
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

func TestRSA_OAEP(t *testing.T) {
	pri, _ := newPKey(pemRSA1024, RSA_OAEP)
	defer pri.Close()
	pub := pri.PublicKey().(*PKey)
	defer pub.Close()
	plain := []byte("Message in a bottle!")
	encrypted, err := pub.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encryption failed: %s", err)
	}
	decrypted, err := pri.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %s", err)
	}
	if !bytes.Equal(plain, decrypted) {
		t.Fatalf("Result mismatch\nPlain    : %x\nEncrypted: %x\nDecrypted: %x\n", plain, encrypted, decrypted)
	}
}

func TestRSA_MD5(t *testing.T) {
	pri, _ := newPKey(pemRSA1024, RSA_MD5)
	defer pri.Close()
	pub := pri.PublicKey().(*PKey)
	defer pub.Close()
	digest := []byte("0123456789ABCDEF")
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
