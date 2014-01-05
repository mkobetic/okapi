// +build !windows

package libcrypto

import (
	"bytes"
	"testing"
)

func TestReadPrivatePEM_RSA(t *testing.T) {
	pri, err := newRSAKey(pemRSA1024, RSA)
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
	pri, _ := newRSAKey(pemRSA1024, RSA_OAEP)
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
