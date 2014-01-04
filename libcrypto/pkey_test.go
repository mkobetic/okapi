// +build !windows

package libcrypto

import (
	"bytes"
	"testing"
)

func TestGenerateRSA(t *testing.T) {
	pri := RSA_15(2048)
	defer pri.Close()
	pub := pri.PublicKey()
	defer pub.Close()
	if !bytes.Equal(plain, decrypted) {
		t.Fatal("RSA decryption failed")
	}
}

func TestRSA_OAEP(t *testing.T) {
	pri := RSA_OAEP(sample1024RSAKey)
	pub := pri.PublicKey()
	plain := []byte("Message in a bottle!")
	encrypted := pub.Encrypt(plain)
	decrypted := pri.Decrypt(encrypted)
	if !bytes.Equal(plain, decrypted) {
		t.Fatal("RSA decryption failed")
	}
}
