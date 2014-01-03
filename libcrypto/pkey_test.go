// +build !windows

package libcrypto

import (
	"bytes"
	"testing"
)

func TestRSA(t *testing.T) {
	pri := RSASize(2048)
	pub := pri.PublicKey()
	plain := []byte("Message in a bottle!")
	encrypted := pub.Encrypt(plain)
	decrypted := pri.Decrypt(encrypted)
	if !bytes.Equal(plain, decrypted) {
		t.Fatal("RSA decryption failed")
	}
}
