// +build !windows

package libcrypto

import (
	"testing"
)

func TestCreateRSA_PEM(t *testing.T) {
	pri, err := RSA_15(pemRSA1024)
	if err != nil {
		t.Fatal("Failed reading PEM")
	}
	defer pri.Close()
	key := pri.(*PrivateKey)
	if key.KeySize() != 1024 {
		t.Fatal("Invalid key size!")
	}
	pub := pri.PublicKey()
	defer pub.Close()
}

// func TestRSA_OAEP(t *testing.T) {
// 	pri, _ := RSA_OAEP(sample1024RSAKey)
// 	pub := pri.PublicKey()
// 	plain := []byte("Message in a bottle!")
// 	encrypted := pub.Encrypt(plain)
// 	decrypted := pri.Decrypt(encrypted)
// 	if !bytes.Equal(plain, decrypted) {
// 		t.Fatal("RSA decryption failed")
// 	}
// }
