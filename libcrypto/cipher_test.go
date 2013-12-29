// +build !windows

package libcrypto

import (
	"testing"
)

func TestEvpCipher(t *testing.T) {
	key := []byte("open sesame")
	rc4 := RC4(key, nil, true)
	defer rc4.Close()
	if rc4.BlockSize() != 1 {
		t.Fail()
	}
	plain := "test"
	encrypted := make([]byte, len(plain))
	count := rc4.Update([]byte(plain), encrypted)
	if count != 4 {
		t.Fail()
	}
	rc4 = RC4(key, nil, false)
	defer rc4.Close()
	decrypted := make([]byte, len(plain))
	count = rc4.Update(encrypted, decrypted)
	if count != 4 {
		t.Fail()
	}
	if string(decrypted) != plain {
		t.Fail()
	}
}

func TestAES_CBC(t *testing.T) {
	key := []byte("0123456789ABCDEF")
	iv := []byte("0123456789ABCDEF")
	aes := AES_CBC(key, iv, true)
	defer aes.Close()
	if aes.BlockSize() != 16 {
		t.Fatal("Wrong block Size")
	}
	plain := "a block's worth!"
	encrypted := make([]byte, len(plain))
	count := aes.Update([]byte(plain), encrypted)
	if count != 16 {
		t.Fatalf("Wrong encryption byte count: %d", count)
	}
	aes = AES_CBC(key, iv, false)
	defer aes.Close()
	decrypted := make([]byte, len(plain))
	count = aes.Update(encrypted, decrypted)
	if count != 16 {
		t.Fatalf("Wrong decryption byte count: %d", count)
	}
	if string(decrypted) != plain {
		t.Fatal("Decrypted does not match plain")
	}
}
