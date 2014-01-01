// +build !windows

package libcrypto

import (
	"bytes"
	"testing"
)

func TestRC4(t *testing.T) {
	key := []byte("open sesame")
	rc4 := RC4(key, nil, true)
	defer rc4.Close()
	if rc4.BlockSize() != 1 {
		t.Fatal("Invalid block size")
	}
	if rc4.KeySize() != len(key) {
		t.Fatal("Invalid key size")
	}
	plain := "test"
	encrypted := make([]byte, len(plain))
	count := rc4.Update([]byte(plain), encrypted)
	if count != 4 {
		t.Fatalf("Wrong encryption byte count: %d", count)
	}
	count = rc4.Finish(encrypted[count:])
	if count != 0 {
		t.Fatalf("Wrong encryption finish count: %d", count)
	}
	rc4 = RC4(key, nil, false)
	defer rc4.Close()
	decrypted := make([]byte, len(plain))
	count = rc4.Update(encrypted, decrypted)
	if count != 4 {
		t.Fatalf("Wrong decryption byte count: %d", count)
	}
	count = rc4.Finish(decrypted[count:])
	if count != 0 {
		t.Fatalf("Wrong decryption finish count: %d", count)
	}
	if string(decrypted) != plain {
		t.Fatal("Decrypted does not match plain")
	}
}

func TestBlockWrites(t *testing.T) {
	bf := BF_CBC([]byte("open sesame!"), []byte("12345678"), true)
	defer bf.Close()
	plain := []byte("0123456789abcdefghijklmnopqrstuvxyz")
	encrypted := make([]byte, 30)
	count := bf.Update(plain[:13], encrypted)
	if count != 8 {
		t.Fatal("Wrong count: %d", count)
	}
	count = bf.Update(plain, encrypted[:12])
	if count != 12 {
		t.Fatal("Wrong count: %d", count)
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
	plain := make([]byte, 100)
	for i := 0; i < len(plain); i += 1 {
		plain[i] = byte(i)
	}
	var count int = 0
	encrypted := make([]byte, len(plain)*16)
	for i := 0; i < len(encrypted); i += 100 {
		count += aes.Update(plain, encrypted[count:])
	}
	if count != len(encrypted) {
		t.Fatalf("Wrong encryption byte count: %d", count)
	}
	count = aes.Finish(encrypted[count:])
	if count != 0 {
		t.Fatalf("Wrong encryption finish count: %d", count)
	}
	aes = AES_CBC(key, iv, false)
	defer aes.Close()
	count = 0
	decrypted := make([]byte, len(plain)*16)
	for i := 0; i < len(encrypted); i += 100 {
		count += aes.Update(encrypted[i:i+100], decrypted[count:])
	}
	if count != len(decrypted) {
		t.Fatalf("Wrong decryption byte count: %d", count)
	}
	count = aes.Finish(decrypted[count:])
	if count != 0 {
		t.Fatalf("Wrong decryption finish count: %d", count)
	}
	for i := 0; i < len(encrypted); i += 100 {
		if !bytes.Equal(decrypted[i:i+100], plain) {
			t.Fatalf("Decrypted chunk at %d does not match plain", i)
		}
	}
}

func TestAES_CTR(t *testing.T) {
	key := make([]byte, 32)
	// In CTR mode the IV is the counter
	iv := make([]byte, 16) // all zeros
	aes := AES_CTR(key, iv, true)
	defer aes.Close()
	plain := make([]byte, 155) // intentionally not a multiple of block length
	for i := 0; i < len(plain); i += 1 {
		plain[i] = byte(i)
	}
	encrypted := make([]byte, len(plain))
	count := aes.Update([]byte(plain), encrypted)
	if count != len(plain) {
		t.Fatalf("Wrong encryption byte count: %d", count)
	}
	count = aes.Finish(encrypted[count:])
	if count != 0 {
		t.Fatalf("Wrong encryption finish count: %d", count)
	}
	// let's decrypt from 9th block on
	iv[15] = 8
	aes = AES_CTR(key, iv, false)
	defer aes.Close()
	decrypted := make([]byte, len(plain)-(8*16))
	count = aes.Update(encrypted[8*16:], decrypted)
	if count != len(plain)-8*16 {
		t.Fatalf("Wrong decryption byte count: %d", count)
	}
	if !bytes.Equal(decrypted, plain[16*8:]) {
		t.Fatal("Decrypted does not match plain")
	}
}

func TestAES_GCM(t *testing.T) {
	key := make([]byte, 16)
	// In GCM mode the IV is the counter
	iv := make([]byte, 16) // all zeros
	aes := AES_GCM(key, iv, true).(*Cipher)
	defer aes.Close()
	plain := make([]byte, 155) // intentionally not a multiple of block length
	for i := 0; i < len(plain); i += 1 {
		plain[i] = byte(i)
	}
	encrypted := make([]byte, len(plain))
	count := aes.Update([]byte(plain), encrypted)
	if count != len(plain) {
		t.Fatalf("Wrong encryption byte count: %d", count)
	}
	count = aes.Finish(encrypted[count:])
	if count != 0 {
		t.Fatalf("Wrong encryption finish count: %d", count)
	}
	tag := make([]byte, 16)
	aes.GCMGetTag(tag)
	aes = AES_GCM(key, iv, false).(*Cipher)
	defer aes.Close()
	aes.GCMSetTag(tag)
	decrypted := make([]byte, len(plain))
	count = aes.Update(encrypted, decrypted)
	if count != len(plain) {
		t.Fatalf("Wrong decryption byte count: %d", count)
	}
	aes.Finish(nil) // this shouldn't panic if authentication checks out
	if !bytes.Equal(decrypted, plain) {
		t.Fatal("Decrypted does not match plain")
	}
}
