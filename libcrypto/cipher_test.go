// +build !windows

package libcrypto

import (
	"bytes"
	"testing"
)

func TestRC4(t *testing.T) {
	key := []byte("open sesame")
	rc4 := NewCipher(RC4, key, nil, true)
	defer rc4.Close()
	if rc4.BlockSize() != 1 {
		t.Fatal("Invalid block size")
	}
	if rc4.KeySize() != len(key) {
		t.Fatal("Invalid key size")
	}
	plain := "test"
	encrypted := make([]byte, len(plain))
	ins, outs := rc4.Update([]byte(plain), encrypted)
	if ins != 4 || outs != 4 {
		t.Fatalf("Wrong encryption counts: %d, %d", ins, outs)
	}
	outs = rc4.Finish(nil)
	if outs != 0 {
		t.Fatalf("Wrong encryption finish count: %d", outs)
	}
	rc4 = NewCipher(RC4, key, nil, false)
	defer rc4.Close()
	decrypted := make([]byte, len(plain))
	ins, outs = rc4.Update(encrypted, decrypted)
	if outs != 4 || ins != 4 {
		t.Fatalf("Wrong decryption byte counts: %d, %d", ins, outs)
	}
	outs = rc4.Finish(nil)
	if outs != 0 {
		t.Fatalf("Wrong decryption finish count: %d", outs)
	}
	if string(decrypted) != plain {
		t.Fatal("Decrypted does not match plain")
	}
}

func TestBlockWrites(t *testing.T) {
	bf := NewCipher(BF_CBC, []byte("open sesame!"), []byte("12345678"), true)
	defer bf.Close()
	plain := []byte("0123456789abcdefghijklmnopqrstuvxyz")
	encrypted := make([]byte, 30)
	ins, outs := bf.Update(plain[:13], encrypted)
	t.Logf("Update: %d, %d (%d)", ins, outs, bf.buffered)
	if ins != 13 || outs != 8 {
		t.Fatalf("Wrong byte counts: %d, %d", ins, outs)
	}
	ins, outs = bf.Update(plain, encrypted[:12])
	t.Logf("Update: %d, %d (%d)", ins, outs, bf.buffered)
	if ins != 7 || outs != 8 {
		t.Fatalf("Wrong counts: %d, %d", ins, outs)
	}
	ins, outs = bf.Update(plain[:4], encrypted)
	t.Logf("Update: %d, %d (%d)", ins, outs, bf.buffered)
	if ins != 4 || outs != 8 {
		t.Fatalf("Wrong counts: %d, %d", ins, outs)
	}
	bf.Finish(nil)
}

func TestAES_CBC(t *testing.T) {
	key := []byte("0123456789ABCDEF")
	iv := []byte("0123456789ABCDEF")
	aes := NewCipher(AES_CBC, key, iv, true)
	defer aes.Close()
	if aes.BlockSize() != 16 {
		t.Fatal("Wrong block Size")
	}
	plain := make([]byte, 100)
	for i := 0; i < len(plain); i += 1 {
		plain[i] = byte(i)
	}
	var ins, outs int
	encrypted := make([]byte, len(plain)*16)
	for i := 0; i < len(encrypted); i += 100 {
		is, os := aes.Update(plain, encrypted[outs:])
		ins += is
		outs += os
	}
	if outs != len(encrypted) || ins != len(encrypted) {
		t.Fatalf("Wrong encryption byte counts: %d, %d", ins, outs)
	}
	outs = aes.Finish(encrypted[outs:])
	if outs != 0 {
		t.Fatalf("Wrong encryption finish count: %d", outs)
	}
	aes = NewCipher(AES_CBC, key, iv, false)
	defer aes.Close()
	outs = 0
	ins = 0
	decrypted := make([]byte, len(plain)*16)
	for i := 0; i < len(encrypted); i += 100 {
		is, os := aes.Update(encrypted[i:i+100], decrypted[outs:])
		ins += is
		outs += os
	}
	if outs != len(decrypted) || ins != len(encrypted) {
		t.Fatalf("Wrong decryption byte counts: %d, %d", ins, outs)
	}
	outs = aes.Finish(decrypted[outs:])
	if outs != 0 {
		t.Fatalf("Wrong decryption finish count: %d", outs)
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
	aes := NewCipher(AES_CTR, key, iv, true)
	defer aes.Close()
	plain := make([]byte, 155) // intentionally not a multiple of block length
	for i := 0; i < len(plain); i += 1 {
		plain[i] = byte(i)
	}
	encrypted := make([]byte, len(plain))
	ins, outs := aes.Update([]byte(plain), encrypted)
	if outs != len(plain) || ins != len(plain) {
		t.Fatalf("Wrong encryption byte counts: %d, %d", ins, outs)
	}
	outs = aes.Finish(encrypted[outs:])
	if outs != 0 {
		t.Fatalf("Wrong encryption finish count: %d", outs)
	}
	// let's decrypt from 9th block on
	iv[15] = 8
	aes = NewCipher(AES_CTR, key, iv, false)
	defer aes.Close()
	decrypted := make([]byte, len(plain)-(8*16))
	ins, outs = aes.Update(encrypted[8*16:], decrypted)
	if outs != len(plain)-8*16 || ins != outs {
		t.Fatalf("Wrong decryption byte counts: %d", ins, outs)
	}
	aes.Finish(nil) // This should not panic
	if !bytes.Equal(decrypted, plain[16*8:]) {
		t.Fatal("Decrypted does not match plain")
	}
}

func TestAES_GCM(t *testing.T) {
	key := make([]byte, 16)
	// In GCM mode the IV is the counter
	iv := make([]byte, 16) // all zeros
	aes := NewCipher(AES_GCM, key, iv, true)
	defer aes.Close()
	plain := make([]byte, 155) // intentionally not a multiple of block length
	for i := 0; i < len(plain); i += 1 {
		plain[i] = byte(i)
	}
	encrypted := make([]byte, len(plain))
	ins, outs := aes.Update([]byte(plain), encrypted)
	if outs != len(plain) || ins != len(plain) {
		t.Fatalf("Wrong encryption byte counts: %d, %d", ins, outs)
	}
	outs = aes.Finish(encrypted[outs:])
	if outs != 0 {
		t.Fatalf("Wrong encryption finish count: %d", outs)
	}
	tag := make([]byte, 16)
	aes.GCMGetTag(tag)
	aes = NewCipher(AES_GCM, key, iv, false)
	defer aes.Close()
	aes.GCMSetTag(tag)
	decrypted := make([]byte, len(plain))
	ins, outs = aes.Update(encrypted, decrypted)
	if outs != len(plain) || ins != len(encrypted) {
		t.Fatalf("Wrong decryption byte counts: %d, %d", ins, outs)
	}
	aes.Finish(nil) // this shouldn't panic if authentication checks out
	if !bytes.Equal(decrypted, plain) {
		t.Fatal("Decrypted does not match plain")
	}
}
