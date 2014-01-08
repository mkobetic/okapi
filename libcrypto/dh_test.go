// +build !windows

package libcrypto

import (
	"testing"
)

func TestGenerateKey_DH(t *testing.T) {
	pri, err := NewPKey(512, DH)
	if err != nil {
		t.Fatalf("Failed generating key: %s", err)
	}
	defer pri.Close()
	if pri.KeySize() != 512 {
		t.Fatal("Invalid key size!")
	}
}

// func TestDH(t *testing.T) {
// 	pri1, err := NewPKey(1024, DH)
// 	if err != nil {
// 		t.Fatalf("Failed generating key: %s", err)
// 	}
// 	defer pri1.Close()
// 	pub1 := pri1.PublicKey()
// 	defer pub1.Close()
// 	pri2, _ := NewPKey(pemDH1024Params, DH)
// 	defer pri2.Close()
// 	pub2 := pri2.PublicKey()
// 	defer pub2.Close()
// 	secret1, err := pri1.Derive(pub2)
// 	if err != nil {
// 		t.Fatalf("Derive error: %s", err)
// 	}
// 	secret2, err := pri2.Derive(pub1)
// 	if err != nil {
// 		t.Fatalf("Derive error: %s", err)
// 	}
// 	if !bytes.Equal(secret1, secret2) {
// 		t.Fatalf("\nDerivation mismatch\nSecret 1: %x\nSecret 2: %x", secret1, secret2)
// 	}
// }
