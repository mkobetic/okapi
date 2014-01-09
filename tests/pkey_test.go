package tests

import (
	"bytes"
	"fmt"
	"github.com/mkobetic/okapi"
	_ "github.com/mkobetic/okapi/libcrypto"
	_ "testing"
)

func ExampleRSA() {
	pri, _ := okapi.RSA(512)
	defer pri.Close()
	pub := pri.PublicKey()
	defer pub.Close()
	plain := []byte("Message in a bottle!")
	fmt.Printf("Plain    : %x\n", plain)
	encrypted, _ := pub.Encrypt(plain)
	// fmt.Printf("Encrypted: %x\n", encrypted)
	decrypted, _ := pri.Decrypt(encrypted)
	fmt.Printf("Decrypted: %x\n", decrypted)
	// Output:
	// Plain    : 4d65737361676520696e206120626f74746c6521
	// Decrypted: 4d65737361676520696e206120626f74746c6521

}

func ExampleDSA_SHA256() {
	pri, _ := okapi.DSA_SHA256(512)
	defer pri.Close()
	pub := pri.PublicKey()
	defer pub.Close()
	message := []byte("Message in a bottle!")
	fmt.Printf("Message : %x\n", message)
	signature, _ := pri.Sign(message)
	// fmt.Printf("Signature: %x", signature)
	verified, _ := pub.Verify(signature, message)
	fmt.Printf("Verified: %v\n", verified)
	// Output:
	// Message : 4d65737361676520696e206120626f74746c6521
	// Verified: true
}

func ExampleDH() {
	pri1, _ := okapi.DH(512)
	defer pri1.Close()
	pub1 := pri1.PublicKey()
	defer pub1.Close()
	// generate the peer key with the same parameters
	pri2, _ := okapi.DH(pub1)
	defer pri2.Close()
	pub2 := pri2.PublicKey()
	defer pub2.Close()
	secret1, _ := pri1.Derive(pub2)
	fmt.Printf("Secret 1: %d bytes\n", len(secret1))
	secret2, _ := pri2.Derive(pub1)
	fmt.Printf("Secret 2: %d bytes\n", len(secret2))
	fmt.Printf("Secrets equal? %v\n", bytes.Equal(secret1, secret2))
	// Output:
	// Secret 1: 64 bytes
	// Secret 2: 64 bytes
	// Secrets equal? true
}
