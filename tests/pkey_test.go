package tests

import (
	"fmt"
	"github.com/mkobetic/okapi"
	_ "github.com/mkobetic/okapi/libcrypto"
	_ "testing"
)

func ExampleRSA() {
	pri, _ := okapi.RSA(512)
	pub := pri.PublicKey()
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
	pub := pri.PublicKey()
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
