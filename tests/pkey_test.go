package tests

// import (
// 	"encoding/hex"
// 	"fmt"
// 	"github.com/mkobetic/okapi"
// 	_ "github.com/mkobetic/okapi/libcrypto"
// 	"testing"
// )

// func ExampleRSA() {
// 	pri := okapi.RSA(2048)
// 	pub := pri.PublicKey()
// 	plain := []byte("Message in a bottle!")
// 	encrypted := pub.Encrypt(plain)
// 	decrypted := pri.Decrypt(encrypted)
// }

// func ExampleDSA_SHA256() {
// 	pri := okapi.DSA_SHA256(2048)
// 	pub := pri.PublicKey()
// 	plain := []byte("Message in a bottle!")
// 	encrypted := pub.Encrypt(plain)
// 	decrypted := pri.Decrypt(encrypted)
// }
